"""Build and read back a deterministic release archive from an exact file allowlist.

This tool never discovers files to include. The reviewed manifest is the authority, and
the source root must contain no unlisted files or directories. Artifact privacy scanning
is a separate mandatory gate because source code and synthetic security fixtures contain
terms that an artifact scanner must reject in logs, proofs, and crash output.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Any
import unicodedata
import zipfile
import zlib


MANIFEST_VERSION = 2
BUILDER_VERSION = "blind-ledger-release-archive-v1"
SOURCE_MANIFEST_NAME = "APP_RELEASE_FILE_MANIFEST.json"
EMBEDDED_MANIFEST_NAME = "RELEASE_FILE_MANIFEST.json"
FIXED_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024

_SHA256 = re.compile(r"[0-9a-f]{64}")
_WINDOWS_RESERVED = re.compile(r"(?i)(?:con|prn|aux|nul|com[1-9]|lpt[1-9])")
_FORBIDDEN_SEGMENTS = {
    ".agents",
    ".claude",
    ".codex",
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "a",
    "cache",
    "m",
    "malformed-target-path",
    "node_modules",
    "out",
    "p",
    "proof",
    "proofs",
    "r",
    "scratch",
    "target",
    "wsl-target",
    "x",
    "y",
}
_FORBIDDEN_FILENAMES = {
    "claude.md",
    "gemini.md",
    "memory.md",
    "batch_main_args.json",
    "batch_package.json",
    "proof.json",
}
_FORBIDDEN_SUFFIXES = {
    ".7z",
    ".dmp",
    ".bin",
    ".bz2",
    ".docx",
    ".gz",
    ".jar",
    ".log",
    ".png",
    ".pptx",
    ".pyo",
    ".pyc",
    ".rar",
    ".tar",
    ".tgz",
    ".tmp",
    ".whl",
    ".woff2",
    ".xlsx",
    ".xz",
    ".zip",
    ".zst",
}
_STRUCTURAL_PRIVATE_CATEGORIES = {
    "encoded_container_not_privacy_scanned",
    "host_private_path",
    "plaintext_x12_837",
    "private_key_material",
}


class ReleaseArchiveError(RuntimeError):
    """A fail-closed release validation or readback failure."""


class _DuplicateJsonKey(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey(key)
        result[key] = value
    return result


def _is_reparse_point(path: Path) -> bool:
    try:
        details = path.lstat()
    except OSError:
        return False
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(details, "st_file_attributes", 0) & marker)


def _same_file(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        stat.S_IFMT(before.st_mode) == stat.S_IFMT(after.st_mode)
        and before.st_dev == after.st_dev
        and before.st_ino == after.st_ino
    )


def _validate_segment(segment: str) -> None:
    if not segment or segment in {".", ".."}:
        raise ReleaseArchiveError("release path has an empty or traversal component")
    if segment != unicodedata.normalize("NFC", segment):
        raise ReleaseArchiveError("release path is not Unicode NFC normalized")
    if segment.endswith((" ", ".")):
        raise ReleaseArchiveError("release path has a trailing space or dot")
    if len(segment.encode("utf-8")) > 255:
        raise ReleaseArchiveError("release path component exceeds the byte limit")
    if any(
        ord(character) < 32
        or character == "\x7f"
        or unicodedata.category(character) in {"Cf", "Cs", "Zl", "Zp"}
        for character in segment
    ):
        raise ReleaseArchiveError("release path contains a control character")
    if ":" in segment:
        raise ReleaseArchiveError("release path contains a colon or alternate-data-stream syntax")
    stem = unicodedata.normalize("NFKC", segment.split(".", 1)[0])
    if _WINDOWS_RESERVED.fullmatch(stem) or stem.casefold() in {"conin$", "conout$"}:
        raise ReleaseArchiveError("release path uses a reserved Windows device name")


def _validate_relative_path(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ReleaseArchiveError("release path must be a non-empty string")
    if "\\" in value or value.startswith("/") or value.endswith("/"):
        raise ReleaseArchiveError("release path must be relative POSIX syntax")
    if value.startswith("//") or "\x00" in value:
        raise ReleaseArchiveError("release path is absolute or contains NUL")
    parts = value.split("/")
    if len(value.encode("utf-8")) > 4096:
        raise ReleaseArchiveError("release path exceeds the byte limit")
    for part in parts:
        _validate_segment(part)
        folded = part.casefold()
        if folded in _FORBIDDEN_SEGMENTS:
            raise ReleaseArchiveError("release path enters a forbidden generated directory")
    filename = parts[-1].casefold()
    if filename in _FORBIDDEN_FILENAMES:
        raise ReleaseArchiveError("release path names a forbidden artifact or assistant file")
    if Path(filename).suffix in _FORBIDDEN_SUFFIXES:
        raise ReleaseArchiveError("release path has a forbidden generated or archive suffix")
    stem = Path(filename).stem
    if Path(filename).suffix == ".json" and "proof" in re.sub(r"[^a-z0-9]", "", stem):
        raise ReleaseArchiveError("release path names a forbidden proof-result JSON")
    if unicodedata.normalize("NFKC", value).casefold() == unicodedata.normalize(
        "NFKC", EMBEDDED_MANIFEST_NAME
    ).casefold():
        raise ReleaseArchiveError("release manifest must not include itself in the file list")
    return value


def _validate_archive_root(value: object) -> str:
    if not isinstance(value, str) or not value or "/" in value or "\\" in value:
        raise ReleaseArchiveError("archive_root must be one safe directory name")
    _validate_segment(value)
    if value.casefold() in _FORBIDDEN_SEGMENTS:
        raise ReleaseArchiveError("archive_root names a forbidden generated directory")
    return value


def _capture_bounded_file(path: Path, *, maximum_size: int, label: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise ReleaseArchiveError(f"{label} is missing or unreadable") from exc
    if path.is_symlink() or _is_reparse_point(path) or not stat.S_ISREG(before.st_mode):
        raise ReleaseArchiveError(f"{label} must be an ordinary unlinked file")
    if before.st_nlink > 1:
        raise ReleaseArchiveError(f"{label} must not be hardlinked")
    if before.st_size > maximum_size:
        raise ReleaseArchiveError(f"{label} exceeds the size limit")
    try:
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if not _same_file(before, opened) or opened.st_nlink > 1:
                raise ReleaseArchiveError(f"{label} changed before capture")
            raw = stream.read(maximum_size + 1)
            closed = os.fstat(stream.fileno())
        after = path.lstat()
    except OSError as exc:
        raise ReleaseArchiveError(f"{label} is unreadable") from exc
    if (
        not _same_file(before, closed)
        or not _same_file(before, after)
        or before.st_size != closed.st_size
        or before.st_size != after.st_size
        or before.st_mtime_ns != closed.st_mtime_ns
        or before.st_mtime_ns != after.st_mtime_ns
        or after.st_nlink > 1
        or len(raw) != after.st_size
    ):
        raise ReleaseArchiveError(f"{label} changed during capture")
    if len(raw) > maximum_size:
        raise ReleaseArchiveError(f"{label} exceeds the size limit")
    return raw


def _read_manifest(path: Path) -> tuple[bytes, str, list[dict[str, Any]]]:
    raw = _capture_bounded_file(
        path, maximum_size=MAX_MANIFEST_BYTES, label="release manifest"
    )
    try:
        text = raw.decode("utf-8")
        document = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (_DuplicateJsonKey, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseArchiveError("release manifest is not strict UTF-8 JSON") from exc
    if not isinstance(document, dict) or set(document) != {
        "archive_root",
        "files",
        "manifest_version",
    }:
        raise ReleaseArchiveError("release manifest fields do not match schema v2")
    if type(document["manifest_version"]) is not int or document["manifest_version"] != MANIFEST_VERSION:
        raise ReleaseArchiveError("release manifest version is unsupported")
    archive_root = _validate_archive_root(document["archive_root"])
    entries = document["files"]
    if not isinstance(entries, list) or not entries:
        raise ReleaseArchiveError("release manifest files must be a non-empty array")

    validated: list[dict[str, Any]] = []
    exact_paths: set[str] = set()
    folded_paths: set[str] = {
        unicodedata.normalize("NFKC", EMBEDDED_MANIFEST_NAME).casefold()
    }
    previous_path: str | None = None
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size"}:
            raise ReleaseArchiveError("release file entry fields do not match schema v2")
        relative = _validate_relative_path(entry["path"])
        size = entry["size"]
        digest = entry["sha256"]
        if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= MAX_FILE_BYTES:
            raise ReleaseArchiveError("release file size is invalid or exceeds the limit")
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            raise ReleaseArchiveError("release file sha256 must be lowercase hexadecimal")
        folded = unicodedata.normalize("NFKC", relative).casefold()
        if relative in exact_paths or folded in folded_paths:
            raise ReleaseArchiveError("release paths collide exactly, by case, or by Unicode")
        if previous_path is not None and relative <= previous_path:
            raise ReleaseArchiveError("release file entries must be strictly path-sorted")
        exact_paths.add(relative)
        folded_paths.add(folded)
        previous_path = relative
        validated.append({"path": relative, "sha256": digest, "size": size})
    return raw, archive_root, validated


def _safe_capture(path: Path, *, expected_size: int, expected_sha256: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise ReleaseArchiveError("a listed release file is missing or unreadable") from exc
    if path.is_symlink() or _is_reparse_point(path) or not stat.S_ISREG(before.st_mode):
        raise ReleaseArchiveError("a listed release file is linked, reparse, or special")
    if before.st_nlink > 1:
        raise ReleaseArchiveError("a listed release file is hardlinked")
    if before.st_size != expected_size:
        raise ReleaseArchiveError("a listed release file size does not match the manifest")
    try:
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if not _same_file(before, opened) or opened.st_nlink > 1:
                raise ReleaseArchiveError("a listed release file changed before capture")
            data = stream.read(MAX_FILE_BYTES + 1)
            closed = os.fstat(stream.fileno())
        after = path.lstat()
    except OSError as exc:
        raise ReleaseArchiveError("a listed release file could not be captured") from exc
    if (
        not _same_file(before, closed)
        or not _same_file(before, after)
        or before.st_size != closed.st_size
        or before.st_size != after.st_size
        or before.st_mtime_ns != closed.st_mtime_ns
        or before.st_mtime_ns != after.st_mtime_ns
        or after.st_nlink > 1
        or len(data) != expected_size
    ):
        raise ReleaseArchiveError("a listed release file changed during capture")
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ReleaseArchiveError("a listed release file hash does not match the manifest")
    return data


def _decoded_payload_is_forbidden(data: bytes) -> bool:
    archive_magic = (
        b"PK\x03\x04",
        b"\x1f\x8b",
        b"7z\xbc\xaf\x27\x1c",
        b"Rar!",
    )
    if data.startswith(archive_magic):
        return True
    try:
        decoded_text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    from tools.privacy_artifact_scan import _text_categories

    return bool(_STRUCTURAL_PRIVATE_CATEGORIES & set(_text_categories(decoded_text)))


def _decode_canonical_base64(compact: str) -> bytes | None:
    if not compact:
        return None

    uses_standard_alphabet = "+" in compact or "/" in compact
    uses_urlsafe_alphabet = "-" in compact or "_" in compact
    if uses_standard_alphabet and uses_urlsafe_alphabet:
        return None

    alphabet = r"[A-Za-z0-9_-]+" if uses_urlsafe_alphabet else r"[A-Za-z0-9+/]+"
    if not re.fullmatch(f"{alphabet}=*", compact):
        return None

    unpadded = compact.rstrip("=")
    padding_count = len(compact) - len(unpadded)
    if padding_count > 2:
        return None
    required_padding = (-len(unpadded)) % 4
    if required_padding == 3:
        return None
    if padding_count and (
        len(compact) % 4 != 0 or padding_count != required_padding
    ):
        return None

    padded = unpadded + ("=" * required_padding)
    altchars = b"-_" if uses_urlsafe_alphabet else None
    try:
        decoded = base64.b64decode(padded, altchars=altchars, validate=True)
    except ValueError:
        return None

    canonical = (
        base64.urlsafe_b64encode(decoded)
        if uses_urlsafe_alphabet
        else base64.b64encode(decoded)
    ).decode("ascii")
    expected = canonical if padding_count else canonical.rstrip("=")
    if compact != expected:
        return None
    return decoded


def _contains_forbidden_encoded_payload(text: str) -> bool:
    compact = re.sub(r"\s+", "", text)
    decoded_base64 = _decode_canonical_base64(compact)
    if (
        decoded_base64 is not None
        and _decoded_payload_is_forbidden(decoded_base64)
    ):
        return True
    for token in re.findall(r"(?i)(?:[0-9a-f]{2}){8,}", text):
        if _decoded_payload_is_forbidden(bytes.fromhex(token)):
            return True
    ascii85 = re.sub(r"\s+", "", text)
    if len(ascii85) >= 5 and all(33 <= ord(character) <= 117 for character in ascii85):
        try:
            if _decoded_payload_is_forbidden(base64.a85decode(ascii85, adobe=False)):
                return True
        except (ValueError, OverflowError):
            pass
    return False


def _validate_payload_content(relative: str, data: bytes) -> None:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ReleaseArchiveError("release payload contains an opaque non-text file") from exc
    if any(
        ord(character) < 32 and character not in {"\t", "\n", "\r"}
        for character in text
    ):
        raise ReleaseArchiveError("release payload contains opaque control bytes")
    from tools.privacy_artifact_scan import (
        _reject_duplicate_keys,
        _text_categories,
        _walk_json,
    )

    categories = set(_text_categories(text))
    if categories & _STRUCTURAL_PRIVATE_CATEGORIES:
        raise ReleaseArchiveError("release payload failed the structural privacy gate")
    if _contains_forbidden_encoded_payload(text):
        raise ReleaseArchiveError("release payload contains encoded opaque or private material")
    if Path(relative).suffix.casefold() in {".json", ".jsonl"}:
        try:
            json_values = (
                [
                    json.loads(line, object_pairs_hook=_reject_duplicate_keys)
                    for line in text.splitlines()
                    if line.strip()
                ]
                if Path(relative).suffix.casefold() == ".jsonl"
                else [json.loads(text, object_pairs_hook=_reject_duplicate_keys)]
            )
        except (ValueError, json.JSONDecodeError) as exc:
            raise ReleaseArchiveError("release payload contains malformed JSON") from exc
        json_findings: list[str] = []
        for value in json_values:
            _walk_json(value, path="", findings=json_findings)
        if any(
            finding.endswith(
                (
                    ":forbidden_json_key",
                    ":plaintext_x12_837",
                    ":sensitive_plaintext_assignment",
                )
            )
            for finding in json_findings
        ):
            raise ReleaseArchiveError("release JSON failed the structural privacy gate")
    if Path(relative).suffix.casefold() in _FORBIDDEN_SUFFIXES:
        raise ReleaseArchiveError("release payload has a forbidden file type")


def _inventory_source(root: Path) -> tuple[set[str], set[str]]:
    files: set[str] = set()
    directories: set[str] = set()
    walk_errors: list[OSError] = []

    def on_walk_error(error: OSError) -> None:
        walk_errors.append(error)

    for current, directory_names, file_names in os.walk(
        root, topdown=True, followlinks=False, onerror=on_walk_error
    ):
        current_path = Path(current)
        directory_names.sort(key=lambda value: (value.casefold(), value))
        file_names.sort(key=lambda value: (value.casefold(), value))
        for name in list(directory_names):
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink() or _is_reparse_point(path):
                raise ReleaseArchiveError("source root contains a linked or reparse directory")
            directories.add(relative)
        for name in file_names:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink() or _is_reparse_point(path):
                raise ReleaseArchiveError("source root contains a linked or reparse file")
            try:
                details = path.lstat()
            except OSError as exc:
                raise ReleaseArchiveError("source inventory contains an unreadable entry") from exc
            if not stat.S_ISREG(details.st_mode):
                raise ReleaseArchiveError("source inventory contains a special file")
            if details.st_nlink > 1:
                raise ReleaseArchiveError("source inventory contains a hardlinked file")
            files.add(relative)
    if walk_errors:
        raise ReleaseArchiveError("source directory enumeration failed")
    return files, directories


def _expected_directories(paths: set[str]) -> set[str]:
    directories: set[str] = set()
    for relative in paths:
        parent = Path(relative).parent
        while parent != Path("."):
            directories.add(parent.as_posix())
            parent = parent.parent
    return directories


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(filename=name, date_time=FIXED_TIMESTAMP)
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    info.extra = b""
    info.comment = b""
    return info


def _render_archive(
    *,
    archive_root: str,
    manifest_bytes: bytes,
    captured: list[tuple[str, bytes]],
) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(
        output, "w", compression=zipfile.ZIP_STORED, allowZip64=False
    ) as archive:
        archive.comment = b""
        archive.writestr(
            _zip_info(f"{archive_root}/{EMBEDDED_MANIFEST_NAME}"), manifest_bytes
        )
        for relative, data in captured:
            archive.writestr(_zip_info(f"{archive_root}/{relative}"), data)
    return output.getvalue()


def _verify_archive(
    archive_path: Path,
    *,
    archive_root: str,
    manifest_bytes: bytes,
    captured: list[tuple[str, bytes]],
) -> None:
    expected = [(f"{archive_root}/{EMBEDDED_MANIFEST_NAME}", manifest_bytes)] + [
        (f"{archive_root}/{relative}", data) for relative, data in captured
    ]
    expected_bytes = _render_archive(
        archive_root=archive_root,
        manifest_bytes=manifest_bytes,
        captured=captured,
    )
    try:
        actual_bytes = _capture_bounded_file(
            archive_path,
            maximum_size=len(expected_bytes),
            label="release archive readback",
        )
        if actual_bytes != expected_bytes:
            raise ReleaseArchiveError("archive bytes are not the canonical deterministic ZIP")
        with zipfile.ZipFile(io.BytesIO(actual_bytes), "r", allowZip64=False) as archive:
            if archive.comment != b"":
                raise ReleaseArchiveError("archive readback found a ZIP comment")
            infos = archive.infolist()
            if [item.filename for item in infos] != [name for name, _data in expected]:
                raise ReleaseArchiveError("archive readback names or ordering differ")
            if len({item.filename for item in infos}) != len(infos):
                raise ReleaseArchiveError("archive readback found duplicate entries")
            for info, (name, data) in zip(infos, expected, strict=True):
                if (
                    info.filename != name
                    or info.date_time != FIXED_TIMESTAMP
                    or info.compress_type != zipfile.ZIP_STORED
                    or info.file_size != len(data)
                    or info.compress_size != len(data)
                    or info.CRC != zlib.crc32(data) & 0xFFFFFFFF
                    or info.extra != b""
                    or info.comment != b""
                    or info.create_system != 3
                    or info.external_attr != (stat.S_IFREG | 0o644) << 16
                    or archive.read(info) != data
                ):
                    raise ReleaseArchiveError("archive entry failed deterministic readback")
            if archive.testzip() is not None:
                raise ReleaseArchiveError("archive CRC readback failed")
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        if isinstance(exc, ReleaseArchiveError):
            raise
        raise ReleaseArchiveError("archive could not be read back") from exc


def build_release_archive(
    source_root: Path, manifest_path: Path, output_path: Path
) -> dict[str, int | str]:
    source_root = Path(source_root)
    manifest_path = Path(manifest_path)
    output_path = Path(output_path)
    if not source_root.exists() or not source_root.is_dir():
        raise ReleaseArchiveError("source root is missing or not a directory")
    if source_root.is_symlink() or _is_reparse_point(source_root):
        raise ReleaseArchiveError("source root must not be linked or reparse")
    source_root = source_root.resolve()
    try:
        manifest_path = manifest_path.resolve(strict=True)
    except OSError as exc:
        raise ReleaseArchiveError("release manifest is missing") from exc
    if manifest_path.parent != source_root:
        raise ReleaseArchiveError("release manifest must be directly inside the source root")
    if manifest_path.name != SOURCE_MANIFEST_NAME:
        raise ReleaseArchiveError("release manifest filename is not the fixed v2 name")

    output_parent = output_path.parent.resolve(strict=True)
    resolved_output = output_parent / output_path.name
    if output_path.name != unicodedata.normalize("NFC", output_path.name):
        raise ReleaseArchiveError("release output filename is not Unicode NFC normalized")
    _validate_segment(output_path.name)
    if output_path.suffix.casefold() != ".zip":
        raise ReleaseArchiveError("release output must use the .zip suffix")
    if resolved_output == source_root or resolved_output.is_relative_to(source_root):
        raise ReleaseArchiveError("release output must be outside the source root")
    if resolved_output.exists():
        raise ReleaseArchiveError("release output already exists")

    manifest_bytes, archive_root, entries = _read_manifest(manifest_path)
    listed_paths = {entry["path"] for entry in entries}
    actual_files, actual_directories = _inventory_source(source_root)
    expected_files = listed_paths | {manifest_path.name}
    expected_directories = _expected_directories(expected_files)
    if actual_files != expected_files or actual_directories != expected_directories:
        raise ReleaseArchiveError("source root contains missing, unknown, or unlisted entries")

    captured: list[tuple[str, bytes]] = []
    total_bytes = 0
    for entry in entries:
        relative = entry["path"]
        path = source_root.joinpath(*relative.split("/"))
        try:
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise ReleaseArchiveError("a listed release file is missing") from exc
        if not resolved.is_relative_to(source_root):
            raise ReleaseArchiveError("a listed release file escapes the source root")
        data = _safe_capture(
            path,
            expected_size=entry["size"],
            expected_sha256=entry["sha256"],
        )
        _validate_payload_content(relative, data)
        total_bytes += len(data)
        if total_bytes > MAX_TOTAL_BYTES:
            raise ReleaseArchiveError("release payload exceeds the total size limit")
        captured.append((relative, data))

    expected_archive_bytes = _render_archive(
        archive_root=archive_root,
        manifest_bytes=manifest_bytes,
        captured=captured,
    )
    temporary_path: Path | None = None
    published_identity: os.stat_result | None = None
    archive_bytes: bytes | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=f".{resolved_output.name}.",
            suffix=".tmp",
            dir=output_parent,
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(expected_archive_bytes)
            temporary.flush()
            os.fsync(temporary.fileno())
        _verify_archive(
            temporary_path,
            archive_root=archive_root,
            manifest_bytes=manifest_bytes,
            captured=captured,
        )
        try:
            os.link(temporary_path, resolved_output, follow_symlinks=False)
        except FileExistsError as exc:
            raise ReleaseArchiveError("release output already exists") from exc
        published_identity = resolved_output.lstat()
        temporary_path.unlink()
        temporary_path = None
        _verify_archive(
            resolved_output,
            archive_root=archive_root,
            manifest_bytes=manifest_bytes,
            captured=captured,
        )
        archive_bytes = _capture_bounded_file(
            resolved_output,
            maximum_size=len(expected_archive_bytes),
            label="completed release archive",
        )
        if archive_bytes != expected_archive_bytes:
            raise ReleaseArchiveError("completed release archive changed after readback")
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        cleanup_failed = False
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                cleanup_failed = True
        if published_identity is not None and resolved_output.exists():
            try:
                current_identity = resolved_output.lstat()
                if _same_file(published_identity, current_identity):
                    resolved_output.unlink()
                else:
                    cleanup_failed = True
            except OSError:
                cleanup_failed = True
        if cleanup_failed:
            raise ReleaseArchiveError(
                "release build failed and cleanup or output custody was incomplete"
            ) from exc
        if isinstance(exc, ReleaseArchiveError):
            raise
        raise ReleaseArchiveError("release archive build failed") from exc

    assert archive_bytes is not None
    return {
        "archive_bytes": len(archive_bytes),
        "archive_sha256": hashlib.sha256(expected_archive_bytes).hexdigest(),
        "builder_version": BUILDER_VERSION,
        "entry_count": len(captured) + 1,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "payload_bytes": total_bytes,
        "payload_file_count": len(captured),
        "receipt_version": 1,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build and read back a deterministic allowlisted release ZIP."
    )
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        receipt = build_release_archive(args.source_root, args.manifest, args.output)
    except ReleaseArchiveError as exc:
        print(f"release_status=blocked reason={exc}", file=sys.stderr)
        raise SystemExit(1) from None
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
