"""Fail-closed scanner for plaintext claim, witness, log, and crash artifacts."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
from typing import Any
import unicodedata
from urllib.parse import unquote


FORBIDDEN_JSON_KEYS = {
    "serialized_arguments_hex_json",
    "serialized_arguments",
    "raw_edi",
    "edi",
    "member_id",
    "patient_id",
    "diagnosis",
    "diagnoses",
    "prior_authorization",
    "claims",
    "witness",
}
FORBIDDEN_FILENAMES = {
    "batch_main_args.json",
    "batch_package.json",
}
UNSCANNED_DIRECTORY_NAMES = {
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
    "r",
    "scratch",
    "target",
    "wsl-target",
    "x",
    "y",
}
ARCHIVE_SUFFIXES = {
    ".7z",
    ".gz",
    ".rar",
    ".tar",
    ".tgz",
    ".zip",
}
MAX_SCAN_BYTES = 64 * 1024 * 1024

_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)\b(?:member[_ -]?id|patient[_ -]?id|raw[_ -]?edi|diagnos(?:is|es)|"
    r"prior[_ -]?authorization|claims|witness)\b\s*(?::|=)"
)
_FORBIDDEN_ARTIFACT_REFERENCE = re.compile(
    r"(?i)\b(?:batch_main_args\.json|batch_package\.json)\b"
)
_WINDOWS_USER_PATH = re.compile(r"(?i)\b[a-z]:[\\/]+users[\\/]+[^\\/\s\"']+")
_POSIX_PRIVATE_PATH = re.compile(
    r"(?i)(?<![A-Za-z0-9])/(?:home|users|tmp|root|private/tmp)/[^/\s\"'`\]]+"
)
_UNC_PATH = re.compile(r"(?i)\\\\(?:wsl\$|wsl\.localhost|[^\\\s]+)\\")
_FILE_URL = re.compile(r"(?i)\bfile://")
_PRIVATE_KEY = re.compile(
    r"(?:-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----|"
    r"-----BEGIN PGP PRIVATE KEY BLOCK-----|AGE-SECRET-KEY-)"
)
_ENCODED_CONTAINER = re.compile(
    r"(?<![A-Za-z0-9+/=])(?:UEsDB|H4sI|N3q8ryccAA|UmFyIQ)[A-Za-z0-9+/=]{8,}"
)
_MALFORMED_HOST_CACHE_DIRECTORY = re.compile(r"(?i)^[a-z][:\uf03a]users[^/\\]*$")
_ENVIRONMENT_PRIVATE_PATH = re.compile(
    r"(?i)(?:%USERPROFILE%|%HOMEPATH%|\$HOME|\$USERPROFILE|~[/\\])"
)


class _DuplicateJsonKey(ValueError):
    pass


def _security_normalize(value: object) -> str:
    normalized = unicodedata.normalize("NFKC", str(value))
    normalized = "".join(
        character
        for character in normalized
        if unicodedata.category(character) not in {"Cf", "Cs"}
    )
    return "".join(
        "-" if unicodedata.category(character) == "Pd" else character
        for character in normalized
    )


def _normalized_key(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", _security_normalize(value).casefold())


def _forbidden_json_key(value: object) -> bool:
    normalized = _normalized_key(value)
    exact = {re.sub(r"[^a-z0-9]+", "", key) for key in FORBIDDEN_JSON_KEYS}
    if normalized in exact:
        return True
    return normalized.startswith(
        (
            "diagnosis",
            "memberid",
            "patientid",
            "priorauthorization",
            "rawedi",
            "serializedarguments",
            "witness",
        )
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey(key)
        result[key] = value
    return result


def _text_categories(value: str) -> list[str]:
    value = unquote(_security_normalize(value))
    categories: list[str] = []
    if _SENSITIVE_ASSIGNMENT.search(value):
        categories.append("sensitive_plaintext_assignment")
    upper = value.upper()
    if "ST*837" in upper and "CLM*" in upper and any(
        marker in upper for marker in ("NM1*IL", "HI*", "REF*G1")
    ):
        categories.append("plaintext_x12_837")
    if _FORBIDDEN_ARTIFACT_REFERENCE.search(value):
        categories.append("forbidden_artifact_reference")
    if (
        _WINDOWS_USER_PATH.search(value)
        or _POSIX_PRIVATE_PATH.search(value)
        or _UNC_PATH.search(value)
        or _FILE_URL.search(value)
        or _ENVIRONMENT_PRIVATE_PATH.search(value)
    ):
        categories.append("host_private_path")
    if _PRIVATE_KEY.search(value):
        categories.append("private_key_material")
    if _ENCODED_CONTAINER.search(value):
        categories.append("encoded_container_not_privacy_scanned")
    return categories


def _scan_text(value: str, *, location: str, findings: list[str]) -> None:
    findings.extend(f"{location}:{category}" for category in _text_categories(value))


def _walk_json(value: Any, *, path: str, findings: list[str]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}" if path else str(key)
            if _forbidden_json_key(key):
                findings.append(f"{child}:forbidden_json_key")
            _scan_text(str(key), location=child, findings=findings)
            _walk_json(item, path=child, findings=findings)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _walk_json(item, path=f"{path}[{index}]", findings=findings)
    elif isinstance(value, str):
        _scan_text(value, location=path or "$", findings=findings)


def _is_reparse_point(path: Path) -> bool:
    try:
        details = path.lstat()
    except OSError:
        return False
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(details, "st_file_attributes", 0) & marker)


def _decode_text(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16")
    return data.decode("utf-8-sig")


def _same_file(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        stat.S_IFMT(before.st_mode) == stat.S_IFMT(after.st_mode)
        and before.st_dev == after.st_dev
        and before.st_ino == after.st_ino
    )


def _read_regular_file(path: Path) -> tuple[bytes | None, str | None]:
    """Read one bounded regular file while detecting links and concurrent replacement."""

    try:
        before = path.lstat()
    except OSError:
        return None, "file_unreadable"
    if path.is_symlink() or _is_reparse_point(path):
        return None, "linked_file_not_scanned"
    if not stat.S_ISREG(before.st_mode):
        return None, "special_file_not_scanned"
    if before.st_nlink > 1:
        return None, "hardlinked_file_not_scanned"
    if before.st_size > MAX_SCAN_BYTES:
        return None, "file_too_large_to_privacy_scan"

    try:
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if not _same_file(before, opened) or opened.st_nlink > 1:
                return None, "file_changed_during_scan"
            data = stream.read(MAX_SCAN_BYTES + 1)
            closed = os.fstat(stream.fileno())
    except OSError:
        return None, "file_unreadable"

    try:
        after = path.lstat()
    except OSError:
        return None, "file_changed_during_scan"
    if (
        not _same_file(before, closed)
        or not _same_file(before, after)
        or before.st_size != closed.st_size
        or before.st_size != after.st_size
        or before.st_mtime_ns != closed.st_mtime_ns
        or before.st_mtime_ns != after.st_mtime_ns
        or after.st_nlink > 1
        or len(data) != after.st_size
    ):
        return None, "file_changed_during_scan"
    if len(data) > MAX_SCAN_BYTES:
        return None, "file_too_large_to_privacy_scan"
    return data, None


def _scan_json_file(path: Path, *, relative: str, findings: list[str]) -> None:
    data, read_error = _read_regular_file(path)
    if read_error is not None:
        category = {
            "file_unreadable": "json_unreadable",
            "file_too_large_to_privacy_scan": "json_too_large_to_privacy_scan",
        }.get(read_error, read_error)
        findings.append(f"{relative}:{category}")
        return
    assert data is not None
    try:
        text = _decode_text(data)
    except UnicodeDecodeError:
        findings.append(f"{relative}:json_not_utf8_or_utf16")
        return

    values: list[Any] = []
    try:
        if path.suffix.casefold() == ".jsonl":
            for line_number, line in enumerate(text.splitlines(), start=1):
                if line.strip():
                    values.append(
                        (
                            line_number,
                            json.loads(line, object_pairs_hook=_reject_duplicate_keys),
                        )
                    )
        else:
            values.append((None, json.loads(text, object_pairs_hook=_reject_duplicate_keys)))
    except _DuplicateJsonKey:
        findings.append(f"{relative}:json_duplicate_key")
        return
    except json.JSONDecodeError:
        findings.append(f"{relative}:json_malformed")
        return

    findings.append(f"{relative}:unapproved_json_artifact_schema")
    for line_number, value in values:
        local: list[str] = []
        _walk_json(value, path="", findings=local)
        prefix = f"{relative}:line[{line_number}]" if line_number is not None else relative
        findings.extend(f"{prefix}:{item}" for item in local)


def _scan_text_file(path: Path, *, relative: str, findings: list[str]) -> None:
    if path.suffix.casefold() in ARCHIVE_SUFFIXES:
        findings.append(f"{relative}:opaque_archive_not_privacy_scanned")
        return
    data, read_error = _read_regular_file(path)
    if read_error is not None:
        findings.append(f"{relative}:{read_error}")
        return
    assert data is not None
    try:
        text = _decode_text(data)
    except UnicodeDecodeError:
        findings.append(f"{relative}:opaque_file_not_privacy_scanned")
        return
    if "\x00" in text:
        findings.append(f"{relative}:opaque_file_not_privacy_scanned")
        return
    _scan_text(text, location=relative, findings=findings)
    findings.append(f"{relative}:unapproved_text_artifact_present")


def scan_artifacts(root: Path) -> list[str]:
    root = Path(root)
    if not root.exists():
        return [".:scan_root_missing"]
    if not root.is_dir():
        return [".:scan_root_not_directory"]
    if root.is_symlink() or _is_reparse_point(root):
        return [".:linked_scan_root_rejected"]
    root = root.resolve()

    findings: list[str] = []

    def on_walk_error(_error: OSError) -> None:
        findings.append(".:directory_enumeration_failed")

    sort_key = lambda value: (
        unicodedata.normalize("NFC", value).casefold(),
        unicodedata.normalize("NFC", value),
    )
    for current, directory_names, file_names in os.walk(
        root, topdown=True, followlinks=False, onerror=on_walk_error
    ):
        current_path = Path(current)
        directory_names.sort(key=sort_key)
        file_names.sort(key=sort_key)

        retained: list[str] = []
        for name in directory_names:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            _scan_text(name, location=relative, findings=findings)
            if (
                name.casefold() in UNSCANNED_DIRECTORY_NAMES
                or _MALFORMED_HOST_CACHE_DIRECTORY.fullmatch(name)
            ):
                findings.append(f"{relative}:unscanned_directory_present")
            elif path.is_symlink() or _is_reparse_point(path):
                findings.append(f"{relative}:linked_directory_not_scanned")
            else:
                retained.append(name)
        directory_names[:] = retained

        for name in file_names:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            _scan_text(name, location=relative, findings=findings)
            if path.is_symlink() or _is_reparse_point(path):
                findings.append(f"{relative}:linked_file_not_scanned")
                continue
            if not path.is_file():
                findings.append(f"{relative}:special_file_not_scanned")
                continue
            if _security_normalize(name).casefold() in FORBIDDEN_FILENAMES:
                findings.append(f"{relative}:forbidden_plaintext_filename")
            if path.suffix.casefold() in {".json", ".jsonl"}:
                _scan_json_file(path, relative=relative, findings=findings)
            else:
                _scan_text_file(path, relative=relative, findings=findings)
    # A path or JSON key may itself contain sensitive data. Findings therefore expose
    # only a deterministic ordinal and a category, never source-controlled names.
    return [
        f"item[{index:06d}]:{finding.rsplit(':', 1)[-1]}"
        for index, finding in enumerate(findings, start=1)
    ]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Reject artifacts containing plaintext claim, witness, log, or crash data."
    )
    parser.add_argument(
        "path",
        nargs="?",
        type=Path,
        help="artifact directory to scan (defaults to the repository root)",
    )
    parser.add_argument(
        "--repo-root",
        dest="repo_root",
        type=Path,
        help="explicit artifact/repository directory to scan",
    )
    args = parser.parse_args()
    if args.path is not None and args.repo_root is not None:
        parser.error("path and --repo-root are mutually exclusive")
    target = args.repo_root or args.path or Path(__file__).resolve().parents[1]
    findings = scan_artifacts(target)
    if findings:
        for finding in findings:
            print(f"privacy_finding={finding}")
        raise SystemExit(1)
    print("privacy_findings=0")


if __name__ == "__main__":
    main()
