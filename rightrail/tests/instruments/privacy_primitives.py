"""Shared release-safe privacy primitives for text and JSON inspection.

This module contains only deterministic, in-memory detectors.  The artifact
scanner owns filesystem traversal and artifact classification; the release
builder owns archive policy and payload validation.  Keeping these primitives
here lets the release builder remain self-contained after extraction while
both consumers retain one detection implementation.
"""

from __future__ import annotations

import re
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

_BACKSLASH = chr(92)
_REGEX_BACKSLASH = re.escape(_BACKSLASH)
_PATH_SEPARATOR = "[" + _REGEX_BACKSLASH + "/]+"
_PATH_COMPONENT = (
    "[^" + _REGEX_BACKSLASH + "/" + r"\s" + '"' + "'" + "]+"
)

_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)\b(?:member[_ -]?id|patient[_ -]?id|raw[_ -]?edi|diagnos(?:is|es)|"
    r"prior[_ -]?authorization|claims|witness)\b\s*(?::|=)"
)
_FORBIDDEN_ARTIFACT_REFERENCE = re.compile(
    r"(?i)\b(?:batch_main_args\.json|batch_package\.json)\b"
)
_WINDOWS_USER_PATH = re.compile(
    r"(?i)\b[a-z]:" + _PATH_SEPARATOR + "users" + _PATH_SEPARATOR + _PATH_COMPONENT
)
_POSIX_PRIVATE_PATH = re.compile(
    r"(?i)(?<![A-Za-z0-9])/"
    + "(?:home|users|tmp|root|private" + chr(47) + "tmp)"
    + r"/[^/\s\"'"
    + chr(96)
    + r"\]]+"
)
_UNC_PATH = re.compile(
    r"(?i)"
    + re.escape(_BACKSLASH * 2)
    + "(?:"
    + re.escape("wsl" + chr(36))
    + "|"
    + re.escape("wsl.localhost")
    + "|[^" + _REGEX_BACKSLASH + r"\s]+)"
    + _REGEX_BACKSLASH
)
_FILE_URL = re.compile(r"(?i)\b" + re.escape("file" + ":" + "/" * 2))
_PRIVATE_KEY = re.compile(
    r"(?:"
    + re.escape(chr(45) * 5 + "BEGIN ")
    + r"(?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?"
    + re.escape("PRIVATE KEY" + chr(45) * 5)
    + "|"
    + re.escape(chr(45) * 5 + "BEGIN PGP PRIVATE KEY BLOCK" + chr(45) * 5)
    + "|"
    + re.escape("AGE" + chr(45) + "SECRET" + chr(45) + "KEY" + chr(45))
    + ")"
)
_ENCODED_CONTAINER = re.compile(
    r"(?<![A-Za-z0-9+/=])(?:UEsDB|H4sI|N3q8ryccAA|UmFyIQ)[A-Za-z0-9+/=]{8,}"
)
_ENVIRONMENT_PRIVATE_PATH = re.compile(
    r"(?i)(?:"
    + re.escape(chr(37) + "USERPROFILE" + chr(37))
    + "|"
    + re.escape(chr(37) + "HOMEPATH" + chr(37))
    + "|"
    + re.escape(chr(36) + "HOME")
    + "|"
    + re.escape(chr(36) + "USERPROFILE")
    + "|"
    + re.escape(chr(126))
    + r"[/\\])"
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
    if (
        "ST" + "*" + "837" in upper
        and "CLM" + "*" in upper
        and any(
            marker in upper
            for marker in ("NM1" + "*" + "IL", "HI" + "*", "REF" + "*" + "G1")
        )
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


def _walk_json(value: Any, *, path: str, findings: list[str]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}" if path else str(key)
            if _forbidden_json_key(key):
                findings.append(f"{child}:forbidden_json_key")
            findings.extend(
                f"{child}:{category}" for category in _text_categories(str(key))
            )
            _walk_json(item, path=child, findings=findings)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _walk_json(item, path=f"{path}[{index}]", findings=findings)
    elif isinstance(value, str):
        findings.extend(
            f"{path or '$'}:{category}" for category in _text_categories(value)
        )
