"""Allowlist-only, zero-PHI support output for the local Mirror candidate."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Mapping

from app.mirror import continuity_store as store
from app.mirror import continuity_store_independent as independent


SUPPORT_SCHEMA = "mirror-continuity-support-bundle-v2"
MAX_SUPPORT_BYTES = 16_384
MAX_TELEMETRY = 5_000_000_000
SUPPORT_KEYS = {
    "schema",
    "schema_version",
    "profiles",
    "row_counts",
    "integrity",
    "diagnostic_codes",
    "resource_telemetry",
    "zero_phi_boundary",
    "support_safe",
    "synthetic_only",
    "no_external_transmission_performed",
}
DIAGNOSTIC_CODES = {
    "DB_CONFORMANCE_PASS",
    "DB_CONFORMANCE_REJECTED",
    "DB_SCHEMA_REJECTED",
    "DB_INTEGRITY_REJECTED",
    "DB_RESOURCE_REJECTED",
    "DB_MISSING",
    "SUPPORT_INPUT_REJECTED",
    "SUPPORT_INTERNAL_REJECTED",
}
TELEMETRY_KEYS = {"process_tree_peak_bytes", "database_bytes", "wal_bytes", "scratch_bytes"}
PROFILE_LABELS = {
    "schema_profile": "MIRROR_CONTINUITY_SUPPORT_PROFILE_V2",
    "capability_profile": "ZERO_PHI_ALLOWLIST_V1",
    "verification_profile": "INDEPENDENT_DB_CONFORMANCE_V2",
}
_RAW_HASH = re.compile(r"^[0-9a-f]{128}$")


class SupportBoundaryError(ValueError):
    pass


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise SupportBoundaryError("support:noncanonical") from exc


def _stat_telemetry(path: str | Path) -> dict[str, int | None]:
    database = Path(path)
    wal = Path(str(database) + "-wal")
    return {
        "process_tree_peak_bytes": None,
        "database_bytes": database.stat().st_size if database.is_file() else 0,
        "wal_bytes": wal.stat().st_size if wal.is_file() else 0,
        "scratch_bytes": 0,
    }


def _safe_telemetry(path: str | Path, telemetry: Mapping[str, object] | None) -> dict[str, int | None]:
    if telemetry is None:
        candidate = _stat_telemetry(path)
    else:
        if not isinstance(telemetry, Mapping) or set(telemetry) != TELEMETRY_KEYS:
            raise SupportBoundaryError("support:telemetry-keys")
        candidate = dict(telemetry)
    result: dict[str, int | None] = {}
    for key in TELEMETRY_KEYS:
        value = candidate[key]
        if key == "process_tree_peak_bytes" and value is None:
            result[key] = None
            continue
        if type(value) is not int or value < 0 or value > MAX_TELEMETRY:
            raise SupportBoundaryError("support:telemetry-value")
        result[key] = value
    return {key: result[key] for key in ("process_tree_peak_bytes", "database_bytes", "wal_bytes", "scratch_bytes")}


def diagnostic_code(exc: BaseException) -> str:
    """Map internal failures to a fixed code; never expose exception text."""

    message = str(exc)
    if isinstance(exc, (OSError, FileNotFoundError)) or "missing" in message:
        return "DB_MISSING"
    if "byte-cap" in message or "resource" in message:
        return "DB_RESOURCE_REJECTED"
    if any(token in message for token in ("schema", "tables", "columns", "pragma", "journal", "index", "foreign-key")):
        return "DB_SCHEMA_REJECTED"
    if any(token in message for token in ("root", "receipt", "event", "artifact", "operation", "head", "state", "orphan", "replay")):
        return "DB_INTEGRITY_REJECTED"
    if isinstance(exc, independent.IndependentStoreError):
        return "DB_CONFORMANCE_REJECTED"
    return "SUPPORT_INTERNAL_REJECTED"


def _bundle(*, path: str | Path, result: Mapping[str, object] | None, code: str, telemetry: dict[str, int | None]) -> bytes:
    if code not in DIAGNOSTIC_CODES:
        code = "SUPPORT_INTERNAL_REJECTED"
    counts = {
        "artifacts": int(result.get("artifact_count", 0)) if result else 0,
        "events": int(result.get("event_count", 0)) if result else 0,
        "receipts": int(result.get("receipt_count", 0)) if result else 0,
        "heads": int(result.get("head_count", 0)) if result else 0,
    }
    if any(value < 0 or value > 64 for value in counts.values()):
        counts = {key: 0 for key in counts}
        code = "DB_RESOURCE_REJECTED"
    value = {
        "schema": SUPPORT_SCHEMA,
        "schema_version": store.SCHEMA_VERSION,
        "profiles": dict(PROFILE_LABELS),
        "row_counts": counts,
        "integrity": "PASS" if code == "DB_CONFORMANCE_PASS" else "REJECTED",
        "diagnostic_codes": [code],
        "resource_telemetry": telemetry,
        "zero_phi_boundary": True,
        "support_safe": True,
        "synthetic_only": True,
        "no_external_transmission_performed": True,
    }
    raw = _canonical(value)
    if len(raw) > MAX_SUPPORT_BYTES:
        raise SupportBoundaryError("support:byte-cap")
    return raw


def build_support_bundle(path: str | Path, telemetry: Mapping[str, object] | None = None) -> bytes:
    """Return a sanitized diagnostic artifact, never a support copy of state."""

    try:
        safe_telemetry = _safe_telemetry(path, telemetry)
    except Exception:
        safe_telemetry = {"process_tree_peak_bytes": None, "database_bytes": 0, "wal_bytes": 0, "scratch_bytes": 0}
        return _bundle(path=path, result=None, code="SUPPORT_INPUT_REJECTED", telemetry=safe_telemetry)
    try:
        result = independent.verify_database(path)
    except Exception as exc:
        return _bundle(path=path, result=None, code=diagnostic_code(exc), telemetry=safe_telemetry)
    return _bundle(path=path, result=result, code="DB_CONFORMANCE_PASS", telemetry=safe_telemetry)


def verify_support_bytes(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_SUPPORT_BYTES:
        raise SupportBoundaryError("support:byte-cap")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicate_keys, parse_constant=lambda _value: (_ for _ in ()).throw(SupportBoundaryError("support:constant")))
    except SupportBoundaryError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SupportBoundaryError("support:parse") from exc
    if not isinstance(value, dict) or set(value) != SUPPORT_KEYS:
        raise SupportBoundaryError("support:keys")
    if _canonical(value) != raw or value["schema"] != SUPPORT_SCHEMA or type(value["schema_version"]) is not int or value["schema_version"] != store.SCHEMA_VERSION:
        raise SupportBoundaryError("support:canonical")
    if value["profiles"] != PROFILE_LABELS:
        raise SupportBoundaryError("support:profiles")
    if value["integrity"] not in {"PASS", "REJECTED"} or not isinstance(value["diagnostic_codes"], list) or len(value["diagnostic_codes"]) != 1 or value["diagnostic_codes"][0] not in DIAGNOSTIC_CODES:
        raise SupportBoundaryError("support:diagnostic")
    counts = value["row_counts"]
    if not isinstance(counts, dict) or set(counts) != {"artifacts", "events", "receipts", "heads"} or any(type(item) is not int or item < 0 or item > 64 for item in counts.values()):
        raise SupportBoundaryError("support:counts")
    telemetry = value["resource_telemetry"]
    if not isinstance(telemetry, dict) or set(telemetry) != TELEMETRY_KEYS:
        raise SupportBoundaryError("support:telemetry")
    _safe_telemetry(".", telemetry)
    if value["zero_phi_boundary"] is not True or value["support_safe"] is not True or value["synthetic_only"] is not True or value["no_external_transmission_performed"] is not True:
        raise SupportBoundaryError("support:boundary-flags")
    if value["integrity"] == "PASS" and value["diagnostic_codes"] != ["DB_CONFORMANCE_PASS"]:
        raise SupportBoundaryError("support:pass-code")
    def reject_raw_hashes(item: object) -> None:
        if isinstance(item, str) and _RAW_HASH.fullmatch(item):
            raise SupportBoundaryError("support:raw-hash")
        if isinstance(item, dict):
            for nested in item.values():
                reject_raw_hashes(nested)
        elif isinstance(item, list):
            for nested in item:
                reject_raw_hashes(nested)
    reject_raw_hashes(value)
    return {"accepted": True, "support_bytes": len(raw), "diagnostic_code": value["diagnostic_codes"][0]}


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise SupportBoundaryError("support:duplicate-key")
        value[key] = item
    return value
