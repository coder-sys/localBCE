"""Independent reader for the five-table Mirror ingress owner.

This module intentionally does not import the ingress producer.  It verifies
one SQLite snapshot, replays the typed event union, and returns only bounded
state evidence.  Raw FHIR is returned only by the explicitly named internal
artifact reader used by the core owner; support/export callers use the
default raw-free projection.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
from typing import Mapping

from app.mirror import external_source_adapter_independent as external
from app.mirror import nc_medicaid_fhir_independent as fhir
from app.mirror.nc_medicaid_fhir_profile import NC_MEDICAID_PROFILE, SOURCE_CONTRACT_SCHEMA, SOURCE_CONTRACT_VERSION, _digest as _contract_digest
from app.mirror.error_boundary import raise_redacted


SCHEMA = "mirror-ingress-v4"
SCHEMA_VERSION = 4
DOMAIN = "BL/MIRROR/INGRESS/V4/"
MAX_DATABASE_BYTES = 64 * 1024 * 1024
MAX_COMPLETE_FRAME_BYTES = fhir.NC_MEDICAID_PROFILE.transport_caps["complete_frame_bytes"]
# Retained as the bounded intake-blob name used by the existing owner API;
# its value is the shared complete-frame contract cap.
MAX_RAW_ENVELOPE_BYTES = MAX_COMPLETE_FRAME_BYTES
MAX_EXTERNAL_ARTIFACT_BYTES = 64 * 1024
INTAKE_MAGIC = b"BLMIRROR-INTAKE-V2\0"
INTAKE_VERSION = 2
INTAKE_FLAGS = 0
INTAKE_DIRECTORY_ENTRY_BYTES = 4 + 4 + 4 + 64
INTAKE_HEADER_BYTES = len(INTAKE_MAGIC) + 4 + 4 + 4 + 4 + 4 + 4 + 64
MAX_EVENT_BYTES = 786_432
MAX_CONFIG_BYTES = 8_192
MAX_IDENTIFIER_BYTES = 128
GENESIS_ROOT = "0" * 128
TABLES = (
    "ingress_meta",
    "ingress_slots",
    "ingress_artifacts",
    "ingress_heads",
    "ingress_events",
)
STATES = (
    "DUE", "LEASED", "CAPTURED", "QUARANTINE_PENDING", "QUARANTINED",
    "HELD", "QUARANTINE_UNCONFIRMED", "WITHDRAWN", "PURGED",
)
EVENT_KINDS = (
    "CREATE_SLOT", "LEASE", "CAPTURE", "FAIL", "REQUEUE",
    "BEGIN_QUARANTINE", "RECOVER_QUARANTINE", "CONFIRM_QUARANTINE",
    "QUARANTINE_UNCONFIRMED", "FETCH_ATTESTATION", "ADMIT", "SUPERSEDE",
    "WITHDRAW", "ARTIFACT_PURGED", "QUARANTINE", "HOLD",
)
FIXED_FLAGS = {
    "read_only": True,
    "observation_only": True,
    "synthetic_only": True,
    "production_usable": False,
    "activation": False,
    "payment_authority": False,
    "clearance_authority": False,
    "settlement_authority": False,
    "adjudication_authority": False,
    "proofSuiteId": None,
}


def _close_readonly(
    connection: sqlite3.Connection | None,
    *,
    code: str = "ingress:database",
) -> None:
    """Close one verifier snapshot without exposing cleanup failures."""

    active = sys.exc_info()[1]
    cleanup_failed = False
    if connection is not None:
        try:
            connection.execute("ROLLBACK")
        except BaseException:
            cleanup_failed = True
        try:
            connection.close()
        except BaseException:
            cleanup_failed = True
    if cleanup_failed:
        raise_redacted(IngressVerificationError, code)
    if isinstance(active, IngressVerificationError):
        active.__cause__ = None
        active.__context__ = None
        active.__suppress_context__ = True
EVENT_KEYS = {
    "schema",
    "schema_version",
    "database_id",
    "chain_id",
    "sequence",
    "event_id",
    "event_kind",
    "stream_kind",
    "stream_id",
    "operation_id",
    "request_digest",
    "slot_id",
    "prior_state",
    "next_state",
    "attempt",
    "lease_token",
    "lease_until",
    "observed_at",
    "material",
    "material_digest",
    "payload_digest",
    "payload_length",
    "before_root",
    "after_root",
    "stream_before_root",
    "stream_after_root",
    "source_id",
    "page_index",
    "transport_attempt",
    "receipt_bytes",
}

TABLE_COLUMNS = {
    "ingress_meta": (
        "meta_id", "schema", "schema_version", "database_id", "chain_id",
        "config_digest", "config_raw", "sequence", "head_root", "watermark", "slot_count",
    ),
    "ingress_slots": (
        "slot_id", "scheduled_at", "state", "attempt", "lease_token",
        "lease_until", "artifact_id", "operation_id",
    ),
    "ingress_artifacts": (
        "artifact_id", "envelope_id", "envelope_digest", "raw", "profile_id",
        "profile_version", "profile_digest", "observation_time", "fetched_at",
        "source_status", "failure_code", "freshness", "page_complete",
        "snapshot_id", "snapshot_root", "content_root", "page_count",
        "resource_count", "event_sequence",
    ),
    "ingress_heads": (
        "stream_kind", "stream_id", "artifact_id", "head_root", "event_sequence",
    ),
    "ingress_events": (
        "sequence", "event_id", "event_kind", "database_id", "chain_id",
        "stream_kind", "stream_id", "operation_id", "request_digest", "slot_id",
        "prior_state", "next_state", "attempt", "lease_token", "lease_until",
        "observed_at", "material_digest", "payload_digest", "payload_length",
        "before_root", "after_root", "stream_before_root", "stream_after_root",
        "event_raw", "receipt_digest", "source_id", "page_index",
        "transport_attempt", "receipt_bytes",
    ),
}
EXPLICIT_INDEXES = (
    "ingress_events_chain_idx",
    "ingress_events_operation_idx",
    "ingress_events_observed_at_idx",
    "ingress_fetch_natural_key_idx",
    "ingress_slots_due_idx",
)
INDEX_DEFINITIONS = {
    "ingress_events_chain_idx": (
        "ingress_events", 1, 0, ("chain_id", "sequence"),
        "create unique index ingress_events_chain_idx on ingress_events(chain_id,sequence)",
    ),
    "ingress_events_operation_idx": (
        "ingress_events", 0, 0, ("operation_id", "event_kind"),
        "create index ingress_events_operation_idx on ingress_events(operation_id,event_kind)",
    ),
    "ingress_events_observed_at_idx": (
        "ingress_events", 0, 0, ("observed_at", "sequence"),
        "create index ingress_events_observed_at_idx on ingress_events(observed_at,sequence)",
    ),
    "ingress_fetch_natural_key_idx": (
        "ingress_events", 1, 1, ("source_id", "slot_id", "page_index", "transport_attempt"),
        "create unique index ingress_fetch_natural_key_idx on ingress_events(source_id,slot_id,page_index,transport_attempt) where event_kind='fetch_attestation'",
    ),
    "ingress_slots_due_idx": (
        "ingress_slots", 0, 0, ("state", "lease_until", "slot_id"),
        "create index ingress_slots_due_idx on ingress_slots(state,lease_until,slot_id)",
    ),
}
_REPARSE_POINT = 0x400
_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")


class IngressVerificationError(ValueError):
    """Fixed, public-safe ingress verification failure."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=True, allow_nan=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise IngressVerificationError("ingress:noncanonical") from None


_PUBLIC_ARTIFACT_KEYS = (
    "profile_id", "profile_version", "source_status", "failure_code",
    "freshness", "page_complete", "page_count", "resource_count",
    "event_sequence",
)


def _public_artifact(value: Mapping[str, object]) -> dict[str, object]:
    try:
        return {key: value[key] for key in _PUBLIC_ARTIFACT_KEYS}
    except (KeyError, TypeError):
        raise IngressVerificationError("ingress:projection") from None


def _safe_identifier(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise IngressVerificationError(label)
    if len(value) > MAX_IDENTIFIER_BYTES:
        raise IngressVerificationError(label)
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError:
        raise IngressVerificationError(label) from None
    if (
        len(raw) > MAX_IDENTIFIER_BYTES
        or not ("A" <= value[0] <= "Z" or "a" <= value[0] <= "z" or "0" <= value[0] <= "9")
        or any(
            not (
                "A" <= character <= "Z"
                or "a" <= character <= "z"
                or "0" <= character <= "9"
                or character in "._:-"
            )
            for character in value
        )
    ):
        raise IngressVerificationError(label)
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IngressVerificationError("ingress:duplicate-key")
        result[key] = value
    return result


def _parse(raw: bytes, label: str, *, max_bytes: int = MAX_EVENT_BYTES) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > max_bytes:
        raise IngressVerificationError(label)
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                IngressVerificationError("ingress:constant")
            ),
        )
    except IngressVerificationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise IngressVerificationError(label) from None
    if not isinstance(value, dict) or _canonical(value) != raw:
        raise IngressVerificationError(label)
    return value


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((DOMAIN + label + "\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _raw_digest(label: str, raw: bytes) -> str:
    digest = hashlib.sha3_512()
    digest.update((DOMAIN + label + "\0").encode("ascii"))
    digest.update(raw)
    return digest.hexdigest()


def _lease_token_digest(
    database_id: str,
    config_digest: str,
    slot_id: str,
    attempt: int,
    raw_token: str,
) -> str:
    """Derive the only lease capability representation stored by ingress."""
    return _digest(
        "lease-token",
        {
            "database_id": database_id,
            "config_digest": config_digest,
            "slot_id": slot_id,
            "attempt": attempt,
            "raw_token": raw_token,
        },
    )


def _hex(value: object, label: str) -> str:
    if type(value) is not str or len(value) != 128 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise IngressVerificationError(label)
    return value


def content_root(resources: object) -> str:
    if not isinstance(resources, list):
        raise IngressVerificationError("ingress:resources")
    normalized: list[dict[str, object]] = []
    for resource in resources:
        if not isinstance(resource, dict):
            raise IngressVerificationError("ingress:resources")
        resource_type = resource.get("resourceType")
        resource_id = resource.get("id")
        if type(resource_type) is not str or type(resource_id) is not str:
            raise IngressVerificationError("ingress:resource-identity")
        normalized.append({"resourceType": resource_type, "id": resource_id, "resource": resource})
    normalized.sort(key=lambda value: (str(value["resourceType"]), str(value["id"])))
    return _digest("content-root", normalized)


def _unpack_intake_frame(raw: object) -> tuple[bytes, bytes, tuple[tuple[int, int, int, str], ...]]:
    """Return external evidence and the exact FHIR envelope from one frame."""
    if type(raw) is not bytes or not raw or len(raw) > MAX_COMPLETE_FRAME_BYTES:
        raise IngressVerificationError("ingress:artifact-raw")
    if len(raw) < INTAKE_HEADER_BYTES or raw[:len(INTAKE_MAGIC)] != INTAKE_MAGIC:
        raise IngressVerificationError("ingress:intake-frame")
    offset = len(INTAKE_MAGIC)
    version = int.from_bytes(raw[offset:offset + 4], "big")
    flags = int.from_bytes(raw[offset + 4:offset + 8], "big")
    evidence_length = int.from_bytes(raw[offset + 8:offset + 12], "big")
    envelope_length = int.from_bytes(raw[offset + 12:offset + 16], "big")
    page_count = int.from_bytes(raw[offset + 16:offset + 20], "big")
    aggregate_length = int.from_bytes(raw[offset + 20:offset + 24], "big")
    aggregate_digest = raw[offset + 24:offset + 88].hex()
    if version != INTAKE_VERSION or flags != INTAKE_FLAGS:
        raise IngressVerificationError("ingress:intake-header")
    if not 1 <= evidence_length <= MAX_EXTERNAL_ARTIFACT_BYTES or not 1 <= envelope_length <= fhir.NC_MEDICAID_PROFILE.transport_caps["max_envelope_bytes"]:
        raise IngressVerificationError("ingress:intake-frame")
    if not 1 <= page_count <= fhir.NC_MEDICAID_PROFILE.transport_caps["max_pages"]:
        raise IngressVerificationError("ingress:intake-frame")
    def checked_add(*values: int, limit: int = MAX_COMPLETE_FRAME_BYTES) -> int:
        if any(type(value) is not int or value < 0 for value in values):
            raise IngressVerificationError("ingress:intake-arithmetic")
        total = sum(values)
        if total > limit:
            raise IngressVerificationError("ingress:intake-arithmetic")
        return total

    def checked_mul(left: int, right: int, limit: int = MAX_COMPLETE_FRAME_BYTES) -> int:
        if type(left) is not int or type(right) is not int or left < 0 or right < 0 or left > limit or right > limit:
            raise IngressVerificationError("ingress:intake-arithmetic")
        product = left * right
        if product > limit:
            raise IngressVerificationError("ingress:intake-arithmetic")
        return product

    directory_bytes = checked_mul(page_count, INTAKE_DIRECTORY_ENTRY_BYTES)
    directory_end = checked_add(INTAKE_HEADER_BYTES, directory_bytes)
    payload_end = checked_add(directory_end, evidence_length, envelope_length)
    if payload_end != len(raw) or aggregate_length > envelope_length:
        raise IngressVerificationError("ingress:intake-frame")
    directory: list[tuple[int, int, int, str]] = []
    cursor = INTAKE_HEADER_BYTES
    for expected_index in range(page_count):
        index = int.from_bytes(raw[cursor:cursor + 4], "big")
        page_offset = int.from_bytes(raw[cursor + 4:cursor + 8], "big")
        page_length = int.from_bytes(raw[cursor + 8:cursor + 12], "big")
        page_digest = raw[cursor + 12:cursor + 76].hex()
        cursor += INTAKE_DIRECTORY_ENTRY_BYTES
        if index != expected_index or len(page_digest) != 128 or any(char not in "0123456789abcdef" for char in page_digest):
            raise IngressVerificationError("ingress:intake-page-directory")
        directory.append((index, page_offset, page_length, page_digest))
    evidence_start = directory_end
    envelope_start = evidence_start + evidence_length
    envelope_raw = raw[envelope_start:envelope_start + envelope_length]
    try:
        envelope = json.loads(
            envelope_raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(IngressVerificationError("ingress:intake-envelope")),
        )
    except IngressVerificationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        raise IngressVerificationError("ingress:intake-envelope") from None
    if not isinstance(envelope, dict) or _canonical(envelope) != envelope_raw or not isinstance(envelope.get("pages"), list) or len(envelope["pages"]) != page_count:
        raise IngressVerificationError("ingress:intake-envelope")
    aggregate = bytearray()
    previous_end = 0
    search_from = 0
    for expected_index, page_offset, page_length, page_digest in directory:
        page = envelope["pages"][expected_index]
        try:
            page_raw = _canonical(page)
        except IngressVerificationError:
            raise
        page_end = checked_add(page_offset, page_length, limit=envelope_length)
        expected_offset = envelope_raw.find(page_raw, search_from)
        if (
            page_offset < previous_end
            or page_length != len(page_raw)
            or page_end > envelope_length
            or expected_offset != page_offset
        ):
            raise IngressVerificationError("ingress:intake-page-directory")
        if envelope_raw[page_offset:page_offset + page_length] != page_raw:
            raise IngressVerificationError("ingress:intake-page-directory")
        if not isinstance(page, dict) or page.get("sequence") != expected_index or page.get("body_digest") != page_digest:
            raise IngressVerificationError("ingress:intake-page-binding")
        aggregate.extend(page_raw)
        previous_end = page_end
        search_from = page_end
    if aggregate_length != len(aggregate) or _raw_digest("frame-pages", bytes(aggregate)) != aggregate_digest:
        raise IngressVerificationError("ingress:intake-aggregate")
    start = directory_end
    return raw[start:start + evidence_length], envelope_raw, tuple(directory)


def _external_policy(config: Mapping[str, object]) -> dict[str, object]:
    value = config.get("external_policy")
    if not isinstance(value, dict):
        raise IngressVerificationError("ingress:external-policy")
    return value


def _attestation_digest(value: Mapping[str, object]) -> str:
    return _digest("attestation", dict(value))


def _event_root(
    *,
    sequence: int,
    previous: str,
    event_id: str,
    event_kind: str,
    stream_kind: str,
    stream_id: str,
    slot_id: str,
    next_state: str,
    observed_at: int,
    material_digest: str,
) -> str:
    return _digest(
        "event-root",
        {
            "sequence": sequence,
            "previous_root": previous,
            "event_id": event_id,
            "event_kind": event_kind,
            "stream_kind": stream_kind,
            "stream_id": stream_id,
            "slot_id": slot_id,
            "next_state": next_state,
            "observed_at": observed_at,
            "material_digest": material_digest,
        },
    )


def _stream_root(
    *,
    sequence: int,
    previous: str,
    event_id: str,
    stream_kind: str,
    stream_id: str,
    next_state: str,
    observed_at: int,
    material_digest: str,
) -> str:
    return _digest(
        "stream-root",
        {
            "sequence": sequence,
            "previous_root": previous,
            "event_id": event_id,
            "stream_kind": stream_kind,
            "stream_id": stream_id,
            "next_state": next_state,
            "observed_at": observed_at,
            "material_digest": material_digest,
        },
    )


def _table_names(connection: sqlite3.Connection) -> tuple[str, ...]:
    rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    return tuple(str(row[0]) for row in rows)


def _columns(connection: sqlite3.Connection, table: str) -> tuple[str, ...]:
    return tuple(str(row[1]) for row in connection.execute(
        "SELECT * FROM pragma_table_info(?) ORDER BY cid", (table,)
    ).fetchall())


def _index_names(connection: sqlite3.Connection) -> tuple[str, ...]:
    return tuple(str(row[0]) for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='index' "
        "AND name NOT LIKE 'sqlite_autoindex_%' ORDER BY name"
    ).fetchall())


def _normalize_index_sql(value: object) -> str:
    if type(value) is not str:
        raise IngressVerificationError("ingress:indexes")
    return " ".join(value.strip().lower().split())


def _index_definitions(connection: sqlite3.Connection) -> dict[str, tuple[object, ...]]:
    rows = connection.execute(
        "SELECT name,tbl_name,sql FROM sqlite_master WHERE type='index' "
        "AND name NOT LIKE 'sqlite_autoindex_%' ORDER BY name"
    ).fetchall()
    if {str(row[0]) for row in rows} != set(EXPLICIT_INDEXES):
        raise IngressVerificationError("ingress:indexes")
    actual: dict[str, tuple[object, ...]] = {}
    for row in rows:
        name = str(row[0])
        expected = INDEX_DEFINITIONS.get(name)
        if expected is None:
            raise IngressVerificationError("ingress:indexes")
        table, unique, partial, columns, sql = expected
        escaped_table = str(row[1]).replace("'", "''")
        index_rows = connection.execute(f"PRAGMA index_list('{escaped_table}')").fetchall()
        index_row = next((item for item in index_rows if str(item[1]) == name), None)
        if index_row is None or int(index_row[2]) != unique or int(index_row[4]) != partial:
            raise IngressVerificationError("ingress:indexes")
        escaped_name = name.replace("'", "''")
        actual_columns = tuple(str(item[2]) for item in connection.execute(
            f"PRAGMA index_info('{escaped_name}')"
        ).fetchall())
        if str(row[1]) != table or actual_columns != columns or _normalize_index_sql(row[2]) != sql:
            raise IngressVerificationError("ingress:indexes")
        actual[name] = expected
    return actual


def _is_reparse(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)


def _sidecar_present(database: Path) -> bool:
    return any(os.path.lexists(os.fspath(database) + suffix) for suffix in _SIDECAR_SUFFIXES)


def _owned_restore_hardlink(database: Path, info: os.stat_result) -> bool:
    """Permit only the transient hard link owned by the publication marker."""
    if info.st_nlink != 2:
        return False
    if database.name == "stage.db" and database.parent.name.startswith(".") and ".restore-v2-" in database.parent.name:
        candidates = (database.parent,)
    else:
        prefix = f".{database.name}.restore-v2-"
        try:
            candidates = tuple(item for item in database.parent.iterdir() if item.name.startswith(prefix))
        except OSError:
            return False
    for namespace in candidates:
        try:
            namespace_info = os.lstat(namespace)
            stage = namespace / "stage.db"
            marker = namespace / "marker.json"
            stage_info = os.lstat(stage)
            marker_info = os.lstat(marker)
            if (
                not stat.S_ISDIR(namespace_info.st_mode)
                or _is_reparse(namespace_info)
                or not stat.S_ISREG(stage_info.st_mode)
                or _is_reparse(stage_info)
                or stage_info.st_nlink != 2
                or (stage_info.st_dev, stage_info.st_ino) != (info.st_dev, info.st_ino)
                or not stat.S_ISREG(marker_info.st_mode)
                or marker_info.st_size > 4096
            ):
                continue
            target_name = namespace.name[1:].split(".restore-v2-", 1)[0]
            target_info = os.lstat(namespace.parent / target_name)
            if (
                not stat.S_ISREG(target_info.st_mode)
                or target_info.st_nlink != 2
                or (target_info.st_dev, target_info.st_ino) != (info.st_dev, info.st_ino)
            ):
                continue
            with marker.open("rb") as stream:
                marker_raw = stream.read(4097)
            marker_value = json.loads(marker_raw.decode("ascii"))
            if _canonical(marker_value) != marker_raw or set(marker_value) != {
                "schema", "schema_version", "target_identity", "target_name",
                "namespace_name", "stage_name", "export_root",
            }:
                continue
            if (
                marker_value["schema"] != "mirror-restore-publication-stage-v2"
                or marker_value["schema_version"] != 2
                or marker_value["target_name"] != target_name
                or marker_value["namespace_name"] != namespace.name
                or marker_value["stage_name"] != "stage.db"
                or type(marker_value["target_identity"]) is not str
                or len(marker_value["target_identity"]) != 128
                or type(marker_value["export_root"]) is not str
                or len(marker_value["export_root"]) != 128
                or any(character not in "0123456789abcdef" for character in marker_value["target_identity"])
                or any(character not in "0123456789abcdef" for character in marker_value["export_root"])
            ):
                continue
            return True
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            continue
    return False


def _parent_identity(database: Path) -> os.stat_result:
    try:
        info = os.lstat(database.parent)
    except OSError:
        raise IngressVerificationError("ingress:database") from None
    if not stat.S_ISDIR(info.st_mode) or _is_reparse(info):
        raise IngressVerificationError("ingress:database")
    return info


def _path_identity(database: Path, *, allow_missing: bool) -> tuple[int, int, int, int] | None:
    _parent_identity(database)
    if _sidecar_present(database):
        raise IngressVerificationError("ingress:database")
    try:
        info = os.lstat(database)
    except FileNotFoundError:
        if allow_missing:
            return None
        raise IngressVerificationError("ingress:database") from None
    except OSError:
        raise IngressVerificationError("ingress:database") from None
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or _is_reparse(info)
        or (info.st_nlink != 1 and not _owned_restore_hardlink(database, info))
        or info.st_size > MAX_DATABASE_BYTES
    ):
        raise IngressVerificationError("ingress:database")
    return (int(info.st_dev), int(info.st_ino), int(info.st_nlink), int(info.st_size))


def _check_page_limits(connection: sqlite3.Connection, *, configure: bool) -> None:
    try:
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        if page_size <= 0 or page_count < 0 or page_count * page_size > MAX_DATABASE_BYTES:
            raise IngressVerificationError("ingress:capacity")
        max_pages = MAX_DATABASE_BYTES // page_size
        if max_pages <= 0:
            raise IngressVerificationError("ingress:capacity")
        if configure:
            configured = int(connection.execute(f"PRAGMA max_page_count={max_pages}").fetchone()[0])
        else:
            configured = int(connection.execute("PRAGMA max_page_count").fetchone()[0])
        if configured <= 0 or (configure and (configured > max_pages or configured * page_size > MAX_DATABASE_BYTES)):
            raise IngressVerificationError("ingress:capacity")
    except IngressVerificationError:
        raise
    except (OSError, sqlite3.Error, TypeError, ValueError):
        raise IngressVerificationError("ingress:capacity") from None


def _open(path: str | Path) -> sqlite3.Connection:
    database = Path(path)
    connection: sqlite3.Connection | None = None
    try:
        identity = _path_identity(database, allow_missing=False)
        if identity is None:
            raise IngressVerificationError("ingress:database")
        connection = sqlite3.connect(
            database.absolute().as_uri() + "?mode=ro",
            uri=True,
            isolation_level=None,
            timeout=0.25,
        )
        connection.row_factory = sqlite3.Row
        if _path_identity(database, allow_missing=False) != identity:
            _close_readonly(connection)
            raise IngressVerificationError("ingress:database")
        if str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower() != "delete":
            raise IngressVerificationError("ingress:database")
        _check_page_limits(connection, configure=False)
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        return connection
    except IngressVerificationError:
        _close_readonly(connection)
        raise
    except (OSError, sqlite3.Error, ValueError):
        _close_readonly(connection)
        raise IngressVerificationError("ingress:database") from None


def _meta(connection: sqlite3.Connection) -> sqlite3.Row:
    row = connection.execute("SELECT * FROM ingress_meta").fetchone()
    if row is None:
        raise IngressVerificationError("ingress:meta")
    expected = (
        "meta_id", "schema", "schema_version", "database_id", "chain_id",
        "config_digest", "config_raw", "sequence", "head_root", "watermark", "slot_count",
    )
    if tuple(row.keys()) != expected or row["meta_id"] != 1:
        raise IngressVerificationError("ingress:meta")
    if row["schema"] != SCHEMA or row["schema_version"] != SCHEMA_VERSION:
        raise IngressVerificationError("ingress:schema")
    _hex(row["config_digest"], "ingress:config")
    _safe_identifier(row["database_id"], "ingress:database-id")
    _safe_identifier(row["chain_id"], "ingress:chain-id")
    config_raw = row["config_raw"]
    if type(config_raw) is not bytes or not config_raw or len(config_raw) > MAX_CONFIG_BYTES:
        raise IngressVerificationError("ingress:config")
    config = _parse(config_raw, "ingress:config", max_bytes=MAX_CONFIG_BYTES)
    expected_config_keys = {
        "schema", "schema_version", "database_id", "chain_id", "policy_digest",
        "authorization_digest", "terms_digest", "source_contract", "source_contract_digest",
        "external_policy", "external_policy_digest", "cadence_seconds", "effective_start",
        "effective_end", "max_slots", "max_attempts", "lease_seconds", "flags",
    }
    if set(config) != expected_config_keys:
        raise IngressVerificationError("ingress:config")
    if (
        config["schema"] != SCHEMA
        or config["schema_version"] != SCHEMA_VERSION
        or config["database_id"] != row["database_id"]
        or config["chain_id"] != row["chain_id"]
        or config["source_contract"] != NC_MEDICAID_PROFILE.material()
        or config["source_contract_digest"] != NC_MEDICAID_PROFILE.profile_digest
        or _contract_digest("source-contract", config["source_contract"]) != config["source_contract_digest"]
        or config["flags"] != FIXED_FLAGS
        or _digest("config", config) != row["config_digest"]
    ):
        raise IngressVerificationError("ingress:config")
    for key in ("policy_digest", "authorization_digest", "terms_digest", "source_contract_digest", "external_policy_digest"):
        _hex(config[key], "ingress:config")
    try:
        policy = _external_policy(config)
        if external.policy_digest(policy) != config["external_policy_digest"]:
            raise IngressVerificationError("ingress:external-policy")
    except IngressVerificationError:
        raise
    except Exception:
        raise IngressVerificationError("ingress:external-policy") from None
    if (
        type(config["cadence_seconds"]) is not int
        or config["cadence_seconds"] <= 0
        or type(config["effective_start"]) is not int
        or type(config["effective_end"]) is not int
        or config["effective_start"] >= config["effective_end"]
        or type(config["max_slots"]) is not int
        or not 1 <= config["max_slots"] <= 4096
        or type(config["max_attempts"]) is not int
        or not 1 <= config["max_attempts"] <= 8
        or type(config["lease_seconds"]) is not int
        or not 1 <= config["lease_seconds"] <= 86_400
    ):
        raise IngressVerificationError("ingress:config")
    if type(row["sequence"]) is not int or row["sequence"] < 0:
        raise IngressVerificationError("ingress:sequence")
    if type(row["watermark"]) is not int or row["watermark"] < 0 or type(row["slot_count"]) is not int or row["slot_count"] < 0:
        raise IngressVerificationError("ingress:watermark")
    if row["head_root"] != GENESIS_ROOT and not (
        type(row["head_root"]) is str and len(row["head_root"]) == 128
    ):
        raise IngressVerificationError("ingress:head-root")
    return row


def _verify_artifact(row: sqlite3.Row, *, config: Mapping[str, object]) -> dict[str, object]:
    expected = (
        "artifact_id", "envelope_id", "envelope_digest", "raw", "profile_id",
        "profile_version", "profile_digest", "observation_time", "fetched_at",
        "source_status", "failure_code", "freshness", "page_complete",
        "snapshot_id", "snapshot_root", "content_root", "page_count",
        "resource_count", "event_sequence",
    )
    if tuple(row.keys()) != expected:
        raise IngressVerificationError("ingress:artifact-columns")
    _hex(row["artifact_id"], "ingress:artifact-id")
    raw = row["raw"]
    evidence_raw, envelope_raw, frame_pages = _unpack_intake_frame(raw)
    if row["envelope_digest"] != _raw_digest("envelope", envelope_raw):
        raise IngressVerificationError("ingress:artifact-digest")
    try:
        result = fhir.verify_bytes(envelope_raw)
    except Exception:
        raise IngressVerificationError("ingress:envelope") from None
    try:
        external_result = external.verify_bytes(evidence_raw, policy=_external_policy(config), capture_raw=envelope_raw)
    except Exception:
        raise IngressVerificationError("ingress:external-evidence") from None
    if external_result.get("derived_status") != "OBSERVATION_ADMITTED" and result["source_status"] == "COMPLETE":
        raise IngressVerificationError("ingress:external-status")
    if tuple((index, digest) for index, _offset, _length, digest in frame_pages) != tuple(external_result["page_bindings"]):
        raise IngressVerificationError("ingress:intake-page-binding")
    if tuple(result["page_digests"]) != tuple(digest for _index, _offset, _length, digest in frame_pages):
        raise IngressVerificationError("ingress:intake-page-binding")
    checks = {
        "envelope_id": result["envelope_id"],
        "profile_id": NC_MEDICAID_PROFILE.source_profile_id,
        "profile_version": NC_MEDICAID_PROFILE.version,
        "profile_digest": NC_MEDICAID_PROFILE.profile_digest,
        "observation_time": result["observation_time"],
        "fetched_at": result["fetched_at"],
        "source_status": result["source_status"],
        "failure_code": result["failure_code"],
        "freshness": result["freshness"],
        "page_complete": result["page_complete"],
        "snapshot_id": result["snapshot_id"],
        "snapshot_root": result["snapshot_root"],
        "content_root": content_root(result["resources"]),
        "page_count": result["page_count"],
        "resource_count": result["resource_count"],
    }
    for key, value in checks.items():
        if row[key] != value:
            raise IngressVerificationError("ingress:artifact-binding")
    _hex(row["envelope_id"], "ingress:envelope-id")
    _hex(row["envelope_digest"], "ingress:envelope-digest")
    _hex(row["snapshot_id"], "ingress:snapshot-id")
    _hex(row["snapshot_root"], "ingress:snapshot-root")
    _hex(row["content_root"], "ingress:content-root")
    expected_id = _digest("artifact-id", {"intake_digest": _raw_digest("intake", raw), "envelope_digest": row["envelope_digest"], "envelope_id": row["envelope_id"], "external_artifact_id": external_result["artifact_id"], "external_artifact_digest": _raw_digest("external-artifact", evidence_raw), "profile_digest": row["profile_digest"], "observation_time": row["observation_time"], "snapshot_id": row["snapshot_id"]})
    if row["artifact_id"] != expected_id:
        raise IngressVerificationError("ingress:artifact-id")
    if type(row["event_sequence"]) is not int or row["event_sequence"] <= 0:
        raise IngressVerificationError("ingress:artifact-event-sequence")
    return {
        "artifact_id": row["artifact_id"],
        "envelope_id": row["envelope_id"],
        "envelope_digest": row["envelope_digest"],
        "profile_id": row["profile_id"],
        "profile_version": row["profile_version"],
        "profile_digest": row["profile_digest"],
        "observation_time": row["observation_time"],
        "fetched_at": row["fetched_at"],
        "source_status": row["source_status"],
        "failure_code": row["failure_code"],
        "freshness": row["freshness"],
        "page_complete": row["page_complete"],
        "snapshot_id": row["snapshot_id"],
        "snapshot_root": row["snapshot_root"],
        "content_root": row["content_root"],
        "page_count": row["page_count"],
        "resource_count": row["resource_count"],
        "event_sequence": row["event_sequence"],
        "_stored_event_sequence": row["event_sequence"],
        "_terminal_event_sequence": None,
        "_terminal_event_kind": None,
        "_terminal_slot_id": None,
        "raw": raw,
        "intake_frame": raw,
        "envelope_raw": envelope_raw,
        "external_evidence_raw": evidence_raw,
        "frame_pages": frame_pages,
        "external_artifact_id": external_result["artifact_id"],
        "external_artifact_digest": _raw_digest("external-artifact", evidence_raw),
        "source_contract_digest": external_result["source_contract_digest"],
        "capture_id": external_result["capture_id"],
        "capture_context": {key: external_result[key] for key in ("subject_id", "credential_id", "enrollment_id", "subject_locator_digest", "observed_at", "fetched_at")},
        "page_bindings": external_result["page_bindings"],
        "page_digests": tuple(digest for _index, digest in external_result["page_bindings"]),
        "result": result,
    }


def _verify_fetch_receipt(
    receipt_raw: bytes,
    *,
    artifact: Mapping[str, object],
    slot_id: str,
    source_id: str,
    page_index: int,
    transport_attempt: int,
    lease_attempt: int,
    observed_at: int,
) -> dict[str, object]:
    value = _parse(receipt_raw, "ingress:fetch-receipt")
    expected_keys = {
        "schema", "schema_version", "artifact_id", "source_id", "slot_id",
        "page_index", "lease_attempt", "transport_attempt", "attestation_digest",
        "request_identity", "response_digest", "status", "retry_after_seconds",
        "response_url", "redirect", "failure_code", "transport_error",
        "evidence_class", "selected", "observed_at",
    }
    if set(value) != expected_keys or value["schema"] != SCHEMA or value["schema_version"] != SCHEMA_VERSION:
        raise IngressVerificationError("ingress:fetch-receipt-keys")
    page_evidence = artifact["result"].get("page_evidence") if isinstance(artifact.get("result"), Mapping) else None
    if not isinstance(page_evidence, tuple) or page_index >= len(page_evidence):
        raise IngressVerificationError("ingress:fetch-evidence")
    page = page_evidence[page_index]
    attempts = page.get("attempts") if isinstance(page, Mapping) else None
    if not isinstance(attempts, tuple) or transport_attempt >= len(attempts):
        raise IngressVerificationError("ingress:fetch-evidence")
    expected = attempts[transport_attempt]
    if not isinstance(expected, Mapping):
        raise IngressVerificationError("ingress:fetch-evidence")
    expected_request_identity = page.get("request_identity")
    if not isinstance(expected_request_identity, str):
        raise IngressVerificationError("ingress:fetch-evidence")
    if (
        value["artifact_id"] != artifact["artifact_id"]
        or value["source_id"] != source_id
        or value["source_id"] != NC_MEDICAID_PROFILE.source_profile_id
        or value["slot_id"] != slot_id
        or value["page_index"] != page_index
        or value["lease_attempt"] != lease_attempt
        or value["transport_attempt"] != transport_attempt
        or value["request_identity"] != expected_request_identity
        or value["response_digest"] != expected["response_digest"]
        or value["status"] != expected["status"]
        or value["retry_after_seconds"] != expected["retry_after_seconds"]
        or value["response_url"] != expected["response_url"]
        or value["redirect"] != expected["redirect"]
        or value["failure_code"] != expected["failure_code"]
        or value["transport_error"] != expected["transport_error"]
        or value["evidence_class"] != "SYNTHETIC_FIXTURE_UNAUTHENTICATED"
        or value["selected"] != expected["selected"]
        or value["observed_at"] != observed_at
    ):
        raise IngressVerificationError("ingress:fetch-binding")
    material = {
        "artifact_id": value["artifact_id"],
        "page_index": value["page_index"],
        "lease_attempt": value["lease_attempt"],
        "transport_attempt": value["transport_attempt"],
        "request_identity": value["request_identity"],
        "response_digest": value["response_digest"],
        "status": value["status"],
        "retry_after_seconds": value["retry_after_seconds"],
        "response_url": value["response_url"],
        "redirect": value["redirect"],
        "failure_code": value["failure_code"],
        "transport_error": value["transport_error"],
        "evidence_class": value["evidence_class"],
        "selected": value["selected"],
        "observed_at": value["observed_at"],
    }
    if value["attestation_digest"] != _attestation_digest(material):
        raise IngressVerificationError("ingress:fetch-digest")
    return value


def _verify_capacity_hold_receipt(
    receipt_raw: bytes,
    *,
    slot_id: str,
    artifact_id: str,
) -> None:
    value = _parse(receipt_raw, "ingress:capacity-receipt")
    if set(value) != {"schema", "schema_version", "kind", "slot_id", "artifact_id", "reason"}:
        raise IngressVerificationError("ingress:capacity-receipt")
    if (
        value["schema"] != SCHEMA
        or value["schema_version"] != SCHEMA_VERSION
        or value["kind"] != "CAPACITY_HOLD"
        or value["slot_id"] != slot_id
        or value["artifact_id"] != artifact_id
        or value["reason"] != "CAPACITY"
    ):
        raise IngressVerificationError("ingress:capacity-receipt")
    _hex(artifact_id, "ingress:capacity-artifact")


def _verify_event(
    row: sqlite3.Row,
    *,
    meta: sqlite3.Row,
    config: Mapping[str, object],
    previous_root: str,
    slot_states: dict[str, str],
    slot_attempts: dict[str, int],
    slot_schedules: Mapping[str, int],
    slot_operations: dict[str, str],
    slot_times: dict[str, int],
    global_observed_at: list[int | None],
    slot_leases: dict[str, tuple[str | None, int | None, int]],
    artifacts: Mapping[str, Mapping[str, object]],
    capture_operations: dict[str, str],
    fetch_capture_operations: dict[str, str],
    heads: dict[tuple[str, str], tuple[str | None, str, int]],
    stream_roots: dict[tuple[str, str], str],
    fetches: dict[str, list[dict[str, object]]],
) -> str:
    if tuple(row.keys()) != (
        "sequence", "event_id", "event_kind", "database_id", "chain_id",
        "stream_kind", "stream_id", "operation_id", "request_digest", "slot_id", "prior_state",
        "next_state", "attempt", "lease_token", "lease_until",
        "observed_at",
        "material_digest", "payload_digest", "payload_length",
        "before_root", "after_root", "stream_before_root", "stream_after_root",
        "event_raw", "receipt_digest",
        "source_id", "page_index", "transport_attempt", "receipt_bytes",
    ):
        raise IngressVerificationError("ingress:event-columns")
    if row["sequence"] <= 0 or row["database_id"] != meta["database_id"] or row["chain_id"] != meta["chain_id"]:
        raise IngressVerificationError("ingress:event-binding")
    _hex(row["event_id"], "ingress:event-id")
    _hex(row["operation_id"], "ingress:operation")
    _hex(row["request_digest"], "ingress:request")
    _hex(row["slot_id"], "ingress:slot")
    if row["lease_token"] is not None:
        _hex(row["lease_token"], "ingress:lease-token")
    raw = row["event_raw"]
    if type(raw) is not bytes or not raw or len(raw) > MAX_EVENT_BYTES:
        raise IngressVerificationError("ingress:event-raw")
    value = _parse(raw, "ingress:event-raw")
    if set(value) != EVENT_KEYS or not isinstance(value.get("material"), dict):
        raise IngressVerificationError("ingress:event-keys")
    material = value["material"]
    if value["material_digest"] != _digest("material", material):
        raise IngressVerificationError("ingress:material-digest")
    for key in EVENT_KEYS:
        if key not in row.keys():
            continue
        row_value = row[key]
        if key == "receipt_bytes":
            if row_value is not None:
                if type(row_value) is not bytes:
                    raise IngressVerificationError("ingress:event-receipt")
                row_value = row_value.decode("ascii")
        if value[key] != row_value:
            raise IngressVerificationError("ingress:event-receipt")
    if row["before_root"] != previous_root or row["event_kind"] not in EVENT_KINDS:
        raise IngressVerificationError("ingress:event-order")
    if type(row["observed_at"]) is not int or row["observed_at"] < 0:
        raise IngressVerificationError("ingress:event-time")
    if row["event_id"] != _digest("event-id", {key: value[key] for key in EVENT_KEYS if key not in {"event_id", "after_root", "stream_after_root"}}):
        raise IngressVerificationError("ingress:event-id")
    if row["receipt_digest"] != _raw_digest("receipt", raw):
        raise IngressVerificationError("ingress:receipt")
    if row["stream_before_root"] != stream_roots.get((row["stream_kind"], row["stream_id"]), GENESIS_ROOT):
        raise IngressVerificationError("ingress:stream-order")
    expected_stream_after = _stream_root(
        sequence=row["sequence"],
        previous=row["stream_before_root"],
        event_id=row["event_id"],
        stream_kind=row["stream_kind"],
        stream_id=row["stream_id"],
        next_state=row["next_state"],
        observed_at=row["observed_at"],
        material_digest=row["material_digest"],
    )
    if row["stream_after_root"] != expected_stream_after:
        raise IngressVerificationError("ingress:stream-root")
    expected_after = _event_root(
        sequence=row["sequence"],
        previous=previous_root,
        event_id=row["event_id"],
        event_kind=row["event_kind"],
        stream_kind=row["stream_kind"],
        stream_id=row["stream_id"],
        slot_id=row["slot_id"],
        next_state=row["next_state"],
        observed_at=row["observed_at"],
        material_digest=row["material_digest"],
    )
    if row["after_root"] != expected_after:
        raise IngressVerificationError("ingress:event-root")
    kind = str(row["event_kind"])
    expected_operation: str
    expected_request: str
    expected_payload: str
    expected_payload_length: int
    if kind == "CREATE_SLOT":
        if set(material) != {"slot_id", "scheduled_at", "operation_id"}:
            raise IngressVerificationError("ingress:event-material")
        scheduled_at = material["scheduled_at"]
        if (
            material["slot_id"] != row["slot_id"]
            or type(scheduled_at) is not int
            or scheduled_at < int(config["effective_start"])
            or scheduled_at > int(config["effective_end"])
            or (scheduled_at - int(config["effective_start"])) % int(config["cadence_seconds"]) != 0
        ):
            raise IngressVerificationError("ingress:slot-grid")
        expected_slot_id = _digest("slot-id", {"config_digest": meta["config_digest"], "scheduled_at": scheduled_at})
        expected_operation = _digest("slot-operation", {"slot_id": expected_slot_id})
        if material["operation_id"] != expected_operation or row["slot_id"] != expected_slot_id:
            raise IngressVerificationError("ingress:slot-identity")
        if not isinstance(slot_schedules, dict):
            raise IngressVerificationError("ingress:event-state")
        slot_schedules[row["slot_id"]] = scheduled_at
        slot_operations[row["slot_id"]] = expected_operation
        expected_request = _digest("request", {"operation_id": expected_operation, "scheduled_at": scheduled_at})
        expected_payload = _digest("slot-payload", {"slot_id": expected_slot_id, "scheduled_at": scheduled_at})
        expected_payload_length = 0
    else:
        scheduled_at = slot_schedules.get(str(row["slot_id"]))
        if scheduled_at is None or str(row["slot_id"]) not in slot_operations:
            raise IngressVerificationError("ingress:event-time")
        slot_operation = slot_operations[str(row["slot_id"])]
        if kind == "LEASE":
            if set(material) != {"slot_id", "attempt", "lease_token", "lease_until", "operation_id"}:
                raise IngressVerificationError("ingress:event-material")
            if material["slot_id"] != row["slot_id"] or material["operation_id"] != slot_operation:
                raise IngressVerificationError("ingress:event-material")
            if (
                type(row["attempt"]) is not int
                or not 1 <= row["attempt"] <= int(config["max_attempts"])
                or type(row["lease_until"]) is not int
                or row["lease_until"] != row["observed_at"] + int(config["lease_seconds"])
                or material["attempt"] != row["attempt"]
                or material["lease_token"] != row["lease_token"]
                or material["lease_until"] != row["lease_until"]
            ):
                raise IngressVerificationError("ingress:lease")
            expected_operation = slot_operation
            expected_request = _digest("request", {"slot_id": row["slot_id"], "action": "LEASE", "attempt": row["attempt"]})
            expected_payload = _digest("lease-payload", material)
            expected_payload_length = 0
        elif kind in {"REQUEUE", "HOLD"} and row["receipt_bytes"] is None:
            if set(material) != {"slot_id", "action", "attempt", "operation_id"}:
                raise IngressVerificationError("ingress:event-material")
            if material != {"slot_id": row["slot_id"], "action": kind, "attempt": row["attempt"], "operation_id": slot_operation}:
                raise IngressVerificationError("ingress:event-material")
            expected_operation = slot_operation
            expected_request = _digest("request", {"slot_id": row["slot_id"], "action": kind})
            expected_payload = _digest("lease-recovery", {"slot_id": row["slot_id"], "attempt": row["attempt"]})
            expected_payload_length = 0
        elif kind == "HOLD" and row["receipt_bytes"] is not None:
            expected_material_keys = {"slot_id", "artifact_id", "operation_id", "decision", "reason"}
            if "operation_value_digest" in material:
                expected_material_keys.add("operation_value_digest")
            if set(material) != expected_material_keys:
                raise IngressVerificationError("ingress:event-material")
            if (
                material["slot_id"] != row["slot_id"]
                or material["decision"] != "HELD"
                or material["reason"] != "CAPACITY"
                or type(material["artifact_id"]) is not str
                or type(material["operation_id"]) is not str
            ):
                raise IngressVerificationError("ingress:capacity-receipt")
            _hex(material["artifact_id"], "ingress:capacity-artifact")
            _hex(material["operation_id"], "ingress:operation")
            if "operation_value_digest" in material:
                _hex(material["operation_value_digest"], "ingress:operation-value")
                expected_operation = _digest(
                    "caller-operation",
                    {
                        "database_id": meta["database_id"],
                        "config_digest": meta["config_digest"],
                        "value_digest": material["operation_value_digest"],
                    },
                )
            else:
                expected_operation = _digest(
                    "capture-operation",
                    {"slot_id": row["slot_id"], "artifact_id": material["artifact_id"]},
                )
            if material["operation_id"] != expected_operation:
                raise IngressVerificationError("ingress:capacity-receipt")
            expected_request = _digest("request", {"operation_id": expected_operation, "slot_id": row["slot_id"], "artifact_id": material["artifact_id"]})
            expected_payload = material["artifact_id"]
            expected_payload_length = 0
        elif kind == "CAPTURE":
            expected_material_keys = {
                "artifact_id", "envelope_digest", "intake_digest", "external_artifact_id",
                "external_artifact_digest", "source_contract_digest", "capture_id",
                "capture_context", "page_bindings", "slot_id", "lease_token_digest", "operation_id",
            }
            if "operation_value_digest" in material:
                expected_material_keys.add("operation_value_digest")
            if set(material) != expected_material_keys:
                raise IngressVerificationError("ingress:event-material")
            artifact_id = material["artifact_id"]
            if (
                type(artifact_id) is not str
                or artifact_id not in artifacts
                or material["slot_id"] != row["slot_id"]
                or material["envelope_digest"] != artifacts[artifact_id]["envelope_digest"]
                or material["intake_digest"] != _raw_digest("intake", artifacts[artifact_id]["raw"])
                or material["external_artifact_id"] != artifacts[artifact_id]["external_artifact_id"]
                or material["external_artifact_digest"] != artifacts[artifact_id]["external_artifact_digest"]
                or material["source_contract_digest"] != artifacts[artifact_id]["source_contract_digest"]
                or material["capture_id"] != artifacts[artifact_id]["capture_id"]
                or material["capture_context"] != artifacts[artifact_id]["capture_context"]
                or material["page_bindings"] != [list(item) for item in artifacts[artifact_id]["page_bindings"]]
                or material["lease_token_digest"] != row["lease_token"]
                or type(material["operation_id"]) is not str
            ):
                raise IngressVerificationError("ingress:event-capture")
            _hex(material["operation_id"], "ingress:operation")
            if "operation_value_digest" in material:
                _hex(material["operation_value_digest"], "ingress:operation-value")
                expected_operation = _digest(
                    "caller-operation",
                    {
                        "database_id": meta["database_id"],
                        "config_digest": meta["config_digest"],
                        "value_digest": material["operation_value_digest"],
                    },
                )
            else:
                expected_operation = _digest(
                    "capture-operation",
                    {"slot_id": row["slot_id"], "artifact_id": artifact_id},
                )
            if material["operation_id"] != expected_operation:
                raise IngressVerificationError("ingress:event-capture")
            capture_operations[artifact_id] = expected_operation
            fetch_operation = fetch_capture_operations.get(artifact_id)
            if fetch_operation is None or fetch_operation != expected_operation:
                raise IngressVerificationError("ingress:fetch-capture-binding")
            expected_request = _digest("request", {"operation_id": expected_operation, "slot_id": row["slot_id"], "artifact_id": artifact_id})
            expected_payload = artifact_id
            raw_artifact = artifacts[artifact_id]["raw"]
            expected_payload_length = len(raw_artifact) if type(raw_artifact) is bytes else -1
        elif kind == "FETCH_ATTESTATION":
            if set(material) != {
                "artifact_id", "page_index", "lease_attempt", "transport_attempt",
                "request_identity", "response_digest", "status", "retry_after_seconds",
                "response_url", "redirect", "failure_code", "transport_error",
                "evidence_class", "selected", "observed_at", "capture_operation_id",
            }:
                raise IngressVerificationError("ingress:event-material")
            capture_operation = material["capture_operation_id"]
            _hex(capture_operation, "ingress:operation")
            expected_operation = _digest(
                "fetch-operation",
                {"operation_id": capture_operation, "page_index": material["page_index"], "transport_attempt": material["transport_attempt"]},
            )
            expected_request = str(material["request_identity"])
            expected_payload = _digest("fetch-payload", material)
            expected_payload_length = len(row["receipt_bytes"]) if type(row["receipt_bytes"]) is bytes else -1
        else:
            if set(material) != {"artifact_id", "decision", "operation_id"}:
                raise IngressVerificationError("ingress:event-material")
            artifact_id = material["artifact_id"]
            if (
                type(artifact_id) is not str
                or artifact_id not in artifacts
                or material["decision"] != row["next_state"]
                or capture_operations.get(artifact_id) != material["operation_id"]
            ):
                raise IngressVerificationError("ingress:event-artifact")
            expected_operation = str(material["operation_id"])
            expected_request = _digest("request", {"operation_id": expected_operation, "slot_id": row["slot_id"], "artifact_id": artifact_id})
            expected_payload = str(artifact_id)
            raw_artifact = artifacts[artifact_id]["raw"]
            expected_payload_length = len(raw_artifact) if type(raw_artifact) is bytes else -1
    if row["operation_id"] != expected_operation or row["request_digest"] != expected_request:
        raise IngressVerificationError("ingress:event-operation")
    if row["payload_digest"] != expected_payload or row["payload_length"] != expected_payload_length:
        raise IngressVerificationError("ingress:event-payload")
    if type(row["attempt"]) is not int or not 0 <= row["attempt"] <= int(config["max_attempts"]):
        raise IngressVerificationError("ingress:attempt")
    capacity_hold = row["event_kind"] == "HOLD" and row["receipt_bytes"] is not None
    if capacity_hold:
        if row["stream_kind"] != "QUARANTINE" or row["stream_id"] != meta["chain_id"]:
            raise IngressVerificationError("ingress:capacity-receipt")
        receipt_raw = row["receipt_bytes"]
        if type(receipt_raw) is not bytes or not receipt_raw or len(receipt_raw) > MAX_EVENT_BYTES:
            raise IngressVerificationError("ingress:capacity-receipt")
        _verify_capacity_hold_receipt(
            receipt_raw,
            slot_id=str(row["slot_id"]),
            artifact_id=str(row["payload_digest"]),
        )
        if str(row["payload_digest"]) in artifacts:
            raise IngressVerificationError("ingress:capacity-receipt")
    if row["event_kind"] not in {"FETCH_ATTESTATION", "HOLD"} and any(
        row[key] is not None for key in ("source_id", "page_index", "transport_attempt", "receipt_bytes")
    ):
        raise IngressVerificationError("ingress:event-receipt")
    if row["event_kind"] == "HOLD" and not capacity_hold and row["receipt_bytes"] is not None:
        raise IngressVerificationError("ingress:event-receipt")
    if row["event_kind"] == "HOLD" and not capacity_hold and (
        row["stream_kind"] != "SLOT"
        or row["stream_id"] != row["slot_id"]
        or row["next_state"] != "HELD"
        or row["payload_digest"] != _digest(
            "lease-recovery", {"slot_id": row["slot_id"], "attempt": row["attempt"]}
        )
        or row["payload_length"] != 0
    ):
        raise IngressVerificationError("ingress:lease-recovery")
    prior = slot_states.get(row["slot_id"])
    if row["prior_state"] != (prior or "NONE"):
        raise IngressVerificationError("ingress:event-state")
    if row["next_state"] not in STATES:
        raise IngressVerificationError("ingress:event-state")
    scheduled_at = slot_schedules.get(str(row["slot_id"]))
    if scheduled_at is None:
        raise IngressVerificationError("ingress:event-time")
    if row["event_kind"] != "CREATE_SLOT" and row["observed_at"] < scheduled_at:
        raise IngressVerificationError("ingress:event-time")
    previous_observed_at = slot_times.get(str(row["slot_id"]))
    if previous_observed_at is not None and row["observed_at"] < previous_observed_at:
        raise IngressVerificationError("ingress:event-chronology")
    previous_global_observed_at = global_observed_at[0]
    if previous_global_observed_at is not None and row["observed_at"] < previous_global_observed_at:
        raise IngressVerificationError("ingress:event-chronology")
    global_observed_at[0] = int(row["observed_at"])
    if row["event_kind"] == "LEASE":
        if type(row["lease_token"]) is not str or not row["lease_token"] or type(row["lease_until"]) is not int or row["lease_until"] <= row["observed_at"]:
            raise IngressVerificationError("ingress:lease")
    if row["event_kind"] in {"REQUEUE", "HOLD"}:
        if type(row["lease_until"]) is not int:
            raise IngressVerificationError("ingress:lease-expiry")
        if capacity_hold:
            if row["observed_at"] >= row["lease_until"]:
                raise IngressVerificationError("ingress:lease-expiry")
        elif row["observed_at"] < row["lease_until"]:
            raise IngressVerificationError("ingress:lease-expiry")
    allowed = {
        "CREATE_SLOT": ("NONE", "DUE"),
        "LEASE": ("DUE", "LEASED"),
        "REQUEUE": ("LEASED", "DUE"),
        "CAPTURE": ("LEASED", "CAPTURED"),
        "FETCH_ATTESTATION": ("LEASED", "LEASED"),
        "FAIL": ("CAPTURED", "HELD"),
        "HOLD": ("LEASED", "HELD"),
        "BEGIN_QUARANTINE": ("CAPTURED", "QUARANTINE_PENDING"),
        "RECOVER_QUARANTINE": ("QUARANTINE_UNCONFIRMED", "QUARANTINE_PENDING"),
        "CONFIRM_QUARANTINE": ("QUARANTINE_PENDING", "QUARANTINED"),
        "ADMIT": ("QUARANTINE_PENDING", "QUARANTINED"),
        "QUARANTINE": ("CAPTURED", "QUARANTINED"),
        "QUARANTINE_UNCONFIRMED": ("QUARANTINE_PENDING", "QUARANTINE_UNCONFIRMED"),
        "SUPERSEDE": ("QUARANTINED", "QUARANTINED"),
        "WITHDRAW": ("QUARANTINED", "WITHDRAWN"),
        "ARTIFACT_PURGED": ("WITHDRAWN", "PURGED"),
    }
    if row["event_kind"] not in allowed:
        raise IngressVerificationError("ingress:event-transition")
    capture_edge = (row["prior_state"], row["next_state"])
    if row["event_kind"] == "CAPTURE" and capture_edge != ("LEASED", "CAPTURED"):
        raise IngressVerificationError("ingress:event-transition")
    if row["event_kind"] != "CAPTURE" and capture_edge != allowed[row["event_kind"]]:
        raise IngressVerificationError("ingress:event-transition")
    if row["event_kind"] in {
        "FAIL", "HOLD", "QUARANTINE_UNCONFIRMED", "CONFIRM_QUARANTINE", "ADMIT",
        "QUARANTINE", "SUPERSEDE", "WITHDRAW", "ARTIFACT_PURGED",
    } and (
        (row["event_kind"] != "HOLD" or capacity_hold)
        and (row["stream_kind"], row["stream_id"]) != ("QUARANTINE", meta["chain_id"])
    ):
        raise IngressVerificationError("ingress:quarantine-stream")
    if row["event_kind"] == "CREATE_SLOT":
        slot_attempts[row["slot_id"]] = 0
        slot_leases[row["slot_id"]] = (None, None, 0)
    elif row["event_kind"] == "LEASE":
        if row["attempt"] != slot_attempts.get(row["slot_id"], 0) + 1:
            raise IngressVerificationError("ingress:attempt")
        slot_attempts[row["slot_id"]] = row["attempt"]
        if slot_leases.get(row["slot_id"], (None, None, 0))[0] is not None:
            raise IngressVerificationError("ingress:lease-state")
        slot_leases[row["slot_id"]] = (str(row["lease_token"]), int(row["lease_until"]), int(row["attempt"]))
    elif row["event_kind"] == "REQUEUE":
        if row["attempt"] != slot_attempts.get(row["slot_id"], 0):
            raise IngressVerificationError("ingress:attempt")
        active = slot_leases.get(row["slot_id"], (None, None, 0))
        if active[0] != row["lease_token"] or active[1] != row["lease_until"]:
            raise IngressVerificationError("ingress:lease")
        slot_leases[row["slot_id"]] = (None, None, int(row["attempt"]))
    active_lease = slot_leases.get(row["slot_id"], (None, None, 0))
    if row["event_kind"] in {
        "FETCH_ATTESTATION", "CAPTURE", "BEGIN_QUARANTINE", "RECOVER_QUARANTINE",
        "CONFIRM_QUARANTINE", "ADMIT", "QUARANTINE", "QUARANTINE_UNCONFIRMED",
        "FAIL",
    } or (row["event_kind"] == "HOLD" and capacity_hold):
        if (
            active_lease[0] is None
            or row["attempt"] != active_lease[2]
            or row["lease_token"] != active_lease[0]
            or row["lease_until"] != active_lease[1]
            or row["observed_at"] >= int(active_lease[1])
        ):
            raise IngressVerificationError("ingress:lease")
    if row["event_kind"] == "FETCH_ATTESTATION":
        if (
            row["stream_kind"] != "FETCH"
            or row["stream_id"] != row["slot_id"]
            or row["source_id"] is None
            or type(row["page_index"]) is not int
            or type(row["transport_attempt"]) is not int
            or row["page_index"] < 0
            or row["transport_attempt"] < 0
            or row["receipt_bytes"] is None
        ):
            raise IngressVerificationError("ingress:fetch-columns")
        receipt_raw = row["receipt_bytes"]
        if type(receipt_raw) is not bytes or not receipt_raw or len(receipt_raw) > MAX_EVENT_BYTES:
            raise IngressVerificationError("ingress:fetch-receipt")
        receipt_value = _parse(receipt_raw, "ingress:fetch-receipt")
        artifact_id = receipt_value.get("artifact_id")
        if type(artifact_id) is not str or artifact_id not in artifacts:
            raise IngressVerificationError("ingress:event-artifact")
        receipt = _verify_fetch_receipt(
            receipt_raw,
            artifact=artifacts[artifact_id],
            slot_id=row["slot_id"],
            source_id=row["source_id"],
            page_index=row["page_index"],
            transport_attempt=row["transport_attempt"],
            lease_attempt=row["attempt"],
            observed_at=row["observed_at"],
        )
        material = {
            key: receipt[key]
            for key in (
                "artifact_id", "page_index", "lease_attempt", "transport_attempt",
                "request_identity", "response_digest", "status", "retry_after_seconds",
                "response_url", "redirect", "failure_code", "transport_error",
                "evidence_class", "selected", "observed_at",
            )
        }
        capture_operation = value["material"].get("capture_operation_id")
        if type(capture_operation) is not str:
            raise IngressVerificationError("ingress:event-material")
        existing_capture_operation = fetch_capture_operations.get(str(receipt["artifact_id"]))
        if existing_capture_operation is not None and existing_capture_operation != capture_operation:
            raise IngressVerificationError("ingress:fetch-capture-binding")
        fetch_capture_operations[str(receipt["artifact_id"])] = capture_operation
        material["capture_operation_id"] = capture_operation
        if (
            row["material_digest"] != _digest("material", material)
            or row["payload_digest"] != _digest("fetch-payload", material)
            or row["payload_length"] != len(row["receipt_bytes"])
        ):
            raise IngressVerificationError("ingress:fetch-payload")
        fetches.setdefault(str(receipt["artifact_id"]), []).append(receipt)
    elif row["event_kind"] == "CAPTURE":
        artifact_id = row["payload_digest"]
        if artifact_id not in artifacts:
            raise IngressVerificationError("ingress:event-artifact")
    if row["event_kind"] in {"BEGIN_QUARANTINE", "RECOVER_QUARANTINE", "CONFIRM_QUARANTINE", "ADMIT", "QUARANTINE", "FAIL", "QUARANTINE_UNCONFIRMED", "SUPERSEDE", "WITHDRAW", "ARTIFACT_PURGED"}:
        artifact_id = row["payload_digest"]
        if artifact_id not in artifacts:
            raise IngressVerificationError("ingress:event-artifact")
    if row["event_kind"] == "HOLD":
        if capacity_hold:
            if row["payload_length"] != 0:
                raise IngressVerificationError("ingress:capacity-receipt")
        elif row["payload_digest"] != _digest(
            "lease-recovery", {"slot_id": row["slot_id"], "attempt": row["attempt"]}
        ) or row["payload_length"] != 0:
            raise IngressVerificationError("ingress:lease-recovery")
    head_key = (str(row["stream_kind"]), str(row["stream_id"]))
    prior_head = heads.get(head_key)
    head_artifact_id = None
    if row["event_kind"] == "FETCH_ATTESTATION":
        head_artifact_id = str(receipt["artifact_id"])
    elif row["event_kind"] in {"CAPTURE", "BEGIN_QUARANTINE", "RECOVER_QUARANTINE", "CONFIRM_QUARANTINE", "ADMIT", "QUARANTINE", "FAIL", "QUARANTINE_UNCONFIRMED", "SUPERSEDE", "WITHDRAW", "ARTIFACT_PURGED"}:
        head_artifact_id = str(row["payload_digest"])
    if head_artifact_id is None and prior_head is not None:
        head_artifact_id = prior_head[0]
    heads[head_key] = (head_artifact_id, row["stream_after_root"], row["sequence"])
    stream_roots[head_key] = row["stream_after_root"]
    if row["event_kind"] in {
        "FAIL", "HOLD", "ADMIT", "QUARANTINE", "CONFIRM_QUARANTINE",
        "QUARANTINE_UNCONFIRMED", "WITHDRAW", "ARTIFACT_PURGED", "HOLD",
    }:
        slot_leases[row["slot_id"]] = (None, None, int(row["attempt"]))
    if row["event_kind"] in {
        "FAIL", "ADMIT", "QUARANTINE", "CONFIRM_QUARANTINE",
        "QUARANTINE_UNCONFIRMED", "SUPERSEDE", "WITHDRAW", "ARTIFACT_PURGED",
    }:
        artifact_id = str(row["payload_digest"])
        artifact = artifacts.get(artifact_id)
        if artifact is None:
            raise IngressVerificationError("ingress:event-artifact")
        artifact["event_sequence"] = int(row["sequence"])
        artifact["event_prefix_root"] = str(row["before_root"])
        artifact["event_after_root"] = str(row["after_root"])
        artifact["_terminal_event_sequence"] = int(row["sequence"])
        artifact["_terminal_event_kind"] = kind
        artifact["_terminal_slot_id"] = str(row["slot_id"])
    slot_times[str(row["slot_id"])] = int(row["observed_at"])
    slot_states[row["slot_id"]] = row["next_state"]
    return row["after_root"]


def _verify_connection(
    connection: sqlite3.Connection,
    *,
    expected_database_id: str | None = None,
    expected_config_digest: str | None = None,
    include_raw: bool = False,
    artifact_id: str | None = None,
    artifact_ids: tuple[str, ...] | None = None,
) -> dict[str, object]:
    try:
        if _table_names(connection) != tuple(sorted(TABLES)):
            raise IngressVerificationError("ingress:tables")
        if _index_definitions(connection) != INDEX_DEFINITIONS:
            raise IngressVerificationError("ingress:indexes")
        _check_page_limits(connection, configure=False)
        for table, columns in TABLE_COLUMNS.items():
            if _columns(connection, table) != columns:
                raise IngressVerificationError("ingress:columns")
        meta = _meta(connection)
        if expected_database_id is not None and meta["database_id"] != expected_database_id:
            raise IngressVerificationError("ingress:database-id")
        if expected_config_digest is not None and meta["config_digest"] != expected_config_digest:
            raise IngressVerificationError("ingress:config")
        config_raw = connection.execute("SELECT config_raw FROM ingress_meta WHERE meta_id=1").fetchone()
        if config_raw is None:
            raise IngressVerificationError("ingress:config")
        config = _parse(config_raw[0], "ingress:config", max_bytes=MAX_CONFIG_BYTES)
        slots = connection.execute("SELECT * FROM ingress_slots ORDER BY slot_id").fetchall()
        if meta["slot_count"] != len(slots):
            raise IngressVerificationError("ingress:slot-count")
        if len(slots) > int(config["max_slots"]):
            raise IngressVerificationError("ingress:capacity")
        artifacts_rows = connection.execute("SELECT * FROM ingress_artifacts ORDER BY artifact_id").fetchall()
        artifacts = {row["artifact_id"]: _verify_artifact(row, config=config) for row in artifacts_rows}
        if len(artifacts) != len(artifacts_rows):
            raise IngressVerificationError("ingress:artifact-duplicate")
        slot_states: dict[str, str] = {}
        slot_attempts: dict[str, int] = {}
        slot_schedules: dict[str, int] = {}
        slot_operations: dict[str, str] = {}
        slot_times: dict[str, int] = {}
        global_observed_at: list[int | None] = [None]
        slot_leases: dict[str, tuple[str | None, int | None, int]] = {}
        capture_operations: dict[str, str] = {}
        fetch_capture_operations: dict[str, str] = {}
        previous = GENESIS_ROOT
        heads: dict[tuple[str, str], tuple[str | None, str, int]] = {}
        stream_roots: dict[tuple[str, str], str] = {}
        fetches: dict[str, list[dict[str, object]]] = {}
        events = connection.execute("SELECT * FROM ingress_events ORDER BY sequence").fetchall()
        for expected_sequence, row in enumerate(events, start=1):
            if row["sequence"] != expected_sequence:
                raise IngressVerificationError("ingress:event-sequence")
            previous = _verify_event(
                row,
                meta=meta,
                config=config,
                previous_root=previous,
                slot_states=slot_states,
                slot_attempts=slot_attempts,
                slot_schedules=slot_schedules,
                slot_operations=slot_operations,
                slot_times=slot_times,
                global_observed_at=global_observed_at,
                slot_leases=slot_leases,
                artifacts=artifacts,
                capture_operations=capture_operations,
                fetch_capture_operations=fetch_capture_operations,
                heads=heads,
                stream_roots=stream_roots,
                fetches=fetches,
            )
        for artifact_id, artifact in artifacts.items():
            selected = fetches.get(artifact_id, [])
            page_evidence = artifact["result"].get("page_evidence") if isinstance(artifact.get("result"), Mapping) else None
            if not isinstance(page_evidence, tuple):
                raise IngressVerificationError("ingress:fetch-evidence")
            expected_keys = [
                (int(page["page_index"]), int(attempt["transport_attempt"]))
                for page in page_evidence
                for attempt in page["attempts"]
            ]
            actual_keys = [(int(item["page_index"]), int(item["transport_attempt"])) for item in selected]
            if actual_keys != expected_keys:
                raise IngressVerificationError("ingress:attestation-count")
            if artifact_id in capture_operations and (
                artifact_id not in fetch_capture_operations
                or fetch_capture_operations[artifact_id] != capture_operations[artifact_id]
            ):
                raise IngressVerificationError("ingress:fetch-capture-binding")
            if artifact["_terminal_event_sequence"] is None or artifact["_stored_event_sequence"] != artifact["_terminal_event_sequence"]:
                raise IngressVerificationError("ingress:artifact-event-sequence")
            if artifact["_terminal_event_kind"] is None or artifact["_terminal_slot_id"] is None:
                raise IngressVerificationError("ingress:artifact-event-sequence")
            artifact["terminal_event_kind"] = artifact.pop("_terminal_event_kind")
            artifact["terminal_slot_id"] = artifact.pop("_terminal_slot_id")
            artifact["terminal_state"] = slot_states.get(artifact["terminal_slot_id"])
            if artifact["terminal_state"] not in STATES:
                raise IngressVerificationError("ingress:artifact-state")
            artifact.pop("_stored_event_sequence", None)
            artifact.pop("_terminal_event_sequence", None)
        for row in slots:
            if (
                row["slot_id"] not in slot_states
                or row["state"] != slot_states[row["slot_id"]]
                or row["slot_id"] not in slot_schedules
                or row["scheduled_at"] != slot_schedules[row["slot_id"]]
                or row["slot_id"] not in slot_operations
                or row["operation_id"] != slot_operations[row["slot_id"]]
            ):
                raise IngressVerificationError("ingress:slot-state")
            if row["attempt"] != slot_attempts.get(row["slot_id"], 0):
                raise IngressVerificationError("ingress:slot-attempt")
            lease = slot_leases.get(str(row["slot_id"]), (None, None, 0))
            if row["state"] == "LEASED":
                if (row["lease_token"], row["lease_until"]) != (lease[0], lease[1]):
                    raise IngressVerificationError("ingress:slot-lease")
            elif row["lease_token"] is not None or row["lease_until"] is not None:
                raise IngressVerificationError("ingress:slot-lease")
            if row["artifact_id"] is not None and row["artifact_id"] not in artifacts:
                raise IngressVerificationError("ingress:slot-artifact")
        head_rows = connection.execute("SELECT * FROM ingress_heads ORDER BY stream_kind,stream_id").fetchall()
        actual_head_keys: set[tuple[str, str]] = set()
        for row in head_rows:
            if tuple(row.keys()) != ("stream_kind", "stream_id", "artifact_id", "head_root", "event_sequence"):
                raise IngressVerificationError("ingress:head-columns")
            key = (str(row["stream_kind"]), str(row["stream_id"]))
            if key in actual_head_keys:
                raise IngressVerificationError("ingress:head-cardinality")
            actual_head_keys.add(key)
            expected_head = heads.get(key)
            if expected_head is None or tuple(row) != (key[0], key[1], expected_head[0], expected_head[1], expected_head[2]):
                raise IngressVerificationError("ingress:head-binding")
            if row["artifact_id"] is not None and row["artifact_id"] not in artifacts:
                raise IngressVerificationError("ingress:head-artifact")
        if actual_head_keys != set(heads):
            raise IngressVerificationError("ingress:head-missing")
        quarantine_head = next(
            (row for row in head_rows if row["stream_kind"] == "QUARANTINE" and row["stream_id"] == meta["chain_id"]),
            None,
        )
        if meta["sequence"] != len(events) or meta["head_root"] != previous:
            raise IngressVerificationError("ingress:meta-root")
        if meta["watermark"] != meta["sequence"]:
            raise IngressVerificationError("ingress:watermark")
        result: dict[str, object] = {
            "accepted": True,
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "database_id": meta["database_id"],
            "chain_id": meta["chain_id"],
            "config_digest": meta["config_digest"],
            "config": dict(config),
            "external_policy": dict(config["external_policy"]),
            "sequence": meta["sequence"],
            "head_root": meta["head_root"],
            "watermark": meta["watermark"],
            "slot_count": len(slots),
            "artifact_count": len(artifacts_rows),
            "attestation_count": sum(len(items) for items in fetches.values()),
            "event_count": len(events),
            "state_counts": {state: sum(1 for row in slots if row["state"] == state) for state in STATES},
            "flags": dict(FIXED_FLAGS),
        }
        if artifact_ids is not None:
            selected: dict[str, dict[str, object]] = {}
            for selected_id in artifact_ids:
                _hex(selected_id, "ingress:artifact-selector")
                if selected_id not in artifacts:
                    raise IngressVerificationError("ingress:artifact-missing")
                selected[selected_id] = (
                    dict(artifacts[selected_id]) if include_raw
                    else _public_artifact(artifacts[selected_id])
                )
                if include_raw:
                    selected[selected_id]["watermark"] = selected[selected_id]["event_sequence"]
            result["selected_artifacts"] = selected
        if quarantine_head is not None and quarantine_head["artifact_id"] is not None:
            result["current_artifact_id"] = quarantine_head["artifact_id"]
            selected_id = artifact_id or quarantine_head["artifact_id"]
            if selected_id not in artifacts:
                raise IngressVerificationError("ingress:artifact-missing")
            current = artifacts[selected_id]
            result["current_artifact"] = (
                dict(current) if include_raw else _public_artifact(current)
            )
            result["selected_artifact_id"] = selected_id
        else:
            if artifact_id is not None:
                raise IngressVerificationError("ingress:artifact-missing")
            result["current_artifact_id"] = None
            result["current_artifact"] = None
        return result
    except IngressVerificationError:
        raise
    except (sqlite3.Error, OSError, TypeError, ValueError):
        raise IngressVerificationError("ingress:database") from None


def verify_database(
    path: str | Path,
    *,
    expected_database_id: str | None = None,
    expected_config_digest: str | None = None,
    include_raw: bool = False,
    artifact_id: str | None = None,
    artifact_ids: tuple[str, ...] | None = None,
) -> dict[str, object]:
    if expected_database_id is not None:
        _safe_identifier(expected_database_id, "ingress:database-id")
    if expected_config_digest is not None:
        _hex(expected_config_digest, "ingress:config")
    if artifact_id is not None:
        _hex(artifact_id, "ingress:artifact-selector")
    if artifact_ids is not None:
        if type(artifact_ids) is not tuple or len(set(artifact_ids)) != len(artifact_ids):
            raise IngressVerificationError("ingress:artifact-selector")
        for value in artifact_ids:
            _hex(value, "ingress:artifact-selector")
    connection = _open(path)
    try:
        return _verify_connection(
            connection,
            expected_database_id=expected_database_id,
            expected_config_digest=expected_config_digest,
            include_raw=include_raw,
            artifact_id=artifact_id,
            artifact_ids=artifact_ids,
        )
    finally:
        _close_readonly(connection)


def verify_bytes(
    raw: bytes,
    *,
    expected_database_id: str | None = None,
    expected_config_digest: str | None = None,
    include_raw: bool = False,
    artifact_id: str | None = None,
    artifact_ids: tuple[str, ...] | None = None,
) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_DATABASE_BYTES:
        raise IngressVerificationError("ingress:image")
    try:
        connection = sqlite3.connect(":memory:", isolation_level=None, timeout=0.25)
        connection.row_factory = sqlite3.Row
        connection.deserialize(raw)
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        if page_size <= 0:
            raise IngressVerificationError("ingress:capacity")
        connection.execute(f"PRAGMA max_page_count={MAX_DATABASE_BYTES // page_size}")
        _check_page_limits(connection, configure=False)
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        return _verify_connection(
            connection,
            expected_database_id=expected_database_id,
            expected_config_digest=expected_config_digest,
            include_raw=include_raw,
            artifact_id=artifact_id,
            artifact_ids=artifact_ids,
        )
    except IngressVerificationError:
        raise
    except (OSError, sqlite3.Error, TypeError, ValueError):
        raise IngressVerificationError("ingress:image") from None
    finally:
        _close_readonly(locals().get("connection"))


def read_artifact(path: str | Path, artifact_id: str) -> dict[str, object]:
    _hex(artifact_id, "ingress:artifact-selector")
    result = verify_database(path, include_raw=True, artifact_id=artifact_id)
    artifact = result.get("current_artifact")
    if not isinstance(artifact, dict) or result.get("current_artifact_id") != artifact_id:
        raise IngressVerificationError("ingress:artifact-not-current")
    returned = dict(artifact)
    returned["head_root"] = result["head_root"]
    returned["database_id"] = result["database_id"]
    returned["chain_id"] = result["chain_id"]
    returned["config_digest"] = result["config_digest"]
    returned["external_policy"] = dict(result["external_policy"])
    returned["watermark"] = returned["event_sequence"]
    return returned


def read_artifact_snapshot(path: str | Path, artifact_id: str) -> dict[str, object]:
    _hex(artifact_id, "ingress:artifact-selector")
    result = verify_database(path, include_raw=True, artifact_ids=(artifact_id,))
    selected = result.get("selected_artifacts")
    artifact = selected.get(artifact_id) if isinstance(selected, dict) else None
    if not isinstance(artifact, dict) or artifact.get("artifact_id") != artifact_id:
        raise IngressVerificationError("ingress:artifact-missing")
    returned = dict(artifact)
    returned["head_root"] = result["head_root"]
    returned["database_id"] = result["database_id"]
    returned["chain_id"] = result["chain_id"]
    returned["config_digest"] = result["config_digest"]
    returned["external_policy"] = dict(result["external_policy"])
    returned["current_artifact_id"] = result["current_artifact_id"]
    returned["watermark"] = returned["event_sequence"]
    return returned


def read_artifact_snapshots(path: str | Path, artifact_ids: tuple[str, ...]) -> dict[str, dict[str, object]]:
    if type(artifact_ids) is not tuple or any(type(value) is not str or not value for value in artifact_ids):
        raise IngressVerificationError("ingress:artifact-selector")
    if len(set(artifact_ids)) != len(artifact_ids):
        raise IngressVerificationError("ingress:artifact-selector")
    for value in artifact_ids:
        _hex(value, "ingress:artifact-selector")
    result = verify_database(path, include_raw=True, artifact_ids=artifact_ids)
    selected = result.get("selected_artifacts")
    if not isinstance(selected, dict):
        raise IngressVerificationError("ingress:artifact-selector")
    returned: dict[str, dict[str, object]] = {}
    for selected_id, artifact in selected.items():
        if not isinstance(artifact, dict):
            raise IngressVerificationError("ingress:artifact-selector")
        item = dict(artifact)
        item["head_root"] = result["head_root"]
        item["database_id"] = result["database_id"]
        item["chain_id"] = result["chain_id"]
        item["config_digest"] = result["config_digest"]
        item["external_policy"] = dict(result["external_policy"])
        item["current_artifact_id"] = result["current_artifact_id"]
        item["watermark"] = item["event_sequence"]
        returned[str(selected_id)] = item
    return returned


def logical_export(result: Mapping[str, object]) -> bytes:
    current = result.get("current_artifact")
    if isinstance(current, Mapping):
        current = _public_artifact(current)
    value = {
        "schema": "mirror-ingress-logical-export-v3",
        "schema_version": 3,
        "database_id": result["database_id"],
        "chain_id": result["chain_id"],
        "config_digest": result["config_digest"],
        "sequence": result["sequence"],
        "head_root": result["head_root"],
        "watermark": result["watermark"],
        "current_artifact": current,
        "counts": {
            "slots": result["slot_count"],
            "artifacts": result["artifact_count"],
            "attestations": result["attestation_count"],
            "events": result["event_count"],
        },
        "flags": dict(FIXED_FLAGS),
    }
    return _canonical(value)


__all__ = [
    "SCHEMA", "SCHEMA_VERSION", "TABLES", "STATES", "FIXED_FLAGS",
    "INTAKE_MAGIC", "INTAKE_VERSION", "INTAKE_FLAGS",
    "IngressVerificationError", "content_root", "verify_database", "verify_bytes",
    "read_artifact", "logical_export", "_canonical", "_digest", "_raw_digest",
    "_lease_token_digest", "MAX_DATABASE_BYTES", "MAX_COMPLETE_FRAME_BYTES", "MAX_RAW_ENVELOPE_BYTES", "MAX_EVENT_BYTES",
    "MAX_IDENTIFIER_BYTES", "TABLE_COLUMNS", "EXPLICIT_INDEXES", "INDEX_DEFINITIONS", "_index_definitions",
    "read_artifact_snapshot",
    "read_artifact_snapshots",
]
