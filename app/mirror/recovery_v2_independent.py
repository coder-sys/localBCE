"""Independent verifier for the three-table Mirror recovery catalog.

The catalog contains identities and receipts only.  Sealed component images
are owned by the injected storage/custody ports and are never read from this
module's database.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Mapping

from app.mirror import core_v2_independent as core
from app.mirror import ingress_v2_independent as ingress


SCHEMA = "mirror-recovery-v2"
SCHEMA_VERSION = 2
DOMAIN = "BL/MIRROR/RECOVERY/V2/"
GENESIS_ROOT = "0" * 128
MAX_DATABASE_BYTES = 32 * 1024 * 1024
MAX_EVENT_BYTES = 64 * 1024
MAX_BOOTSTRAP_BYTES = 32 * 1024
STATES = ("PREPARED", "OBJECT_PENDING", "VERIFIED", "PUBLISHED", "INVALIDATED")
EVENT_KINDS = ("PREPARE", "OBJECT_PENDING", "VERIFIED", "PUBLISHED", "INVALIDATED")
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
    "controlled_shadow_ready": False,
    "proofSuiteId": None,
}


class RecoveryVerificationError(ValueError):
    """Fixed independent recovery error."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise RecoveryVerificationError("recovery:noncanonical") from None


def _parse(raw: bytes, label: str = "recovery:parse") -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_EVENT_BYTES:
        raise RecoveryVerificationError(label)
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicates, parse_constant=lambda _value: (_ for _ in ()).throw(RecoveryVerificationError("recovery:constant")))
    except RecoveryVerificationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RecoveryVerificationError(label) from None
    if not isinstance(value, dict) or _canonical(value) != raw:
        raise RecoveryVerificationError(label)
    return value


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise RecoveryVerificationError("recovery:duplicate-key")
        value[key] = item
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


def _hex(value: object, label: str) -> str:
    if type(value) is not str or len(value) != 128 or any(char not in "0123456789abcdef" for char in value):
        raise RecoveryVerificationError(label)
    return value


def _open(path: str | Path) -> sqlite3.Connection:
    database = Path(path)
    try:
        if not database.is_file() or database.stat().st_size > MAX_DATABASE_BYTES:
            raise RecoveryVerificationError("recovery:database")
        connection = sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True, isolation_level=None, timeout=0.25)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        return connection
    except RecoveryVerificationError:
        raise
    except (OSError, sqlite3.Error):
        raise RecoveryVerificationError("recovery:database") from None


def _tables(connection: sqlite3.Connection) -> tuple[str, ...]:
    return tuple(row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall())


def _columns(connection: sqlite3.Connection, table: str) -> tuple[str, ...]:
    return tuple(row[1] for row in connection.execute("SELECT * FROM pragma_table_info(?) ORDER BY cid", (table,)).fetchall())


def _event_root(sequence: int, previous: str, event_id: str, kind: str, point_id: str, next_state: str, material_digest: str, stream_kind: str = "POINT", stream_id: str | None = None) -> str:
    return _digest("event-root", {"sequence": sequence, "previous_root": previous, "event_id": event_id, "event_kind": kind, "point_id": point_id, "stream_kind": stream_kind, "stream_id": stream_id or point_id, "next_state": next_state, "material_digest": material_digest})


def _verify_meta(connection: sqlite3.Connection, expected_database_id: str | None, expected_config_digest: str | None) -> sqlite3.Row:
    row = connection.execute("SELECT * FROM recovery_meta WHERE meta_id=1").fetchone()
    if row is None or row["schema"] != SCHEMA or row["schema_version"] != SCHEMA_VERSION:
        raise RecoveryVerificationError("recovery:schema")
    if expected_database_id is not None and row["database_id"] != expected_database_id:
        raise RecoveryVerificationError("recovery:database-id")
    if expected_config_digest is not None and row["config_digest"] != expected_config_digest:
        raise RecoveryVerificationError("recovery:config")
    for key in ("config_digest", "head_root", "profile_digest", "key_custody_id_digest", "storage_id_digest"):
        _hex(row[key], "recovery:" + key)
    for key in ("database_id", "chain_id", "ingress_database_id", "core_database_id"):
        if type(row[key]) is not str or not row[key]:
            raise RecoveryVerificationError("recovery:identity")
    if type(row["sequence"]) is not int or row["sequence"] < 0 or type(row["current_generation"]) is not int or row["current_generation"] < 0:
        raise RecoveryVerificationError("recovery:sequence")
    return row


def _verify_point(row: sqlite3.Row, meta: sqlite3.Row) -> None:
    required = ("point_id", "generation", "state", "object_id", "bundle_digest", "bundle_length", "ingress_database_id", "ingress_config_digest", "ingress_head_root", "ingress_watermark", "core_database_id", "core_config_digest", "core_head_root", "core_watermark", "key_id", "key_epoch", "key_state", "storage_id", "prior_point_id", "prior_root", "operation_id", "request_digest", "sequence", "updated_sequence")
    if tuple(row.keys()) != required or row["state"] not in STATES:
        raise RecoveryVerificationError("recovery:point")
    for key in ("point_id", "object_id", "bundle_digest", "ingress_config_digest", "ingress_head_root", "core_config_digest", "core_head_root", "prior_root", "request_digest"):
        _hex(row[key], "recovery:point-" + key)
    for key in ("ingress_database_id", "core_database_id", "key_id", "storage_id", "operation_id"):
        if type(row[key]) is not str or not row[key]:
            raise RecoveryVerificationError("recovery:point-identity")
    if row["ingress_database_id"] != meta["ingress_database_id"] or row["core_database_id"] != meta["core_database_id"] or _digest("storage-id", row["storage_id"]) != meta["storage_id_digest"]:
        raise RecoveryVerificationError("recovery:point-owner")
    if type(row["generation"]) is not int or row["generation"] <= 0 or type(row["bundle_length"]) is not int or not 0 < row["bundle_length"] <= 16 * 1024 * 1024:
        raise RecoveryVerificationError("recovery:point-size")
    if type(row["ingress_watermark"]) is not int or row["ingress_watermark"] < 0 or type(row["core_watermark"]) is not int or row["core_watermark"] < 0:
        raise RecoveryVerificationError("recovery:point-watermark")
    if type(row["key_epoch"]) is not int or row["key_epoch"] < 0 or row["key_state"] not in {"ACTIVE", "REVOKED", "UNKNOWN"}:
        raise RecoveryVerificationError("recovery:key")


def _verify_event(row: sqlite3.Row, meta: sqlite3.Row, previous: str, states: dict[str, str]) -> str:
    required = {"schema", "schema_version", "database_id", "chain_id", "sequence", "event_id", "event_kind", "stream_kind", "stream_id", "point_id", "operation_id", "request_digest", "prior_state", "next_state", "attempt", "before_root", "after_root", "material_digest", "payload_digest", "payload_length"}
    raw = bytes(row["event_raw"])
    value = _parse(raw, "recovery:event")
    if set(value) != required or row["sequence"] != value["sequence"] or any(value[key] != row[key] for key in required - {"schema", "schema_version"}):
        raise RecoveryVerificationError("recovery:event-binding")
    if value["schema"] != SCHEMA or value["schema_version"] != SCHEMA_VERSION or row["database_id"] != meta["database_id"] or row["chain_id"] != meta["chain_id"] or row["stream_kind"] != "POINT" or row["stream_id"] != row["point_id"] or row["before_root"] != previous or row["event_kind"] not in EVENT_KINDS:
        raise RecoveryVerificationError("recovery:event-order")
    if row["event_id"] != _digest("event-id", {key: value[key] for key in required if key not in {"event_id", "after_root"}}) or row["receipt_digest"] != _raw_digest("receipt", raw):
        raise RecoveryVerificationError("recovery:event-digest")
    if row["after_root"] != _event_root(row["sequence"], previous, row["event_id"], row["event_kind"], row["point_id"], row["next_state"], row["material_digest"], row["stream_kind"], row["stream_id"]):
        raise RecoveryVerificationError("recovery:event-root")
    if row["point_id"] not in states:
        if row["event_kind"] != "PREPARE" or row["prior_state"] != "NONE" or row["next_state"] != "PREPARED":
            raise RecoveryVerificationError("recovery:event-state")
    elif row["prior_state"] != states[row["point_id"]]:
        raise RecoveryVerificationError("recovery:event-state")
    allowed = {
        "PREPARE": ("NONE", "PREPARED"),
        "OBJECT_PENDING": ("PREPARED", "OBJECT_PENDING"),
        "VERIFIED": ("OBJECT_PENDING", "VERIFIED"),
        "PUBLISHED": ("VERIFIED", "PUBLISHED"),
        "INVALIDATED": ("OBJECT_PENDING", "INVALIDATED"),
    }
    if (row["prior_state"], row["next_state"]) != allowed[row["event_kind"]]:
        raise RecoveryVerificationError("recovery:event-transition")
    states[row["point_id"]] = row["next_state"]
    return row["after_root"]


def verify_database(path: str | Path, *, expected_database_id: str | None = None, expected_config_digest: str | None = None) -> dict[str, object]:
    connection = _open(path)
    try:
        tables = ("recovery_meta", "recovery_points", "recovery_events")
        if _tables(connection) != tuple(sorted(tables)):
            raise RecoveryVerificationError("recovery:tables")
        expected = {
            "recovery_meta": ("meta_id", "schema", "schema_version", "database_id", "chain_id", "config_digest", "sequence", "head_root", "profile_digest", "key_custody_id_digest", "storage_id_digest", "ingress_database_id", "core_database_id", "current_generation"),
            "recovery_points": ("point_id", "generation", "state", "object_id", "bundle_digest", "bundle_length", "ingress_database_id", "ingress_config_digest", "ingress_head_root", "ingress_watermark", "core_database_id", "core_config_digest", "core_head_root", "core_watermark", "key_id", "key_epoch", "key_state", "storage_id", "prior_point_id", "prior_root", "operation_id", "request_digest", "sequence", "updated_sequence"),
            "recovery_events": ("sequence", "event_id", "event_kind", "database_id", "chain_id", "stream_kind", "stream_id", "point_id", "operation_id", "request_digest", "prior_state", "next_state", "attempt", "before_root", "after_root", "material_digest", "payload_digest", "payload_length", "event_raw", "receipt_digest"),
        }
        for table, columns in expected.items():
            if _columns(connection, table) != columns:
                raise RecoveryVerificationError("recovery:columns")
        meta = _verify_meta(connection, expected_database_id, expected_config_digest)
        points_rows = connection.execute("SELECT * FROM recovery_points ORDER BY sequence").fetchall()
        points = {row["point_id"]: row for row in points_rows}
        if len(points) != len(points_rows):
            raise RecoveryVerificationError("recovery:point-duplicate")
        for row in points_rows:
            _verify_point(row, meta)
        states: dict[str, str] = {}
        events = connection.execute("SELECT * FROM recovery_events ORDER BY sequence").fetchall()
        previous = GENESIS_ROOT
        for expected_sequence, row in enumerate(events, start=1):
            if row["sequence"] != expected_sequence:
                raise RecoveryVerificationError("recovery:event-sequence")
            previous = _verify_event(row, meta, previous, states)
        for point_id, row in points.items():
            if states.get(point_id) != row["state"] or row["sequence"] > len(events) or row["updated_sequence"] > len(events):
                raise RecoveryVerificationError("recovery:point-state")
            if row["prior_point_id"] is not None:
                prior = points.get(row["prior_point_id"])
                if prior is None or prior["generation"] >= row["generation"] or row["prior_root"] != meta["head_root"] and prior["updated_sequence"] >= row["sequence"]:
                    raise RecoveryVerificationError("recovery:point-chain")
        if meta["current_generation"] != max((row["generation"] for row in points_rows), default=0):
            raise RecoveryVerificationError("recovery:generation")
        if meta["sequence"] != len(events) or meta["head_root"] != previous:
            raise RecoveryVerificationError("recovery:meta-root")
        return {
            "accepted": True, "schema": SCHEMA, "schema_version": SCHEMA_VERSION,
            "database_id": meta["database_id"], "chain_id": meta["chain_id"],
            "config_digest": meta["config_digest"], "profile_digest": meta["profile_digest"],
            "key_custody_id_digest": meta["key_custody_id_digest"], "storage_id_digest": meta["storage_id_digest"],
            "sequence": meta["sequence"], "head_root": meta["head_root"],
            "point_count": len(points_rows), "event_count": len(events),
            "current_generation": meta["current_generation"], "states": {key: sum(1 for row in points_rows if row["state"] == key) for key in STATES},
            "flags": dict(FIXED_FLAGS),
        }
    except RecoveryVerificationError:
        raise
    except (OSError, sqlite3.Error, TypeError, ValueError):
        raise RecoveryVerificationError("recovery:database") from None
    finally:
        try:
            connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        connection.close()


def parse_bootstrap(raw: bytes) -> dict[str, object]:
    value = _parse(raw, "recovery:bootstrap")
    required = {"schema", "schema_version", "bootstrap_id", "catalog_id", "point_id", "generation", "object_id", "bundle_digest", "bundle_length", "key_id", "key_epoch", "storage_id", "ingress_database_id", "core_database_id", "ingress_head_root", "core_head_root", "ingress_watermark", "core_watermark", "publication_receipt_digest", "flags"}
    if set(value) != required or value["schema"] != "mirror-recovery-bootstrap-v2" or value["schema_version"] != 2 or value["flags"] != FIXED_FLAGS:
        raise RecoveryVerificationError("recovery:bootstrap")
    for key in ("bootstrap_id", "catalog_id", "point_id", "object_id", "bundle_digest", "ingress_head_root", "core_head_root", "publication_receipt_digest"):
        _hex(value[key], "recovery:bootstrap-id")
    if type(value["generation"]) is not int or value["generation"] <= 0 or type(value["bundle_length"]) is not int or value["bundle_length"] <= 0:
        raise RecoveryVerificationError("recovery:bootstrap-range")
    bootstrap_id = value["bootstrap_id"]
    if bootstrap_id != _digest("bootstrap-id", {key: value[key] for key in value if key not in {"bootstrap_id", "flags"}}):
        raise RecoveryVerificationError("recovery:bootstrap-id")
    return value


def logical_export(result: Mapping[str, object]) -> bytes:
    return _canonical({
        "schema": "mirror-recovery-logical-export-v2", "schema_version": 2,
        "database_id": result["database_id"], "chain_id": result["chain_id"],
        "config_digest": result["config_digest"], "profile_digest": result["profile_digest"],
        "sequence": result["sequence"], "head_root": result["head_root"],
        "point_count": result["point_count"], "event_count": result["event_count"],
        "states": result["states"], "flags": dict(FIXED_FLAGS),
    })


__all__ = ["SCHEMA", "SCHEMA_VERSION", "STATES", "EVENT_KINDS", "FIXED_FLAGS", "GENESIS_ROOT", "RecoveryVerificationError", "verify_database", "logical_export", "parse_bootstrap", "_canonical", "_digest", "_raw_digest"]
