"""Independent verifier for the three-table Mirror recovery catalog.

The verifier reconstructs recovery points from canonical event material.  It
never imports the producer and never treats a mutable point row as an
authority.  Component images and sealed objects remain outside this catalog.
"""

from __future__ import annotations

import base64
import binascii
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
MAX_BUNDLE_BYTES = 32 * 1024 * 1024
MAX_CUSTODY_OVERHEAD_BYTES = 65_536
MAX_RECOVERY_POINTS = 512
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

_META_COLUMNS = (
    "meta_id", "schema", "schema_version", "database_id", "chain_id",
    "config_digest", "sequence", "head_root", "profile_digest",
    "key_custody_id_digest", "storage_id_digest", "ingress_database_id",
    "core_database_id", "current_generation",
)
_POINT_COLUMNS = (
    "point_id", "generation", "state", "object_id", "bundle_digest",
    "bundle_length", "ingress_database_id", "ingress_config_digest",
    "ingress_head_root", "ingress_watermark", "core_database_id",
    "core_config_digest", "core_head_root", "core_watermark", "key_id",
    "key_epoch", "key_state", "storage_id", "prior_point_id", "prior_root",
    "operation_id", "request_digest", "sequence", "updated_sequence",
)
_EVENT_COLUMNS = (
    "sequence", "event_id", "event_kind", "database_id", "chain_id",
    "stream_kind", "stream_id", "point_id", "operation_id",
    "request_digest", "prior_state", "next_state", "attempt", "before_root",
    "after_root", "material_digest", "payload_digest", "payload_length",
    "event_raw", "receipt_digest",
)
_EVENT_RAW_KEYS = {
    "schema", "schema_version", "database_id", "chain_id", "sequence",
    "event_id", "event_kind", "stream_kind", "stream_id", "point_id",
    "operation_id", "request_digest", "prior_state", "next_state", "attempt",
    "before_root", "after_root", "material", "material_digest", "payload_digest",
    "payload_length",
}
_PREPARE_KEYS = {
    "point_id", "generation", "object_id", "bundle_digest", "bundle_length",
    "ingress", "core", "key_id", "key_epoch", "key_state", "storage_id",
    "prior_point_id", "prior_root", "operation_id", "request_digest",
}
_COMPONENT_KEYS = {
    "database_id", "chain_id", "config_digest", "head_root", "watermark",
    "image_digest", "image_length",
}
_PENDING_KEYS = {"point_id", "object_id", "storage_id", "key_id", "key_epoch"}
_VERIFIED_KEYS = {"point_id", "object_id", "bundle_digest", "bundle_length", "storage_id", "key_id", "key_epoch"}
_INVALIDATED_KEYS = {"point_id", "object_id", "key_id", "key_epoch", "reason"}
_PUBLISHED_KEYS = {"point_id", "object_id", "ingress_target", "core_target"}


class RecoveryVerificationError(ValueError):
    """Fixed independent recovery error."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise RecoveryVerificationError("recovery:noncanonical") from None


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise RecoveryVerificationError("recovery:duplicate-key")
        value[key] = item
    return value


def _parse(raw: bytes, label: str = "recovery:parse", *, max_bytes: int = MAX_EVENT_BYTES) -> dict[str, object]:
    if type(raw) is not bytes or not raw or type(max_bytes) is not int or max_bytes <= 0 or len(raw) > max_bytes:
        raise RecoveryVerificationError(label)
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(RecoveryVerificationError("recovery:constant")),
        )
    except RecoveryVerificationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RecoveryVerificationError(label) from None
    if not isinstance(value, dict) or _canonical(value) != raw:
        raise RecoveryVerificationError(label)
    return value


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((DOMAIN + label + "\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _raw_digest(label: str, raw: bytes) -> str:
    if type(raw) is not bytes:
        raise RecoveryVerificationError("recovery:bytes")
    digest = hashlib.sha3_512()
    digest.update((DOMAIN + label + "\0").encode("ascii"))
    digest.update(raw)
    return digest.hexdigest()


def _hex(value: object, label: str) -> str:
    if type(value) is not str or len(value) != 128 or any(char not in "0123456789abcdef" for char in value):
        raise RecoveryVerificationError(label)
    return value


def _opaque(value: object, label: str, *, maximum: int = 256) -> str:
    if type(value) is not str or not value or len(value) > maximum:
        raise RecoveryVerificationError(label)
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        raise RecoveryVerificationError(label) from None
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
    return _digest("event-root", {
        "sequence": sequence, "previous_root": previous, "event_id": event_id,
        "event_kind": kind, "point_id": point_id, "stream_kind": stream_kind,
        "stream_id": stream_id or point_id, "next_state": next_state,
        "material_digest": material_digest,
    })


def _verify_meta(connection: sqlite3.Connection, expected_database_id: str | None, expected_config_digest: str | None) -> sqlite3.Row:
    row = connection.execute("SELECT * FROM recovery_meta WHERE meta_id=1").fetchone()
    if row is None or tuple(row.keys()) != _META_COLUMNS or row["meta_id"] != 1 or row["schema"] != SCHEMA or row["schema_version"] != SCHEMA_VERSION:
        raise RecoveryVerificationError("recovery:schema")
    if expected_database_id is not None and row["database_id"] != expected_database_id:
        raise RecoveryVerificationError("recovery:database-id")
    if expected_config_digest is not None and row["config_digest"] != expected_config_digest:
        raise RecoveryVerificationError("recovery:config")
    for key in ("config_digest", "head_root", "profile_digest", "key_custody_id_digest", "storage_id_digest"):
        _hex(row[key], "recovery:" + key)
    for key in ("database_id", "chain_id", "ingress_database_id", "core_database_id"):
        _opaque(row[key], "recovery:identity")
    if type(row["sequence"]) is not int or row["sequence"] < 0 or type(row["current_generation"]) is not int or row["current_generation"] < 0:
        raise RecoveryVerificationError("recovery:sequence")
    if row["current_generation"] > MAX_RECOVERY_POINTS:
        raise RecoveryVerificationError("recovery:capacity")
    return row


def _validate_point_shape(row: Mapping[str, object], meta: Mapping[str, object]) -> None:
    if tuple(row.keys()) != _POINT_COLUMNS or row["state"] not in STATES:
        raise RecoveryVerificationError("recovery:point")
    for key in ("point_id", "object_id", "bundle_digest", "ingress_config_digest", "ingress_head_root", "core_config_digest", "core_head_root", "prior_root", "operation_id", "request_digest"):
        _hex(row[key], "recovery:point-" + key)
    if row["prior_point_id"] is not None:
        _hex(row["prior_point_id"], "recovery:point-prior")
    for key in ("ingress_database_id", "core_database_id", "key_id", "storage_id"):
        _opaque(row[key], "recovery:point-identity")
    if row["ingress_database_id"] != meta["ingress_database_id"] or row["core_database_id"] != meta["core_database_id"] or _digest("storage-id", row["storage_id"]) != meta["storage_id_digest"]:
        raise RecoveryVerificationError("recovery:point-owner")
    if type(row["generation"]) is not int or not 1 <= row["generation"] <= MAX_RECOVERY_POINTS:
        raise RecoveryVerificationError("recovery:point-generation")
    if type(row["bundle_length"]) is not int or not 0 < row["bundle_length"] <= MAX_BUNDLE_BYTES:
        raise RecoveryVerificationError("recovery:point-size")
    if type(row["ingress_watermark"]) is not int or row["ingress_watermark"] < 0 or type(row["core_watermark"]) is not int or row["core_watermark"] < 0:
        raise RecoveryVerificationError("recovery:point-watermark")
    if type(row["key_epoch"]) is not int or row["key_epoch"] < 0 or row["key_state"] not in {"ACTIVE", "REVOKED", "UNKNOWN"}:
        raise RecoveryVerificationError("recovery:key")
    if any(type(row[key]) is not int or row[key] < 0 for key in ("sequence", "updated_sequence")):
        raise RecoveryVerificationError("recovery:point-sequence")


def _component(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != _COMPONENT_KEYS:
        raise RecoveryVerificationError(label)
    _opaque(value["database_id"], label)
    _opaque(value["chain_id"], label)
    _hex(value["config_digest"], label)
    _hex(value["head_root"], label)
    _hex(value["image_digest"], label)
    if type(value["watermark"]) is not int or value["watermark"] < 0 or type(value["image_length"]) is not int or value["image_length"] <= 0:
        raise RecoveryVerificationError(label)
    return value


def parse_bundle(
    raw: bytes,
    *,
    max_bundle_bytes: int,
    expected_generation: int | None = None,
    expected_prior_root: str | None = None,
    expected_ingress: Mapping[str, object] | None = None,
    expected_core: Mapping[str, object] | None = None,
) -> tuple[dict[str, object], bytes, bytes]:
    if type(max_bundle_bytes) is not int or not 1024 <= max_bundle_bytes <= MAX_BUNDLE_BYTES:
        raise RecoveryVerificationError("recovery:bundle-config")
    value = _parse(raw, "recovery:bundle", max_bytes=max_bundle_bytes)
    required = {"schema", "schema_version", "generation", "prior_recovery_root", "ingress", "core", "ingress_image", "core_image", "flags"}
    if set(value) != required or value["schema"] != "mirror-recovery-bundle-v2" or value["schema_version"] != 2 or value["flags"] != FIXED_FLAGS:
        raise RecoveryVerificationError("recovery:bundle")
    if type(value["generation"]) is not int or value["generation"] <= 0:
        raise RecoveryVerificationError("recovery:bundle-generation")
    _hex(value["prior_recovery_root"], "recovery:bundle-prior")
    ing = _component(value["ingress"], "recovery:bundle-ingress")
    cor = _component(value["core"], "recovery:bundle-core")
    if expected_generation is not None and value["generation"] != expected_generation:
        raise RecoveryVerificationError("recovery:bundle-binding")
    if expected_prior_root is not None and value["prior_recovery_root"] != expected_prior_root:
        raise RecoveryVerificationError("recovery:bundle-binding")
    for actual, expected, label in ((ing, expected_ingress, "recovery:bundle-ingress-binding"), (cor, expected_core, "recovery:bundle-core-binding")):
        if expected is not None and any(actual[key] != expected[key] for key in _COMPONENT_KEYS):
            raise RecoveryVerificationError(label)
    images: list[bytes] = []
    for component, field, cap, label, digest_label in ((ing, "ingress_image", ingress.MAX_DATABASE_BYTES, "recovery:bundle-ingress-image", "ingress-image"), (cor, "core_image", core.MAX_DATABASE_BYTES, "recovery:bundle-core-image", "core-image")):
        encoded = value[field]
        if type(encoded) is not str:
            raise RecoveryVerificationError(label)
        try:
            encoded_bytes = encoded.encode("ascii")
        except UnicodeEncodeError:
            raise RecoveryVerificationError(label) from None
        length = component["image_length"]
        if length > cap or len(encoded_bytes) != 4 * ((length + 2) // 3) or len(encoded_bytes) > 4 * ((cap + 2) // 3):
            raise RecoveryVerificationError(label)
        try:
            image = base64.b64decode(encoded_bytes, validate=True)
        except (ValueError, binascii.Error):
            raise RecoveryVerificationError(label) from None
        if len(image) != length or _raw_digest(digest_label, image) != component["image_digest"] or base64.b64encode(image) != encoded_bytes:
            raise RecoveryVerificationError(label)
        images.append(image)
    return value, images[0], images[1]


def _prepare_point(material: Mapping[str, object], event: Mapping[str, object], meta: Mapping[str, object]) -> dict[str, object]:
    if set(material) != _PREPARE_KEYS:
        raise RecoveryVerificationError("recovery:prepare-material")
    ingress_value = _component(material["ingress"], "recovery:prepare-ingress")
    core_value = _component(material["core"], "recovery:prepare-core")
    for key in ("point_id", "object_id", "bundle_digest", "operation_id", "request_digest"):
        _hex(material[key], "recovery:prepare-identity")
    if material["point_id"] != event["point_id"] or material["operation_id"] != event["operation_id"] or material["request_digest"] != event["request_digest"]:
        raise RecoveryVerificationError("recovery:prepare-binding")
    _opaque(material["key_id"], "recovery:prepare-key")
    if type(material["generation"]) is not int or type(material["bundle_length"]) is not int or type(material["key_epoch"]) is not int or material["generation"] <= 0 or material["key_epoch"] < 0 or not 0 < material["bundle_length"] <= MAX_BUNDLE_BYTES:
        raise RecoveryVerificationError("recovery:prepare-range")
    if material["key_state"] not in {"ACTIVE", "REVOKED", "UNKNOWN"} or not isinstance(material["storage_id"], str) or not material["storage_id"] or _digest("storage-id", material["storage_id"]) != meta["storage_id_digest"]:
        raise RecoveryVerificationError("recovery:prepare-owner")
    prior_point_id = material["prior_point_id"]
    if prior_point_id is not None:
        _hex(prior_point_id, "recovery:prepare-prior")
    _hex(material["prior_root"], "recovery:prepare-root")
    if material["point_id"] != _digest("point-id", {"config_digest": meta["config_digest"], "generation": material["generation"]}):
        raise RecoveryVerificationError("recovery:prepare-point")
    if material["object_id"] != _digest("object-id", {"bundle_digest": material["bundle_digest"], "profile_digest": meta["profile_digest"], "key_id": material["key_id"], "key_epoch": material["key_epoch"]}):
        raise RecoveryVerificationError("recovery:prepare-object")
    if material["operation_id"] != _digest("operation-id", {"point_id": material["point_id"]}) or material["request_digest"] != _digest("request", {"point_id": material["point_id"], "bundle_digest": material["bundle_digest"], "object_id": material["object_id"]}):
        raise RecoveryVerificationError("recovery:prepare-request")
    if event["before_root"] != material["prior_root"]:
        raise RecoveryVerificationError("recovery:prepare-prior-root")
    if ingress_value["database_id"] != meta["ingress_database_id"] or core_value["database_id"] != meta["core_database_id"]:
        raise RecoveryVerificationError("recovery:prepare-component")
    return {
        "point_id": material["point_id"], "generation": material["generation"], "state": "PREPARED",
        "object_id": material["object_id"], "bundle_digest": material["bundle_digest"], "bundle_length": material["bundle_length"],
        "ingress_database_id": ingress_value["database_id"], "ingress_config_digest": ingress_value["config_digest"], "ingress_head_root": ingress_value["head_root"], "ingress_watermark": ingress_value["watermark"],
        "core_database_id": core_value["database_id"], "core_config_digest": core_value["config_digest"], "core_head_root": core_value["head_root"], "core_watermark": core_value["watermark"],
        "key_id": material["key_id"], "key_epoch": material["key_epoch"], "key_state": material["key_state"], "storage_id": material["storage_id"],
        "prior_point_id": prior_point_id, "prior_root": material["prior_root"], "operation_id": material["operation_id"], "request_digest": material["request_digest"],
        "sequence": event["sequence"], "updated_sequence": event["sequence"],
    }


def _transition_material(kind: str, material: object, point: Mapping[str, object], payload_digest: str, payload_length: int) -> None:
    if not isinstance(material, dict):
        raise RecoveryVerificationError("recovery:transition-material")
    if kind == "OBJECT_PENDING":
        if material != {"point_id": point["point_id"], "object_id": point["object_id"], "storage_id": point["storage_id"], "key_id": point["key_id"], "key_epoch": point["key_epoch"]} or payload_digest != point["object_id"] or payload_length != 0:
            raise RecoveryVerificationError("recovery:pending-material")
    elif kind == "VERIFIED":
        expected = {"point_id": point["point_id"], "object_id": point["object_id"], "bundle_digest": point["bundle_digest"], "bundle_length": point["bundle_length"], "storage_id": point["storage_id"], "key_id": point["key_id"], "key_epoch": point["key_epoch"]}
        if set(material) != _VERIFIED_KEYS or any(material[key] != expected[key] for key in expected) or payload_digest != point["object_id"] or payload_length != 0:
            raise RecoveryVerificationError("recovery:verified-material")
    elif kind == "INVALIDATED":
        if material != {"point_id": point["point_id"], "object_id": point["object_id"], "key_id": point["key_id"], "key_epoch": point["key_epoch"], "reason": "key-revoked"} or payload_digest != point["object_id"] or payload_length != 0:
            raise RecoveryVerificationError("recovery:invalidated-material")
    elif kind == "PUBLISHED":
        if material != {"point_id": point["point_id"], "object_id": point["object_id"], "ingress_target": "opaque", "core_target": "opaque"} or payload_digest != point["object_id"] or payload_length != 0:
            raise RecoveryVerificationError("recovery:published-material")
    else:
        raise RecoveryVerificationError("recovery:event-kind")


def _verify_event(row: sqlite3.Row, meta: sqlite3.Row, previous: str, points: dict[str, dict[str, object]], receipts: dict[str, bytes]) -> str:
    raw = bytes(row["event_raw"])
    value = _parse(raw, "recovery:event")
    if set(value) != _EVENT_RAW_KEYS or tuple(row.keys()) != _EVENT_COLUMNS:
        raise RecoveryVerificationError("recovery:event-binding")
    if any(value[key] != row[key] for key in _EVENT_COLUMNS if key in value):
        raise RecoveryVerificationError("recovery:event-binding")
    if value["schema"] != SCHEMA or value["schema_version"] != SCHEMA_VERSION or value["database_id"] != meta["database_id"] or value["chain_id"] != meta["chain_id"] or value["stream_kind"] != "POINT" or value["stream_id"] != value["point_id"] or value["event_kind"] not in EVENT_KINDS or value["before_root"] != previous or type(value["attempt"]) is not int or value["attempt"] != 0:
        raise RecoveryVerificationError("recovery:event-order")
    for key in ("event_id", "point_id", "operation_id", "request_digest", "before_root", "after_root", "material_digest", "payload_digest"):
        _hex(value[key], "recovery:event-identity")
    if type(value["sequence"]) is not int or value["sequence"] <= 0 or type(value["payload_length"]) is not int or not 0 <= value["payload_length"] <= MAX_BUNDLE_BYTES + MAX_CUSTODY_OVERHEAD_BYTES:
        raise RecoveryVerificationError("recovery:event-range")
    if value["event_id"] != _digest("event-id", {key: value[key] for key in _EVENT_RAW_KEYS if key not in {"event_id", "after_root"}}) or value["material_digest"] != _digest("material", value["material"]) or row["receipt_digest"] != _raw_digest("receipt", raw):
        raise RecoveryVerificationError("recovery:event-digest")
    if value["after_root"] != _event_root(value["sequence"], previous, value["event_id"], value["event_kind"], value["point_id"], value["next_state"], value["material_digest"], value["stream_kind"], value["stream_id"]):
        raise RecoveryVerificationError("recovery:event-root")
    kind = value["event_kind"]
    if kind == "PREPARE":
        if value["prior_state"] != "NONE" or value["next_state"] != "PREPARED" or value["point_id"] in points:
            raise RecoveryVerificationError("recovery:event-transition")
        point = _prepare_point(value["material"], value, meta)
        if value["operation_id"] != point["operation_id"] or value["request_digest"] != point["request_digest"] or value["payload_digest"] != point["bundle_digest"] or value["payload_length"] != point["bundle_length"]:
            raise RecoveryVerificationError("recovery:prepare-binding")
        points[value["point_id"]] = point
    else:
        point = points.get(value["point_id"])
        if point is None or value["operation_id"] != point["operation_id"] or value["request_digest"] != point["request_digest"]:
            raise RecoveryVerificationError("recovery:event-point")
        allowed = {"OBJECT_PENDING": ("PREPARED", "OBJECT_PENDING"), "VERIFIED": ("OBJECT_PENDING", "VERIFIED"), "PUBLISHED": ("VERIFIED", "PUBLISHED"), "INVALIDATED": ("OBJECT_PENDING", "INVALIDATED")}
        if (value["prior_state"], value["next_state"]) != allowed[kind] or point["state"] != value["prior_state"]:
            raise RecoveryVerificationError("recovery:event-transition")
        _transition_material(kind, value["material"], point, value["payload_digest"], value["payload_length"])
        point["state"] = value["next_state"]
        point["updated_sequence"] = value["sequence"]
    receipts[value["point_id"]] = raw
    return value["after_root"]


def _verify_snapshot(connection: sqlite3.Connection, *, expected_database_id: str | None, expected_config_digest: str | None) -> tuple[dict[str, object], dict[str, dict[str, object]], dict[str, bytes]]:
    tables = ("recovery_meta", "recovery_points", "recovery_events")
    if _tables(connection) != tuple(sorted(tables)):
        raise RecoveryVerificationError("recovery:tables")
    expected = {"recovery_meta": _META_COLUMNS, "recovery_points": _POINT_COLUMNS, "recovery_events": _EVENT_COLUMNS}
    for table, columns in expected.items():
        if _columns(connection, table) != columns:
            raise RecoveryVerificationError("recovery:columns")
    explicit_indexes = tuple(sorted(row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_autoindex_%' ORDER BY name").fetchall()))
    if explicit_indexes != ("recovery_events_chain_idx", "recovery_events_operation_idx", "recovery_points_state_idx"):
        raise RecoveryVerificationError("recovery:indexes")
    meta = _verify_meta(connection, expected_database_id, expected_config_digest)
    persisted_rows = connection.execute("SELECT * FROM recovery_points ORDER BY generation,point_id").fetchall()
    if len(persisted_rows) > MAX_RECOVERY_POINTS:
        raise RecoveryVerificationError("recovery:capacity")
    persisted = {row["point_id"]: row for row in persisted_rows}
    if len(persisted) != len(persisted_rows):
        raise RecoveryVerificationError("recovery:point-duplicate")
    for row in persisted_rows:
        _validate_point_shape(row, meta)
    points: dict[str, dict[str, object]] = {}
    receipts: dict[str, bytes] = {}
    event_roots: dict[int, str] = {}
    events = connection.execute("SELECT * FROM recovery_events ORDER BY sequence").fetchall()
    previous = GENESIS_ROOT
    for expected_sequence, row in enumerate(events, start=1):
        if row["sequence"] != expected_sequence:
            raise RecoveryVerificationError("recovery:event-sequence")
        previous = _verify_event(row, meta, previous, points, receipts)
        event_roots[expected_sequence] = previous
    if len(points) != len(persisted):
        raise RecoveryVerificationError("recovery:point-missing")
    for point_id, point in points.items():
        row = persisted.get(point_id)
        if row is None or dict(row) != point:
            raise RecoveryVerificationError("recovery:point-reconstruction")
    for point in sorted(points.values(), key=lambda item: int(item["generation"])):
        if point["prior_point_id"] is None:
            if point["generation"] != 1:
                raise RecoveryVerificationError("recovery:point-chain")
        else:
            prior = points.get(point["prior_point_id"])
            if prior is None or prior["generation"] >= point["generation"] or prior["updated_sequence"] >= point["sequence"] or event_roots.get(int(prior["updated_sequence"])) != point["prior_root"]:
                raise RecoveryVerificationError("recovery:point-chain")
    if meta["current_generation"] != max((int(point["generation"]) for point in points.values()), default=0) or meta["sequence"] != len(events) or meta["head_root"] != previous:
        raise RecoveryVerificationError("recovery:meta-root")
    summary = {
        "accepted": True, "schema": SCHEMA, "schema_version": SCHEMA_VERSION,
        "database_id": meta["database_id"], "chain_id": meta["chain_id"], "config_digest": meta["config_digest"], "profile_digest": meta["profile_digest"],
        "key_custody_id_digest": meta["key_custody_id_digest"], "storage_id_digest": meta["storage_id_digest"], "sequence": meta["sequence"], "head_root": meta["head_root"],
        "point_count": len(points), "event_count": len(events), "current_generation": meta["current_generation"],
        "states": {key: sum(1 for point in points.values() if point["state"] == key) for key in STATES}, "flags": dict(FIXED_FLAGS),
    }
    return summary, points, receipts


def verify_database(path: str | Path, *, expected_database_id: str | None = None, expected_config_digest: str | None = None) -> dict[str, object]:
    connection = _open(path)
    try:
        result, _points, _receipts = _verify_snapshot(connection, expected_database_id=expected_database_id, expected_config_digest=expected_config_digest)
        return result
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


def select_point(path: str | Path, *, point_id: str | None = None, generation: int | None = None, expected_database_id: str | None = None, expected_config_digest: str | None = None, allowed_states: tuple[str, ...] = STATES) -> dict[str, object]:
    if (point_id is None) == (generation is None):
        raise RecoveryVerificationError("recovery:selector")
    if point_id is not None:
        _hex(point_id, "recovery:selector")
    if generation is not None and (type(generation) is not int or not 1 <= generation <= MAX_RECOVERY_POINTS):
        raise RecoveryVerificationError("recovery:selector")
    if any(state not in STATES for state in allowed_states):
        raise RecoveryVerificationError("recovery:selector")
    connection = _open(path)
    try:
        summary, points, receipts = _verify_snapshot(connection, expected_database_id=expected_database_id, expected_config_digest=expected_config_digest)
        selected_id = point_id
        if selected_id is None:
            matches = [key for key, point in points.items() if point["generation"] == generation]
            if len(matches) != 1:
                raise RecoveryVerificationError("recovery:point-missing")
            selected_id = matches[0]
        point = points.get(selected_id)
        if point is None or point["state"] not in allowed_states:
            raise RecoveryVerificationError("recovery:point-state")
        return {"summary": dict(summary), "point": dict(point), "receipt": bytes(receipts[selected_id])}
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
    value = _parse(raw, "recovery:bootstrap", max_bytes=MAX_BOOTSTRAP_BYTES)
    required = {"schema", "schema_version", "bootstrap_id", "catalog_id", "point_id", "generation", "object_id", "bundle_digest", "bundle_length", "key_id", "key_epoch", "storage_id", "ingress_database_id", "core_database_id", "ingress_head_root", "core_head_root", "ingress_watermark", "core_watermark", "publication_receipt_digest", "flags"}
    if set(value) != required or value["schema"] != "mirror-recovery-bootstrap-v2" or value["schema_version"] != 2 or value["flags"] != FIXED_FLAGS:
        raise RecoveryVerificationError("recovery:bootstrap")
    for key in ("bootstrap_id", "catalog_id", "point_id", "object_id", "bundle_digest", "ingress_head_root", "core_head_root", "publication_receipt_digest"):
        _hex(value[key], "recovery:bootstrap-id")
    for key in ("key_id", "storage_id", "ingress_database_id", "core_database_id"):
        _opaque(value[key], "recovery:bootstrap-identity")
    if type(value["generation"]) is not int or not 1 <= value["generation"] <= MAX_RECOVERY_POINTS or type(value["bundle_length"]) is not int or not 0 < value["bundle_length"] <= MAX_BUNDLE_BYTES or type(value["key_epoch"]) is not int or value["key_epoch"] < 0 or type(value["ingress_watermark"]) is not int or value["ingress_watermark"] < 0 or type(value["core_watermark"]) is not int or value["core_watermark"] < 0:
        raise RecoveryVerificationError("recovery:bootstrap-range")
    if value["bootstrap_id"] != _digest("bootstrap-id", {key: value[key] for key in value if key not in {"bootstrap_id", "flags"}}):
        raise RecoveryVerificationError("recovery:bootstrap-id")
    return value


def logical_export(result: Mapping[str, object]) -> bytes:
    return _canonical({
        "schema": "mirror-recovery-logical-export-v2", "schema_version": 2,
        "database_id": result["database_id"], "chain_id": result["chain_id"], "config_digest": result["config_digest"], "profile_digest": result["profile_digest"],
        "sequence": result["sequence"], "head_root": result["head_root"], "point_count": result["point_count"], "event_count": result["event_count"], "states": result["states"], "flags": dict(FIXED_FLAGS),
    })


__all__ = ["SCHEMA", "SCHEMA_VERSION", "STATES", "EVENT_KINDS", "FIXED_FLAGS", "GENESIS_ROOT", "MAX_DATABASE_BYTES", "MAX_EVENT_BYTES", "MAX_BOOTSTRAP_BYTES", "MAX_BUNDLE_BYTES", "MAX_CUSTODY_OVERHEAD_BYTES", "MAX_RECOVERY_POINTS", "RecoveryVerificationError", "verify_database", "select_point", "parse_bundle", "logical_export", "parse_bootstrap", "_canonical", "_digest", "_raw_digest", "_event_root", "_parse"]
