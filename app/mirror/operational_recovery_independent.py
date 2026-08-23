"""Independent verification for the synthetic operational-recovery catalog.

This module deliberately knows nothing about the SQLite mutation service.  It
reconstructs component manifests, the in-memory recovery bundle, catalog roots,
receipts, and export rows from bytes and fixed public component verifiers.
Production key custody and storage are ports; this module never supplies them.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Mapping

from app.mirror import controlled_shadow_runtime_independent as runtime
from app.mirror import external_source_quarantine_independent as quarantine
from app.mirror import sqlite_snapshot


SCHEMA = "mirror-operational-recovery-v2"
SCHEMA_VERSION = 2
EXPORT_SCHEMA = "mirror-operational-recovery-export-v2"
EXPORT_VERSION = 2
BUNDLE_SCHEMA = "mirror-operational-recovery-bundle-v2"
BUNDLE_VERSION = 2
RECEIPT_SCHEMA = "mirror-operational-recovery-receipt-v2"
STORAGE_RECEIPT_SCHEMA = "mirror-operational-recovery-storage-receipt-v2"
DRILL_RECEIPT_SCHEMA = "mirror-operational-recovery-drill-receipt-v2"
HEX128 = re.compile(r"^[0-9a-f]{128}$")
SAFE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

STATE_PREPARED = "PREPARED"
STATE_STORE_PENDING = "STORE_PENDING"
STATE_STORED = "STORED"
STATE_RESTORE_VERIFIED = "RESTORE_VERIFIED"
STATE_SUPERSEDED = "SUPERSEDED"
STATE_INVALIDATED = "INVALIDATED"
STATES = (STATE_PREPARED, STATE_STORE_PENDING, STATE_STORED, STATE_RESTORE_VERIFIED, STATE_SUPERSEDED, STATE_INVALIDATED)

ACTION_PREPARE = "PREPARE"
ACTION_STORE_PENDING = "STORE_PENDING"
ACTION_STORE = "STORE"
ACTION_RESTORE_VERIFIED = "RESTORE_VERIFIED"
ACTION_SUPERSEDE = "SUPERSEDE"
ACTION_INVALIDATE = "INVALIDATE"
ACTIONS = (ACTION_PREPARE, ACTION_STORE_PENDING, ACTION_STORE, ACTION_RESTORE_VERIFIED, ACTION_SUPERSEDE, ACTION_INVALIDATE)

INVALIDATION_REASONS = ("KEY_REVOKED", "OBJECT_CORRUPT", "CHAIN_INTEGRITY", "STATE_OWNED_INVALIDATION")
KEY_STATES = ("ACTIVE", "REVOKED")
MAX_BUNDLE_BYTES = 4 * 1024 * 1024
MAX_COMPONENT_EXPORT_BYTES = 2 * 1024 * 1024
MAX_SEALED_BYTES = 8 * 1024 * 1024
MAX_GENERATION = 64
MAX_ROWS = 512
BUSY_TIMEOUT_MS = 250
DOMAIN = "BL/MIRROR/OPERATIONAL_RECOVERY/"
FIXED_FLAGS = {
    "read_only": True,
    "zero_phi": True,
    "state_owned": True,
    "synthetic_only": True,
    "encryption_at_rest_qualified": False,
    "hsm_fips_qualified": False,
    "ha_qualified": False,
    "backup_dr_qualified": False,
    "production_usable": False,
    "activation": False,
    "payment_authority": False,
    "clearance_authority": False,
    "settlement_authority": False,
    "proofSuiteId": None,
}
SUPPORT_FLAGS = {
    "read_only": True,
    "zero_phi": True,
    "state_owned": True,
    "synthetic_only": True,
    "production_usable": False,
    "activation": False,
    "payment_authority": False,
    "clearance_authority": False,
    "settlement_authority": False,
    "proofSuiteId": None,
}

TABLE_COLUMNS = {
    "recovery_meta": ("key", "value"),
    "recovery_points": (
        "point_id", "operation_id", "profile_digest", "generation", "prior_root", "bundle_digest",
        "bundle_length", "created_at", "state", "object_id", "sealed_digest", "sealed_length",
        "storage_id", "key_id", "key_epoch", "key_state", "invalid_reason", "restore_digest", "restore_at",
    ),
    "recovery_operations": (
        "operation_id", "action", "request_digest", "request_material_digest", "point_id", "transition_id", "sequence",
        "receipt_digest", "receipt_raw",
    ),
    "recovery_transitions": (
        "transition_id", "sequence", "action", "point_id", "prior_state", "next_state",
        "prior_root", "next_root", "operation_id", "observed_at", "transition_raw",
    ),
    "recovery_manifests": (
        "point_id", "component_kind", "component_schema", "component_version", "config_digest",
        "state_root", "head_id", "component_sequence", "export_digest", "byte_length",
    ),
    "recovery_storage_receipts": (
        "point_id", "object_id", "storage_id", "sealed_digest", "sealed_length", "key_id",
        "key_epoch", "key_state", "bundle_digest", "receipt_digest", "receipt_raw",
    ),
    "recovery_drills": (
        "drill_id", "point_id", "observed_at", "duration_ms", "quarantine_root", "runtime_root",
        "receipt_digest", "receipt_raw",
    ),
    "recovery_key_observations": (
        "observation_id", "point_id", "key_id", "key_epoch", "key_state", "observed_at",
    ),
}
TABLES = tuple(TABLE_COLUMNS)
TABLE_BLOB_FIELDS = {
    "recovery_operations": {"receipt_raw"},
    "recovery_transitions": {"transition_raw"},
    "recovery_storage_receipts": {"receipt_raw"},
    "recovery_drills": {"receipt_raw"},
}
META_KEYS = {"schema", "schema_version", "profile_digest", "custody_id", "storage_id", "sequence", "head_root", "head_point_id", "generation", "state_root"}

DDL = (
    "CREATE TABLE recovery_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    "CREATE TABLE recovery_points ("
    "point_id TEXT PRIMARY KEY, operation_id TEXT NOT NULL UNIQUE, profile_digest TEXT NOT NULL, "
    "generation INTEGER NOT NULL, prior_root TEXT NOT NULL, bundle_digest TEXT NOT NULL, bundle_length INTEGER NOT NULL, "
    "created_at INTEGER NOT NULL, state TEXT NOT NULL, object_id TEXT NOT NULL DEFAULT '', sealed_digest TEXT NOT NULL DEFAULT '', "
    "sealed_length INTEGER NOT NULL DEFAULT 0, storage_id TEXT NOT NULL DEFAULT '', key_id TEXT NOT NULL DEFAULT '', "
    "key_epoch INTEGER NOT NULL DEFAULT 0, key_state TEXT NOT NULL DEFAULT '', invalid_reason TEXT NOT NULL DEFAULT '', "
    "restore_digest TEXT NOT NULL DEFAULT '', restore_at INTEGER NOT NULL DEFAULT 0)",
    "CREATE TABLE recovery_operations ("
    "operation_id TEXT PRIMARY KEY, action TEXT NOT NULL, request_digest TEXT NOT NULL, request_material_digest TEXT NOT NULL, point_id TEXT NOT NULL, "
    "transition_id TEXT NOT NULL, sequence INTEGER NOT NULL, receipt_digest TEXT NOT NULL, receipt_raw BLOB NOT NULL, "
    "FOREIGN KEY(point_id) REFERENCES recovery_points(point_id))",
    "CREATE TABLE recovery_transitions ("
    "transition_id TEXT PRIMARY KEY, sequence INTEGER NOT NULL, action TEXT NOT NULL, point_id TEXT NOT NULL, "
    "prior_state TEXT NOT NULL, next_state TEXT NOT NULL, prior_root TEXT NOT NULL, next_root TEXT NOT NULL, "
    "operation_id TEXT NOT NULL, observed_at INTEGER NOT NULL, transition_raw BLOB NOT NULL, "
    "FOREIGN KEY(point_id) REFERENCES recovery_points(point_id), FOREIGN KEY(operation_id) REFERENCES recovery_operations(operation_id))",
    "CREATE TABLE recovery_manifests ("
    "point_id TEXT NOT NULL, component_kind TEXT NOT NULL, component_schema TEXT NOT NULL, component_version INTEGER NOT NULL, "
    "config_digest TEXT NOT NULL, state_root TEXT NOT NULL, head_id TEXT NOT NULL, component_sequence INTEGER NOT NULL, "
    "export_digest TEXT NOT NULL, byte_length INTEGER NOT NULL, PRIMARY KEY(point_id, component_kind), "
    "FOREIGN KEY(point_id) REFERENCES recovery_points(point_id))",
    "CREATE TABLE recovery_storage_receipts ("
    "point_id TEXT PRIMARY KEY, object_id TEXT NOT NULL, storage_id TEXT NOT NULL, sealed_digest TEXT NOT NULL, "
    "sealed_length INTEGER NOT NULL, key_id TEXT NOT NULL, key_epoch INTEGER NOT NULL, key_state TEXT NOT NULL, "
    "bundle_digest TEXT NOT NULL, receipt_digest TEXT NOT NULL, receipt_raw BLOB NOT NULL, "
    "FOREIGN KEY(point_id) REFERENCES recovery_points(point_id))",
    "CREATE TABLE recovery_drills ("
    "drill_id TEXT PRIMARY KEY, point_id TEXT NOT NULL, observed_at INTEGER NOT NULL, duration_ms INTEGER NOT NULL, "
    "quarantine_root TEXT NOT NULL, runtime_root TEXT NOT NULL, receipt_digest TEXT NOT NULL, receipt_raw BLOB NOT NULL, "
    "FOREIGN KEY(point_id) REFERENCES recovery_points(point_id))",
    "CREATE TABLE recovery_key_observations ("
    "observation_id TEXT PRIMARY KEY, point_id TEXT NOT NULL, key_id TEXT NOT NULL, key_epoch INTEGER NOT NULL, "
    "key_state TEXT NOT NULL, observed_at INTEGER NOT NULL, FOREIGN KEY(point_id) REFERENCES recovery_points(point_id))",
)


class IndependentOperationalRecoveryError(ValueError):
    """A catalog, bundle, component, or receipt failed independent verification."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise IndependentOperationalRecoveryError("recovery:noncanonical") from exc


def _digest(label: str, value: object) -> str:
    h = hashlib.sha3_512()
    h.update((DOMAIN + label + "/v1\0").encode("ascii"))
    h.update(_canonical(value))
    return h.hexdigest()


def _raw_digest(raw: bytes) -> str:
    if type(raw) is not bytes:
        raise IndependentOperationalRecoveryError("recovery:raw-type")
    return hashlib.sha3_512(raw).hexdigest()


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, item in pairs:
        if key in result:
            raise IndependentOperationalRecoveryError("recovery:duplicate-key")
        result[key] = item
    return result


def _walk(value: object, *, depth: int = 0, nodes: list[int] | None = None) -> None:
    if nodes is None:
        nodes = [0]
    if depth > 16:
        raise IndependentOperationalRecoveryError("recovery:depth")
    nodes[0] += 1
    if nodes[0] > 10000:
        raise IndependentOperationalRecoveryError("recovery:nodes")
    if isinstance(value, dict):
        for key, item in value.items():
            if type(key) is not str or len(key.encode("utf-8")) > 256:
                raise IndependentOperationalRecoveryError("recovery:key")
            _walk(item, depth=depth + 1, nodes=nodes)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth=depth + 1, nodes=nodes)
    elif isinstance(value, str) and len(value.encode("utf-8")) > MAX_BUNDLE_BYTES:
        raise IndependentOperationalRecoveryError("recovery:string")


def _parse(raw: bytes, *, maximum: int = MAX_BUNDLE_BYTES) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > maximum or any(byte > 0x7F for byte in raw):
        raise IndependentOperationalRecoveryError("recovery:bytes")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicates, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
        raise IndependentOperationalRecoveryError("recovery:json") from exc
    _walk(value)
    if not isinstance(value, dict) or _canonical(value) != raw:
        raise IndependentOperationalRecoveryError("recovery:canonical")
    return value


def _hex(value: object, label: str) -> str:
    if not isinstance(value, str) or HEX128.fullmatch(value) is None:
        raise IndependentOperationalRecoveryError(f"recovery:{label}")
    return value


def _token(value: object, label: str) -> str:
    if not isinstance(value, str) or SAFE_TOKEN.fullmatch(value) is None:
        raise IndependentOperationalRecoveryError(f"recovery:{label}")
    lowered = value.lower()
    if any(marker in lowered for marker in ("http", "url", "token", "secret", "password", "credential", "patient", "member", "claim", "npi", "address", "email", "phone")):
        raise IndependentOperationalRecoveryError(f"recovery:{label}")
    return value


def _integer(value: object, label: str, *, minimum: int = 0, maximum: int = 10**12) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise IndependentOperationalRecoveryError(f"recovery:{label}")
    return value


def _expect_keys(value: object, expected: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise IndependentOperationalRecoveryError(f"recovery:{label}-keys")
    return value


def _profile_material(profile: Mapping[str, object]) -> dict[str, object]:
    expected = {
        "profile_id", "version", "quarantine_policy_digest", "runtime_profile_digest", "max_bundle_bytes",
        "max_component_export_bytes", "busy_timeout_ms", "max_generation", "zero_phi", "state_owned",
        "synthetic_only", "production_usable", "activation", "payment_authority", "clearance_authority",
        "settlement_authority", "proofSuiteId", "custody_id", "storage_id",
    }
    value = _expect_keys(profile, expected, "profile")
    configured = {
        "profile_id": _token(value["profile_id"], "profile-id"),
        "version": _integer(value["version"], "profile-version", minimum=1, maximum=16),
        "quarantine_policy_digest": _hex(value["quarantine_policy_digest"], "quarantine-policy"),
        "runtime_profile_digest": _hex(value["runtime_profile_digest"], "runtime-profile"),
        "max_bundle_bytes": _integer(value["max_bundle_bytes"], "max-bundle", minimum=1, maximum=MAX_BUNDLE_BYTES),
        "max_component_export_bytes": _integer(value["max_component_export_bytes"], "max-component", minimum=1, maximum=MAX_COMPONENT_EXPORT_BYTES),
        "busy_timeout_ms": _integer(value["busy_timeout_ms"], "busy-timeout", minimum=1, maximum=5000),
        "max_generation": _integer(value["max_generation"], "max-generation", minimum=1, maximum=MAX_GENERATION),
        "zero_phi": value["zero_phi"], "state_owned": value["state_owned"], "synthetic_only": value["synthetic_only"],
        "production_usable": value["production_usable"], "activation": value["activation"],
        "payment_authority": value["payment_authority"], "clearance_authority": value["clearance_authority"],
        "settlement_authority": value["settlement_authority"], "proofSuiteId": value["proofSuiteId"],
        "custody_id": _token(value["custody_id"], "custody-id"),
        "storage_id": _token(value["storage_id"], "storage-id"),
    }
    if configured["zero_phi"] is not True or configured["state_owned"] is not True or configured["synthetic_only"] is not True:
        raise IndependentOperationalRecoveryError("recovery:profile-safety")
    if any(configured[name] is not False for name in ("production_usable", "activation", "payment_authority", "clearance_authority", "settlement_authority")) or configured["proofSuiteId"] is not None:
        raise IndependentOperationalRecoveryError("recovery:profile-authority")
    return configured


def verify_profile(profile: Mapping[str, object]) -> dict[str, object]:
    return _profile_material(profile)


def profile_digest(profile: Mapping[str, object]) -> str:
    return _digest("profile", _profile_material(profile))


def _component_manifest(kind: str, raw: bytes, result: Mapping[str, object], *, profile: Mapping[str, object]) -> dict[str, object]:
    if kind == "EXTERNAL_SOURCE_QUARANTINE":
        state_root = result.get("state_root")
        head_id = result.get("head_artifact_id") or ""
        sequence = result.get("sequence")
        config_digest = result.get("policy_digest")
        schema = result.get("schema")
        version = result.get("schema_version")
    elif kind == "CONTROLLED_SHADOW_RUNTIME":
        state_root = result.get("global_head_root")
        head_id = result.get("chain_id")
        sequence = result.get("global_sequence")
        config_digest = result.get("profile_digest")
        schema = result.get("schema")
        version = result.get("schema_version")
    else:
        raise IndependentOperationalRecoveryError("recovery:component-kind")
    if not isinstance(state_root, str) or HEX128.fullmatch(state_root) is None or not isinstance(config_digest, str) or HEX128.fullmatch(config_digest) is None:
        raise IndependentOperationalRecoveryError("recovery:component-root")
    if not isinstance(head_id, str) or (head_id and len(head_id.encode("utf-8")) > 256) or type(sequence) is not int or sequence < 0:
        raise IndependentOperationalRecoveryError("recovery:component-sequence")
    if not isinstance(schema, str) or type(version) is not int:
        raise IndependentOperationalRecoveryError("recovery:component-schema")
    return {
        "component_kind": kind,
        "component_schema": schema,
        "component_version": version,
        "config_digest": config_digest,
        "state_root": state_root,
        "head_id": head_id,
        "component_sequence": sequence,
        "export_digest": _raw_digest(raw),
        "byte_length": len(raw),
    }


def verify_component_exports(
    quarantine_raw: bytes,
    runtime_raw: bytes,
    *,
    profile: Mapping[str, object],
    quarantine_policy: Mapping[str, object],
    runtime_profile: Mapping[str, object],
) -> dict[str, object]:
    configured = _profile_material(profile)
    if type(quarantine_raw) is not bytes or len(quarantine_raw) > configured["max_component_export_bytes"]:
        raise IndependentOperationalRecoveryError("recovery:quarantine-export-cap")
    if type(runtime_raw) is not bytes or len(runtime_raw) > configured["max_component_export_bytes"]:
        raise IndependentOperationalRecoveryError("recovery:runtime-export-cap")
    if quarantine._policy_digest(quarantine_policy) != configured["quarantine_policy_digest"]:
        raise IndependentOperationalRecoveryError("recovery:quarantine-policy")
    if runtime.profile_digest(runtime_profile) != configured["runtime_profile_digest"]:
        raise IndependentOperationalRecoveryError("recovery:runtime-profile")
    try:
        q_export = quarantine._parse(quarantine_raw, maximum=quarantine.MAX_EXPORT_BYTES, max_string_bytes=quarantine.MAX_EXPORT_BYTES)
        database_id = quarantine._database_id(q_export.get("database_id"))
        q = quarantine.verify_export_bytes(quarantine_raw, policy=quarantine_policy, database_id=database_id)
        r = runtime.verify_export_bytes(runtime_raw, profile=runtime_profile)
    except Exception as exc:
        raise IndependentOperationalRecoveryError("recovery:component-verification") from exc
    return {
        "quarantine": _component_manifest("EXTERNAL_SOURCE_QUARANTINE", quarantine_raw, q, profile=configured),
        "runtime": _component_manifest("CONTROLLED_SHADOW_RUNTIME", runtime_raw, r, profile=configured),
        "quarantine_result": q,
        "runtime_result": r,
        "quarantine_export_root": q["export_root"],
        "runtime_export_root": r["export_root"],
        "quarantine_database_id": database_id,
    }


def _component_exports(raw: bytes) -> dict[str, bytes]:
    value = _parse(raw, maximum=MAX_BUNDLE_BYTES)
    exports = value.get("component_exports")
    if not isinstance(exports, list) or len(exports) != 2:
        raise IndependentOperationalRecoveryError("recovery:bundle-components")
    result: dict[str, bytes] = {}
    for item in exports:
        if not isinstance(item, dict) or set(item) != {"component_kind", "export_hex"}:
            raise IndependentOperationalRecoveryError("recovery:bundle-export-keys")
        kind = item["component_kind"]
        if kind not in {"EXTERNAL_SOURCE_QUARANTINE", "CONTROLLED_SHADOW_RUNTIME"} or kind in result:
            raise IndependentOperationalRecoveryError("recovery:bundle-export-kind")
        encoded = item["export_hex"]
        if not isinstance(encoded, str) or len(encoded) % 2 or len(encoded) > MAX_COMPONENT_EXPORT_BYTES * 2:
            raise IndependentOperationalRecoveryError("recovery:bundle-export-hex")
        try:
            decoded = bytes.fromhex(encoded)
        except ValueError as exc:
            raise IndependentOperationalRecoveryError("recovery:bundle-export-hex") from exc
        result[kind] = decoded
    if set(result) != {"EXTERNAL_SOURCE_QUARANTINE", "CONTROLLED_SHADOW_RUNTIME"}:
        raise IndependentOperationalRecoveryError("recovery:bundle-export-set")
    return result


def build_bundle(
    *,
    profile: Mapping[str, object],
    generation: int,
    prior_root: str,
    created_at: int,
    quarantine_raw: bytes,
    runtime_raw: bytes,
    quarantine_policy: Mapping[str, object],
    runtime_profile: Mapping[str, object],
) -> tuple[bytes, dict[str, object]]:
    configured = _profile_material(profile)
    generation = _integer(generation, "generation", minimum=1, maximum=configured["max_generation"])
    prior_root = _hex(prior_root, "prior-root")
    created_at = _integer(created_at, "created-at", maximum=10**12)
    checked = verify_component_exports(quarantine_raw, runtime_raw, profile=configured, quarantine_policy=quarantine_policy, runtime_profile=runtime_profile)
    manifests = [checked["quarantine"], checked["runtime"]]
    body: dict[str, object] = {
        "schema": BUNDLE_SCHEMA,
        "schema_version": BUNDLE_VERSION,
        "profile_digest": profile_digest(configured),
        "generation": generation,
        "prior_root": prior_root,
        "created_at": created_at,
        "component_manifests": manifests,
        "component_exports": [
            {"component_kind": "EXTERNAL_SOURCE_QUARANTINE", "export_hex": bytes(quarantine_raw).hex()},
            {"component_kind": "CONTROLLED_SHADOW_RUNTIME", "export_hex": bytes(runtime_raw).hex()},
        ],
        "flags": dict(FIXED_FLAGS),
    }
    raw = _canonical(body)
    if len(raw) > configured["max_bundle_bytes"]:
        raise IndependentOperationalRecoveryError("recovery:bundle-cap")
    return raw, {
        "bundle_digest": _raw_digest(raw), "manifests": manifests,
        "generation": generation, "prior_root": prior_root, "created_at": created_at,
        "quarantine_export_root": checked["quarantine_export_root"],
        "runtime_export_root": checked["runtime_export_root"],
        "quarantine_database_id": checked["quarantine_database_id"],
    }


def verify_bundle(
    raw: bytes,
    *,
    profile: Mapping[str, object],
    quarantine_policy: Mapping[str, object],
    runtime_profile: Mapping[str, object],
    expected_generation: int | None = None,
    expected_prior_root: str | None = None,
) -> dict[str, object]:
    configured = _profile_material(profile)
    value = _parse(raw, maximum=configured["max_bundle_bytes"])
    expected_keys = {"schema", "schema_version", "profile_digest", "generation", "prior_root", "created_at", "component_manifests", "component_exports", "flags"}
    _expect_keys(value, expected_keys, "bundle")
    if value["schema"] != BUNDLE_SCHEMA or value["schema_version"] != BUNDLE_VERSION or value["profile_digest"] != profile_digest(configured) or value["flags"] != FIXED_FLAGS:
        raise IndependentOperationalRecoveryError("recovery:bundle-binding")
    generation = _integer(value["generation"], "generation", minimum=1, maximum=configured["max_generation"])
    if expected_generation is not None and generation != expected_generation:
        raise IndependentOperationalRecoveryError("recovery:bundle-generation")
    prior_root = _hex(value["prior_root"], "prior-root")
    if expected_prior_root is not None and prior_root != expected_prior_root:
        raise IndependentOperationalRecoveryError("recovery:bundle-prior-root")
    created_at = _integer(value["created_at"], "created-at", maximum=10**12)
    exports = _component_exports(raw)
    manifests = value["component_manifests"]
    if not isinstance(manifests, list) or len(manifests) != 2 or [item.get("component_kind") for item in manifests if isinstance(item, dict)] != ["EXTERNAL_SOURCE_QUARANTINE", "CONTROLLED_SHADOW_RUNTIME"]:
        raise IndependentOperationalRecoveryError("recovery:bundle-manifests")
    expected_raw, details = build_bundle(
        profile=configured, generation=generation, prior_root=prior_root, created_at=created_at,
        quarantine_raw=exports["EXTERNAL_SOURCE_QUARANTINE"], runtime_raw=exports["CONTROLLED_SHADOW_RUNTIME"],
        quarantine_policy=quarantine_policy, runtime_profile=runtime_profile,
    )
    if expected_raw != raw or value["component_manifests"] != details["manifests"]:
        raise IndependentOperationalRecoveryError("recovery:bundle-rebind")
    return {
        "accepted": True,
        "bundle_digest": _raw_digest(raw),
        "bundle_length": len(raw),
        "profile_digest": profile_digest(configured),
        "generation": generation,
        "prior_root": prior_root,
        "created_at": created_at,
        "manifests": details["manifests"],
        "quarantine_raw": exports["EXTERNAL_SOURCE_QUARANTINE"],
        "runtime_raw": exports["CONTROLLED_SHADOW_RUNTIME"],
        "quarantine_export_root": details["quarantine_export_root"],
        "runtime_export_root": details["runtime_export_root"],
        "quarantine_database_id": details["quarantine_database_id"],
    }


def _point_id(profile_digest_value: str, generation: int, prior_root: str, bundle_digest: str, bundle_length: int, created_at: int, operation_id: str) -> str:
    return _digest("point-id", {"profile_digest": profile_digest_value, "generation": generation, "prior_root": prior_root, "bundle_digest": bundle_digest, "bundle_length": bundle_length, "created_at": created_at, "operation_id": operation_id})


def _operation_id(action: str, request_digest: str) -> str:
    return _digest("operation-id", {"action": action, "request_digest": request_digest})


def _transition_id(body: Mapping[str, object]) -> str:
    material = dict(body)
    material["transition_id"] = ""
    material["next_root"] = ""
    return _digest("transition-id", material)


def _transition_after(body: Mapping[str, object], transition_id: str) -> str:
    return _digest("transition-after", {"schema": SCHEMA, "sequence": body["sequence"], "transition_id": transition_id, "point_id": body["point_id"], "prior_root": body["prior_root"], "next_state": body["next_state"]})


def _receipt_id(body: Mapping[str, object]) -> str:
    material = dict(body)
    material["receipt_id"] = ""
    return _digest("receipt-id", material)


def _object_id(bundle_digest: str, key_id: str, key_epoch: int) -> str:
    return _digest("object-id", {"bundle_digest": bundle_digest, "key_id": key_id, "key_epoch": key_epoch})


def _genesis_root(profile_digest_value: str, custody_id: str = "", storage_id: str = "") -> str:
    return _digest("genesis", {"schema": SCHEMA, "profile_digest": profile_digest_value, "custody_id": custody_id, "storage_id": storage_id})


def _state_root(sequence: int, head_root: str, head_point_id: str, generation: int, custody_id: str = "", storage_id: str = "") -> str:
    return _digest("state-root", {"sequence": sequence, "head_root": head_root, "head_point_id": head_point_id, "generation": generation, "custody_id": custody_id, "storage_id": storage_id})


def _decode_blob(value: object, label: str, maximum: int = MAX_BUNDLE_BYTES) -> bytes:
    if not isinstance(value, str) or len(value) % 2 or len(value) > maximum * 2:
        raise IndependentOperationalRecoveryError(f"recovery:{label}")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise IndependentOperationalRecoveryError(f"recovery:{label}") from exc
    if len(raw) > maximum:
        raise IndependentOperationalRecoveryError(f"recovery:{label}")
    return raw


def _check_schema(connection: sqlite3.Connection, *, immutable: bool) -> None:
    try:
        if int(connection.execute("PRAGMA foreign_keys").fetchone()[0]) != 1 or int(connection.execute("PRAGMA trusted_schema").fetchone()[0]) != 0:
            raise IndependentOperationalRecoveryError("recovery:pragma")
        journal = connection.execute("PRAGMA journal_mode").fetchone()
        if journal is None or str(journal[0]).lower() != ("delete" if immutable else "wal"):
            raise IndependentOperationalRecoveryError("recovery:journal-mode")
        tables = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
        if tables != set(TABLES):
            raise IndependentOperationalRecoveryError("recovery:tables")
        extras = list(connection.execute("SELECT type,name FROM sqlite_master WHERE type IN ('view','trigger','index') AND name NOT LIKE 'sqlite_%'"))
        if extras:
            raise IndependentOperationalRecoveryError("recovery:unknown-object")
        for table, columns in TABLE_COLUMNS.items():
            actual = tuple(str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})"))
            if actual != columns:
                raise IndependentOperationalRecoveryError(f"recovery:columns:{table}")
        if list(connection.execute("PRAGMA foreign_key_check")):
            raise IndependentOperationalRecoveryError("recovery:foreign-key")
    except sqlite3.Error as exc:
        raise IndependentOperationalRecoveryError("recovery:schema") from exc


def _snapshot(connection: sqlite3.Connection) -> dict[str, list[dict[str, object]]]:
    result: dict[str, list[dict[str, object]]] = {}
    for table, columns in TABLE_COLUMNS.items():
        count = int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        if count > MAX_ROWS:
            raise IndependentOperationalRecoveryError(f"recovery:{table}-count")
        result[table] = [dict(row) for row in connection.execute(f"SELECT {','.join(columns)} FROM {table} ORDER BY rowid LIMIT ?", (MAX_ROWS + 1,))]
        if len(result[table]) > MAX_ROWS:
            raise IndependentOperationalRecoveryError(f"recovery:{table}-count")
    return result


def _store_pending_material(point: Mapping[str, object], custody_id: str) -> str:
    return _digest("store-pending-material", {
        "point_id": point["point_id"],
        "generation": point["generation"],
        "bundle_digest": point["bundle_digest"],
        "object_id": point["object_id"],
        "storage_id": point["storage_id"],
        "key_id": point["key_id"],
        "key_epoch": point["key_epoch"],
        "key_state": point["key_state"],
        "custody_id": custody_id,
    })


def _verify_blob_row(row: Mapping[str, object], table: str) -> None:
    for field in TABLE_BLOB_FIELDS.get(table, set()):
        if type(row[field]) is not bytes:
            raise IndependentOperationalRecoveryError(f"recovery:{table}-blob")


def _verify_transition(row: Mapping[str, object], *, profile_digest_value: str, custody_id: str, storage_id: str) -> dict[str, object]:
    expected = set(TABLE_COLUMNS["recovery_transitions"])
    raw = row["transition_raw"]
    if type(raw) is not bytes:
        raise IndependentOperationalRecoveryError("recovery:transition-raw")
    value = _parse(raw, maximum=MAX_BUNDLE_BYTES)
    keys = {"schema", "schema_version", "transition_id", "sequence", "action", "point_id", "prior_state", "next_state", "prior_root", "next_root", "operation_id", "observed_at", "profile_digest", "custody_id", "storage_id", "flags"}
    _expect_keys(value, keys, "transition")
    if value["schema"] != SCHEMA or value["schema_version"] != SCHEMA_VERSION or value["profile_digest"] != profile_digest_value or value["custody_id"] != custody_id or value["storage_id"] != storage_id or value["flags"] != FIXED_FLAGS:
        raise IndependentOperationalRecoveryError("recovery:transition-binding")
    sequence = _integer(value["sequence"], "transition-sequence", minimum=1, maximum=MAX_ROWS)
    action = value["action"]
    if action not in ACTIONS:
        raise IndependentOperationalRecoveryError("recovery:transition-action")
    point_id = _hex(value["point_id"], "transition-point")
    operation_id = _hex(value["operation_id"], "transition-operation")
    prior_root = _hex(value["prior_root"], "transition-prior-root")
    next_root = _hex(value["next_root"], "transition-next-root")
    _integer(value["observed_at"], "transition-time", maximum=10**12)
    transition_id = _hex(value["transition_id"], "transition-id")
    material = dict(value)
    if _transition_id(material) != transition_id or _transition_after(material, transition_id) != next_root:
        raise IndependentOperationalRecoveryError("recovery:transition-identity")
    if set(row) != expected:
        raise IndependentOperationalRecoveryError("recovery:transition-row")
    return dict(value)


def _verify_receipt(raw: bytes, *, profile_digest_value: str, custody_id: str, storage_id: str, expected_action: str, expected_point: str, expected_state: str, expected_sequence: int, expected_transition: str, expected_prior: str, expected_next: str) -> dict[str, object]:
    value = _parse(raw, maximum=MAX_BUNDLE_BYTES)
    keys = {"schema", "schema_version", "receipt_id", "operation_id", "action", "point_id", "state", "sequence", "transition_id", "prior_root", "next_root", "profile_digest", "custody_id", "storage_id", "flags"}
    _expect_keys(value, keys, "receipt")
    if value["schema"] != RECEIPT_SCHEMA or value["schema_version"] != SCHEMA_VERSION or value["profile_digest"] != profile_digest_value or value["custody_id"] != custody_id or value["storage_id"] != storage_id or value["flags"] != FIXED_FLAGS:
        raise IndependentOperationalRecoveryError("recovery:receipt-binding")
    if value["action"] != expected_action or value["point_id"] != expected_point or value["state"] != expected_state or value["sequence"] != expected_sequence or value["transition_id"] != expected_transition or value["prior_root"] != expected_prior or value["next_root"] != expected_next:
        raise IndependentOperationalRecoveryError("recovery:receipt-fields")
    receipt_id = _hex(value["receipt_id"], "receipt-id")
    if _receipt_id(value) != receipt_id:
        raise IndependentOperationalRecoveryError("recovery:receipt-identity")
    return value


def _verify_rows(rows: Mapping[str, list[Mapping[str, object]]], *, profile: Mapping[str, object]) -> dict[str, object]:
    configured = _profile_material(profile)
    if set(rows) != set(TABLES):
        raise IndependentOperationalRecoveryError("recovery:snapshot-tables")
    meta_rows = rows["recovery_meta"]
    if len(meta_rows) != len(META_KEYS) or {row.get("key") for row in meta_rows} != META_KEYS:
        raise IndependentOperationalRecoveryError("recovery:meta")
    meta = {str(row["key"]): row["value"] for row in meta_rows}
    if any(not isinstance(v, str) for v in meta.values()) or meta["schema"] != SCHEMA or meta["schema_version"] != str(SCHEMA_VERSION) or meta["profile_digest"] != profile_digest(configured) or meta["custody_id"] != configured["custody_id"] or meta["storage_id"] != configured["storage_id"]:
        raise IndependentOperationalRecoveryError("recovery:meta-binding")
    sequence = _integer(int(meta["sequence"]), "meta-sequence", maximum=MAX_ROWS)
    generation = _integer(int(meta["generation"]), "meta-generation", maximum=configured["max_generation"])
    head_root = _hex(meta["head_root"], "meta-head-root")
    head_point_id = meta["head_point_id"]
    if head_point_id:
        _hex(head_point_id, "meta-head-point")
    state_root = _hex(meta["state_root"], "meta-state-root")
    if sequence == 0 and (head_root != _genesis_root(profile_digest(configured), configured["custody_id"], configured["storage_id"]) or head_point_id or generation != 0):
        raise IndependentOperationalRecoveryError("recovery:genesis")
    points = rows["recovery_points"]
    point_map: dict[str, Mapping[str, object]] = {}
    generations: dict[int, str] = {}
    for point in points:
        if set(point) != set(TABLE_COLUMNS["recovery_points"]):
            raise IndependentOperationalRecoveryError("recovery:point-row")
        point_id = _hex(point["point_id"], "point-id")
        if point_id in point_map or point["profile_digest"] != profile_digest(configured):
            raise IndependentOperationalRecoveryError("recovery:point-identity")
        gen = _integer(point["generation"], "point-generation", minimum=1, maximum=configured["max_generation"])
        if gen in generations:
            raise IndependentOperationalRecoveryError("recovery:generation-duplicate")
        generations[gen] = point_id
        if gen > generation:
            raise IndependentOperationalRecoveryError("recovery:generation-head")
        for field in ("prior_root", "bundle_digest"):
            _hex(point[field], f"point-{field}")
        _integer(point["bundle_length"], "point-bundle-length", minimum=1, maximum=configured["max_bundle_bytes"])
        _integer(point["created_at"], "point-created", maximum=10**12)
        if point["state"] not in STATES:
            raise IndependentOperationalRecoveryError("recovery:point-state")
        if point["state"] == STATE_PREPARED and any(point[field] not in ("", 0) for field in ("object_id", "sealed_digest", "sealed_length", "storage_id", "key_id", "key_epoch", "key_state")):
            raise IndependentOperationalRecoveryError("recovery:prepared-storage")
        pending_storage = point["state"] == STATE_STORE_PENDING or (
            point["state"] == STATE_INVALIDATED and point["sealed_length"] == 0 and point["object_id"] != ""
        )
        if pending_storage:
            _hex(point["object_id"], "point-object")
            if point["sealed_digest"] != "" or point["sealed_length"] != 0:
                raise IndependentOperationalRecoveryError("recovery:pending-sealed")
            _token(point["storage_id"], "point-storage")
            if point["storage_id"] != configured["storage_id"]:
                raise IndependentOperationalRecoveryError("recovery:storage-owner")
            _token(point["key_id"], "point-key")
            _integer(point["key_epoch"], "point-key-epoch", minimum=1, maximum=MAX_GENERATION)
            if point["key_state"] != "ACTIVE":
                raise IndependentOperationalRecoveryError("recovery:pending-key-state")
            if point["object_id"] != _object_id(str(point["bundle_digest"]), str(point["key_id"]), int(point["key_epoch"])):
                raise IndependentOperationalRecoveryError("recovery:object-identity")
        if point["state"] not in {STATE_PREPARED, STATE_STORE_PENDING} and not pending_storage:
            _hex(point["object_id"], "point-object")
            _hex(point["sealed_digest"], "point-sealed")
            _integer(point["sealed_length"], "point-sealed-length", minimum=1, maximum=MAX_SEALED_BYTES)
            _token(point["storage_id"], "point-storage")
            if point["storage_id"] != configured["storage_id"]:
                raise IndependentOperationalRecoveryError("recovery:storage-owner")
            _token(point["key_id"], "point-key")
            _integer(point["key_epoch"], "point-key-epoch", minimum=1, maximum=MAX_GENERATION)
            if point["key_state"] not in KEY_STATES:
                raise IndependentOperationalRecoveryError("recovery:point-key-state")
            if point["object_id"] != _object_id(str(point["bundle_digest"]), str(point["key_id"]), int(point["key_epoch"])):
                raise IndependentOperationalRecoveryError("recovery:object-identity")
        if point["state"] == STATE_INVALIDATED and point["invalid_reason"] not in INVALIDATION_REASONS:
            raise IndependentOperationalRecoveryError("recovery:invalid-reason")
        if point["state"] != STATE_INVALIDATED and point["invalid_reason"] != "":
            raise IndependentOperationalRecoveryError("recovery:unexpected-invalid-reason")
        operation_id = _hex(point["operation_id"], "point-operation")
        expected_point = _point_id(profile_digest(configured), gen, str(point["prior_root"]), str(point["bundle_digest"]), int(point["bundle_length"]), int(point["created_at"]), operation_id)
        if expected_point != point_id:
            raise IndependentOperationalRecoveryError("recovery:point-identity")
        point_map[point_id] = point
    if generation != (max(generations) if generations else 0) or (head_point_id and head_point_id != generations.get(generation)):
        raise IndependentOperationalRecoveryError("recovery:head-generation")
    manifests = rows["recovery_manifests"]
    by_point: dict[str, list[Mapping[str, object]]] = {}
    for manifest in manifests:
        if set(manifest) != set(TABLE_COLUMNS["recovery_manifests"]):
            raise IndependentOperationalRecoveryError("recovery:manifest-row")
        pid = _hex(manifest["point_id"], "manifest-point")
        if pid not in point_map or manifest["component_kind"] not in {"EXTERNAL_SOURCE_QUARANTINE", "CONTROLLED_SHADOW_RUNTIME"}:
            raise IndependentOperationalRecoveryError("recovery:manifest-binding")
        by_point.setdefault(pid, []).append(manifest)
        _token(manifest["component_schema"], "manifest-schema")
        _integer(manifest["component_version"], "manifest-version", minimum=1, maximum=16)
        _hex(manifest["config_digest"], "manifest-config")
        _hex(manifest["state_root"], "manifest-root")
        if manifest["head_id"]:
            if not isinstance(manifest["head_id"], str) or len(manifest["head_id"].encode("utf-8")) > 256:
                raise IndependentOperationalRecoveryError("recovery:manifest-head")
        _integer(manifest["component_sequence"], "manifest-sequence", maximum=MAX_ROWS)
        _hex(manifest["export_digest"], "manifest-export")
        _integer(manifest["byte_length"], "manifest-length", minimum=1, maximum=configured["max_component_export_bytes"])
    if any(len(by_point.get(pid, [])) != 2 for pid in point_map):
        raise IndependentOperationalRecoveryError("recovery:manifest-count")
    transitions = rows["recovery_transitions"]
    if len(transitions) != sequence:
        raise IndependentOperationalRecoveryError("recovery:transition-count")
    transition_by_point: dict[str, list[Mapping[str, object]]] = {}
    previous_root = _genesis_root(profile_digest(configured), configured["custody_id"], configured["storage_id"])
    for expected_sequence, row in enumerate(transitions, 1):
        if row["sequence"] != expected_sequence or row["prior_root"] != previous_root:
            raise IndependentOperationalRecoveryError("recovery:transition-order")
        value = _verify_transition(row, profile_digest_value=profile_digest(configured), custody_id=str(configured["custody_id"]), storage_id=str(configured["storage_id"]))
        pid = str(value["point_id"])
        if pid not in point_map:
            raise IndependentOperationalRecoveryError("recovery:transition-point")
        transition_by_point.setdefault(pid, []).append(value)
        legal = {
            ACTION_PREPARE: ("", STATE_PREPARED),
            ACTION_STORE_PENDING: (STATE_PREPARED, STATE_STORE_PENDING),
            ACTION_STORE: (STATE_STORE_PENDING, STATE_STORED),
            ACTION_RESTORE_VERIFIED: (STATE_STORED, STATE_RESTORE_VERIFIED),
            ACTION_SUPERSEDE: (STATE_RESTORE_VERIFIED, STATE_SUPERSEDED),
            ACTION_INVALIDATE: (STATE_STORED, STATE_INVALIDATED),
        }
        if value["action"] == ACTION_INVALIDATE:
            if value["prior_state"] not in {STATE_STORE_PENDING, STATE_STORED, STATE_RESTORE_VERIFIED} or value["next_state"] != STATE_INVALIDATED:
                raise IndependentOperationalRecoveryError("recovery:transition-lifecycle")
        elif tuple((value["prior_state"], value["next_state"])) != legal[value["action"]]:
            raise IndependentOperationalRecoveryError("recovery:transition-lifecycle")
        previous_root = str(value["next_root"])
    if sequence == 0 and previous_root != head_root:
        raise IndependentOperationalRecoveryError("recovery:head-root")
    if sequence and previous_root != head_root:
        raise IndependentOperationalRecoveryError("recovery:head-root")
    if state_root != _state_root(sequence, head_root, head_point_id, generation, configured["custody_id"], configured["storage_id"]):
        raise IndependentOperationalRecoveryError("recovery:state-root")
    operations = rows["recovery_operations"]
    operation_map: dict[str, Mapping[str, object]] = {}
    for op in operations:
        if set(op) != set(TABLE_COLUMNS["recovery_operations"]):
            raise IndependentOperationalRecoveryError("recovery:operation-row")
        _verify_blob_row(op, "recovery_operations")
        oid = _hex(op["operation_id"], "operation-id")
        if oid in operation_map or _operation_id(str(op["action"]), str(op["request_digest"])) != oid or op["action"] not in ACTIONS:
            raise IndependentOperationalRecoveryError("recovery:operation-identity")
        if str(op["point_id"]) not in point_map:
            raise IndependentOperationalRecoveryError("recovery:operation-point")
        transition_id = _hex(op["transition_id"], "operation-transition")
        seq = _integer(op["sequence"], "operation-sequence", minimum=1, maximum=MAX_ROWS)
        _hex(op["request_digest"], "operation-request")
        _hex(op["request_material_digest"], "operation-request-material")
        _hex(op["receipt_digest"], "operation-receipt")
        operation_map[oid] = op
        if seq > sequence:
            raise IndependentOperationalRecoveryError("recovery:operation-sequence")
        matching = [item for item in transitions if item["transition_id"] == transition_id and item["operation_id"] == oid]
        if len(matching) != 1:
            raise IndependentOperationalRecoveryError("recovery:operation-transition")
        t = matching[0]
        if (
            op["point_id"] != t["point_id"]
            or op["action"] != t["action"]
            or int(op["sequence"]) != int(t["sequence"])
        ):
            raise IndependentOperationalRecoveryError("recovery:operation-transition")
        point = point_map[str(op["point_id"])]
        if op["action"] == ACTION_STORE_PENDING:
            if op["request_material_digest"] != _store_pending_material(point, str(configured["custody_id"])):
                raise IndependentOperationalRecoveryError("recovery:pending-material")
        elif op["action"] == ACTION_STORE:
            expected_material = _digest("store-material", {
                "point_id": point["point_id"], "object_id": point["object_id"],
                "sealed_digest": point["sealed_digest"], "bundle_digest": point["bundle_digest"],
                "key_id": point["key_id"], "key_epoch": point["key_epoch"],
            })
            if op["request_material_digest"] != expected_material:
                raise IndependentOperationalRecoveryError("recovery:store-material")
        receipt = _verify_receipt(bytes(op["receipt_raw"]), profile_digest_value=profile_digest(configured), custody_id=str(configured["custody_id"]), storage_id=str(configured["storage_id"]), expected_action=str(op["action"]), expected_point=str(op["point_id"]), expected_state=str(t["next_state"]), expected_sequence=seq, expected_transition=transition_id, expected_prior=str(t["prior_root"]), expected_next=str(t["next_root"]))
        if _raw_digest(bytes(op["receipt_raw"])) != op["receipt_digest"] or receipt["operation_id"] != oid:
            raise IndependentOperationalRecoveryError("recovery:operation-receipt")
    if len(operation_map) != len(transitions):
        raise IndependentOperationalRecoveryError("recovery:operation-count")
    for pid, point in point_map.items():
        ts = transition_by_point.get(pid, [])
        if not ts or ts[-1]["next_state"] != point["state"]:
            raise IndependentOperationalRecoveryError("recovery:point-head")
        if point["operation_id"] != ts[0]["operation_id"] or ts[0]["action"] != ACTION_PREPARE or ts[0]["next_state"] != STATE_PREPARED:
            raise IndependentOperationalRecoveryError("recovery:point-prepare")
        if point["prior_root"] != ts[0]["prior_root"]:
            raise IndependentOperationalRecoveryError("recovery:point-prior")
        if point["state"] == STATE_STORE_PENDING or (point["state"] == STATE_INVALIDATED and point["sealed_length"] == 0):
            pending = [item for item in ts if item["action"] == ACTION_STORE_PENDING]
            if len(pending) != 1:
                raise IndependentOperationalRecoveryError("recovery:pending-transition")
    storage_rows = rows["recovery_storage_receipts"]
    storage_map: dict[str, Mapping[str, object]] = {}
    for receipt in storage_rows:
        if set(receipt) != set(TABLE_COLUMNS["recovery_storage_receipts"]):
            raise IndependentOperationalRecoveryError("recovery:storage-row")
        _verify_blob_row(receipt, "recovery_storage_receipts")
        pid = _hex(receipt["point_id"], "storage-point")
        if pid not in point_map or pid in storage_map:
            raise IndependentOperationalRecoveryError("recovery:storage-point")
        for field in ("object_id", "sealed_digest", "bundle_digest", "receipt_digest"):
            _hex(receipt[field], f"storage-{field}")
        _token(receipt["storage_id"], "storage-id")
        if receipt["storage_id"] != configured["storage_id"]:
            raise IndependentOperationalRecoveryError("recovery:storage-owner")
        _token(receipt["key_id"], "storage-key")
        if receipt["key_state"] not in KEY_STATES:
            raise IndependentOperationalRecoveryError("recovery:storage-key-state")
        _integer(receipt["sealed_length"], "storage-length", minimum=1, maximum=MAX_SEALED_BYTES)
        _integer(receipt["key_epoch"], "storage-key-epoch", minimum=1, maximum=MAX_GENERATION)
        raw = bytes(receipt["receipt_raw"])
        value = _parse(raw, maximum=MAX_BUNDLE_BYTES)
        keys = {"schema", "schema_version", "receipt_id", "object_id", "storage_id", "sealed_digest", "sealed_length", "key_id", "key_epoch", "key_state", "bundle_digest", "custody_id", "flags"}
        _expect_keys(value, keys, "storage-receipt")
        if value["schema"] != STORAGE_RECEIPT_SCHEMA or value["schema_version"] != SCHEMA_VERSION or value["custody_id"] != configured["custody_id"] or value["storage_id"] != configured["storage_id"] or value["flags"] != FIXED_FLAGS:
            raise IndependentOperationalRecoveryError("recovery:storage-receipt")
        receipt_material = dict(value)
        receipt_material["receipt_id"] = ""
        if _digest("storage-receipt-id", receipt_material) != value["receipt_id"]:
            raise IndependentOperationalRecoveryError("recovery:storage-receipt-identity")
        if any(value[field] != receipt[field] for field in ("object_id", "storage_id", "sealed_digest", "sealed_length", "key_id", "key_epoch", "key_state", "bundle_digest")) or value["custody_id"] != configured["custody_id"] or _raw_digest(raw) != receipt["receipt_digest"]:
            raise IndependentOperationalRecoveryError("recovery:storage-receipt-binding")
        storage_map[pid] = receipt
        point = point_map[pid]
        if any(point[field] != receipt[field] for field in ("object_id", "sealed_digest", "sealed_length", "storage_id", "key_id", "key_epoch", "key_state", "bundle_digest")):
            raise IndependentOperationalRecoveryError("recovery:point-storage-binding")
    for pid, point in point_map.items():
        if point["state"] in {STATE_STORED, STATE_RESTORE_VERIFIED, STATE_SUPERSEDED} and pid not in storage_map:
            raise IndependentOperationalRecoveryError("recovery:missing-storage")
    drills = rows["recovery_drills"]
    drill_points: set[str] = set()
    for drill in drills:
        if set(drill) != set(TABLE_COLUMNS["recovery_drills"]):
            raise IndependentOperationalRecoveryError("recovery:drill-row")
        _verify_blob_row(drill, "recovery_drills")
        did = _hex(drill["drill_id"], "drill-id")
        pid = _hex(drill["point_id"], "drill-point")
        if pid not in point_map or pid in drill_points:
            raise IndependentOperationalRecoveryError("recovery:drill-point")
        drill_points.add(pid)
        _integer(drill["observed_at"], "drill-time", maximum=10**12)
        _integer(drill["duration_ms"], "drill-duration", maximum=10**9)
        _hex(drill["quarantine_root"], "drill-quarantine-root")
        _hex(drill["runtime_root"], "drill-runtime-root")
        _hex(drill["receipt_digest"], "drill-receipt")
        raw = bytes(drill["receipt_raw"])
        value = _parse(raw, maximum=MAX_BUNDLE_BYTES)
        keys = {"schema", "schema_version", "receipt_id", "point_id", "observed_at", "duration_ms", "quarantine_root", "runtime_root", "custody_id", "storage_id", "flags"}
        _expect_keys(value, keys, "drill-receipt")
        if value["schema"] != DRILL_RECEIPT_SCHEMA or value["schema_version"] != SCHEMA_VERSION or value["custody_id"] != configured["custody_id"] or value["storage_id"] != configured["storage_id"] or value["flags"] != FIXED_FLAGS or value["point_id"] != pid or _raw_digest(raw) != drill["receipt_digest"]:
            raise IndependentOperationalRecoveryError("recovery:drill-receipt")
        if any(value[field] != drill[field] for field in ("observed_at", "duration_ms", "quarantine_root", "runtime_root")) or value["custody_id"] != configured["custody_id"] or value["storage_id"] != configured["storage_id"]:
            raise IndependentOperationalRecoveryError("recovery:drill-binding")
        receipt_material = dict(value)
        receipt_material["receipt_id"] = ""
        if _digest("drill-receipt-id", receipt_material) != value["receipt_id"]:
            raise IndependentOperationalRecoveryError("recovery:drill-identity")
    for pid, point in point_map.items():
        if point["state"] in {STATE_RESTORE_VERIFIED, STATE_SUPERSEDED} and pid not in drill_points:
            raise IndependentOperationalRecoveryError("recovery:missing-drill")
        if point["state"] == STATE_RESTORE_VERIFIED and point["restore_digest"] == "":
            raise IndependentOperationalRecoveryError("recovery:restore-binding")
        if point["state"] == STATE_PREPARED and point["restore_digest"] != "":
            raise IndependentOperationalRecoveryError("recovery:prepared-restore")
        if point["restore_digest"] and not any(drill["receipt_digest"] == point["restore_digest"] for drill in drills if drill["point_id"] == pid):
            raise IndependentOperationalRecoveryError("recovery:restore-binding")
    for pid, point in point_map.items():
        if point["state"] == STATE_SUPERSEDED and not any(int(other["generation"]) > int(point["generation"]) and other["state"] in {STATE_RESTORE_VERIFIED, STATE_SUPERSEDED} for other in point_map.values()):
            raise IndependentOperationalRecoveryError("recovery:supersede-newer")
    key_rows = rows["recovery_key_observations"]
    seen_keys: set[str] = set()
    seen_key_points: set[str] = set()
    for item in key_rows:
        if set(item) != set(TABLE_COLUMNS["recovery_key_observations"]):
            raise IndependentOperationalRecoveryError("recovery:key-row")
        oid = _hex(item["observation_id"], "key-observation")
        if oid in seen_keys:
            raise IndependentOperationalRecoveryError("recovery:key-duplicate")
        seen_keys.add(oid)
        pid = _hex(item["point_id"], "key-point")
        if pid in seen_key_points or pid not in storage_map:
            raise IndependentOperationalRecoveryError("recovery:key-point")
        seen_key_points.add(pid)
        _token(item["key_id"], "key-id")
        _integer(item["key_epoch"], "key-epoch", minimum=1, maximum=MAX_GENERATION)
        if item["key_state"] not in KEY_STATES:
            raise IndependentOperationalRecoveryError("recovery:key-state")
        _integer(item["observed_at"], "key-time", maximum=10**12)
        storage = storage_map[pid]
        if any(item[field] != storage[field] for field in ("key_id", "key_epoch", "key_state")):
            raise IndependentOperationalRecoveryError("recovery:key-binding")
    if len(key_rows) != len(storage_rows):
        raise IndependentOperationalRecoveryError("recovery:key-count")
    epochs_by_generation = sorted((int(point["generation"]), int(point["key_epoch"])) for point in point_map.values() if int(point["key_epoch"]) > 0)
    if any(right[1] < left[1] for left, right in zip(epochs_by_generation, epochs_by_generation[1:])):
        raise IndependentOperationalRecoveryError("recovery:key-epoch-downgrade")
    return {
        "accepted": True,
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "profile_digest": profile_digest(configured),
        "sequence": sequence,
        "head_root": head_root,
        "head_point_id": head_point_id or None,
        "generation": generation,
        "state_root": state_root,
        "point_count": len(points),
        "operation_count": len(operations),
        "transition_count": len(transitions),
        "storage_count": len(storage_rows),
        "restore_count": len(drills),
        "state_counts": {state: sum(point["state"] == state for point in points) for state in STATES},
        "key_epochs": sorted({int(item["key_epoch"]) for item in key_rows}),
    }


def snapshot_database(path: str | Path, *, profile: Mapping[str, object]) -> dict[str, object]:
    try:
        image = sqlite_snapshot.read_only_image(
            path, max_database_bytes=64 * 1024 * 1024, max_sidecar_bytes=64 * 1024 * 1024,
        )
    except sqlite_snapshot.SQLiteSnapshotError as exc:
        code = "journal-mode" if str(exc) == "journal-mode" else "database"
        raise IndependentOperationalRecoveryError(f"recovery:{code}") from exc
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(image.uri, uri=True, timeout=BUSY_TIMEOUT_MS / 1000.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("BEGIN")
        _check_schema(connection, immutable=image.immutable)
        rows = _snapshot(connection)
        result = _verify_rows(rows, profile=profile)
        connection.commit()
        return {**result, "snapshot": rows}
    except IndependentOperationalRecoveryError:
        raise
    except (sqlite3.Error, OSError, ValueError, TypeError, KeyError) as exc:
        raise IndependentOperationalRecoveryError("recovery:database-corrupt") from exc
    finally:
        if connection is not None:
            connection.close()


def verify_database(path: str | Path, *, profile: Mapping[str, object]) -> dict[str, object]:
    result = snapshot_database(path, profile=profile)
    return {key: value for key, value in result.items() if key != "snapshot"}


def _export_rows(rows: Mapping[str, list[Mapping[str, object]]]) -> dict[str, list[dict[str, object]]]:
    result: dict[str, list[dict[str, object]]] = {}
    for table, columns in TABLE_COLUMNS.items():
        converted: list[dict[str, object]] = []
        for row in rows[table]:
            item: dict[str, object] = {}
            for column in columns:
                value = row[column]
                if column in TABLE_BLOB_FIELDS.get(table, set()):
                    item[column[:-4] + "_hex"] = bytes(value).hex()
                else:
                    item[column] = value
            converted.append(item)
        result[table] = converted
    return result


def _import_rows(value: Mapping[str, object]) -> dict[str, list[dict[str, object]]]:
    if set(value) != set(TABLES):
        raise IndependentOperationalRecoveryError("recovery:export-tables")
    result: dict[str, list[dict[str, object]]] = {}
    for table, columns in TABLE_COLUMNS.items():
        values = value[table]
        if not isinstance(values, list) or len(values) > MAX_ROWS:
            raise IndependentOperationalRecoveryError("recovery:export-count")
        result[table] = []
        for item in values:
            if not isinstance(item, dict):
                raise IndependentOperationalRecoveryError("recovery:export-row")
            expected = set(columns)
            actual: set[str] = set()
            for key in item:
                if key in expected:
                    actual.add(key)
                    continue
                matches = [column for column in TABLE_BLOB_FIELDS.get(table, set()) if column[:-4] + "_hex" == key]
                if len(matches) != 1:
                    raise IndependentOperationalRecoveryError("recovery:export-keys")
                actual.add(matches[0])
            if actual != expected:
                raise IndependentOperationalRecoveryError("recovery:export-keys")
            row: dict[str, object] = {}
            for column in columns:
                encoded = column[:-4] + "_hex" if column in TABLE_BLOB_FIELDS.get(table, set()) else column
                if encoded not in item:
                    raise IndependentOperationalRecoveryError("recovery:export-column")
                row[column] = _decode_blob(item[encoded], f"export-{table}-{column}", MAX_BUNDLE_BYTES) if column in TABLE_BLOB_FIELDS.get(table, set()) else item[encoded]
            result[table].append(row)
    return result


def verify_export_bytes(raw: bytes, *, profile: Mapping[str, object]) -> dict[str, object]:
    configured = _profile_material(profile)
    value = _parse(raw, maximum=MAX_BUNDLE_BYTES)
    expected = {"schema", "schema_version", "profile", "profile_digest", "tables", "flags", "export_root"}
    _expect_keys(value, expected, "export")
    if value["schema"] != EXPORT_SCHEMA or value["schema_version"] != EXPORT_VERSION or value["profile"] != configured or value["profile_digest"] != profile_digest(configured) or value["flags"] != FIXED_FLAGS:
        raise IndependentOperationalRecoveryError("recovery:export-binding")
    body = dict(value)
    root = _hex(body.pop("export_root"), "export-root")
    if root != _digest("export-root", body):
        raise IndependentOperationalRecoveryError("recovery:export-root")
    rows = _import_rows(value["tables"])
    return {**_verify_rows(rows, profile=configured), "export_root": root, "snapshot": rows}


__all__ = [
    "SCHEMA", "SCHEMA_VERSION", "EXPORT_SCHEMA", "EXPORT_VERSION", "BUNDLE_SCHEMA", "BUNDLE_VERSION",
    "RECEIPT_SCHEMA", "STORAGE_RECEIPT_SCHEMA", "DRILL_RECEIPT_SCHEMA", "STATE_PREPARED", "STATE_STORE_PENDING", "STATE_STORED",
    "STATE_RESTORE_VERIFIED", "STATE_SUPERSEDED", "STATE_INVALIDATED", "STATES", "ACTION_PREPARE", "ACTION_STORE_PENDING", "ACTION_STORE",
    "ACTION_RESTORE_VERIFIED", "ACTION_SUPERSEDE", "ACTION_INVALIDATE", "ACTIONS", "INVALIDATION_REASONS", "KEY_STATES",
    "MAX_BUNDLE_BYTES", "MAX_COMPONENT_EXPORT_BYTES", "MAX_SEALED_BYTES", "MAX_GENERATION", "BUSY_TIMEOUT_MS",
    "FIXED_FLAGS", "SUPPORT_FLAGS", "TABLE_COLUMNS", "TABLES", "DDL", "IndependentOperationalRecoveryError",
    "verify_profile", "profile_digest", "verify_component_exports", "build_bundle", "verify_bundle", "snapshot_database", "verify_database",
    "verify_export_bytes", "_canonical", "_digest", "_raw_digest", "_point_id", "_operation_id", "_transition_id",
    "_transition_after", "_receipt_id", "_object_id", "_genesis_root", "_state_root", "_store_pending_material", "_export_rows", "_import_rows",
]
