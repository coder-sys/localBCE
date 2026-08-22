"""Durable, synthetic operational recovery for the Mirror quarantine/runtime seam.

The coordinator owns only its catalog and lifecycle.  Component semantics stay
with their existing exporters and independent verifiers.  Key custody and
immutable storage are explicit ports; this repository supplies no production
implementation for either port.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
from typing import Callable, Mapping, Protocol, runtime_checkable

from app.mirror import controlled_shadow_runtime as runtime
from app.mirror import controlled_shadow_runtime_independent as runtime_independent
from app.mirror import external_source_quarantine as quarantine
from app.mirror import external_source_quarantine_independent as quarantine_independent
from app.mirror import operational_recovery_independent as independent


SCHEMA = independent.SCHEMA
SCHEMA_VERSION = independent.SCHEMA_VERSION
STATE_PREPARED = independent.STATE_PREPARED
STATE_STORED = independent.STATE_STORED
STATE_RESTORE_VERIFIED = independent.STATE_RESTORE_VERIFIED
STATE_SUPERSEDED = independent.STATE_SUPERSEDED
STATE_INVALIDATED = independent.STATE_INVALIDATED
FIXED_FLAGS = dict(independent.FIXED_FLAGS)
BUSY_TIMEOUT_MS = independent.BUSY_TIMEOUT_MS
SAFE_REQUEST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class OperationalRecoveryError(ValueError):
    """Base class for bounded recovery failures."""


class RecoveryConflictError(OperationalRecoveryError):
    """Identity, head, lifecycle, replay, or downgrade conflict."""


class RecoveryBusyError(OperationalRecoveryError):
    """Finite SQLite writer contention exceeded the configured timeout."""


class RecoveryInjectedFault(OperationalRecoveryError):
    """Test-only precommit fault."""


class RecoveryResponseLost(OperationalRecoveryError):
    """A committed or externally stored result was intentionally not returned."""


class RecoveryIntegrityError(OperationalRecoveryError):
    """A catalog, sealed object, bundle, or restored component failed closed."""


class RecoveryStorageError(OperationalRecoveryError):
    """The immutable storage port could not prove the requested object."""


@runtime_checkable
class StateClock(Protocol):
    def now(self) -> int: ...

    def monotonic(self) -> float: ...


@dataclass(frozen=True)
class SealedRecoveryObjectV1:
    """Opaque result owned by a KeyCustodyPort; bytes are never catalog plaintext."""

    object_id: str
    key_id: str
    key_epoch: int
    key_state: str
    sealed_bytes: bytes


@runtime_checkable
class KeyCustodyPort(Protocol):
    custody_id: str

    def current_key(self) -> Mapping[str, object]: ...

    def key_state(self, key_id: str, key_epoch: int) -> str: ...

    def seal(self, plaintext: bytes, *, object_id: str) -> SealedRecoveryObjectV1: ...

    def open(self, sealed_bytes: bytes, *, key_id: str, key_epoch: int) -> bytes: ...


@runtime_checkable
class RecoveryStoragePort(Protocol):
    storage_id: str

    def put(self, object_id: str, sealed_bytes: bytes) -> Mapping[str, object]: ...

    def get(self, object_id: str) -> bytes: ...

    def stat(self, object_id: str) -> Mapping[str, object]: ...


@dataclass(frozen=True)
class OperationalRecoveryProfileV1:
    profile_id: str
    version: int
    quarantine_policy_digest: str
    runtime_profile_digest: str
    custody_id: str
    storage_id: str
    max_bundle_bytes: int = independent.MAX_BUNDLE_BYTES
    max_component_export_bytes: int = independent.MAX_COMPONENT_EXPORT_BYTES
    busy_timeout_ms: int = BUSY_TIMEOUT_MS
    max_generation: int = independent.MAX_GENERATION
    zero_phi: bool = True
    state_owned: bool = True
    synthetic_only: bool = True
    production_usable: bool = False
    activation: bool = False
    payment_authority: bool = False
    clearance_authority: bool = False
    settlement_authority: bool = False
    proofSuiteId: None = None

    def material(self) -> dict[str, object]:
        return {
            "profile_id": self.profile_id,
            "version": self.version,
            "quarantine_policy_digest": self.quarantine_policy_digest,
            "runtime_profile_digest": self.runtime_profile_digest,
            "custody_id": self.custody_id,
            "storage_id": self.storage_id,
            "max_bundle_bytes": self.max_bundle_bytes,
            "max_component_export_bytes": self.max_component_export_bytes,
            "busy_timeout_ms": self.busy_timeout_ms,
            "max_generation": self.max_generation,
            "zero_phi": self.zero_phi,
            "state_owned": self.state_owned,
            "synthetic_only": self.synthetic_only,
            "production_usable": self.production_usable,
            "activation": self.activation,
            "payment_authority": self.payment_authority,
            "clearance_authority": self.clearance_authority,
            "settlement_authority": self.settlement_authority,
            "proofSuiteId": self.proofSuiteId,
        }

    @property
    def digest(self) -> str:
        try:
            return independent.profile_digest(self.material())
        except independent.IndependentOperationalRecoveryError as exc:
            raise OperationalRecoveryError(str(exc)) from exc


def _material(value: Mapping[str, object] | object) -> dict[str, object]:
    candidate = value.material() if hasattr(value, "material") else value
    if not isinstance(candidate, Mapping):
        raise OperationalRecoveryError("recovery:profile-material")
    return dict(candidate)


def _canonical(value: object) -> bytes:
    return independent._canonical(value)


def _digest(label: str, value: object) -> str:
    return independent._digest(label, value)


def _resolve_database(path: str | Path) -> Path:
    if not isinstance(path, (str, Path)):
        raise OperationalRecoveryError("recovery:database-path")
    try:
        value = os.fspath(path)
    except TypeError as exc:
        raise OperationalRecoveryError("recovery:database-path") from exc
    if isinstance(value, bytes) or not value:
        raise OperationalRecoveryError("recovery:database-path")
    target = Path(os.path.abspath(value))
    if target.name in ("", ".", "..") or not target.parent.is_dir() or target.is_symlink() or target.parent.is_symlink():
        raise OperationalRecoveryError("recovery:database-path")
    return target


def _request_key(value: str) -> str:
    if not isinstance(value, str) or SAFE_REQUEST.fullmatch(value) is None:
        raise OperationalRecoveryError("recovery:request-key")
    lowered = value.lower()
    if any(marker in lowered for marker in ("http", "url", "token", "secret", "password", "credential", "patient", "member", "claim", "npi", "address", "email", "phone")):
        raise OperationalRecoveryError("recovery:request-key")
    return value


def _key_view(value: Mapping[str, object]) -> dict[str, object]:
    if set(value) != {"key_id", "key_epoch", "key_state"}:
        raise OperationalRecoveryError("recovery:key-identity")
    key_id = value["key_id"]
    if not isinstance(key_id, str) or independent.SAFE_TOKEN.fullmatch(key_id) is None:
        raise OperationalRecoveryError("recovery:key-id")
    epoch = value["key_epoch"]
    if type(epoch) is not int or epoch < 1 or epoch > independent.MAX_GENERATION:
        raise OperationalRecoveryError("recovery:key-epoch")
    if value["key_state"] not in independent.KEY_STATES:
        raise OperationalRecoveryError("recovery:key-state")
    return {"key_id": key_id, "key_epoch": epoch, "key_state": value["key_state"]}


def _storage_view(value: Mapping[str, object], *, object_id: str, sealed_bytes: bytes, expected_storage_id: str | None = None) -> dict[str, object]:
    expected = {"object_id", "storage_id", "sealed_digest", "sealed_length"}
    if set(value) != expected or value["object_id"] != object_id:
        raise RecoveryStorageError("recovery:storage-receipt")
    storage_id = value["storage_id"]
    if not isinstance(storage_id, str) or independent.SAFE_TOKEN.fullmatch(storage_id) is None:
        raise RecoveryStorageError("recovery:storage-id")
    if expected_storage_id is not None and storage_id != expected_storage_id:
        raise RecoveryStorageError("recovery:storage-owner")
    if type(sealed_bytes) is not bytes or not sealed_bytes or len(sealed_bytes) > independent.MAX_SEALED_BYTES:
        raise RecoveryStorageError("recovery:sealed-bytes")
    digest = hashlib.sha3_512(sealed_bytes).hexdigest()
    if value["sealed_digest"] != digest or value["sealed_length"] != len(sealed_bytes):
        raise RecoveryStorageError("recovery:storage-integrity")
    return {"object_id": object_id, "storage_id": storage_id, "sealed_digest": digest, "sealed_length": len(sealed_bytes)}


class OperationalRecoveryService:
    """One profile-owned SQLite recovery catalog and lifecycle owner."""

    def __init__(
        self,
        database: str | Path,
        *,
        profile: OperationalRecoveryProfileV1,
        quarantine_policy: Mapping[str, object] | object,
        runtime_profile: Mapping[str, object] | object,
        clock: StateClock,
        key_custody: KeyCustodyPort,
        storage: RecoveryStoragePort,
        fault_injector: Callable[[str], None] | None = None,
    ) -> None:
        self.database = _resolve_database(database)
        if not isinstance(clock, StateClock):
            raise OperationalRecoveryError("recovery:clock")
        self.profile = profile
        self.profile_material = profile.material()
        try:
            independent.verify_profile(self.profile_material)
        except independent.IndependentOperationalRecoveryError as exc:
            raise OperationalRecoveryError(str(exc)) from exc
        self.quarantine_policy_value = quarantine_policy
        self.quarantine_policy = _material(quarantine_policy)
        self.runtime_profile_value = runtime_profile
        self.runtime_profile = _material(runtime_profile)
        if quarantine_independent._policy_digest(self.quarantine_policy) != profile.quarantine_policy_digest:
            raise OperationalRecoveryError("recovery:quarantine-policy")
        if runtime_independent.profile_digest(self.runtime_profile) != profile.runtime_profile_digest:
            raise OperationalRecoveryError("recovery:runtime-profile")
        self.clock = clock
        self.key_custody = key_custody
        self.storage = storage
        try:
            custody_id = self.key_custody.custody_id
            storage_id = self.storage.storage_id
        except AttributeError as exc:
            raise OperationalRecoveryError("recovery:port-identity") from exc
        if custody_id != self.profile.custody_id or storage_id != self.profile.storage_id:
            raise OperationalRecoveryError("recovery:port-identity")
        self.fault_injector = fault_injector
        self.profile_digest = profile.digest
        self.chain_genesis = independent._genesis_root(self.profile_digest, self.profile.custody_id, self.profile.storage_id)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(self.database, timeout=self.profile.busy_timeout_ms / 1000.0, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(f"PRAGMA busy_timeout={self.profile.busy_timeout_ms}")
            connection.execute("PRAGMA journal_mode=WAL")
            return connection
        except sqlite3.OperationalError as exc:
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise RecoveryBusyError("recovery:busy") from exc
            raise OperationalRecoveryError("recovery:database-open") from exc
        except (sqlite3.Error, OSError) as exc:
            raise OperationalRecoveryError("recovery:database-open") from exc

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            tables = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            if not tables:
                connection.execute("BEGIN IMMEDIATE")
                for statement in independent.DDL:
                    connection.execute(statement)
                values = {
                    "schema": SCHEMA,
                    "schema_version": str(SCHEMA_VERSION),
                    "profile_digest": self.profile_digest,
                    "custody_id": self.profile.custody_id,
                    "storage_id": self.profile.storage_id,
                    "sequence": "0",
                    "head_root": self.chain_genesis,
                    "head_point_id": "",
                    "generation": "0",
                    "state_root": independent._state_root(0, self.chain_genesis, "", 0, self.profile.custody_id, self.profile.storage_id),
                }
                for key in sorted(values):
                    connection.execute("INSERT INTO recovery_meta(key,value) VALUES(?,?)", (key, values[key]))
                connection.commit()
            elif tables != set(independent.TABLES):
                raise OperationalRecoveryError("recovery:database-schema")
        except OperationalRecoveryError:
            if connection.in_transaction:
                connection.rollback()
            raise
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.rollback()
            raise OperationalRecoveryError("recovery:database-initialize") from exc
        finally:
            connection.close()
        try:
            independent.verify_database(self.database, profile=self.profile_material)
        except independent.IndependentOperationalRecoveryError as exc:
            raise RecoveryIntegrityError(str(exc)) from exc

    def _fault(self, point: str) -> None:
        if self.fault_injector is not None:
            self.fault_injector(point)

    @staticmethod
    def _metadata(connection: sqlite3.Connection) -> dict[str, str]:
        return {str(row["key"]): str(row["value"]) for row in connection.execute("SELECT key,value FROM recovery_meta ORDER BY key")}

    @staticmethod
    def _point(connection: sqlite3.Connection, point_id: str) -> dict[str, object] | None:
        row = connection.execute("SELECT * FROM recovery_points WHERE point_id=?", (point_id,)).fetchone()
        return dict(row) if row is not None else None

    @staticmethod
    def _operation(connection: sqlite3.Connection, operation_id: str) -> dict[str, object] | None:
        row = connection.execute("SELECT * FROM recovery_operations WHERE operation_id=?", (operation_id,)).fetchone()
        return dict(row) if row is not None else None

    def _head(self, connection: sqlite3.Connection) -> dict[str, str]:
        return self._metadata(connection)

    def _result_from_operation(self, connection: sqlite3.Connection, operation: Mapping[str, object]) -> dict[str, object]:
        meta = self._metadata(connection)
        point = self._point(connection, str(operation["point_id"]))
        if point is None:
            raise RecoveryIntegrityError("recovery:operation-point")
        return {
            "accepted": True,
            "operation_id": operation["operation_id"],
            "action": operation["action"],
            "point_id": point["point_id"],
            "generation": point["generation"],
            "state": point["state"],
            "sequence": operation["sequence"],
            "transition_id": operation["transition_id"],
            "head_root": meta["head_root"],
            "state_root": meta["state_root"],
            "receipt_raw": bytes(operation["receipt_raw"]),
            "receipt_digest": operation["receipt_digest"],
            "custody_id": self.profile.custody_id,
            "storage_id": self.profile.storage_id,
            "flags": dict(FIXED_FLAGS),
        }

    def _build_transition(
        self,
        *,
        sequence: int,
        action: str,
        point_id: str,
        prior_state: str,
        next_state: str,
        prior_root: str,
        operation_id: str,
        observed_at: int,
    ) -> dict[str, object]:
        body: dict[str, object] = {
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "transition_id": "",
            "sequence": sequence,
            "action": action,
            "point_id": point_id,
            "prior_state": prior_state,
            "next_state": next_state,
            "prior_root": prior_root,
            "next_root": "",
            "operation_id": operation_id,
            "observed_at": observed_at,
            "profile_digest": self.profile_digest,
            "custody_id": self.profile.custody_id,
            "storage_id": self.profile.storage_id,
            "flags": dict(FIXED_FLAGS),
        }
        transition_id = independent._transition_id(body)
        body["transition_id"] = transition_id
        body["next_root"] = independent._transition_after(body, transition_id)
        return {**body, "transition_raw": _canonical(body)}

    def _build_receipt(self, transition: Mapping[str, object], *, operation_id: str) -> tuple[bytes, str]:
        body: dict[str, object] = {
            "schema": independent.RECEIPT_SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "receipt_id": "",
            "operation_id": operation_id,
            "action": transition["action"],
            "point_id": transition["point_id"],
            "state": transition["next_state"],
            "sequence": transition["sequence"],
            "transition_id": transition["transition_id"],
            "prior_root": transition["prior_root"],
            "next_root": transition["next_root"],
            "profile_digest": self.profile_digest,
            "custody_id": self.profile.custody_id,
            "storage_id": self.profile.storage_id,
            "flags": dict(FIXED_FLAGS),
        }
        body["receipt_id"] = independent._receipt_id(body)
        raw = _canonical(body)
        return raw, hashlib.sha3_512(raw).hexdigest()

    def _update_meta(self, connection: sqlite3.Connection, *, sequence: int, head_root: str, head_point_id: str, generation: int) -> None:
        values = {
            "sequence": str(sequence),
            "head_root": head_root,
            "head_point_id": head_point_id,
            "generation": str(generation),
            "state_root": independent._state_root(sequence, head_root, head_point_id, generation, self.profile.custody_id, self.profile.storage_id),
        }
        for key, value in values.items():
            connection.execute("UPDATE recovery_meta SET value=? WHERE key=?", (value, key))

    def _append_locked(
        self,
        connection: sqlite3.Connection,
        *,
        action: str,
        point_id: str,
        prior_state: str,
        next_state: str,
        request_digest: str,
        request_material_digest: str,
        observed_at: int,
        point_updates: Mapping[str, object] | None = None,
        keep_head_point: bool = True,
    ) -> dict[str, object]:
        operation_id = independent._operation_id(action, request_digest)
        existing = self._operation(connection, operation_id)
        if existing is not None:
            if existing["request_material_digest"] != request_material_digest:
                raise RecoveryConflictError("recovery:operation-conflict")
            return self._result_from_operation(connection, existing)
        meta = self._metadata(connection)
        sequence = int(meta["sequence"]) + 1
        point = self._point(connection, point_id)
        if point is None or point["state"] != prior_state:
            raise RecoveryConflictError("recovery:lifecycle")
        transition = self._build_transition(
            sequence=sequence, action=action, point_id=point_id, prior_state=prior_state,
            next_state=next_state, prior_root=meta["head_root"], operation_id=operation_id, observed_at=observed_at,
        )
        receipt_raw, receipt_digest = self._build_receipt(transition, operation_id=operation_id)
        connection.execute(
            "INSERT INTO recovery_operations(operation_id,action,request_digest,request_material_digest,point_id,transition_id,sequence,receipt_digest,receipt_raw) VALUES(?,?,?,?,?,?,?,?,?)",
            (operation_id, action, request_digest, request_material_digest, point_id, transition["transition_id"], sequence, receipt_digest, receipt_raw),
        )
        connection.execute(
            "INSERT INTO recovery_transitions(transition_id,sequence,action,point_id,prior_state,next_state,prior_root,next_root,operation_id,observed_at,transition_raw) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (transition["transition_id"], sequence, action, point_id, prior_state, next_state, transition["prior_root"], transition["next_root"], operation_id, observed_at, transition["transition_raw"]),
        )
        assignments = {"state": next_state}
        if point_updates:
            assignments.update(point_updates)
        assignments_sql = ",".join(f"{key}=?" for key in assignments)
        connection.execute(f"UPDATE recovery_points SET {assignments_sql} WHERE point_id=?", tuple(assignments.values()) + (point_id,))
        head_point = meta["head_point_id"] if keep_head_point else point_id
        generation = int(meta["generation"])
        self._update_meta(connection, sequence=sequence, head_root=str(transition["next_root"]), head_point_id=head_point, generation=generation)
        return {
            "accepted": True,
            "operation_id": operation_id,
            "action": action,
            "point_id": point_id,
            "generation": point["generation"],
            "state": next_state,
            "sequence": sequence,
            "transition_id": transition["transition_id"],
            "head_root": transition["next_root"],
            "state_root": independent._state_root(sequence, str(transition["next_root"]), head_point, generation, self.profile.custody_id, self.profile.storage_id),
            "receipt_raw": receipt_raw,
            "receipt_digest": receipt_digest,
            "flags": dict(FIXED_FLAGS),
        }

    def _verify_components(self, quarantine_raw: bytes, runtime_raw: bytes) -> dict[str, object]:
        try:
            return independent.verify_component_exports(
                quarantine_raw, runtime_raw, profile=self.profile_material,
                quarantine_policy=self.quarantine_policy, runtime_profile=self.runtime_profile,
            )
        except independent.IndependentOperationalRecoveryError as exc:
            raise RecoveryIntegrityError(str(exc)) from exc

    def _build_bundle(self, *, generation: int, prior_root: str, created_at: int, quarantine_raw: bytes, runtime_raw: bytes) -> tuple[bytes, dict[str, object]]:
        try:
            return independent.build_bundle(
                profile=self.profile_material, generation=generation, prior_root=prior_root, created_at=created_at,
                quarantine_raw=quarantine_raw, runtime_raw=runtime_raw,
                quarantine_policy=self.quarantine_policy, runtime_profile=self.runtime_profile,
            )
        except independent.IndependentOperationalRecoveryError as exc:
            raise RecoveryIntegrityError(str(exc)) from exc

    def _prepare(
        self,
        request_key: str,
        *,
        generation: int,
        expected_head: str,
        quarantine_raw: bytes,
        runtime_raw: bytes,
        manifests: list[Mapping[str, object]],
    ) -> tuple[dict[str, object], bytes]:
        request_key = _request_key(request_key)
        if not isinstance(expected_head, str) or independent.HEX128.fullmatch(expected_head) is None:
            raise RecoveryConflictError("recovery:head-selector")
        request_digest = _digest("idempotency-key", request_key)
        material = {
            "generation": generation,
            "expected_head": expected_head,
            "quarantine_export_digest": manifests[0]["export_digest"],
            "runtime_export_digest": manifests[1]["export_digest"],
        }
        request_material_digest = _digest("request-material", material)
        operation_id = independent._operation_id(independent.ACTION_PREPARE, request_digest)
        self._fault("before_prepare")
        connection = self._connect()
        committed = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._operation(connection, operation_id)
            if existing is not None:
                if existing["request_material_digest"] != request_material_digest or existing["action"] != independent.ACTION_PREPARE:
                    raise RecoveryConflictError("recovery:prepare-conflict")
                point = self._point(connection, str(existing["point_id"]))
                if point is None:
                    raise RecoveryIntegrityError("recovery:prepare-point")
                bundle_raw, details = self._build_bundle(
                    generation=int(point["generation"]), prior_root=str(point["prior_root"]), created_at=int(point["created_at"]),
                    quarantine_raw=quarantine_raw, runtime_raw=runtime_raw,
                )
                if hashlib.sha3_512(bundle_raw).hexdigest() != point["bundle_digest"] or len(bundle_raw) != point["bundle_length"]:
                    raise RecoveryConflictError("recovery:prepare-payload-conflict")
                stored_manifests = [dict(row) for row in connection.execute("SELECT component_kind,component_schema,component_version,config_digest,state_root,head_id,component_sequence,export_digest,byte_length FROM recovery_manifests WHERE point_id=? ORDER BY component_kind", (point["point_id"],))]
                expected_manifests = [dict(item) for item in details["manifests"]]
                expected_rows = [dict(item) for item in expected_manifests]
                if sorted(expected_rows, key=lambda item: item["component_kind"]) != stored_manifests:
                    raise RecoveryConflictError("recovery:prepare-manifest-conflict")
                connection.commit()
                committed = True
                return point, bundle_raw
            meta = self._metadata(connection)
            current_head = meta["head_root"]
            current_generation = int(meta["generation"])
            if current_head != expected_head:
                raise RecoveryConflictError("recovery:head-conflict")
            if type(generation) is not int or generation != current_generation + 1 or generation > self.profile.max_generation:
                raise RecoveryConflictError("recovery:generation-conflict")
            created_at = self.clock.now()
            if type(created_at) is not int or created_at < 0:
                raise OperationalRecoveryError("recovery:clock-value")
            bundle_raw, details = self._build_bundle(
                generation=generation, prior_root=current_head, created_at=created_at,
                quarantine_raw=quarantine_raw, runtime_raw=runtime_raw,
            )
            bundle_digest = hashlib.sha3_512(bundle_raw).hexdigest()
            point_id = independent._point_id(self.profile_digest, generation, current_head, bundle_digest, len(bundle_raw), created_at, operation_id)
            transition = self._build_transition(
                sequence=int(meta["sequence"]) + 1, action=independent.ACTION_PREPARE, point_id=point_id,
                prior_state="", next_state=STATE_PREPARED, prior_root=current_head,
                operation_id=operation_id, observed_at=created_at,
            )
            receipt_raw, receipt_digest = self._build_receipt(transition, operation_id=operation_id)
            connection.execute(
                "INSERT INTO recovery_points(point_id,operation_id,profile_digest,generation,prior_root,bundle_digest,bundle_length,created_at,state,object_id,sealed_digest,sealed_length,storage_id,key_id,key_epoch,key_state,invalid_reason,restore_digest,restore_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (point_id, operation_id, self.profile_digest, generation, current_head, bundle_digest, len(bundle_raw), created_at, STATE_PREPARED, "", "", 0, "", "", 0, "", "", "", 0),
            )
            for manifest in details["manifests"]:
                connection.execute(
                    "INSERT INTO recovery_manifests(point_id,component_kind,component_schema,component_version,config_digest,state_root,head_id,component_sequence,export_digest,byte_length) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (point_id, manifest["component_kind"], manifest["component_schema"], manifest["component_version"], manifest["config_digest"], manifest["state_root"], manifest["head_id"], manifest["component_sequence"], manifest["export_digest"], manifest["byte_length"]),
                )
            connection.execute(
                "INSERT INTO recovery_operations(operation_id,action,request_digest,request_material_digest,point_id,transition_id,sequence,receipt_digest,receipt_raw) VALUES(?,?,?,?,?,?,?,?,?)",
                (operation_id, independent.ACTION_PREPARE, request_digest, request_material_digest, point_id, transition["transition_id"], transition["sequence"], receipt_digest, receipt_raw),
            )
            connection.execute(
                "INSERT INTO recovery_transitions(transition_id,sequence,action,point_id,prior_state,next_state,prior_root,next_root,operation_id,observed_at,transition_raw) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (transition["transition_id"], transition["sequence"], transition["action"], point_id, "", STATE_PREPARED, current_head, transition["next_root"], operation_id, created_at, transition["transition_raw"]),
            )
            self._update_meta(connection, sequence=int(transition["sequence"]), head_root=str(transition["next_root"]), head_point_id=point_id, generation=generation)
            self._fault("before_prepare_commit")
            connection.commit()
            committed = True
            self._fault("after_prepare_commit")
            return {"point_id": point_id, "generation": generation, "prior_root": current_head, "bundle_digest": bundle_digest, "bundle_length": len(bundle_raw), "created_at": created_at, "state": STATE_PREPARED}, bundle_raw
        except RecoveryResponseLost:
            if not committed and connection.in_transaction:
                connection.rollback()
            raise
        except (RecoveryInjectedFault, RecoveryConflictError, RecoveryIntegrityError, OperationalRecoveryError):
            if connection.in_transaction:
                connection.rollback()
            raise
        except sqlite3.IntegrityError as exc:
            if connection.in_transaction:
                connection.rollback()
            raise RecoveryConflictError("recovery:integrity") from exc
        except sqlite3.OperationalError as exc:
            if connection.in_transaction:
                connection.rollback()
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise RecoveryBusyError("recovery:busy") from exc
            raise OperationalRecoveryError("recovery:operational") from exc
        finally:
            connection.close()

    def _validate_sealed(self, sealed: SealedRecoveryObjectV1, *, object_id: str, bundle_digest: str, key_snapshot: Mapping[str, object]) -> dict[str, object]:
        if not isinstance(sealed, SealedRecoveryObjectV1) or sealed.object_id != object_id:
            raise RecoveryStorageError("recovery:sealed-result")
        key = _key_view({"key_id": sealed.key_id, "key_epoch": sealed.key_epoch, "key_state": sealed.key_state})
        if any(key[field] != key_snapshot[field] for field in ("key_id", "key_epoch", "key_state")):
            raise RecoveryStorageError("recovery:key-snapshot")
        if key["key_state"] != "ACTIVE":
            raise RecoveryConflictError("recovery:key-not-active")
        if type(sealed.sealed_bytes) is not bytes or not sealed.sealed_bytes or len(sealed.sealed_bytes) > independent.MAX_SEALED_BYTES:
            raise RecoveryStorageError("recovery:sealed-result")
        expected = independent._object_id(bundle_digest, str(key["key_id"]), int(key["key_epoch"]))
        if expected != object_id:
            raise RecoveryStorageError("recovery:object-identity")
        return {**key, "custody_id": self.profile.custody_id, "object_id": object_id, "sealed_bytes": bytes(sealed.sealed_bytes), "sealed_digest": hashlib.sha3_512(sealed.sealed_bytes).hexdigest(), "sealed_length": len(sealed.sealed_bytes)}

    def _record_stored(self, point_id: str, *, bundle_digest: str, sealed: Mapping[str, object], storage_receipt: Mapping[str, object]) -> dict[str, object]:
        object_id = str(sealed["object_id"])
        sealed_digest = str(sealed["sealed_digest"])
        request_digest = _digest("store-request", {"point_id": point_id, "object_id": object_id, "sealed_digest": sealed_digest, "bundle_digest": bundle_digest})
        request_material_digest = _digest("store-material", {"point_id": point_id, "object_id": object_id, "sealed_digest": sealed_digest, "bundle_digest": bundle_digest, "key_id": sealed["key_id"], "key_epoch": sealed["key_epoch"]})
        operation_id = independent._operation_id(independent.ACTION_STORE, request_digest)
        connection = self._connect()
        committed = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._operation(connection, operation_id)
            if existing is not None:
                if existing["request_material_digest"] != request_material_digest:
                    raise RecoveryConflictError("recovery:store-conflict")
                connection.commit()
                committed = True
                return self._result_from_operation(connection, existing)
            point = self._point(connection, point_id)
            if point is None or point["bundle_digest"] != bundle_digest:
                raise RecoveryConflictError("recovery:store-point")
            if point["state"] != STATE_PREPARED:
                raise RecoveryConflictError("recovery:store-lifecycle")
            if self.key_custody.key_state(str(sealed["key_id"]), int(sealed["key_epoch"])) != "ACTIVE":
                raise RecoveryConflictError("recovery:key-revoked")
            if storage_receipt["storage_id"] != self.profile.storage_id or sealed.get("custody_id") != self.profile.custody_id:
                raise RecoveryConflictError("recovery:owner-drift")
            previous_epoch = connection.execute(
                "SELECT MAX(key_epoch) FROM recovery_points WHERE sealed_length>0"
            ).fetchone()[0]
            if previous_epoch is not None and int(sealed["key_epoch"]) < int(previous_epoch):
                raise RecoveryConflictError("recovery:key-epoch-downgrade")
            self._fault("before_record_stored")
            result = self._append_locked(
                connection, action=independent.ACTION_STORE, point_id=point_id, prior_state=STATE_PREPARED,
                next_state=STATE_STORED, request_digest=request_digest, request_material_digest=request_material_digest,
                observed_at=int(self.clock.now()), point_updates={
                    "object_id": object_id, "sealed_digest": sealed_digest, "sealed_length": sealed["sealed_length"],
                    "storage_id": storage_receipt["storage_id"], "key_id": sealed["key_id"], "key_epoch": sealed["key_epoch"], "key_state": sealed["key_state"],
                },
            )
            storage_body: dict[str, object] = {
                "schema": independent.STORAGE_RECEIPT_SCHEMA, "schema_version": SCHEMA_VERSION, "receipt_id": "",
                "object_id": object_id, "storage_id": storage_receipt["storage_id"], "sealed_digest": sealed_digest,
                "sealed_length": sealed["sealed_length"], "key_id": sealed["key_id"], "key_epoch": sealed["key_epoch"],
                "key_state": sealed["key_state"], "bundle_digest": bundle_digest,
                "custody_id": self.profile.custody_id, "flags": dict(FIXED_FLAGS),
            }
            storage_body["receipt_id"] = _digest("storage-receipt-id", storage_body)
            storage_raw = _canonical(storage_body)
            storage_digest = hashlib.sha3_512(storage_raw).hexdigest()
            connection.execute(
                "INSERT INTO recovery_storage_receipts(point_id,object_id,storage_id,sealed_digest,sealed_length,key_id,key_epoch,key_state,bundle_digest,receipt_digest,receipt_raw) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (point_id, object_id, storage_receipt["storage_id"], sealed_digest, sealed["sealed_length"], sealed["key_id"], sealed["key_epoch"], sealed["key_state"], bundle_digest, storage_digest, storage_raw),
            )
            observation_id = _digest("key-observation", {"point_id": point_id, "key_id": sealed["key_id"], "key_epoch": sealed["key_epoch"], "key_state": sealed["key_state"], "operation_id": result["operation_id"]})
            connection.execute(
                "INSERT INTO recovery_key_observations(observation_id,point_id,key_id,key_epoch,key_state,observed_at) VALUES(?,?,?,?,?,?)",
                (observation_id, point_id, sealed["key_id"], sealed["key_epoch"], sealed["key_state"], int(self.clock.now())),
            )
            self._fault("before_record_stored_commit")
            connection.commit()
            committed = True
            self._fault("after_record_stored_commit")
            return result
        except RecoveryResponseLost:
            if not committed and connection.in_transaction:
                connection.rollback()
            raise
        except (RecoveryInjectedFault, RecoveryConflictError, RecoveryIntegrityError, OperationalRecoveryError):
            if connection.in_transaction:
                connection.rollback()
            raise
        except sqlite3.IntegrityError as exc:
            if connection.in_transaction:
                connection.rollback()
            raise RecoveryConflictError("recovery:integrity") from exc
        except sqlite3.OperationalError as exc:
            if connection.in_transaction:
                connection.rollback()
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise RecoveryBusyError("recovery:busy") from exc
            raise OperationalRecoveryError("recovery:operational") from exc
        finally:
            connection.close()

    def create_recovery_point(
        self,
        request_key: str,
        *,
        generation: int,
        expected_head: str,
        quarantine_export: bytes,
        runtime_export: bytes,
    ) -> dict[str, object]:
        q_snapshot = bytes(quarantine_export) if type(quarantine_export) is bytes else quarantine_export
        r_snapshot = bytes(runtime_export) if type(runtime_export) is bytes else runtime_export
        checked = self._verify_components(q_snapshot, r_snapshot)
        manifests = [checked["quarantine"], checked["runtime"]]
        prepared, bundle_raw = self._prepare(
            request_key, generation=generation, expected_head=expected_head,
            quarantine_raw=q_snapshot, runtime_raw=r_snapshot, manifests=manifests,
        )
        if prepared["state"] != STATE_PREPARED:
            connection = self._connect()
            try:
                operation = connection.execute("SELECT * FROM recovery_operations WHERE point_id=? AND action=? ORDER BY sequence DESC LIMIT 1", (prepared["point_id"], independent.ACTION_STORE)).fetchone()
                if operation is not None:
                    return self._result_from_operation(connection, dict(operation))
            finally:
                connection.close()
            raise RecoveryIntegrityError("recovery:stored-receipt")
        bundle_digest = hashlib.sha3_512(bundle_raw).hexdigest()
        try:
            key = _key_view(self.key_custody.current_key())
            object_id = independent._object_id(bundle_digest, str(key["key_id"]), int(key["key_epoch"]))
            self._fault("before_seal")
            sealed = self._validate_sealed(
                self.key_custody.seal(bundle_raw, object_id=object_id),
                object_id=object_id, bundle_digest=bundle_digest, key_snapshot=key,
            )
            stored_bytes = bytes(sealed["sealed_bytes"])
            if self.key_custody.key_state(str(key["key_id"]), int(key["key_epoch"])) != "ACTIVE":
                raise RecoveryConflictError("recovery:key-revoked")
            try:
                storage_result = self.storage.put(object_id, stored_bytes)
            except Exception as exc:
                try:
                    storage_result = self.storage.stat(object_id)
                except Exception as stat_exc:
                    raise RecoveryStorageError("recovery:storage-put-unknown") from stat_exc
            try:
                storage_bytes = self.storage.get(object_id)
            except Exception as exc:
                raise RecoveryStorageError("recovery:storage-get") from exc
            storage_view = _storage_view(storage_result, object_id=object_id, sealed_bytes=storage_bytes, expected_storage_id=self.profile.storage_id)
            if storage_bytes != stored_bytes or storage_view["sealed_digest"] != sealed["sealed_digest"]:
                raise RecoveryStorageError("recovery:storage-object-conflict")
            self._fault("after_put_before_record")
            return self._record_stored(prepared["point_id"], bundle_digest=bundle_digest, sealed=sealed, storage_receipt=storage_view)
        except RecoveryResponseLost:
            raise
        except (RecoveryStorageError, RecoveryConflictError, RecoveryIntegrityError, OperationalRecoveryError):
            raise
        except Exception as exc:
            raise RecoveryStorageError("recovery:storage") from exc

    def _open_and_verify_bundle(self, point: Mapping[str, object]) -> dict[str, object]:
        if point["state"] in {STATE_INVALIDATED, STATE_SUPERSEDED}:
            raise RecoveryConflictError("recovery:point-not-restorable")
        key_state = self.key_custody.key_state(str(point["key_id"]), int(point["key_epoch"]))
        if key_state != "ACTIVE":
            raise RecoveryIntegrityError("recovery:key-revoked")
        object_id = str(point["object_id"])
        try:
            sealed_bytes = self.storage.get(object_id)
            stat = _storage_view(self.storage.stat(object_id), object_id=object_id, sealed_bytes=sealed_bytes, expected_storage_id=self.profile.storage_id)
        except Exception as exc:
            raise RecoveryIntegrityError("recovery:storage-missing") from exc
        if stat["sealed_digest"] != point["sealed_digest"] or stat["sealed_length"] != point["sealed_length"]:
            raise RecoveryIntegrityError("recovery:storage-integrity")
        try:
            plaintext = self.key_custody.open(sealed_bytes, key_id=str(point["key_id"]), key_epoch=int(point["key_epoch"]))
            bundle = independent.verify_bundle(
                plaintext, profile=self.profile_material, quarantine_policy=self.quarantine_policy, runtime_profile=self.runtime_profile,
                expected_generation=int(point["generation"]), expected_prior_root=str(point["prior_root"]),
            )
        except independent.IndependentOperationalRecoveryError as exc:
            raise RecoveryIntegrityError(str(exc)) from exc
        if bundle["bundle_digest"] != point["bundle_digest"] or bundle["bundle_length"] != point["bundle_length"]:
            raise RecoveryIntegrityError("recovery:bundle-integrity")
        return {**bundle, "sealed_bytes": sealed_bytes, "storage": stat}

    def _record_restore(self, point_id: str, *, bundle: Mapping[str, object], duration_ms: int, expected_head: str) -> dict[str, object]:
        request_digest = _digest("restore-request", {"point_id": point_id, "bundle_digest": bundle["bundle_digest"], "quarantine_root": bundle["manifests"][0]["state_root"], "runtime_root": bundle["manifests"][1]["state_root"], "expected_head": expected_head})
        request_material_digest = _digest("restore-material", {"point_id": point_id, "bundle_digest": bundle["bundle_digest"], "expected_head": expected_head, "duration_policy": "synthetic-monotonic-local"})
        operation_id = independent._operation_id(independent.ACTION_RESTORE_VERIFIED, request_digest)
        connection = self._connect()
        committed = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._operation(connection, operation_id)
            if existing is not None:
                if existing["request_material_digest"] != request_material_digest:
                    raise RecoveryConflictError("recovery:restore-conflict")
                connection.commit()
                committed = True
                return self._result_from_operation(connection, existing)
            point = self._point(connection, point_id)
            if point is None or point["state"] != STATE_STORED:
                raise RecoveryConflictError("recovery:restore-lifecycle")
            if self._metadata(connection)["head_root"] != expected_head:
                raise RecoveryConflictError("recovery:head-conflict")
            observed_at = self.clock.now()
            transition_result = self._append_locked(
                connection, action=independent.ACTION_RESTORE_VERIFIED, point_id=point_id, prior_state=STATE_STORED,
                next_state=STATE_RESTORE_VERIFIED, request_digest=request_digest, request_material_digest=request_material_digest,
                observed_at=observed_at, point_updates={"restore_at": observed_at},
            )
            drill_id = _digest("drill-id", {"point_id": point_id, "operation_id": transition_result["operation_id"], "quarantine_root": bundle["manifests"][0]["state_root"], "runtime_root": bundle["manifests"][1]["state_root"]})
            drill_body: dict[str, object] = {
                "schema": independent.DRILL_RECEIPT_SCHEMA, "schema_version": SCHEMA_VERSION, "receipt_id": "",
                "point_id": point_id, "observed_at": observed_at, "duration_ms": duration_ms,
                "quarantine_root": bundle["manifests"][0]["state_root"], "runtime_root": bundle["manifests"][1]["state_root"],
                "custody_id": self.profile.custody_id, "storage_id": self.profile.storage_id, "flags": dict(FIXED_FLAGS),
            }
            drill_body["receipt_id"] = _digest("drill-receipt-id", drill_body)
            drill_raw = _canonical(drill_body)
            drill_digest = hashlib.sha3_512(drill_raw).hexdigest()
            connection.execute(
                "INSERT INTO recovery_drills(drill_id,point_id,observed_at,duration_ms,quarantine_root,runtime_root,receipt_digest,receipt_raw) VALUES(?,?,?,?,?,?,?,?)",
                (drill_id, point_id, observed_at, duration_ms, drill_body["quarantine_root"], drill_body["runtime_root"], drill_digest, drill_raw),
            )
            connection.execute("UPDATE recovery_points SET restore_digest=?,restore_at=? WHERE point_id=?", (drill_digest, observed_at, point_id))
            self._fault("before_restore_verified_commit")
            connection.commit()
            committed = True
            self._fault("after_restore_verified_commit")
            return transition_result
        except RecoveryResponseLost:
            if not committed and connection.in_transaction:
                connection.rollback()
            raise
        except (RecoveryInjectedFault, RecoveryConflictError, RecoveryIntegrityError, OperationalRecoveryError):
            if connection.in_transaction:
                connection.rollback()
            raise
        except sqlite3.IntegrityError as exc:
            if connection.in_transaction:
                connection.rollback()
            raise RecoveryConflictError("recovery:integrity") from exc
        except sqlite3.OperationalError as exc:
            if connection.in_transaction:
                connection.rollback()
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise RecoveryBusyError("recovery:busy") from exc
            raise OperationalRecoveryError("recovery:operational") from exc
        finally:
            connection.close()

    def restore_point(
        self,
        point_id: str,
        *,
        expected_head: str,
    ) -> dict[str, object]:
        if not isinstance(point_id, str) or independent.HEX128.fullmatch(point_id) is None:
            raise RecoveryConflictError("recovery:point-selector")
        if not isinstance(expected_head, str) or independent.HEX128.fullmatch(expected_head) is None:
            raise RecoveryConflictError("recovery:head-selector")
        connection = self._connect()
        try:
            point = self._point(connection, point_id)
            meta = self._metadata(connection)
        finally:
            connection.close()
        if point is None:
            raise RecoveryConflictError("recovery:point-missing")
        if meta["head_root"] != expected_head:
            raise RecoveryConflictError("recovery:head-conflict")
        if point["state"] == STATE_RESTORE_VERIFIED:
            if self.key_custody.key_state(str(point["key_id"]), int(point["key_epoch"])) != "ACTIVE":
                raise RecoveryIntegrityError("recovery:key-revoked")
            connection = self._connect()
            try:
                operation = connection.execute("SELECT * FROM recovery_operations WHERE point_id=? AND action=? ORDER BY sequence DESC LIMIT 1", (point_id, independent.ACTION_RESTORE_VERIFIED)).fetchone()
                if operation is None:
                    raise RecoveryIntegrityError("recovery:restore-receipt")
                return self._result_from_operation(connection, dict(operation))
            finally:
                connection.close()
        start = self.clock.monotonic()
        try:
            bundle = self._open_and_verify_bundle(point)
        except RecoveryIntegrityError as exc:
            reason = "KEY_REVOKED" if "key-revoked" in str(exc) else "OBJECT_CORRUPT"
            try:
                self.invalidate(point_id, expected_head=expected_head, reason=reason)
            except (RecoveryConflictError, RecoveryBusyError, OperationalRecoveryError):
                pass
            raise
        root = Path(tempfile.mkdtemp(prefix="mirror-recovery-drill-"))
        try:
            q_target = root / "quarantine.db"
            r_target = root / "runtime.db"
            quarantine_service = quarantine.restore_export(q_target, bundle["quarantine_raw"], policy=self.quarantine_policy_value)
            runtime_service = runtime.restore_export(r_target, bundle["runtime_raw"], profile=self.runtime_profile_value, clock=self.clock)
            q_evidence = quarantine_service.integrity()
            r_evidence = runtime_service.integrity()
            if q_evidence["state_root"] != bundle["manifests"][0]["state_root"] or r_evidence["global_head_root"] != bundle["manifests"][1]["state_root"]:
                raise RecoveryIntegrityError("recovery:restore-root")
            try:
                quarantine_service.export_bytes()
                runtime_service.export_bytes()
            except Exception as exc:
                raise RecoveryIntegrityError("recovery:restore-reverify") from exc
            duration_ms = max(0, int((self.clock.monotonic() - start) * 1000))
            return self._record_restore(point_id, bundle=bundle, duration_ms=duration_ms, expected_head=expected_head)
        except quarantine.ExternalSourceQuarantineError as exc:
            raise RecoveryIntegrityError(f"recovery:quarantine-restore:{exc}") from exc
        except runtime.ControlledShadowRuntimeError as exc:
            raise RecoveryIntegrityError(f"recovery:runtime-restore:{exc}") from exc
        finally:
            for suffix in ("", "-wal", "-shm"):
                target = Path(str(root) + suffix)
                if target.is_file():
                    target.unlink(missing_ok=True)
            for child in root.glob("**/*") if root.exists() else ():
                if child.is_file():
                    child.unlink(missing_ok=True)
            root.rmdir() if root.exists() else None

    def _mutate_lifecycle(self, *, action: str, point_id: str, expected_head: str, next_state: str, reason: str = "") -> dict[str, object]:
        if action not in {independent.ACTION_SUPERSEDE, independent.ACTION_INVALIDATE}:
            raise OperationalRecoveryError("recovery:action")
        if not isinstance(point_id, str) or independent.HEX128.fullmatch(point_id) is None or not isinstance(expected_head, str) or independent.HEX128.fullmatch(expected_head) is None:
            raise RecoveryConflictError("recovery:selector")
        if action == independent.ACTION_INVALIDATE and reason not in independent.INVALIDATION_REASONS:
            raise RecoveryConflictError("recovery:invalidation-reason")
        request_digest = _digest("lifecycle-request", {"action": action, "point_id": point_id, "expected_head": expected_head, "reason": reason})
        request_material_digest = _digest("lifecycle-material", {"action": action, "point_id": point_id, "expected_head": expected_head, "reason": reason})
        operation_id = independent._operation_id(action, request_digest)
        connection = self._connect()
        committed = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._operation(connection, operation_id)
            if existing is not None:
                if existing["request_material_digest"] != request_material_digest:
                    raise RecoveryConflictError("recovery:lifecycle-conflict")
                connection.commit()
                committed = True
                return self._result_from_operation(connection, existing)
            meta = self._metadata(connection)
            if meta["head_root"] != expected_head:
                raise RecoveryConflictError("recovery:head-conflict")
            point = self._point(connection, point_id)
            if point is None:
                raise RecoveryConflictError("recovery:point-missing")
            if action == independent.ACTION_SUPERSEDE:
                if point["state"] != STATE_RESTORE_VERIFIED:
                    raise RecoveryConflictError("recovery:supersede-lifecycle")
                newer = connection.execute("SELECT COUNT(*) FROM recovery_points WHERE generation>? AND state=?", (point["generation"], STATE_RESTORE_VERIFIED)).fetchone()[0]
                if int(newer) != 1:
                    raise RecoveryConflictError("recovery:supersede-newer")
                prior_state = STATE_RESTORE_VERIFIED
            else:
                if point["state"] not in {STATE_STORED, STATE_RESTORE_VERIFIED}:
                    raise RecoveryConflictError("recovery:invalidate-lifecycle")
                if reason == "KEY_REVOKED" and self.key_custody.key_state(str(point["key_id"]), int(point["key_epoch"])) != "REVOKED":
                    raise RecoveryConflictError("recovery:key-not-revoked")
                prior_state = str(point["state"])
            result = self._append_locked(
                connection, action=action, point_id=point_id, prior_state=prior_state, next_state=next_state,
                request_digest=request_digest, request_material_digest=request_material_digest, observed_at=int(self.clock.now()),
                point_updates={"invalid_reason": reason} if action == independent.ACTION_INVALIDATE else None,
            )
            self._fault("before_lifecycle_commit")
            connection.commit()
            committed = True
            self._fault("after_lifecycle_commit")
            return result
        except RecoveryResponseLost:
            if not committed and connection.in_transaction:
                connection.rollback()
            raise
        except (RecoveryInjectedFault, RecoveryConflictError, RecoveryIntegrityError, OperationalRecoveryError):
            if connection.in_transaction:
                connection.rollback()
            raise
        except sqlite3.IntegrityError as exc:
            if connection.in_transaction:
                connection.rollback()
            raise RecoveryConflictError("recovery:integrity") from exc
        except sqlite3.OperationalError as exc:
            if connection.in_transaction:
                connection.rollback()
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise RecoveryBusyError("recovery:busy") from exc
            raise OperationalRecoveryError("recovery:operational") from exc
        finally:
            connection.close()

    def supersede(self, point_id: str, *, expected_head: str) -> dict[str, object]:
        return self._mutate_lifecycle(action=independent.ACTION_SUPERSEDE, point_id=point_id, expected_head=expected_head, next_state=STATE_SUPERSEDED)

    def invalidate(self, point_id: str, *, expected_head: str, reason: str) -> dict[str, object]:
        return self._mutate_lifecycle(action=independent.ACTION_INVALIDATE, point_id=point_id, expected_head=expected_head, next_state=STATE_INVALIDATED, reason=reason)

    def select_latest_restore_verified(self) -> dict[str, object] | None:
        connection = self._connect()
        try:
            row = connection.execute("SELECT * FROM recovery_points WHERE state=? ORDER BY generation DESC LIMIT 1", (STATE_RESTORE_VERIFIED,)).fetchone()
            if row is None:
                return None
            point = dict(row)
        finally:
            connection.close()
        if self.key_custody.key_state(str(point["key_id"]), int(point["key_epoch"])) != "ACTIVE":
            return None
        return {"point_id": point["point_id"], "generation": point["generation"], "state": point["state"]}

    def integrity(self) -> dict[str, object]:
        try:
            return independent.verify_database(self.database, profile=self.profile_material)
        except independent.IndependentOperationalRecoveryError as exc:
            raise RecoveryIntegrityError(str(exc)) from exc

    def _snapshot(self) -> dict[str, list[dict[str, object]]]:
        connection = self._connect()
        try:
            return {table: [dict(row) for row in connection.execute(f"SELECT {','.join(columns)} FROM {table} ORDER BY rowid")] for table, columns in independent.TABLE_COLUMNS.items()}
        finally:
            connection.close()

    def export_bytes(self) -> bytes:
        self.integrity()
        tables = independent._export_rows(self._snapshot())
        body: dict[str, object] = {
            "schema": independent.EXPORT_SCHEMA,
            "schema_version": independent.EXPORT_VERSION,
            "profile": self.profile_material,
            "profile_digest": self.profile_digest,
            "tables": tables,
            "flags": dict(FIXED_FLAGS),
        }
        body["export_root"] = _digest("export-root", body)
        raw = _canonical(body)
        if len(raw) > independent.MAX_BUNDLE_BYTES:
            raise OperationalRecoveryError("recovery:export-cap")
        try:
            independent.verify_export_bytes(raw, profile=self.profile_material)
        except independent.IndependentOperationalRecoveryError as exc:
            raise RecoveryIntegrityError(str(exc)) from exc
        return raw

    def support_snapshot(self) -> dict[str, object]:
        evidence = self.integrity()
        connection = self._connect()
        try:
            invalidated = int(connection.execute("SELECT COUNT(*) FROM recovery_points WHERE state=?", (STATE_INVALIDATED,)).fetchone()[0])
            restored = int(connection.execute("SELECT MAX(restore_at) FROM recovery_points").fetchone()[0] or 0)
            key_state_rows = connection.execute(
                "SELECT key_state,COUNT(*) FROM recovery_key_observations GROUP BY key_state ORDER BY key_state"
            ).fetchall()
            drill = connection.execute(
                "SELECT duration_ms FROM recovery_drills ORDER BY observed_at DESC,drill_id DESC LIMIT 1"
            ).fetchone()
        finally:
            connection.close()
        now = self.clock.now()
        age = max(0, int(now) - restored) if restored else None
        if age is None:
            age_bucket = "NEVER"
        elif age <= 60:
            age_bucket = "0_60_SECONDS"
        elif age <= 3600:
            age_bucket = "61_SECONDS_1_HOUR"
        elif age <= 86400:
            age_bucket = "1_HOUR_1_DAY"
        else:
            age_bucket = "OVER_1_DAY"
        duration = int(drill[0]) if drill is not None else None
        if duration is None:
            duration_bucket = "NONE"
        elif duration <= 100:
            duration_bucket = "0_100_MS"
        elif duration <= 1000:
            duration_bucket = "101_1000_MS"
        else:
            duration_bucket = "OVER_1000_MS"
        return {
            "schema": "mirror-operational-recovery-support-v1",
            "schema_version": 1,
            "profile_version": self.profile.version,
            "generation": evidence["generation"],
            "state_counts": evidence["state_counts"],
            "point_count": evidence["point_count"],
            "operation_count": evidence["operation_count"],
            "transition_count": evidence["transition_count"],
            "storage_count": evidence["storage_count"],
            "restore_count": evidence["restore_count"],
            "key_epochs": evidence["key_epochs"],
            "key_state_counts": {str(row[0]): int(row[1]) for row in key_state_rows},
            "head_root": evidence["head_root"],
            "state_root": evidence["state_root"],
            "last_verified_age_bucket": age_bucket,
            "drill_duration_bucket": duration_bucket,
            "failure_counts": {"invalidated": invalidated},
            "flags": dict(independent.SUPPORT_FLAGS),
        }

    def _restore_snapshot(self, snapshot: Mapping[str, list[Mapping[str, object]]]) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            for table in reversed(independent.TABLES[1:]):
                connection.execute(f"DELETE FROM {table}")
            connection.execute("DELETE FROM recovery_meta")
            for table in independent.TABLES:
                columns = independent.TABLE_COLUMNS[table]
                for row in snapshot[table]:
                    connection.execute(f"INSERT INTO {table}({','.join(columns)}) VALUES({','.join('?' for _ in columns)})", tuple(row[column] for column in columns))
            connection.commit()
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.rollback()
            raise RecoveryIntegrityError("recovery:restore-catalog") from exc
        finally:
            connection.close()

    @classmethod
    def restore_export(
        cls,
        destination: str | Path,
        raw: bytes,
        *,
        profile: OperationalRecoveryProfileV1,
        quarantine_policy: Mapping[str, object] | object,
        runtime_profile: Mapping[str, object] | object,
        clock: StateClock,
        key_custody: KeyCustodyPort,
        storage: RecoveryStoragePort,
    ) -> "OperationalRecoveryService":
        target = _resolve_database(destination)
        if target.exists() or target.is_symlink():
            raise RecoveryConflictError("recovery:restore-target-exists")
        try:
            verified = independent.verify_export_bytes(raw, profile=profile.material())
        except independent.IndependentOperationalRecoveryError as exc:
            raise RecoveryIntegrityError(str(exc)) from exc
        stage_fd, stage_name = tempfile.mkstemp(prefix=f".{target.name}.restore-", suffix=".db", dir=target.parent)
        os.close(stage_fd)
        stage = Path(stage_name)
        try:
            service = cls(stage, profile=profile, quarantine_policy=quarantine_policy, runtime_profile=runtime_profile, clock=clock, key_custody=key_custody, storage=storage)
            service._restore_snapshot(verified["snapshot"])
            service.integrity()
            os.replace(stage, target)
            for suffix in ("-wal", "-shm"):
                Path(str(stage) + suffix).unlink(missing_ok=True)
            return cls(target, profile=profile, quarantine_policy=quarantine_policy, runtime_profile=runtime_profile, clock=clock, key_custody=key_custody, storage=storage)
        except Exception:
            stage.unlink(missing_ok=True)
            Path(str(stage) + "-wal").unlink(missing_ok=True)
            Path(str(stage) + "-shm").unlink(missing_ok=True)
            raise


def restore_export(
    destination: str | Path,
    raw: bytes,
    *,
    profile: OperationalRecoveryProfileV1,
    quarantine_policy: Mapping[str, object] | object,
    runtime_profile: Mapping[str, object] | object,
    clock: StateClock,
    key_custody: KeyCustodyPort,
    storage: RecoveryStoragePort,
) -> OperationalRecoveryService:
    return OperationalRecoveryService.restore_export(destination, raw, profile=profile, quarantine_policy=quarantine_policy, runtime_profile=runtime_profile, clock=clock, key_custody=key_custody, storage=storage)


__all__ = [
    "SCHEMA", "SCHEMA_VERSION", "STATE_PREPARED", "STATE_STORED", "STATE_RESTORE_VERIFIED", "STATE_SUPERSEDED", "STATE_INVALIDATED",
    "OperationalRecoveryError", "RecoveryConflictError", "RecoveryBusyError", "RecoveryInjectedFault", "RecoveryResponseLost",
    "RecoveryIntegrityError", "RecoveryStorageError", "StateClock", "SealedRecoveryObjectV1", "KeyCustodyPort", "RecoveryStoragePort",
    "OperationalRecoveryProfileV1", "OperationalRecoveryService", "restore_export",
]
