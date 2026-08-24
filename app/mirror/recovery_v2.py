"""Three-table, catalog-only recovery owner for the Mirror V2 stores.

The coordinator persists identities, lifecycle events, and recovery receipts.
Component images exist only as bounded process-memory bytes and opaque sealed
objects owned by the injected custody/storage ports.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import json
from pathlib import Path
import sqlite3
from typing import Mapping, Protocol

from app.mirror import core_v2_independent as core
from app.mirror import ingress_v2_independent as ingress
from app.mirror import recovery_v2_independent as independent
from app.mirror import restore_publication
from app.mirror.error_boundary import raise_redacted


SCHEMA = independent.SCHEMA
SCHEMA_VERSION = independent.SCHEMA_VERSION
TABLES = ("recovery_meta", "recovery_points", "recovery_events")
FIXED_FLAGS = dict(independent.FIXED_FLAGS)


class RecoveryError(ValueError):
    """Fixed public recovery failure."""


class RecoveryConflictError(RecoveryError):
    """A stale, conflicting, or no-clobber request."""


class RecoveryIndeterminateError(RecoveryError):
    """An external storage/custody result was not safely knowable."""


class StorageNotFound(LookupError):
    """The only storage read result that permits a create attempt."""


@dataclass(frozen=True)
class RecoveryKey:
    key_id: str
    key_epoch: int
    state: str


@dataclass(frozen=True)
class StorageReceipt:
    storage_id: str
    object_id: str
    result: str
    byte_length: int
    sealed_digest: str
    key_id: str
    key_epoch: int


class KeyCustodyPort(Protocol):
    custody_id: str

    def current_key(self) -> RecoveryKey: ...
    def state(self, key_id: str, key_epoch: int) -> str: ...
    def seal(self, plaintext: bytes, key_id: str, key_epoch: int) -> bytes: ...
    def open(self, sealed: bytes, key_id: str, key_epoch: int) -> bytes: ...


class RecoveryStoragePort(Protocol):
    storage_id: str

    def get(self, object_id: str) -> bytes: ...
    def put_if_absent(self, object_id: str, sealed: bytes, *, key_id: str, key_epoch: int) -> StorageReceipt: ...


@dataclass(frozen=True)
class RecoveryConfigV2:
    database_id: str
    chain_id: str
    profile_digest: str
    custody_id: str
    storage_id: str
    ingress_database_id: str
    core_database_id: str
    ingress_config_digest: str
    core_config_digest: str
    max_bundle_bytes: int = 16 * 1024 * 1024

    def __post_init__(self) -> None:
        if any(type(value) is not str or not value for value in (self.database_id, self.chain_id, self.custody_id, self.storage_id, self.ingress_database_id, self.core_database_id)):
            raise RecoveryError("recovery:config")
        for value in (self.profile_digest, self.ingress_config_digest, self.core_config_digest):
            if type(value) is not str or len(value) != 128 or any(char not in "0123456789abcdef" for char in value):
                raise RecoveryError("recovery:config")
        if type(self.max_bundle_bytes) is not int or not 1024 <= self.max_bundle_bytes <= 32 * 1024 * 1024:
            raise RecoveryError("recovery:config")

    def material(self) -> dict[str, object]:
        return {
            "schema": SCHEMA, "schema_version": SCHEMA_VERSION,
            "database_id": self.database_id, "chain_id": self.chain_id,
            "profile_digest": self.profile_digest, "custody_id": self.custody_id,
            "storage_id": self.storage_id, "ingress_database_id": self.ingress_database_id,
            "core_database_id": self.core_database_id,
            "ingress_config_digest": self.ingress_config_digest,
            "core_config_digest": self.core_config_digest,
            "max_bundle_bytes": self.max_bundle_bytes, "flags": dict(FIXED_FLAGS),
        }

    @property
    def digest(self) -> str:
        return independent._digest("config", self.material())


@dataclass(frozen=True)
class RecoveryReceipt:
    raw: bytes
    point_id: str
    operation_id: str
    event_id: str
    state: str
    sequence: int
    after_root: str


def _canonical(value: object) -> bytes:
    return independent._canonical(value)


def _digest(label: str, value: object) -> str:
    return independent._digest(label, value)


def _raw_digest(label: str, raw: bytes) -> str:
    return independent._raw_digest(label, raw)


def _connection(path: Path) -> sqlite3.Connection:
    try:
        connection = sqlite3.connect(path, timeout=0.25, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=250")
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        return connection
    except (OSError, sqlite3.Error):
        raise_redacted(RecoveryError, "recovery:database-open")


def _init(path: Path, config: RecoveryConfigV2) -> None:
    connection = _connection(path)
    try:
        existing = tuple(row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall())
        if existing and existing != TABLES:
            raise RecoveryError("recovery:legacy-schema")
        if not existing:
            connection.executescript(
                """
                CREATE TABLE recovery_meta(
                    meta_id INTEGER PRIMARY KEY CHECK(meta_id=1), schema TEXT NOT NULL,
                    schema_version INTEGER NOT NULL, database_id TEXT NOT NULL,
                    chain_id TEXT NOT NULL, config_digest TEXT NOT NULL,
                    sequence INTEGER NOT NULL, head_root TEXT NOT NULL,
                    profile_digest TEXT NOT NULL, key_custody_id_digest TEXT NOT NULL,
                    storage_id_digest TEXT NOT NULL, ingress_database_id TEXT NOT NULL,
                    core_database_id TEXT NOT NULL, current_generation INTEGER NOT NULL
                );
                CREATE TABLE recovery_points(
                    point_id TEXT PRIMARY KEY, generation INTEGER NOT NULL UNIQUE,
                    state TEXT NOT NULL, object_id TEXT NOT NULL UNIQUE,
                    bundle_digest TEXT NOT NULL, bundle_length INTEGER NOT NULL,
                    ingress_database_id TEXT NOT NULL, ingress_config_digest TEXT NOT NULL,
                    ingress_head_root TEXT NOT NULL, ingress_watermark INTEGER NOT NULL,
                    core_database_id TEXT NOT NULL, core_config_digest TEXT NOT NULL,
                    core_head_root TEXT NOT NULL, core_watermark INTEGER NOT NULL,
                    key_id TEXT NOT NULL, key_epoch INTEGER NOT NULL, key_state TEXT NOT NULL,
                    storage_id TEXT NOT NULL, prior_point_id TEXT, prior_root TEXT NOT NULL, operation_id TEXT NOT NULL UNIQUE,
                    request_digest TEXT NOT NULL, sequence INTEGER NOT NULL,
                    updated_sequence INTEGER NOT NULL
                );
                CREATE TABLE recovery_events(
                    sequence INTEGER PRIMARY KEY, event_id TEXT NOT NULL UNIQUE,
                    event_kind TEXT NOT NULL, database_id TEXT NOT NULL,
                    chain_id TEXT NOT NULL, stream_kind TEXT NOT NULL,
                    stream_id TEXT NOT NULL, point_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL, request_digest TEXT NOT NULL,
                    prior_state TEXT NOT NULL, next_state TEXT NOT NULL,
                    attempt INTEGER NOT NULL, before_root TEXT NOT NULL,
                    after_root TEXT NOT NULL, material_digest TEXT NOT NULL,
                    payload_digest TEXT NOT NULL, payload_length INTEGER NOT NULL,
                    event_raw BLOB NOT NULL, receipt_digest TEXT NOT NULL,
                    FOREIGN KEY(point_id) REFERENCES recovery_points(point_id)
                );
                CREATE INDEX recovery_points_state_idx ON recovery_points(state,generation);
                CREATE UNIQUE INDEX recovery_events_chain_idx ON recovery_events(chain_id,sequence);
                CREATE INDEX recovery_events_operation_idx ON recovery_events(operation_id,event_kind);
                """
            )
            connection.execute(
                "INSERT INTO recovery_meta VALUES(1,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (SCHEMA, SCHEMA_VERSION, config.database_id, config.chain_id, config.digest, 0, independent.GENESIS_ROOT, config.profile_digest, _digest("custody-id", config.custody_id), _digest("storage-id", config.storage_id), config.ingress_database_id, config.core_database_id, 0),
            )
        else:
            row = connection.execute("SELECT * FROM recovery_meta WHERE meta_id=1").fetchone()
            if row is None or row["database_id"] != config.database_id or row["chain_id"] != config.chain_id or row["config_digest"] != config.digest or row["profile_digest"] != config.profile_digest or row["ingress_database_id"] != config.ingress_database_id or row["core_database_id"] != config.core_database_id:
                raise RecoveryError("recovery:identity")
    except RecoveryError:
        raise
    except sqlite3.Error:
        raise_redacted(RecoveryError, "recovery:database-initialize")
    finally:
        connection.close()


class RecoveryServiceV2:
    def __init__(self, path: str | Path, config: RecoveryConfigV2, custody: KeyCustodyPort, storage: RecoveryStoragePort) -> None:
        if getattr(custody, "custody_id", None) != config.custody_id or getattr(storage, "storage_id", None) != config.storage_id:
            raise RecoveryError("recovery:port-identity")
        self.path = Path(path)
        self.config = config
        self.custody = custody
        self.storage = storage
        _init(self.path, config)

    def verify(self) -> dict[str, object]:
        return independent.verify_database(self.path, expected_database_id=self.config.database_id, expected_config_digest=self.config.digest)

    def _append(self, connection: sqlite3.Connection, *, kind: str, point_id: str, operation_id: str, request_digest: str, prior_state: str, next_state: str, material: Mapping[str, object], payload_digest: str, payload_length: int) -> bytes:
        meta = connection.execute("SELECT * FROM recovery_meta WHERE meta_id=1").fetchone()
        if meta is None:
            raise RecoveryError("recovery:meta")
        sequence = int(meta["sequence"]) + 1
        body: dict[str, object] = {
            "schema": SCHEMA, "schema_version": SCHEMA_VERSION,
            "database_id": self.config.database_id, "chain_id": self.config.chain_id,
            "sequence": sequence, "event_id": "", "event_kind": kind,
            "stream_kind": "POINT", "stream_id": point_id,
            "point_id": point_id, "operation_id": operation_id,
            "request_digest": request_digest, "prior_state": prior_state,
            "next_state": next_state, "attempt": 0,
            "before_root": meta["head_root"], "after_root": "",
            "material_digest": _digest("material", material),
            "payload_digest": payload_digest, "payload_length": payload_length,
        }
        body["event_id"] = _digest("event-id", {key: body[key] for key in body if key not in {"event_id", "after_root"}})
        body["after_root"] = independent._event_root(sequence, str(meta["head_root"]), str(body["event_id"]), kind, point_id, next_state, str(body["material_digest"]), str(body["stream_kind"]), str(body["stream_id"]))
        raw = _canonical(body)
        connection.execute("INSERT INTO recovery_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (sequence, body["event_id"], kind, self.config.database_id, self.config.chain_id, body["stream_kind"], body["stream_id"], point_id, operation_id, request_digest, prior_state, next_state, 0, body["before_root"], body["after_root"], body["material_digest"], payload_digest, payload_length, raw, _raw_digest("receipt", raw)))
        connection.execute("UPDATE recovery_meta SET sequence=?,head_root=? WHERE meta_id=1", (sequence, body["after_root"]))
        return raw

    @staticmethod
    def _receipt(raw: bytes) -> RecoveryReceipt:
        value = json.loads(raw.decode("ascii"))
        return RecoveryReceipt(raw=raw, point_id=str(value["point_id"]), operation_id=str(value["operation_id"]), event_id=str(value["event_id"]), state=str(value["next_state"]), sequence=int(value["sequence"]), after_root=str(value["after_root"]))

    def _read_pair(self, ingress_path: Path, core_path: Path) -> tuple[dict[str, object], dict[str, object], bytes, bytes]:
        try:
            core_before = core.verify_database(
                core_path,
                expected_database_id=self.config.core_database_id,
                expected_config_digest=self.config.core_config_digest,
            )
            ing = ingress.verify_database(ingress_path, expected_database_id=self.config.ingress_database_id, expected_config_digest=self.config.ingress_config_digest)
            if core_before["ingress_database_id"] != ing["database_id"] or core_before["ingress_watermark"] > ing["sequence"]:
                raise RecoveryConflictError("recovery:watermark")
            cor = core.verify_database(core_path, expected_database_id=self.config.core_database_id, expected_config_digest=self.config.core_config_digest, ingress_path=ingress_path)
            if (
                cor["ingress_database_id"] != ing["database_id"]
                or cor["ingress_watermark"] > ing["sequence"]
                or cor["sequence"] != core_before["sequence"]
                or cor["head_root"] != core_before["head_root"]
                or cor["ingress_watermark"] != core_before["ingress_watermark"]
            ):
                raise RecoveryConflictError("recovery:watermark")
            if any(path.with_name(path.name + suffix).exists() for path in (Path(ingress_path), Path(core_path)) for suffix in ("-wal", "-shm")):
                raise RecoveryError("recovery:sidecar")
            ing_raw = Path(ingress_path).read_bytes()
            core_raw = Path(core_path).read_bytes()
            if len(ing_raw) > independent.MAX_DATABASE_BYTES or len(core_raw) > independent.MAX_DATABASE_BYTES:
                raise RecoveryError("recovery:image-cap")
            return ing, cor, ing_raw, core_raw
        except (RecoveryError, ingress.IngressVerificationError, core.CoreVerificationError):
            raise
        except Exception:
            raise_redacted(RecoveryError, "recovery:source")

    def _bundle(self, ing: Mapping[str, object], cor: Mapping[str, object], ing_raw: bytes, cor_raw: bytes, generation: int, prior_root: str) -> bytes:
        value = {
            "schema": "mirror-recovery-bundle-v2", "schema_version": 2,
            "generation": generation, "prior_recovery_root": prior_root,
            "ingress": {"database_id": ing["database_id"], "chain_id": ing["chain_id"], "config_digest": ing["config_digest"], "head_root": ing["head_root"], "watermark": ing["sequence"], "image_digest": _raw_digest("ingress-image", ing_raw), "image_length": len(ing_raw)},
            "core": {"database_id": cor["database_id"], "chain_id": cor["chain_id"], "config_digest": cor["config_digest"], "head_root": cor["head_root"], "watermark": cor["ingress_watermark"], "image_digest": _raw_digest("core-image", cor_raw), "image_length": len(cor_raw)},
            "ingress_image": base64.b64encode(ing_raw).decode("ascii"),
            "core_image": base64.b64encode(cor_raw).decode("ascii"),
            "flags": dict(FIXED_FLAGS),
        }
        raw = _canonical(value)
        if len(raw) > self.config.max_bundle_bytes:
            raise RecoveryError("recovery:bundle-cap")
        return raw

    def _find(self, connection: sqlite3.Connection, *, generation: int | None = None, point_id: str | None = None) -> sqlite3.Row | None:
        if point_id is not None:
            return connection.execute("SELECT * FROM recovery_points WHERE point_id=?", (point_id,)).fetchone()
        return connection.execute("SELECT * FROM recovery_points WHERE generation=?", (generation,)).fetchone()

    def _invalidate(self, point_id: str, reason: str) -> None:
        connection = _connection(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM recovery_points WHERE point_id=?", (point_id,)).fetchone()
            if row is None or row["state"] != "OBJECT_PENDING":
                connection.rollback()
                return
            raw = self._append(connection, kind="INVALIDATED", point_id=point_id, operation_id=row["operation_id"], request_digest=row["request_digest"], prior_state="OBJECT_PENDING", next_state="INVALIDATED", material={"point_id": point_id, "reason": reason}, payload_digest=row["object_id"], payload_length=0)
            connection.execute("UPDATE recovery_points SET state='INVALIDATED',updated_sequence=? WHERE point_id=?", (json.loads(raw.decode("ascii"))["sequence"], point_id))
            connection.commit()
        except sqlite3.Error:
            connection.rollback()
            raise_redacted(RecoveryError, "recovery:invalidate")
        finally:
            connection.close()

    def _complete_storage(self, point: sqlite3.Row, bundle: bytes, sealed: bytes) -> RecoveryReceipt:
        key_id, key_epoch = str(point["key_id"]), int(point["key_epoch"])
        if self.custody.state(key_id, key_epoch) != "ACTIVE":
            self._invalidate(str(point["point_id"]), "key-revoked")
            raise RecoveryConflictError("recovery:key-revoked")
        object_id = str(point["object_id"])
        try:
            try:
                existing = self.storage.get(object_id)
            except StorageNotFound:
                receipt = self.storage.put_if_absent(object_id, sealed, key_id=key_id, key_epoch=key_epoch)
                if receipt.result not in {"CREATED", "EXISTING_SAME"} or receipt.object_id != object_id or receipt.storage_id != self.config.storage_id or receipt.key_id != key_id or receipt.key_epoch != key_epoch or receipt.byte_length != len(sealed) or receipt.sealed_digest != _raw_digest("sealed", sealed):
                    raise RecoveryConflictError("recovery:storage-receipt")
                existing = self.storage.get(object_id)
            if type(existing) is not bytes or existing != sealed:
                raise RecoveryConflictError("recovery:storage-conflict")
            opened = self.custody.open(existing, key_id, key_epoch)
            if opened != bundle or _raw_digest("bundle", opened) != point["bundle_digest"]:
                raise RecoveryConflictError("recovery:bundle-conflict")
        except (StorageNotFound, RecoveryConflictError):
            raise
        except Exception:
            raise_redacted(RecoveryIndeterminateError, "recovery:storage-indeterminate")
        connection = _connection(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute("SELECT * FROM recovery_points WHERE point_id=?", (point["point_id"],)).fetchone()
            if current is None:
                raise RecoveryError("recovery:point-missing")
            if current["state"] in {"VERIFIED", "PUBLISHED"}:
                event = connection.execute("SELECT event_raw FROM recovery_events WHERE point_id=? AND next_state=? ORDER BY sequence DESC LIMIT 1", (point["point_id"], current["state"])).fetchone()
                if event is None:
                    raise RecoveryError("recovery:receipt")
                connection.commit()
                return self._receipt(bytes(event[0]))
            if current["state"] != "OBJECT_PENDING":
                raise RecoveryConflictError("recovery:state")
            raw = self._append(connection, kind="VERIFIED", point_id=str(point["point_id"]), operation_id=str(point["operation_id"]), request_digest=str(point["request_digest"]), prior_state="OBJECT_PENDING", next_state="VERIFIED", material={"point_id": point["point_id"], "object_id": point["object_id"], "bundle_digest": point["bundle_digest"]}, payload_digest=point["object_id"], payload_length=len(sealed))
            sequence = json.loads(raw.decode("ascii"))["sequence"]
            connection.execute("UPDATE recovery_points SET state='VERIFIED',updated_sequence=? WHERE point_id=?", (sequence, point["point_id"]))
            connection.commit()
            return self._receipt(raw)
        except (RecoveryError, RecoveryConflictError):
            connection.rollback()
            raise
        except sqlite3.Error:
            connection.rollback()
            raise_redacted(RecoveryError, "recovery:database")
        finally:
            connection.close()

    def create_point(self, ingress_path: str | Path, core_path: str | Path, *, generation: int, now: int) -> RecoveryReceipt:
        if type(generation) is not int or generation <= 0 or type(now) is not int or now < 0:
            raise RecoveryError("recovery:input")
        ing, cor, ing_raw, cor_raw = self._read_pair(Path(ingress_path), Path(core_path))
        connection = _connection(self.path)
        try:
            meta = connection.execute("SELECT * FROM recovery_meta WHERE meta_id=1").fetchone()
            prior_point = connection.execute("SELECT * FROM recovery_points ORDER BY generation DESC LIMIT 1").fetchone()
            prior_root = str(meta["head_root"] if meta else independent.GENESIS_ROOT)
            bundle = self._bundle(ing, cor, ing_raw, cor_raw, generation, prior_root)
            bundle_digest = _raw_digest("bundle", bundle)
            point_id = _digest("point-id", {"config_digest": self.config.digest, "generation": generation})
            existing = self._find(connection, generation=generation)
            if existing is not None:
                if existing["point_id"] != point_id:
                    raise RecoveryConflictError("recovery:generation-conflict")
                if existing["state"] in {"VERIFIED", "PUBLISHED"}:
                    if existing["ingress_head_root"] != ing["head_root"] or existing["core_head_root"] != cor["head_root"] or existing["ingress_watermark"] != ing["sequence"] or existing["core_watermark"] != cor["ingress_watermark"]:
                        raise RecoveryConflictError("recovery:source-drift")
                    event = connection.execute("SELECT event_raw FROM recovery_events WHERE point_id=? AND next_state=? ORDER BY sequence DESC LIMIT 1", (existing["point_id"], existing["state"])).fetchone()
                    if event is None:
                        raise RecoveryError("recovery:receipt")
                    connection.close()
                    if self.custody.state(existing["key_id"], int(existing["key_epoch"])) != "ACTIVE":
                        raise RecoveryConflictError("recovery:key-revoked")
                    return self._receipt(bytes(event[0]))
                if existing["bundle_digest"] != bundle_digest:
                    raise RecoveryConflictError("recovery:generation-conflict")
                key = RecoveryKey(str(existing["key_id"]), int(existing["key_epoch"]), str(existing["key_state"]))
                connection.close()
                retry_bundle = self._bundle(ing, cor, ing_raw, cor_raw, generation, str(existing["prior_root"]))
                if _raw_digest("bundle", retry_bundle) != existing["bundle_digest"]:
                    raise RecoveryConflictError("recovery:bundle-conflict")
                sealed = self.custody.seal(retry_bundle, key.key_id, key.key_epoch)
                if _digest("object-id", {"sealed_digest": _raw_digest("sealed", sealed), "profile_digest": self.config.profile_digest, "key_id": key.key_id, "key_epoch": key.key_epoch}) != existing["object_id"]:
                    raise RecoveryConflictError("recovery:object-rebound")
                return self._complete_storage(existing, retry_bundle, sealed)
            key = self.custody.current_key()
            if not isinstance(key, RecoveryKey) or key.state != "ACTIVE" or not key.key_id or type(key.key_epoch) is not int or key.key_epoch < 0:
                raise RecoveryConflictError("recovery:key-unavailable")
            sealed = self.custody.seal(bundle, key.key_id, key.key_epoch)
            object_id = _digest("object-id", {"sealed_digest": _raw_digest("sealed", sealed), "profile_digest": self.config.profile_digest, "key_id": key.key_id, "key_epoch": key.key_epoch})
            if self.custody.state(key.key_id, key.key_epoch) != "ACTIVE":
                raise RecoveryConflictError("recovery:key-revoked")
            operation_id = _digest("operation-id", {"point_id": point_id})
            request_digest = _digest("request", {"point_id": point_id, "bundle_digest": bundle_digest, "object_id": object_id})
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute("SELECT 1 FROM recovery_points WHERE generation=?", (generation,)).fetchone() is not None:
                raise RecoveryConflictError("recovery:generation-conflict")
            connection.execute("INSERT INTO recovery_points VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (point_id, generation, "PREPARED", object_id, bundle_digest, len(bundle), ing["database_id"], ing["config_digest"], ing["head_root"], ing["sequence"], cor["database_id"], cor["config_digest"], cor["head_root"], cor["ingress_watermark"], key.key_id, key.key_epoch, key.state, self.config.storage_id, prior_point["point_id"] if prior_point else None, prior_root, operation_id, request_digest, 0, 0))
            prepare_raw = self._append(connection, kind="PREPARE", point_id=point_id, operation_id=operation_id, request_digest=request_digest, prior_state="NONE", next_state="PREPARED", material={"point_id": point_id, "bundle_digest": bundle_digest, "object_id": object_id, "key_id": key.key_id, "key_epoch": key.key_epoch}, payload_digest=bundle_digest, payload_length=len(bundle))
            sequence = json.loads(prepare_raw.decode("ascii"))["sequence"]
            connection.execute("UPDATE recovery_points SET sequence=?,updated_sequence=? WHERE point_id=?", (sequence, sequence, point_id))
            pending_raw = self._append(connection, kind="OBJECT_PENDING", point_id=point_id, operation_id=operation_id, request_digest=request_digest, prior_state="PREPARED", next_state="OBJECT_PENDING", material={"point_id": point_id, "object_id": object_id, "storage_id": self.config.storage_id}, payload_digest=object_id, payload_length=len(sealed))
            pending_sequence = json.loads(pending_raw.decode("ascii"))["sequence"]
            connection.execute("UPDATE recovery_points SET state='OBJECT_PENDING',updated_sequence=? WHERE point_id=?", (pending_sequence, point_id))
            connection.execute("UPDATE recovery_meta SET current_generation=? WHERE meta_id=1", (generation,))
            connection.commit()
            point = connection.execute("SELECT * FROM recovery_points WHERE point_id=?", (point_id,)).fetchone()
        except (RecoveryError, RecoveryConflictError):
            connection.rollback()
            connection.close()
            raise
        except sqlite3.IntegrityError:
            connection.rollback()
            connection.close()
            raise RecoveryConflictError("recovery:conflict")
        except sqlite3.Error:
            connection.rollback()
            connection.close()
            raise_redacted(RecoveryError, "recovery:database")
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass
        if point is None:
            raise RecoveryError("recovery:point")
        return self._complete_storage(point, bundle, sealed)

    @staticmethod
    def _publish_database(
        target: Path,
        image: bytes,
        *,
        export_root: str,
        expected_evidence: Mapping[str, object],
        verify_database: callable,
    ) -> tuple[bool, dict[str, object]]:
        publication: dict[str, object] = {}
        try:
            restore_publication.publish_create_only(
                target,
                export_root=export_root,
                expected_evidence=expected_evidence,
                build_stage=lambda stage: stage.write_bytes(image),
                verify_database=verify_database,
                result_factory=lambda published: published,
                publication_receipt_sink=publication.update,
            )
        except restore_publication.RestorePublicationConflict:
            raise_redacted(RecoveryConflictError, "recovery:publication-conflict")
        except restore_publication.RestorePublicationError:
            raise_redacted(RecoveryError, "recovery:publication")
        if publication.get("publication_kind") not in {"CREATED", "ADOPTED_EXISTING"}:
            raise RecoveryError("recovery:publication-receipt")
        return publication.get("publication_kind") == "CREATED", publication

    def _bundle_images(self, point: sqlite3.Row) -> tuple[dict[str, object], bytes, bytes]:
        try:
            sealed = self.storage.get(str(point["object_id"]))
            if type(sealed) is not bytes:
                raise RecoveryIndeterminateError("recovery:storage-type")
            expected_object = _digest("object-id", {"sealed_digest": _raw_digest("sealed", sealed), "profile_digest": self.config.profile_digest, "key_id": point["key_id"], "key_epoch": point["key_epoch"]})
            if expected_object != point["object_id"] or self.custody.state(point["key_id"], int(point["key_epoch"])) != "ACTIVE":
                raise RecoveryConflictError("recovery:key-or-object")
            bundle = self.custody.open(sealed, str(point["key_id"]), int(point["key_epoch"]))
            if _raw_digest("bundle", bundle) != point["bundle_digest"]:
                raise RecoveryConflictError("recovery:bundle")
            value = json.loads(bundle.decode("ascii"))
            if not isinstance(value, dict) or value.get("schema") != "mirror-recovery-bundle-v2" or value.get("flags") != FIXED_FLAGS:
                raise RecoveryConflictError("recovery:bundle")
            ing_raw = base64.b64decode(value["ingress_image"], validate=True)
            core_raw = base64.b64decode(value["core_image"], validate=True)
            if _raw_digest("ingress-image", ing_raw) != value["ingress"]["image_digest"] or _raw_digest("core-image", core_raw) != value["core"]["image_digest"]:
                raise RecoveryConflictError("recovery:image")
            return value, ing_raw, core_raw
        except (RecoveryError, RecoveryConflictError):
            raise
        except StorageNotFound:
            raise RecoveryConflictError("recovery:object-missing")
        except Exception:
            raise_redacted(RecoveryIndeterminateError, "recovery:restore-indeterminate")

    def restore_point(self, point_id: str, ingress_target: str | Path, core_target: str | Path) -> RecoveryReceipt:
        verification = self.verify()
        connection = _connection(self.path)
        try:
            point = connection.execute("SELECT * FROM recovery_points WHERE point_id=?", (point_id,)).fetchone()
        finally:
            connection.close()
        if point is None or point["state"] not in {"VERIFIED", "PUBLISHED"}:
            raise RecoveryConflictError("recovery:point-state")
        bundle, ing_raw, core_raw = self._bundle_images(point)
        if bundle["ingress"]["database_id"] != self.config.ingress_database_id or bundle["core"]["database_id"] != self.config.core_database_id:
            raise RecoveryConflictError("recovery:pair")
        import tempfile
        with tempfile.TemporaryDirectory(prefix="mirror-recovery-v2-") as temp:
            temp_path = Path(temp)
            ing_stage = temp_path / "ingress.db"
            core_stage = temp_path / "core.db"
            ing_stage.write_bytes(ing_raw)
            core_stage.write_bytes(core_raw)
            ing_check = ingress.verify_database(ing_stage, expected_database_id=self.config.ingress_database_id, expected_config_digest=self.config.ingress_config_digest)
            core_check = core.verify_database(core_stage, expected_database_id=self.config.core_database_id, expected_config_digest=self.config.core_config_digest, ingress_path=ing_stage)
            if ing_check["head_root"] != point["ingress_head_root"] or core_check["head_root"] != point["core_head_root"] or core_check["ingress_watermark"] > ing_check["sequence"]:
                raise RecoveryConflictError("recovery:pair-root")
            made_ing, ingress_publication = self._publish_database(
                Path(ingress_target),
                ing_raw,
                export_root=str(point["ingress_head_root"]),
                expected_evidence=ing_check,
                verify_database=lambda path: ingress.verify_database(
                    path,
                    expected_database_id=self.config.ingress_database_id,
                    expected_config_digest=self.config.ingress_config_digest,
                ),
            )
            try:
                self._publish_database(
                    Path(core_target),
                    core_raw,
                    export_root=str(point["core_head_root"]),
                    expected_evidence=core_check,
                    verify_database=lambda path: core.verify_database(
                        path,
                        expected_database_id=self.config.core_database_id,
                        expected_config_digest=self.config.core_config_digest,
                        ingress_path=ingress_target,
                    ),
                )
            except Exception:
                if made_ing:
                    try:
                        storage = ingress_publication["storage_identity"]
                        restore_publication._delete_exact_file(
                            Path(ingress_target),
                            expected_inode=(int(storage["dev"]), int(storage["ino"])),
                            allow_empty=False,
                            label="recovery-pair-rollback",
                        )
                    except Exception:
                        raise_redacted(RecoveryError, "recovery:pair-rollback")
                raise
        if point["state"] == "PUBLISHED":
            connection = _connection(self.path)
            try:
                row = connection.execute("SELECT event_raw FROM recovery_events WHERE point_id=? AND next_state='PUBLISHED' ORDER BY sequence DESC LIMIT 1", (point_id,)).fetchone()
                if row is None:
                    raise RecoveryError("recovery:receipt")
                return self._receipt(bytes(row[0]))
            finally:
                connection.close()
        connection = _connection(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute("SELECT * FROM recovery_points WHERE point_id=?", (point_id,)).fetchone()
            if current is None or current["state"] != "VERIFIED":
                raise RecoveryConflictError("recovery:point-state")
            raw = self._append(connection, kind="PUBLISHED", point_id=point_id, operation_id=current["operation_id"], request_digest=current["request_digest"], prior_state="VERIFIED", next_state="PUBLISHED", material={"point_id": point_id, "ingress_target": "opaque", "core_target": "opaque"}, payload_digest=current["object_id"], payload_length=0)
            sequence = json.loads(raw.decode("ascii"))["sequence"]
            connection.execute("UPDATE recovery_points SET state='PUBLISHED',updated_sequence=? WHERE point_id=?", (sequence, point_id))
            connection.commit()
            return self._receipt(raw)
        except (RecoveryError, RecoveryConflictError):
            connection.rollback()
            raise
        except sqlite3.Error:
            connection.rollback()
            raise_redacted(RecoveryError, "recovery:database")
        finally:
            connection.close()

    def bootstrap(self, point_id: str) -> bytes:
        self.verify()
        connection = _connection(self.path)
        try:
            point = connection.execute("SELECT * FROM recovery_points WHERE point_id=?", (point_id,)).fetchone()
        finally:
            connection.close()
        if point is None:
            raise RecoveryConflictError("recovery:point-missing")
        body = {
            "schema": "mirror-recovery-bootstrap-v2", "schema_version": 2,
            "catalog_id": _digest("catalog-id", self.config.database_id), "point_id": point["point_id"], "generation": point["generation"], "object_id": point["object_id"], "bundle_digest": point["bundle_digest"], "bundle_length": point["bundle_length"], "key_id": point["key_id"], "key_epoch": point["key_epoch"], "storage_id": point["storage_id"], "ingress_database_id": point["ingress_database_id"], "core_database_id": point["core_database_id"], "ingress_head_root": point["ingress_head_root"], "core_head_root": point["core_head_root"], "ingress_watermark": point["ingress_watermark"], "core_watermark": point["core_watermark"], "publication_receipt_digest": _digest("publication-receipt", {"point_id": point["point_id"], "object_id": point["object_id"], "state": point["state"]}), "flags": dict(FIXED_FLAGS),
        }
        body["bootstrap_id"] = _digest("bootstrap-id", {key: body[key] for key in body if key not in {"bootstrap_id", "flags"}})
        raw = _canonical(body)
        if len(raw) > independent.MAX_BOOTSTRAP_BYTES:
            raise RecoveryError("recovery:bootstrap-cap")
        return raw

    def logical_export(self) -> bytes:
        return independent.logical_export(self.verify())

    def support(self) -> dict[str, object]:
        result = self.verify()
        return {"schema": "mirror-recovery-support-v2", "states": result["states"], "point_count": result["point_count"], "event_count": result["event_count"], "sequence": result["sequence"], "flags": dict(FIXED_FLAGS)}


__all__ = ["RecoveryConfigV2", "RecoveryServiceV2", "RecoveryReceipt", "RecoveryKey", "StorageReceipt", "KeyCustodyPort", "RecoveryStoragePort", "StorageNotFound", "RecoveryError", "RecoveryConflictError", "RecoveryIndeterminateError", "SCHEMA", "SCHEMA_VERSION", "TABLES", "FIXED_FLAGS"]
