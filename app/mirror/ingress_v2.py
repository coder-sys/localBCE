"""The single five-table durable ingress owner for Mirror V2."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Mapping

from app.mirror import ingress_v2_independent as independent
from app.mirror import nc_medicaid_fhir_independent as fhir
from app.mirror.nc_medicaid_fhir_profile import NC_MEDICAID_PROFILE
from app.mirror.error_boundary import raise_redacted


SCHEMA = independent.SCHEMA
SCHEMA_VERSION = independent.SCHEMA_VERSION
TABLES = independent.TABLES
STATES = independent.STATES
FIXED_FLAGS = dict(independent.FIXED_FLAGS)
MAX_DATABASE_BYTES = independent.MAX_DATABASE_BYTES


class IngressError(ValueError):
    """Public-safe ingress boundary."""


class IngressConflictError(IngressError):
    """A stale, conflicting, or rebound ingress request."""


class IngressBusyError(IngressError):
    """A bounded writer contention failure."""


@dataclass(frozen=True)
class IngressConfigV2:
    database_id: str
    chain_id: str
    policy_digest: str
    authorization_digest: str
    terms_digest: str
    cadence_seconds: int
    effective_start: int
    effective_end: int
    max_slots: int = 64
    max_attempts: int = 3
    lease_seconds: int = 60

    def __post_init__(self) -> None:
        if any(type(value) is not str or not value for value in (
            self.database_id, self.chain_id,
        )):
            raise IngressError("ingress:config")
        for value in (self.policy_digest, self.authorization_digest, self.terms_digest):
            if type(value) is not str or len(value) != 128 or any(
                char not in "0123456789abcdef" for char in value
            ):
                raise IngressError("ingress:config")
        if type(self.cadence_seconds) is not int or self.cadence_seconds <= 0:
            raise IngressError("ingress:config")
        if type(self.effective_start) is not int or type(self.effective_end) is not int or self.effective_start >= self.effective_end:
            raise IngressError("ingress:config")
        if type(self.max_slots) is not int or not 1 <= self.max_slots <= 4096:
            raise IngressError("ingress:config")
        if type(self.max_attempts) is not int or not 1 <= self.max_attempts <= 8:
            raise IngressError("ingress:config")
        if type(self.lease_seconds) is not int or not 1 <= self.lease_seconds <= 86_400:
            raise IngressError("ingress:config")

    def material(self) -> dict[str, object]:
        return {
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "database_id": self.database_id,
            "chain_id": self.chain_id,
            "policy_digest": self.policy_digest,
            "authorization_digest": self.authorization_digest,
            "terms_digest": self.terms_digest,
            "profile_id": NC_MEDICAID_PROFILE.source_profile_id,
            "profile_version": NC_MEDICAID_PROFILE.version,
            "profile_digest": NC_MEDICAID_PROFILE.profile_digest,
            "cadence_seconds": self.cadence_seconds,
            "effective_start": self.effective_start,
            "effective_end": self.effective_end,
            "max_slots": self.max_slots,
            "max_attempts": self.max_attempts,
            "lease_seconds": self.lease_seconds,
            "flags": dict(FIXED_FLAGS),
        }

    @property
    def digest(self) -> str:
        return independent._digest("config", self.material())


@dataclass(frozen=True)
class IngressReceipt:
    raw: bytes
    event_id: str
    operation_id: str
    artifact_id: str | None
    next_state: str
    sequence: int
    after_root: str
    database_id: str


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise_redacted(IngressError, "ingress:noncanonical")


def _digest(label: str, value: object) -> str:
    return independent._digest(label, value)


def _raw_digest(label: str, raw: bytes) -> str:
    return independent._raw_digest(label, raw)


def _connection(path: Path, *, timeout: float = 0.25) -> sqlite3.Connection:
    try:
        connection = sqlite3.connect(path, timeout=timeout, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=250")
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        return connection
    except (OSError, sqlite3.Error):
        raise_redacted(IngressError, "ingress:database-open")


def _table_names(connection: sqlite3.Connection) -> tuple[str, ...]:
    return tuple(row[0] for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall())


def _init(path: Path, config: IngressConfigV2) -> None:
    connection = _connection(path)
    try:
        current = _table_names(connection)
        if current and current != tuple(sorted(TABLES)):
            raise IngressError("ingress:legacy-schema")
        if not current:
            connection.executescript(
                """
                CREATE TABLE ingress_meta(
                    meta_id INTEGER PRIMARY KEY CHECK(meta_id=1),
                    schema TEXT NOT NULL,
                    schema_version INTEGER NOT NULL,
                    database_id TEXT NOT NULL,
                    chain_id TEXT NOT NULL,
                    config_digest TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    head_root TEXT NOT NULL,
                    watermark INTEGER NOT NULL,
                    slot_count INTEGER NOT NULL
                );
                CREATE TABLE ingress_slots(
                    slot_id TEXT PRIMARY KEY,
                    scheduled_at INTEGER NOT NULL UNIQUE,
                    state TEXT NOT NULL,
                    attempt INTEGER NOT NULL,
                    lease_token TEXT,
                    lease_until INTEGER,
                    artifact_id TEXT,
                    operation_id TEXT
                );
                CREATE TABLE ingress_artifacts(
                    artifact_id TEXT PRIMARY KEY,
                    envelope_id TEXT NOT NULL UNIQUE,
                    envelope_digest TEXT NOT NULL UNIQUE,
                    raw BLOB NOT NULL,
                    profile_id TEXT NOT NULL,
                    profile_version INTEGER NOT NULL,
                    profile_digest TEXT NOT NULL,
                    observation_time INTEGER NOT NULL,
                    fetched_at INTEGER NOT NULL,
                    source_status TEXT NOT NULL,
                    failure_code TEXT,
                    freshness TEXT NOT NULL,
                    page_complete INTEGER NOT NULL,
                    snapshot_id TEXT NOT NULL,
                    snapshot_root TEXT NOT NULL,
                    content_root TEXT NOT NULL,
                    page_count INTEGER NOT NULL,
                    resource_count INTEGER NOT NULL,
                    event_sequence INTEGER NOT NULL
                );
                CREATE TABLE ingress_heads(
                    stream_kind TEXT NOT NULL,
                    stream_id TEXT NOT NULL,
                    artifact_id TEXT,
                    head_root TEXT NOT NULL,
                    event_sequence INTEGER NOT NULL,
                    PRIMARY KEY(stream_kind,stream_id),
                    FOREIGN KEY(artifact_id) REFERENCES ingress_artifacts(artifact_id)
                );
                CREATE TABLE ingress_events(
                    sequence INTEGER PRIMARY KEY,
                    event_id TEXT NOT NULL UNIQUE,
                    event_kind TEXT NOT NULL,
                    database_id TEXT NOT NULL,
                    chain_id TEXT NOT NULL,
                    stream_kind TEXT NOT NULL,
                    stream_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    slot_id TEXT NOT NULL,
                    prior_state TEXT NOT NULL,
                    next_state TEXT NOT NULL,
                    attempt INTEGER NOT NULL,
                    lease_token TEXT,
                    lease_until INTEGER,
                    material_digest TEXT NOT NULL,
                    payload_digest TEXT NOT NULL,
                    payload_length INTEGER NOT NULL,
                    before_root TEXT NOT NULL,
                    after_root TEXT NOT NULL,
                    stream_before_root TEXT NOT NULL,
                    stream_after_root TEXT NOT NULL,
                    event_raw BLOB NOT NULL,
                    receipt_digest TEXT NOT NULL,
                    source_id TEXT,
                    page_index INTEGER,
                    transport_attempt INTEGER,
                    receipt_bytes BLOB,
                    FOREIGN KEY(slot_id) REFERENCES ingress_slots(slot_id)
                );
                CREATE INDEX ingress_slots_due_idx ON ingress_slots(state,lease_until,slot_id);
                CREATE UNIQUE INDEX ingress_events_chain_idx ON ingress_events(chain_id,sequence);
                CREATE INDEX ingress_events_operation_idx ON ingress_events(operation_id,event_kind);
                CREATE UNIQUE INDEX ingress_fetch_natural_key_idx ON ingress_events(source_id,slot_id,page_index,transport_attempt) WHERE event_kind='FETCH_ATTESTATION';
                """
            )
            connection.execute(
                "INSERT INTO ingress_meta VALUES(1,?,?,?,?,?,?,?,?,?)",
                    (
                    SCHEMA, SCHEMA_VERSION, config.database_id, config.chain_id,
                    config.digest, 0, independent.GENESIS_ROOT, 0, 0,
                ),
            )
        else:
            row = connection.execute("SELECT * FROM ingress_meta").fetchone()
            if row is None or row["database_id"] != config.database_id or row["chain_id"] != config.chain_id or row["config_digest"] != config.digest:
                raise IngressError("ingress:identity")
    except IngressError:
        raise
    except sqlite3.Error:
        raise_redacted(IngressError, "ingress:database-initialize")
    finally:
        connection.close()


class IngressServiceV2:
    """Owns scheduling, raw envelope custody, fetch attestations, and quarantine state."""

    def __init__(self, path: str | Path, config: IngressConfigV2) -> None:
        self.path = Path(path)
        self.config = config
        _init(self.path, config)

    def close(self) -> None:
        return None

    def verify(self, *, include_raw: bool = False) -> dict[str, object]:
        return independent.verify_database(
            self.path,
            expected_database_id=self.config.database_id,
            expected_config_digest=self.config.digest,
            include_raw=include_raw,
        )

    def _append(
        self,
        connection: sqlite3.Connection,
        *,
        kind: str,
        operation_id: str,
        request_digest: str,
        slot_id: str,
        prior_state: str,
        next_state: str,
        attempt: int,
        lease_token: str | None,
        lease_until: int | None,
        material: Mapping[str, object],
        payload_digest: str,
        payload_length: int,
        stream_kind: str = "SLOT",
        stream_id: str | None = None,
        source_id: str | None = None,
        page_index: int | None = None,
        transport_attempt: int | None = None,
        receipt_bytes: bytes | None = None,
        head_artifact_id: str | None = None,
    ) -> bytes:
        meta = connection.execute("SELECT * FROM ingress_meta WHERE meta_id=1").fetchone()
        if meta is None:
            raise IngressError("ingress:meta")
        sequence = int(meta["sequence"]) + 1
        stream_kind = str(stream_kind)
        stream_id = str(stream_id or slot_id)
        stream_head = connection.execute(
            "SELECT head_root,artifact_id FROM ingress_heads WHERE stream_kind=? AND stream_id=?",
            (stream_kind, stream_id),
        ).fetchone()
        stream_before_root = str(stream_head["head_root"]) if stream_head is not None else independent.GENESIS_ROOT
        if head_artifact_id is None and stream_head is not None:
            head_artifact_id = stream_head["artifact_id"]
        body: dict[str, object] = {
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "database_id": self.config.database_id,
            "chain_id": self.config.chain_id,
            "sequence": sequence,
            "event_id": "",
            "event_kind": kind,
            "stream_kind": stream_kind,
            "stream_id": stream_id,
            "operation_id": operation_id,
            "request_digest": request_digest,
            "slot_id": slot_id,
            "prior_state": prior_state,
            "next_state": next_state,
            "attempt": attempt,
            "lease_token": lease_token,
            "lease_until": lease_until,
            "material_digest": _digest("material", material),
            "payload_digest": payload_digest,
            "payload_length": payload_length,
            "before_root": meta["head_root"],
            "after_root": "",
            "stream_before_root": stream_before_root,
            "stream_after_root": "",
            "source_id": source_id,
            "page_index": page_index,
            "transport_attempt": transport_attempt,
            "receipt_bytes": receipt_bytes.decode("ascii") if receipt_bytes is not None else None,
        }
        body["event_id"] = _digest("event-id", {key: body[key] for key in body if key not in {"event_id", "after_root", "stream_after_root"}})
        body["after_root"] = independent._event_root(
            sequence=sequence,
            previous=str(meta["head_root"]),
            event_id=str(body["event_id"]),
            event_kind=kind,
            stream_kind=str(body["stream_kind"]),
            stream_id=str(body["stream_id"]),
            slot_id=slot_id,
            next_state=next_state,
            material_digest=str(body["material_digest"]),
        )
        body["stream_after_root"] = independent._stream_root(
            sequence=sequence,
            previous=stream_before_root,
            event_id=str(body["event_id"]),
            stream_kind=stream_kind,
            stream_id=stream_id,
            next_state=next_state,
            material_digest=str(body["material_digest"]),
        )
        raw = _canonical(body)
        receipt_digest = _raw_digest("receipt", raw)
        connection.execute(
            "INSERT INTO ingress_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                sequence, body["event_id"], kind, self.config.database_id,
                self.config.chain_id, body["stream_kind"], body["stream_id"], operation_id, request_digest, slot_id,
                prior_state, next_state, attempt, lease_token, lease_until,
                body["material_digest"], payload_digest, payload_length,
                body["before_root"], body["after_root"], body["stream_before_root"], body["stream_after_root"], raw, receipt_digest,
                source_id, page_index, transport_attempt, receipt_bytes,
            ),
        )
        connection.execute(
            "INSERT INTO ingress_heads(stream_kind,stream_id,artifact_id,head_root,event_sequence) VALUES(?,?,?,?,?) ON CONFLICT(stream_kind,stream_id) DO UPDATE SET artifact_id=COALESCE(excluded.artifact_id,ingress_heads.artifact_id),head_root=excluded.head_root,event_sequence=excluded.event_sequence",
            (stream_kind, stream_id, head_artifact_id, body["stream_after_root"], sequence),
        )
        connection.execute(
            "UPDATE ingress_meta SET sequence=?,head_root=?,watermark=? WHERE meta_id=1",
            (sequence, body["after_root"], sequence),
        )
        return raw

    def _receipt(
        self,
        raw: bytes,
        *,
        artifact_id: str | None,
        next_state: str,
    ) -> IngressReceipt:
        value = json.loads(raw.decode("ascii"))
        return IngressReceipt(
            raw=raw,
            event_id=str(value["event_id"]),
            operation_id=str(value["operation_id"]),
            artifact_id=artifact_id,
            next_state=next_state,
            sequence=int(value["sequence"]),
            after_root=str(value["after_root"]),
            database_id=self.config.database_id,
        )

    def ensure_slot(self, scheduled_at: int) -> IngressReceipt:
        if type(scheduled_at) is not int or not (
            self.config.effective_start <= scheduled_at <= self.config.effective_end
        ) or (scheduled_at - self.config.effective_start) % self.config.cadence_seconds:
            raise IngressConflictError("ingress:slot-grid")
        slot_id = _digest(
            "slot-id",
            {"config_digest": self.config.digest, "scheduled_at": scheduled_at},
        )
        operation_id = _digest("slot-operation", {"slot_id": slot_id})
        request_digest = _digest("request", {"operation_id": operation_id, "scheduled_at": scheduled_at})
        connection = _connection(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM ingress_slots WHERE slot_id=?", (slot_id,)).fetchone()
            if row is not None:
                if row["scheduled_at"] != scheduled_at:
                    raise IngressConflictError("ingress:slot-conflict")
                event = connection.execute(
                    "SELECT event_raw FROM ingress_events WHERE operation_id=? AND event_kind='CREATE_SLOT'",
                    (operation_id,),
                ).fetchone()
                if event is None:
                    raise IngressError("ingress:slot-receipt")
                connection.commit()
                return self._receipt(bytes(event[0]), artifact_id=row["artifact_id"], next_state=str(row["state"]))
            meta = connection.execute("SELECT slot_count FROM ingress_meta WHERE meta_id=1").fetchone()
            if meta is None or int(meta[0]) >= self.config.max_slots:
                raise IngressConflictError("ingress:capacity")
            connection.execute(
                "INSERT INTO ingress_slots(slot_id,scheduled_at,state,attempt,lease_token,lease_until,artifact_id,operation_id) VALUES(?,?,?,?,?,?,?,?)",
                (slot_id, scheduled_at, "DUE", 0, None, None, None, operation_id),
            )
            raw = self._append(
                connection,
                kind="CREATE_SLOT",
                operation_id=operation_id,
                request_digest=request_digest,
                slot_id=slot_id,
                prior_state="NONE",
                next_state="DUE",
                attempt=0,
                lease_token=None,
                lease_until=None,
                material={"slot_id": slot_id, "scheduled_at": scheduled_at},
                payload_digest=_digest("slot-payload", {"slot_id": slot_id, "scheduled_at": scheduled_at}),
                payload_length=0,
            )
            connection.execute("UPDATE ingress_meta SET slot_count=slot_count+1 WHERE meta_id=1")
            connection.commit()
            return self._receipt(raw, artifact_id=None, next_state="DUE")
        except (IngressConflictError, IngressError):
            connection.rollback()
            raise
        except sqlite3.OperationalError as exc:
            connection.rollback()
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise_redacted(IngressBusyError, "ingress:busy")
            raise_redacted(IngressError, "ingress:database")
        except sqlite3.Error:
            connection.rollback()
            raise_redacted(IngressError, "ingress:database")
        finally:
            connection.close()

    def claim_slot(self, slot_id: str, *, now: int, lease_token: str) -> IngressReceipt:
        if any(type(value) is not str or not value for value in (slot_id, lease_token)) or type(now) is not int:
            raise IngressError("ingress:lease")
        connection = _connection(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM ingress_slots WHERE slot_id=?", (slot_id,)).fetchone()
            if row is None:
                raise IngressConflictError("ingress:slot-missing")
            if row["state"] == "LEASED" and row["lease_until"] is not None and row["lease_until"] <= now:
                if row["attempt"] >= self.config.max_attempts:
                    next_state = "HELD"
                    kind = "HOLD"
                else:
                    next_state = "DUE"
                    kind = "REQUEUE"
                raw = self._append(
                    connection, kind=kind, operation_id=str(row["operation_id"]),
                    request_digest=_digest("request", {"slot_id": slot_id, "action": kind}),
                    slot_id=slot_id, prior_state="LEASED", next_state=next_state,
                    attempt=int(row["attempt"]), lease_token=str(row["lease_token"]),
                    lease_until=int(row["lease_until"]),
                    material={"slot_id": slot_id, "action": kind, "attempt": row["attempt"]},
                    payload_digest=_digest("lease-recovery", {"slot_id": slot_id, "attempt": row["attempt"]}),
                    payload_length=0,
                )
                connection.execute(
                    "UPDATE ingress_slots SET state=?,lease_token=NULL,lease_until=NULL WHERE slot_id=?",
                    (next_state, slot_id),
                )
                if next_state == "HELD":
                    connection.commit()
                    return self._receipt(raw, artifact_id=row["artifact_id"], next_state=next_state)
                row = connection.execute("SELECT * FROM ingress_slots WHERE slot_id=?", (slot_id,)).fetchone()
            if row["state"] != "DUE" or row["scheduled_at"] > now:
                raise IngressConflictError("ingress:lease-state")
            attempt = int(row["attempt"]) + 1
            if attempt > self.config.max_attempts:
                raise IngressConflictError("ingress:attempt-exhausted")
            lease_until = now + self.config.lease_seconds
            request_digest = _digest("request", {"slot_id": slot_id, "action": "LEASE", "attempt": attempt})
            material = {"slot_id": slot_id, "attempt": attempt, "lease_token": lease_token, "lease_until": lease_until}
            raw = self._append(
                connection, kind="LEASE", operation_id=str(row["operation_id"]),
                request_digest=request_digest, slot_id=slot_id, prior_state="DUE",
                next_state="LEASED", attempt=attempt, lease_token=lease_token,
                lease_until=lease_until, material=material,
                payload_digest=_digest("lease-payload", material), payload_length=0,
            )
            connection.execute(
                "UPDATE ingress_slots SET state='LEASED',attempt=?,lease_token=?,lease_until=? WHERE slot_id=?",
                (attempt, lease_token, lease_until, slot_id),
            )
            connection.commit()
            return self._receipt(raw, artifact_id=row["artifact_id"], next_state="LEASED")
        except (IngressConflictError, IngressError):
            connection.rollback()
            raise
        except sqlite3.OperationalError as exc:
            connection.rollback()
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise_redacted(IngressBusyError, "ingress:busy")
            raise_redacted(IngressError, "ingress:database")
        except sqlite3.Error:
            connection.rollback()
            raise_redacted(IngressError, "ingress:database")
        finally:
            connection.close()

    def admit_capture(
        self,
        envelope_raw: bytes,
        *,
        scheduled_at: int,
        lease_token: str | None = None,
        operation_id: str | None = None,
    ) -> IngressReceipt:
        raw_snapshot = bytes(envelope_raw) if type(envelope_raw) is bytes else b""
        if not raw_snapshot or len(raw_snapshot) > independent.MAX_RAW_ENVELOPE_BYTES:
            raise IngressError("ingress:envelope")
        try:
            result = fhir.verify_bytes(raw_snapshot)
        except Exception:
            raise_redacted(IngressError, "ingress:envelope-reject")
        if result["observation_time"] != scheduled_at:
            raise IngressConflictError("ingress:observation-slot")
        artifact_id = _digest(
            "artifact-id",
            {
                "envelope_digest": _raw_digest("envelope", raw_snapshot),
                "envelope_id": result["envelope_id"],
                "profile_digest": NC_MEDICAID_PROFILE.profile_digest,
                "observation_time": result["observation_time"],
                "snapshot_id": result["snapshot_id"],
            },
        )
        slot_id = _digest("slot-id", {"config_digest": self.config.digest, "scheduled_at": scheduled_at})
        operation_id = operation_id or _digest("capture-operation", {"slot_id": slot_id, "artifact_id": artifact_id})
        request_digest = _digest("request", {"operation_id": operation_id, "slot_id": slot_id, "artifact_id": artifact_id})
        attestation_materials: list[dict[str, object]] = []
        for index, response_digest in enumerate(result["page_digests"]):
            material = {
                "artifact_id": artifact_id,
                "page_index": index,
                "lease_attempt": 0,
                "transport_attempt": 0,
                "request_digest": independent._request_digest(index),
                "response_digest": response_digest,
                "status": 200,
                "authenticated": True,
                "redirect": False,
                "selected": True,
            }
            material["attestation_digest"] = independent._attestation_digest(material)
            attestation_materials.append(material)
        connection = _connection(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            slot = connection.execute("SELECT * FROM ingress_slots WHERE slot_id=?", (slot_id,)).fetchone()
            if slot is None:
                raise IngressConflictError("ingress:slot-missing")
            existing = connection.execute(
                "SELECT * FROM ingress_events WHERE operation_id=? AND event_kind IN ('ADMIT','FAIL','QUARANTINE','HOLD')",
                (operation_id,),
            ).fetchone()
            if existing is not None:
                if existing["payload_digest"] != artifact_id:
                    raise IngressConflictError("ingress:operation-conflict")
                connection.commit()
                return self._receipt(bytes(existing["event_raw"]), artifact_id=artifact_id, next_state=str(existing["next_state"]))
            if slot["state"] not in {"DUE", "LEASED"}:
                raise IngressConflictError("ingress:slot-state")
            if slot["state"] == "LEASED" and lease_token != slot["lease_token"]:
                raise IngressConflictError("ingress:lease-token")
            row = connection.execute("SELECT * FROM ingress_artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()
            if row is not None and bytes(row["raw"]) != raw_snapshot:
                raise IngressConflictError("ingress:artifact-conflict")
            if row is None:
                connection.execute(
                    "INSERT INTO ingress_artifacts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        artifact_id, result["envelope_id"], _raw_digest("envelope", raw_snapshot),
                        raw_snapshot, NC_MEDICAID_PROFILE.source_profile_id, NC_MEDICAID_PROFILE.version,
                        NC_MEDICAID_PROFILE.profile_digest, result["observation_time"], result["fetched_at"],
                        result["source_status"], result["failure_code"], result["freshness"],
                        1 if result["page_complete"] else 0, result["snapshot_id"], result["snapshot_root"],
                        independent.content_root(result["resources"]), result["page_count"],
                        result["resource_count"], 0,
                    ),
                )
            for material in attestation_materials:
                receipt = {
                    "schema": SCHEMA,
                    "schema_version": SCHEMA_VERSION,
                    **material,
                    "source_id": NC_MEDICAID_PROFILE.source_profile_id,
                    "slot_id": slot_id,
                }
                receipt_raw = _canonical(receipt)
                fetch_operation = _digest(
                    "fetch-operation",
                    {"operation_id": operation_id, "page_index": material["page_index"], "transport_attempt": material["transport_attempt"]},
                )
                self._append(
                    connection,
                    kind="FETCH_ATTESTATION",
                    operation_id=fetch_operation,
                    request_digest=str(material["request_digest"]),
                    slot_id=slot_id,
                    prior_state=str(slot["state"]),
                    next_state=str(slot["state"]),
                    attempt=int(slot["attempt"]),
                    lease_token=lease_token,
                    lease_until=slot["lease_until"],
                    material=material,
                    payload_digest=str(material["response_digest"]),
                    payload_length=len(receipt_raw),
                    stream_kind="FETCH",
                    stream_id=slot_id,
                    source_id=str(receipt["source_id"]),
                    page_index=int(material["page_index"]),
                    transport_attempt=int(material["transport_attempt"]),
                    receipt_bytes=receipt_raw,
                    head_artifact_id=artifact_id,
                )
            complete = result["source_status"] == "COMPLETE" and result["page_complete"] is True and result["freshness"] in {"FRESH", "UNKNOWN"} and result["failure_code"] is None
            capture_material = {
                "artifact_id": artifact_id,
                "envelope_digest": _raw_digest("envelope", raw_snapshot),
                "slot_id": slot_id,
                "lease_token": lease_token,
            }
            capture_raw = self._append(
                connection, kind="CAPTURE", operation_id=operation_id,
                request_digest=request_digest, slot_id=slot_id,
                prior_state=str(slot["state"]), next_state="CAPTURED",
                attempt=int(slot["attempt"]), lease_token=lease_token,
                 lease_until=slot["lease_until"], material=capture_material,
                 payload_digest=artifact_id, payload_length=len(raw_snapshot),
                 head_artifact_id=artifact_id,
            )
            if complete:
                self._append(
                    connection, kind="BEGIN_QUARANTINE", operation_id=operation_id,
                    request_digest=request_digest, slot_id=slot_id,
                    prior_state="CAPTURED", next_state="QUARANTINE_PENDING",
                    attempt=int(slot["attempt"]), lease_token=lease_token,
                     lease_until=slot["lease_until"], material={"artifact_id": artifact_id, "decision": "QUARANTINE_PENDING"},
                     payload_digest=artifact_id, payload_length=len(raw_snapshot),
                     head_artifact_id=artifact_id,
                )
                next_state = "QUARANTINED"
                final_kind = "ADMIT"
                final_prior = "QUARANTINE_PENDING"
            else:
                next_state = "HELD"
                final_kind = "FAIL"
                final_prior = "CAPTURED"
            final_raw = self._append(
                connection, kind=final_kind, operation_id=operation_id,
                request_digest=request_digest, slot_id=slot_id,
                prior_state=final_prior, next_state=next_state,
                attempt=int(slot["attempt"]), lease_token=lease_token,
                lease_until=slot["lease_until"], material={"artifact_id": artifact_id, "decision": next_state},
                 payload_digest=artifact_id, payload_length=len(raw_snapshot),
                 stream_kind="QUARANTINE", stream_id=self.config.chain_id,
                 head_artifact_id=artifact_id,
            )
            sequence = int(json.loads(final_raw.decode("ascii"))["sequence"])
            connection.execute(
                "UPDATE ingress_artifacts SET event_sequence=? WHERE artifact_id=?",
                (sequence, artifact_id),
            )
            connection.execute(
                "UPDATE ingress_slots SET state=?,artifact_id=?,operation_id=?,lease_token=NULL,lease_until=NULL WHERE slot_id=?",
                (next_state, artifact_id, operation_id, slot_id),
            )
            connection.commit()
            return self._receipt(final_raw, artifact_id=artifact_id, next_state=next_state)
        except (IngressConflictError, IngressError):
            connection.rollback()
            raise
        except sqlite3.OperationalError as exc:
            connection.rollback()
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise_redacted(IngressBusyError, "ingress:busy")
            raise_redacted(IngressError, "ingress:database")
        except sqlite3.Error:
            connection.rollback()
            raise_redacted(IngressError, "ingress:database")
        finally:
            connection.close()

    def current(self, *, include_raw: bool = False) -> dict[str, object]:
        return self.verify(include_raw=include_raw)

    def logical_export(self) -> bytes:
        return independent.logical_export(self.verify())

    def support(self) -> dict[str, object]:
        result = self.verify()
        return {
            "schema": "mirror-ingress-support-v2",
            "states": result["state_counts"],
            "slot_count": result["slot_count"],
            "artifact_count": result["artifact_count"],
            "attestation_count": result["attestation_count"],
            "event_count": result["event_count"],
            "flags": dict(FIXED_FLAGS),
        }


__all__ = [
    "IngressConfigV2", "IngressReceipt", "IngressError",
    "IngressConflictError", "IngressBusyError", "IngressServiceV2",
    "SCHEMA", "SCHEMA_VERSION", "TABLES", "STATES", "FIXED_FLAGS",
]
