"""The single six-table durable Mirror Core V2 owner.

Core is a read-only evidence and continuity owner.  It does not send to a
receiver, adjudicate, authorize payment, or own ingress raw source bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
import hmac
import json
from pathlib import Path
import re
import sqlite3
import time
from typing import Mapping

from app.mirror import core_v2_independent as independent
from app.mirror import external_governance_approval_independent as governance
from app.mirror import external_privacy_support_approval_independent as privacy
from app.mirror import ingress_v2_independent as ingress
from app.mirror import nc_medicaid_fhir_independent as fhir
from app.mirror import nc_medicaid_fhir_profile as profile
from app.mirror import provider_trust_graph_independent as graph_independent
from app.mirror.source_admission import SourceAdmissionService
from app.mirror.error_boundary import raise_redacted


SCHEMA = independent.SCHEMA
SCHEMA_VERSION = independent.SCHEMA_VERSION
TABLES = independent.TABLES
ARTIFACT_KINDS = independent.ARTIFACT_KINDS
FIXED_FLAGS = dict(independent.FIXED_FLAGS)
CASE_EDGES = {
    "OPEN": {"RESPONSIBILITY"}, "RESPONSIBILITY": {"REMEDIATION"},
    "REMEDIATION": {"RETEST"}, "RETEST": {"PERSISTENCE"},
    "PERSISTENCE": {"RESOLVED", "SUPERSEDED"},
}
TOKEN_RE = re.compile(r"^[0-9a-f]{128}$")


class CoreError(ValueError):
    """Public-safe core error."""


class CoreConflictError(CoreError):
    """A stale or conflicting core request."""


class CoreBusyError(CoreError):
    """A bounded core writer failure."""


@dataclass(frozen=True)
class CoreConfigV2:
    database_id: str
    chain_id: str
    ingress_database_id: str
    runtime_profile_digest: str
    governance_policy_digest: str
    privacy_policy_digest: str
    max_sessions: int = 8
    max_slots_per_session: int = 16
    cadence_seconds: int = 60
    max_delivery_attempts: int = 3

    def __post_init__(self) -> None:
        if any(type(value) is not str or not value for value in (self.database_id, self.chain_id, self.ingress_database_id)):
            raise CoreError("core:config")
        for value in (self.runtime_profile_digest, self.governance_policy_digest, self.privacy_policy_digest):
            if type(value) is not str or len(value) != 128 or any(char not in "0123456789abcdef" for char in value):
                raise CoreError("core:config")
        if type(self.max_sessions) is not int or not 1 <= self.max_sessions <= 64 or type(self.max_slots_per_session) is not int or not 1 <= self.max_slots_per_session <= 256 or type(self.cadence_seconds) is not int or self.cadence_seconds <= 0 or type(self.max_delivery_attempts) is not int or not 1 <= self.max_delivery_attempts <= 8:
            raise CoreError("core:config")

    def material(self) -> dict[str, object]:
        return {
            "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "database_id": self.database_id,
            "chain_id": self.chain_id, "ingress_database_id": self.ingress_database_id,
            "runtime_profile_digest": self.runtime_profile_digest,
            "governance_policy_digest": self.governance_policy_digest,
            "privacy_policy_digest": self.privacy_policy_digest, "max_sessions": self.max_sessions,
            "max_slots_per_session": self.max_slots_per_session, "cadence_seconds": self.cadence_seconds,
            "max_delivery_attempts": self.max_delivery_attempts, "flags": dict(FIXED_FLAGS),
        }

    @property
    def digest(self) -> str:
        return independent._digest("config", self.material())


@dataclass(frozen=True)
class CoreReceipt:
    raw: bytes
    operation_id: str
    event_id: str
    subject_id: str
    next_state: str
    sequence: int
    after_root: str


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise_redacted(CoreError, "core:noncanonical")


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
        raise_redacted(CoreError, "core:database-open")


def _table_names(connection: sqlite3.Connection) -> tuple[str, ...]:
    return tuple(row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall())


def _columns(connection: sqlite3.Connection, table: str) -> tuple[str, ...]:
    return tuple(row[1] for row in connection.execute("SELECT * FROM pragma_table_info(?) ORDER BY cid", (table,)).fetchall())


def _init(path: Path, config: CoreConfigV2) -> None:
    connection = _connection(path)
    try:
        current = _table_names(connection)
        if current and current != tuple(sorted(TABLES)):
            raise CoreError("core:legacy-schema")
        if not current:
            connection.executescript(
                """
                CREATE TABLE core_meta(
                    meta_id INTEGER PRIMARY KEY CHECK(meta_id=1),
                    schema TEXT NOT NULL,
                    schema_version INTEGER NOT NULL,
                    database_id TEXT NOT NULL,
                    chain_id TEXT NOT NULL,
                    config_digest TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    head_root TEXT NOT NULL,
                    ingress_database_id TEXT NOT NULL,
                    ingress_watermark INTEGER NOT NULL
                );
                CREATE TABLE core_artifacts(
                    artifact_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    raw BLOB NOT NULL,
                    profile_digest TEXT NOT NULL,
                    source_artifact_id TEXT,
                    predecessor_id TEXT,
                    current_state TEXT NOT NULL,
                    created_event_sequence INTEGER NOT NULL
                );
                CREATE TABLE core_heads(
                    stream_kind TEXT NOT NULL,
                    stream_id TEXT NOT NULL,
                    head_ref TEXT NOT NULL,
                    head_root TEXT NOT NULL,
                    event_sequence INTEGER NOT NULL,
                    PRIMARY KEY(stream_kind,stream_id)
                );
                CREATE TABLE core_sessions(
                    session_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    source_artifact_id TEXT NOT NULL,
                    governance_artifact_id TEXT NOT NULL,
                    privacy_artifact_id TEXT NOT NULL,
                    head_root TEXT NOT NULL,
                    last_slot INTEGER NOT NULL,
                    delivery_state TEXT NOT NULL,
                    delivery_job_id TEXT,
                    delivery_attempt INTEGER NOT NULL,
                    delivery_lease_token_digest TEXT,
                    delivery_lease_until INTEGER,
                    delivery_response_digest TEXT,
                    delivery_error_code TEXT
                );
                CREATE TABLE core_slots(
                    session_id TEXT NOT NULL,
                    slot_number INTEGER NOT NULL,
                    result_digest TEXT NOT NULL,
                    result_raw BLOB NOT NULL,
                    PRIMARY KEY(session_id,slot_number),
                    FOREIGN KEY(session_id) REFERENCES core_sessions(session_id)
                );
                CREATE TABLE core_events(
                    sequence INTEGER PRIMARY KEY,
                    event_id TEXT NOT NULL UNIQUE,
                    event_kind TEXT NOT NULL,
                    operation_id TEXT NOT NULL UNIQUE,
                    subject_id TEXT NOT NULL,
                    event_raw BLOB NOT NULL,
                    receipt_digest TEXT NOT NULL
                );
                CREATE INDEX core_artifacts_kind_source_event_idx ON core_artifacts(kind,source_artifact_id,created_event_sequence);
                """
            )
            connection.execute(
                "INSERT INTO core_meta(meta_id,schema,schema_version,database_id,chain_id,config_digest,sequence,head_root,ingress_database_id,ingress_watermark) VALUES(1,?,?,?,?,?,?,?,?,?)",
                (SCHEMA, SCHEMA_VERSION, config.database_id, config.chain_id, config.digest, 0, independent.GENESIS_ROOT, config.ingress_database_id, 0),
            )
        else:
            for table, columns in independent.TABLE_COLUMNS.items():
                if _columns(connection, table) != columns:
                    raise CoreError("core:legacy-schema")
            indexes = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_autoindex_%'").fetchall()}
            if indexes != {independent.EXPLICIT_INDEX}:
                raise CoreError("core:legacy-schema")
            row = connection.execute("SELECT * FROM core_meta WHERE meta_id=1").fetchone()
            if row is None or row["schema"] != SCHEMA or row["schema_version"] != SCHEMA_VERSION or row["database_id"] != config.database_id or row["chain_id"] != config.chain_id or row["config_digest"] != config.digest or row["ingress_database_id"] != config.ingress_database_id:
                raise CoreError("core:identity")
    except CoreError:
        raise
    except sqlite3.Error:
        raise_redacted(CoreError, "core:database-initialize")
    finally:
        connection.close()


class CoreServiceV2:
    def __init__(self, path: str | Path, config: CoreConfigV2, *, clock: object | None = None) -> None:
        self.path = Path(path)
        self.config = config
        self.clock = clock if clock is not None else lambda: int(time.time())
        if not callable(self.clock):
            raise CoreError("core:clock")
        _init(self.path, config)

    def verify(self, *, ingress_path: str | Path | None = None) -> dict[str, object]:
        return independent.verify_database(self.path, expected_database_id=self.config.database_id, expected_config_digest=self.config.digest, ingress_path=ingress_path)

    def _owner_now(self, connection: sqlite3.Connection) -> int:
        try:
            value = self.clock()
        except Exception:
            raise_redacted(CoreError, "core:clock")
        if type(value) is not int or value < 0:
            raise CoreError("core:clock")
        row = connection.execute("SELECT event_raw FROM core_events ORDER BY sequence DESC LIMIT 1").fetchone()
        latest = None
        if row is not None:
            try:
                latest = independent._parse(bytes(row[0]))["observed_at"]
            except Exception:
                raise CoreError("core:event")
        if latest is not None and value < int(latest):
            raise CoreConflictError("core:clock-rewind")
        return value

    @staticmethod
    def _event(connection: sqlite3.Connection, operation_id: str) -> bytes | None:
        row = connection.execute("SELECT event_raw FROM core_events WHERE operation_id=?", (operation_id,)).fetchone()
        return bytes(row[0]) if row is not None else None

    @staticmethod
    def _receipt(raw: bytes) -> CoreReceipt:
        value = json.loads(raw.decode("ascii"))
        return CoreReceipt(raw=raw, operation_id=str(value["operation_id"]), event_id=str(value["event_id"]), subject_id=str(value["subject_id"]), next_state=str(value["next_state"]), sequence=int(value["sequence"]), after_root=str(value["after_root"]))

    @staticmethod
    def _session_snapshot(row: Mapping[str, object]) -> dict[str, object]:
        return {key: row[key] for key in independent.SESSION_FIELDS}

    def _append(self, connection: sqlite3.Connection, *, kind: str, operation_id: str, subject_id: str, request_digest: str, prior_state: str, next_state: str, attempt: int, observed_at: int, material: Mapping[str, object], payload_digest: str, payload_length: int, stream_kind: str, stream_id: str, head_ref: str, ingress_watermark: int = 0) -> bytes:
        meta = connection.execute("SELECT * FROM core_meta WHERE meta_id=1").fetchone()
        if meta is None:
            raise CoreError("core:meta")
        sequence = int(meta["sequence"]) + 1
        stream_row = connection.execute("SELECT head_root FROM core_heads WHERE stream_kind=? AND stream_id=?", (stream_kind, stream_id)).fetchone()
        stream_before = str(stream_row[0]) if stream_row is not None else independent.GENESIS_ROOT
        body: dict[str, object] = {
            "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "database_id": self.config.database_id, "chain_id": self.config.chain_id,
            "sequence": sequence, "event_id": "", "event_kind": kind, "stream_kind": stream_kind, "stream_id": stream_id,
            "operation_id": operation_id, "subject_id": subject_id, "request_digest": request_digest, "prior_state": prior_state,
            "next_state": next_state, "attempt": attempt, "observed_at": observed_at, "material": dict(material),
            "material_digest": _digest("material", material), "payload_digest": payload_digest, "payload_length": payload_length,
            "before_root": str(meta["head_root"]), "after_root": "", "stream_before_root": stream_before, "stream_after_root": "",
        }
        body["event_id"] = _digest("event-id", {key: body[key] for key in independent.EVENT_RAW_KEYS if key not in {"event_id", "after_root", "stream_after_root"}})
        body["after_root"] = independent._event_root(body)
        body["stream_after_root"] = independent._stream_root(body)
        raw = _canonical(body)
        connection.execute("INSERT INTO core_events(sequence,event_id,event_kind,operation_id,subject_id,event_raw,receipt_digest) VALUES(?,?,?,?,?,?,?)", (sequence, body["event_id"], kind, operation_id, subject_id, raw, _raw_digest("receipt", raw)))
        connection.execute("UPDATE core_meta SET sequence=?,head_root=?,ingress_watermark=MAX(ingress_watermark,?) WHERE meta_id=1", (sequence, body["after_root"], ingress_watermark))
        connection.execute("INSERT INTO core_heads(stream_kind,stream_id,head_ref,head_root,event_sequence) VALUES(?,?,?,?,?) ON CONFLICT(stream_kind,stream_id) DO UPDATE SET head_ref=excluded.head_ref,head_root=excluded.head_root,event_sequence=excluded.event_sequence", (stream_kind, stream_id, head_ref, body["stream_after_root"], sequence))
        return raw

    def _admit_artifact(self, connection: sqlite3.Connection, *, kind: str, raw: bytes, profile_digest: str, predecessor_id: str | None, source_artifact_id: str | None, operation_id: str, request_digest: str, state: str, observed_at: int, ingress_watermark: int = 0) -> tuple[str, bytes]:
        if kind not in ARTIFACT_KINDS:
            raise CoreConflictError("core:artifact-kind")
        artifact_id = _digest("artifact-row-id", {"kind": kind, "raw": _raw_digest("artifact-bytes", raw), "profile_digest": profile_digest, "source_artifact_id": source_artifact_id, "predecessor_id": predecessor_id})
        existing_event = self._event(connection, operation_id)
        if existing_event is not None:
            value = independent._parse(existing_event)
            material = value.get("material")
            if value.get("event_kind") != "ARTIFACT" or not isinstance(material, dict) or material.get("artifact_id") != artifact_id or material.get("raw_digest") != _raw_digest("artifact-bytes", raw):
                raise CoreConflictError("core:operation-conflict")
            return artifact_id, existing_event
        existing = connection.execute("SELECT * FROM core_artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()
        if existing is not None:
            if bytes(existing["raw"]) != raw or existing["profile_digest"] != profile_digest or existing["source_artifact_id"] != source_artifact_id or existing["predecessor_id"] != predecessor_id or existing["current_state"] != state:
                raise CoreConflictError("core:artifact-conflict")
            raise CoreError("core:artifact-receipt")
        connection.execute("INSERT INTO core_artifacts(artifact_id,kind,raw,profile_digest,source_artifact_id,predecessor_id,current_state,created_event_sequence) VALUES(?,?,?,?,?,?,?,0)", (artifact_id, kind, raw, profile_digest, source_artifact_id, predecessor_id, state))
        material = {"artifact_id": artifact_id, "kind": kind, "raw_hex": raw.hex(), "raw_digest": _raw_digest("artifact-bytes", raw), "raw_length": len(raw), "profile_digest": profile_digest, "source_artifact_id": source_artifact_id, "predecessor_id": predecessor_id, "current_state": state, "ingress_watermark": ingress_watermark}
        event_raw = self._append(connection, kind="ARTIFACT", operation_id=operation_id, subject_id=artifact_id, request_digest=request_digest, prior_state="NONE", next_state=kind, attempt=0, observed_at=observed_at, material=material, payload_digest=artifact_id, payload_length=len(raw), stream_kind="ARTIFACT", stream_id=kind, head_ref=artifact_id, ingress_watermark=ingress_watermark)
        sequence = json.loads(event_raw.decode("ascii"))["sequence"]
        connection.execute("UPDATE core_artifacts SET created_event_sequence=? WHERE artifact_id=?", (sequence, artifact_id))
        return artifact_id, event_raw

    def ingest_source(self, ingress_path: str | Path, artifact_id: str) -> dict[str, object]:
        try:
            ing = ingress.read_artifact(ingress_path, artifact_id)
            raw_envelope = ing["raw"]
            fhir.verify_bytes(raw_envelope)
            admission = SourceAdmissionService(profile.NC_MEDICAID_GRAPH_PROFILE, fhir.NcMedicaidFhirVerifier()).admit(raw_envelope)
            graph_raw = bytes(admission.graph_artifact)
            graph_result = graph_independent.verify_bytes_v2(graph_raw, dict(profile.NC_MEDICAID_GRAPH_PROFILE_REGISTRY))
            if graph_result.get("accepted") is not True:
                raise CoreError("core:graph-reject")
            graph_artifact_digest = _raw_digest("graph-artifact", graph_raw)
        except CoreError:
            raise
        except Exception:
            raise_redacted(CoreError, "core:ingress-reject")
        ingress_watermark = int(ing["event_sequence"])
        source_operation = _digest("source-operation", {"ingress_artifact_id": artifact_id})
        connection = _connection(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing_event = self._event(connection, source_operation)
            if existing_event is not None:
                parsed = independent._parse(existing_event)
                material = parsed.get("material")
                if not isinstance(material, dict) or material.get("artifact_id") != parsed.get("subject_id"):
                    raise CoreError("core:source-receipt")
                row = connection.execute("SELECT raw FROM core_artifacts WHERE artifact_id=?", (material["artifact_id"],)).fetchone()
                if row is None:
                    raise CoreError("core:source-receipt")
                source_value = independent._parse(bytes(row[0]))
                if source_value.get("ingress_artifact_id") != artifact_id or source_value.get("envelope_digest") != ing["envelope_digest"] or source_value.get("content_root") != ing["content_root"]:
                    raise CoreConflictError("core:source-conflict")
                connection.commit()
                return {"source_artifact_id": str(material["artifact_id"]), "graph_artifact_id": str(source_value["graph_artifact_id"]), "reconciliation_artifact_id": self._find_reconciliation(connection, str(material["artifact_id"])), "observation_status": source_value["observation_status"], "receipt": self._receipt(existing_event)}
            current = connection.execute("SELECT head_ref FROM core_heads WHERE stream_kind='ARTIFACT' AND stream_id='SOURCE_OBSERVATION'").fetchone()
            predecessor_id = str(current[0]) if current is not None else None
            prior = None
            if predecessor_id is not None:
                prior_row = connection.execute("SELECT raw FROM core_artifacts WHERE artifact_id=?", (predecessor_id,)).fetchone()
                if prior_row is None:
                    raise CoreError("core:head")
                prior = independent._parse(bytes(prior_row[0]))
            chronology = "INITIAL" if prior is None else ("EQUAL" if prior.get("observation_time") == ing["observation_time"] else "ADVANCING")
            status = "OBSERVED_NEW" if prior is None else ("INCOMPLETE" if ing["source_status"] != "COMPLETE" else ("OBSERVED_CONTINUED" if prior.get("content_root") == ing["content_root"] else "OBSERVED_CHANGED"))
            now = self._owner_now(connection)
            graph_body = _canonical({"schema": "mirror-core-graph-v2", "schema_version": 2, "kind": "GRAPH", "artifact_id": str(graph_result["report_id"]), "graph": json.loads(graph_raw.decode("ascii")), "graph_digest": graph_artifact_digest, "flags": dict(FIXED_FLAGS)})
            graph_id, _ = self._admit_artifact(connection, kind="GRAPH", raw=graph_body, profile_digest=profile.NC_MEDICAID_GRAPH_PROFILE.profile_digest, predecessor_id=None, source_artifact_id=None, operation_id=_digest("graph-operation", {"graph_id": str(graph_result["report_id"]), "graph_digest": graph_artifact_digest}), request_digest=_digest("graph-request", {"graph_id": str(graph_result["report_id"]), "graph_digest": graph_artifact_digest}), state="GRAPH", observed_at=now, ingress_watermark=ingress_watermark)
            source_body = {"schema": "mirror-core-source-observation-v2", "schema_version": 2, "kind": "SOURCE_OBSERVATION", "artifact_id": "", "ingress_database_id": self.config.ingress_database_id, "ingress_artifact_id": artifact_id, "ingress_event_sequence": ing["event_sequence"], "ingress_head_root": ing["head_root"], "envelope_id": ing["envelope_id"], "envelope_digest": ing["envelope_digest"], "snapshot_id": ing["snapshot_id"], "snapshot_root": ing["snapshot_root"], "content_root": ing["content_root"], "profile_id": ing["profile_id"], "profile_version": ing["profile_version"], "profile_digest": ing["profile_digest"], "source_status": ing["source_status"], "freshness": ing["freshness"], "page_count": ing["page_count"], "resource_count": ing["resource_count"], "graph_artifact_id": graph_id, "graph_artifact_digest": graph_artifact_digest, "observation_status": status, "chronology": chronology, "flags": dict(FIXED_FLAGS)}
            source_body["artifact_id"] = _digest("source-artifact-id", {key: source_body[key] for key in source_body if key not in {"artifact_id", "flags"}})
            source_raw = _canonical(source_body)
            source_id, _ = self._admit_artifact(connection, kind="SOURCE_OBSERVATION", raw=source_raw, profile_digest=ing["profile_digest"], predecessor_id=predecessor_id, source_artifact_id=artifact_id, operation_id=source_operation, request_digest=_digest("source-request", {"ingress_artifact_id": artifact_id}), state=status, observed_at=now, ingress_watermark=ingress_watermark)
            rec_body = {"schema": "mirror-core-reconciliation-v2", "schema_version": 2, "kind": "RECONCILIATION", "artifact_id": "", "current_source_artifact_id": source_id, "prior_source_artifact_id": predecessor_id, "current_content_root": ing["content_root"], "prior_content_root": prior.get("content_root") if prior else None, "source_status": ing["source_status"], "observation_status": status, "chronology": chronology, "linkage": "UNCHANGED" if prior and prior.get("graph_artifact_digest") == graph_artifact_digest else "LINKED", "flags": dict(FIXED_FLAGS)}
            rec_body["artifact_id"] = _digest("reconciliation-id", {key: rec_body[key] for key in rec_body if key != "artifact_id"})
            rec_id, rec_event = self._admit_artifact(connection, kind="RECONCILIATION", raw=_canonical(rec_body), profile_digest=ing["profile_digest"], predecessor_id=self._find_reconciliation(connection, predecessor_id) if predecessor_id else None, source_artifact_id=source_id, operation_id=_digest("reconciliation-operation", {"source_artifact_id": source_id}), request_digest=_digest("reconciliation-request", {"source_artifact_id": source_id}), state=status, observed_at=now, ingress_watermark=ingress_watermark)
            connection.commit()
            return {"source_artifact_id": source_id, "graph_artifact_id": graph_id, "reconciliation_artifact_id": rec_id, "observation_status": status, "receipt": self._receipt(rec_event)}
        except (CoreConflictError, CoreError):
            connection.rollback()
            raise
        except sqlite3.OperationalError as exc:
            connection.rollback()
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise_redacted(CoreBusyError, "core:busy")
            raise_redacted(CoreError, "core:database")
        except sqlite3.Error:
            connection.rollback()
            raise_redacted(CoreError, "core:database")
        finally:
            connection.close()

    @staticmethod
    def _find_reconciliation(connection: sqlite3.Connection, source_id: str | None) -> str | None:
        if source_id is None:
            return None
        row = connection.execute("SELECT artifact_id FROM core_artifacts WHERE kind='RECONCILIATION' AND source_artifact_id=? ORDER BY created_event_sequence DESC LIMIT 1", (source_id,)).fetchone()
        return str(row[0]) if row else None

    def _admit_approval(self, raw: bytes, *, kind: str, profile_digest: str, decision: str) -> str:
        value = independent._parse(raw)
        if value.get("kind") != kind or value.get("flags") != FIXED_FLAGS or (kind == "GOVERNANCE" and value.get("decision") != decision) or (kind == "PRIVACY" and value.get("privacy_decision") != decision):
            raise CoreError("core:approval")
        operation_id = _digest("approval-operation", {"kind": kind, "raw": _raw_digest("approval", raw)})
        connection = _connection(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._event(connection, operation_id)
            if existing is not None:
                connection.commit()
                return str(independent._parse(existing)["material"]["artifact_id"])
            head = connection.execute("SELECT head_ref FROM core_heads WHERE stream_kind='ARTIFACT' AND stream_id=?", (kind,)).fetchone()
            predecessor = str(head[0]) if head else None
            now = self._owner_now(connection)
            artifact_id, _event = self._admit_artifact(connection, kind=kind, raw=raw, profile_digest=profile_digest, predecessor_id=predecessor, source_artifact_id=None, operation_id=operation_id, request_digest=_digest("approval-request", {"kind": kind, "raw": _raw_digest("approval", raw)}), state=decision, observed_at=now)
            connection.commit()
            return artifact_id
        except (CoreError, CoreConflictError):
            connection.rollback()
            raise
        except sqlite3.Error:
            connection.rollback()
            raise_redacted(CoreError, "core:database")
        finally:
            connection.close()

    def admit_governance(self, raw: bytes, *, policy: object, evidence_raw: bytes) -> str:
        try:
            result = governance.verify_artifact(raw, policy=policy.material(), evidence_raw=evidence_raw)
            if result.get("accepted") is not True:
                raise CoreError("core:governance")
            value = independent._parse(raw)
            assertion = value["assertion"]
            projection = {"schema": "mirror-core-governance-v2", "schema_version": 2, "kind": "GOVERNANCE", "artifact_id": value["artifact_id"], "decision": assertion["decision"], "policy_digest": value["policy_digest"], "evidence_digest": assertion["evidence_sha3_512"], "verifier_id": assertion["verifier_id"], "verifier_epoch": assertion["verifier_epoch"], "valid_from": assertion["valid_from"], "valid_until": assertion["valid_until"], "flags": dict(FIXED_FLAGS)}
            return self._admit_approval(_canonical(projection), kind="GOVERNANCE", profile_digest=str(policy.digest), decision=str(assertion["decision"]))
        except CoreError:
            raise
        except Exception:
            raise_redacted(CoreError, "core:governance")

    def admit_privacy(self, raw: bytes, *, policy: object, evidence_raw: bytes) -> str:
        try:
            result = privacy.verify_artifact(raw, policy=policy.material(), evidence_raw=evidence_raw)
            if result.get("accepted") is not True:
                raise CoreError("core:privacy")
            value = independent._parse(raw)
            assertion = value["assertion"]
            projection = {"schema": "mirror-core-privacy-v2", "schema_version": 2, "kind": "PRIVACY", "artifact_id": value["artifact_id"], "privacy_decision": assertion["privacy_decision"], "support_decision": assertion["support_decision"], "policy_digest": value["policy_digest"], "evidence_digest": assertion["evidence_sha3_512"], "verifier_id": assertion["verifier_id"], "verifier_epoch": assertion["verifier_epoch"], "valid_from": assertion["valid_from"], "valid_until": assertion["valid_until"], "flags": dict(FIXED_FLAGS)}
            return self._admit_approval(_canonical(projection), kind="PRIVACY", profile_digest=str(policy.digest), decision=str(assertion["privacy_decision"]))
        except CoreError:
            raise
        except Exception:
            raise_redacted(CoreError, "core:privacy")

    def admit_case(self, reconciliation_artifact_id: str) -> str:
        if type(reconciliation_artifact_id) is not str or len(reconciliation_artifact_id) != 128 or any(char not in "0123456789abcdef" for char in reconciliation_artifact_id):
            raise CoreConflictError("core:case-input")
        connection = _connection(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT raw,source_artifact_id FROM core_artifacts WHERE artifact_id=? AND kind='RECONCILIATION'", (reconciliation_artifact_id,)).fetchone()
            if row is None:
                raise CoreConflictError("core:case-reconciliation")
            reconciliation = independent._parse(bytes(row[0]))
            reason = "SOURCE_CHANGED" if reconciliation["observation_status"] == "OBSERVED_CHANGED" else ("SOURCE_INCOMPLETE" if reconciliation["observation_status"] == "INCOMPLETE" else "OBSERVATION_ONLY")
            parity = "DIVERGENT" if reason == "SOURCE_CHANGED" else ("PARTIAL" if reason == "SOURCE_INCOMPLETE" else "UNKNOWN")
            case_id = _digest("case-id", {"reconciliation_artifact_id": reconciliation_artifact_id, "source_artifact_id": reconciliation["current_source_artifact_id"]})
            operation_id = _digest("case-operation", {"case_id": case_id})
            existing_event = self._event(connection, operation_id)
            if existing_event is not None:
                connection.commit()
                head = connection.execute("SELECT head_ref FROM core_heads WHERE stream_kind='ARTIFACT' AND stream_id='CASE'").fetchone()
                return str(head[0]) if head is not None else str(independent._parse(existing_event)["material"]["artifact_id"])
            body = {"schema": "mirror-core-case-v2", "schema_version": 2, "kind": "CASE", "artifact_id": "", "case_id": case_id, "reconciliation_artifact_id": reconciliation_artifact_id, "source_artifact_id": reconciliation["current_source_artifact_id"], "state": "OPEN", "responsibility": "UNKNOWN", "remediation": "UNOBSERVED", "retest": "UNREQUESTED", "parity": parity, "reason": reason, "flags": dict(FIXED_FLAGS)}
            body["artifact_id"] = _digest("case-artifact", {key: body[key] for key in body if key != "artifact_id"})
            now = self._owner_now(connection)
            artifact_id, _ = self._admit_artifact(connection, kind="CASE", raw=_canonical(body), profile_digest=self.config.runtime_profile_digest, predecessor_id=None, source_artifact_id=body["source_artifact_id"], operation_id=operation_id, request_digest=_digest("case-request", {"reconciliation_artifact_id": reconciliation_artifact_id}), state="OPEN", observed_at=now)
            connection.commit()
            return artifact_id
        except (CoreError, CoreConflictError):
            connection.rollback()
            raise
        except sqlite3.Error:
            connection.rollback()
            raise_redacted(CoreError, "core:database")
        finally:
            connection.close()

    def advance_case(self, case_artifact_id: str, *, next_state: str, responsibility: str | None = None, remediation: str | None = None, retest: str | None = None, parity: str | None = None) -> CoreReceipt:
        if type(case_artifact_id) is not str or len(case_artifact_id) != 128 or any(char not in "0123456789abcdef" for char in case_artifact_id) or next_state not in CASE_EDGES and next_state not in {"RESOLVED", "SUPERSEDED"}:
            raise CoreConflictError("core:case-input")
        supplied = {"responsibility": responsibility, "remediation": remediation, "retest": retest, "parity": parity}
        operation_id = _digest("case-transition-operation", {"case_artifact_id": case_artifact_id, "next_state": next_state, **supplied})
        connection = _connection(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._event(connection, operation_id)
            if existing is not None:
                connection.commit()
                return self._receipt(existing)
            head = connection.execute("SELECT head_ref FROM core_heads WHERE stream_kind='ARTIFACT' AND stream_id='CASE'").fetchone()
            if head is None or head[0] != case_artifact_id:
                raise CoreConflictError("core:case-head")
            prior_row = connection.execute("SELECT * FROM core_artifacts WHERE artifact_id=? AND kind='CASE'", (case_artifact_id,)).fetchone()
            if prior_row is None:
                raise CoreConflictError("core:case-missing")
            prior = independent._parse(bytes(prior_row["raw"]))
            if next_state not in CASE_EDGES.get(str(prior["state"]), set()):
                raise CoreConflictError("core:case-transition")
            allowed = {"responsibility": {"UNKNOWN", "SHARED", "STATE_SOURCE", "PLAN_OR_PROVIDER", "RIGHTRAIL_PROCESSING"}, "remediation": {"UNOBSERVED", "PROPOSED", "ASSERTED", "VERIFIED"}, "retest": {"UNREQUESTED", "REQUESTED", "EXECUTED"}, "parity": {"UNKNOWN", "PARTIAL", "MATCHED", "DIVERGENT"}}
            for key, value in supplied.items():
                if value is not None and value not in allowed[key]:
                    raise CoreConflictError("core:case-value")
            required = {"RESPONSIBILITY": "responsibility", "REMEDIATION": "remediation", "RETEST": "retest", "PERSISTENCE": "parity"}.get(next_state)
            if (required is None and any(value is not None for value in supplied.values())) or (required is not None and supplied[required] is None):
                raise CoreConflictError("core:case-value")
            if next_state == "RETEST" and prior["remediation"] == "UNOBSERVED":
                raise CoreConflictError("core:case-remediation")
            if next_state == "PERSISTENCE" and prior["retest"] != "EXECUTED":
                raise CoreConflictError("core:case-retest")
            if next_state == "RESOLVED" and (prior["parity"] != "MATCHED" or prior["remediation"] != "VERIFIED" or prior["retest"] != "EXECUTED"):
                raise CoreConflictError("core:case-resolve")
            if next_state == "SUPERSEDED" and prior["state"] != "PERSISTENCE":
                raise CoreConflictError("core:case-supersede")
            body = dict(prior)
            body["state"] = next_state
            if required is not None:
                body[required] = supplied[required]
            body["artifact_id"] = ""
            body["artifact_id"] = _digest("case-artifact", {key: body[key] for key in body if key != "artifact_id"})
            now = self._owner_now(connection)
            artifact_id, event_raw = self._admit_artifact(connection, kind="CASE", raw=_canonical(body), profile_digest=self.config.runtime_profile_digest, predecessor_id=case_artifact_id, source_artifact_id=str(prior["source_artifact_id"]), operation_id=operation_id, request_digest=_digest("case-transition-request", {"case_artifact_id": case_artifact_id, "next_state": next_state, **supplied}), state=next_state, observed_at=now)
            connection.commit()
            return self._receipt(event_raw)
        except (CoreError, CoreConflictError):
            connection.rollback()
            raise
        except sqlite3.Error:
            connection.rollback()
            raise_redacted(CoreError, "core:database")
        finally:
            connection.close()

    def open_session(self, *, source_artifact_id: str, governance_artifact_id: str, privacy_artifact_id: str) -> CoreReceipt:
        session_id = _digest("session-id", {"source": source_artifact_id, "governance": governance_artifact_id, "privacy": privacy_artifact_id, "config": self.config.digest})
        operation_id = _digest("session-operation", {"session_id": session_id, "action": "OPEN"})
        connection = _connection(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._event(connection, operation_id)
            if existing is not None:
                connection.commit()
                return self._receipt(existing)
            for kind, expected in (("SOURCE_OBSERVATION", source_artifact_id), ("GOVERNANCE", governance_artifact_id), ("PRIVACY", privacy_artifact_id)):
                head = connection.execute("SELECT head_ref FROM core_heads WHERE stream_kind='ARTIFACT' AND stream_id=?", (kind,)).fetchone()
                if head is None or head[0] != expected:
                    raise CoreConflictError("core:authority-head")
            gov = independent._parse(bytes(connection.execute("SELECT raw FROM core_artifacts WHERE artifact_id=?", (governance_artifact_id,)).fetchone()[0]))
            pval = independent._parse(bytes(connection.execute("SELECT raw FROM core_artifacts WHERE artifact_id=?", (privacy_artifact_id,)).fetchone()[0]))
            if gov.get("decision") != "GRANTED" or pval.get("privacy_decision") != "GRANTED" or pval.get("support_decision") != "GRANTED":
                raise CoreConflictError("core:authority-negative")
            count = int(connection.execute("SELECT COUNT(*) FROM core_sessions").fetchone()[0])
            if count >= self.config.max_sessions:
                raise CoreConflictError("core:capacity")
            now = self._owner_now(connection)
            row = {"session_id": session_id, "state": "OPEN", "source_artifact_id": source_artifact_id, "governance_artifact_id": governance_artifact_id, "privacy_artifact_id": privacy_artifact_id, "head_root": "", "last_slot": -1, "delivery_state": "DUE", "delivery_job_id": None, "delivery_attempt": 0, "delivery_lease_token_digest": None, "delivery_lease_until": None, "delivery_response_digest": None, "delivery_error_code": None}
            connection.execute("INSERT INTO core_sessions(session_id,state,source_artifact_id,governance_artifact_id,privacy_artifact_id,head_root,last_slot,delivery_state,delivery_job_id,delivery_attempt,delivery_lease_token_digest,delivery_lease_until,delivery_response_digest,delivery_error_code) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", tuple(row[key] for key in independent.TABLE_COLUMNS["core_sessions"]))
            material = {key: row[key] for key in independent.SESSION_FIELDS}
            raw = self._append(connection, kind="SESSION_OPEN", operation_id=operation_id, subject_id=session_id, request_digest=_digest("session-request", {"session_id": session_id}), prior_state="NONE", next_state="OPEN", attempt=0, observed_at=now, material={"session": material}, payload_digest=source_artifact_id, payload_length=0, stream_kind="SESSION", stream_id=session_id, head_ref=session_id)
            connection.execute("UPDATE core_sessions SET head_root=? WHERE session_id=?", (json.loads(raw.decode("ascii"))["stream_after_root"], session_id))
            connection.commit()
            return self._receipt(raw)
        except (CoreError, CoreConflictError):
            connection.rollback()
            raise
        except sqlite3.Error:
            connection.rollback()
            raise_redacted(CoreError, "core:database")
        finally:
            connection.close()

    @staticmethod
    def _session(connection: sqlite3.Connection, session_id: str) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM core_sessions WHERE session_id=?", (session_id,)).fetchone()
        if row is None:
            raise CoreConflictError("core:session-missing")
        return row

    def start_session(self, session_id: str) -> CoreReceipt:
        operation_id = _digest("session-operation", {"session_id": session_id, "action": "START"})
        connection = _connection(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._event(connection, operation_id)
            if existing is not None:
                connection.commit()
                return self._receipt(existing)
            row = self._session(connection, session_id)
            if row["state"] != "OPEN":
                raise CoreConflictError("core:session-state")
            now = self._owner_now(connection)
            snapshot = self._session_snapshot(row)
            snapshot["state"] = "RUNNING"
            raw = self._append(connection, kind="SESSION_START", operation_id=operation_id, subject_id=session_id, request_digest=_digest("session-request", {"session_id": session_id, "action": "START"}), prior_state="OPEN", next_state="RUNNING", attempt=0, observed_at=now, material={"session": snapshot}, payload_digest=session_id, payload_length=0, stream_kind="SESSION", stream_id=session_id, head_ref=session_id)
            connection.execute("UPDATE core_sessions SET state=?,head_root=? WHERE session_id=?", ("RUNNING", json.loads(raw.decode("ascii"))["stream_after_root"], session_id))
            connection.commit()
            return self._receipt(raw)
        except (CoreError, CoreConflictError):
            connection.rollback()
            raise
        except sqlite3.Error:
            connection.rollback()
            raise_redacted(CoreError, "core:database")
        finally:
            connection.close()

    def observe(self, session_id: str, slot_number: int, result: str, *, counts: Mapping[str, int] | None = None) -> CoreReceipt:
        if type(slot_number) is not int or slot_number < 0 or slot_number >= self.config.max_slots_per_session or result not in independent.OBSERVATION_RESULTS:
            raise CoreConflictError("core:observation-input")
        counts = dict(counts or {"observed": 0, "changed": 0})
        if set(counts) != {"observed", "changed"} or any(type(value) is not int or value < 0 or value > 64 for value in counts.values()):
            raise CoreConflictError("core:observation-input")
        observation = {"schema": "mirror-core-observation-v2", "schema_version": 2, "session_id": session_id, "slot_number": slot_number, "result": result, "counts": {"changed": counts["changed"], "observed": counts["observed"]}, "flags": dict(FIXED_FLAGS)}
        observation["result_digest"] = _digest("observation", {key: observation[key] for key in observation if key != "result_digest"})
        result_raw = _canonical(observation)
        operation_id = _digest("observation-operation", {"session_id": session_id, "slot_number": slot_number})
        connection = _connection(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._event(connection, operation_id)
            if existing is not None:
                parsed = independent._parse(existing)
                if not isinstance(parsed.get("material"), dict) or parsed["material"].get("observation") != observation:
                    raise CoreConflictError("core:observation-conflict")
                connection.commit()
                return self._receipt(existing)
            row = self._session(connection, session_id)
            if row["state"] != "RUNNING":
                raise CoreConflictError("core:session-state")
            expected_slot = int(row["last_slot"]) + 1
            if slot_number != expected_slot:
                raise CoreConflictError("core:observation-order")
            old = connection.execute("SELECT result_raw FROM core_slots WHERE session_id=? AND slot_number=?", (session_id, slot_number)).fetchone()
            if old is not None:
                if bytes(old[0]) != result_raw:
                    raise CoreConflictError("core:observation-conflict")
                raise CoreError("core:observation-receipt")
            now = self._owner_now(connection)
            snapshot = self._session_snapshot(row)
            snapshot["last_slot"] = slot_number
            connection.execute("INSERT INTO core_slots(session_id,slot_number,result_digest,result_raw) VALUES(?,?,?,?)", (session_id, slot_number, observation["result_digest"], result_raw))
            raw = self._append(connection, kind="OBSERVATION", operation_id=operation_id, subject_id=session_id, request_digest=_digest("observation-request", {"session_id": session_id, "slot_number": slot_number}), prior_state="RUNNING", next_state="RUNNING", attempt=0, observed_at=now, material={"observation": observation, "session": snapshot}, payload_digest=observation["result_digest"], payload_length=len(result_raw), stream_kind="SESSION", stream_id=session_id, head_ref=session_id)
            connection.execute("UPDATE core_sessions SET last_slot=?,head_root=? WHERE session_id=?", (slot_number, json.loads(raw.decode("ascii"))["stream_after_root"], session_id))
            connection.commit()
            return self._receipt(raw)
        except (CoreError, CoreConflictError):
            connection.rollback()
            raise
        except sqlite3.Error:
            connection.rollback()
            raise_redacted(CoreError, "core:database")
        finally:
            connection.close()

    def pause_if_stale(self, session_id: str, current_source_artifact_id: str, *, reason: str = "SOURCE_SUPERSEDED") -> CoreReceipt:
        if reason not in {"SOURCE_SUPERSEDED", "AUTHORITY_EXPIRED", "AUTHORITY_INDETERMINATE"}:
            raise CoreConflictError("core:pause-reason")
        operation_id = _digest("pause-operation", {"session_id": session_id, "reason": reason, "current_source_artifact_id": current_source_artifact_id})
        connection = _connection(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._event(connection, operation_id)
            if existing is not None:
                connection.commit()
                return self._receipt(existing)
            row = self._session(connection, session_id)
            if row["source_artifact_id"] == current_source_artifact_id:
                raise CoreConflictError("core:source-current")
            if row["state"] != "RUNNING":
                raise CoreConflictError("core:pause-state")
            now = self._owner_now(connection)
            snapshot = self._session_snapshot(row)
            snapshot["state"] = "PAUSED"
            raw = self._append(connection, kind="SESSION_PAUSE", operation_id=operation_id, subject_id=session_id, request_digest=_digest("pause-request", {"session_id": session_id, "reason": reason, "current_source_artifact_id": current_source_artifact_id}), prior_state="RUNNING", next_state="PAUSED", attempt=0, observed_at=now, material={"session": snapshot, "current_source_artifact_id": current_source_artifact_id, "reason": reason}, payload_digest=_digest("pause-reason", {"reason": reason}), payload_length=0, stream_kind="SESSION", stream_id=session_id, head_ref=session_id)
            connection.execute("UPDATE core_sessions SET state=?,head_root=? WHERE session_id=?", ("PAUSED", json.loads(raw.decode("ascii"))["stream_after_root"], session_id))
            connection.commit()
            return self._receipt(raw)
        except (CoreError, CoreConflictError):
            connection.rollback()
            raise
        except sqlite3.Error:
            connection.rollback()
            raise_redacted(CoreError, "core:database")
        finally:
            connection.close()

    @staticmethod
    def _token_digest(token: str) -> str:
        if type(token) is not str or TOKEN_RE.fullmatch(token) is None:
            raise CoreConflictError("core:delivery-token")
        return _digest("delivery-token", {"token": token})

    def _delivery_requeue(self, connection: sqlite3.Connection, row: sqlite3.Row, *, job_id: str, delivery_id: str, now: int, reason: str) -> bytes:
        prior_token = row["delivery_lease_token_digest"]
        prior_lease = row["delivery_lease_until"]
        snapshot = self._session_snapshot(row)
        snapshot.update({"delivery_state": "DUE", "delivery_job_id": job_id, "delivery_lease_token_digest": None, "delivery_lease_until": None, "delivery_response_digest": None, "delivery_error_code": None})
        raw = self._append(connection, kind="DELIVERY_REQUEUE", operation_id=_digest("delivery-requeue-operation", {"session_id": row["session_id"], "job_id": job_id, "attempt": row["delivery_attempt"]}), subject_id=str(row["session_id"]), request_digest=_digest("delivery-request", {"session_id": row["session_id"], "job_id": job_id, "action": "REQUEUE", "attempt": row["delivery_attempt"], "prior_token_digest": prior_token}), prior_state=str(row["delivery_state"]), next_state="DUE", attempt=int(row["delivery_attempt"]), observed_at=now, material={"session": snapshot, "job_id": job_id, "delivery_id": delivery_id, "expired_attempt": int(row["delivery_attempt"]), "prior_token_digest": prior_token, "prior_lease_until": prior_lease, "reason": reason}, payload_digest=_digest("delivery-requeue-payload", {"job_id": job_id, "attempt": row["delivery_attempt"]}), payload_length=0, stream_kind="DELIVERY", stream_id=delivery_id, head_ref=delivery_id)
        connection.execute("UPDATE core_sessions SET delivery_state='DUE',delivery_job_id=?,delivery_lease_token_digest=NULL,delivery_lease_until=NULL,delivery_response_digest=NULL,delivery_error_code=NULL WHERE session_id=?", (job_id, row["session_id"]))
        return raw

    def _delivery_exhaust(self, connection: sqlite3.Connection, row: sqlite3.Row, *, job_id: str, delivery_id: str, now: int) -> bytes:
        snapshot = self._session_snapshot(row)
        snapshot.update({"delivery_state": "EXHAUSTED", "delivery_job_id": job_id, "delivery_response_digest": None, "delivery_error_code": "ATTEMPTS_EXHAUSTED"})
        raw = self._append(connection, kind="DELIVERY_EXHAUSTED", operation_id=_digest("delivery-exhausted-operation", {"session_id": row["session_id"], "job_id": job_id, "attempt": row["delivery_attempt"]}), subject_id=str(row["session_id"]), request_digest=_digest("delivery-request", {"session_id": row["session_id"], "job_id": job_id, "action": "EXHAUSTED", "attempt": row["delivery_attempt"]}), prior_state=str(row["delivery_state"]), next_state="EXHAUSTED", attempt=int(row["delivery_attempt"]), observed_at=now, material={"session": snapshot, "job_id": job_id, "delivery_id": delivery_id, "token_digest": row["delivery_lease_token_digest"], "lease_until": row["delivery_lease_until"], "error_code": "ATTEMPTS_EXHAUSTED", "max_attempts": self.config.max_delivery_attempts}, payload_digest=_digest("delivery-exhausted-payload", {"job_id": job_id, "attempt": row["delivery_attempt"]}), payload_length=0, stream_kind="DELIVERY", stream_id=delivery_id, head_ref=delivery_id)
        connection.execute("UPDATE core_sessions SET delivery_state='EXHAUSTED',delivery_job_id=?,delivery_response_digest=NULL,delivery_error_code='ATTEMPTS_EXHAUSTED' WHERE session_id=?", (job_id, row["session_id"]))
        return raw

    def begin_delivery(self, session_id: str, job_id: str, *, lease_token: str) -> CoreReceipt:
        if any(type(value) is not str or not value for value in (session_id, job_id)):
            raise CoreConflictError("core:delivery-input")
        token_digest = self._token_digest(lease_token)
        connection = _connection(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = self._session(connection, session_id)
            if row["delivery_job_id"] is not None and row["delivery_job_id"] != job_id:
                raise CoreConflictError("core:delivery-job")
            state = str(row["delivery_state"])
            delivery_id = _digest("delivery-id", {"session_id": session_id, "job_id": job_id})
            if state == "INTENT" and row["delivery_lease_token_digest"] is not None and hmac.compare_digest(str(row["delivery_lease_token_digest"]), token_digest):
                op = _digest("delivery-intent-operation", {"session_id": session_id, "job_id": job_id, "attempt": row["delivery_attempt"], "token_digest": token_digest})
                existing = self._event(connection, op)
                if existing is None:
                    raise CoreError("core:delivery-receipt")
                now = self._owner_now(connection)
                if row["delivery_lease_until"] is not None and now < int(row["delivery_lease_until"]):
                    connection.commit()
                    return self._receipt(existing)
                raise CoreConflictError("core:delivery-stale-token")
            if state in {"ACK", "EXHAUSTED"}:
                raise CoreConflictError("core:delivery-exhausted" if state == "EXHAUSTED" else "core:delivery-state")
            now = self._owner_now(connection)
            if state in {"INTENT", "UNKNOWN"}:
                if row["delivery_lease_until"] is None or now < int(row["delivery_lease_until"]):
                    raise CoreConflictError("core:delivery-lease")
                if int(row["delivery_attempt"]) >= self.config.max_delivery_attempts:
                    raw = self._delivery_exhaust(connection, row, job_id=job_id, delivery_id=delivery_id, now=now)
                    connection.commit()
                    return self._receipt(raw)
                self._delivery_requeue(connection, row, job_id=job_id, delivery_id=delivery_id, now=now, reason="LEASE_EXPIRED")
                row = self._session(connection, session_id)
                state = "DUE"
            if state != "DUE":
                raise CoreConflictError("core:delivery-state")
            attempt = int(row["delivery_attempt"]) + 1
            if attempt > self.config.max_delivery_attempts:
                raise CoreConflictError("core:delivery-exhausted")
            lease_until = now + self.config.cadence_seconds
            operation_id = _digest("delivery-intent-operation", {"session_id": session_id, "job_id": job_id, "attempt": attempt, "token_digest": token_digest})
            snapshot = self._session_snapshot(row)
            snapshot.update({"delivery_state": "INTENT", "delivery_job_id": job_id, "delivery_attempt": attempt, "delivery_lease_token_digest": token_digest, "delivery_lease_until": lease_until, "delivery_response_digest": None, "delivery_error_code": None})
            raw = self._append(connection, kind="DELIVERY_INTENT", operation_id=operation_id, subject_id=session_id, request_digest=_digest("delivery-request", {"session_id": session_id, "job_id": job_id, "attempt": attempt, "token_digest": token_digest}), prior_state="DUE", next_state="INTENT", attempt=attempt, observed_at=now, material={"session": snapshot, "job_id": job_id, "delivery_id": delivery_id, "token_digest": token_digest, "lease_until": lease_until}, payload_digest=_digest("delivery-job", {"session_id": session_id, "job_id": job_id, "delivery_id": delivery_id}), payload_length=0, stream_kind="DELIVERY", stream_id=delivery_id, head_ref=delivery_id)
            connection.execute("UPDATE core_sessions SET delivery_state='INTENT',delivery_job_id=?,delivery_attempt=?,delivery_lease_token_digest=?,delivery_lease_until=?,delivery_response_digest=NULL,delivery_error_code=NULL WHERE session_id=?", (job_id, attempt, token_digest, lease_until, session_id))
            connection.commit()
            return self._receipt(raw)
        except (CoreError, CoreConflictError):
            connection.rollback()
            raise
        except sqlite3.Error:
            connection.rollback()
            raise_redacted(CoreError, "core:database")
        finally:
            connection.close()

    def acknowledge_delivery(self, session_id: str, *, job_id: str, lease_token: str, response_digest: str) -> CoreReceipt:
        return self._finish_delivery(session_id, job_id=job_id, lease_token=lease_token, response_digest=response_digest, unknown=False)

    def mark_delivery_unknown(self, session_id: str, *, job_id: str, lease_token: str, code: str = "RESPONSE_LOST") -> CoreReceipt:
        if code not in {"RESPONSE_LOST", "TIMEOUT", "REMOTE_INDETERMINATE"}:
            raise CoreConflictError("core:delivery-code")
        return self._finish_delivery(session_id, job_id=job_id, lease_token=lease_token, response_digest=None, unknown=True, code=code)

    def _finish_delivery(self, session_id: str, *, job_id: str, lease_token: str, response_digest: str | None, unknown: bool, code: str = "RESPONSE_LOST") -> CoreReceipt:
        if any(type(value) is not str or not value for value in (session_id, job_id)):
            raise CoreConflictError("core:delivery-input")
        token_digest = self._token_digest(lease_token)
        if response_digest is not None and (len(response_digest) != 128 or any(char not in "0123456789abcdef" for char in response_digest)):
            raise CoreConflictError("core:delivery-response")
        connection = _connection(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = self._session(connection, session_id)
            state = str(row["delivery_state"])
            if state in {"ACK", "UNKNOWN"}:
                match = row["delivery_job_id"] == job_id and row["delivery_lease_token_digest"] is not None and hmac.compare_digest(str(row["delivery_lease_token_digest"]), token_digest) and ((not unknown and state == "ACK" and row["delivery_response_digest"] == response_digest) or (unknown and state == "UNKNOWN" and row["delivery_error_code"] == code))
                if not match:
                    raise CoreConflictError("core:delivery-token")
                op = _digest("delivery-finish-operation", {"session_id": session_id, "job_id": job_id, "attempt": row["delivery_attempt"], "action": "UNKNOWN" if unknown else "ACK", "token_digest": token_digest, "response_digest": response_digest, "code": code if unknown else None})
                existing = self._event(connection, op)
                if existing is None:
                    raise CoreError("core:delivery-receipt")
                connection.commit()
                return self._receipt(existing)
            if state != "INTENT" or row["delivery_job_id"] != job_id or row["delivery_lease_token_digest"] is None or not hmac.compare_digest(str(row["delivery_lease_token_digest"]), token_digest):
                raise CoreConflictError("core:delivery-token")
            now = self._owner_now(connection)
            if row["delivery_lease_until"] is None or now >= int(row["delivery_lease_until"]):
                raise CoreConflictError("core:delivery-lease-expired")
            next_state = "UNKNOWN" if unknown else "ACK"
            event_kind = "DELIVERY_RESPONSE_UNKNOWN" if unknown else "DELIVERY_ACK"
            op = _digest("delivery-finish-operation", {"session_id": session_id, "job_id": job_id, "attempt": row["delivery_attempt"], "action": "UNKNOWN" if unknown else "ACK", "token_digest": token_digest, "response_digest": response_digest, "code": code if unknown else None})
            snapshot = self._session_snapshot(row)
            snapshot.update({"delivery_state": next_state, "delivery_response_digest": response_digest, "delivery_error_code": code if unknown else None})
            material = {"session": snapshot, "job_id": job_id, "delivery_id": _digest("delivery-id", {"session_id": session_id, "job_id": job_id}), "token_digest": token_digest, ("error_code" if unknown else "response_digest"): code if unknown else response_digest}
            raw = self._append(connection, kind=event_kind, operation_id=op, subject_id=session_id, request_digest=_digest("delivery-request", {"session_id": session_id, "job_id": job_id, "attempt": row["delivery_attempt"], "action": event_kind, "token_digest": token_digest}), prior_state="INTENT", next_state=next_state, attempt=int(row["delivery_attempt"]), observed_at=now, material=material, payload_digest=_digest("delivery-response", {"job_id": job_id, "response_digest": response_digest, "code": code if unknown else None}), payload_length=0, stream_kind="DELIVERY", stream_id=material["delivery_id"], head_ref=material["delivery_id"])
            connection.execute("UPDATE core_sessions SET delivery_state=?,delivery_response_digest=?,delivery_error_code=? WHERE session_id=?", (next_state, response_digest, code if unknown else None, session_id))
            connection.commit()
            return self._receipt(raw)
        except (CoreError, CoreConflictError):
            connection.rollback()
            raise
        except sqlite3.Error:
            connection.rollback()
            raise_redacted(CoreError, "core:database")
        finally:
            connection.close()

    def logical_export(self) -> bytes:
        return independent.logical_export(self.verify())

    def support(self) -> dict[str, object]:
        result = self.verify()
        return {"schema": "mirror-core-support-v2", "artifact_count": result["artifact_count"], "session_count": result["session_count"], "slot_count": result["slot_count"], "event_count": result["event_count"], "flags": dict(FIXED_FLAGS)}


__all__ = ["CoreConfigV2", "CoreReceipt", "CoreError", "CoreConflictError", "CoreBusyError", "CoreServiceV2", "SCHEMA", "SCHEMA_VERSION", "TABLES", "ARTIFACT_KINDS", "FIXED_FLAGS"]
