"""The single six-table durable Mirror core owner.

The core stores graph and bounded raw-free projections.  It reads ingress
through the independent ingress verifier before its own write transaction;
it never copies the ingress envelope into core state.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import sqlite3
from typing import Mapping

from app.mirror import core_v2_independent as independent
from app.mirror import external_governance_approval_independent as governance
from app.mirror import external_privacy_support_approval_independent as privacy
from app.mirror import ingress_v2_independent as ingress
from app.mirror import nc_medicaid_fhir_independent as fhir
from app.mirror import nc_medicaid_fhir_profile as profile
from app.mirror import provider_trust_graph_independent as graph_independent
from app.mirror import provider_trust_graph as graph
from app.mirror.source_admission import SourceAdmissionService
from app.mirror.error_boundary import raise_redacted


SCHEMA = independent.SCHEMA
SCHEMA_VERSION = independent.SCHEMA_VERSION
TABLES = independent.TABLES
ARTIFACT_KINDS = independent.ARTIFACT_KINDS
FIXED_FLAGS = dict(independent.FIXED_FLAGS)
CASE_EDGES = {
    "OPEN": {"RESPONSIBILITY"},
    "RESPONSIBILITY": {"REMEDIATION"},
    "REMEDIATION": {"RETEST"},
    "RETEST": {"PERSISTENCE"},
    "PERSISTENCE": {"RESOLVED", "SUPERSEDED"},
}


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
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "database_id": self.database_id,
            "chain_id": self.chain_id,
            "ingress_database_id": self.ingress_database_id,
            "runtime_profile_digest": self.runtime_profile_digest,
            "governance_policy_digest": self.governance_policy_digest,
            "privacy_policy_digest": self.privacy_policy_digest,
            "max_sessions": self.max_sessions,
            "max_slots_per_session": self.max_slots_per_session,
            "cadence_seconds": self.cadence_seconds,
            "max_delivery_attempts": self.max_delivery_attempts,
            "flags": dict(FIXED_FLAGS),
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
    return tuple(row[0] for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall())


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
                    ingress_watermark INTEGER NOT NULL,
                    session_count INTEGER NOT NULL
                );
                CREATE TABLE core_artifacts(
                    artifact_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    raw BLOB NOT NULL,
                    profile_digest TEXT NOT NULL,
                    source_artifact_id TEXT,
                    predecessor_id TEXT,
                    sequence INTEGER NOT NULL UNIQUE,
                    current_state TEXT NOT NULL,
                    created_event_sequence INTEGER NOT NULL
                );
                CREATE TABLE core_heads(
                    stream_kind TEXT NOT NULL,
                    stream_id TEXT NOT NULL,
                    artifact_id TEXT NOT NULL UNIQUE,
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
                    operation_id TEXT NOT NULL UNIQUE,
                    head_root TEXT NOT NULL,
                    last_slot INTEGER NOT NULL,
                    lease_until INTEGER,
                    delivery_state TEXT NOT NULL,
                    delivery_job_id TEXT,
                    delivery_attempt INTEGER NOT NULL,
                    delivery_lease_token TEXT,
                    delivery_lease_until INTEGER,
                    delivery_response_digest TEXT,
                    delivery_error_code TEXT
                );
                CREATE TABLE core_slots(
                    session_id TEXT NOT NULL,
                    slot_number INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    attempt INTEGER NOT NULL,
                    lease_token TEXT,
                    lease_until INTEGER,
                    result_digest TEXT,
                    result_raw BLOB,
                    PRIMARY KEY(session_id,slot_number),
                    FOREIGN KEY(session_id) REFERENCES core_sessions(session_id)
                );
                CREATE TABLE core_events(
                    sequence INTEGER PRIMARY KEY,
                    event_id TEXT NOT NULL UNIQUE,
                    event_kind TEXT NOT NULL,
                    database_id TEXT NOT NULL,
                    chain_id TEXT NOT NULL,
                    stream_kind TEXT NOT NULL,
                    stream_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    prior_state TEXT NOT NULL,
                    next_state TEXT NOT NULL,
                    attempt INTEGER NOT NULL,
                    before_root TEXT NOT NULL,
                    after_root TEXT NOT NULL,
                    stream_before_root TEXT NOT NULL,
                    stream_after_root TEXT NOT NULL,
                    material_digest TEXT NOT NULL,
                    payload_digest TEXT NOT NULL,
                    payload_length INTEGER NOT NULL,
                    event_raw BLOB NOT NULL,
                    receipt_digest TEXT NOT NULL
                );
                CREATE INDEX core_heads_stream_idx ON core_heads(stream_kind,stream_id);
                CREATE INDEX core_sessions_state_idx ON core_sessions(state,lease_until,session_id);
                CREATE INDEX core_delivery_state_idx ON core_sessions(delivery_state,delivery_lease_until,delivery_job_id);
                CREATE INDEX core_slots_state_idx ON core_slots(state,lease_until,session_id);
                CREATE UNIQUE INDEX core_events_chain_idx ON core_events(chain_id,sequence);
                CREATE INDEX core_events_operation_idx ON core_events(operation_id,event_kind);
                CREATE INDEX core_artifacts_kind_idx ON core_artifacts(kind,sequence);
                """
            )
            connection.execute(
                "INSERT INTO core_meta VALUES(1,?,?,?,?,?,?,?,?,?,?)",
                (
                    SCHEMA, SCHEMA_VERSION, config.database_id, config.chain_id,
                    config.digest, 0, independent.GENESIS_ROOT,
                    config.ingress_database_id, 0, 0,
                ),
            )
        else:
            row = connection.execute("SELECT * FROM core_meta").fetchone()
            if row is None or row["database_id"] != config.database_id or row["chain_id"] != config.chain_id or row["config_digest"] != config.digest or row["ingress_database_id"] != config.ingress_database_id:
                raise CoreError("core:identity")
    except CoreError:
        raise
    except sqlite3.Error:
        raise_redacted(CoreError, "core:database-initialize")
    finally:
        connection.close()


class CoreServiceV2:
    def __init__(self, path: str | Path, config: CoreConfigV2) -> None:
        self.path = Path(path)
        self.config = config
        _init(self.path, config)

    def verify(self, *, ingress_path: str | Path | None = None) -> dict[str, object]:
        return independent.verify_database(
            self.path,
            expected_database_id=self.config.database_id,
            expected_config_digest=self.config.digest,
            ingress_path=ingress_path,
        )

    def _append(
        self,
        connection: sqlite3.Connection,
        *,
        kind: str,
        operation_id: str,
        subject_id: str,
        request_digest: str,
        prior_state: str,
        next_state: str,
        attempt: int,
        material: Mapping[str, object],
        payload_digest: str,
        payload_length: int,
        stream_kind: str | None = None,
        stream_id: str | None = None,
        head_ref: str | None = None,
        ingress_watermark: int = 0,
    ) -> bytes:
        meta = connection.execute("SELECT * FROM core_meta WHERE meta_id=1").fetchone()
        if meta is None:
            raise CoreError("core:meta")
        sequence = int(meta["sequence"]) + 1
        stream_kind = stream_kind or ("ARTIFACT" if kind == "ARTIFACT" else "SESSION" if subject_id else "OWNER")
        stream_id = stream_id or subject_id
        stream_head = connection.execute(
            "SELECT head_root FROM core_heads WHERE stream_kind=? AND stream_id=?",
            (stream_kind, stream_id),
        ).fetchone()
        stream_before_root = str(stream_head[0]) if stream_head is not None else independent.GENESIS_ROOT
        body = {
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
            "subject_id": subject_id,
            "request_digest": request_digest,
            "prior_state": prior_state,
            "next_state": next_state,
            "attempt": attempt,
            "before_root": meta["head_root"],
            "after_root": "",
            "stream_before_root": stream_before_root,
            "stream_after_root": "",
            "material_digest": _digest("material", material),
            "payload_digest": payload_digest,
            "payload_length": payload_length,
        }
        body["event_id"] = _digest("event-id", {key: body[key] for key in body if key not in {"event_id", "after_root", "stream_after_root"}})
        body["after_root"] = independent._event_root(
            sequence, str(meta["head_root"]), str(body["event_id"]), kind,
            subject_id, next_state, str(body["material_digest"]), stream_kind, stream_id,
        )
        body["stream_after_root"] = independent._stream_root(
            sequence, stream_before_root, str(body["event_id"]), stream_kind, stream_id,
            next_state, str(body["material_digest"]),
        )
        raw = _canonical(body)
        connection.execute(
            "INSERT INTO core_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                sequence, body["event_id"], kind, self.config.database_id,
                self.config.chain_id, stream_kind, stream_id, operation_id, subject_id, request_digest,
                prior_state, next_state, attempt, body["before_root"],
                body["after_root"], body["stream_before_root"], body["stream_after_root"], body["material_digest"], payload_digest,
                payload_length, raw, _raw_digest("receipt", raw),
            ),
        )
        connection.execute(
            "UPDATE core_meta SET sequence=?,head_root=?,ingress_watermark=MAX(ingress_watermark,?) WHERE meta_id=1",
            (sequence, body["after_root"], ingress_watermark),
        )
        connection.execute(
            "INSERT INTO core_heads(stream_kind,stream_id,artifact_id,head_root,event_sequence) VALUES(?,?,?,?,?) ON CONFLICT(stream_kind,stream_id) DO UPDATE SET artifact_id=excluded.artifact_id,head_root=excluded.head_root,event_sequence=excluded.event_sequence",
            (stream_kind, stream_id, head_ref or stream_id, body["stream_after_root"], sequence),
        )
        return raw

    def _receipt(self, raw: bytes) -> CoreReceipt:
        value = json.loads(raw.decode("ascii"))
        return CoreReceipt(
            raw=raw, operation_id=str(value["operation_id"]),
            event_id=str(value["event_id"]), subject_id=str(value["subject_id"]),
            next_state=str(value["next_state"]), sequence=int(value["sequence"]),
            after_root=str(value["after_root"]),
        )

    def _admit_artifact(
        self,
        connection: sqlite3.Connection,
        *,
        kind: str,
        raw: bytes,
        profile_digest: str,
        predecessor_id: str | None,
        source_artifact_id: str | None,
        operation_id: str,
        request_digest: str,
        state: str,
        ingress_watermark: int = 0,
    ) -> tuple[str, bytes]:
        if kind not in ARTIFACT_KINDS:
            raise CoreConflictError("core:artifact-kind")
        material = {
            "kind": kind,
            "raw": _raw_digest("artifact-bytes", raw),
            "predecessor_id": predecessor_id,
            "sequence": connection.execute("SELECT sequence FROM core_meta WHERE meta_id=1").fetchone()[0] + 1,
        }
        artifact_id = _digest("artifact-row-id", material)
        existing = connection.execute("SELECT * FROM core_artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()
        if existing is not None:
            if bytes(existing["raw"]) != raw:
                raise CoreConflictError("core:artifact-conflict")
            event = connection.execute("SELECT event_raw FROM core_events WHERE operation_id=? AND event_kind='ARTIFACT' AND payload_digest=?", (operation_id, artifact_id)).fetchone()
            if event is None:
                raise CoreError("core:artifact-receipt")
            return artifact_id, bytes(event[0])
        sequence = int(connection.execute("SELECT sequence FROM core_meta WHERE meta_id=1").fetchone()[0]) + 1
        connection.execute(
            "INSERT INTO core_artifacts VALUES(?,?,?,?,?,?,?,?,?)",
            (artifact_id, kind, raw, profile_digest, source_artifact_id, predecessor_id, sequence, state, 0),
        )
        event_raw = self._append(
            connection, kind="ARTIFACT", operation_id=operation_id,
            subject_id=artifact_id, request_digest=request_digest,
            prior_state="NONE", next_state=kind, attempt=0, material=material,
            payload_digest=artifact_id, payload_length=len(raw),
            ingress_watermark=ingress_watermark,
            stream_kind="ARTIFACT", stream_id=kind, head_ref=artifact_id,
        )
        event_value = json.loads(event_raw.decode("ascii"))
        connection.execute(
            "UPDATE core_artifacts SET created_event_sequence=? WHERE artifact_id=?",
            (event_value["sequence"], artifact_id),
        )
        return artifact_id, event_raw

    def ingest_source(self, ingress_path: str | Path, artifact_id: str) -> dict[str, object]:
        try:
            ing = ingress.read_artifact(ingress_path, artifact_id)
            raw_envelope = ing["raw"]
            result = fhir.verify_bytes(raw_envelope)
            admission = SourceAdmissionService(
                profile.NC_MEDICAID_GRAPH_PROFILE,
                fhir.NcMedicaidFhirVerifier(),
            ).admit(raw_envelope)
            graph_raw = bytes(admission.graph_artifact)
            graph_result = graph_independent.verify_bytes_v2(
                graph_raw, dict(profile.NC_MEDICAID_GRAPH_PROFILE_REGISTRY)
            )
            if graph_result.get("accepted") is not True:
                raise CoreError("core:graph-reject")
            graph_artifact_digest = _raw_digest("graph-artifact", graph_raw)
        except CoreError:
            raise
        except Exception:
            raise_redacted(CoreError, "core:ingress-reject")
        connection = _connection(self.path)
        ingress_watermark = int(ing["event_sequence"])
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute("SELECT * FROM core_heads WHERE stream_kind='ARTIFACT' AND stream_id='SOURCE_OBSERVATION'").fetchone()
            predecessor_id = current["artifact_id"] if current is not None else None
            prior = None
            if predecessor_id is not None:
                prior_row = connection.execute("SELECT raw FROM core_artifacts WHERE artifact_id=?", (predecessor_id,)).fetchone()
                if prior_row is None:
                    raise CoreError("core:head")
                prior = independent._parse(bytes(prior_row[0]))
            existing_source = connection.execute(
                "SELECT * FROM core_artifacts WHERE kind='SOURCE_OBSERVATION' AND source_artifact_id=? ORDER BY sequence DESC LIMIT 1",
                (artifact_id,),
            ).fetchone()
            if existing_source is not None:
                existing_event = connection.execute(
                    "SELECT event_raw FROM core_events WHERE event_kind='ARTIFACT' AND payload_digest=? ORDER BY sequence DESC LIMIT 1",
                    (existing_source["artifact_id"],),
                ).fetchone()
                if existing_event is None:
                    raise CoreError("core:source-receipt")
                existing_value = independent._parse(bytes(existing_source["raw"]))
                if existing_value.get("envelope_digest") != ing["envelope_digest"] or existing_value.get("content_root") != ing["content_root"]:
                    raise CoreConflictError("core:source-conflict")
                connection.commit()
                return {
                    "source_artifact_id": str(existing_source["artifact_id"]),
                    "graph_artifact_id": str(existing_value["graph_artifact_id"]),
                    "reconciliation_artifact_id": self._find_reconciliation(connection, str(existing_source["artifact_id"])),
                    "observation_status": existing_value["observation_status"],
                    "receipt": self._receipt(bytes(existing_event[0])),
                }
            chronology = "INITIAL" if prior is None else ("EQUAL" if prior.get("observation_time") == ing["observation_time"] else "ADVANCING")
            if prior is None:
                status = "OBSERVED_NEW"
            elif ing["source_status"] != "COMPLETE":
                status = "INCOMPLETE"
            elif prior.get("content_root") == ing["content_root"]:
                status = "OBSERVED_CONTINUED"
            else:
                status = "OBSERVED_CHANGED"
            graph_body = _canonical({
                "schema": "mirror-core-graph-v2",
                "schema_version": 2,
                "kind": "GRAPH",
                "artifact_id": str(graph_result["report_id"]),
                "graph": json.loads(graph_raw.decode("ascii")),
                "graph_digest": graph_artifact_digest,
                "flags": dict(FIXED_FLAGS),
            })
            graph_id, _ = self._admit_artifact(
                connection, kind="GRAPH", raw=graph_body,
                profile_digest=profile.NC_MEDICAID_GRAPH_PROFILE.profile_digest,
                predecessor_id=None, source_artifact_id=None,
                operation_id=_digest("graph-operation", {"graph_id": str(graph_result["report_id"]), "ingress_artifact_id": artifact_id}),
                request_digest=_digest("graph-request", {"ingress_artifact_id": artifact_id}),
                state="GRAPH", ingress_watermark=ingress_watermark,
            )
            source_body = {
                "schema": "mirror-core-source-observation-v2",
                "schema_version": 2,
                "kind": "SOURCE_OBSERVATION",
                "artifact_id": "",
                "ingress_database_id": self.config.ingress_database_id,
                "ingress_artifact_id": artifact_id,
                "ingress_event_sequence": ing["event_sequence"],
                "ingress_head_root": ing["head_root"],
                "envelope_id": ing["envelope_id"],
                "envelope_digest": ing["envelope_digest"],
                "snapshot_id": ing["snapshot_id"],
                "snapshot_root": ing["snapshot_root"],
                "content_root": ing["content_root"],
                "profile_id": ing["profile_id"],
                "profile_version": ing["profile_version"],
                "profile_digest": ing["profile_digest"],
                "source_status": ing["source_status"],
                "freshness": ing["freshness"],
                "page_count": ing["page_count"],
                "resource_count": ing["resource_count"],
                "graph_artifact_id": graph_id,
                "graph_artifact_digest": graph_artifact_digest,
                "observation_status": status,
                "chronology": chronology,
                "flags": dict(FIXED_FLAGS),
            }
            source_body["artifact_id"] = _digest(
                "source-artifact-id",
                {key: source_body[key] for key in source_body if key not in {"artifact_id", "flags"}},
            )
            source_raw = _canonical(source_body)
            source_id, source_event = self._admit_artifact(
                connection, kind="SOURCE_OBSERVATION", raw=source_raw,
                profile_digest=ing["profile_digest"], predecessor_id=predecessor_id,
                source_artifact_id=artifact_id,
                operation_id=_digest("source-operation", {"ingress_artifact_id": artifact_id}),
                request_digest=_digest("source-request", {"ingress_artifact_id": artifact_id}),
                state=status, ingress_watermark=ingress_watermark,
            )
            rec_body = {
                "schema": "mirror-core-reconciliation-v2",
                "schema_version": 2,
                "kind": "RECONCILIATION",
                "artifact_id": "",
                "current_source_artifact_id": source_id,
                "prior_source_artifact_id": predecessor_id,
                "current_content_root": ing["content_root"],
                "prior_content_root": prior.get("content_root") if prior else None,
                "source_status": ing["source_status"],
                "observation_status": status,
                "chronology": chronology,
                "linkage": "UNCHANGED" if prior and prior.get("graph_artifact_digest") == graph_artifact_digest else "LINKED",
                "flags": dict(FIXED_FLAGS),
            }
            rec_body["artifact_id"] = _digest("reconciliation-id", {key: rec_body[key] for key in rec_body if key != "artifact_id"})
            rec_raw = _canonical(rec_body)
            rec_id, rec_event = self._admit_artifact(
                connection, kind="RECONCILIATION", raw=rec_raw,
                profile_digest=ing["profile_digest"], predecessor_id=self._find_reconciliation(connection, predecessor_id) if predecessor_id else None,
                source_artifact_id=source_id,
                operation_id=_digest("reconciliation-operation", {"source_artifact_id": source_id}),
                request_digest=_digest("reconciliation-request", {"source_artifact_id": source_id}),
                state=status, ingress_watermark=ingress_watermark,
            )
            connection.execute(
                "UPDATE core_meta SET ingress_watermark=MAX(ingress_watermark,?) WHERE meta_id=1",
                (ing["event_sequence"],),
            )
            connection.commit()
            return {
                "source_artifact_id": source_id,
                "graph_artifact_id": graph_id,
                "reconciliation_artifact_id": rec_id,
                "observation_status": status,
                "receipt": self._receipt(rec_event),
            }
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
        row = connection.execute("SELECT artifact_id FROM core_artifacts WHERE kind='RECONCILIATION' AND source_artifact_id=?", (source_id,)).fetchone()
        return str(row[0]) if row else None

    def _admit_approval(self, raw: bytes, *, kind: str, profile_digest: str, decision: str) -> str:
        value = independent._parse(raw)
        if value.get("kind") != kind or value.get("flags") != FIXED_FLAGS:
            raise CoreError("core:approval")
        if kind == "GOVERNANCE" and value.get("decision") != decision:
            raise CoreError("core:approval")
        if kind == "PRIVACY" and value.get("privacy_decision") != decision:
            raise CoreError("core:approval")
        connection = _connection(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            head = connection.execute("SELECT artifact_id FROM core_heads WHERE stream_kind='ARTIFACT' AND stream_id=?", (kind,)).fetchone()
            predecessor = str(head[0]) if head else None
            artifact_id, event = self._admit_artifact(
                connection, kind=kind, raw=raw, profile_digest=profile_digest,
                predecessor_id=predecessor, source_artifact_id=None,
                operation_id=_digest("approval-operation", {"kind": kind, "raw": _raw_digest("approval", raw)}),
                request_digest=_digest("approval-request", {"kind": kind, "raw": _raw_digest("approval", raw)}),
                state=decision,
            )
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
            projection = {
                "schema": "mirror-core-governance-v2", "schema_version": 2, "kind": "GOVERNANCE",
                "artifact_id": value["artifact_id"], "decision": assertion["decision"],
                "policy_digest": value["policy_digest"], "evidence_digest": assertion["evidence_sha3_512"],
                "verifier_id": assertion["verifier_id"], "verifier_epoch": assertion["verifier_epoch"],
                "valid_from": assertion["valid_from"], "valid_until": assertion["valid_until"],
                "flags": dict(FIXED_FLAGS),
            }
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
            projection = {
                "schema": "mirror-core-privacy-v2", "schema_version": 2, "kind": "PRIVACY",
                "artifact_id": value["artifact_id"], "privacy_decision": assertion["privacy_decision"],
                "support_decision": assertion["support_decision"], "policy_digest": value["policy_digest"],
                "evidence_digest": assertion["evidence_sha3_512"], "verifier_id": assertion["verifier_id"],
                "verifier_epoch": assertion["verifier_epoch"], "valid_from": assertion["valid_from"],
                "valid_until": assertion["valid_until"], "flags": dict(FIXED_FLAGS),
            }
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
            existing = connection.execute("SELECT artifact_id FROM core_artifacts WHERE kind='CASE' AND source_artifact_id=? ORDER BY sequence DESC LIMIT 1", (reconciliation["current_source_artifact_id"],)).fetchone()
            if existing is not None:
                return str(existing[0])
            body = {
                "schema": "mirror-core-case-v2", "schema_version": 2, "kind": "CASE", "artifact_id": "",
                "case_id": _digest("case-id", {"reconciliation_artifact_id": reconciliation_artifact_id, "source_artifact_id": reconciliation["current_source_artifact_id"]}),
                "reconciliation_artifact_id": reconciliation_artifact_id,
                "source_artifact_id": reconciliation["current_source_artifact_id"], "state": "OPEN",
                "responsibility": "UNKNOWN", "remediation": "UNOBSERVED", "retest": "UNREQUESTED",
                "parity": parity, "reason": reason, "flags": dict(FIXED_FLAGS),
            }
            body["artifact_id"] = _digest("case-artifact", {key: body[key] for key in body if key != "artifact_id"})
            raw = _canonical(body)
            artifact_id, _ = self._admit_artifact(
                connection, kind="CASE", raw=raw, profile_digest=self.config.runtime_profile_digest,
                predecessor_id=None, source_artifact_id=body["source_artifact_id"],
                operation_id=_digest("case-operation", {"case_id": body["case_id"]}),
                request_digest=_digest("case-request", {"reconciliation_artifact_id": reconciliation_artifact_id}), state="OPEN",
            )
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

    def advance_case(
        self,
        case_artifact_id: str,
        *,
        next_state: str,
        responsibility: str | None = None,
        remediation: str | None = None,
        retest: str | None = None,
        parity: str | None = None,
    ) -> CoreReceipt:
        """Append one bounded discrepancy observation to the immutable case chain."""
        if type(case_artifact_id) is not str or len(case_artifact_id) != 128 or any(char not in "0123456789abcdef" for char in case_artifact_id):
            raise CoreConflictError("core:case-input")
        if next_state not in CASE_EDGES and next_state not in {"RESOLVED", "SUPERSEDED"}:
            raise CoreConflictError("core:case-transition")
        supplied = {
            "responsibility": responsibility,
            "remediation": remediation,
            "retest": retest,
            "parity": parity,
        }
        operation_id = _digest(
            "case-transition-operation",
            {"case_artifact_id": case_artifact_id, "next_state": next_state, **supplied},
        )
        connection = _connection(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            prior_event = connection.execute(
                "SELECT event_raw FROM core_events WHERE operation_id=? AND event_kind='ARTIFACT'",
                (operation_id,),
            ).fetchone()
            if prior_event is not None:
                connection.commit()
                return self._receipt(bytes(prior_event[0]))
            head = connection.execute(
                "SELECT artifact_id FROM core_heads WHERE stream_kind='ARTIFACT' AND stream_id='CASE'"
            ).fetchone()
            if head is None or head[0] != case_artifact_id:
                raise CoreConflictError("core:case-head")
            prior_row = connection.execute(
                "SELECT * FROM core_artifacts WHERE artifact_id=? AND kind='CASE'",
                (case_artifact_id,),
            ).fetchone()
            if prior_row is None:
                raise CoreConflictError("core:case-missing")
            prior = independent._parse(bytes(prior_row["raw"]))
            prior_state = str(prior["state"])
            if next_state not in CASE_EDGES.get(prior_state, set()):
                raise CoreConflictError("core:case-transition")
            allowed_values = {
                "responsibility": {"UNKNOWN", "SHARED", "STATE_SOURCE", "PLAN_OR_PROVIDER", "RIGHTRAIL_PROCESSING"},
                "remediation": {"UNOBSERVED", "PROPOSED", "ASSERTED", "VERIFIED"},
                "retest": {"UNREQUESTED", "REQUESTED", "EXECUTED"},
                "parity": {"UNKNOWN", "PARTIAL", "MATCHED", "DIVERGENT"},
            }
            for key, value in supplied.items():
                if value is not None and value not in allowed_values[key]:
                    raise CoreConflictError("core:case-value")
            required_field = {
                "RESPONSIBILITY": "responsibility",
                "REMEDIATION": "remediation",
                "RETEST": "retest",
                "PERSISTENCE": "parity",
            }.get(next_state)
            if required_field is None:
                if any(value is not None for value in supplied.values()):
                    raise CoreConflictError("core:case-value")
            elif supplied[required_field] is None:
                raise CoreConflictError("core:case-value")
            if next_state == "RETEST" and prior["remediation"] == "UNOBSERVED":
                raise CoreConflictError("core:case-remediation")
            if next_state == "PERSISTENCE" and prior["retest"] != "EXECUTED":
                raise CoreConflictError("core:case-retest")
            if next_state == "RESOLVED" and (prior["parity"] != "MATCHED" or prior["remediation"] != "VERIFIED" or prior["retest"] != "EXECUTED"):
                raise CoreConflictError("core:case-resolve")
            if next_state == "SUPERSEDED" and prior_state != "PERSISTENCE":
                raise CoreConflictError("core:case-supersede")
            body = dict(prior)
            body["state"] = next_state
            if required_field is not None:
                body[required_field] = supplied[required_field]
            body["artifact_id"] = ""
            body["artifact_id"] = _digest("case-artifact", {key: body[key] for key in body if key != "artifact_id"})
            raw = _canonical(body)
            artifact_id, event_raw = self._admit_artifact(
                connection,
                kind="CASE",
                raw=raw,
                profile_digest=self.config.runtime_profile_digest,
                predecessor_id=case_artifact_id,
                source_artifact_id=str(prior["source_artifact_id"]),
                operation_id=operation_id,
                request_digest=_digest("case-transition-request", {"case_artifact_id": case_artifact_id, "next_state": next_state, **supplied}),
                state=next_state,
            )
            if not artifact_id or event_raw is None:
                raise CoreError("core:case-receipt")
            connection.commit()
            return self._receipt(event_raw)
        except (CoreConflictError, CoreError):
            connection.rollback()
            raise
        except sqlite3.Error:
            connection.rollback()
            raise_redacted(CoreError, "core:database")
        finally:
            connection.close()

    def open_session(self, *, source_artifact_id: str, governance_artifact_id: str, privacy_artifact_id: str, now: int) -> CoreReceipt:
        connection = _connection(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            source_head = connection.execute("SELECT artifact_id FROM core_heads WHERE stream_kind='ARTIFACT' AND stream_id='SOURCE_OBSERVATION'").fetchone()
            gov_head = connection.execute("SELECT artifact_id FROM core_heads WHERE stream_kind='ARTIFACT' AND stream_id='GOVERNANCE'").fetchone()
            privacy_head = connection.execute("SELECT artifact_id FROM core_heads WHERE stream_kind='ARTIFACT' AND stream_id='PRIVACY'").fetchone()
            if not source_head or source_head[0] != source_artifact_id or not gov_head or gov_head[0] != governance_artifact_id or not privacy_head or privacy_head[0] != privacy_artifact_id:
                raise CoreConflictError("core:authority-head")
            gov_raw = connection.execute("SELECT raw FROM core_artifacts WHERE artifact_id=?", (governance_artifact_id,)).fetchone()[0]
            privacy_raw = connection.execute("SELECT raw FROM core_artifacts WHERE artifact_id=?", (privacy_artifact_id,)).fetchone()[0]
            gov = independent._parse(bytes(gov_raw))
            pval = independent._parse(bytes(privacy_raw))
            if gov.get("decision") != "GRANTED" or pval.get("privacy_decision") != "GRANTED" or pval.get("support_decision") != "GRANTED":
                raise CoreConflictError("core:authority-negative")
            session_id = _digest("session-id", {"source": source_artifact_id, "governance": governance_artifact_id, "privacy": privacy_artifact_id, "config": self.config.digest})
            operation_id = _digest("session-operation", {"session_id": session_id, "action": "OPEN"})
            existing = connection.execute("SELECT * FROM core_sessions WHERE session_id=?", (session_id,)).fetchone()
            if existing is not None:
                event = connection.execute("SELECT event_raw FROM core_events WHERE operation_id=?", (operation_id,)).fetchone()
                if event is None:
                    raise CoreError("core:session-receipt")
                connection.commit()
                return self._receipt(bytes(event[0]))
            meta = connection.execute("SELECT session_count FROM core_meta WHERE meta_id=1").fetchone()
            if meta is None or int(meta[0]) >= self.config.max_sessions:
                raise CoreConflictError("core:capacity")
            connection.execute(
                "INSERT INTO core_sessions(session_id,state,source_artifact_id,governance_artifact_id,privacy_artifact_id,operation_id,head_root,last_slot,lease_until,delivery_state,delivery_job_id,delivery_attempt,delivery_lease_token,delivery_lease_until,delivery_response_digest,delivery_error_code) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (session_id, "OPEN", source_artifact_id, governance_artifact_id, privacy_artifact_id, operation_id, "", -1, None, "DUE", None, 0, None, None, None, None),
            )
            connection.execute("UPDATE core_meta SET session_count=session_count+1 WHERE meta_id=1")
            raw = self._append(
                connection, kind="SESSION_OPEN", operation_id=operation_id,
                subject_id=session_id, request_digest=_digest("session-request", {"session_id": session_id}),
                prior_state="NONE", next_state="OPEN", attempt=0,
                material={"session_id": session_id, "source_artifact_id": source_artifact_id, "observed_at": now},
                payload_digest=source_artifact_id, payload_length=0,
            )
            connection.execute("UPDATE core_sessions SET head_root=? WHERE session_id=?", (json.loads(raw.decode("ascii"))["stream_after_root"], session_id))
            connection.commit()
            return self._receipt(raw)
        except (CoreConflictError, CoreError):
            connection.rollback()
            raise
        except sqlite3.Error:
            connection.rollback()
            raise_redacted(CoreError, "core:database")
        finally:
            connection.close()

    def _session(self, connection: sqlite3.Connection, session_id: str) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM core_sessions WHERE session_id=?", (session_id,)).fetchone()
        if row is None:
            raise CoreConflictError("core:session-missing")
        return row

    def start_session(self, session_id: str) -> CoreReceipt:
        connection = _connection(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = self._session(connection, session_id)
            if row["state"] != "OPEN":
                if row["state"] == "RUNNING":
                    event = connection.execute("SELECT event_raw FROM core_events WHERE subject_id=? AND event_kind='SESSION_START'", (session_id,)).fetchone()
                    if event:
                        connection.commit()
                        return self._receipt(bytes(event[0]))
                raise CoreConflictError("core:session-state")
            operation_id = _digest("session-operation", {"session_id": session_id, "action": "START"})
            raw = self._append(
                connection, kind="SESSION_START", operation_id=operation_id,
                subject_id=session_id, request_digest=_digest("session-request", {"session_id": session_id, "action": "START"}),
                prior_state="OPEN", next_state="RUNNING", attempt=0,
                material={"session_id": session_id, "action": "START"},
                payload_digest=session_id, payload_length=0,
            )
            connection.execute("UPDATE core_sessions SET state=?,head_root=? WHERE session_id=?", ("RUNNING", json.loads(raw.decode("ascii"))["stream_after_root"], session_id))
            connection.commit()
            return self._receipt(raw)
        except (CoreConflictError, CoreError):
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
        connection = _connection(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            session = self._session(connection, session_id)
            if session["state"] != "RUNNING":
                raise CoreConflictError("core:session-state")
            existing = connection.execute("SELECT * FROM core_slots WHERE session_id=? AND slot_number=?", (session_id, slot_number)).fetchone()
            observation = {
                "schema": "mirror-core-observation-v2",
                "schema_version": 2,
                "session_id": session_id,
                "slot_number": slot_number,
                "result": result,
                "counts": {"changed": counts["changed"], "observed": counts["observed"]},
                "flags": dict(FIXED_FLAGS),
            }
            observation["result_digest"] = _digest("observation", {key: observation[key] for key in observation if key != "result_digest"})
            result_raw = _canonical(observation)
            if existing is not None:
                if bytes(existing["result_raw"] or b"") != result_raw:
                    raise CoreConflictError("core:observation-conflict")
                event = connection.execute("SELECT event_raw FROM core_events WHERE payload_digest=? AND event_kind='OBSERVATION'", (observation["result_digest"],)).fetchone()
                if event is None:
                    raise CoreError("core:observation-receipt")
                connection.commit()
                return self._receipt(bytes(event[0]))
            connection.execute("INSERT INTO core_slots VALUES(?,?,?,?,?,?,?,?)", (session_id, slot_number, "OBSERVED", 0, None, None, observation["result_digest"], result_raw))
            operation_id = _digest("observation-operation", {"session_id": session_id, "slot_number": slot_number})
            raw = self._append(
                connection, kind="OBSERVATION", operation_id=operation_id,
                subject_id=session_id, request_digest=_digest("observation-request", {"session_id": session_id, "slot_number": slot_number}),
                prior_state="RUNNING", next_state="OBSERVED", attempt=0,
                material={"session_id": session_id, "slot_number": slot_number, "result_digest": observation["result_digest"]},
                payload_digest=observation["result_digest"], payload_length=len(result_raw),
            )
            connection.execute("UPDATE core_sessions SET last_slot=?,head_root=? WHERE session_id=?", (slot_number, json.loads(raw.decode("ascii"))["stream_after_root"], session_id))
            connection.commit()
            return self._receipt(raw)
        except (CoreConflictError, CoreError):
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
        connection = _connection(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = self._session(connection, session_id)
            if row["source_artifact_id"] == current_source_artifact_id:
                raise CoreConflictError("core:source-current")
            if row["state"] == "PAUSED":
                event = connection.execute("SELECT event_raw FROM core_events WHERE subject_id=? AND event_kind='SESSION_PAUSE'", (session_id,)).fetchone()
                if event:
                    connection.commit()
                    return self._receipt(bytes(event[0]))
            if row["state"] != "RUNNING":
                raise CoreConflictError("core:pause-state")
            operation_id = _digest("pause-operation", {"session_id": session_id, "reason": reason})
            raw = self._append(
                connection, kind="SESSION_PAUSE", operation_id=operation_id,
                subject_id=session_id, request_digest=_digest("pause-request", {"session_id": session_id, "reason": reason}),
                prior_state="RUNNING", next_state="PAUSED", attempt=0,
                material={"session_id": session_id, "reason": reason, "current_source_artifact_id": current_source_artifact_id},
                payload_digest=_digest("pause-reason", {"reason": reason}), payload_length=0,
            )
            connection.execute("UPDATE core_sessions SET state=?,head_root=? WHERE session_id=?", ("PAUSED", json.loads(raw.decode("ascii"))["stream_after_root"], session_id))
            connection.commit()
            return self._receipt(raw)
        except (CoreConflictError, CoreError):
            connection.rollback()
            raise
        except sqlite3.Error:
            connection.rollback()
            raise_redacted(CoreError, "core:database")
        finally:
            connection.close()

    def begin_delivery(self, session_id: str, job_id: str, *, lease_token: str, now: int) -> CoreReceipt:
        """Durably reserve a bounded read-only delivery attempt before any send."""
        if any(type(value) is not str or not value for value in (session_id, job_id, lease_token)) or type(now) is not int:
            raise CoreConflictError("core:delivery-input")
        connection = _connection(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = self._session(connection, session_id)
            state = str(row["delivery_state"])
            existing_job = row["delivery_job_id"]
            if existing_job is not None and existing_job != job_id:
                raise CoreConflictError("core:delivery-job")
            if state == "ACK":
                event = connection.execute(
                    "SELECT event_raw FROM core_events WHERE subject_id=? AND event_kind='DELIVERY_ACK' ORDER BY sequence DESC LIMIT 1",
                    (session_id,),
                ).fetchone()
                if event is None:
                    raise CoreError("core:delivery-receipt")
                connection.commit()
                return self._receipt(bytes(event[0]))
            if state == "EXHAUSTED":
                raise CoreConflictError("core:delivery-exhausted")
            attempt = int(row["delivery_attempt"])
            if state == "INTENT":
                if row["delivery_lease_until"] is not None and int(row["delivery_lease_until"]) > now:
                    event = connection.execute(
                        "SELECT event_raw FROM core_events WHERE subject_id=? AND event_kind='DELIVERY_INTENT' ORDER BY sequence DESC LIMIT 1",
                        (session_id,),
                    ).fetchone()
                    if event is None:
                        raise CoreError("core:delivery-receipt")
                    connection.commit()
                    return self._receipt(bytes(event[0]))
                if attempt >= self.config.max_delivery_attempts:
                    raise CoreConflictError("core:delivery-exhausted")
                requeue_raw = self._append(
                    connection, kind="DELIVERY_REQUEUE", operation_id=_digest("delivery-requeue", {"session_id": session_id, "job_id": job_id, "attempt": attempt}),
                    subject_id=session_id, request_digest=_digest("delivery-request", {"session_id": session_id, "job_id": job_id, "action": "REQUEUE", "attempt": attempt}),
                    prior_state="INTENT", next_state="DUE", attempt=attempt,
                    material={"session_id": session_id, "job_id": job_id, "attempt": attempt},
                    payload_digest=_digest("delivery-requeue-payload", {"job_id": job_id, "attempt": attempt}), payload_length=0,
                    stream_kind="DELIVERY", stream_id=job_id, head_ref=job_id,
                )
                connection.execute("UPDATE core_sessions SET delivery_state='DUE',delivery_lease_token=NULL,delivery_lease_until=NULL WHERE session_id=?", (session_id,))
                state = "DUE"
            if state == "UNKNOWN":
                if row["delivery_lease_until"] is not None and int(row["delivery_lease_until"]) > now:
                    raise CoreConflictError("core:delivery-lease")
                if attempt >= self.config.max_delivery_attempts:
                    raise CoreConflictError("core:delivery-exhausted")
                self._append(
                    connection, kind="DELIVERY_REQUEUE", operation_id=_digest("delivery-requeue", {"session_id": session_id, "job_id": job_id, "attempt": attempt}),
                    subject_id=session_id, request_digest=_digest("delivery-request", {"session_id": session_id, "job_id": job_id, "action": "REQUEUE", "attempt": attempt}),
                    prior_state="UNKNOWN", next_state="DUE", attempt=attempt,
                    material={"session_id": session_id, "job_id": job_id, "attempt": attempt},
                    payload_digest=_digest("delivery-requeue-payload", {"job_id": job_id, "attempt": attempt}), payload_length=0,
                    stream_kind="DELIVERY", stream_id=job_id, head_ref=job_id,
                )
                connection.execute("UPDATE core_sessions SET delivery_state='DUE',delivery_lease_token=NULL,delivery_lease_until=NULL WHERE session_id=?", (session_id,))
                state = "DUE"
            if state not in {"DUE", "NONE"}:
                raise CoreConflictError("core:delivery-state")
            attempt += 1
            if attempt > self.config.max_delivery_attempts:
                raise CoreConflictError("core:delivery-exhausted")
            lease_until = now + self.config.cadence_seconds
            operation_id = _digest("delivery-operation", {"session_id": session_id, "job_id": job_id, "attempt": attempt})
            raw = self._append(
                connection, kind="DELIVERY_INTENT", operation_id=operation_id,
                subject_id=session_id, request_digest=_digest("delivery-request", {"session_id": session_id, "job_id": job_id, "attempt": attempt}),
                prior_state=state, next_state="INTENT", attempt=attempt,
                material={"session_id": session_id, "job_id": job_id, "attempt": attempt, "lease_until": lease_until},
                payload_digest=_digest("delivery-job", {"job_id": job_id}), payload_length=0,
                stream_kind="DELIVERY", stream_id=job_id, head_ref=job_id,
            )
            connection.execute(
                "UPDATE core_sessions SET delivery_state='INTENT',delivery_job_id=?,delivery_attempt=?,delivery_lease_token=?,delivery_lease_until=?,delivery_response_digest=NULL,delivery_error_code=NULL WHERE session_id=?",
                (job_id, attempt, lease_token, lease_until, session_id),
            )
            connection.commit()
            return self._receipt(raw)
        except (CoreConflictError, CoreError):
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
        if any(type(value) is not str or not value for value in (session_id, job_id, lease_token)):
            raise CoreConflictError("core:delivery-input")
        if response_digest is not None and (len(response_digest) != 128 or any(char not in "0123456789abcdef" for char in response_digest)):
            raise CoreConflictError("core:delivery-response")
        connection = _connection(self.path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = self._session(connection, session_id)
            if row["delivery_job_id"] != job_id or row["delivery_state"] != "INTENT" or row["delivery_lease_token"] != lease_token:
                if (not unknown and row["delivery_state"] == "ACK" and row["delivery_response_digest"] == response_digest) or (unknown and row["delivery_state"] == "UNKNOWN" and row["delivery_error_code"] == code):
                    kind = "DELIVERY_RESPONSE_UNKNOWN" if unknown else "DELIVERY_ACK"
                    event = connection.execute("SELECT event_raw FROM core_events WHERE subject_id=? AND event_kind=? ORDER BY sequence DESC LIMIT 1", (session_id, kind)).fetchone()
                    if event is not None:
                        connection.commit()
                        return self._receipt(bytes(event[0]))
                raise CoreConflictError("core:delivery-token")
            kind = "DELIVERY_RESPONSE_UNKNOWN" if unknown else "DELIVERY_ACK"
            next_state = "UNKNOWN" if unknown else "ACK"
            payload = _digest("delivery-response", {"job_id": job_id, "response_digest": response_digest, "code": code if unknown else None})
            raw = self._append(
                connection, kind=kind,
                operation_id=_digest("delivery-operation", {"session_id": session_id, "job_id": job_id, "attempt": row["delivery_attempt"], "action": kind}),
                subject_id=session_id, request_digest=_digest("delivery-request", {"session_id": session_id, "job_id": job_id, "action": kind}),
                prior_state="INTENT", next_state=next_state, attempt=int(row["delivery_attempt"]),
                material={"session_id": session_id, "job_id": job_id, "attempt": row["delivery_attempt"], "response_digest": response_digest, "code": code if unknown else None},
                payload_digest=payload, payload_length=0,
                stream_kind="DELIVERY", stream_id=job_id, head_ref=job_id,
            )
            connection.execute(
                "UPDATE core_sessions SET delivery_state=?,delivery_lease_token=NULL,delivery_lease_until=NULL,delivery_response_digest=?,delivery_error_code=? WHERE session_id=?",
                (next_state, response_digest, code if unknown else None, session_id),
            )
            connection.commit()
            return self._receipt(raw)
        except (CoreConflictError, CoreError):
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
        return {
            "schema": "mirror-core-support-v2",
            "artifact_count": result["artifact_count"],
            "session_count": result["session_count"],
            "slot_count": result["slot_count"],
            "event_count": result["event_count"],
            "flags": dict(FIXED_FLAGS),
        }


__all__ = [
    "CoreConfigV2", "CoreReceipt", "CoreError", "CoreConflictError",
    "CoreBusyError", "CoreServiceV2", "SCHEMA", "SCHEMA_VERSION",
    "TABLES", "ARTIFACT_KINDS", "FIXED_FLAGS",
]
