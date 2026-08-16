"""Bounded local operational candidate for Mirror continuity artifacts.

This module is deliberately separate from the Blind Ledger clearance database.  It
stores only independently verified synthetic Provider Trust Graph and observation-only
Governance V1 lineage artifacts, including the terminal withdrawal stage.  Storage
admission is not a policy, payment, proof, or source truth decision.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any, Mapping
from types import MappingProxyType

from app.governance import provider_continuity_control_pack_independent as governance_independent
from app.governance import provider_continuity_control_pack_withdrawal_independent as withdrawal_independent
from app.mirror import provider_trust_graph_independent as graph_independent
from app.mirror import continuity_store_independent as store_independent


STORE_SCHEMA = "mirror-continuity-operational-foundation-v2"
SCHEMA_VERSION = 2
ARTIFACT_GRAPH = "PROVIDER_TRUST_GRAPH_V1"
ARTIFACT_GOVERNANCE = "PROVIDER_CONTINUITY_CONTROL_PACK_V1"
ARTIFACT_KINDS = (ARTIFACT_GRAPH, ARTIFACT_GOVERNANCE)
GENESIS_EVENT_ROOT = "GENESIS_EVENT_ROOT_V2"
NO_PRIOR = "NO_PRIOR_V2"
MAX_ARTIFACT_BYTES = 524_288
MAX_ARTIFACTS = 16
MAX_EVENTS = 32
MAX_RECEIPT_BYTES = 32_768
MAX_DB_BYTES = 64 * 1024 * 1024
MAX_WAL_BYTES = 64 * 1024 * 1024
BUSY_TIMEOUT_MS = 250
STORE_DOMAIN = "BL/MIRROR/CONTINUITY-STORE-V2/"
RECEIPT_EVENT_PLACEHOLDER = "EVENT_ROOT_PENDING_V2"
LIFECYCLE_STATUS_ABSENT = "ABSENT"
LIFECYCLE_STATUS_NOT_APPROVED = "NOT_APPROVED"
LIFECYCLE_STATUS_APPROVED = governance_independent.STAGE_APPROVED
LIFECYCLE_STATUS_WITHDRAWN = withdrawal_independent.ACTION
AUTHORITY_FLAGS = {
    "automaticControlSetId": None,
    "automatic_enforcement_eligible": False,
    "clearance_authority": False,
    "payment_authority": False,
    "economic_mutation": False,
    "production_usable": False,
    "synthetic_only": True,
    "production_source_authentication": False,
    "proofSuiteId": None,
}
FAULT_POINTS = (
    "before_transaction",
    "after_begin",
    "after_artifact_insert",
    "after_event_receipt_before_commit",
    "after_commit_before_response",
)


class ContinuityStoreError(ValueError):
    """Base class for bounded store failures."""


class ArtifactAdmissionError(ContinuityStoreError):
    pass


class StoreConflictError(ContinuityStoreError):
    pass


class StoreBusyError(ContinuityStoreError):
    pass


class InjectedFault(ContinuityStoreError):
    pass


class IndeterminateCommitError(ContinuityStoreError):
    def __init__(self, operation_id: str) -> None:
        super().__init__(f"commit:indeterminate:{operation_id}")
        self.operation_id = operation_id


class StoreSchemaError(ContinuityStoreError):
    pass


@dataclass(frozen=True)
class VerifiedArtifact:
    kind: str
    schema: str
    artifact_id: str
    payload_hash: str
    payload: bytes
    subject: str
    scope: str
    report_id: str | None
    current_stage_id: str
    transition_id: str
    stage_kind: str
    prior_artifact_id: str | None
    prior_stage_id: str | None
    authority_json: str
    profile_id: str | None = None


@dataclass(frozen=True)
class AdmissionReceipt:
    raw: bytes

    @property
    def value(self) -> dict[str, object]:
        value = json.loads(self.raw.decode("ascii"))
        if not isinstance(value, dict):
            raise StoreSchemaError("receipt:top-level")
        return value

    @property
    def operation_id(self) -> str:
        return str(self.value["operation_id"])


@dataclass(frozen=True)
class ProviderContinuityLifecycleHead:
    """Durable state-owned interpretation of the current governance-lineage head."""

    chain_id: str
    provider_graph_subject: str
    scope: str
    artifact_id: str
    stage_id: str
    stage_kind: str
    transition_id: str
    event_sequence: int
    head_root: str
    state_root: str
    status: str
    active: bool
    terminal: bool


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise ContinuityStoreError("json:noncanonical-value") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ContinuityStoreError("json:duplicate-key")
        result[key] = value
    return result


def _walk(value: object, *, depth: int = 0, count: list[int] | None = None) -> None:
    count = [0] if count is None else count
    count[0] += 1
    if count[0] > 16_384:
        raise ContinuityStoreError("json:node-cap")
    if depth > 24:
        raise ContinuityStoreError("json:depth-cap")
    if isinstance(value, float):
        raise ContinuityStoreError("json:float-forbidden")
    if isinstance(value, str) and len(value.encode("ascii", "strict")) > 512:
        raise ContinuityStoreError("json:string-cap")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ContinuityStoreError("json:key-type")
            _walk(key, depth=depth + 1, count=count)
            _walk(item, depth=depth + 1, count=count)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth=depth + 1, count=count)


def _parse_canonical(raw: bytes, *, maximum: int = MAX_ARTIFACT_BYTES) -> dict[str, object]:
    if type(raw) is not bytes or not raw:
        raise ContinuityStoreError("json:empty-or-type")
    if len(raw) > maximum:
        raise ContinuityStoreError("json:byte-cap")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(ContinuityStoreError("json:constant-forbidden")),
        )
    except ContinuityStoreError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContinuityStoreError("json:parse") from exc
    if not isinstance(value, dict):
        raise ContinuityStoreError("json:top-level")
    _walk(value)
    if _canonical(value) != raw:
        raise ContinuityStoreError("json:not-canonical")
    return value


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((STORE_DOMAIN + label + "/v2\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _payload_hash(raw: bytes) -> str:
    digest = hashlib.sha3_512()
    digest.update((STORE_DOMAIN + "CANONICAL-PAYLOAD/v2\0").encode("ascii"))
    digest.update(raw)
    return digest.hexdigest()


def _chain_id(artifact_kind: str, subject: str, scope: str, profile_id: str | None = None) -> str:
    if not all(type(value) is str and value for value in (artifact_kind, subject, scope)):
        raise StoreConflictError("chain:identity")
    if profile_id is not None and (type(profile_id) is not str or not profile_id):
        raise StoreConflictError("chain:profile")
    material: dict[str, object] = {"artifact_kind": artifact_kind, "scope": scope, "subject": subject}
    if profile_id is not None:
        material["profile_id"] = profile_id
    return _digest(
        "chain-id",
        material,
    )


def _authority_json(value: Mapping[str, object], *, kind: str) -> str:
    if kind == ARTIFACT_GRAPH:
        expected = {
            "clearance_authority": False,
            "payment_authority": False,
            "economic_mutation": False,
            "production_usable": False,
            "synthetic_only": True,
        }
        if dict(value) != expected:
            raise ArtifactAdmissionError("artifact:authority-flags")
    elif dict(value) != governance_independent.AUTHORITY_FLAGS:
        raise ArtifactAdmissionError("artifact:authority-flags")
    return _canonical(AUTHORITY_FLAGS).decode("ascii")


def _governance_prefix(value: Mapping[str, object], stage_count: int) -> tuple[bytes, dict[str, object]]:
    stages = value.get("stages")
    if not isinstance(stages, list) or len(stages) < stage_count or stage_count not in (1, 2):
        raise ArtifactAdmissionError("governance:prior-prefix")
    prefix_stages = list(stages[:stage_count])
    current = prefix_stages[-1]
    if not isinstance(current, dict):
        raise ArtifactAdmissionError("governance:prior-prefix")
    body: dict[str, object] = {
        "schema": value["schema"],
        "subject": value["subject"],
        "source_contracts": value["source_contracts"],
        "stages": prefix_stages,
        "current_stage_kind": current["stage_kind"],
        "current_stage_id": current["stage_id"],
        "chain_root": governance_independent._digest("chain-root", {"stages": prefix_stages}),
        **{key: value[key] for key in governance_independent.AUTHORITY_FLAGS},
    }
    artifact = {"artifact_id": governance_independent._digest("artifact-id", body), **body}
    raw = governance_independent._canonical(artifact)
    return raw, artifact


def verify_artifact(
    artifact_kind: str,
    raw: bytes,
    *,
    graph_profile_registry: Mapping[str, object] | None = None,
) -> VerifiedArtifact:
    """Run the matching independent verifier and normalize its exact identities."""

    if artifact_kind not in ARTIFACT_KINDS:
        raise ArtifactAdmissionError("artifact:kind")
    if type(raw) is not bytes or not raw or len(raw) > MAX_ARTIFACT_BYTES:
        raise ArtifactAdmissionError("artifact:byte-cap")
    try:
        value = _parse_canonical(raw)
    except ContinuityStoreError as exc:
        raise ArtifactAdmissionError(str(exc)) from exc
    try:
        if artifact_kind == ARTIFACT_GRAPH:
            if value.get("schema") == graph_independent.SCHEMA_V2:
                result = graph_independent.verify_bytes_v2(raw, graph_profile_registry or {})
            else:
                result = graph_independent.verify_bytes(raw)
        elif value.get("schema") == withdrawal_independent.SCHEMA:
            result = withdrawal_independent.verify_bytes(raw)
        else:
            result = governance_independent.verify_bytes(raw)
    except Exception as exc:
        raise ArtifactAdmissionError(f"artifact:independent-reject:{type(exc).__name__}") from exc
    payload_hash = _payload_hash(raw)
    try:
        if artifact_kind == ARTIFACT_GRAPH:
            subject = value["subject"]
            snapshot = value["observation_snapshot"]
            transition = value["transition"]
            report = value["report"]
            identity = report["identity_material"]
            if not isinstance(subject, dict) or not isinstance(snapshot, dict) or not isinstance(transition, dict) or not isinstance(report, dict) or not isinstance(identity, dict):
                raise ArtifactAdmissionError("artifact:graph-shape")
            artifact_id = str(report["report_id"])
            report_id = artifact_id
            current_stage_id = str(snapshot["snapshot_id"])
            transition_id = str(transition["transition_id"])
            stage_kind = str(transition["transition_kind"])
            prior_artifact_id = identity["prior_report_id"]
            prior_stage_id = identity["prior_snapshot_id"]
            schema = str(value["schema"])
            subject_id = str(subject["provider_graph_subject"])
            scope = str(subject["scope"])
            authority_json = _authority_json(value["authority"], kind=artifact_kind)
            profile_id = None
            if schema == graph_independent.SCHEMA_V2:
                profile_value = graph_independent._expect_keys(value.get("profile"), graph_independent.PROFILE_KEYS, "artifact:profile")
                profile_id = profile_value["profile_id"]
        elif value.get("schema") == withdrawal_independent.SCHEMA:
            result_artifact_id = result.get("artifact_id")
            if not isinstance(result_artifact_id, str):
                raise ArtifactAdmissionError("artifact:withdrawal-id")
            artifact_id = result_artifact_id
            report_id = None
            current_stage_id = str(value["withdrawal_id"])
            transition_id = str(value["withdrawal_root"])
            stage_kind = str(value["action"])
            prior_artifact_id = str(value["approved_artifact_id"])
            prior_stage_id = str(value["approved_stage_id"])
            schema = str(value["schema"])
            subject_id = str(value["provider_graph_subject"])
            scope = str(value["scope"])
            authority_json = _authority_json(
                {key: value[key] for key in withdrawal_independent.AUTHORITY_FLAGS},
                kind=artifact_kind,
            )
        else:
            result_artifact_id = result.get("artifact_id")
            if not isinstance(result_artifact_id, str):
                raise ArtifactAdmissionError("artifact:governance-id")
            subject = value["subject"]
            stages = value["stages"]
            current_stage = stages[-1] if isinstance(stages, list) and stages else None
            if not isinstance(subject, dict) or not isinstance(stages, list) or not isinstance(current_stage, dict):
                raise ArtifactAdmissionError("artifact:governance-shape")
            artifact_id = result_artifact_id
            report_id = None
            current_stage_id = str(current_stage["stage_id"])
            transition_id = str(value["chain_root"])
            stage_kind = str(current_stage["stage_kind"])
            prior_artifact_id = None
            prior_stage_id = None
            if len(stages) > 1:
                prefix_raw, prefix = _governance_prefix(value, len(stages) - 1)
                try:
                    governance_independent.verify_bytes(prefix_raw)
                except Exception as exc:
                    raise ArtifactAdmissionError("governance:prior-prefix") from exc
                prior_artifact_id = str(prefix["artifact_id"])
                prior_stage = stages[-2]
                if not isinstance(prior_stage, dict):
                    raise ArtifactAdmissionError("governance:prior-stage")
                prior_stage_id = str(prior_stage["stage_id"])
            schema = str(value["schema"])
            subject_id = str(subject["provider_graph_subject"])
            scope = str(subject["scope"])
            authority_json = _authority_json({key: value[key] for key in governance_independent.AUTHORITY_FLAGS}, kind=artifact_kind)
        if not subject_id or not scope or not artifact_id or not current_stage_id or not transition_id:
            raise ArtifactAdmissionError("artifact:identity-empty")
        if prior_artifact_id is not None and not isinstance(prior_artifact_id, str):
            raise ArtifactAdmissionError("artifact:prior-id")
        if prior_stage_id is not None and not isinstance(prior_stage_id, str):
            raise ArtifactAdmissionError("artifact:prior-stage")
    except (KeyError, TypeError, ValueError) as exc:
        raise ArtifactAdmissionError("artifact:identity-shape") from exc
    return VerifiedArtifact(
        kind=artifact_kind,
        schema=schema,
        artifact_id=artifact_id,
        payload_hash=payload_hash,
        payload=raw,
        subject=subject_id,
        scope=scope,
        report_id=report_id,
        current_stage_id=current_stage_id,
        transition_id=transition_id,
        stage_kind=stage_kind,
        prior_artifact_id=prior_artifact_id,
        prior_stage_id=prior_stage_id,
        authority_json=authority_json,
        profile_id=profile_id if artifact_kind == ARTIFACT_GRAPH else None,
    )


def _operation_id(artifact: VerifiedArtifact, chain_id: str, expected_head: tuple[str, str]) -> str:
    return _digest(
        "operation-id",
        {
            "chain_id": chain_id,
            "artifact_kind": artifact.kind,
            "artifact_id": artifact.artifact_id,
            "payload_hash": artifact.payload_hash,
            "prior_artifact_id": artifact.prior_artifact_id or NO_PRIOR,
            "prior_stage_id": artifact.prior_stage_id or NO_PRIOR,
            "expected_head_artifact_id": expected_head[0],
            "expected_head_stage_id": expected_head[1],
        },
    )


def _receipt_hash(raw: bytes) -> str:
    """Hash receipt identity material without making event-root hashing circular."""

    value = _parse_canonical(raw, maximum=MAX_RECEIPT_BYTES)
    if "event_root" not in value:
        raise StoreSchemaError("receipt:event-root")
    identity = dict(value)
    identity.pop("event_root")
    return _digest("receipt-hash", identity)


def _event_root(material: Mapping[str, object]) -> str:
    return _digest("event-root", dict(material))


def _state_root(sequence: int, heads: list[Mapping[str, object]]) -> str:
    # A head's state_root is the result of this calculation, not an input to it.
    # Excluding it keeps the state root deterministic and non-circular.
    fields = (
        "chain_id",
        "artifact_kind",
        "artifact_id",
        "current_stage_id",
        "stage_kind",
        "transition_id",
        "event_sequence",
        "head_root",
    )
    ordered = sorted(
        ({key: item[key] for key in fields} for item in heads),
        key=lambda item: str(item["chain_id"]),
    )
    return _digest("state-root", {"event_sequence": sequence, "heads": ordered})


class ContinuityStore:
    """Small transactional SQLite candidate with immutable artifacts and events."""

    def __init__(self, path: str | Path, *, graph_profile_registry: Mapping[str, object] | None = None) -> None:
        self.path = Path(path)
        if self.path.name in {"", ".", ".."}:
            raise StoreSchemaError("database:path")
        if self.path.parent.exists() is False:
            raise StoreSchemaError("database:parent-missing")
        self.graph_profile_registry = MappingProxyType(dict(graph_profile_registry or {}))
        self._fault_point: str | None = None
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        if self.path.is_file() and self.path.stat().st_size > MAX_DB_BYTES:
            raise StoreSchemaError("database:byte-cap")
        wal_path = Path(str(self.path) + "-wal")
        if wal_path.is_file() and wal_path.stat().st_size > MAX_WAL_BYTES:
            raise StoreSchemaError("database:wal-byte-cap")
        try:
            connection = sqlite3.connect(self.path, timeout=BUSY_TIMEOUT_MS / 1000, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
            journal = connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if str(journal).lower() != "wal":
                connection.close()
                raise StoreSchemaError("sqlite:wal-required")
            connection.execute("PRAGMA synchronous=FULL")
            if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
                raise StoreSchemaError("sqlite:foreign-keys")
            if connection.execute("PRAGMA trusted_schema").fetchone()[0] != 0:
                raise StoreSchemaError("sqlite:trusted-schema")
            if connection.execute("PRAGMA synchronous").fetchone()[0] != 2:
                raise StoreSchemaError("sqlite:synchronous")
            return connection
        except sqlite3.OperationalError as exc:
            raise StoreBusyError("sqlite:open-busy") from exc

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            expected = {"store_meta", "artifacts", "operations", "receipts", "events", "heads"}
            if tables and tables != expected:
                raise StoreSchemaError("database:unknown-tables")
            if tables:
                self._validate_transaction_snapshot(connection)
            statements = (
                """
                CREATE TABLE IF NOT EXISTS store_meta(
                    key TEXT NOT NULL PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS artifacts(
                    kind TEXT NOT NULL,
                    artifact_id TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    payload BLOB NOT NULL,
                    artifact_schema TEXT NOT NULL,
                    report_id TEXT,
                    current_stage_id TEXT NOT NULL,
                    transition_id TEXT NOT NULL,
                    prior_artifact_id TEXT,
                    prior_stage_id TEXT,
                    subject TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    stage_kind TEXT NOT NULL,
                    authority_json TEXT NOT NULL,
                    PRIMARY KEY(kind, artifact_id),
                    UNIQUE(kind, payload_hash)
                )
                """,
                "CREATE INDEX IF NOT EXISTS artifacts_payload_hash_idx ON artifacts(kind, payload_hash)",
                """
                CREATE TABLE IF NOT EXISTS operations(
                    operation_id TEXT NOT NULL PRIMARY KEY,
                    chain_id TEXT NOT NULL,
                    artifact_kind TEXT NOT NULL,
                    artifact_id TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    prior_artifact_id TEXT,
                    prior_stage_id TEXT,
                    expected_head_artifact_id TEXT NOT NULL,
                    expected_head_stage_id TEXT NOT NULL,
                    event_sequence INTEGER NOT NULL UNIQUE,
                    receipt_hash TEXT NOT NULL UNIQUE,
                    commit_state_root TEXT NOT NULL,
                    FOREIGN KEY(artifact_kind, artifact_id) REFERENCES artifacts(kind, artifact_id)
                )
                """,
                "CREATE INDEX IF NOT EXISTS operations_request_idx ON operations(chain_id, artifact_kind, artifact_id, payload_hash, prior_artifact_id, prior_stage_id)",
                """
                CREATE TABLE IF NOT EXISTS receipts(
                    operation_id TEXT NOT NULL PRIMARY KEY,
                    receipt_hash TEXT NOT NULL UNIQUE,
                    receipt BLOB NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS events(
                    sequence INTEGER NOT NULL PRIMARY KEY,
                    chain_id TEXT NOT NULL,
                    previous_event_root TEXT NOT NULL,
                    event_root TEXT NOT NULL UNIQUE,
                    operation_id TEXT NOT NULL UNIQUE,
                    artifact_kind TEXT NOT NULL,
                    artifact_id TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    prior_artifact_id TEXT,
                    prior_stage_id TEXT,
                    receipt_hash TEXT NOT NULL,
                    commit_state_root TEXT NOT NULL,
                    FOREIGN KEY(operation_id) REFERENCES operations(operation_id),
                    FOREIGN KEY(artifact_kind, artifact_id) REFERENCES artifacts(kind, artifact_id),
                    FOREIGN KEY(receipt_hash) REFERENCES receipts(receipt_hash)
                )
                """,
                "CREATE INDEX IF NOT EXISTS events_chain_idx ON events(chain_id, sequence)",
                """
                CREATE TABLE IF NOT EXISTS heads(
                    chain_id TEXT NOT NULL PRIMARY KEY,
                    artifact_kind TEXT NOT NULL,
                    artifact_id TEXT NOT NULL,
                    current_stage_id TEXT NOT NULL,
                    stage_kind TEXT NOT NULL,
                    transition_id TEXT NOT NULL,
                    event_sequence INTEGER NOT NULL,
                    head_root TEXT NOT NULL,
                    state_root TEXT NOT NULL,
                    FOREIGN KEY(artifact_kind, artifact_id) REFERENCES artifacts(kind, artifact_id)
                )
                """,
            )
            for statement in statements:
                connection.execute(statement)
            row = connection.execute("SELECT value FROM store_meta WHERE key='schema_version'").fetchone()
            if row is None:
                connection.execute("INSERT INTO store_meta(key,value) VALUES('schema_version',?)", (str(SCHEMA_VERSION),))
                connection.execute("INSERT INTO store_meta(key,value) VALUES('schema',?)", (STORE_SCHEMA,))
            elif row[0] != str(SCHEMA_VERSION):
                raise StoreSchemaError("database:schema-version")
            schema_row = connection.execute("SELECT value FROM store_meta WHERE key='schema'").fetchone()
            if schema_row is None or schema_row[0] != STORE_SCHEMA:
                raise StoreSchemaError("database:schema")
            self._validate_transaction_snapshot(connection)
            connection.commit()
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            raise StoreSchemaError("database:schema-integrity") from exc
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def close(self) -> None:
        """Connections are operation-scoped; this is an explicit lifecycle no-op."""

    def _fault(self, point: str) -> None:
        if self._fault_point == point:
            self._fault_point = None
            raise InjectedFault(point)

    def _validate_transaction_snapshot(self, connection: sqlite3.Connection) -> None:
        """Validate schema and all logical rows while this transaction is held."""

        try:
            store_independent._check_sqlite_shape(connection)
            snapshot = store_independent._snapshot_from_connection(connection)
            store_independent._verify_rows(snapshot, graph_profile_registry=self.graph_profile_registry)
        except store_independent.IndependentStoreError as exc:
            raise StoreSchemaError(f"database:conformance:{exc}") from exc

    def _head(self, connection: sqlite3.Connection, chain_id: str) -> sqlite3.Row | None:
        return connection.execute("SELECT * FROM heads WHERE chain_id=?", (chain_id,)).fetchone()

    def provider_continuity_lifecycle_head(
        self,
        provider_graph_subject: str,
        scope: str,
    ) -> ProviderContinuityLifecycleHead | None:
        """Return the verified governance-lineage head used for active-status decisions.

        An approved artifact is active only while it remains the current head.  A terminal
        withdrawal is admitted as the next immutable governance-lineage stage and therefore
        makes the same approval non-active without any caller-selected status flag.
        """

        chain_id = _chain_id(ARTIFACT_GOVERNANCE, provider_graph_subject, scope)
        connection = self._connect()
        try:
            try:
                connection.execute("BEGIN")
            except sqlite3.OperationalError as exc:
                raise StoreBusyError("transaction:read-busy") from exc
            self._validate_transaction_snapshot(connection)
            row = connection.execute(
                "SELECT h.*, a.subject, a.scope FROM heads h JOIN artifacts a ON a.kind=h.artifact_kind AND a.artifact_id=h.artifact_id WHERE h.chain_id=?",
                (chain_id,),
            ).fetchone()
            if row is None:
                connection.commit()
                return None
            if row["artifact_kind"] != ARTIFACT_GOVERNANCE or (row["subject"], row["scope"]) != (provider_graph_subject, scope):
                raise StoreSchemaError("lifecycle:head-binding")
            stage_kind = str(row["stage_kind"])
            if stage_kind == governance_independent.STAGE_APPROVED:
                status, active, terminal = LIFECYCLE_STATUS_APPROVED, True, False
            elif stage_kind == withdrawal_independent.ACTION:
                status, active, terminal = LIFECYCLE_STATUS_WITHDRAWN, False, True
            elif stage_kind in (governance_independent.STAGE_CANDIDATE, governance_independent.STAGE_TESTED):
                status, active, terminal = LIFECYCLE_STATUS_NOT_APPROVED, False, False
            else:
                raise StoreSchemaError("lifecycle:stage-kind")
            result = ProviderContinuityLifecycleHead(
                chain_id=chain_id,
                provider_graph_subject=provider_graph_subject,
                scope=scope,
                artifact_id=str(row["artifact_id"]),
                stage_id=str(row["current_stage_id"]),
                stage_kind=stage_kind,
                transition_id=str(row["transition_id"]),
                event_sequence=int(row["event_sequence"]),
                head_root=str(row["head_root"]),
                state_root=str(row["state_root"]),
                status=status,
                active=active,
                terminal=terminal,
            )
            connection.commit()
            return result
        except (StoreSchemaError, StoreBusyError):
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        except sqlite3.OperationalError as exc:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise StoreBusyError("transaction:read-operational") from exc
        finally:
            connection.close()

    def _heads_for_state(self, connection: sqlite3.Connection, replacement: Mapping[str, object]) -> list[dict[str, object]]:
        rows = [dict(row) for row in connection.execute("SELECT * FROM heads ORDER BY chain_id")]
        rows = [row for row in rows if row["chain_id"] != replacement["chain_id"]]
        rows.append(dict(replacement))
        return rows

    def _artifact_matches(self, row: sqlite3.Row, artifact: VerifiedArtifact) -> bool:
        return (
            row["payload_hash"] == artifact.payload_hash
            and bytes(row["payload"]) == artifact.payload
            and row["artifact_schema"] == artifact.schema
            and row["current_stage_id"] == artifact.current_stage_id
            and row["transition_id"] == artifact.transition_id
            and row["authority_json"] == artifact.authority_json
        )

    def _insert_or_check_artifact(self, connection: sqlite3.Connection, artifact: VerifiedArtifact) -> None:
        row = connection.execute("SELECT * FROM artifacts WHERE kind=? AND artifact_id=?", (artifact.kind, artifact.artifact_id)).fetchone()
        if row is not None:
            if not self._artifact_matches(row, artifact):
                raise StoreConflictError("artifact:immutable-mismatch")
            return
        collision = connection.execute("SELECT kind,artifact_id FROM artifacts WHERE kind=? AND payload_hash=?", (artifact.kind, artifact.payload_hash)).fetchone()
        if collision is not None:
            raise StoreConflictError("artifact:hash-identity-conflict")
        if connection.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0] >= MAX_ARTIFACTS:
            raise StoreConflictError("artifact:count-cap")
        connection.execute(
            "INSERT INTO artifacts(kind,artifact_id,payload_hash,payload,artifact_schema,report_id,current_stage_id,transition_id,prior_artifact_id,prior_stage_id,subject,scope,stage_kind,authority_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                artifact.kind,
                artifact.artifact_id,
                artifact.payload_hash,
                sqlite3.Binary(artifact.payload),
                artifact.schema,
                artifact.report_id,
                artifact.current_stage_id,
                artifact.transition_id,
                artifact.prior_artifact_id,
                artifact.prior_stage_id,
                artifact.subject,
                artifact.scope,
                artifact.stage_kind,
                artifact.authority_json,
            ),
        )

    def _make_receipt(
        self,
        *,
        operation_id: str,
        event_sequence: int,
        previous_event_root: str,
        event_root: str,
        chain_id: str,
        artifact: VerifiedArtifact,
        expected_head: tuple[str, str],
        head_root: str,
        state_root: str,
        receipt_hash: str | None = None,
    ) -> tuple[bytes, str]:
        value: dict[str, object] = {
            "schema": "mirror-continuity-receipt-v2",
            "operation_id": operation_id,
            "event_sequence": event_sequence,
            "previous_event_root": previous_event_root,
            "event_root": event_root,
            "chain_id": chain_id,
            "artifact_kind": artifact.kind,
            "artifact_id": artifact.artifact_id,
            "payload_hash": artifact.payload_hash,
            "prior_artifact_id": artifact.prior_artifact_id or NO_PRIOR,
            "prior_stage_id": artifact.prior_stage_id or NO_PRIOR,
            "expected_head_artifact_id": expected_head[0],
            "expected_head_stage_id": expected_head[1],
            "resulting_head_artifact_id": artifact.artifact_id,
            "resulting_head_stage_id": artifact.current_stage_id,
            "resulting_head_root": head_root,
            "state_root": state_root,
            "authority": dict(AUTHORITY_FLAGS),
        }
        raw = _canonical(value)
        if len(raw) > MAX_RECEIPT_BYTES:
            raise StoreConflictError("receipt:byte-cap")
        return raw, _receipt_hash(raw)

    def admit(self, artifact_kind: str, artifact_raw: bytes) -> AdmissionReceipt:
        """Verify and atomically admit one artifact, or replay its exact receipt."""

        artifact = verify_artifact(artifact_kind, artifact_raw, graph_profile_registry=self.graph_profile_registry)
        chain_id = _chain_id(artifact.kind, artifact.subject, artifact.scope, artifact.profile_id)
        request_hash = _payload_hash(artifact_raw)
        self._fault("before_transaction")
        connection = self._connect()
        try:
            try:
                connection.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                raise StoreBusyError("transaction:busy") from exc
            self._fault("after_begin")
            self._validate_transaction_snapshot(connection)
            existing = connection.execute(
                "SELECT operation_id,request_hash FROM operations WHERE chain_id=? AND artifact_kind=? AND artifact_id=? AND payload_hash=? AND (prior_artifact_id IS ? OR prior_artifact_id=?) AND (prior_stage_id IS ? OR prior_stage_id=?)",
                (
                    chain_id,
                    artifact.kind,
                    artifact.artifact_id,
                    artifact.payload_hash,
                    artifact.prior_artifact_id,
                    artifact.prior_artifact_id,
                    artifact.prior_stage_id,
                    artifact.prior_stage_id,
                ),
            ).fetchone()
            if existing is not None:
                if existing["request_hash"] != request_hash:
                    raise StoreConflictError("operation:request-conflict")
                receipt_row = connection.execute("SELECT receipt FROM receipts WHERE operation_id=?", (existing["operation_id"],)).fetchone()
                if receipt_row is None:
                    raise StoreSchemaError("operation:receipt-missing")
                connection.commit()
                return AdmissionReceipt(bytes(receipt_row[0]))
            head = self._head(connection, chain_id)
            if artifact.prior_artifact_id is None:
                if head is not None:
                    raise StoreConflictError("head:unexpected-existing")
                expected_head = (NO_PRIOR, NO_PRIOR)
            else:
                if head is None or (head["artifact_id"], head["current_stage_id"]) != (artifact.prior_artifact_id, artifact.prior_stage_id):
                    raise StoreConflictError("head:stale-or-wrong-prior")
                expected_head = (str(head["artifact_id"]), str(head["current_stage_id"]))
            operation_id = _operation_id(artifact, chain_id, expected_head)
            by_operation = connection.execute("SELECT request_hash FROM operations WHERE operation_id=?", (operation_id,)).fetchone()
            if by_operation is not None:
                if by_operation["request_hash"] != request_hash:
                    raise StoreConflictError("operation:request-conflict")
                receipt_row = connection.execute("SELECT receipt FROM receipts WHERE operation_id=?", (operation_id,)).fetchone()
                if receipt_row is None:
                    raise StoreSchemaError("operation:receipt-missing")
                connection.commit()
                return AdmissionReceipt(bytes(receipt_row[0]))
            self._insert_or_check_artifact(connection, artifact)
            self._fault("after_artifact_insert")
            event_sequence = int(connection.execute("SELECT COALESCE(MAX(sequence),0)+1 FROM events").fetchone()[0])
            if event_sequence > MAX_EVENTS:
                raise StoreConflictError("event:count-cap")
            previous_row = connection.execute("SELECT event_root FROM events ORDER BY sequence DESC LIMIT 1").fetchone()
            previous_event_root = str(previous_row[0]) if previous_row is not None else GENESIS_EVENT_ROOT
            head_root = _digest(
                "head-root",
                {
                    "chain_id": chain_id,
                    "artifact_kind": artifact.kind,
                    "artifact_id": artifact.artifact_id,
                    "current_stage_id": artifact.current_stage_id,
                    "stage_kind": artifact.stage_kind,
                    "transition_id": artifact.transition_id,
                    "event_sequence": event_sequence,
                },
            )
            head_material = {
                "chain_id": chain_id,
                "artifact_kind": artifact.kind,
                "artifact_id": artifact.artifact_id,
                "current_stage_id": artifact.current_stage_id,
                "stage_kind": artifact.stage_kind,
                "transition_id": artifact.transition_id,
                "event_sequence": event_sequence,
                "head_root": head_root,
            }
            state_root = _state_root(event_sequence, self._heads_for_state(connection, head_material))
            event_material = {
                "sequence": event_sequence,
                "chain_id": chain_id,
                "previous_event_root": previous_event_root,
                "operation_id": operation_id,
                "artifact_kind": artifact.kind,
                "artifact_id": artifact.artifact_id,
                "payload_hash": artifact.payload_hash,
                "prior_artifact_id": artifact.prior_artifact_id or NO_PRIOR,
                "prior_stage_id": artifact.prior_stage_id or NO_PRIOR,
                "receipt_hash": RECEIPT_EVENT_PLACEHOLDER,
                "commit_state_root": state_root,
            }
            # The receipt hash excludes event_root; this permits a receipt to bind
            # the final event root while the event root binds the receipt hash.
            _receipt_template, receipt_hash = self._make_receipt(
                operation_id=operation_id,
                event_sequence=event_sequence,
                previous_event_root=previous_event_root,
                event_root=RECEIPT_EVENT_PLACEHOLDER,
                chain_id=chain_id,
                artifact=artifact,
                expected_head=expected_head,
                head_root=head_root,
                state_root=state_root,
            )
            event_material["receipt_hash"] = receipt_hash
            event_root = _event_root(event_material)
            receipt_raw, final_receipt_hash = self._make_receipt(
                operation_id=operation_id,
                event_sequence=event_sequence,
                previous_event_root=previous_event_root,
                event_root=event_root,
                chain_id=chain_id,
                artifact=artifact,
                expected_head=expected_head,
                head_root=head_root,
                state_root=state_root,
            )
            if final_receipt_hash != receipt_hash:
                raise StoreSchemaError("receipt:identity-binding")
            if _event_root({**event_material, "receipt_hash": final_receipt_hash}) != event_root:
                raise StoreSchemaError("event:receipt-binding")
            connection.execute(
                "INSERT INTO operations(operation_id,chain_id,artifact_kind,artifact_id,payload_hash,request_hash,prior_artifact_id,prior_stage_id,expected_head_artifact_id,expected_head_stage_id,event_sequence,receipt_hash,commit_state_root) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (operation_id, chain_id, artifact.kind, artifact.artifact_id, artifact.payload_hash, request_hash, artifact.prior_artifact_id, artifact.prior_stage_id, expected_head[0], expected_head[1], event_sequence, receipt_hash, state_root),
            )
            connection.execute("INSERT INTO receipts(operation_id,receipt_hash,receipt) VALUES(?,?,?)", (operation_id, receipt_hash, sqlite3.Binary(receipt_raw)))
            connection.execute(
                "INSERT INTO events(sequence,chain_id,previous_event_root,event_root,operation_id,artifact_kind,artifact_id,payload_hash,prior_artifact_id,prior_stage_id,receipt_hash,commit_state_root) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (event_sequence, chain_id, previous_event_root, event_root, operation_id, artifact.kind, artifact.artifact_id, artifact.payload_hash, artifact.prior_artifact_id, artifact.prior_stage_id, receipt_hash, state_root),
            )
            connection.execute(
                "INSERT INTO heads(chain_id,artifact_kind,artifact_id,current_stage_id,stage_kind,transition_id,event_sequence,head_root,state_root) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(chain_id) DO UPDATE SET artifact_kind=excluded.artifact_kind,artifact_id=excluded.artifact_id,current_stage_id=excluded.current_stage_id,stage_kind=excluded.stage_kind,transition_id=excluded.transition_id,event_sequence=excluded.event_sequence,head_root=excluded.head_root,state_root=excluded.state_root",
                (chain_id, artifact.kind, artifact.artifact_id, artifact.current_stage_id, artifact.stage_kind, artifact.transition_id, event_sequence, head_root, state_root),
            )
            self._validate_transaction_snapshot(connection)
            self._fault("after_event_receipt_before_commit")
            connection.commit()
            try:
                self._fault("after_commit_before_response")
            except InjectedFault as exc:
                raise IndeterminateCommitError(operation_id) from exc
            return AdmissionReceipt(receipt_raw)
        except IndeterminateCommitError:
            raise
        except (InjectedFault, StoreConflictError, StoreSchemaError, StoreBusyError):
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        except sqlite3.IntegrityError as exc:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise StoreConflictError("transaction:integrity") from exc
        except sqlite3.OperationalError as exc:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise StoreBusyError("transaction:operational") from exc
        finally:
            connection.close()

    def _snapshot_rows(self) -> dict[str, list[dict[str, object]]]:
        connection = self._connect()
        try:
            return {
                "meta": [dict(row) for row in connection.execute("SELECT key,value FROM store_meta ORDER BY key")],
                "artifacts": [dict(row) for row in connection.execute("SELECT * FROM artifacts ORDER BY kind,artifact_id")],
                "operations": [dict(row) for row in connection.execute("SELECT * FROM operations ORDER BY event_sequence")],
                "receipts": [dict(row) for row in connection.execute("SELECT * FROM receipts ORDER BY operation_id")],
                "events": [dict(row) for row in connection.execute("SELECT * FROM events ORDER BY sequence")],
                "heads": [dict(row) for row in connection.execute("SELECT * FROM heads ORDER BY chain_id")],
            }
        finally:
            connection.close()

    def _restore_snapshot(self, snapshot: Mapping[str, list[Mapping[str, object]]]) -> None:
        """Restore one independently verified complete snapshot into this fresh DB."""

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            if any(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in ("artifacts", "operations", "receipts", "events", "heads")):
                raise StoreConflictError("restore:nonempty")
            connection.execute("DELETE FROM store_meta")
            for row in snapshot["meta"]:
                connection.execute("INSERT INTO store_meta(key,value) VALUES(?,?)", (row["key"], row["value"]))
            for row in snapshot["artifacts"]:
                connection.execute(
                    "INSERT INTO artifacts(kind,artifact_id,payload_hash,payload,artifact_schema,report_id,current_stage_id,transition_id,prior_artifact_id,prior_stage_id,subject,scope,stage_kind,authority_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    tuple(sqlite3.Binary(row["payload"]) if key == "payload" else row[key] for key in (
                        "kind", "artifact_id", "payload_hash", "payload", "artifact_schema", "report_id",
                        "current_stage_id", "transition_id", "prior_artifact_id", "prior_stage_id", "subject",
                        "scope", "stage_kind", "authority_json",
                    )),
                )
            for row in snapshot["operations"]:
                connection.execute(
                    "INSERT INTO operations(operation_id,chain_id,artifact_kind,artifact_id,payload_hash,request_hash,prior_artifact_id,prior_stage_id,expected_head_artifact_id,expected_head_stage_id,event_sequence,receipt_hash,commit_state_root) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    tuple(row[key] for key in (
                        "operation_id", "chain_id", "artifact_kind", "artifact_id", "payload_hash", "request_hash",
                        "prior_artifact_id", "prior_stage_id", "expected_head_artifact_id", "expected_head_stage_id",
                        "event_sequence", "receipt_hash", "commit_state_root",
                    )),
                )
            for row in snapshot["receipts"]:
                connection.execute(
                    "INSERT INTO receipts(operation_id,receipt_hash,receipt) VALUES(?,?,?)",
                    (row["operation_id"], row["receipt_hash"], sqlite3.Binary(row["receipt"])),
                )
            for row in snapshot["events"]:
                connection.execute(
                    "INSERT INTO events(sequence,chain_id,previous_event_root,event_root,operation_id,artifact_kind,artifact_id,payload_hash,prior_artifact_id,prior_stage_id,receipt_hash,commit_state_root) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    tuple(row[key] for key in (
                        "sequence", "chain_id", "previous_event_root", "event_root", "operation_id", "artifact_kind",
                        "artifact_id", "payload_hash", "prior_artifact_id", "prior_stage_id", "receipt_hash",
                        "commit_state_root",
                    )),
                )
            for row in snapshot["heads"]:
                connection.execute(
                    "INSERT INTO heads(chain_id,artifact_kind,artifact_id,current_stage_id,stage_kind,transition_id,event_sequence,head_root,state_root) VALUES(?,?,?,?,?,?,?,?,?)",
                    tuple(row[key] for key in (
                        "chain_id", "artifact_kind", "artifact_id", "current_stage_id", "stage_kind", "transition_id",
                        "event_sequence", "head_root", "state_root",
                    )),
                )
            connection.commit()
        except Exception:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()
