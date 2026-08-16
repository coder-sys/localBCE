"""Bounded local operational candidate for Mirror continuity artifacts.

This module is deliberately separate from the Blind Ledger clearance database.  It
stores only independently verified synthetic Provider Trust Graph and observation-only
Governance V1/V2 lineage artifacts, including the terminal withdrawal stage.  Storage
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
from app.governance import provider_continuity_control_pack_v2_independent as governance_v2_independent
from app.governance import provider_continuity_control_pack_withdrawal_independent as withdrawal_independent
from app.mirror import provider_trust_graph_independent as graph_independent
from app.mirror import continuity_store_independent as store_independent
from app.mirror import source_evidence_custody_independent as source_independent
from app.mirror import source_reconciliation_independent as reconciliation_independent


STORE_SCHEMA = "mirror-continuity-operational-foundation-v2"
SCHEMA_VERSION = 2
ARTIFACT_GRAPH = "PROVIDER_TRUST_GRAPH_V1"
ARTIFACT_GOVERNANCE = "PROVIDER_CONTINUITY_CONTROL_PACK_V1"
ARTIFACT_SOURCE_EVIDENCE = source_independent.ARTIFACT_KIND
ARTIFACT_RECONCILIATION = reconciliation_independent.ARTIFACT_KIND
ARTIFACT_KINDS = (ARTIFACT_GRAPH, ARTIFACT_GOVERNANCE, ARTIFACT_SOURCE_EVIDENCE, ARTIFACT_RECONCILIATION)
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


class GovernanceObservationOnly(StoreConflictError):
    """Typed verifier-owned result for an explicitly ineligible V2 governance head."""

    _REASONS = frozenset({"not-approved", "withdrawn"})

    def __init__(self, reason: str) -> None:
        if reason not in self._REASONS:
            raise ValueError("governance:observation-reason")
        self.reason = reason
        super().__init__(f"governance:{reason}")


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
class SourceCustodyAdmission:
    """Atomic source-custody result and optional graph continuity receipt."""

    custody_receipt: AdmissionReceipt
    graph_receipt: AdmissionReceipt | None
    graph_admitted: bool


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
    profile_id: str | None = None
    profile_version: int | None = None


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
    elif kind == ARTIFACT_SOURCE_EVIDENCE:
        if dict(value) != source_independent.AUTHORITY_FLAGS:
            raise ArtifactAdmissionError("artifact:authority-flags")
    elif kind == ARTIFACT_RECONCILIATION:
        if dict(value) != reconciliation_independent.AUTHORITY_FLAGS:
            raise ArtifactAdmissionError("artifact:authority-flags")
    elif dict(value) != governance_independent.AUTHORITY_FLAGS:
        raise ArtifactAdmissionError("artifact:authority-flags")
    return _canonical(AUTHORITY_FLAGS).decode("ascii")


def _governance_prefix(value: Mapping[str, object], stage_count: int) -> tuple[bytes, dict[str, object]]:
    if value.get("schema") == governance_v2_independent.SCHEMA:
        raw = governance_v2_independent.prefix_bytes(value, stage_count)
        return raw, _parse_canonical(raw)
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
    reconciliation_context: Mapping[str, object] | None = None,
) -> VerifiedArtifact:
    """Run the matching independent verifier and normalize its exact identities."""

    if artifact_kind not in ARTIFACT_KINDS:
        raise ArtifactAdmissionError("artifact:kind")
    if type(raw) is not bytes or not raw or len(raw) > MAX_ARTIFACT_BYTES:
        raise ArtifactAdmissionError("artifact:byte-cap")
    try:
        if artifact_kind == ARTIFACT_SOURCE_EVIDENCE:
            value = source_independent._parse(raw)
        elif artifact_kind == ARTIFACT_RECONCILIATION:
            value = reconciliation_independent._parse(raw)
        else:
            value = _parse_canonical(raw)
    except (
        ContinuityStoreError,
        source_independent.IndependentSourceCustodyError,
        reconciliation_independent.IndependentSourceReconciliationError,
    ) as exc:
        raise ArtifactAdmissionError(str(exc)) from exc
    try:
        if artifact_kind == ARTIFACT_SOURCE_EVIDENCE:
            result = source_independent.verify_artifact(raw, graph_profile_registry=graph_profile_registry, allow_unresolved_graph=True)
        elif artifact_kind == ARTIFACT_RECONCILIATION:
            if not isinstance(reconciliation_context, Mapping):
                raise ArtifactAdmissionError("reconciliation:context-required")
            result = reconciliation_independent.verify_artifact(
                raw,
                current_custody_raw=reconciliation_context["current_custody_raw"],
                prior_custody_raw=reconciliation_context.get("prior_custody_raw"),
                current_graph_raw=reconciliation_context.get("current_graph_raw"),
                prior_graph_raw=reconciliation_context.get("prior_graph_raw"),
                prior_reconciliation_raw=reconciliation_context.get("prior_reconciliation_raw"),
                graph_profile_registry=graph_profile_registry,
            )
        elif artifact_kind == ARTIFACT_GRAPH:
            if value.get("schema") == graph_independent.SCHEMA_V2:
                result = graph_independent.verify_bytes_v2(raw, graph_profile_registry or {})
            else:
                result = graph_independent.verify_bytes(raw)
        elif value.get("schema") in (governance_v2_independent.SCHEMA, governance_v2_independent.WITHDRAWAL_SCHEMA):
            result = governance_v2_independent.verify_bytes(raw, graph_profile_registry or {})
        elif value.get("schema") == withdrawal_independent.SCHEMA:
            result = withdrawal_independent.verify_bytes(raw)
        else:
            result = governance_independent.verify_bytes(raw)
    except Exception as exc:
        raise ArtifactAdmissionError(f"artifact:independent-reject:{type(exc).__name__}") from exc
    payload_hash = _payload_hash(raw)
    profile_id: str | None = None
    try:
        if artifact_kind == ARTIFACT_SOURCE_EVIDENCE:
            artifact_id = result["artifact_id"]
            report_id = result["report_id"]
            current_stage_id = result["current_stage_id"]
            transition_id = result["transition_id"]
            stage_kind = result["stage_kind"]
            prior_artifact_id = result["prior_artifact_id"]
            prior_stage_id = result["prior_stage_id"]
            schema = result["schema"]
            subject_id = result["subject"]
            scope = result["scope"]
            profile_id = result["profile_id"]
            authority_json = _authority_json(value["authority"], kind=artifact_kind)
        elif artifact_kind == ARTIFACT_RECONCILIATION:
            artifact_id = result["artifact_id"]
            report_id = None
            current_stage_id = result["current_stage_id"]
            transition_id = result["transition_id"]
            stage_kind = result["stage_kind"]
            prior_artifact_id = result["prior_artifact_id"]
            prior_stage_id = result["prior_stage_id"]
            schema = result["schema"]
            subject_id = result["subject"]
            scope = result["scope"]
            profile_id = result["profile_id"]
            authority_json = _authority_json(value["authority"], kind=artifact_kind)
        elif artifact_kind == ARTIFACT_GRAPH:
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
            if schema == graph_independent.SCHEMA_V2:
                profile_value = graph_independent._expect_keys(value.get("profile"), graph_independent.PROFILE_KEYS, "artifact:profile")
                profile_id = profile_value["profile_id"]
        elif value.get("schema") in (withdrawal_independent.SCHEMA, governance_v2_independent.WITHDRAWAL_SCHEMA):
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
            authority_flags = governance_v2_independent.AUTHORITY_FLAGS if schema == governance_v2_independent.WITHDRAWAL_SCHEMA else withdrawal_independent.AUTHORITY_FLAGS
            authority_json = _authority_json({key: value[key] for key in authority_flags}, kind=artifact_kind)
            if schema == governance_v2_independent.WITHDRAWAL_SCHEMA:
                profile_value = governance_v2_independent._expect_keys(value.get("profile"), governance_v2_independent.PROFILE_KEYS, "artifact:profile")
                profile_id = str(profile_value["profile_id"])
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
                    if value.get("schema") == governance_v2_independent.SCHEMA:
                        governance_v2_independent.verify_bytes(prefix_raw, graph_profile_registry or {})
                    else:
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
            authority_flags = governance_v2_independent.AUTHORITY_FLAGS if schema == governance_v2_independent.SCHEMA else governance_independent.AUTHORITY_FLAGS
            authority_json = _authority_json({key: value[key] for key in authority_flags}, kind=artifact_kind)
            if schema == governance_v2_independent.SCHEMA:
                profile_value = governance_v2_independent._expect_keys(value.get("profile"), governance_v2_independent.PROFILE_KEYS, "artifact:profile")
                profile_id = str(profile_value["profile_id"])
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
        profile_id=profile_id,
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
        try:
            wal_size = wal_path.stat().st_size if wal_path.is_file() else 0
        except FileNotFoundError:
            # A concurrent FULL checkpoint may remove the WAL between the
            # existence check and stat; reopening the bounded database is safe.
            wal_size = 0
        if wal_size > MAX_WAL_BYTES:
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

    def _require_active_v2_governance(self, connection: sqlite3.Connection, artifact: VerifiedArtifact) -> None:
        """Require the state-owned approved V2 profile before a new graph write."""

        if artifact.kind != ARTIFACT_GRAPH or artifact.schema != graph_independent.SCHEMA_V2:
            return
        if artifact.profile_id is None:
            raise StoreConflictError("governance:profile-missing")
        governance_chain = _chain_id(ARTIFACT_GOVERNANCE, artifact.subject, artifact.scope, artifact.profile_id)
        row = connection.execute(
            "SELECT h.*, a.payload, a.artifact_schema FROM heads h JOIN artifacts a ON a.kind=h.artifact_kind AND a.artifact_id=h.artifact_id WHERE h.chain_id=?",
            (governance_chain,),
        ).fetchone()
        if row is None:
            raise GovernanceObservationOnly("not-approved")
        if row["artifact_schema"] not in (governance_v2_independent.SCHEMA, governance_v2_independent.WITHDRAWAL_SCHEMA):
            raise StoreConflictError("governance:v1-not-v2")
        try:
            governed = governance_v2_independent.verify_bytes(bytes(row["payload"]), self.graph_profile_registry)
            graph_value = _parse_canonical(artifact.payload)
            observation = graph_value["observation_snapshot"]["observation_time"]
        except Exception as exc:
            raise StoreSchemaError("governance:independent-reject") from exc
        if governed.get("schema") == governance_v2_independent.WITHDRAWAL_SCHEMA:
            raise GovernanceObservationOnly("withdrawn")
        if governed.get("current_stage_kind") != governance_v2_independent.STAGE_APPROVED:
            raise GovernanceObservationOnly("not-approved")
        if governed.get("profile_id") != artifact.profile_id or governed.get("profile_digest") != graph_value["profile"]["profile_digest"]:
            raise StoreConflictError("governance:profile-binding")
        if type(observation) is not int or not governed["effective_start"] <= observation <= governed["effective_end"]:
            raise StoreConflictError("governance:effective-interval")

    def provider_continuity_lifecycle_head(
        self,
        provider_graph_subject: str,
        scope: str,
        profile_id: str | None = None,
    ) -> ProviderContinuityLifecycleHead | None:
        """Return the verified governance-lineage head used for active-status decisions.

        An approved artifact is active only while it remains the current head.  A terminal
        withdrawal is admitted as the next immutable governance-lineage stage and therefore
        makes the same approval non-active without any caller-selected status flag.
        """

        chain_id = _chain_id(ARTIFACT_GOVERNANCE, provider_graph_subject, scope, profile_id)
        connection = self._connect()
        try:
            try:
                connection.execute("BEGIN")
            except sqlite3.OperationalError as exc:
                raise StoreBusyError("transaction:read-busy") from exc
            self._validate_transaction_snapshot(connection)
            row = connection.execute(
                "SELECT h.*, a.subject, a.scope, a.payload, a.artifact_schema FROM heads h JOIN artifacts a ON a.kind=h.artifact_kind AND a.artifact_id=h.artifact_id WHERE h.chain_id=?",
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
                profile_id=profile_id,
                profile_version=(
                    int(governance_v2_independent.verify_bytes(bytes(row["payload"]), self.graph_profile_registry)["profile_version"])
                    if row["artifact_schema"] in (governance_v2_independent.SCHEMA, governance_v2_independent.WITHDRAWAL_SCHEMA)
                    else None
                ),
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

    def _admit_in_transaction(
        self,
        connection: sqlite3.Connection,
        artifact: VerifiedArtifact,
        request_hash: str,
        *,
        enforce_governance: bool = True,
    ) -> AdmissionReceipt:
        """Insert one artifact while the caller owns BEGIN IMMEDIATE."""

        chain_id = _chain_id(artifact.kind, artifact.subject, artifact.scope, artifact.profile_id)
        existing = connection.execute(
            "SELECT operation_id,request_hash FROM operations WHERE chain_id=? AND artifact_kind=? AND artifact_id=? AND payload_hash=? AND (prior_artifact_id IS ? OR prior_artifact_id=?) AND (prior_stage_id IS ? OR prior_stage_id=?)",
            (
                chain_id, artifact.kind, artifact.artifact_id, artifact.payload_hash,
                artifact.prior_artifact_id, artifact.prior_artifact_id,
                artifact.prior_stage_id, artifact.prior_stage_id,
            ),
        ).fetchone()
        if existing is not None:
            if existing["request_hash"] != request_hash:
                raise StoreConflictError("operation:request-conflict")
            receipt_row = connection.execute("SELECT receipt FROM receipts WHERE operation_id=?", (existing["operation_id"],)).fetchone()
            if receipt_row is None:
                raise StoreSchemaError("operation:receipt-missing")
            return AdmissionReceipt(bytes(receipt_row[0]))
        if enforce_governance:
            self._require_active_v2_governance(connection, artifact)
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
        return AdmissionReceipt(receipt_raw)

    def admit(self, artifact_kind: str, artifact_raw: bytes) -> AdmissionReceipt:
        """Verify and atomically admit one artifact, or replay its exact receipt."""

        if artifact_kind == ARTIFACT_RECONCILIATION:
            raise StoreConflictError("reconciliation:transaction-required")
        artifact = verify_artifact(artifact_kind, artifact_raw, graph_profile_registry=self.graph_profile_registry)
        if artifact_kind == ARTIFACT_SOURCE_EVIDENCE and source_independent.has_graph_link(artifact_raw):
            raise StoreConflictError("custody:graph-link-transaction-required")
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
            receipt = self._admit_in_transaction(connection, artifact, request_hash)
            self._validate_transaction_snapshot(connection)
            self._fault("after_event_receipt_before_commit")
            connection.commit()
            try:
                self._fault("after_commit_before_response")
            except InjectedFault as exc:
                raise IndeterminateCommitError(receipt.operation_id) from exc
            return receipt
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

    def source_evidence_head(
        self,
        subject: str,
        scope: str,
        profile_id: str,
        graph_profile_registry: Mapping[str, object] | None = None,
    ) -> tuple[str, str] | None:
        """Return the state-owned source-evidence head for canonical retry binding."""

        if graph_profile_registry is not None and dict(graph_profile_registry) != dict(self.graph_profile_registry):
            raise StoreConflictError("profile:registry-mismatch")
        chain_id = _chain_id(ARTIFACT_SOURCE_EVIDENCE, subject, scope, profile_id)
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            self._validate_transaction_snapshot(connection)
            row = connection.execute("SELECT artifact_id,current_stage_id FROM heads WHERE chain_id=?", (chain_id,)).fetchone()
            connection.commit()
            return None if row is None else (str(row["artifact_id"]), str(row["current_stage_id"]))
        except Exception:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()

    def _receipt_for_artifact(self, connection: sqlite3.Connection, artifact: VerifiedArtifact) -> AdmissionReceipt:
        row = connection.execute(
            "SELECT o.operation_id,r.receipt FROM operations o JOIN receipts r ON r.operation_id=o.operation_id WHERE o.artifact_kind=? AND o.artifact_id=? AND o.payload_hash=?",
            (artifact.kind, artifact.artifact_id, artifact.payload_hash),
        ).fetchone()
        if row is None:
            raise StoreSchemaError("operation:artifact-receipt-missing")
        return AdmissionReceipt(bytes(row["receipt"]))

    def find_source_evidence(
        self,
        envelope_raw: bytes,
        graph_profile_registry: Mapping[str, object] | None = None,
    ) -> SourceCustodyAdmission | None:
        """Find an immutable envelope retry without exposing its payload."""

        if type(envelope_raw) is not bytes or not envelope_raw:
            raise StoreConflictError("custody:envelope-bytes")
        if graph_profile_registry is not None and dict(graph_profile_registry) != dict(self.graph_profile_registry):
            raise StoreConflictError("profile:registry-mismatch")
        expected_digest = source_independent._raw_digest("envelope", envelope_raw)
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            self._validate_transaction_snapshot(connection)
            rows = connection.execute(
                "SELECT * FROM artifacts WHERE kind=? ORDER BY artifact_id",
                (ARTIFACT_SOURCE_EVIDENCE,),
            ).fetchall()
            for row in rows:
                candidate_raw = bytes(row["payload"])
                if source_independent.envelope_digest_from_artifact(candidate_raw) != expected_digest:
                    continue
                source_artifact = verify_artifact(ARTIFACT_SOURCE_EVIDENCE, candidate_raw, graph_profile_registry=self.graph_profile_registry)
                source_receipt = self._receipt_for_artifact(connection, source_artifact)
                graph_receipt = None
                if source_independent.has_graph_link(candidate_raw):
                    normalized = source_independent.verify_artifact(candidate_raw, graph_profile_registry=self.graph_profile_registry, allow_unresolved_graph=True)
                    linked_row = connection.execute(
                        "SELECT * FROM artifacts WHERE kind=? AND artifact_id=?",
                        (ARTIFACT_GRAPH, normalized["linked_graph_artifact_id"]),
                    ).fetchone()
                    if linked_row is None:
                        raise StoreSchemaError("custody:linked-graph-missing")
                    linked = verify_artifact(ARTIFACT_GRAPH, bytes(linked_row["payload"]), graph_profile_registry=self.graph_profile_registry)
                    source_independent.verify_artifact(candidate_raw, graph_raw=linked.payload, graph_profile_registry=self.graph_profile_registry)
                    graph_receipt = self._receipt_for_artifact(connection, linked)
                connection.commit()
                return SourceCustodyAdmission(source_receipt, graph_receipt, graph_receipt is not None)
            connection.commit()
            return None
        except Exception:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()

    def _load_source_reconciliation_context(
        self,
        connection: sqlite3.Connection,
        custody_raw: bytes,
        *,
        require_source_head: bool = True,
    ) -> dict[str, object]:
        """Load the verifier-owned custody chain needed for one delta.

        This runs under the caller's transaction.  The returned bytes are
        state-owned rows, never caller-selected predecessor or graph payloads.
        """

        registry = self.graph_profile_registry
        try:
            preview = source_independent.verify_artifact(
                custody_raw,
                graph_profile_registry=registry,
                allow_unresolved_graph=True,
            )
            source_artifact = verify_artifact(
                ARTIFACT_SOURCE_EVIDENCE,
                custody_raw,
                graph_profile_registry=registry,
            )
        except Exception as exc:
            raise StoreConflictError("reconciliation:custody-reject") from exc
        source_row = connection.execute(
            "SELECT * FROM artifacts WHERE kind=? AND artifact_id=?",
            (ARTIFACT_SOURCE_EVIDENCE, source_artifact.artifact_id),
        ).fetchone()
        if source_row is None or bytes(source_row["payload"]) != custody_raw or source_row["payload_hash"] != _payload_hash(custody_raw):
            raise StoreConflictError("reconciliation:custody-not-stored")

        current_graph_raw: bytes | None = None
        if preview.get("linked_graph_artifact_id") is not None:
            graph_row = connection.execute(
                "SELECT * FROM artifacts WHERE kind=? AND artifact_id=?",
                (ARTIFACT_GRAPH, preview["linked_graph_artifact_id"]),
            ).fetchone()
            if graph_row is None:
                raise StoreConflictError("reconciliation:current-graph-missing")
            current_graph_raw = bytes(graph_row["payload"])
            try:
                source_independent.verify_artifact(
                    custody_raw,
                    graph_raw=current_graph_raw,
                    graph_profile_registry=registry,
                )
            except Exception as exc:
                raise StoreConflictError("reconciliation:current-graph-binding") from exc

        source_chain = _chain_id(
            ARTIFACT_SOURCE_EVIDENCE,
            source_artifact.subject,
            source_artifact.scope,
            source_artifact.profile_id,
        )
        source_head = self._head(connection, source_chain)
        if require_source_head and (source_head is None or (source_head["artifact_id"], source_head["current_stage_id"]) != (source_artifact.artifact_id, source_artifact.current_stage_id)):
            raise StoreConflictError("reconciliation:source-not-head")

        prior_custody_raw: bytes | None = None
        prior_graph_raw: bytes | None = None
        prior_source_artifact: VerifiedArtifact | None = None
        if source_artifact.prior_artifact_id is not None:
            prior_row = connection.execute(
                "SELECT * FROM artifacts WHERE kind=? AND artifact_id=?",
                (ARTIFACT_SOURCE_EVIDENCE, source_artifact.prior_artifact_id),
            ).fetchone()
            if prior_row is None or prior_row["current_stage_id"] != source_artifact.prior_stage_id:
                raise StoreConflictError("reconciliation:prior-custody-missing")
            prior_custody_raw = bytes(prior_row["payload"])
            prior_preview = source_independent.verify_artifact(
                prior_custody_raw,
                graph_profile_registry=registry,
                allow_unresolved_graph=True,
            )
            if prior_preview.get("linked_graph_artifact_id") is not None:
                prior_graph_row = connection.execute(
                    "SELECT * FROM artifacts WHERE kind=? AND artifact_id=?",
                    (ARTIFACT_GRAPH, prior_preview["linked_graph_artifact_id"]),
                ).fetchone()
                if prior_graph_row is None:
                    raise StoreConflictError("reconciliation:prior-graph-missing")
                prior_graph_raw = bytes(prior_graph_row["payload"])
            try:
                prior_source_artifact = verify_artifact(
                    ARTIFACT_SOURCE_EVIDENCE,
                    prior_custody_raw,
                    graph_profile_registry=registry,
                )
                source_independent.verify_artifact(
                    prior_custody_raw,
                    graph_raw=prior_graph_raw,
                    graph_profile_registry=registry,
                )
            except Exception as exc:
                raise StoreConflictError("reconciliation:prior-custody-binding") from exc
            if prior_source_artifact.artifact_id != source_artifact.prior_artifact_id or prior_source_artifact.current_stage_id != source_artifact.prior_stage_id:
                raise StoreConflictError("reconciliation:prior-custody-binding")

        recon_chain = _chain_id(
            ARTIFACT_RECONCILIATION,
            source_artifact.subject,
            source_artifact.scope,
            source_artifact.profile_id,
        )
        recon_head = self._head(connection, recon_chain)
        prior_reconciliation_raw: bytes | None = None
        if prior_source_artifact is None:
            if recon_head is not None:
                raise StoreConflictError("reconciliation:unexpected-existing-head")
        else:
            if recon_head is None:
                raise StoreConflictError("reconciliation:prior-head-missing")
            prior_recon_row = connection.execute(
                "SELECT * FROM artifacts WHERE kind=? AND artifact_id=?",
                (ARTIFACT_RECONCILIATION, recon_head["artifact_id"]),
            ).fetchone()
            if prior_recon_row is None or prior_recon_row["current_stage_id"] != recon_head["current_stage_id"]:
                raise StoreSchemaError("reconciliation:head-artifact-missing")
            prior_reconciliation_raw = bytes(prior_recon_row["payload"])
            try:
                prior_value = reconciliation_independent._parse(prior_reconciliation_raw)
            except Exception as exc:
                raise StoreSchemaError("reconciliation:head-artifact-invalid") from exc
            prior_current = prior_value.get("current_custody")
            if not isinstance(prior_current, dict) or prior_current.get("artifact_id") != source_artifact.prior_artifact_id or prior_current.get("stage_id") != source_artifact.prior_stage_id:
                raise StoreConflictError("reconciliation:prior-head-binding")

        return {
            "current_custody_raw": custody_raw,
            "prior_custody_raw": prior_custody_raw,
            "current_graph_raw": current_graph_raw,
            "prior_graph_raw": prior_graph_raw,
            "prior_reconciliation_raw": prior_reconciliation_raw,
            "source_artifact": source_artifact,
            "source_preview": preview,
            "reconciliation_head": recon_head,
        }

    def source_reconciliation_context(
        self,
        custody_raw: bytes,
        graph_profile_registry: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        """Return an immutable read context for the configured reconciliation service."""

        if graph_profile_registry is not None and dict(graph_profile_registry) != dict(self.graph_profile_registry):
            raise StoreConflictError("profile:registry-mismatch")
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            self._validate_transaction_snapshot(connection)
            context = self._load_source_reconciliation_context(connection, custody_raw)
            connection.commit()
            return {key: value for key, value in context.items() if key not in {"source_artifact", "source_preview", "reconciliation_head"}}
        except Exception:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()

    def find_source_reconciliation(
        self,
        custody_raw: bytes,
        graph_profile_registry: Mapping[str, object] | None = None,
    ) -> AdmissionReceipt | None:
        """Find an exact retry by its already-stored current custody identity."""

        if graph_profile_registry is not None and dict(graph_profile_registry) != dict(self.graph_profile_registry):
            raise StoreConflictError("profile:registry-mismatch")
        try:
            preview = source_independent.verify_artifact(
                custody_raw,
                graph_profile_registry=self.graph_profile_registry,
                allow_unresolved_graph=True,
            )
        except Exception as exc:
            raise StoreConflictError("reconciliation:custody-reject") from exc
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            self._validate_transaction_snapshot(connection)
            source_row = connection.execute(
                "SELECT payload,payload_hash FROM artifacts WHERE kind=? AND artifact_id=?",
                (ARTIFACT_SOURCE_EVIDENCE, preview["artifact_id"]),
            ).fetchone()
            if source_row is None or bytes(source_row["payload"]) != custody_raw or source_row["payload_hash"] != _payload_hash(custody_raw):
                connection.commit()
                return None
            for row in connection.execute("SELECT * FROM artifacts WHERE kind=? ORDER BY artifact_id", (ARTIFACT_RECONCILIATION,)):
                value = reconciliation_independent._parse(bytes(row["payload"]))
                current = value.get("current_custody")
                if isinstance(current, dict) and current.get("artifact_id") == preview["artifact_id"]:
                    receipt_row = connection.execute(
                        "SELECT r.receipt FROM operations o JOIN receipts r ON r.operation_id=o.operation_id WHERE o.artifact_kind=? AND o.artifact_id=? AND o.payload_hash=?",
                        (ARTIFACT_RECONCILIATION, row["artifact_id"], row["payload_hash"]),
                    ).fetchone()
                    if receipt_row is None:
                        raise StoreSchemaError("reconciliation:receipt-missing")
                    receipt = AdmissionReceipt(bytes(receipt_row["receipt"]))
                    connection.commit()
                    return receipt
            connection.commit()
            return None
        except Exception:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()

    def admit_source_reconciliation(
        self,
        custody_raw: bytes,
        reconciliation_raw: bytes,
        graph_profile_registry: Mapping[str, object] | None = None,
    ) -> AdmissionReceipt:
        """Atomically admit one verifier-bound temporal delta over custody state."""

        if graph_profile_registry is not None and dict(graph_profile_registry) != dict(self.graph_profile_registry):
            raise StoreConflictError("profile:registry-mismatch")
        if type(custody_raw) is not bytes or type(reconciliation_raw) is not bytes:
            raise StoreConflictError("reconciliation:bytes")
        self._fault("before_transaction")
        connection = self._connect()
        try:
            try:
                connection.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                raise StoreBusyError("transaction:busy") from exc
            self._fault("after_begin")
            self._validate_transaction_snapshot(connection)
            try:
                current_preview = source_independent.verify_artifact(
                    custody_raw,
                    graph_profile_registry=self.graph_profile_registry,
                    allow_unresolved_graph=True,
                )
            except Exception as exc:
                raise StoreConflictError("reconciliation:custody-reject") from exc
            current_source_row = connection.execute(
                "SELECT payload,payload_hash FROM artifacts WHERE kind=? AND artifact_id=?",
                (ARTIFACT_SOURCE_EVIDENCE, current_preview["artifact_id"]),
            ).fetchone()
            if current_source_row is not None and (bytes(current_source_row["payload"]) != custody_raw or current_source_row["payload_hash"] != _payload_hash(custody_raw)):
                raise StoreConflictError("reconciliation:custody-identity-conflict")
            if current_source_row is not None:
                for existing_row in connection.execute("SELECT * FROM artifacts WHERE kind=? ORDER BY artifact_id", (ARTIFACT_RECONCILIATION,)):
                    existing_value = reconciliation_independent._parse(bytes(existing_row["payload"]))
                    existing_current = existing_value.get("current_custody")
                    if isinstance(existing_current, dict) and existing_current.get("artifact_id") == current_preview["artifact_id"]:
                        if bytes(existing_row["payload"]) != reconciliation_raw:
                            raise StoreConflictError("reconciliation:identity-conflict")
                        receipt_row = connection.execute(
                            "SELECT r.receipt FROM operations o JOIN receipts r ON r.operation_id=o.operation_id WHERE o.artifact_kind=? AND o.artifact_id=? AND o.payload_hash=?",
                            (ARTIFACT_RECONCILIATION, existing_row["artifact_id"], existing_row["payload_hash"]),
                        ).fetchone()
                        if receipt_row is None:
                            raise StoreSchemaError("reconciliation:receipt-missing")
                        connection.commit()
                        return AdmissionReceipt(bytes(receipt_row["receipt"]))
            context = self._load_source_reconciliation_context(connection, custody_raw)
            artifact = verify_artifact(
                ARTIFACT_RECONCILIATION,
                reconciliation_raw,
                graph_profile_registry=self.graph_profile_registry,
                reconciliation_context=context,
            )
            receipt = self._admit_in_transaction(
                connection,
                artifact,
                _payload_hash(reconciliation_raw),
                enforce_governance=False,
            )
            self._validate_transaction_snapshot(connection)
            self._fault("after_event_receipt_before_commit")
            connection.commit()
            try:
                self._fault("after_commit_before_response")
            except InjectedFault as exc:
                raise IndeterminateCommitError(receipt.operation_id) from exc
            return receipt
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

    def admit_source_evidence(
        self,
        custody_raw: bytes,
        graph_raw: bytes | None = None,
        graph_profile_registry: Mapping[str, object] | None = None,
    ) -> SourceCustodyAdmission:
        """Atomically custody source evidence and, when present, its graph artifact."""

        return self._admit_source_evidence(
            custody_raw,
            graph_raw,
            graph_profile_registry,
            observation_raw=None,
        )

    def admit_source_evidence_with_governance_observation(
        self,
        custody_raw: bytes,
        graph_raw: bytes,
        observation_raw: bytes,
        graph_profile_registry: Mapping[str, object] | None = None,
    ) -> SourceCustodyAdmission:
        """Atomically retain observation evidence only for a typed governance outcome."""

        return self._admit_source_evidence(
            custody_raw,
            graph_raw,
            graph_profile_registry,
            observation_raw=observation_raw,
        )

    def _admit_source_evidence(
        self,
        custody_raw: bytes,
        graph_raw: bytes | None,
        graph_profile_registry: Mapping[str, object] | None,
        *,
        observation_raw: bytes | None,
    ) -> SourceCustodyAdmission:
        """Run source/graph admission with any observation fallback inside one transaction."""

        if graph_profile_registry is not None and dict(graph_profile_registry) != dict(self.graph_profile_registry):
            raise StoreConflictError("profile:registry-mismatch")
        registry = self.graph_profile_registry
        if observation_raw is not None and graph_raw is None:
            raise StoreConflictError("custody:observation-without-graph")
        try:
            source_preview = source_independent.verify_artifact(custody_raw, graph_raw=graph_raw, graph_profile_registry=registry)
        except Exception as exc:
            raise StoreConflictError("custody:independent-reject") from exc
        linked = source_preview.get("linked_graph_artifact_id") is not None
        if linked != (graph_raw is not None):
            raise StoreConflictError("custody:graph-link-carrier")
        graph_artifact: VerifiedArtifact | None = None
        if graph_raw is not None:
            try:
                source_independent.verify_artifact(custody_raw, graph_raw=graph_raw, graph_profile_registry=registry)
                graph_artifact = verify_artifact(ARTIFACT_GRAPH, graph_raw, graph_profile_registry=registry)
            except Exception as exc:
                raise StoreConflictError("custody:graph-independent-reject") from exc
            if (
                source_preview.get("linked_graph_artifact_id") != graph_artifact.artifact_id
                or source_preview.get("linked_graph_payload_hash") != graph_artifact.payload_hash
                or source_preview.get("linked_graph_report_id") != graph_artifact.report_id
            ):
                raise StoreConflictError("custody:graph-link-mismatch")
        source_artifact = verify_artifact(ARTIFACT_SOURCE_EVIDENCE, custody_raw, graph_profile_registry=registry)
        observation_artifact: VerifiedArtifact | None = None
        if observation_raw is not None:
            try:
                observation_preview = source_independent.verify_artifact(
                    observation_raw,
                    graph_profile_registry=registry,
                )
                observation_artifact = verify_artifact(
                    ARTIFACT_SOURCE_EVIDENCE,
                    observation_raw,
                    graph_profile_registry=registry,
                )
            except Exception as exc:
                raise StoreConflictError("custody:observation-independent-reject") from exc
            if observation_preview.get("linked_graph_artifact_id") is not None:
                raise StoreConflictError("custody:observation-graph-link")
            if (
                observation_preview.get("envelope_digest") != source_preview.get("envelope_digest")
                or observation_artifact.subject != source_artifact.subject
                or observation_artifact.scope != source_artifact.scope
                or observation_artifact.profile_id != source_artifact.profile_id
                or observation_artifact.prior_artifact_id != source_artifact.prior_artifact_id
                or observation_artifact.prior_stage_id != source_artifact.prior_stage_id
            ):
                raise StoreConflictError("custody:observation-binding")
        request_hash = _payload_hash(custody_raw)
        self._fault("before_transaction")
        connection = self._connect()
        try:
            try:
                connection.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                raise StoreBusyError("transaction:busy") from exc
            self._fault("after_begin")
            self._validate_transaction_snapshot(connection)
            expected_envelope_digest = source_preview["envelope_digest"]
            for row in connection.execute(
                "SELECT artifact_id,payload_hash,payload FROM artifacts WHERE kind=? ORDER BY artifact_id",
                (ARTIFACT_SOURCE_EVIDENCE,),
            ):
                existing_digest = source_independent.envelope_digest_from_artifact(bytes(row["payload"]))
                if existing_digest == expected_envelope_digest:
                    if row["artifact_id"] != source_artifact.artifact_id or row["payload_hash"] != source_artifact.payload_hash or bytes(row["payload"]) != custody_raw:
                        raise StoreConflictError("custody:envelope-collision")
                    existing = verify_artifact(ARTIFACT_SOURCE_EVIDENCE, custody_raw, graph_profile_registry=registry)
                    source_receipt = self._receipt_for_artifact(connection, existing)
                    graph_receipt = None
                    if graph_artifact is not None:
                        graph_receipt = self._receipt_for_artifact(connection, graph_artifact)
                    connection.commit()
                    return SourceCustodyAdmission(source_receipt, graph_receipt, graph_receipt is not None)
            admitted_source_artifact = source_artifact
            admitted_source_request_hash = request_hash
            if graph_artifact is not None:
                try:
                    self._require_active_v2_governance(connection, graph_artifact)
                except GovernanceObservationOnly:
                    if observation_artifact is None or observation_raw is None:
                        raise
                    admitted_source_artifact = observation_artifact
                    admitted_source_request_hash = _payload_hash(observation_raw)
                    graph_artifact = None
            if graph_artifact is not None:
                existing_graph_row = connection.execute(
                    "SELECT * FROM artifacts WHERE kind=? AND artifact_id=?",
                    (ARTIFACT_GRAPH, graph_artifact.artifact_id),
                ).fetchone()
                if existing_graph_row is not None and not self._artifact_matches(existing_graph_row, graph_artifact):
                    raise StoreConflictError("custody:graph-identity-conflict")
            source_receipt = self._admit_in_transaction(
                connection,
                admitted_source_artifact,
                admitted_source_request_hash,
                enforce_governance=False,
            )
            if graph_artifact is None:
                graph_receipt = None
            elif existing_graph_row is not None:
                graph_receipt = self._receipt_for_artifact(connection, graph_artifact)
            else:
                graph_receipt = self._admit_in_transaction(connection, graph_artifact, _payload_hash(graph_raw), enforce_governance=True)
            self._validate_transaction_snapshot(connection)
            self._fault("after_event_receipt_before_commit")
            connection.commit()
            try:
                self._fault("after_commit_before_response")
            except InjectedFault as exc:
                operation = graph_receipt or source_receipt
                raise IndeterminateCommitError(operation.operation_id) from exc
            return SourceCustodyAdmission(source_receipt, graph_receipt, graph_receipt is not None)
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
