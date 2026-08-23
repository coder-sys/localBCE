"""Durable, read-only controlled-shadow runtime mechanics.

The runtime is deliberately separate from ContinuityStore, Provider Trust
Graph, and the upstream evidence contracts.  It stores only independently
verified digests, bounded authorization/evaluator material, and its own
append-only observation chain.  Synthetic fixture implementations live in
``controlled_shadow_runtime_fixtures.py``; this module provides only ports.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from typing import Callable, Mapping, Protocol, runtime_checkable

from app.mirror import controlled_shadow_runtime_independent as independent
from app.mirror import restore_publication


SCOPE = "MIRROR_CONTROLLED_SHADOW_READ_ONLY"
STATUS = "SOFTWARE_RUNTIME_EXECUTED"
FAULT_POINTS = (
    "before_transaction", "after_begin", "after_transition_insert", "after_operation_insert",
    "before_commit", "after_commit_before_response",
)


class ControlledShadowRuntimeError(ValueError):
    """Base class for bounded runtime errors."""


class RuntimeConflictError(ControlledShadowRuntimeError):
    pass


class RuntimeBusyError(ControlledShadowRuntimeError):
    pass


class RuntimeInjectedFault(ControlledShadowRuntimeError):
    pass


class RuntimeResponseLost(ControlledShadowRuntimeError):
    def __init__(self, operation_id: str) -> None:
        self.operation_id = operation_id
        super().__init__(f"runtime:response-lost:{operation_id}")


class RuntimeAuthorizationError(ControlledShadowRuntimeError):
    pass


class RuntimeIntegrityError(ControlledShadowRuntimeError):
    pass


class RuntimeEvaluatorRetryable(ControlledShadowRuntimeError):
    def __init__(self, code: str) -> None:
        if code not in independent.FAILURE_CODES:
            raise ValueError("runtime:failure-code")
        self.code = code
        super().__init__(f"runtime:evaluator-retryable:{code}")


class RuntimeLeaseError(RuntimeConflictError):
    pass


@runtime_checkable
class Clock(Protocol):
    def now(self) -> int: ...


@runtime_checkable
class ControlledShadowAuthorizationVerifier(Protocol):
    verifier_id: str
    verifier_epoch: int
    mode: str
    fixture_only: bool

    def verify(self, input_raw: bytes) -> "VerifiedShadowAuthorizationV1": ...


@runtime_checkable
class ShadowEvaluatorPort(Protocol):
    evaluator_id: str
    evaluator_epoch: int

    def evaluate(self, input_raw: bytes) -> "VerifiedShadowEvaluationV1": ...


@dataclass(frozen=True)
class ControlledShadowRuntimeProfileV1:
    profile_id: str
    version: int
    runtime_id_domain: str
    source_policy_digest: str
    quarantine_policy_digest: str
    quarantine_artifact_id: str
    quarantine_head_artifact_id: str
    quarantine_head_root: str
    governance_policy_digest: str
    governance_artifact_id: str
    governance_evidence_digest: str
    governance_decision: str
    privacy_policy_digest: str
    privacy_artifact_id: str
    privacy_evidence_digest: str
    privacy_decision: str
    support_decision: str
    authorization_verifier_id: str
    authorization_verifier_epoch: int
    evaluator_id: str
    evaluator_epoch: int
    scope: str = SCOPE
    authorization_effective_start: int = 1_000
    authorization_effective_end: int = 2_000
    cadence_seconds: int = 10
    freshness_grace_seconds: int = 60
    lease_seconds: int = 20
    max_observations: int = 3
    minimum_completed_observations: int = 2
    max_evaluator_input_bytes: int = 8_192
    max_evaluator_output_bytes: int = 8_192
    busy_timeout_ms: int = independent.BUSY_TIMEOUT_MS
    max_attempts: int = 3
    max_sessions: int = 4
    max_worker_concurrency: int = 2
    allowed_pause_reasons: tuple[str, ...] = independent.PAUSE_REASONS
    allowed_abort_reasons: tuple[str, ...] = independent.ABORT_REASONS
    allowed_failure_codes: tuple[str, ...] = independent.FAILURE_CODES
    zero_phi: bool = True
    state_owned: bool = True
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
            "runtime_id_domain": self.runtime_id_domain,
            "source_policy_digest": self.source_policy_digest,
            "quarantine_policy_digest": self.quarantine_policy_digest,
            "quarantine_artifact_id": self.quarantine_artifact_id,
            "quarantine_head_artifact_id": self.quarantine_head_artifact_id,
            "quarantine_head_root": self.quarantine_head_root,
            "governance_policy_digest": self.governance_policy_digest,
            "governance_artifact_id": self.governance_artifact_id,
            "governance_evidence_digest": self.governance_evidence_digest,
            "governance_decision": self.governance_decision,
            "privacy_policy_digest": self.privacy_policy_digest,
            "privacy_artifact_id": self.privacy_artifact_id,
            "privacy_evidence_digest": self.privacy_evidence_digest,
            "privacy_decision": self.privacy_decision,
            "support_decision": self.support_decision,
            "authorization_verifier_id": self.authorization_verifier_id,
            "authorization_verifier_epoch": self.authorization_verifier_epoch,
            "evaluator_id": self.evaluator_id,
            "evaluator_epoch": self.evaluator_epoch,
            "scope": self.scope,
            "authorization_effective_start": self.authorization_effective_start,
            "authorization_effective_end": self.authorization_effective_end,
            "cadence_seconds": self.cadence_seconds,
            "freshness_grace_seconds": self.freshness_grace_seconds,
            "lease_seconds": self.lease_seconds,
            "max_observations": self.max_observations,
            "minimum_completed_observations": self.minimum_completed_observations,
            "max_evaluator_input_bytes": self.max_evaluator_input_bytes,
            "max_evaluator_output_bytes": self.max_evaluator_output_bytes,
            "busy_timeout_ms": self.busy_timeout_ms,
            "max_attempts": self.max_attempts,
            "max_sessions": self.max_sessions,
            "max_worker_concurrency": self.max_worker_concurrency,
            "allowed_pause_reasons": list(self.allowed_pause_reasons),
            "allowed_abort_reasons": list(self.allowed_abort_reasons),
            "allowed_failure_codes": list(self.allowed_failure_codes),
            "zero_phi": self.zero_phi,
            "state_owned": self.state_owned,
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
        except independent.IndependentControlledShadowError as exc:
            raise ControlledShadowRuntimeError(str(exc)) from exc


@dataclass(frozen=True)
class RuntimeUpstreamBundleV1:
    source_policy: Mapping[str, object]
    quarantine_raw: bytes
    quarantine_head: Mapping[str, object]
    governance_policy: Mapping[str, object]
    governance_raw: bytes
    governance_evidence_raw: bytes
    privacy_policy: Mapping[str, object]
    privacy_raw: bytes
    privacy_evidence_raw: bytes

    def snapshot(self) -> dict[str, object]:
        return {
            "source_policy": deepcopy(dict(self.source_policy)),
            "quarantine_raw": bytes(self.quarantine_raw),
            "quarantine_head": deepcopy(dict(self.quarantine_head)),
            "governance_policy": deepcopy(dict(self.governance_policy)),
            "governance_raw": bytes(self.governance_raw),
            "governance_evidence_raw": bytes(self.governance_evidence_raw),
            "privacy_policy": deepcopy(dict(self.privacy_policy)),
            "privacy_raw": bytes(self.privacy_raw),
            "privacy_evidence_raw": bytes(self.privacy_evidence_raw),
        }


@dataclass(frozen=True)
class VerifiedShadowAuthorizationV1:
    authorization_id: str
    evidence_sha3_512: str
    evidence_byte_length: int
    profile_digest: str
    manifest_digest: str
    source_policy_digest: str
    scope: str
    mode: str
    terms_digest: str
    retention_policy_digest: str
    revocation_head_digest: str
    authority_identity_digest: str
    valid_from: int
    valid_until: int
    observed_at: int
    verifier_id: str
    verifier_epoch: int
    external_authority_authenticated: bool
    zero_phi: bool
    state_owned: bool

    def material(self) -> dict[str, object]:
        return {
            "authorization_id": self.authorization_id,
            "evidence_sha3_512": self.evidence_sha3_512,
            "evidence_byte_length": self.evidence_byte_length,
            "profile_digest": self.profile_digest,
            "manifest_digest": self.manifest_digest,
            "source_policy_digest": self.source_policy_digest,
            "scope": self.scope,
            "mode": self.mode,
            "terms_digest": self.terms_digest,
            "retention_policy_digest": self.retention_policy_digest,
            "revocation_head_digest": self.revocation_head_digest,
            "authority_identity_digest": self.authority_identity_digest,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "observed_at": self.observed_at,
            "verifier_id": self.verifier_id,
            "verifier_epoch": self.verifier_epoch,
            "external_authority_authenticated": self.external_authority_authenticated,
            "zero_phi": self.zero_phi,
            "state_owned": self.state_owned,
        }


@dataclass(frozen=True)
class VerifiedShadowEvaluationV1:
    session_id: str
    profile_digest: str
    slot_number: int
    attempt: int
    input_digest: str
    evaluator_id: str
    evaluator_epoch: int
    result: str
    aggregate: Mapping[str, int]
    observed_at: int
    completed_at: int
    zero_phi: bool
    result_digest: str

    def material(self) -> dict[str, object]:
        return {
            "session_id": self.session_id,
            "profile_digest": self.profile_digest,
            "slot_number": self.slot_number,
            "attempt": self.attempt,
            "input_digest": self.input_digest,
            "evaluator_id": self.evaluator_id,
            "evaluator_epoch": self.evaluator_epoch,
            "result": self.result,
            "aggregate": dict(self.aggregate),
            "observed_at": self.observed_at,
            "completed_at": self.completed_at,
            "zero_phi": self.zero_phi,
            "result_digest": self.result_digest,
        }


@dataclass(frozen=True)
class ObservationClaim:
    session_id: str
    slot_number: int
    attempt: int
    input_digest: str
    input_raw: bytes
    lease_token_digest: str
    head_root: str
    operation_id: str


def _canonical(value: object) -> bytes:
    return independent._canonical(value)


def _digest(label: str, value: object) -> str:
    return independent._digest(label, value)


def _raw_digest(raw: bytes) -> str:
    return independent._raw_digest(raw)


def _parse(raw: bytes) -> dict[str, object]:
    return independent._parse(raw, maximum=independent.MAX_EXPORT_BYTES)


def _token(value: str, label: str) -> str:
    try:
        return independent._text(value, label, token=True)
    except independent.IndependentControlledShadowError as exc:
        raise ControlledShadowRuntimeError(str(exc)) from exc


def _hex(value: str, label: str) -> str:
    try:
        return independent._hex(value, label)
    except independent.IndependentControlledShadowError as exc:
        raise ControlledShadowRuntimeError(str(exc)) from exc


class ControlledShadowRuntimeService:
    """One profile-owned SQLite runtime with an independent state chain."""

    def __init__(
        self,
        database: str | Path,
        *,
        profile: ControlledShadowRuntimeProfileV1,
        clock: Clock,
        fault_injector: Callable[[str], None] | None = None,
    ) -> None:
        self.database = Path(database)
        if self.database.name in ("", ".", "..") or not self.database.parent.exists():
            raise ControlledShadowRuntimeError("runtime:database-path")
        if not isinstance(clock, Clock):
            raise ControlledShadowRuntimeError("runtime:clock")
        self.profile = profile
        self.profile_material = profile.material()
        self.profile_digest = profile.digest
        self.clock = clock
        self.fault_injector = fault_injector
        self._initialize()

    def _fault(self, point: str) -> None:
        if self.fault_injector is not None:
            self.fault_injector(point)

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(self.database, timeout=self.profile.busy_timeout_ms / 1000.0, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute(f"PRAGMA busy_timeout={self.profile.busy_timeout_ms}")
            journal = connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if str(journal).lower() != "wal":
                connection.close()
                raise ControlledShadowRuntimeError("runtime:wal-required")
            connection.execute("PRAGMA synchronous=FULL")
            return connection
        except sqlite3.OperationalError as exc:
            raise RuntimeBusyError("runtime:busy") from exc
        except ControlledShadowRuntimeError:
            raise
        except (sqlite3.Error, OSError) as exc:
            raise ControlledShadowRuntimeError("runtime:database-open") from exc

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            tables = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            if not tables:
                connection.execute("BEGIN IMMEDIATE")
                for statement in (
                    "CREATE TABLE runtime_meta(key TEXT NOT NULL PRIMARY KEY,value TEXT NOT NULL)",
                    "CREATE TABLE runtime_sessions(session_id TEXT NOT NULL PRIMARY KEY,profile_digest TEXT NOT NULL,manifest_digest TEXT NOT NULL,manifest_material BLOB NOT NULL,authorization_id TEXT NOT NULL,authorization_material BLOB NOT NULL,mode TEXT NOT NULL,state TEXT NOT NULL,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,session_head_root TEXT NOT NULL,last_sequence INTEGER NOT NULL,flags_raw BLOB NOT NULL)",
                    "CREATE TABLE runtime_operations(operation_id TEXT NOT NULL PRIMARY KEY,session_id TEXT NOT NULL,action TEXT NOT NULL,request_raw BLOB NOT NULL,request_hash TEXT NOT NULL,transition_sequence INTEGER NOT NULL,transition_id TEXT NOT NULL,receipt_raw BLOB NOT NULL,receipt_hash TEXT NOT NULL,before_global_root TEXT NOT NULL,after_global_root TEXT NOT NULL,FOREIGN KEY(session_id) REFERENCES runtime_sessions(session_id),FOREIGN KEY(transition_sequence) REFERENCES runtime_transitions(sequence))",
                    "CREATE TABLE runtime_transitions(sequence INTEGER NOT NULL PRIMARY KEY,session_id TEXT NOT NULL,action TEXT NOT NULL,operation_id TEXT NOT NULL UNIQUE,transition_id TEXT NOT NULL UNIQUE,payload_raw BLOB NOT NULL,before_session_root TEXT NOT NULL,after_session_root TEXT NOT NULL,before_global_root TEXT NOT NULL,after_global_root TEXT NOT NULL,FOREIGN KEY(session_id) REFERENCES runtime_sessions(session_id))",
                    "CREATE TABLE runtime_slots(session_id TEXT NOT NULL,slot_number INTEGER NOT NULL,attempt INTEGER NOT NULL,state TEXT NOT NULL,input_digest TEXT NOT NULL,worker_digest TEXT NOT NULL,lease_token_digest TEXT NOT NULL,lease_expires_at INTEGER NOT NULL,due_at INTEGER NOT NULL,result_raw BLOB,result_digest TEXT,observed_at INTEGER,completed_at INTEGER,last_failure_code TEXT,PRIMARY KEY(session_id,slot_number),FOREIGN KEY(session_id) REFERENCES runtime_sessions(session_id))",
                    "CREATE TABLE runtime_discrepancies(session_id TEXT NOT NULL,slot_number INTEGER NOT NULL,result_digest TEXT NOT NULL,aggregate_raw BLOB NOT NULL,code TEXT NOT NULL,PRIMARY KEY(session_id,slot_number),FOREIGN KEY(session_id) REFERENCES runtime_sessions(session_id))",
                ):
                    connection.execute(statement)
                genesis = independent._genesis_root(self.profile_digest)
                chain_id = _digest("runtime-chain", {"profile_digest": self.profile_digest})
                values = {
                    "schema": independent.SCHEMA,
                    "schema_version": str(independent.SCHEMA_VERSION),
                    "profile_digest": self.profile_digest,
                    "profile_json": _canonical(self.profile_material).decode("ascii"),
                    "chain_id": chain_id,
                    "global_sequence": "0",
                    "global_head_root": genesis,
                    "flags_json": _canonical(independent.FIXED_FLAGS).decode("ascii"),
                }
                for key in sorted(values):
                    connection.execute("INSERT INTO runtime_meta(key,value) VALUES(?,?)", (key, values[key]))
                connection.commit()
            elif tables != set(independent.TABLES):
                raise ControlledShadowRuntimeError("runtime:database-schema")
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()
        try:
            independent.verify_database(self.database, profile=self.profile_material)
        except independent.IndependentControlledShadowError as exc:
            raise ControlledShadowRuntimeError(str(exc)) from exc

    @staticmethod
    def _meta(connection: sqlite3.Connection) -> dict[str, str]:
        return {str(row["key"]): str(row["value"]) for row in connection.execute("SELECT key,value FROM runtime_meta ORDER BY key")}

    @staticmethod
    def _session(connection: sqlite3.Connection, session_id: str) -> dict[str, object] | None:
        row = connection.execute("SELECT * FROM runtime_sessions WHERE session_id=?", (session_id,)).fetchone()
        return dict(row) if row is not None else None

    @staticmethod
    def _request(operation_id: str, action: str, session_id: str, body: Mapping[str, object]) -> bytes:
        return _canonical({"schema": "mirror-controlled-shadow-request-v1", "action": action, "session_id": session_id, "operation_id": operation_id, "body": dict(body)})

    @staticmethod
    def _existing_operation(connection: sqlite3.Connection, operation_id: str, request_raw: bytes) -> dict[str, object] | None:
        row = connection.execute("SELECT * FROM runtime_operations WHERE operation_id=?", (operation_id,)).fetchone()
        if row is None:
            return None
        if bytes(row["request_raw"]) != request_raw or row["request_hash"] != _raw_digest(request_raw):
            raise RuntimeConflictError("runtime:operation-conflict")
        try:
            receipt_raw = bytes(row["receipt_raw"])
            receipt = _parse(receipt_raw)
            return {"receipt_raw": receipt_raw, "receipt": receipt, "state": receipt["state"], "head_root": receipt["after_session_root"]}
        except Exception as exc:
            raise RuntimeIntegrityError("runtime:receipt-corrupt") from exc

    def _run_mutation(self, operation_id: str, callback: Callable[[sqlite3.Connection], dict[str, object]]) -> dict[str, object]:
        self._fault("before_transaction")
        connection = self._connect()
        committed = False
        try:
            try:
                connection.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                raise RuntimeBusyError("runtime:busy") from exc
            self._fault("after_begin")
            result = callback(connection)
            self._fault("before_commit")
            connection.commit()
            committed = True
            try:
                self._fault("after_commit_before_response")
            except RuntimeInjectedFault as exc:
                raise RuntimeResponseLost(operation_id) from exc
            return result
        except RuntimeResponseLost:
            raise
        except (RuntimeInjectedFault, RuntimeConflictError, RuntimeBusyError, RuntimeAuthorizationError, RuntimeIntegrityError, ControlledShadowRuntimeError):
            if not committed and connection.in_transaction:
                connection.rollback()
            raise
        except sqlite3.IntegrityError as exc:
            if not committed and connection.in_transaction:
                connection.rollback()
            raise RuntimeConflictError("runtime:integrity") from exc
        except sqlite3.OperationalError as exc:
            if not committed and connection.in_transaction:
                connection.rollback()
            if "busy" in str(exc).lower() or "locked" in str(exc).lower():
                raise RuntimeBusyError("runtime:busy") from exc
            raise ControlledShadowRuntimeError("runtime:operational") from exc
        finally:
            connection.close()

    def _append_locked(
        self,
        connection: sqlite3.Connection,
        *,
        operation_id: str,
        request_raw: bytes,
        session_id: str,
        action: str,
        state_before: str,
        state_after: str,
        data: Mapping[str, object],
        details: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        meta = self._meta(connection)
        session = self._session(connection, session_id)
        if session is None:
            raise RuntimeConflictError("runtime:session-missing")
        sequence = int(meta["global_sequence"]) + 1
        before_session = str(session["session_head_root"])
        before_global = str(meta["global_head_root"])
        payload = {
            "schema": independent.TRANSITION_PAYLOAD_SCHEMA,
            "session_id": session_id,
            "action": action,
            "state_before": state_before,
            "state_after": state_after,
            "data": dict(data),
        }
        payload_raw = _canonical(payload)
        transition_id = independent._transition_id(sequence, session_id, action, payload, before_session, before_global)
        after_session = independent._session_after_root(sequence, session_id, transition_id, before_session)
        after_global = independent._global_after_root(sequence, transition_id, before_global)
        connection.execute(
            "INSERT INTO runtime_transitions VALUES(?,?,?,?,?,?,?,?,?,?)",
            (sequence, session_id, action, operation_id, transition_id, payload_raw, before_session, after_session, before_global, after_global),
        )
        self._fault("after_transition_insert")
        now = int(self.clock.now())
        connection.execute("UPDATE runtime_sessions SET state=?,updated_at=?,session_head_root=?,last_sequence=? WHERE session_id=?", (state_after, now, after_session, sequence, session_id))
        connection.execute("UPDATE runtime_meta SET value=? WHERE key='global_sequence'", (str(sequence),))
        connection.execute("UPDATE runtime_meta SET value=? WHERE key='global_head_root'", (after_global,))
        receipt_body = {
            "schema": "mirror-controlled-shadow-receipt-v1",
            "operation_id": operation_id,
            "action": action,
            "session_id": session_id,
            "transition_id": transition_id,
            "sequence": sequence,
            "state": state_after,
            "before_session_root": before_session,
            "after_session_root": after_session,
            "before_global_root": before_global,
            "after_global_root": after_global,
            "details": dict(details if details is not None else data),
            "flags": dict(independent.FIXED_FLAGS),
        }
        receipt_raw = _canonical(receipt_body)
        connection.execute(
            "INSERT INTO runtime_operations VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (operation_id, session_id, action, request_raw, _raw_digest(request_raw), sequence, transition_id, receipt_raw, _raw_digest(receipt_raw), before_global, after_global),
        )
        self._fault("after_operation_insert")
        return {"receipt_raw": receipt_raw, "receipt": receipt_body, "session_id": session_id, "head_root": after_session, "state": state_after}

    @staticmethod
    def _response(existing_or_new: Mapping[str, object]) -> dict[str, object]:
        return dict(existing_or_new)

    def _read_operation(self, operation_id: str) -> dict[str, object] | None:
        connection = self._connect()
        try:
            row = connection.execute("SELECT receipt_raw FROM runtime_operations WHERE operation_id=?", (operation_id,)).fetchone()
            if row is None:
                return None
            raw = bytes(row[0])
            return {"receipt_raw": raw, "receipt": _parse(raw)}
        except sqlite3.Error as exc:
            raise RuntimeBusyError("runtime:read-busy") from exc
        finally:
            connection.close()

    def _authorize(self, bundle: RuntimeUpstreamBundleV1, verifier: ControlledShadowAuthorizationVerifier) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
        snapshot = bundle.snapshot()
        try:
            upstream = independent.verify_upstream_bundle(snapshot, self.profile_material)
        except independent.IndependentControlledShadowError as exc:
            raise RuntimeAuthorizationError(str(exc)) from exc
        try:
            mode = verifier.mode
            verifier_id = verifier.verifier_id
            verifier_epoch = verifier.verifier_epoch
            fixture_only = verifier.fixture_only
        except AttributeError as exc:
            raise RuntimeAuthorizationError("runtime:authorization-verifier-config") from exc
        if mode not in independent.MODES:
            raise RuntimeAuthorizationError("runtime:authorization-mode")
        input_raw = independent.authorization_input(self.profile_material, upstream["manifest"])
        try:
            result = verifier.verify(bytes(input_raw))
        except Exception as exc:
            raise RuntimeAuthorizationError("runtime:authorization-verifier-failure") from exc
        if type(result) is not VerifiedShadowAuthorizationV1:
            raise RuntimeAuthorizationError("runtime:authorization-result-type")
        result_material = result.material()
        try:
            checked = independent.verify_authorization_result(
                result_material,
                profile=self.profile_material,
                manifest=upstream["manifest"],
                verifier_id=verifier_id,
                verifier_epoch=verifier_epoch,
                verifier_mode=mode,
                fixture_only=bool(fixture_only),
            )
        except independent.IndependentControlledShadowError as exc:
            raise RuntimeAuthorizationError(str(exc)) from exc
        return snapshot, upstream, checked

    def create_session(
        self,
        operation_id: str,
        session_key: str,
        bundle: RuntimeUpstreamBundleV1,
        verifier: ControlledShadowAuthorizationVerifier,
    ) -> dict[str, object]:
        _token(operation_id, "operation-id")
        _token(session_key, "session-key")
        snapshot, upstream, authorization = self._authorize(bundle, verifier)
        session_key_digest = _digest("runtime-session-key", {"value": session_key})
        session_id = _digest("runtime-session-id", {"profile_digest": self.profile_digest, "manifest_digest": upstream["manifest_digest"], "authorization_id": authorization["authorization_id"], "session_key_digest": session_key_digest})
        request_raw = self._request(operation_id, "OPEN", session_id, {"session_key_digest": session_key_digest, "manifest_digest": upstream["manifest_digest"], "authorization_id": authorization["authorization_id"], "mode": authorization["mode"]})

        def mutate(connection: sqlite3.Connection) -> dict[str, object]:
            existing = self._existing_operation(connection, operation_id, request_raw)
            if existing is not None:
                return self._response({**existing, "session_id": session_id})
            if self._session(connection, session_id) is not None:
                raise RuntimeConflictError("runtime:session-collision")
            count = int(connection.execute("SELECT COUNT(*) FROM runtime_sessions").fetchone()[0])
            if count >= self.profile.max_sessions:
                raise RuntimeConflictError("runtime:session-capacity")
            genesis = independent._genesis_root(self.profile_digest)
            now = int(self.clock.now())
            connection.execute("INSERT INTO runtime_sessions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", (session_id, self.profile_digest, upstream["manifest_digest"], _canonical(upstream["manifest"]), authorization["authorization_id"], _canonical(authorization), authorization["mode"], independent.STATE_OPEN, now, now, genesis, 0, _canonical(independent.FIXED_FLAGS)))
            return self._append_locked(connection, operation_id=operation_id, request_raw=request_raw, session_id=session_id, action="OPEN", state_before="ABSENT", state_after=independent.STATE_OPEN, data={"manifest_digest": upstream["manifest_digest"], "authorization_id": authorization["authorization_id"], "mode": authorization["mode"]})

        result = self._run_mutation(operation_id, mutate)
        result["session_id"] = session_id
        result["mode"] = authorization["mode"]
        result["status"] = STATUS
        return result

    def _simple_state_transition(self, operation_id: str, session_id: str, action: str, expected_head: str, allowed_before: str, after_state: str, data: Mapping[str, object]) -> dict[str, object]:
        _token(operation_id, "operation-id")
        _token(session_id, "session-id")
        _hex(expected_head, "expected-head")
        request_raw = self._request(operation_id, action, session_id, {"expected_head": expected_head, **dict(data)})

        def mutate(connection: sqlite3.Connection) -> dict[str, object]:
            existing = self._existing_operation(connection, operation_id, request_raw)
            if existing is not None:
                return existing
            session = self._session(connection, session_id)
            if session is None:
                raise RuntimeConflictError("runtime:session-missing")
            if session["session_head_root"] != expected_head:
                raise RuntimeConflictError("runtime:stale-head")
            if session["state"] != allowed_before:
                raise RuntimeConflictError("runtime:illegal-state")
            if action in ("START", "RESUME") and not self._authority_current(session):
                raise RuntimeConflictError("runtime:authority-expired")
            return self._append_locked(connection, operation_id=operation_id, request_raw=request_raw, session_id=session_id, action=action, state_before=allowed_before, state_after=after_state, data=data)

        return self._run_mutation(operation_id, mutate)

    def start_session(self, operation_id: str, session_id: str, *, expected_head: str) -> dict[str, object]:
        return self._simple_state_transition(operation_id, session_id, "START", expected_head, independent.STATE_OPEN, independent.STATE_RUNNING, {})

    def pause_session(self, operation_id: str, session_id: str, *, expected_head: str, reason: str) -> dict[str, object]:
        if reason not in self.profile.allowed_pause_reasons:
            raise RuntimeConflictError("runtime:pause-reason")
        return self._simple_state_transition(operation_id, session_id, "PAUSE", expected_head, independent.STATE_RUNNING, independent.STATE_PAUSED, {"reason": reason})

    def resume_session(self, operation_id: str, session_id: str, *, expected_head: str) -> dict[str, object]:
        return self._simple_state_transition(operation_id, session_id, "RESUME", expected_head, independent.STATE_PAUSED, independent.STATE_RUNNING, {})

    def abort_session(self, operation_id: str, session_id: str, *, expected_head: str, reason: str) -> dict[str, object]:
        if reason not in self.profile.allowed_abort_reasons:
            raise RuntimeConflictError("runtime:abort-reason")
        _token(operation_id, "operation-id")
        _token(session_id, "session-id")
        _hex(expected_head, "expected-head")
        request_raw = self._request(operation_id, "ABORT", session_id, {"expected_head": expected_head, "reason": reason})

        def mutate(connection: sqlite3.Connection) -> dict[str, object]:
            existing = self._existing_operation(connection, operation_id, request_raw)
            if existing is not None:
                return existing
            session = self._session(connection, session_id)
            if session is None or session["session_head_root"] != expected_head or session["state"] in independent.TERMINAL_STATES:
                raise RuntimeConflictError("runtime:illegal-abort")
            return self._append_locked(connection, operation_id=operation_id, request_raw=request_raw, session_id=session_id, action="ABORT", state_before=str(session["state"]), state_after=independent.STATE_ABORTED, data={"reason": reason})

        return self._run_mutation(operation_id, mutate)

    def _authority_current(self, session: Mapping[str, object]) -> bool:
        try:
            auth = _parse(bytes(session["authorization_material"]))
            return int(self.clock.now()) <= int(auth["valid_until"])
        except Exception as exc:
            raise RuntimeIntegrityError("runtime:authorization-material") from exc

    def claim_observation(self, operation_id: str, session_id: str, *, expected_head: str, worker_id: str = "SYNTHETIC_WORKER") -> ObservationClaim:
        _token(operation_id, "operation-id")
        _token(session_id, "session-id")
        _token(worker_id, "worker-id")
        _hex(expected_head, "expected-head")
        worker_digest = _digest("runtime-worker", {"worker_id": worker_id})
        request_raw = self._request(operation_id, "CLAIM_SLOT", session_id, {"expected_head": expected_head, "worker_digest": worker_digest})
        holder: dict[str, object] = {}

        def mutate(connection: sqlite3.Connection) -> dict[str, object]:
            existing = self._existing_operation(connection, operation_id, request_raw)
            if existing is not None:
                details = existing["receipt"].get("details")
                if not isinstance(details, dict):
                    raise RuntimeIntegrityError("runtime:claim-receipt")
                holder.update({"slot_number": details["slot_number"], "attempt": details["attempt"], "input_digest": details["input_digest"], "lease_token_digest": details["lease_token_digest"], "head_root": existing["receipt"]["after_session_root"]})
                return existing
            session = self._session(connection, session_id)
            if session is None or session["state"] != independent.STATE_RUNNING:
                raise RuntimeConflictError("runtime:claim-state")
            if session["session_head_root"] != expected_head:
                raise RuntimeConflictError("runtime:stale-head")
            if not self._authority_current(session):
                raise RuntimeConflictError("runtime:authority-expired")
            now = int(self.clock.now())
            expired_rows = connection.execute("SELECT slot_number FROM runtime_slots WHERE session_id=? AND state=? AND lease_expires_at<=? ORDER BY slot_number", (session_id, independent.SLOT_LEASED, now)).fetchall()
            for expired_row in expired_rows:
                connection.execute("UPDATE runtime_slots SET state=?,due_at=?,lease_expires_at=? WHERE session_id=? AND slot_number=?", (independent.SLOT_DUE, now, now, session_id, expired_row["slot_number"]))
            active = connection.execute("SELECT slot_number FROM runtime_slots WHERE session_id=? AND state=? AND lease_expires_at>?", (session_id, independent.SLOT_LEASED, now)).fetchone()
            if active is not None:
                raise RuntimeBusyError("runtime:slot-active")
            active_workers = int(connection.execute("SELECT COUNT(*) FROM runtime_slots WHERE state=? AND lease_expires_at>?", (independent.SLOT_LEASED, now)).fetchone()[0])
            if active_workers >= self.profile.max_worker_concurrency:
                raise RuntimeBusyError("runtime:worker-capacity")
            due = connection.execute("SELECT * FROM runtime_slots WHERE session_id=? AND state=? ORDER BY slot_number LIMIT 1", (session_id, independent.SLOT_DUE)).fetchone()
            expired_slot: int | None = None
            if due is not None:
                slot_number = int(due["slot_number"])
                attempt = int(due["attempt"]) + 1
                if attempt > self.profile.max_attempts:
                    raise RuntimeConflictError("runtime:attempts-exhausted")
                expired_slot = slot_number
            else:
                count = int(connection.execute("SELECT COUNT(*) FROM runtime_slots WHERE session_id=?", (session_id,)).fetchone()[0])
                if count >= self.profile.max_observations:
                    raise RuntimeConflictError("runtime:observation-capacity")
                slot_number = count
                attempt = 1
            manifest_material = _parse(bytes(session["manifest_material"]))
            input_raw = independent.evaluator_input(self.profile_material, manifest_material, session_id, slot_number, attempt, str(session["mode"]))
            input_digest = _raw_digest(input_raw)
            token_digest = _digest("runtime-lease", {"session_id": session_id, "slot_number": slot_number, "attempt": attempt, "worker_digest": worker_digest})
            expires = now + self.profile.lease_seconds
            data = {"slot_number": slot_number, "attempt": attempt, "input_digest": input_digest, "worker_digest": worker_digest, "lease_token_digest": token_digest, "lease_expires_at": expires, "expired_slot_number": expired_slot}
            if due is None:
                connection.execute("INSERT INTO runtime_slots(session_id,slot_number,attempt,state,input_digest,worker_digest,lease_token_digest,lease_expires_at,due_at,result_raw,result_digest,observed_at,completed_at,last_failure_code) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (session_id, slot_number, attempt, independent.SLOT_LEASED, input_digest, worker_digest, token_digest, expires, now, None, None, None, None, None))
            else:
                connection.execute("UPDATE runtime_slots SET attempt=?,state=?,input_digest=?,worker_digest=?,lease_token_digest=?,lease_expires_at=?,due_at=?,result_raw=NULL,result_digest=NULL,observed_at=NULL,completed_at=NULL WHERE session_id=? AND slot_number=?", (attempt, independent.SLOT_LEASED, input_digest, worker_digest, token_digest, expires, now, session_id, slot_number))
            result = self._append_locked(connection, operation_id=operation_id, request_raw=request_raw, session_id=session_id, action="CLAIM_SLOT", state_before=independent.STATE_RUNNING, state_after=independent.STATE_RUNNING, data=data, details=data)
            holder.update({"slot_number": slot_number, "attempt": attempt, "input_digest": input_digest, "lease_token_digest": token_digest, "head_root": result["head_root"], "input_raw": input_raw})
            return result

        result = self._run_mutation(operation_id, mutate)
        if "input_raw" not in holder:
            connection = self._connect()
            try:
                row = connection.execute("SELECT manifest_material FROM runtime_sessions WHERE session_id=?", (session_id,)).fetchone()
                if row is None:
                    raise RuntimeConflictError("runtime:session-missing")
                manifest = _parse(bytes(row[0]))
            finally:
                connection.close()
            holder["input_raw"] = independent.evaluator_input(self.profile_material, manifest, session_id, int(holder["slot_number"]), int(holder["attempt"]), self._session_mode(session_id))
        return ObservationClaim(session_id, int(holder["slot_number"]), int(holder["attempt"]), str(holder["input_digest"]), bytes(holder["input_raw"]), str(holder["lease_token_digest"]), str(holder["head_root"]), operation_id)

    def _session_mode(self, session_id: str) -> str:
        connection = self._connect()
        try:
            row = self._session(connection, session_id)
            if row is None:
                raise RuntimeConflictError("runtime:session-missing")
            return str(row["mode"])
        finally:
            connection.close()

    def complete_observation(self, operation_id: str, claim: ObservationClaim, result: VerifiedShadowEvaluationV1) -> dict[str, object]:
        _token(operation_id, "operation-id")
        expected = {"session_id": claim.session_id, "profile_digest": self.profile_digest, "slot_number": claim.slot_number, "attempt": claim.attempt, "input_digest": claim.input_digest}
        try:
            checked = independent.verify_evaluation_result(result.material(), expected=expected, evaluator_id=self.profile.evaluator_id, evaluator_epoch=self.profile.evaluator_epoch)
        except independent.IndependentControlledShadowError as exc:
            raise RuntimeIntegrityError(str(exc)) from exc
        if int(checked["completed_at"]) > int(self.clock.now()):
            raise RuntimeIntegrityError("runtime:evaluation-future")
        request_raw = self._request(operation_id, "COMPLETE_OBSERVATION", claim.session_id, {"expected_head": claim.head_root, "slot_number": claim.slot_number, "attempt": claim.attempt, "result_digest": checked["result_digest"]})

        def mutate(connection: sqlite3.Connection) -> dict[str, object]:
            existing = self._existing_operation(connection, operation_id, request_raw)
            if existing is not None:
                return existing
            session = self._session(connection, claim.session_id)
            if session is None or session["state"] != independent.STATE_RUNNING or session["session_head_root"] != claim.head_root:
                raise RuntimeLeaseError("runtime:stale-head")
            row = connection.execute("SELECT * FROM runtime_slots WHERE session_id=? AND slot_number=?", (claim.session_id, claim.slot_number)).fetchone()
            now = int(self.clock.now())
            if row is None or row["state"] != independent.SLOT_LEASED or int(row["attempt"]) != claim.attempt or row["lease_token_digest"] != claim.lease_token_digest or int(row["lease_expires_at"]) < now:
                raise RuntimeLeaseError("runtime:stale-lease")
            result_raw = _canonical(checked)
            connection.execute("UPDATE runtime_slots SET state=?,result_raw=?,result_digest=?,observed_at=?,completed_at=?,last_failure_code=NULL WHERE session_id=? AND slot_number=?", (independent.SLOT_COMPLETED, result_raw, checked["result_digest"], checked["observed_at"], checked["completed_at"], claim.session_id, claim.slot_number))
            if checked["result"] == "DISCREPANCY":
                connection.execute("INSERT INTO runtime_discrepancies VALUES(?,?,?,?,?)", (claim.session_id, claim.slot_number, checked["result_digest"], _canonical(checked["aggregate"]), "DISCREPANCY"))
            data = {"slot_number": claim.slot_number, "attempt": claim.attempt, "result": checked["result"], "result_digest": checked["result_digest"], "aggregate": checked["aggregate"]}
            return self._append_locked(connection, operation_id=operation_id, request_raw=request_raw, session_id=claim.session_id, action="COMPLETE_OBSERVATION", state_before=independent.STATE_RUNNING, state_after=independent.STATE_RUNNING, data=data, details=data)

        return self._run_mutation(operation_id, mutate)

    def _record_failure(self, operation_id: str, claim: ObservationClaim, code: str) -> dict[str, object]:
        if code not in self.profile.allowed_failure_codes:
            raise RuntimeIntegrityError("runtime:failure-code")
        request_raw = self._request(operation_id, "EVALUATOR_FAILURE", claim.session_id, {"expected_head": claim.head_root, "slot_number": claim.slot_number, "attempt": claim.attempt, "failure_code": code})

        def mutate(connection: sqlite3.Connection) -> dict[str, object]:
            existing = self._existing_operation(connection, operation_id, request_raw)
            if existing is not None:
                return existing
            session = self._session(connection, claim.session_id)
            if session is None or session["state"] != independent.STATE_RUNNING or session["session_head_root"] != claim.head_root:
                raise RuntimeLeaseError("runtime:stale-head")
            row = connection.execute("SELECT * FROM runtime_slots WHERE session_id=? AND slot_number=?", (claim.session_id, claim.slot_number)).fetchone()
            if row is None or row["state"] != independent.SLOT_LEASED or int(row["attempt"]) != claim.attempt or row["lease_token_digest"] != claim.lease_token_digest:
                raise RuntimeLeaseError("runtime:stale-lease")
            pause = code == "EVALUATOR_INVALID" or claim.attempt >= self.profile.max_attempts
            next_slot = independent.SLOT_FAILED if pause else independent.SLOT_DUE
            next_state = independent.STATE_PAUSED if pause else independent.STATE_RUNNING
            connection.execute("UPDATE runtime_slots SET state=?,last_failure_code=?,due_at=?,lease_expires_at=? WHERE session_id=? AND slot_number=?", (next_slot, code, int(self.clock.now()), int(self.clock.now()), claim.session_id, claim.slot_number))
            data = {"slot_number": claim.slot_number, "attempt": claim.attempt, "failure_code": code, "next_slot_state": next_slot}
            return self._append_locked(connection, operation_id=operation_id, request_raw=request_raw, session_id=claim.session_id, action="EVALUATOR_FAILURE", state_before=independent.STATE_RUNNING, state_after=next_state, data=data, details=data)

        return self._run_mutation(operation_id, mutate)

    def run_observation(self, operation_id: str, session_id: str, *, expected_head: str, evaluator: ShadowEvaluatorPort, worker_id: str = "SYNTHETIC_WORKER") -> dict[str, object]:
        _token(operation_id, "operation-id")
        existing = self._read_operation(operation_id)
        if existing is not None:
            return existing
        claim = self.claim_observation(operation_id + "::claim", session_id, expected_head=expected_head, worker_id=worker_id)
        try:
            if evaluator.evaluator_id != self.profile.evaluator_id or evaluator.evaluator_epoch != self.profile.evaluator_epoch:
                raise RuntimeIntegrityError("runtime:evaluator-config")
            result = evaluator.evaluate(bytes(claim.input_raw))
            if type(result) is not VerifiedShadowEvaluationV1:
                raise RuntimeIntegrityError("runtime:evaluator-result-type")
            try:
                independent.verify_evaluation_result(
                    result.material(),
                    expected={"session_id": claim.session_id, "profile_digest": self.profile_digest, "slot_number": claim.slot_number, "attempt": claim.attempt, "input_digest": claim.input_digest},
                    evaluator_id=self.profile.evaluator_id,
                    evaluator_epoch=self.profile.evaluator_epoch,
                )
            except independent.IndependentControlledShadowError as exc:
                raise RuntimeIntegrityError(str(exc)) from exc
            if int(result.completed_at) > int(self.clock.now()):
                raise RuntimeIntegrityError("runtime:evaluation-future")
        except RuntimeEvaluatorRetryable as exc:
            return self._record_failure(operation_id, claim, exc.code)
        except TimeoutError:
            return self._record_failure(operation_id, claim, "EVALUATOR_TIMEOUT")
        except RuntimeIntegrityError:
            return self._record_failure(operation_id, claim, "EVALUATOR_INVALID")
        except Exception:
            return self._record_failure(operation_id, claim, "EVALUATOR_EXCEPTION")
        # Completion is a separate authority crossing. Stale heads, lease
        # tokens, and result bindings must propagate as fail-closed runtime
        # errors; they must never be converted into an evaluator failure.
        return self.complete_observation(operation_id, claim, result)

    def complete_session(self, operation_id: str, session_id: str, *, expected_head: str) -> dict[str, object]:
        _token(operation_id, "operation-id")
        _token(session_id, "session-id")
        _hex(expected_head, "expected-head")
        request_raw = self._request(operation_id, "COMPLETE_SESSION", session_id, {"expected_head": expected_head})

        def mutate(connection: sqlite3.Connection) -> dict[str, object]:
            existing = self._existing_operation(connection, operation_id, request_raw)
            if existing is not None:
                return existing
            session = self._session(connection, session_id)
            if session is None or session["state"] != independent.STATE_RUNNING or session["session_head_root"] != expected_head:
                raise RuntimeConflictError("runtime:completion-state")
            if not self._authority_current(session):
                raise RuntimeConflictError("runtime:authority-expired")
            rows = [dict(row) for row in connection.execute("SELECT * FROM runtime_slots WHERE session_id=? ORDER BY slot_number", (session_id,))]
            completed = [row for row in rows if row["state"] == independent.SLOT_COMPLETED]
            if len(completed) < self.profile.minimum_completed_observations or any(row["state"] == independent.SLOT_LEASED for row in rows):
                raise RuntimeConflictError("runtime:completion-requirements")
            times = [int(row["completed_at"]) for row in completed]
            if any(right - left < self.profile.cadence_seconds for left, right in zip(times, times[1:])) or int(self.clock.now()) - times[-1] > self.profile.freshness_grace_seconds:
                raise RuntimeConflictError("runtime:cadence-or-freshness")
            data = {"completed_observations": len(completed)}
            return self._append_locked(connection, operation_id=operation_id, request_raw=request_raw, session_id=session_id, action="COMPLETE_SESSION", state_before=independent.STATE_RUNNING, state_after=independent.STATE_COMPLETED, data=data)

        return self._run_mutation(operation_id, mutate)

    def integrity(self) -> dict[str, object]:
        try:
            return independent.verify_database(self.database, profile=self.profile_material)
        except independent.IndependentControlledShadowError as exc:
            raise RuntimeIntegrityError(str(exc)) from exc

    def export_bytes(self) -> bytes:
        try:
            snapshot_result = independent.snapshot_database(self.database, profile=self.profile_material)
            tables = independent._export_rows(snapshot_result["snapshot"])
        except independent.IndependentControlledShadowError as exc:
            raise RuntimeIntegrityError(str(exc)) from exc
        body: dict[str, object] = {
            "schema": independent.EXPORT_SCHEMA,
            "schema_version": independent.EXPORT_VERSION,
            "profile": self.profile_material,
            "profile_digest": self.profile_digest,
            "tables": tables,
            "flags": dict(independent.FIXED_FLAGS),
        }
        body["export_root"] = _digest("runtime-export-root", body)
        raw = _canonical(body)
        if len(raw) > independent.MAX_EXPORT_BYTES:
            raise ControlledShadowRuntimeError("runtime:export-byte-cap")
        try:
            independent.verify_export_bytes(raw, profile=self.profile_material)
        except independent.IndependentControlledShadowError as exc:
            raise RuntimeIntegrityError(str(exc)) from exc
        return raw

    def support_snapshot(self) -> dict[str, object]:
        try:
            snapshot_result = independent.snapshot_database(self.database, profile=self.profile_material)
        except independent.IndependentControlledShadowError as exc:
            raise RuntimeIntegrityError(str(exc)) from exc
        evidence = {key: value for key, value in snapshot_result.items() if key != "snapshot"}
        rows = snapshot_result["snapshot"]
        failures = sorted({str(row["last_failure_code"]) for row in rows["runtime_slots"] if row["last_failure_code"] is not None})[:independent.MAX_SUPPORT_CODES]
        active_slots = sum(row["state"] == independent.SLOT_LEASED for row in rows["runtime_slots"])
        return {
            "schema": "mirror-controlled-shadow-runtime-support-v1",
            "schema_version": 1,
            "profile_version": self.profile.version,
            "global_sequence": evidence["global_sequence"],
            "session_count": evidence["session_count"],
            "state_counts": evidence["state_counts"],
            "slot_count": evidence["slot_count"],
            "active_slot_count": active_slots,
            "result_counts": evidence["result_counts"],
            "failure_codes": failures,
            "cadence_seconds": self.profile.cadence_seconds,
            "freshness_grace_seconds": self.profile.freshness_grace_seconds,
            "status": STATUS,
            "flags": dict(independent.SUPPORT_SAFE_FLAGS),
        }

    @classmethod
    def restore_export(
        cls,
        destination: str | Path,
        raw: bytes,
        *,
        profile: ControlledShadowRuntimeProfileV1,
        clock: Clock,
        fault_injector: Callable[[str], None] | None = None,
    ) -> "ControlledShadowRuntimeService":
        try:
            verified = independent.verify_export_bytes(raw, profile=profile.material())
        except independent.IndependentControlledShadowError as exc:
            raise RuntimeIntegrityError(str(exc)) from exc

        def build_stage(stage: Path) -> None:
            service = cls(stage, profile=profile, clock=clock)
            rows = verified["snapshot"]
            connection = service._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                for table in ("runtime_discrepancies", "runtime_slots", "runtime_operations", "runtime_transitions", "runtime_sessions", "runtime_meta"):
                    connection.execute(f"DELETE FROM {table}")
                for table in ("runtime_meta", "runtime_sessions", "runtime_transitions", "runtime_operations", "runtime_slots", "runtime_discrepancies"):
                    for row in rows[table]:
                        columns = independent.TABLE_COLUMNS[table]
                        placeholders = ",".join("?" for _ in columns)
                        connection.execute(f"INSERT INTO {table}({','.join(columns)}) VALUES({placeholders})", tuple(row[column] for column in columns))
                connection.commit()
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise
            finally:
                connection.close()

        def verify_database(path: Path) -> object:
            try:
                return independent.verify_database(path, profile=profile.material())
            except independent.IndependentControlledShadowError as exc:
                raise RuntimeIntegrityError(str(exc)) from exc

        def open_service(path: Path) -> ControlledShadowRuntimeService:
            return cls(path, profile=profile, clock=clock)

        try:
            return restore_publication.publish_create_only(
                destination, raw, expected_evidence=verified, build_stage=build_stage, verify_database=verify_database,
                open_service=open_service, fault_injector=fault_injector,
            )
        except restore_publication.RestorePublicationConflict as exc:
            raise RuntimeConflictError(str(exc)) from exc
        except (restore_publication.RestorePublicationError, RuntimeIntegrityError) as exc:
            raise RuntimeIntegrityError(str(exc)) from exc


def restore_export(destination: str | Path, raw: bytes, *, profile: ControlledShadowRuntimeProfileV1, clock: Clock, fault_injector: Callable[[str], None] | None = None) -> ControlledShadowRuntimeService:
    return ControlledShadowRuntimeService.restore_export(destination, raw, profile=profile, clock=clock, fault_injector=fault_injector)


__all__ = [
    "SCOPE", "STATUS", "FAULT_POINTS", "ControlledShadowRuntimeError", "RuntimeConflictError", "RuntimeBusyError",
    "RuntimeInjectedFault", "RuntimeResponseLost", "RuntimeAuthorizationError", "RuntimeIntegrityError", "RuntimeEvaluatorRetryable",
    "RuntimeLeaseError", "Clock", "ControlledShadowAuthorizationVerifier", "ShadowEvaluatorPort",
    "ControlledShadowRuntimeProfileV1", "RuntimeUpstreamBundleV1", "VerifiedShadowAuthorizationV1", "VerifiedShadowEvaluationV1",
    "ObservationClaim", "ControlledShadowRuntimeService", "restore_export",
]
