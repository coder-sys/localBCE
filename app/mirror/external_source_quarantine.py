"""Durable, state-owned quarantine for independently verified source artifacts.

The quarantine is intentionally a terminal evidence boundary: every admitted
artifact is durably ``QUARANTINED`` and can only be superseded or explicitly
withdrawn.  This module owns the SQLite mutation and lifecycle.  It does not
call ContinuityStore, Provider Trust Graph, qualification, network code, or
any payment/clearance path.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
from typing import Callable, Mapping

from app.mirror import external_source_adapter_independent as adapter
from app.mirror import external_source_quarantine_independent as independent


SCHEMA = independent.SCHEMA
SCHEMA_VERSION = independent.SCHEMA_VERSION
EXPORT_SCHEMA = independent.EXPORT_SCHEMA
EXPORT_VERSION = independent.EXPORT_VERSION
QUARANTINE_STATUS = independent.QUARANTINE_STATUS
ACTION_ADMIT = independent.ACTION_ADMIT
ACTION_SUPERSEDE = independent.ACTION_SUPERSEDE
ACTION_WITHDRAW = independent.ACTION_WITHDRAW
WITHDRAW_REASONS = independent.WITHDRAW_REASONS
GENESIS_TRANSITION = independent.GENESIS_TRANSITION
BUSY_TIMEOUT_MS = independent.BUSY_TIMEOUT_MS
MAX_ARTIFACT_BYTES = adapter.MAX_ARTIFACT_BYTES
MAX_EXPORT_BYTES = independent.MAX_EXPORT_BYTES
SAFE_REQUEST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
DOMAIN = "BL/MIRROR/EXTERNAL_SOURCE_QUARANTINE/"

DDL = (
    "CREATE TABLE quarantine_meta ("
    "key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    "CREATE TABLE quarantine_artifacts ("
    "policy_digest TEXT NOT NULL, artifact_id TEXT NOT NULL, capture_id TEXT NOT NULL, "
    "artifact_digest TEXT NOT NULL, artifact_raw BLOB NOT NULL, status TEXT NOT NULL, "
    "observed_at INTEGER NOT NULL, fetched_at INTEGER NOT NULL, "
    "PRIMARY KEY(policy_digest, artifact_id), UNIQUE(policy_digest, capture_id))",
    "CREATE TABLE quarantine_operations ("
    "operation_id TEXT PRIMARY KEY, policy_digest TEXT NOT NULL, action TEXT NOT NULL, "
    "request_digest TEXT NOT NULL, request_material_digest TEXT NOT NULL, artifact_id TEXT NOT NULL, "
    "expected_head TEXT NOT NULL DEFAULT '', reason TEXT NOT NULL DEFAULT '', transition_id TEXT NOT NULL, "
    "receipt_digest TEXT NOT NULL, sequence INTEGER NOT NULL, receipt_raw BLOB NOT NULL, "
    "FOREIGN KEY(policy_digest, artifact_id) REFERENCES quarantine_artifacts(policy_digest, artifact_id))",
    "CREATE TABLE quarantine_transitions ("
    "transition_id TEXT PRIMARY KEY, policy_digest TEXT NOT NULL, database_id TEXT NOT NULL, sequence INTEGER NOT NULL, action TEXT NOT NULL, "
    "artifact_id TEXT NOT NULL, prior_head TEXT NOT NULL DEFAULT '', next_head TEXT NOT NULL, "
    "prior_state TEXT NOT NULL, next_state TEXT NOT NULL, observed_at INTEGER NOT NULL, "
    "reason TEXT NOT NULL DEFAULT '', operation_id TEXT NOT NULL, before_root TEXT NOT NULL, after_root TEXT NOT NULL, "
    "transition_raw BLOB NOT NULL, "
    "FOREIGN KEY(policy_digest, artifact_id) REFERENCES quarantine_artifacts(policy_digest, artifact_id), "
    "FOREIGN KEY(operation_id) REFERENCES quarantine_operations(operation_id))",
    "CREATE TABLE quarantine_heads ("
    "policy_digest TEXT PRIMARY KEY, head_artifact_id TEXT NOT NULL, state TEXT NOT NULL, sequence INTEGER NOT NULL, "
    "head_root TEXT NOT NULL, head_transition_id TEXT NOT NULL, observed_at INTEGER NOT NULL, capture_id TEXT NOT NULL, "
    "FOREIGN KEY(policy_digest, head_artifact_id) REFERENCES quarantine_artifacts(policy_digest, artifact_id), "
    "FOREIGN KEY(head_transition_id) REFERENCES quarantine_transitions(transition_id))",
    "CREATE INDEX quarantine_artifacts_capture_idx ON quarantine_artifacts(policy_digest, capture_id)",
    "CREATE INDEX quarantine_operations_request_idx ON quarantine_operations(policy_digest, action, request_digest)",
    "CREATE INDEX quarantine_transitions_sequence_idx ON quarantine_transitions(sequence)",
)


FIXED_FLAGS = dict(independent.FIXED_FLAGS)


class ExternalSourceQuarantineError(ValueError):
    """Base class for bounded quarantine failures."""


class QuarantineConflictError(ExternalSourceQuarantineError):
    """A typed fail-closed identity, head, lifecycle, or integrity conflict."""


class QuarantineBusyError(ExternalSourceQuarantineError):
    """SQLite writer contention exceeded the finite configured wait."""


class QuarantineInjectedFault(ExternalSourceQuarantineError):
    """Test-only precommit fault; the transaction must roll back."""


class QuarantineResponseLost(ExternalSourceQuarantineError):
    """Test-only postcommit response loss; retry must recover the receipt."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ExternalSourceQuarantineError("quarantine:noncanonical") from exc


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _request_digest(request_key: str) -> str:
    if not isinstance(request_key, str) or SAFE_REQUEST.fullmatch(request_key) is None:
        raise ExternalSourceQuarantineError("quarantine:request-key")
    lowered = request_key.lower()
    if any(marker in lowered for marker in ("http://", "https://", "token", "secret", "password", "patient", "member", "claim", "npi", "email", "phone", "address")):
        raise ExternalSourceQuarantineError("quarantine:request-key-forbidden")
    return _digest("request", request_key)


def _head_selector(value: str | None) -> str:
    if value is None:
        return ""
    if not isinstance(value, str) or independent.HEX128.fullmatch(value) is None:
        raise QuarantineConflictError("quarantine:head-selector")
    return value


def _resolve_database(path: str | Path) -> Path:
    if not isinstance(path, (str, Path)):
        raise ExternalSourceQuarantineError("quarantine:database-path")
    try:
        value = os.fspath(path)
    except TypeError as exc:
        raise ExternalSourceQuarantineError("quarantine:database-path") from exc
    if isinstance(value, bytes) or not value:
        raise ExternalSourceQuarantineError("quarantine:database-path")
    target = Path(os.path.abspath(value))
    if not target.name or len(target.name.encode("utf-8")) > 128:
        raise ExternalSourceQuarantineError("quarantine:database-name")
    if target.is_symlink() or target.parent.is_symlink() or not target.parent.is_dir():
        raise ExternalSourceQuarantineError("quarantine:database-parent")
    return target


def _policy_material(policy: Mapping[str, object] | object) -> dict[str, object]:
    try:
        return independent._policy_view(policy)
    except independent.IndependentQuarantineError as exc:
        raise ExternalSourceQuarantineError(str(exc)) from exc


class ExternalSourceQuarantineService:
    """One configured policy's state-owned quarantine database."""

    def __init__(
        self,
        database: str | Path,
        *,
        policy: Mapping[str, object] | object,
        database_id: str,
        fault_injector: Callable[[str], None] | None = None,
    ) -> None:
        self.database = _resolve_database(database)
        self.policy = _policy_material(policy)
        self.policy_digest = independent._policy_digest(self.policy)
        try:
            self.database_id = independent._database_id(database_id)
        except independent.IndependentQuarantineError as exc:
            raise ExternalSourceQuarantineError(str(exc)) from exc
        self.chain_id = independent._chain_id(self.policy, self.database_id)
        self.fault_injector = fault_injector
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(self.database, timeout=BUSY_TIMEOUT_MS / 1000.0, isolation_level=None)
        except (sqlite3.Error, OSError) as exc:
            raise ExternalSourceQuarantineError("quarantine:database-open") from exc
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
            connection.execute("PRAGMA journal_mode=WAL")
        except sqlite3.OperationalError as exc:
            connection.close()
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise QuarantineBusyError("quarantine:busy") from exc
            raise ExternalSourceQuarantineError("quarantine:database-pragmas") from exc
        except sqlite3.Error as exc:
            connection.close()
            raise ExternalSourceQuarantineError("quarantine:database-pragmas") from exc
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            tables = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            if not tables:
                connection.execute("BEGIN IMMEDIATE")
                for statement in DDL:
                    connection.execute(statement)
                genesis = independent._genesis_root(self.chain_id)
                state_root = independent._state_root(self.chain_id, 0, genesis)
                values = {
                    "schema": SCHEMA,
                    "schema_version": str(SCHEMA_VERSION),
                    "policy_digest": self.policy_digest,
                    "database_id": self.database_id,
                    "chain_id": self.chain_id,
                    "sequence": "0",
                    "head_root": genesis,
                    "head_transition_id": GENESIS_TRANSITION,
                    "state_root": state_root,
                }
                for key in sorted(values):
                    connection.execute("INSERT INTO quarantine_meta(key,value) VALUES(?,?)", (key, values[key]))
                connection.commit()
            elif tables != set(independent.TABLE_COLUMNS):
                raise ExternalSourceQuarantineError("quarantine:database-schema")
        except ExternalSourceQuarantineError:
            if connection.in_transaction:
                connection.rollback()
            raise
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.rollback()
            raise ExternalSourceQuarantineError("quarantine:database-initialize") from exc
        finally:
            connection.close()
        # Opening an existing database is a read-only integrity gate.  It
        # prevents a restart from becoming an implicit repair operation.
        try:
            independent.verify_database(self.database, policy=self.policy, database_id=self.database_id)
        except independent.IndependentQuarantineError as exc:
            raise ExternalSourceQuarantineError(str(exc)) from exc

    def _fault(self, point: str) -> None:
        if self.fault_injector is not None:
            self.fault_injector(point)

    def _verify_artifact(self, artifact_raw: bytes) -> dict[str, object]:
        if type(artifact_raw) is not bytes or not artifact_raw or len(artifact_raw) > MAX_ARTIFACT_BYTES:
            raise ExternalSourceQuarantineError("quarantine:artifact-bytes")
        snapshot = bytes(artifact_raw)
        try:
            result = adapter.verify_artifact(snapshot, policy=self.policy)
            value = adapter._parse(snapshot)
        except Exception as exc:
            raise ExternalSourceQuarantineError(f"quarantine:adapter:{exc}") from exc
        capture = value.get("capture")
        if not isinstance(capture, dict) or type(capture.get("observed_at")) is not int or type(capture.get("fetched_at")) is not int:
            raise ExternalSourceQuarantineError("quarantine:artifact-capture")
        return {
            "raw": snapshot,
            "artifact_id": str(result["artifact_id"]),
            "capture_id": str(result["capture_id"]),
            "artifact_digest": hashlib.sha3_512(snapshot).hexdigest(),
            "observed_at": int(capture["observed_at"]),
            "fetched_at": int(capture["fetched_at"]),
            "source_status": str(result["derived_status"]),
            "payload_sha3_512": str(result["payload_sha3_512"]),
        }

    def _reverify_inside_transaction(self, candidate: Mapping[str, object]) -> None:
        checked = self._verify_artifact(candidate["raw"])  # type: ignore[arg-type]
        for key in ("artifact_id", "capture_id", "artifact_digest", "observed_at", "fetched_at", "payload_sha3_512"):
            if checked[key] != candidate[key]:
                raise QuarantineConflictError("quarantine:artifact-snapshot-drift")

    def _verify_stored_artifact(self, row: Mapping[str, object]) -> dict[str, object]:
        raw = row.get("artifact_raw")
        if type(raw) is not bytes:
            raise QuarantineConflictError("quarantine:head-artifact-integrity")
        checked = self._verify_artifact(raw)
        for key in ("artifact_id", "capture_id", "artifact_digest", "observed_at", "fetched_at"):
            if row.get(key) != checked[key]:
                raise QuarantineConflictError("quarantine:head-artifact-integrity")
        if row.get("status") != QUARANTINE_STATUS:
            raise QuarantineConflictError("quarantine:head-status")
        return checked

    @staticmethod
    def _metadata(connection: sqlite3.Connection) -> dict[str, str]:
        rows = connection.execute("SELECT key,value FROM quarantine_meta ORDER BY key").fetchall()
        return {str(row["key"]): str(row["value"]) for row in rows}

    @staticmethod
    def _head(connection: sqlite3.Connection) -> dict[str, object] | None:
        row = connection.execute("SELECT * FROM quarantine_heads ORDER BY policy_digest").fetchone()
        return dict(row) if row is not None else None

    @staticmethod
    def _operation_for_request(connection: sqlite3.Connection, policy_digest: str, request_digest: str) -> dict[str, object] | None:
        row = connection.execute(
            "SELECT * FROM quarantine_operations WHERE policy_digest=? AND request_digest=? ORDER BY sequence",
            (policy_digest, request_digest),
        ).fetchone()
        return dict(row) if row is not None else None

    def _result_from_operation(
        self,
        row: Mapping[str, object],
        *,
        connection: sqlite3.Connection | None = None,
    ) -> dict[str, object]:
        receipt = independent._parse(bytes(row["receipt_raw"]), maximum=MAX_EXPORT_BYTES)
        owned_connection = connection is None
        query_connection = connection or self._connect()
        try:
            artifact_row = query_connection.execute(
                "SELECT artifact_digest,capture_id FROM quarantine_artifacts WHERE policy_digest=? AND artifact_id=?",
                (self.policy_digest, row["artifact_id"]),
            ).fetchone()
        finally:
            if owned_connection:
                query_connection.close()
        if artifact_row is None:
            raise QuarantineConflictError("quarantine:receipt-artifact")
        return {
            "accepted": True,
            "operation_id": row["operation_id"],
            "action": row["action"],
            "policy_digest": self.policy_digest,
            "database_id": self.database_id,
            "chain_id": self.chain_id,
            "artifact_id": row["artifact_id"],
            "artifact_digest": artifact_row["artifact_digest"],
            "capture_id": artifact_row["capture_id"],
            "head_artifact_id": receipt["head_artifact_id"],
            "head_root": receipt["after_root"],
            "after_root": receipt["after_root"],
            "prior_head": receipt["prior_head"],
            "state": "WITHDRAWN" if row["action"] == ACTION_WITHDRAW else QUARANTINE_STATUS,
            "durable_status": QUARANTINE_STATUS,
            "sequence": row["sequence"],
            "transition_id": row["transition_id"],
            "receipt_raw": bytes(row["receipt_raw"]),
            "receipt_digest": row["receipt_digest"],
            "flags": dict(FIXED_FLAGS),
        }

    def _insert_transition(
        self,
        connection: sqlite3.Connection,
        *,
        operation_id: str,
        action: str,
        artifact: Mapping[str, object],
        expected_head: str,
        reason: str,
        prior_head: str,
        prior_state: str,
        sequence: int,
        before_root: str,
    ) -> dict[str, object]:
        next_state = "WITHDRAWN" if action == ACTION_WITHDRAW else QUARANTINE_STATUS
        body: dict[str, object] = {
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "transition_id": "",
            "sequence": sequence,
            "action": action,
            "policy_digest": self.policy_digest,
            "database_id": self.database_id,
            "artifact_id": artifact["artifact_id"],
            "prior_head": prior_head,
            "next_head": artifact["artifact_id"],
            "prior_state": prior_state,
            "next_state": next_state,
            "observed_at": artifact["observed_at"],
            "reason": reason,
            "operation_id": operation_id,
            "before_root": before_root,
            "after_root": "",
            "flags": dict(FIXED_FLAGS),
        }
        transition_id = independent._transition_id(body)
        body["transition_id"] = transition_id
        body["after_root"] = independent._after_root(
            self.chain_id, sequence, transition_id, str(artifact["artifact_id"]), next_state, before_root,
        )
        transition_raw = _canonical(body)
        return {
            "transition_id": transition_id,
            "raw": transition_raw,
            "sequence": sequence,
            "action": action,
            "prior_head": prior_head,
            "next_head": str(artifact["artifact_id"]),
            "prior_state": prior_state,
            "next_state": next_state,
            "observed_at": int(artifact["observed_at"]),
            "reason": reason,
            "before_root": before_root,
            "after_root": body["after_root"],
            "artifact_id": artifact["artifact_id"],
            "expected_head": expected_head,
        }

    def _insert_receipt(
        self,
        *,
        operation_id: str,
        action: str,
        artifact: Mapping[str, object],
        transition: Mapping[str, object],
        prior_head: str,
    ) -> tuple[bytes, str]:
        body: dict[str, object] = {
            "schema": f"{SCHEMA}-receipt",
            "schema_version": SCHEMA_VERSION,
            "receipt_id": "",
            "operation_id": operation_id,
            "action": action,
            "policy_digest": self.policy_digest,
            "artifact_id": artifact["artifact_id"],
            "capture_id": artifact["capture_id"],
            "prior_head": prior_head,
            "head_artifact_id": artifact["artifact_id"],
            "state": transition["next_state"],
            "sequence": transition["sequence"],
            "transition_id": transition["transition_id"],
            "before_root": transition["before_root"],
            "after_root": transition["after_root"],
            "chain_id": self.chain_id,
            "database_id": self.database_id,
            "flags": dict(FIXED_FLAGS),
        }
        body["receipt_id"] = independent._receipt_id(body)
        raw = _canonical(body)
        return raw, hashlib.sha3_512(raw).hexdigest()

    def _write_meta_and_head(
        self,
        connection: sqlite3.Connection,
        *,
        artifact: Mapping[str, object],
        transition: Mapping[str, object],
        sequence: int,
    ) -> None:
        after_root = str(transition["after_root"])
        state_root = independent._state_root(self.chain_id, sequence, after_root)
        connection.execute(
            "INSERT INTO quarantine_heads(policy_digest,head_artifact_id,state,sequence,head_root,head_transition_id,observed_at,capture_id) "
            "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(policy_digest) DO UPDATE SET head_artifact_id=excluded.head_artifact_id,state=excluded.state,sequence=excluded.sequence,head_root=excluded.head_root,head_transition_id=excluded.head_transition_id,observed_at=excluded.observed_at,capture_id=excluded.capture_id",
            (self.policy_digest, artifact["artifact_id"], transition["next_state"], sequence, after_root, transition["transition_id"], artifact["observed_at"], artifact["capture_id"]),
        )
        values = {
            "sequence": str(sequence),
            "head_root": after_root,
            "head_transition_id": str(transition["transition_id"]),
            "state_root": state_root,
        }
        for key, value in values.items():
            connection.execute("UPDATE quarantine_meta SET value=? WHERE key=?", (value, key))

    def _admit_locked(
        self,
        connection: sqlite3.Connection,
        *,
        candidate: Mapping[str, object],
        request_digest: str,
        expected_head: str,
    ) -> dict[str, object]:
        self._reverify_inside_transaction(candidate)
        existing_operation = self._operation_for_request(connection, self.policy_digest, request_digest)
        if existing_operation is not None:
            stored_material = independent._request_material_digest(
                operation_id=str(existing_operation["operation_id"]),
                policy_digest=self.policy_digest,
                artifact_id=str(candidate["artifact_id"]),
                expected_head=expected_head,
                reason="",
            )
            if stored_material != existing_operation["request_material_digest"] or existing_operation["artifact_id"] != candidate["artifact_id"]:
                raise QuarantineConflictError("quarantine:operation-conflict")
            stored_raw = connection.execute(
                "SELECT artifact_raw FROM quarantine_artifacts WHERE policy_digest=? AND artifact_id=?",
                (self.policy_digest, candidate["artifact_id"]),
            ).fetchone()
            if stored_raw is None or bytes(stored_raw[0]) != candidate["raw"]:
                raise QuarantineConflictError("quarantine:artifact-collision")
            return self._result_from_operation(existing_operation, connection=connection)
        head = self._head(connection)
        if head is None:
            action, prior_head, prior_state = ACTION_ADMIT, "", "EMPTY"
            if expected_head:
                raise QuarantineConflictError("quarantine:stale-head")
        else:
            if head["state"] == "WITHDRAWN":
                raise QuarantineConflictError("quarantine:withdrawn")
            if head["state"] != QUARANTINE_STATUS or expected_head != head["head_artifact_id"]:
                raise QuarantineConflictError("quarantine:stale-head")
            current_row = connection.execute(
                "SELECT * FROM quarantine_artifacts WHERE policy_digest=? AND artifact_id=?",
                (self.policy_digest, head["head_artifact_id"]),
            ).fetchone()
            if current_row is None:
                raise QuarantineConflictError("quarantine:head-artifact-missing")
            current_artifact = self._verify_stored_artifact(dict(current_row))
            if int(candidate["observed_at"]) <= int(head["observed_at"]):
                raise QuarantineConflictError("quarantine:out-of-order")
            if int(current_artifact["observed_at"]) != int(head["observed_at"]):
                raise QuarantineConflictError("quarantine:head-integrity")
            action, prior_head, prior_state = ACTION_SUPERSEDE, str(head["head_artifact_id"]), str(head["state"])
        existing_artifact = connection.execute(
            "SELECT artifact_id FROM quarantine_artifacts WHERE policy_digest=? AND artifact_id=?",
            (self.policy_digest, candidate["artifact_id"]),
        ).fetchone()
        if existing_artifact is not None:
            raise QuarantineConflictError("quarantine:artifact-collision")
        existing_capture = connection.execute(
            "SELECT artifact_id FROM quarantine_artifacts WHERE policy_digest=? AND capture_id=?",
            (self.policy_digest, candidate["capture_id"]),
        ).fetchone()
        if existing_capture is not None:
            raise QuarantineConflictError("quarantine:capture-collision")
        sequence = int(self._metadata(connection)["sequence"]) + 1
        operation_id = independent._operation_id(action, request_digest, self.database_id)
        request_material = independent._request_material_digest(
            operation_id=operation_id,
            policy_digest=self.policy_digest,
            artifact_id=str(candidate["artifact_id"]),
            expected_head=expected_head,
            reason="",
        )
        transition = self._insert_transition(
            connection,
            operation_id=operation_id,
            action=action,
            artifact=candidate,
            expected_head=expected_head,
            reason="",
            prior_head=prior_head,
            prior_state=prior_state,
            sequence=sequence,
            before_root=str(self._metadata(connection)["head_root"]),
        )
        receipt_raw, receipt_digest = self._insert_receipt(
            operation_id=operation_id,
            action=action,
            artifact=candidate,
            transition=transition,
            prior_head=prior_head,
        )
        connection.execute(
            "INSERT INTO quarantine_artifacts(policy_digest,artifact_id,capture_id,artifact_digest,artifact_raw,status,observed_at,fetched_at) VALUES(?,?,?,?,?,?,?,?)",
            (self.policy_digest, candidate["artifact_id"], candidate["capture_id"], candidate["artifact_digest"], candidate["raw"], QUARANTINE_STATUS, candidate["observed_at"], candidate["fetched_at"]),
        )
        self._fault("after_artifact_insert")
        connection.execute(
            "INSERT INTO quarantine_operations(operation_id,policy_digest,action,request_digest,request_material_digest,artifact_id,expected_head,reason,transition_id,receipt_digest,sequence,receipt_raw) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (operation_id, self.policy_digest, action, request_digest, request_material, candidate["artifact_id"], expected_head, "", transition["transition_id"], receipt_digest, sequence, receipt_raw),
        )
        self._fault("after_operation_insert")
        connection.execute(
            "INSERT INTO quarantine_transitions(transition_id,policy_digest,database_id,sequence,action,artifact_id,prior_head,next_head,prior_state,next_state,observed_at,reason,operation_id,before_root,after_root,transition_raw) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (transition["transition_id"], self.policy_digest, self.database_id, sequence, action, candidate["artifact_id"], prior_head, candidate["artifact_id"], prior_state, transition["next_state"], candidate["observed_at"], "", operation_id, transition["before_root"], transition["after_root"], transition["raw"]),
        )
        self._fault("after_transition_insert")
        self._write_meta_and_head(connection, artifact=candidate, transition=transition, sequence=sequence)
        self._fault("before_commit")
        connection.commit()
        return self._result_from_operation({
            "operation_id": operation_id, "action": action, "artifact_id": candidate["artifact_id"],
            "sequence": sequence, "transition_id": transition["transition_id"], "receipt_raw": receipt_raw,
            "receipt_digest": receipt_digest,
        }, connection=connection)

    def admit(self, request_key: str, artifact_raw: bytes, *, expected_head: str | None = None) -> dict[str, object]:
        candidate = self._verify_artifact(artifact_raw)
        request_digest = _request_digest(request_key)
        expected = _head_selector(expected_head)
        self._fault("before_transaction")
        connection = self._connect()
        committed = False
        try:
            try:
                connection.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                raise QuarantineBusyError("quarantine:busy") from exc
            self._fault("after_begin")
            result = self._admit_locked(connection, candidate=candidate, request_digest=request_digest, expected_head=expected)
            # The only postcommit hook is intentionally a response-loss fault.
            connection.commit() if connection.in_transaction else None
            committed = True
            self._fault("after_commit_before_response")
            return result
        except QuarantineResponseLost:
            if not committed:
                if connection.in_transaction:
                    connection.rollback()
            raise
        except (QuarantineInjectedFault, QuarantineConflictError, ExternalSourceQuarantineError):
            if connection.in_transaction:
                connection.rollback()
            raise
        except sqlite3.IntegrityError as exc:
            if connection.in_transaction:
                connection.rollback()
            raise QuarantineConflictError("quarantine:integrity") from exc
        except sqlite3.OperationalError as exc:
            if connection.in_transaction:
                connection.rollback()
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise QuarantineBusyError("quarantine:busy") from exc
            raise ExternalSourceQuarantineError("quarantine:operational") from exc
        except sqlite3.DatabaseError as exc:
            if connection.in_transaction:
                connection.rollback()
            raise QuarantineConflictError("quarantine:database") from exc
        finally:
            connection.close()

    def _withdraw_locked(self, connection: sqlite3.Connection, *, request_digest: str, expected_head: str, reason: str) -> dict[str, object]:
        existing_operation = self._operation_for_request(connection, self.policy_digest, request_digest)
        if existing_operation is not None:
            stored_material = independent._request_material_digest(
                operation_id=str(existing_operation["operation_id"]), policy_digest=self.policy_digest,
                artifact_id=str(existing_operation["artifact_id"]), expected_head=expected_head, reason=reason,
            )
            if existing_operation["action"] != ACTION_WITHDRAW or stored_material != existing_operation["request_material_digest"]:
                raise QuarantineConflictError("quarantine:operation-conflict")
            return self._result_from_operation(existing_operation, connection=connection)
        head = self._head(connection)
        if head is None:
            raise QuarantineConflictError("quarantine:head-missing")
        if head["state"] != QUARANTINE_STATUS or expected_head != head["head_artifact_id"]:
            raise QuarantineConflictError("quarantine:stale-head")
        artifact_row = connection.execute(
            "SELECT * FROM quarantine_artifacts WHERE policy_digest=? AND artifact_id=?",
            (self.policy_digest, head["head_artifact_id"]),
        ).fetchone()
        if artifact_row is None:
            raise QuarantineConflictError("quarantine:head-artifact-missing")
        artifact = dict(artifact_row)
        self._verify_stored_artifact(artifact)
        sequence = int(self._metadata(connection)["sequence"]) + 1
        operation_id = independent._operation_id(ACTION_WITHDRAW, request_digest, self.database_id)
        request_material = independent._request_material_digest(
            operation_id=operation_id, policy_digest=self.policy_digest,
            artifact_id=str(artifact["artifact_id"]), expected_head=expected_head, reason=reason,
        )
        transition = self._insert_transition(
            connection, operation_id=operation_id, action=ACTION_WITHDRAW, artifact=artifact,
            expected_head=expected_head, reason=reason, prior_head=str(head["head_artifact_id"]),
            prior_state=QUARANTINE_STATUS, sequence=sequence, before_root=str(self._metadata(connection)["head_root"]),
        )
        receipt_raw, receipt_digest = self._insert_receipt(
            operation_id=operation_id, action=ACTION_WITHDRAW, artifact=artifact,
            transition=transition, prior_head=str(head["head_artifact_id"]),
        )
        connection.execute(
            "INSERT INTO quarantine_operations(operation_id,policy_digest,action,request_digest,request_material_digest,artifact_id,expected_head,reason,transition_id,receipt_digest,sequence,receipt_raw) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (operation_id, self.policy_digest, ACTION_WITHDRAW, request_digest, request_material, artifact["artifact_id"], expected_head, reason, transition["transition_id"], receipt_digest, sequence, receipt_raw),
        )
        self._fault("after_operation_insert")
        connection.execute(
            "INSERT INTO quarantine_transitions(transition_id,policy_digest,database_id,sequence,action,artifact_id,prior_head,next_head,prior_state,next_state,observed_at,reason,operation_id,before_root,after_root,transition_raw) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (transition["transition_id"], self.policy_digest, self.database_id, sequence, ACTION_WITHDRAW, artifact["artifact_id"], head["head_artifact_id"], artifact["artifact_id"], QUARANTINE_STATUS, "WITHDRAWN", artifact["observed_at"], reason, operation_id, transition["before_root"], transition["after_root"], transition["raw"]),
        )
        self._fault("after_transition_insert")
        self._write_meta_and_head(connection, artifact=artifact, transition=transition, sequence=sequence)
        self._fault("before_commit")
        connection.commit()
        return self._result_from_operation({
            "operation_id": operation_id, "action": ACTION_WITHDRAW, "artifact_id": artifact["artifact_id"],
            "sequence": sequence, "transition_id": transition["transition_id"], "receipt_raw": receipt_raw,
            "receipt_digest": receipt_digest,
        }, connection=connection)

    def withdraw(self, request_key: str, *, expected_head: str, reason: str) -> dict[str, object]:
        request_digest = _request_digest(request_key)
        expected = _head_selector(expected_head)
        if not isinstance(reason, str) or reason not in WITHDRAW_REASONS:
            raise QuarantineConflictError("quarantine:withdraw-reason")
        self._fault("before_transaction")
        connection = self._connect()
        committed = False
        try:
            try:
                connection.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                raise QuarantineBusyError("quarantine:busy") from exc
            self._fault("after_begin")
            result = self._withdraw_locked(connection, request_digest=request_digest, expected_head=expected, reason=reason)
            committed = True if not connection.in_transaction else False
            if connection.in_transaction:
                connection.commit()
                committed = True
            self._fault("after_commit_before_response")
            return result
        except QuarantineResponseLost:
            if not committed and connection.in_transaction:
                connection.rollback()
            raise
        except (QuarantineInjectedFault, QuarantineConflictError, ExternalSourceQuarantineError):
            if connection.in_transaction:
                connection.rollback()
            raise
        except sqlite3.IntegrityError as exc:
            if connection.in_transaction:
                connection.rollback()
            raise QuarantineConflictError("quarantine:integrity") from exc
        except sqlite3.OperationalError as exc:
            if connection.in_transaction:
                connection.rollback()
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise QuarantineBusyError("quarantine:busy") from exc
            raise ExternalSourceQuarantineError("quarantine:operational") from exc
        finally:
            connection.close()

    def head(self) -> dict[str, object] | None:
        connection = self._connect()
        try:
            row = self._head(connection)
            if row is None:
                return None
            return {**dict(row), "database_id": self.database_id}
        finally:
            connection.close()

    def lookup_request(
        self,
        request_key: str,
        *,
        artifact_id: str,
        artifact_digest: str,
        expected_head: str | None = None,
    ) -> dict[str, object] | None:
        """Read-only exact reconciliation for a previously dispatched request."""
        request_digest = _request_digest(request_key)
        expected = _head_selector(expected_head)
        try:
            independent._hex(artifact_id, "artifact-id")
            independent._hex(artifact_digest, "artifact-digest")
        except independent.IndependentQuarantineError as exc:
            raise QuarantineConflictError(str(exc)) from exc
        connection = self._connect()
        try:
            row = self._operation_for_request(connection, self.policy_digest, request_digest)
            if row is None:
                return None
            if row["action"] not in {ACTION_ADMIT, ACTION_SUPERSEDE} or row["artifact_id"] != artifact_id or row["expected_head"] != expected:
                raise QuarantineConflictError("quarantine:lookup-binding")
            stored = connection.execute(
                "SELECT * FROM quarantine_artifacts WHERE policy_digest=? AND artifact_id=?",
                (self.policy_digest, artifact_id),
            ).fetchone()
            if stored is None or stored["artifact_digest"] != artifact_digest:
                raise QuarantineConflictError("quarantine:lookup-artifact")
            self._verify_stored_artifact(dict(stored))
            result = self._result_from_operation(dict(row), connection=connection)
            return result
        finally:
            connection.close()

    def integrity(self) -> dict[str, object]:
        try:
            return independent.verify_database(self.database, policy=self.policy, database_id=self.database_id)
        except independent.IndependentQuarantineError as exc:
            raise ExternalSourceQuarantineError(str(exc)) from exc

    def support_snapshot(self) -> dict[str, object]:
        evidence = self.integrity()
        return {
            "schema": f"{SCHEMA}-support",
            "schema_version": SCHEMA_VERSION,
            "chain_id": evidence["chain_id"],
            "database_id": self.database_id,
            "head_state": evidence["head_state"],
            "head_sequence": evidence["sequence"],
            "head_root": evidence["head_root"],
            "artifact_count": evidence["artifact_count"],
            "operation_count": evidence["operation_count"],
            "transition_count": evidence["transition_count"],
            "durable_status": QUARANTINE_STATUS if evidence["artifact_count"] else "EMPTY",
            "state_owned": True,
            "synthetic_only": True,
            "production_usable": False,
            "activation": False,
            "payment_authority": False,
            "clearance_authority": False,
            "settlement_authority": False,
            "downstream_bridge": False,
            "proofSuiteId": None,
        }

    def _snapshot(self) -> dict[str, list[dict[str, object]]]:
        connection = self._connect()
        try:
            return {
                "quarantine_meta": [dict(row) for row in connection.execute("SELECT * FROM quarantine_meta ORDER BY key")],
                "quarantine_artifacts": [dict(row) for row in connection.execute("SELECT * FROM quarantine_artifacts ORDER BY policy_digest,artifact_id")],
                "quarantine_operations": [dict(row) for row in connection.execute("SELECT * FROM quarantine_operations ORDER BY sequence")],
                "quarantine_transitions": [dict(row) for row in connection.execute("SELECT * FROM quarantine_transitions ORDER BY sequence")],
                "quarantine_heads": [dict(row) for row in connection.execute("SELECT * FROM quarantine_heads ORDER BY policy_digest")],
            }
        finally:
            connection.close()

    def export_bytes(self) -> bytes:
        self.integrity()
        snapshot = self._snapshot()
        body: dict[str, object] = {
            "schema": EXPORT_SCHEMA,
            "schema_version": EXPORT_VERSION,
            "policy_digest": self.policy_digest,
            "database_id": self.database_id,
            "chain_id": self.chain_id,
            "meta": snapshot["quarantine_meta"],
            "artifacts": [],
            "operations": [],
            "transitions": [],
            "heads": snapshot["quarantine_heads"],
            "state_owned": True,
            "synthetic_only": True,
            "support_safe": False,
            "production_usable": False,
        }
        body["artifacts"] = [
            {**{key: value for key, value in row.items() if key != "artifact_raw"}, "artifact_hex": bytes(row["artifact_raw"]).hex()}
            for row in snapshot["quarantine_artifacts"]
        ]
        body["operations"] = [
            {**{key: value for key, value in row.items() if key != "receipt_raw"}, "receipt_hex": bytes(row["receipt_raw"]).hex()}
            for row in snapshot["quarantine_operations"]
        ]
        body["transitions"] = [
            {**{key: value for key, value in row.items() if key != "transition_raw"}, "transition_hex": bytes(row["transition_raw"]).hex()}
            for row in snapshot["quarantine_transitions"]
        ]
        body["export_root"] = independent._digest("export-root", body)
        raw = _canonical(body)
        if len(raw) > MAX_EXPORT_BYTES:
            raise ExternalSourceQuarantineError("quarantine:export-byte-cap")
        try:
            independent.verify_export_bytes(raw, policy=self.policy, database_id=self.database_id)
        except independent.IndependentQuarantineError as exc:
            raise ExternalSourceQuarantineError(str(exc)) from exc
        return raw

    def _restore_snapshot(self, snapshot: Mapping[str, list[Mapping[str, object]]]) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            for table in ("quarantine_artifacts", "quarantine_operations", "quarantine_transitions", "quarantine_heads"):
                if connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]:
                    raise QuarantineConflictError("quarantine:restore-nonempty")
            connection.execute("DELETE FROM quarantine_meta")
            for row in snapshot["quarantine_meta"]:
                connection.execute("INSERT INTO quarantine_meta(key,value) VALUES(?,?)", (row["key"], row["value"]))
            for row in snapshot["quarantine_artifacts"]:
                connection.execute("INSERT INTO quarantine_artifacts VALUES(?,?,?,?,?,?,?,?)", tuple(row[key] for key in independent.TABLE_COLUMNS["quarantine_artifacts"]))
            for row in snapshot["quarantine_operations"]:
                connection.execute("INSERT INTO quarantine_operations VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", tuple(row[key] for key in independent.TABLE_COLUMNS["quarantine_operations"]))
            for row in snapshot["quarantine_transitions"]:
                connection.execute("INSERT INTO quarantine_transitions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", tuple(row[key] for key in independent.TABLE_COLUMNS["quarantine_transitions"]))
            for row in snapshot["quarantine_heads"]:
                connection.execute("INSERT INTO quarantine_heads VALUES(?,?,?,?,?,?,?,?)", tuple(row[key] for key in independent.TABLE_COLUMNS["quarantine_heads"]))
            connection.commit()
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except (QuarantineConflictError, sqlite3.Error):
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    @classmethod
    def restore_export(
        cls,
        destination: str | Path,
        raw: bytes,
        *,
        policy: Mapping[str, object] | object,
        database_id: str,
        fault_injector: Callable[[str], None] | None = None,
    ) -> "ExternalSourceQuarantineService":
        target = _resolve_database(destination)
        if target.exists() or target.is_symlink():
            raise QuarantineConflictError("quarantine:restore-target-exists")
        try:
            verified = independent.verify_export_bytes(raw, policy=policy, database_id=database_id)
        except independent.IndependentQuarantineError as exc:
            raise ExternalSourceQuarantineError(str(exc)) from exc
        fd, descriptor = tempfile.mkstemp(prefix=f".{target.name}.restore-", suffix=".db", dir=target.parent)
        os.close(fd)
        stage = Path(descriptor)
        try:
            service = cls(stage, policy=policy, database_id=database_id, fault_injector=fault_injector)
            service._restore_snapshot(verified["snapshot"])  # type: ignore[arg-type]
            service.integrity()
            os.replace(stage, target)
            for suffix in ("-wal", "-shm"):
                Path(str(stage) + suffix).unlink(missing_ok=True)
            return cls(target, policy=policy, database_id=database_id)
        except Exception:
            stage.unlink(missing_ok=True)
            Path(str(stage) + "-wal").unlink(missing_ok=True)
            Path(str(stage) + "-shm").unlink(missing_ok=True)
            raise


def restore_export(
    destination: str | Path,
    raw: bytes,
    *,
    policy: Mapping[str, object] | object,
    database_id: str,
) -> ExternalSourceQuarantineService:
    return ExternalSourceQuarantineService.restore_export(destination, raw, policy=policy, database_id=database_id)


__all__ = [
    "SCHEMA", "SCHEMA_VERSION", "EXPORT_SCHEMA", "EXPORT_VERSION", "QUARANTINE_STATUS",
    "ACTION_ADMIT", "ACTION_SUPERSEDE", "ACTION_WITHDRAW", "WITHDRAW_REASONS", "FIXED_FLAGS",
    "ExternalSourceQuarantineError", "QuarantineConflictError", "QuarantineBusyError",
    "QuarantineInjectedFault", "QuarantineResponseLost", "ExternalSourceQuarantineService", "restore_export",
]
