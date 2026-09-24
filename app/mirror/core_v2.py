"""The single six-table durable Mirror Core V2 owner.

Core is a read-only evidence, reconciliation, and observation owner.  It has
no delivery, payment, clearance, settlement, adjudication, or source-truth
authority.  Raw source custody ends at the source-side adapter; Core receives
only the independently verified sanitized observation and its at-time receipt.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import wraps
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import time
from typing import Callable, Mapping

from app.mirror import core_v2_independent as independent
from app.mirror import external_governance_approval_independent as governance
from app.mirror import external_privacy_support_approval_independent as privacy
from app.mirror import ingress_v2_independent as ingress
from app.mirror import external_corrective_action as corrective_action
from app.mirror import external_corrective_action_independent as corrective_action_independent
from app.mirror.error_boundary import raise_redacted
from app.mirror import writer_authority


SCHEMA = independent.SCHEMA
SCHEMA_VERSION = independent.SCHEMA_VERSION
TABLES = independent.TABLES
ARTIFACT_KINDS = independent.ARTIFACT_KINDS
FIXED_FLAGS = dict(independent.FIXED_FLAGS)
MAX_DATABASE_BYTES = independent.MAX_DATABASE_BYTES
MAX_ARTIFACT_BYTES = independent.MAX_ARTIFACT_BYTES
MAX_EVENT_BYTES = independent.MAX_EVENT_BYTES
MAX_BATCH_ARTIFACTS = 256
MAX_IDENTIFIER_BYTES = 128
_REPARSE_POINT = 0x400
_SIDECARS = ("-wal", "-shm", "-journal")


class CoreError(ValueError):
    """Public-safe Core error."""


class CoreConflictError(CoreError):
    """A stale, conflicting, or rebound Core request."""


class CoreBusyError(CoreError):
    """A bounded Core writer contention failure."""


class CoreIndeterminateError(CoreError):
    """The transaction outcome or its finalization cannot be established."""


def _mutation(method):
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        with self._authority.mutation_scope(self.path):
            return method(self, *args, **kwargs)
    return wrapped


def _finalize_core_connection(
    connection: sqlite3.Connection | None,
    *,
    commit_attempted: bool = False,
    commit_succeeded: bool = False,
    identity_check: Callable[[], None] | None = None,
    transactional: bool = True,
    cleanup_code: str = "core:database",
    close: bool = True,
    continue_after_cleanup: bool = False,
    ignore_active: bool = False,
    rollback_before_close: bool = False,
) -> None:
    """Own Core rollback/close without exposing cleanup failures."""

    active = None if ignore_active else sys.exc_info()[1]
    active_present = active is not None
    active_is_core_error = isinstance(active, CoreError)
    active_is_fatal = isinstance(active, (KeyboardInterrupt, SystemExit, GeneratorExit))
    if not active_is_core_error:
        active = None
    if connection is None:
        if transactional and (commit_attempted or commit_succeeded):
            active = None
            raise_redacted(CoreIndeterminateError, "core:transaction-indeterminate")
        if active_present and not active_is_core_error:
            active = None
            raise_redacted(CoreError, cleanup_code)
        active = None
        return
    cleanup_failed = False
    try:
        in_transaction = bool(connection.in_transaction)
    except BaseException:
        in_transaction = False
        cleanup_failed = True
    if (transactional or rollback_before_close) and not commit_succeeded and in_transaction:
        try:
            connection.rollback()
        except BaseException:
            cleanup_failed = True
    if close:
        try:
            connection.close()
        except BaseException:
            cleanup_failed = True
    if identity_check is not None and (commit_succeeded or not transactional):
        try:
            identity_check()
        except BaseException:
            cleanup_failed = True
    if continue_after_cleanup:
        if cleanup_failed or (commit_attempted and not commit_succeeded):
            active = None
            raise_redacted(CoreIndeterminateError, "core:transaction-indeterminate")
        if active_is_core_error and active is not None:
            active.__cause__ = None
            active.__context__ = None
            active.__suppress_context__ = True
        active = None
        return
    if active_is_fatal:
        active = None
        return
    if transactional and (
        cleanup_failed
        or (commit_attempted and not commit_succeeded)
        or (commit_succeeded and active_present)
    ):
        active = None
        raise_redacted(CoreIndeterminateError, "core:transaction-indeterminate")
    if not transactional and cleanup_failed:
        active = None
        raise_redacted(CoreError, cleanup_code)
    if active_present and not active_is_core_error:
        active = None
        raise_redacted(CoreError, cleanup_code)
    if active_is_core_error and active is not None:
        active.__cause__ = None
        active.__context__ = None
        active.__suppress_context__ = True
    active = None


def _safe_identifier(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise CoreError(label)
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError:
        raise CoreError(label) from None
    if len(raw) > MAX_IDENTIFIER_BYTES or any(not (char.isalnum() or char in "._:-") for char in value):
        raise CoreError(label)
    return value


@dataclass(frozen=True)
class CoreConfigV2:
    database_id: str
    chain_id: str
    ingress_database_id: str
    ingress_chain_id: str
    runtime_profile_digest: str
    governance_policy_digest: str
    privacy_policy_digest: str
    ingress_config_digest: str
    corrective_action_control_digest: str
    max_sessions: int = 8
    max_slots_per_session: int = 16
    cadence_seconds: int = 60

    def __post_init__(self) -> None:
        for value in (self.database_id, self.chain_id, self.ingress_database_id, self.ingress_chain_id):
            _safe_identifier(value, "core:config")
        for value in (self.runtime_profile_digest, self.governance_policy_digest, self.privacy_policy_digest):
            if type(value) is not str or len(value) != 128 or any(char not in "0123456789abcdef" for char in value):
                raise CoreError("core:config")
        if type(self.ingress_config_digest) is not str or len(self.ingress_config_digest) != 128 or any(char not in "0123456789abcdef" for char in self.ingress_config_digest):
            raise CoreError("core:config")
        if type(self.corrective_action_control_digest) is not str or len(self.corrective_action_control_digest) != 128 or any(char not in "0123456789abcdef" for char in self.corrective_action_control_digest):
            raise CoreError("core:config")
        if type(self.max_sessions) is not int or not 1 <= self.max_sessions <= 64 or type(self.max_slots_per_session) is not int or not 1 <= self.max_slots_per_session <= 256 or type(self.cadence_seconds) is not int or self.cadence_seconds <= 0:
            raise CoreError("core:config")

    def material(self) -> dict[str, object]:
        return {
            "schema": SCHEMA, "schema_version": SCHEMA_VERSION,
            "database_id": self.database_id, "chain_id": self.chain_id,
            "ingress_database_id": self.ingress_database_id,
            "ingress_chain_id": self.ingress_chain_id,
            "ingress_config_digest": self.ingress_config_digest,
            "runtime_profile_digest": self.runtime_profile_digest,
            "governance_policy_digest": self.governance_policy_digest,
            "privacy_policy_digest": self.privacy_policy_digest,
            "corrective_action_control_digest": self.corrective_action_control_digest,
            "max_sessions": self.max_sessions, "max_slots_per_session": self.max_slots_per_session,
            "cadence_seconds": self.cadence_seconds, "flags": dict(FIXED_FLAGS),
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


def _require_digest(value: object, label: str) -> str:
    if type(value) is not str or len(value) != 128 or any(char not in "0123456789abcdef" for char in value):
        raise CoreConflictError(label)
    return value


def _sqlite_error(exc: sqlite3.Error, *, busy: bool = False) -> None:
    error_name = getattr(exc, "sqlite_errorname", "")
    if error_name in {"SQLITE_FULL", "SQLITE_TOOBIG"}:
        raise_redacted(CoreError, "core:capacity")
    if busy and error_name in {"SQLITE_BUSY", "SQLITE_LOCKED"}:
        raise_redacted(CoreBusyError, "core:busy")
    raise_redacted(CoreError, "core:database")


def _is_reparse(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)


def _sidecar_present(path: Path) -> bool:
    return any(os.path.lexists(os.fspath(path) + suffix) for suffix in _SIDECARS)


def _path_identity(path: Path, *, allow_missing: bool) -> tuple[int, int] | None:
    try:
        parent = os.lstat(path.parent)
        if not stat.S_ISDIR(parent.st_mode) or _is_reparse(parent):
            raise CoreError("core:database-open")
        if _sidecar_present(path):
            raise CoreError("core:database-open")
        info = os.lstat(path)
    except FileNotFoundError:
        if allow_missing:
            return None
        raise CoreError("core:database-open") from None
    except CoreError:
        raise
    except OSError:
        raise_redacted(CoreError, "core:database-open")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or _is_reparse(info) or info.st_nlink != 1:
        raise CoreError("core:database-open")
    if info.st_size > MAX_DATABASE_BYTES:
        raise CoreError("core:capacity")
    return int(info.st_dev), int(info.st_ino)


def _require_path_identity(path: Path, expected: tuple[int, int]) -> tuple[int, int]:
    try:
        current = _path_identity(path, allow_missing=False)
    except CoreError:
        raise_redacted(CoreError, "core:database-open")
    if current != expected:
        raise_redacted(CoreError, "core:database-open")
    return current


def _configure(connection: sqlite3.Connection) -> None:
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=250")
        mode = str(connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0]).lower()
        if mode != "delete":
            raise CoreError("core:database-open")
        connection.execute("PRAGMA synchronous=FULL")
        if int(connection.execute("PRAGMA synchronous").fetchone()[0]) != 2:
            raise CoreError("core:database-open")
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        if page_size != 4096 or page_count < 0 or page_size * page_count > MAX_DATABASE_BYTES:
            raise CoreError("core:capacity")
        max_pages = MAX_DATABASE_BYTES // page_size
        configured = int(connection.execute(f"PRAGMA max_page_count={max_pages}").fetchone()[0])
        if configured <= 0 or configured > max_pages or configured * page_size > MAX_DATABASE_BYTES:
            raise CoreError("core:capacity")
        if int(connection.execute("PRAGMA page_count").fetchone()[0]) > configured:
            raise CoreError("core:capacity")
    except CoreError:
        raise
    except sqlite3.Error as exc:
        _sqlite_error(exc)


def _connection(path: Path, *, expected_identity: tuple[int, int] | None = None, create: bool = False) -> sqlite3.Connection:
    before = _path_identity(path, allow_missing=create)
    if create and expected_identity is not None:
        raise CoreError("core:database-open")
    if not create and before is None:
        raise CoreError("core:database-open")
    if expected_identity is not None and (before is None or before != expected_identity):
        raise CoreError("core:database-open")
    connection: sqlite3.Connection | None = None
    try:
        if create:
            connection = sqlite3.connect(path, isolation_level=None, timeout=0.25)
        else:
            connection = sqlite3.connect(path.absolute().as_uri() + "?mode=rw", uri=True, isolation_level=None, timeout=0.25)
        after_connect = _path_identity(path, allow_missing=False)
        if expected_identity is not None and after_connect != expected_identity:
            raise CoreError("core:database-open")
        _configure(connection)
        after_setup = _path_identity(path, allow_missing=False)
        if after_setup != after_connect or (expected_identity is not None and after_setup != expected_identity):
            raise CoreError("core:database-open")
        connection.row_factory = sqlite3.Row
        return connection
    except CoreError:
        _finalize_core_connection(
            connection,
            transactional=False,
            cleanup_code="core:database-open",
        )
        raise
    except OSError:
        _finalize_core_connection(
            connection,
            transactional=False,
            cleanup_code="core:database-open",
        )
        raise_redacted(CoreError, "core:database-open")
    except sqlite3.Error as exc:
        _finalize_core_connection(
            connection,
            transactional=False,
            cleanup_code="core:database-open",
        )
        _sqlite_error(exc)
    raise CoreError("core:database-open")


def _table_names(connection: sqlite3.Connection) -> tuple[str, ...]:
    return tuple(row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall())


def _columns(connection: sqlite3.Connection, table: str) -> tuple[str, ...]:
    return tuple(row[1] for row in connection.execute("SELECT * FROM pragma_table_info(?) ORDER BY cid", (table,)).fetchall())


def _init(path: Path, config: CoreConfigV2) -> tuple[int, int]:
    existing = _path_identity(path, allow_missing=True)
    if existing is not None:
        try:
            independent.verify_database(path, expected_database_id=config.database_id, expected_config_digest=config.digest)
        except independent.CoreVerificationError:
            _require_path_identity(path, existing)
            raise
        connection = _connection(path, expected_identity=existing)

        def _existing_identity() -> None:
            _require_path_identity(path, existing)

        try:
            if _table_names(connection) != tuple(sorted(TABLES)) or any(_columns(connection, table) != columns for table, columns in independent.TABLE_COLUMNS.items()):
                raise CoreError("core:legacy-schema")
            indexes = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_autoindex_%'").fetchall()}
            if indexes != {independent.EXPLICIT_INDEX}:
                raise CoreError("core:legacy-schema")
            row = connection.execute("SELECT * FROM core_meta WHERE meta_id=1").fetchone()
            if row is None or bytes(row["config_raw"]) != _canonical(config.material()) or row["database_id"] != config.database_id or row["chain_id"] != config.chain_id:
                raise CoreError("core:identity")
        finally:
            _finalize_core_connection(
                connection,
                identity_check=_existing_identity,
                transactional=False,
                cleanup_code="core:database-open",
            )
        return existing

    connection = _connection(path, create=True)
    try:
        initial_identity = _path_identity(path, allow_missing=False)
    except CoreError:
        _finalize_core_connection(connection, transactional=False, cleanup_code="core:database-open")
        raise
    if initial_identity is None:
        _finalize_core_connection(connection, transactional=False, cleanup_code="core:database-open")
        raise CoreError("core:database-open")
    commit_attempted = False
    commit_succeeded = False

    def _postcommit_identity() -> None:
        _require_path_identity(path, initial_identity)

    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("CREATE TABLE core_meta(meta_id INTEGER PRIMARY KEY CHECK(meta_id=1),schema TEXT NOT NULL,schema_version INTEGER NOT NULL,database_id TEXT NOT NULL,chain_id TEXT NOT NULL,config_digest TEXT NOT NULL,config_raw BLOB NOT NULL,sequence INTEGER NOT NULL,head_root TEXT NOT NULL,ingress_database_id TEXT NOT NULL,ingress_watermark INTEGER NOT NULL)")
        connection.execute("CREATE TABLE core_artifacts(artifact_id TEXT PRIMARY KEY,kind TEXT NOT NULL,raw BLOB NOT NULL,profile_digest TEXT NOT NULL,source_artifact_id TEXT,predecessor_id TEXT,current_state TEXT NOT NULL,created_event_sequence INTEGER NOT NULL)")
        connection.execute("CREATE TABLE core_heads(stream_kind TEXT NOT NULL,stream_id TEXT NOT NULL,head_ref TEXT NOT NULL,head_root TEXT NOT NULL,event_sequence INTEGER NOT NULL,PRIMARY KEY(stream_kind,stream_id))")
        connection.execute("CREATE TABLE core_sessions(session_id TEXT PRIMARY KEY,state TEXT NOT NULL,source_artifact_id TEXT NOT NULL,governance_artifact_id TEXT NOT NULL,privacy_artifact_id TEXT NOT NULL,head_root TEXT NOT NULL,last_slot INTEGER NOT NULL)")
        connection.execute("CREATE TABLE core_slots(session_id TEXT NOT NULL,slot_number INTEGER NOT NULL,result_digest TEXT NOT NULL,result_raw BLOB NOT NULL,PRIMARY KEY(session_id,slot_number),FOREIGN KEY(session_id) REFERENCES core_sessions(session_id))")
        connection.execute("CREATE TABLE core_events(sequence INTEGER PRIMARY KEY,event_id TEXT NOT NULL UNIQUE,event_kind TEXT NOT NULL,operation_id TEXT NOT NULL UNIQUE,subject_id TEXT NOT NULL,event_raw BLOB NOT NULL,receipt_digest TEXT NOT NULL)")
        connection.execute("CREATE INDEX core_artifacts_kind_source_event_idx ON core_artifacts(kind,source_artifact_id,created_event_sequence)")
        connection.execute("INSERT INTO core_meta(meta_id,schema,schema_version,database_id,chain_id,config_digest,config_raw,sequence,head_root,ingress_database_id,ingress_watermark) VALUES(1,?,?,?,?,?,?,?,?,?,?)", (SCHEMA, SCHEMA_VERSION, config.database_id, config.chain_id, config.digest, _canonical(config.material()), 0, independent.GENESIS_ROOT, config.ingress_database_id, 0))
        commit_attempted = True
        connection.commit()
        commit_succeeded = True
    except CoreError:
        _finalize_core_connection(
            connection,
            commit_attempted=commit_attempted,
            commit_succeeded=commit_succeeded,
            close=False,
            continue_after_cleanup=True,
        )
        raise
    except sqlite3.OperationalError as exc:
        _finalize_core_connection(
            connection,
            commit_attempted=commit_attempted,
            commit_succeeded=commit_succeeded,
            close=False,
            continue_after_cleanup=True,
        )
        _sqlite_error(exc, busy=True)
    except sqlite3.Error as exc:
        _finalize_core_connection(
            connection,
            commit_attempted=commit_attempted,
            commit_succeeded=commit_succeeded,
            close=False,
            continue_after_cleanup=True,
        )
        _sqlite_error(exc)
    finally:
        _finalize_core_connection(
            connection,
            commit_attempted=commit_attempted,
            commit_succeeded=commit_succeeded,
            identity_check=_postcommit_identity,
            cleanup_code="core:database-initialize",
        )
    _require_path_identity(path, initial_identity)
    try:
        independent.verify_database(path, expected_database_id=config.database_id, expected_config_digest=config.digest)
    except independent.CoreVerificationError:
        _require_path_identity(path, initial_identity)
        raise
    _require_path_identity(path, initial_identity)
    return initial_identity


class CoreServiceV2:
    def __init__(
        self,
        path: str | Path,
        config: CoreConfigV2,
        *,
        clock: object | None = None,
        authority: writer_authority.WriterAuthority,
        corrective_action_control: corrective_action.CorrectiveActionControlV1 | None = None,
        corrective_action_verifier: corrective_action.CorrectiveActionVerifier | None = None,
    ) -> None:
        if not isinstance(authority, writer_authority.WriterAuthority):
            raise CoreError("core:writer")
        self.path = Path(path)
        self.config = config
        self._authority = authority
        authority.assert_database_parent(self.path)
        self.clock = clock if clock is not None else lambda: int(time.time())
        if not callable(self.clock):
            raise CoreError("core:clock")
        if (corrective_action_control is None) != (corrective_action_verifier is None):
            raise CoreError("core:action-control")
        self._corrective_action_control = corrective_action_control
        self._corrective_action_verifier = corrective_action_verifier
        if corrective_action_control is not None:
            self._require_corrective_action_dependencies()
        with authority.mutation_scope(self.path):
            self._database_identity = _init(self.path, config)

    def _open(self) -> sqlite3.Connection:
        self._authority.assert_database_parent(self.path)
        return _connection(self.path, expected_identity=self._database_identity)

    def _assert_database_identity(self) -> None:
        self._authority.assert_database_parent(self.path)
        _require_path_identity(self.path, self._database_identity)

    def _require_corrective_action_dependencies(self) -> tuple[corrective_action.CorrectiveActionControlV1, corrective_action.CorrectiveActionVerifier]:
        control = self._corrective_action_control
        verifier = self._corrective_action_verifier
        if not isinstance(control, corrective_action.CorrectiveActionControlV1) or verifier is None:
            raise CoreConflictError("core:action-control")
        if control.digest != self.config.corrective_action_control_digest:
            raise CoreConflictError("core:action-control")
        try:
            values = (
                verifier.identity,
                verifier.epoch,
                verifier.authority_evidence_digest,
                verifier.revocation_head_digest,
                verifier.terms_digest,
                verifier.retention_policy_digest,
                verifier.valid_from,
                verifier.valid_until,
                verifier.max_evidence_bytes,
                verifier.verify,
            )
        except Exception:
            raise_redacted(CoreConflictError, "core:action-control")
        if values[:-1] != (
            control.verifier_id,
            control.verifier_epoch,
            control.authority_evidence_digest,
            control.revocation_head_digest,
            control.terms_digest,
            control.retention_policy_digest,
            control.valid_from,
            control.valid_until,
            control.max_evidence_bytes,
        ) or not callable(values[-1]):
            raise CoreConflictError("core:action-control")
        return control, verifier

    def _operational_represented_ingress_artifact_ids(self, limit: int) -> tuple[str, ...]:
        """Return the bounded raw-free source representation projection."""

        if type(limit) is not int or not 1 <= limit <= 4096:
            raise CoreConflictError("core:projection-limit")
        self._assert_database_identity()
        connection: sqlite3.Connection | None = None
        try:
            connection = self._open()
            rows = connection.execute(
                """
                SELECT source_artifact_id, created_event_sequence
                FROM core_artifacts
                WHERE kind='SOURCE_OBSERVATION' AND source_artifact_id IS NOT NULL
                ORDER BY created_event_sequence, source_artifact_id
                LIMIT ?
                """,
                (limit + 1,),
            ).fetchall()
            if len(rows) > limit:
                raise CoreConflictError("core:projection-capacity")
            result: list[str] = []
            seen: set[str] = set()
            prior_sequence = 0
            for row in rows:
                source_artifact_id = _require_digest(row["source_artifact_id"], "core:projection")
                event_sequence = row["created_event_sequence"]
                if type(event_sequence) is not int or event_sequence <= prior_sequence or source_artifact_id in seen:
                    raise CoreError("core:projection")
                prior_sequence = event_sequence
                seen.add(source_artifact_id)
                result.append(source_artifact_id)
            return tuple(result)
        except (CoreConflictError, CoreError):
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError):
            raise_redacted(CoreError, "core:projection")
        finally:
            if connection is not None:
                _finalize_core_connection(
                    connection,
                    identity_check=self._assert_database_identity,
                    transactional=False,
                    cleanup_code="core:projection",
                )

    def verify(self, *, ingress_path: str | Path | None = None) -> dict[str, object]:
        self._assert_database_identity()
        try:
            result = independent.verify_database(
                self.path,
                expected_database_id=self.config.database_id,
                expected_config_digest=self.config.digest,
                ingress_path=ingress_path,
            )
        except independent.CoreVerificationError:
            self._assert_database_identity()
            raise
        self._assert_database_identity()
        return result

    def logical_export(self) -> bytes:
        return independent.logical_export(self.verify())

    def support(self) -> dict[str, object]:
        result = self.verify()
        return {"schema": "mirror-core-support-v3", "artifact_count": result["artifact_count"], "session_count": result["session_count"], "slot_count": result["slot_count"], "event_count": result["event_count"], "structural_valid": result["structural_valid"], "ingress_bound": result["ingress_bound"], "flags": dict(FIXED_FLAGS)}

    def _owner_now(self, connection: sqlite3.Connection) -> int:
        self._authority.assert_live()
        try:
            value = self.clock()
        except Exception:
            raise_redacted(CoreError, "core:clock")
        if type(value) is not int or value < 0:
            raise CoreError("core:clock")
        row = connection.execute("SELECT event_raw FROM core_events ORDER BY sequence DESC LIMIT 1").fetchone()
        if row is not None:
            raw = row[0]
            if type(raw) is not bytes or len(raw) > MAX_EVENT_BYTES:
                raise CoreError("core:event")
            latest = independent._parse(raw, "core:event-raw")["observed_at"]
            if type(latest) is not int or value < latest:
                raise CoreConflictError("core:clock-rewind")
        return value

    @staticmethod
    def _event(connection: sqlite3.Connection, operation_id: str) -> bytes | None:
        row = connection.execute("SELECT event_raw FROM core_events WHERE operation_id=?", (operation_id,)).fetchone()
        if row is None:
            return None
        if type(row[0]) is not bytes or len(row[0]) > MAX_EVENT_BYTES:
            raise CoreError("core:receipt")
        return bytes(row[0])

    @staticmethod
    def _receipt(raw: bytes) -> CoreReceipt:
        try:
            value = independent._parse(raw, "core:receipt")
        except independent.CoreVerificationError:
            raise_redacted(CoreError, "core:receipt")
        return CoreReceipt(raw=raw, operation_id=str(value["operation_id"]), event_id=str(value["event_id"]), subject_id=str(value["subject_id"]), next_state=str(value["next_state"]), sequence=int(value["sequence"]), after_root=str(value["after_root"]))

    def _append(self, connection: sqlite3.Connection, *, kind: str, operation_id: str, subject_id: str, request_digest: str, prior_state: str, next_state: str, attempt: int, observed_at: int, material: Mapping[str, object], payload_digest: str, payload_length: int, stream_kind: str, stream_id: str, head_ref: str, ingress_watermark: int = 0) -> bytes:
        meta = connection.execute("SELECT * FROM core_meta WHERE meta_id=1").fetchone()
        if meta is None:
            raise CoreError("core:meta")
        if type(observed_at) is not int or observed_at < 0:
            raise CoreConflictError("core:clock")
        latest_row = connection.execute(
            "SELECT event_raw FROM core_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        if latest_row is not None:
            try:
                latest = independent._parse(latest_row[0], "core:event-raw")["observed_at"]
            except Exception:
                raise CoreError("core:event") from None
            if type(latest) is not int or observed_at < latest:
                raise CoreConflictError("core:clock-rewind")
        sequence = int(meta["sequence"]) + 1
        stream = connection.execute("SELECT head_root FROM core_heads WHERE stream_kind=? AND stream_id=?", (stream_kind, stream_id)).fetchone()
        stream_before = str(stream[0]) if stream is not None else independent.GENESIS_ROOT
        body: dict[str, object] = {"schema": SCHEMA, "schema_version": SCHEMA_VERSION, "database_id": self.config.database_id, "chain_id": self.config.chain_id, "sequence": sequence, "event_id": "", "event_kind": kind, "stream_kind": stream_kind, "stream_id": stream_id, "operation_id": operation_id, "subject_id": subject_id, "request_digest": request_digest, "prior_state": prior_state, "next_state": next_state, "attempt": attempt, "observed_at": observed_at, "material": dict(material), "material_digest": _digest("material", material), "payload_digest": payload_digest, "payload_length": payload_length, "before_root": str(meta["head_root"]), "after_root": "", "stream_before_root": stream_before, "stream_after_root": ""}
        body["event_id"] = _digest("event-id", {key: body[key] for key in independent.EVENT_RAW_KEYS if key not in {"event_id", "after_root", "stream_after_root"}})
        body["after_root"] = independent._event_root(body)
        body["stream_after_root"] = independent._stream_root(body)
        raw = _canonical(body)
        if len(raw) > MAX_EVENT_BYTES:
            raise CoreConflictError("core:capacity")
        connection.execute("INSERT INTO core_events(sequence,event_id,event_kind,operation_id,subject_id,event_raw,receipt_digest) VALUES(?,?,?,?,?,?,?)", (sequence, body["event_id"], kind, operation_id, subject_id, raw, _raw_digest("receipt", raw)))
        connection.execute("UPDATE core_meta SET sequence=?,head_root=?,ingress_watermark=MAX(ingress_watermark,?) WHERE meta_id=1", (sequence, body["after_root"], ingress_watermark))
        connection.execute("INSERT INTO core_heads(stream_kind,stream_id,head_ref,head_root,event_sequence) VALUES(?,?,?,?,?) ON CONFLICT(stream_kind,stream_id) DO UPDATE SET head_ref=excluded.head_ref,head_root=excluded.head_root,event_sequence=excluded.event_sequence", (stream_kind, stream_id, head_ref, body["stream_after_root"], sequence))
        return raw

    def _admit_artifact(self, connection: sqlite3.Connection, *, kind: str, raw: bytes, profile_digest: str, predecessor_id: str | None, source_artifact_id: str | None, operation_id: str, request_digest: str, state: str, observed_at: int, ingress_watermark: int = 0, event_stream_kind: str = "ARTIFACT", event_stream_id: str | None = None) -> tuple[str, bytes]:
        if type(raw) is not bytes or not raw or len(raw) > MAX_ARTIFACT_BYTES:
            raise CoreConflictError("core:capacity")
        if kind not in ARTIFACT_KINDS:
            raise CoreConflictError("core:artifact-kind")
        artifact_id = _digest("artifact-row-id", {"kind": kind, "raw": _raw_digest("artifact-bytes", raw), "profile_digest": profile_digest, "source_artifact_id": source_artifact_id, "predecessor_id": predecessor_id})
        existing_event = self._event(connection, operation_id)
        if existing_event is not None:
            value = independent._parse(existing_event, "core:event-raw")
            material = value.get("material")
            expected_material = {
                "artifact_id": artifact_id, "kind": kind,
                "raw_digest": _raw_digest("artifact-bytes", raw), "raw_length": len(raw),
                "profile_digest": profile_digest, "source_artifact_id": source_artifact_id,
                "predecessor_id": predecessor_id, "current_state": state,
                "ingress_watermark": ingress_watermark,
            }
            if value.get("event_kind") != "ARTIFACT" or material != expected_material or value.get("request_digest") != request_digest:
                raise CoreConflictError("core:operation-conflict")
            return artifact_id, existing_event
        existing = connection.execute("SELECT * FROM core_artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()
        if existing is not None:
            if bytes(existing["raw"]) != raw or existing["profile_digest"] != profile_digest or existing["source_artifact_id"] != source_artifact_id or existing["predecessor_id"] != predecessor_id or existing["current_state"] != state:
                raise CoreConflictError("core:artifact-conflict")
            raise CoreConflictError("core:artifact-receipt")
        parsed = independent._parse(raw, "core:artifact")
        if kind == "CASE":
            stream_id = str(parsed["case_id"])
        elif kind == "CASE_ACTION":
            stream_id = str(parsed["policy"]["case_id"])
        else:
            stream_id = kind
        stream_id = event_stream_id or stream_id
        connection.execute("INSERT INTO core_artifacts(artifact_id,kind,raw,profile_digest,source_artifact_id,predecessor_id,current_state,created_event_sequence) VALUES(?,?,?,?,?,?,?,0)", (artifact_id, kind, raw, profile_digest, source_artifact_id, predecessor_id, state))
        material = {"artifact_id": artifact_id, "kind": kind, "raw_digest": _raw_digest("artifact-bytes", raw), "raw_length": len(raw), "profile_digest": profile_digest, "source_artifact_id": source_artifact_id, "predecessor_id": predecessor_id, "current_state": state, "ingress_watermark": ingress_watermark}
        event_raw = self._append(connection, kind="ARTIFACT", operation_id=operation_id, subject_id=artifact_id, request_digest=request_digest, prior_state="NONE", next_state=kind, attempt=0, observed_at=observed_at, material=material, payload_digest=artifact_id, payload_length=len(raw), stream_kind=event_stream_kind, stream_id=stream_id, head_ref=artifact_id, ingress_watermark=ingress_watermark)
        sequence = independent._parse(event_raw, "core:event-raw")["sequence"]
        connection.execute("UPDATE core_artifacts SET created_event_sequence=? WHERE artifact_id=?", (sequence, artifact_id))
        return artifact_id, event_raw

    @staticmethod
    def _source_status(ing: Mapping[str, object], prior: Mapping[str, object] | None) -> tuple[str, str]:
        if prior is None:
            return ("INCOMPLETE" if ing.get("outcome") == "EVIDENCE_INCOMPLETE" else "OBSERVED_NEW", "INITIAL")
        if int(ing["event_sequence"]) <= int(prior["ingress_event_sequence"]):
            raise CoreConflictError("core:source-chronology")
        if int(ing["observation_time"]) <= int(prior["observation_time"]):
            raise CoreConflictError("core:source-chronology")
        status = "INCOMPLETE" if ing.get("outcome") == "EVIDENCE_INCOMPLETE" else ("OBSERVED_CONTINUED" if ing.get("observation_identity") == prior.get("observation_identity") else "OBSERVED_CHANGED")
        return status, "ADVANCING"

    @staticmethod
    def _ingress_projection_matches(source: Mapping[str, object], ing: Mapping[str, object]) -> bool:
        for source_key, ingress_key in (
            ("ingress_database_id", "database_id"),
            ("ingress_chain_id", "chain_id"),
            ("ingress_config_digest", "config_digest"),
            ("ingress_artifact_id", "artifact_id"),
            ("ingress_event_sequence", "event_sequence"),
            ("ingress_prefix_root", "event_prefix_root"),
            ("ingress_after_root", "event_after_root"),
            ("profile_id", "profile_id"),
            ("profile_version", "profile_version"),
            ("observation_time", "observation_time"),
            ("source_status", "source_status"),
            ("freshness", "freshness"),
            ("page_complete", "page_complete"),
            ("page_count", "page_count"),
            ("resource_count", "resource_count"),
            ("source_count", "source_count"),
            ("complete_source_count", "complete_source_count"),
            ("record_count", "record_count"),
            ("finding_count", "finding_count"),
            ("discrepancy_count", "discrepancy_count"),
            ("outcome", "outcome"),
        ):
            if source.get(source_key) != ing.get(ingress_key):
                return False
        return source.get("ingress_head_root") == ing.get("event_after_root") and source.get("observation_identity") == ing.get("observation_id")

    def _authority_staleness(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        now: int,
    ) -> tuple[str | None, dict[str, str | None]]:
        heads = CoreServiceV2._current_authority_heads(connection)
        if heads["SOURCE_OBSERVATION"] != row["source_artifact_id"]:
            return "SOURCE_SUPERSEDED", heads
        if heads["GOVERNANCE"] != row["governance_artifact_id"] or heads["PRIVACY"] != row["privacy_artifact_id"]:
            return "AUTHORITY_INDETERMINATE", heads
        source_authority = connection.execute(
            "SELECT raw,profile_digest FROM core_artifacts WHERE artifact_id=? AND kind='SOURCE_OBSERVATION'",
            (row["source_artifact_id"],),
        ).fetchone()
        if source_authority is None or type(source_authority[0]) is not bytes:
            return "AUTHORITY_INDETERMINATE", heads
        if source_authority[1] != self.config.runtime_profile_digest:
            return "AUTHORITY_INDETERMINATE", heads
        try:
            source_value = independent._parse(source_authority[0], "core:artifact")
        except independent.CoreVerificationError:
            return "AUTHORITY_INDETERMINATE", heads
        if source_value.get("runtime_profile_digest") != self.config.runtime_profile_digest:
            return "AUTHORITY_INDETERMINATE", heads
        authority_rows: list[sqlite3.Row] = []
        for kind in ("GOVERNANCE", "PRIVACY"):
            authority = connection.execute(
                "SELECT raw,profile_digest FROM core_artifacts WHERE artifact_id=? AND kind=?",
                (row["governance_artifact_id"] if kind == "GOVERNANCE" else row["privacy_artifact_id"], kind),
            ).fetchone()
            if authority is None or type(authority[0]) is not bytes:
                return "AUTHORITY_INDETERMINATE", heads
            expected_profile = self.config.governance_policy_digest if kind == "GOVERNANCE" else self.config.privacy_policy_digest
            if authority[1] != expected_profile:
                return "AUTHORITY_INDETERMINATE", heads
            try:
                value = independent._parse(authority[0], "core:artifact")
            except independent.CoreVerificationError:
                return "AUTHORITY_INDETERMINATE", heads
            authority_rows.append(value)  # type: ignore[arg-type]
        governance_value, privacy_value = authority_rows
        if (
            governance_value.get("policy_digest") != self.config.governance_policy_digest
            or privacy_value.get("policy_digest") != self.config.privacy_policy_digest
            or governance_value.get("decision") != "GRANTED"
            or privacy_value.get("privacy_decision") != "GRANTED"
            or privacy_value.get("support_decision") != "GRANTED"
        ):
            return "AUTHORITY_INDETERMINATE", heads
        for value in (governance_value, privacy_value):
            if type(value.get("valid_from")) is not int or type(value.get("valid_until")) is not int:
                return "AUTHORITY_INDETERMINATE", heads
            if now < int(value["valid_from"]) or now > int(value["valid_until"]):
                return "AUTHORITY_EXPIRED", heads
        return None, heads

    @staticmethod
    def _current_authority_heads(connection: sqlite3.Connection) -> dict[str, str | None]:
        heads: dict[str, str | None] = {}
        for kind in ("SOURCE_OBSERVATION", "GOVERNANCE", "PRIVACY"):
            head = connection.execute(
                "SELECT head_ref FROM core_heads WHERE stream_kind='ARTIFACT' AND stream_id=?",
                (kind,),
            ).fetchone()
            heads[kind] = str(head[0]) if head is not None else None
        return heads

    @staticmethod
    def _latest_pause_receipt(connection: sqlite3.Connection, session_id: str) -> CoreReceipt:
        head = connection.execute(
            "SELECT event_sequence FROM core_heads WHERE stream_kind='SESSION' AND stream_id=?",
            (session_id,),
        ).fetchone()
        if head is None:
            raise CoreError("core:session-head")
        event = connection.execute(
            "SELECT event_raw FROM core_events WHERE sequence=?",
            (int(head[0]),),
        ).fetchone()
        if event is None or type(event[0]) is not bytes:
            raise CoreError("core:session-head")
        parsed = independent._parse(event[0], "core:event-raw")
        if parsed.get("event_kind") != "SESSION_PAUSE":
            raise CoreConflictError("core:session-paused")
        return CoreServiceV2._receipt(bytes(event[0]))

    def _append_pause(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        *,
        operation_id: str,
        request_digest: str,
        trigger: str,
        observed_at: int,
        slot_number: int | None = None,
        observation_digest: str | None = None,
    ) -> CoreReceipt:
        reason, heads = self._authority_staleness(connection, row, observed_at)
        if reason is None:
            raise CoreConflictError("core:pause-current")
        material = {
            "state": "PAUSED",
            "reason": reason,
            "trigger": trigger,
            "current_source_artifact_id": heads["SOURCE_OBSERVATION"],
            "current_governance_artifact_id": heads["GOVERNANCE"],
            "current_privacy_artifact_id": heads["PRIVACY"],
            "slot_number": slot_number,
            "observation_digest": observation_digest,
        }
        raw = self._append(
            connection,
            kind="SESSION_PAUSE",
            operation_id=operation_id,
            subject_id=str(row["session_id"]),
            request_digest=request_digest,
            prior_state=str(row["state"]),
            next_state="PAUSED",
            attempt=0,
            observed_at=observed_at,
            material=material,
            payload_digest=_digest("pause-reason", {"reason": reason}),
            payload_length=0,
            stream_kind="SESSION",
            stream_id=str(row["session_id"]),
            head_ref=str(row["session_id"]),
        )
        event = independent._parse(raw, "core:event-raw")
        connection.execute(
            "UPDATE core_sessions SET state=?,head_root=? WHERE session_id=?",
            ("PAUSED", event["stream_after_root"], row["session_id"]),
        )
        return self._receipt(raw)

    @staticmethod
    def _result_from_event(connection: sqlite3.Connection, event_raw: bytes) -> dict[str, object]:
        event = independent._parse(event_raw, "core:event-raw")
        source_id = str(event["subject_id"]) if event["event_kind"] == "ARTIFACT" else None
        if event["event_kind"] == "ARTIFACT":
            row = connection.execute("SELECT raw FROM core_artifacts WHERE artifact_id=?", (source_id,)).fetchone()
            if row is None:
                raise CoreError("core:receipt")
            body = independent._parse(row[0], "core:artifact")
            if body.get("kind") == "SOURCE_OBSERVATION":
                rec = connection.execute("SELECT artifact_id FROM core_artifacts WHERE kind='RECONCILIATION' AND source_artifact_id=? ORDER BY created_event_sequence DESC LIMIT 1", (source_id,)).fetchone()
                graph_id = body.get("graph_artifact_id")
                return {"source_artifact_id": source_id, "graph_artifact_id": graph_id, "reconciliation_artifact_id": str(rec[0]) if rec else None, "observation_status": body.get("observation_status"), "receipt": CoreServiceV2._receipt(event_raw)}
        raise CoreError("core:receipt")

    @_mutation
    def ingest_source(self, ingress_path: str | Path, artifact_id: str) -> dict[str, object]:
        result = self._ingest_sources(ingress_path, (artifact_id,))
        return result[0]

    @_mutation
    def ingest_sources(self, ingress_path: str | Path, artifact_ids: tuple[str, ...]) -> tuple[dict[str, object], ...]:
        return self._ingest_sources(ingress_path, artifact_ids)

    def _ingest_sources(self, ingress_path: str | Path, artifact_ids: tuple[str, ...]) -> tuple[dict[str, object], ...]:
        if type(artifact_ids) is not tuple or not artifact_ids or len(artifact_ids) > MAX_BATCH_ARTIFACTS or len(set(artifact_ids)) != len(artifact_ids):
            raise CoreConflictError("core:source-batch")
        for value in artifact_ids:
            if type(value) is not str or len(value) != 128 or any(char not in "0123456789abcdef" for char in value):
                raise CoreConflictError("core:source-input")
        connection = self._open()
        local: dict[str, dict[str, object]] = {}
        unresolved: list[str] = []
        predecessor_ingress_id: str | None = None
        try:
            connection.execute("BEGIN")
            for artifact_id in artifact_ids:
                operation = _digest("source-operation", {"ingress_artifact_id": artifact_id})
                event = self._event(connection, operation)
                if event is None:
                    unresolved.append(artifact_id)
                else:
                    local[artifact_id] = self._result_from_event(connection, event)
            if unresolved:
                source_head = connection.execute("SELECT head_ref FROM core_heads WHERE stream_kind='ARTIFACT' AND stream_id='SOURCE_OBSERVATION'").fetchone()
                if source_head is not None:
                    prior_row = connection.execute("SELECT raw FROM core_artifacts WHERE artifact_id=? AND kind='SOURCE_OBSERVATION'", (source_head[0],)).fetchone()
                    if prior_row is None:
                        raise CoreError("core:source-head")
                    predecessor_ingress_id = str(independent._parse(prior_row[0], "core:artifact")["ingress_artifact_id"])
            connection.commit()
        finally:
            _finalize_core_connection(connection, transactional=False, cleanup_code="core:database", rollback_before_close=True)
        if not unresolved:
            return tuple(local[value] for value in artifact_ids)
        try:
            selected_ids = tuple(dict.fromkeys(unresolved + ([predecessor_ingress_id] if predecessor_ingress_id else [])))
            snapshots = ingress.read_artifact_snapshots(ingress_path, selected_ids)
            if any(not isinstance(snapshots.get(value), dict) or snapshots[value].get("artifact_id") != value for value in unresolved):
                raise CoreConflictError("core:source-not-current")
            if predecessor_ingress_id is not None and not isinstance(snapshots.get(predecessor_ingress_id), dict):
                raise CoreConflictError("core:source-predecessor")
            checked: dict[str, dict[str, object]] = {}
            for artifact_id in unresolved:
                item = snapshots[artifact_id]
                if item.get("terminal_state") != "QUARANTINED" or item.get("terminal_event_kind") != "ADMIT":
                    raise CoreConflictError("core:source-lifecycle")
                observation = item.get("observation")
                receipt = item.get("verification_receipt")
                if type(observation) is not bytes or type(receipt) is not bytes:
                    raise CoreConflictError("core:source-observation")
                try:
                    checked[artifact_id] = ingress.verify_observation_pair(observation, receipt)
                except ingress.IngressVerificationError:
                    raise CoreConflictError("core:source-observation") from None
        except (CoreError, CoreConflictError):
            raise
        except ingress.IngressVerificationError:
            raise CoreConflictError("core:ingress-reject") from None
        except Exception:
            raise_redacted(CoreError, "core:ingress-reject")
        connection = self._open()
        commit_attempted = False
        commit_succeeded = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            now = self._owner_now(connection)
            results: dict[str, dict[str, object]] = dict(local)
            ordered = sorted(unresolved, key=lambda value: int(snapshots[value]["event_sequence"]))
            for artifact_id in ordered:
                operation = _digest("source-operation", {"ingress_artifact_id": artifact_id})
                existing = self._event(connection, operation)
                if existing is not None:
                    results[artifact_id] = self._result_from_event(connection, existing)
                    continue
                ing = snapshots[artifact_id]
                checked_value = checked[artifact_id]
                observation_value = dict(checked_value["observation"])
                receipt_value = dict(checked_value["verification_receipt"])
                if ing["database_id"] != self.config.ingress_database_id or ing["chain_id"] != self.config.ingress_chain_id or ing["config_digest"] != self.config.ingress_config_digest:
                    raise CoreConflictError("core:source-profile")
                source_head = connection.execute("SELECT head_ref FROM core_heads WHERE stream_kind='ARTIFACT' AND stream_id='SOURCE_OBSERVATION'").fetchone()
                predecessor_id = str(source_head[0]) if source_head else None
                prior = None
                if predecessor_id is not None:
                    prior_row = connection.execute("SELECT raw FROM core_artifacts WHERE artifact_id=?", (predecessor_id,)).fetchone()
                    if prior_row is None:
                        raise CoreError("core:source-head")
                    prior = independent._parse(prior_row[0], "core:artifact")
                    prior_ingress = snapshots.get(str(prior["ingress_artifact_id"]))
                    if not isinstance(prior_ingress, dict) or not self._ingress_projection_matches(prior, prior_ingress):
                        raise CoreConflictError("core:source-predecessor")
                status, chronology = self._source_status(ing, prior)
                finding_id = _digest("sanitized-finding", {"profile_id": observation_value["profile_id"], "profile_version": observation_value["profile_version"], "observation_time": observation_value["observation_time"], "outcome": observation_value["outcome"]})
                graph_value: dict[str, object] = {
                    "schema": "mirror-core-graph-observation-v1",
                    "schema_version": 1,
                    "kind": "GRAPH",
                    "profile": {"profile_id": observation_value["profile_id"], "version": observation_value["profile_version"]},
                    "observation": observation_value,
                    "findings": [{"finding_id": finding_id, "kind": observation_value["outcome"]}],
                    "report": {"report_id": _digest("sanitized-report", {"profile_id": observation_value["profile_id"], "profile_version": observation_value["profile_version"], "observation_time": observation_value["observation_time"], "outcome": observation_value["outcome"], "finding_id": finding_id})},
                    "authority": dict(FIXED_FLAGS),
                }
                graph_raw = _canonical(graph_value)
                graph_digest = _raw_digest("graph-artifact", graph_raw)
                graph_report_id = str(graph_value["report"]["report_id"])
                graph_id, _ = self._admit_artifact(connection, kind="GRAPH", raw=graph_raw, profile_digest=self.config.runtime_profile_digest, predecessor_id=None, source_artifact_id=None, operation_id=_digest("graph-operation", {"graph_id": graph_report_id, "graph_digest": graph_digest}), request_digest=_digest("graph-request", {"graph_id": graph_report_id, "graph_digest": graph_digest}), state="GRAPH", observed_at=now)
                observation_identity = str(checked_value["observation_id"])
                source_body: dict[str, object] = {
                    "schema": "mirror-core-source-observation-v4", "schema_version": 4, "kind": "SOURCE_OBSERVATION", "artifact_id": "",
                    "ingress_database_id": ing["database_id"], "ingress_chain_id": ing["chain_id"], "ingress_config_digest": ing["config_digest"],
                    "ingress_artifact_id": artifact_id, "ingress_event_sequence": ing["event_sequence"], "ingress_prefix_root": ing.get("event_prefix_root"), "ingress_after_root": ing.get("event_after_root"), "ingress_head_root": ing.get("event_after_root"),
                    "observation_identity": observation_identity, "observation": observation_value, "verification_receipt": receipt_value,
                    "profile_id": observation_value["profile_id"], "profile_version": observation_value["profile_version"], "runtime_profile_digest": self.config.runtime_profile_digest,
                    "observation_time": observation_value["observation_time"], "source_status": observation_value["source_status"], "freshness": observation_value["freshness"], "page_complete": observation_value["page_complete"], "page_count": observation_value["page_count"], "resource_count": observation_value["resource_count"],
                    "source_count": observation_value["source_count"], "complete_source_count": observation_value["complete_source_count"], "record_count": observation_value["record_count"], "finding_count": observation_value["finding_count"], "discrepancy_count": observation_value["discrepancy_count"], "outcome": observation_value["outcome"],
                    "graph_artifact_id": graph_id, "graph_artifact_digest": graph_digest, "admission_receipt": receipt_value, "admission_report_id": graph_report_id,
                    "observation_status": status, "chronology": chronology, "flags": dict(FIXED_FLAGS),
                }
                if source_body["ingress_prefix_root"] is None or source_body["ingress_after_root"] is None:
                    raise CoreError("core:source-boundary")
                source_body["artifact_id"] = _digest("source-artifact-id", {key: value for key, value in source_body.items() if key not in {"artifact_id", "flags"}})
                source_id, _ = self._admit_artifact(connection, kind="SOURCE_OBSERVATION", raw=_canonical(source_body), profile_digest=self.config.runtime_profile_digest, predecessor_id=predecessor_id, source_artifact_id=artifact_id, operation_id=operation, request_digest=_digest("source-request", {"ingress_artifact_id": artifact_id}), state=status, observed_at=now, ingress_watermark=int(ing["event_sequence"]))
                rec_body: dict[str, object] = {
                    "schema": "mirror-core-reconciliation-v4", "schema_version": 4, "kind": "RECONCILIATION", "artifact_id": "",
                    "current_source_artifact_id": source_id, "prior_source_artifact_id": predecessor_id,
                    "current_observation_identity": observation_identity, "prior_observation_identity": prior.get("observation_identity") if prior else None,
                    "source_status": observation_value["source_status"], "observation_status": status, "chronology": chronology,
                    "linkage": "UNCHANGED" if prior and prior.get("observation_identity") == observation_identity else "LINKED", "flags": dict(FIXED_FLAGS),
                }
                rec_body["artifact_id"] = _digest("reconciliation-id", {key: value for key, value in rec_body.items() if key != "artifact_id"})
                rec_predecessor = self._find_reconciliation(connection, predecessor_id) if predecessor_id else None
                if predecessor_id is not None and rec_predecessor is None:
                    raise CoreConflictError("core:reconciliation-chain")
                rec_id, rec_event = self._admit_artifact(connection, kind="RECONCILIATION", raw=_canonical(rec_body), profile_digest=self.config.runtime_profile_digest, predecessor_id=rec_predecessor, source_artifact_id=source_id, operation_id=_digest("reconciliation-operation", {"source_artifact_id": source_id}), request_digest=_digest("reconciliation-request", {"source_artifact_id": source_id}), state=status, observed_at=now, ingress_watermark=int(ing["event_sequence"]))
                results[artifact_id] = {"source_artifact_id": source_id, "graph_artifact_id": graph_id, "reconciliation_artifact_id": rec_id, "observation_status": status, "receipt": self._receipt(rec_event)}
            commit_attempted = True
            connection.commit()
            commit_succeeded = True
            return tuple(results[value] for value in artifact_ids)
        except (CoreError, CoreConflictError):
            _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, close=False, continue_after_cleanup=True)
            raise
        except sqlite3.OperationalError as exc:
            _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, close=False, continue_after_cleanup=True)
            _sqlite_error(exc, busy=True)
        except sqlite3.Error as exc:
            _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, close=False, continue_after_cleanup=True)
            _sqlite_error(exc)
        finally:
            _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, identity_check=self._assert_database_identity, cleanup_code="core:database")
        raise CoreError("core:database")

    @staticmethod
    def _find_reconciliation(connection: sqlite3.Connection, source_id: str | None) -> str | None:
        if source_id is None:
            return None
        row = connection.execute("SELECT artifact_id FROM core_artifacts WHERE kind='RECONCILIATION' AND source_artifact_id=? ORDER BY created_event_sequence DESC LIMIT 1", (source_id,)).fetchone()
        return str(row[0]) if row else None

    def _admit_approval(self, raw: bytes, *, kind: str, profile_digest: str, decision: str) -> str:
        value = independent._parse(raw, "core:artifact")
        if value.get("kind") != kind or value.get("flags") != FIXED_FLAGS or value.get("policy_digest") != profile_digest:
            raise CoreError("core:approval")
        operation_id = _digest("approval-operation", {"kind": kind, "raw": _raw_digest("approval", raw)})
        connection = self._open()
        commit_attempted = False
        commit_succeeded = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._event(connection, operation_id)
            if existing is not None:
                commit_attempted = True
                connection.commit()
                commit_succeeded = True
                return str(independent._parse(existing, "core:event-raw")["material"]["artifact_id"])
            head = connection.execute("SELECT head_ref FROM core_heads WHERE stream_kind='ARTIFACT' AND stream_id=?", (kind,)).fetchone()
            predecessor = str(head[0]) if head else None
            now = self._owner_now(connection)
            artifact_id, _ = self._admit_artifact(connection, kind=kind, raw=raw, profile_digest=profile_digest, predecessor_id=predecessor, source_artifact_id=None, operation_id=operation_id, request_digest=_digest("approval-request", {"kind": kind, "raw": _raw_digest("approval", raw)}), state=decision, observed_at=now)
            commit_attempted = True
            connection.commit()
            commit_succeeded = True
            return artifact_id
        except (CoreError, CoreConflictError):
            _finalize_core_connection(
                connection,
                commit_attempted=commit_attempted,
                commit_succeeded=commit_succeeded,
                close=False,
                continue_after_cleanup=True,
            )
            raise
        except sqlite3.Error as exc:
            _finalize_core_connection(
                connection,
                commit_attempted=commit_attempted,
                commit_succeeded=commit_succeeded,
                close=False,
                continue_after_cleanup=True,
            )
            _sqlite_error(exc)
        finally:
            _finalize_core_connection(
                connection,
                commit_attempted=commit_attempted,
                commit_succeeded=commit_succeeded,
                identity_check=self._assert_database_identity,
                cleanup_code="core:database",
            )
        raise CoreError("core:database")

    @_mutation
    def admit_governance(self, raw: bytes, *, policy: object, evidence_raw: bytes) -> str:
        try:
            result = governance.verify_artifact(raw, policy=policy.material(), evidence_raw=evidence_raw)
            value = independent._parse(raw, "core:artifact")
            if result.get("accepted") is not True or value.get("policy_digest") != self.config.governance_policy_digest or value.get("policy_digest") != policy.digest:
                raise CoreError("core:governance")
            assertion = value["assertion"]
            projection = {"schema": "mirror-core-governance-v3", "schema_version": 3, "kind": "GOVERNANCE", "artifact_id": value["artifact_id"], "decision": assertion["decision"], "policy_digest": value["policy_digest"], "evidence_digest": assertion["evidence_sha3_512"], "verifier_id": assertion["verifier_id"], "verifier_epoch": assertion["verifier_epoch"], "valid_from": assertion["valid_from"], "valid_until": assertion["valid_until"], "flags": dict(FIXED_FLAGS)}
            return self._admit_approval(_canonical(projection), kind="GOVERNANCE", profile_digest=self.config.governance_policy_digest, decision=str(assertion["decision"]))
        except CoreError:
            raise
        except Exception:
            raise_redacted(CoreError, "core:governance")

    @_mutation
    def admit_privacy(self, raw: bytes, *, policy: object, evidence_raw: bytes) -> str:
        try:
            result = privacy.verify_artifact(raw, policy=policy.material(), evidence_raw=evidence_raw)
            value = independent._parse(raw, "core:artifact")
            if result.get("accepted") is not True or value.get("policy_digest") != self.config.privacy_policy_digest or value.get("policy_digest") != policy.digest:
                raise CoreError("core:privacy")
            assertion = value["assertion"]
            projection = {"schema": "mirror-core-privacy-v3", "schema_version": 3, "kind": "PRIVACY", "artifact_id": value["artifact_id"], "privacy_decision": assertion["privacy_decision"], "support_decision": assertion["support_decision"], "policy_digest": value["policy_digest"], "evidence_digest": assertion["evidence_sha3_512"], "verifier_id": assertion["verifier_id"], "verifier_epoch": assertion["verifier_epoch"], "valid_from": assertion["valid_from"], "valid_until": assertion["valid_until"], "flags": dict(FIXED_FLAGS)}
            return self._admit_approval(_canonical(projection), kind="PRIVACY", profile_digest=self.config.privacy_policy_digest, decision=str(assertion["privacy_decision"]))
        except CoreError:
            raise
        except Exception:
            raise_redacted(CoreError, "core:privacy")

    @staticmethod
    def _case_graph(connection: sqlite3.Connection, source_artifact_id: str) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
        source_row = connection.execute("SELECT raw FROM core_artifacts WHERE artifact_id=? AND kind='SOURCE_OBSERVATION'", (source_artifact_id,)).fetchone()
        if source_row is None:
            raise CoreConflictError("core:case-source")
        source = independent._parse(source_row[0], "core:case-source")
        graph_row = connection.execute("SELECT raw FROM core_artifacts WHERE artifact_id=? AND kind='GRAPH'", (source["graph_artifact_id"],)).fetchone()
        if graph_row is None:
            raise CoreConflictError("core:case-graph")
        graph_value = independent._parse(graph_row[0], "core:case-graph")
        report = graph_value.get("report")
        if not isinstance(report, dict) or not isinstance(report.get("report_id"), str):
            raise CoreConflictError("core:case-graph")
        return source, graph_value, graph_row

    @_mutation
    def admit_case(self, reconciliation_artifact_id: str) -> str:
        _require_digest(reconciliation_artifact_id, "core:case-input")
        connection = self._open()
        commit_attempted = False
        commit_succeeded = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            rec_row = connection.execute("SELECT raw FROM core_artifacts WHERE artifact_id=? AND kind='RECONCILIATION'", (reconciliation_artifact_id,)).fetchone()
            if rec_row is None:
                raise CoreConflictError("core:case-reconciliation")
            reconciliation = independent._parse(rec_row[0], "core:case-reconciliation")
            source_id = str(reconciliation["current_source_artifact_id"])
            reconciliation_head = connection.execute(
                "SELECT head_ref FROM core_heads WHERE stream_kind='ARTIFACT' AND stream_id='RECONCILIATION'"
            ).fetchone()
            source_head = connection.execute(
                "SELECT head_ref FROM core_heads WHERE stream_kind='ARTIFACT' AND stream_id='SOURCE_OBSERVATION'"
            ).fetchone()
            if reconciliation_head is None or reconciliation_head[0] != reconciliation_artifact_id or source_head is None or source_head[0] != source_id:
                raise CoreConflictError("core:case-not-current")
            source, graph_value, _graph_row = self._case_graph(connection, source_id)
            findings = graph_value.get("findings")
            if not isinstance(findings, list):
                raise CoreConflictError("core:case-findings")
            actionable = [finding for finding in findings if isinstance(finding, dict) and finding.get("kind") != "CONTINUITY_CONFIRMED"]
            if not actionable:
                raise CoreConflictError("core:case-no-actionable-finding")
            target_ids = tuple(sorted(str(finding["finding_id"]) for finding in actionable))
            target_kinds = tuple(str(finding["kind"]) for finding in sorted(actionable, key=lambda item: str(item["finding_id"])))
            report_id = str(graph_value["report"]["report_id"])
            subject = {
                "profile_id": graph_value["profile"]["profile_id"],
                "profile_version": graph_value["profile"]["version"],
            }
            subject_digest = _digest("case-subject", subject)
            case_id = _digest("case-id", {"reconciliation_artifact_id": reconciliation_artifact_id, "source_artifact_id": source_id, "graph_artifact_id": source["graph_artifact_id"], "graph_report_id": report_id, "profile_digest": self.config.runtime_profile_digest, "subject_digest": subject_digest, "target_finding_ids": list(target_ids), "target_finding_kinds": list(target_kinds)})
            operation_id = _digest("case-operation", {"case_id": case_id})
            existing = self._event(connection, operation_id)
            if existing is not None:
                material = independent._parse(existing, "core:event-raw")["material"]
                commit_attempted = True
                connection.commit(); commit_succeeded = True
                return str(material["artifact_id"])
            body: dict[str, object] = {
                "schema": "mirror-core-case-v4", "schema_version": 4, "kind": "CASE", "artifact_id": "",
                "case_id": case_id, "reconciliation_artifact_id": reconciliation_artifact_id, "source_artifact_id": source_id,
                "graph_artifact_id": source["graph_artifact_id"], "graph_report_id": report_id, "graph_profile_digest": self.config.runtime_profile_digest,
                "subject_digest": subject_digest, "target_finding_ids": list(target_ids), "target_finding_kinds": list(target_kinds),
                "state": "OPEN", "responsibility": "UNKNOWN", "reason": "ACTIONABLE_FINDING", "action_artifact_id": None,
                "action_observed_at": None, "retest_source_artifact_id": None, "retest_graph_artifact_id": None, "retest_observation_time": None,
                "flags": dict(FIXED_FLAGS),
            }
            body["artifact_id"] = _digest("case-artifact", {key: body[key] for key in body if key != "artifact_id"})
            now = self._owner_now(connection)
            artifact_id, _ = self._admit_artifact(connection, kind="CASE", raw=_canonical(body), profile_digest=self.config.runtime_profile_digest, predecessor_id=None, source_artifact_id=source_id, operation_id=operation_id, request_digest=_digest("case-request", {"reconciliation_artifact_id": reconciliation_artifact_id, "case_id": case_id}), state="OPEN", observed_at=now)
            commit_attempted = True
            connection.commit(); commit_succeeded = True
            return artifact_id
        except (CoreError, CoreConflictError):
            _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, close=False, continue_after_cleanup=True)
            raise
        except sqlite3.Error as exc:
            _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, close=False, continue_after_cleanup=True)
            _sqlite_error(exc)
        finally:
            _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, identity_check=self._assert_database_identity, cleanup_code="core:database")
        raise CoreError("core:database")

    def _read_open_case_for_action(
        self,
        current_case_artifact_id: str,
        control: corrective_action.CorrectiveActionControlV1,
        evidence_raw: bytes,
    ) -> tuple[corrective_action.CorrectiveActionPolicyV1 | None, str | None]:
        connection: sqlite3.Connection | None = None
        try:
            connection = self._open()
            row = connection.execute(
                "SELECT raw,predecessor_id FROM core_artifacts WHERE artifact_id=? AND kind='CASE'",
                (current_case_artifact_id,),
            ).fetchone()
            if row is None or type(row["raw"]) is not bytes:
                raise CoreConflictError("core:case-missing")
            case = independent._parse(row["raw"], "core:case")
            action_case: dict[str, object] | None = None
            action_row_id: str | None = None
            expected_action_current_id: str | None = None
            if case.get("state") == "ACTION_RECORDED":
                action_case = case
                action_row_id = case.get("action_artifact_id")
                expected_action_current_id = row["predecessor_id"]
            elif case.get("state") == "OPEN":
                successor_rows = connection.execute(
                    "SELECT raw FROM core_artifacts WHERE kind='CASE' AND predecessor_id=? ORDER BY created_event_sequence",
                    (current_case_artifact_id,),
                ).fetchall()
                if len(successor_rows) > 1:
                    raise CoreConflictError("core:case-chain")
                if successor_rows:
                    candidate = independent._parse(successor_rows[0]["raw"], "core:case")
                    if candidate.get("state") == "ACTION_RECORDED":
                        action_case = candidate
                        action_row_id = candidate.get("action_artifact_id")
                        expected_action_current_id = current_case_artifact_id
            if action_case is not None:
                if type(action_row_id) is not str:
                    raise CoreConflictError("core:case-action")
                action_row = connection.execute(
                    "SELECT raw FROM core_artifacts WHERE artifact_id=? AND kind='CASE_ACTION'",
                    (action_row_id,),
                ).fetchone()
                if action_row is None or type(action_row["raw"]) is not bytes:
                    raise CoreConflictError("core:case-action")
                try:
                    action = corrective_action_independent.verify_artifact(
                        action_row["raw"],
                        evidence_raw=evidence_raw,
                        control_digest=control.digest,
                    )
                except Exception:
                    raise_redacted(CoreConflictError, "core:action-verification")
                if action.get("current_case_artifact_id") != expected_action_current_id or action.get("case_id") != action_case.get("case_id"):
                    raise CoreConflictError("core:action-binding")
                return None, _digest(
                    "case-transition-operation",
                    {
                        "case_artifact_id": expected_action_current_id,
                        "action_artifact_id": action_row_id,
                        "transition": "ACTION_RECORDED",
                    },
                )
            if case.get("state") != "OPEN":
                raise CoreConflictError("core:case-state")
            head = connection.execute(
                "SELECT head_ref FROM core_heads WHERE stream_kind='ARTIFACT' AND stream_id=?",
                (case["case_id"],),
            ).fetchone()
            if head is None or head["head_ref"] != current_case_artifact_id:
                raise CoreConflictError("core:case-head")
            return corrective_action.CorrectiveActionPolicyV1.for_case(
                case,
                control,
                current_case_artifact_id=current_case_artifact_id,
            ), None
        except (CoreError, CoreConflictError):
            raise
        except independent.CoreVerificationError:
            raise_redacted(CoreConflictError, "core:case")
        except (OSError, sqlite3.Error, TypeError, ValueError, KeyError):
            raise_redacted(CoreConflictError, "core:case")
        finally:
            _finalize_core_connection(
                connection,
                identity_check=self._assert_database_identity,
                transactional=False,
                cleanup_code="core:case",
            )

    @_mutation
    def record_case_action(self, current_case_artifact_id: str, *, evidence_raw: bytes) -> CoreReceipt:
        _require_digest(current_case_artifact_id, "core:case-input")
        control, verifier = self._require_corrective_action_dependencies()
        if type(evidence_raw) is not bytes or not evidence_raw or len(evidence_raw) > control.max_evidence_bytes:
            raise CoreConflictError("core:action-evidence")
        policy, retry_operation_id = self._read_open_case_for_action(current_case_artifact_id, control, evidence_raw)
        if retry_operation_id is not None:
            connection = self._open(); commit_attempted = False; commit_succeeded = False
            try:
                connection.execute("BEGIN IMMEDIATE")
                existing = self._event(connection, retry_operation_id)
                if existing is None:
                    raise CoreConflictError("core:case-retry")
                commit_attempted = True; connection.commit(); commit_succeeded = True
                return self._receipt(existing)
            except (CoreError, CoreConflictError):
                _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, close=False, continue_after_cleanup=True); raise
            except sqlite3.Error as exc:
                _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, close=False, continue_after_cleanup=True); _sqlite_error(exc)
            finally:
                _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, identity_check=self._assert_database_identity, cleanup_code="core:database")
        if policy is None:
            raise CoreConflictError("core:case")
        try:
            with self._authority.external_scope():
                action_raw = corrective_action.CorrectiveActionService(
                    policy,
                    verifier,
                    control=control,
                ).observe(evidence_raw)
                checked = corrective_action_independent.verify_artifact(
                    action_raw,
                    policy=policy.material(),
                    evidence_raw=evidence_raw,
                    control_digest=control.digest,
                )
        except Exception:
            raise_redacted(CoreConflictError, "core:action-verification")
        self._require_corrective_action_dependencies()
        action_id = str(checked["artifact_id"])
        action_row_id = _digest(
            "artifact-row-id",
            {
                "kind": "CASE_ACTION",
                "raw": _raw_digest("artifact-bytes", action_raw),
                "profile_digest": self.config.runtime_profile_digest,
                "source_artifact_id": policy.source_artifact_id,
                "predecessor_id": current_case_artifact_id,
            },
        )
        operation_id = _digest("case-transition-operation", {"case_artifact_id": current_case_artifact_id, "action_artifact_id": action_row_id, "transition": "ACTION_RECORDED"})
        connection = self._open(); commit_attempted = False; commit_succeeded = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._require_corrective_action_dependencies()
            existing = self._event(connection, operation_id)
            if existing is not None:
                commit_attempted = True; connection.commit(); commit_succeeded = True; return self._receipt(existing)
            case_row = connection.execute("SELECT raw,predecessor_id FROM core_artifacts WHERE artifact_id=? AND kind='CASE'", (current_case_artifact_id,)).fetchone()
            if case_row is None:
                raise CoreConflictError("core:case-missing")
            prior = independent._parse(case_row[0], "core:case")
            if prior.get("state") != "OPEN":
                raise CoreConflictError("core:case-state")
            head = connection.execute("SELECT head_ref FROM core_heads WHERE stream_kind='ARTIFACT' AND stream_id=?", (prior["case_id"],)).fetchone()
            if head is None or head[0] != current_case_artifact_id:
                raise CoreConflictError("core:case-head")
            if (
                checked["case_id"] != prior["case_id"]
                or checked["current_case_artifact_id"] != current_case_artifact_id
                or checked["source_artifact_id"] != prior["source_artifact_id"]
                or checked["graph_artifact_id"] != prior["graph_artifact_id"]
                or checked["graph_report_id"] != prior["graph_report_id"]
                or tuple(checked["target_finding_ids"]) != tuple(prior["target_finding_ids"])
                or tuple(checked["target_finding_kinds"]) != tuple(prior["target_finding_kinds"])
            ):
                raise CoreConflictError("core:action-binding")
            current_policy = corrective_action.CorrectiveActionPolicyV1.for_case(
                prior,
                control,
                current_case_artifact_id=current_case_artifact_id,
            )
            if current_policy.material() != policy.material() or checked.get("control_digest") != control.digest:
                raise CoreConflictError("core:action-control")
            now = self._owner_now(connection)
            if not control.valid_from <= now <= control.valid_until or int(checked["observed_at"]) > now:
                raise CoreConflictError("core:action-time")
            action_op = _digest("case-action-operation", {"action_id": action_id, "case_id": prior["case_id"]})
            action_req = _digest("case-action-request", {"action_id": action_id, "case_id": prior["case_id"], "evidence_digest": checked["evidence_sha3_512"]})
            stored_action_row_id, _ = self._admit_artifact(connection, kind="CASE_ACTION", raw=action_raw, profile_digest=self.config.runtime_profile_digest, predecessor_id=current_case_artifact_id, source_artifact_id=prior["source_artifact_id"], operation_id=action_op, request_digest=action_req, state="ACTION_RECORDED", observed_at=now, event_stream_kind="CASE_ACTION", event_stream_id=str(prior["case_id"]))
            if stored_action_row_id != action_row_id:
                raise CoreConflictError("core:action-binding")
            body = dict(prior); body.update({"artifact_id": "", "state": "ACTION_RECORDED", "reason": "ACTION_VERIFIED", "action_artifact_id": action_row_id, "action_observed_at": int(checked["observed_at"])})
            body["artifact_id"] = _digest("case-artifact", {key: body[key] for key in body if key != "artifact_id"})
            _artifact_id, event_raw = self._admit_artifact(connection, kind="CASE", raw=_canonical(body), profile_digest=self.config.runtime_profile_digest, predecessor_id=current_case_artifact_id, source_artifact_id=str(prior["source_artifact_id"]), operation_id=operation_id, request_digest=_digest("case-transition-request", {"case_artifact_id": current_case_artifact_id, "action_artifact_id": action_row_id, "transition": "ACTION_RECORDED"}), state="ACTION_RECORDED", observed_at=now)
            commit_attempted = True; connection.commit(); commit_succeeded = True
            return self._receipt(event_raw)
        except (CoreError, CoreConflictError):
            _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, close=False, continue_after_cleanup=True); raise
        except sqlite3.Error as exc:
            _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, close=False, continue_after_cleanup=True); _sqlite_error(exc)
        finally:
            _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, identity_check=self._assert_database_identity, cleanup_code="core:database")
        raise CoreError("core:database")

    @_mutation
    def evaluate_case(self, current_case_artifact_id: str, later_source_artifact_id: str) -> CoreReceipt:
        _require_digest(current_case_artifact_id, "core:case-input")
        _require_digest(later_source_artifact_id, "core:source-input")
        operation_id = _digest("case-evaluate-operation", {"case_artifact_id": current_case_artifact_id, "later_source_artifact_id": later_source_artifact_id})
        connection = self._open(); commit_attempted = False; commit_succeeded = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._event(connection, operation_id)
            if existing is not None:
                commit_attempted = True; connection.commit(); commit_succeeded = True; return self._receipt(existing)
            case_row = connection.execute("SELECT raw,predecessor_id FROM core_artifacts WHERE artifact_id=? AND kind='CASE'", (current_case_artifact_id,)).fetchone()
            if case_row is None:
                raise CoreConflictError("core:case-missing")
            prior = independent._parse(case_row[0], "core:case")
            if prior.get("state") != "ACTION_RECORDED":
                raise CoreConflictError("core:case-state")
            predecessor_case_id = case_row["predecessor_id"]
            if type(predecessor_case_id) is not str:
                raise CoreConflictError("core:case-action")
            action_id = prior.get("action_artifact_id")
            if not isinstance(action_id, str):
                raise CoreConflictError("core:case-action")
            action_row = connection.execute(
                "SELECT raw FROM core_artifacts WHERE artifact_id=? AND kind='CASE_ACTION'",
                (action_id,),
            ).fetchone()
            if action_row is None or type(action_row[0]) is not bytes:
                raise CoreConflictError("core:case-action")
            try:
                action = corrective_action_independent.verify_artifact(
                    action_row[0],
                    control_digest=self.config.corrective_action_control_digest,
                )
            except Exception:
                raise_redacted(CoreConflictError, "core:case-action")
            if (
                action["current_case_artifact_id"] != predecessor_case_id
                or action["case_id"] != prior["case_id"]
                or action["source_artifact_id"] != prior["source_artifact_id"]
                or action["graph_artifact_id"] != prior["graph_artifact_id"]
                or action["graph_report_id"] != prior["graph_report_id"]
                or tuple(action["target_finding_ids"]) != tuple(prior["target_finding_ids"])
                or tuple(action["target_finding_kinds"]) != tuple(prior["target_finding_kinds"])
                or int(action["observed_at"]) != int(prior["action_observed_at"])
            ):
                raise CoreConflictError("core:case-action")
            head = connection.execute("SELECT head_ref FROM core_heads WHERE stream_kind='ARTIFACT' AND stream_id=?", (prior["case_id"],)).fetchone()
            if head is None or head[0] != current_case_artifact_id:
                raise CoreConflictError("core:case-head")
            later, later_graph, _ = self._case_graph(connection, later_source_artifact_id)
            initial, initial_graph, _ = self._case_graph(connection, str(prior["source_artifact_id"]))
            source_head = connection.execute(
                "SELECT head_ref FROM core_heads WHERE stream_kind='ARTIFACT' AND stream_id='SOURCE_OBSERVATION'"
            ).fetchone()
            if source_head is None or source_head[0] != later_source_artifact_id:
                raise CoreConflictError("core:case-source-not-current")
            if (
                later_graph.get("profile", {}).get("profile_id") != initial_graph.get("profile", {}).get("profile_id")
                or later_graph.get("profile", {}).get("version") != initial_graph.get("profile", {}).get("version")
                or later_graph.get("profile") != initial_graph.get("profile")
            ):
                raise CoreConflictError("core:case-lineage")
            if int(later["observation_time"]) <= int(prior["action_observed_at"]):
                raise CoreConflictError("core:case-chronology")
            later_findings = {str(item["kind"]) for item in later_graph.get("findings", []) if isinstance(item, dict)}
            target_kinds = set(str(item) for item in prior["target_finding_kinds"])
            if later.get("observation_status") in {"INCOMPLETE", "OBSERVATION_ONLY"}:
                state = "RETEST_FAILED_OR_INDETERMINATE"; reason = "RETEST_INDETERMINATE"
            elif target_kinds.isdisjoint(later_findings) and "CONTINUITY_CONFIRMED" in later_findings:
                state = "RESOLVED"; reason = "ALL_TARGET_FINDINGS_CLEARED"
            else:
                state = "RETEST_FAILED_OR_INDETERMINATE"; reason = "TARGET_FINDINGS_REMAIN"
            now = self._owner_now(connection)
            body = dict(prior); body.update({"artifact_id": "", "state": state, "reason": reason, "retest_source_artifact_id": later_source_artifact_id, "retest_graph_artifact_id": later["graph_artifact_id"], "retest_observation_time": int(later["observation_time"])})
            body["artifact_id"] = _digest("case-artifact", {key: body[key] for key in body if key != "artifact_id"})
            _artifact_id, event_raw = self._admit_artifact(connection, kind="CASE", raw=_canonical(body), profile_digest=self.config.runtime_profile_digest, predecessor_id=current_case_artifact_id, source_artifact_id=str(prior["source_artifact_id"]), operation_id=operation_id, request_digest=_digest("case-evaluate-request", {"case_artifact_id": current_case_artifact_id, "later_source_artifact_id": later_source_artifact_id, "state": state, "reason": reason}), state=state, observed_at=now)
            commit_attempted = True; connection.commit(); commit_succeeded = True
            return self._receipt(event_raw)
        except (CoreError, CoreConflictError):
            _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, close=False, continue_after_cleanup=True); raise
        except sqlite3.Error as exc:
            _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, close=False, continue_after_cleanup=True); _sqlite_error(exc)
        finally:
            _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, identity_check=self._assert_database_identity, cleanup_code="core:database")
        raise CoreError("core:database")

    @staticmethod
    def _session(connection: sqlite3.Connection, session_id: str) -> sqlite3.Row:
        if type(session_id) is not str or len(session_id) != 128 or any(char not in "0123456789abcdef" for char in session_id):
            raise CoreConflictError("core:session-input")
        row = connection.execute("SELECT * FROM core_sessions WHERE session_id=?", (session_id,)).fetchone()
        if row is None:
            raise CoreConflictError("core:session-missing")
        return row

    @_mutation
    def open_session(self) -> CoreReceipt:
        connection = self._open()
        commit_attempted = False
        commit_succeeded = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            heads = self._current_authority_heads(connection)
            for kind in ("SOURCE_OBSERVATION", "GOVERNANCE", "PRIVACY"):
                if heads[kind] is None:
                    raise CoreConflictError("core:authority-head")
                _require_digest(heads[kind], "core:authority-head")
            source_artifact_id = str(heads["SOURCE_OBSERVATION"])
            governance_artifact_id = str(heads["GOVERNANCE"])
            privacy_artifact_id = str(heads["PRIVACY"])
            session_id = _digest("session-id", {"source": source_artifact_id, "governance": governance_artifact_id, "privacy": privacy_artifact_id, "config": self.config.digest})
            operation_id = _digest("session-operation", {"session_id": session_id, "action": "OPEN"})
            existing = self._event(connection, operation_id)
            if existing is not None:
                commit_attempted = True
                connection.commit()
                commit_succeeded = True
                return self._receipt(existing)
            now = self._owner_now(connection)
            for kind, expected in (("SOURCE_OBSERVATION", source_artifact_id), ("GOVERNANCE", governance_artifact_id), ("PRIVACY", privacy_artifact_id)):
                if type(expected) is not str or len(expected) != 128 or any(char not in "0123456789abcdef" for char in expected):
                    raise CoreConflictError("core:authority-head")
                head = connection.execute("SELECT head_ref FROM core_heads WHERE stream_kind='ARTIFACT' AND stream_id=?", (kind,)).fetchone()
                if head is None or head[0] != expected:
                    raise CoreConflictError("core:authority-head")
            rows = {}
            for kind, identifier in (("SOURCE_OBSERVATION", source_artifact_id), ("GOVERNANCE", governance_artifact_id), ("PRIVACY", privacy_artifact_id)):
                row = connection.execute("SELECT raw,profile_digest FROM core_artifacts WHERE artifact_id=? AND kind=?", (identifier, kind)).fetchone()
                if row is None or type(row[0]) is not bytes:
                    raise CoreConflictError("core:authority-missing")
                expected_profile = self.config.runtime_profile_digest if kind == "SOURCE_OBSERVATION" else self.config.governance_policy_digest if kind == "GOVERNANCE" else self.config.privacy_policy_digest
                if row[1] != expected_profile:
                    raise CoreConflictError("core:authority-config")
                rows[kind] = independent._parse(row[0], "core:artifact")
            gov = rows["GOVERNANCE"]; pval = rows["PRIVACY"]; source = rows["SOURCE_OBSERVATION"]
            if source.get("runtime_profile_digest") != self.config.runtime_profile_digest or gov.get("policy_digest") != self.config.governance_policy_digest or pval.get("policy_digest") != self.config.privacy_policy_digest:
                raise CoreConflictError("core:authority-config")
            if gov.get("decision") != "GRANTED" or pval.get("privacy_decision") != "GRANTED" or pval.get("support_decision") != "GRANTED":
                raise CoreConflictError("core:authority-negative")
            for authority in (gov, pval):
                if type(authority.get("valid_from")) is not int or type(authority.get("valid_until")) is not int or int(authority["valid_from"]) > now or now > int(authority["valid_until"]):
                    raise CoreConflictError("core:authority-window")
            capacity_row = connection.execute("SELECT COUNT(*) FROM core_sessions").fetchone()
            if capacity_row is None or type(capacity_row[0]) is not int:
                raise CoreError("core:capacity")
            if capacity_row[0] >= self.config.max_sessions:
                raise CoreConflictError("core:capacity")
            material = {"session_id": session_id, "state": "OPEN", "source_artifact_id": source_artifact_id, "governance_artifact_id": governance_artifact_id, "privacy_artifact_id": privacy_artifact_id, "last_slot": -1}
            connection.execute("INSERT INTO core_sessions(session_id,state,source_artifact_id,governance_artifact_id,privacy_artifact_id,head_root,last_slot) VALUES(?,?,?,?,?,?,?)", (session_id, "OPEN", source_artifact_id, governance_artifact_id, privacy_artifact_id, independent.GENESIS_ROOT, -1))
            raw = self._append(connection, kind="SESSION_OPEN", operation_id=operation_id, subject_id=session_id, request_digest=_digest("session-request", {"session_id": session_id}), prior_state="NONE", next_state="OPEN", attempt=0, observed_at=now, material={"session": material}, payload_digest=source_artifact_id, payload_length=0, stream_kind="SESSION", stream_id=session_id, head_ref=session_id)
            stream_root = independent._parse(raw, "core:event-raw")["stream_after_root"]
            connection.execute("UPDATE core_sessions SET head_root=? WHERE session_id=?", (stream_root, session_id))
            commit_attempted = True
            connection.commit()
            commit_succeeded = True
            return self._receipt(raw)
        except (CoreError, CoreConflictError):
            _finalize_core_connection(
                connection,
                commit_attempted=commit_attempted,
                commit_succeeded=commit_succeeded,
                close=False,
                continue_after_cleanup=True,
            )
            raise
        except sqlite3.Error as exc:
            _finalize_core_connection(
                connection,
                commit_attempted=commit_attempted,
                commit_succeeded=commit_succeeded,
                close=False,
                continue_after_cleanup=True,
            )
            _sqlite_error(exc)
        finally:
            _finalize_core_connection(
                connection,
                commit_attempted=commit_attempted,
                commit_succeeded=commit_succeeded,
                identity_check=self._assert_database_identity,
                cleanup_code="core:database",
            )
        raise CoreError("core:database")

    @_mutation
    def start_session(self, session_id: str) -> CoreReceipt:
        _require_digest(session_id, "core:session-input")
        operation_id = _digest("session-operation", {"session_id": session_id, "action": "START"})
        request_digest = _digest("session-request", {"session_id": session_id, "action": "START"})
        connection = self._open()
        commit_attempted = False
        commit_succeeded = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._event(connection, operation_id)
            if existing is not None:
                parsed = independent._parse(existing, "core:event-raw")
                if parsed.get("event_kind") not in {"SESSION_START", "SESSION_PAUSE"}:
                    raise CoreConflictError("core:operation-conflict")
                if parsed.get("event_kind") == "SESSION_PAUSE" and parsed.get("material", {}).get("trigger") != "START":
                    raise CoreConflictError("core:operation-conflict")
                commit_attempted = True
                connection.commit()
                commit_succeeded = True
                return self._receipt(existing)
            row = self._session(connection, session_id)
            if row["state"] == "PAUSED":
                receipt = self._latest_pause_receipt(connection, session_id)
                commit_attempted = True
                connection.commit()
                commit_succeeded = True
                return receipt
            if row["state"] != "OPEN":
                raise CoreConflictError("core:session-state")
            now = self._owner_now(connection)
            reason, _heads = self._authority_staleness(connection, row, now)
            if reason is not None:
                receipt = self._append_pause(
                    connection,
                    row,
                    operation_id=operation_id,
                    request_digest=request_digest,
                    trigger="START",
                    observed_at=now,
                )
                commit_attempted = True
                connection.commit()
                commit_succeeded = True
                return receipt
            raw = self._append(connection, kind="SESSION_START", operation_id=operation_id, subject_id=session_id, request_digest=_digest("session-request", {"session_id": session_id, "action": "START"}), prior_state="OPEN", next_state="RUNNING", attempt=0, observed_at=now, material={"delta": {"state": "RUNNING"}}, payload_digest=session_id, payload_length=0, stream_kind="SESSION", stream_id=session_id, head_ref=session_id)
            event = independent._parse(raw, "core:event-raw")
            connection.execute("UPDATE core_sessions SET state=?,head_root=? WHERE session_id=?", ("RUNNING", event["stream_after_root"], session_id))
            commit_attempted = True
            connection.commit()
            commit_succeeded = True
            return self._receipt(raw)
        except (CoreError, CoreConflictError):
            _finalize_core_connection(
                connection,
                commit_attempted=commit_attempted,
                commit_succeeded=commit_succeeded,
                close=False,
                continue_after_cleanup=True,
            )
            raise
        except sqlite3.Error as exc:
            _finalize_core_connection(
                connection,
                commit_attempted=commit_attempted,
                commit_succeeded=commit_succeeded,
                close=False,
                continue_after_cleanup=True,
            )
            _sqlite_error(exc)
        finally:
            _finalize_core_connection(
                connection,
                commit_attempted=commit_attempted,
                commit_succeeded=commit_succeeded,
                identity_check=self._assert_database_identity,
                cleanup_code="core:database",
            )
        raise CoreError("core:database")

    @_mutation
    def observe(self, session_id: str, slot_number: int, result: str, *, counts: Mapping[str, int] | None = None) -> CoreReceipt:
        _require_digest(session_id, "core:observation-input")
        if type(slot_number) is not int or slot_number < 0 or slot_number >= self.config.max_slots_per_session or result not in independent.OBSERVATION_RESULTS:
            raise CoreConflictError("core:observation-input")
        values = dict(counts or {"observed": 0, "changed": 0})
        if set(values) != {"observed", "changed"} or any(type(value) is not int or value < 0 or value > 64 for value in values.values()):
            raise CoreConflictError("core:observation-input")
        observation = {"schema": "mirror-core-observation-v3", "schema_version": 3, "session_id": session_id, "slot_number": slot_number, "result": result, "counts": {"changed": values["changed"], "observed": values["observed"]}, "flags": dict(FIXED_FLAGS)}
        observation["result_digest"] = _digest("observation", {key: observation[key] for key in observation if key != "result_digest"})
        result_raw = _canonical(observation)
        operation_id = _digest("observation-operation", {"session_id": session_id, "slot_number": slot_number})
        connection = self._open()
        commit_attempted = False
        commit_succeeded = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._event(connection, operation_id)
            if existing is not None:
                parsed = independent._parse(existing, "core:event-raw")
                material = parsed.get("material")
                exact_observation = isinstance(material, dict) and material.get("observation") == observation
                exact_pause = (
                    isinstance(material, dict)
                    and parsed.get("event_kind") == "SESSION_PAUSE"
                    and material.get("trigger") == "OBSERVATION"
                    and material.get("slot_number") == slot_number
                    and material.get("observation_digest") == observation["result_digest"]
                )
                if not exact_observation and not exact_pause:
                    raise CoreConflictError("core:observation-conflict")
                commit_attempted = True
                connection.commit()
                commit_succeeded = True
                return self._receipt(existing)
            row = self._session(connection, session_id)
            if row["state"] == "PAUSED":
                receipt = self._latest_pause_receipt(connection, session_id)
                commit_attempted = True
                connection.commit()
                commit_succeeded = True
                return receipt
            if row["state"] not in {"OPEN", "RUNNING"}:
                raise CoreConflictError("core:observation-order")
            now = self._owner_now(connection)
            reason, _heads = self._authority_staleness(connection, row, now)
            if reason is not None:
                receipt = self._append_pause(
                    connection,
                    row,
                    operation_id=operation_id,
                    request_digest=_digest("observation-request", {"session_id": session_id, "slot_number": slot_number}),
                    trigger="OBSERVATION",
                    observed_at=now,
                    slot_number=slot_number,
                    observation_digest=observation["result_digest"],
                )
                commit_attempted = True
                connection.commit()
                commit_succeeded = True
                return receipt
            if row["state"] != "RUNNING" or slot_number != int(row["last_slot"]) + 1:
                raise CoreConflictError("core:observation-order")
            if int(row["last_slot"]) >= 0:
                head = connection.execute("SELECT event_sequence FROM core_heads WHERE stream_kind='SESSION' AND stream_id=?", (session_id,)).fetchone()
                if head is None:
                    raise CoreError("core:session-head")
                previous_row = connection.execute("SELECT event_raw FROM core_events WHERE sequence=?", (int(head[0]),)).fetchone()
                if previous_row is None or type(previous_row[0]) is not bytes or len(previous_row[0]) > MAX_EVENT_BYTES:
                    raise CoreError("core:session-head")
                try:
                    previous_event = independent._parse(previous_row[0], "core:event-raw")
                except Exception:
                    raise_redacted(CoreError, "core:session-head")
                if previous_event.get("event_kind") != "OBSERVATION" or previous_event.get("subject_id") != session_id or type(previous_event.get("observed_at")) is not int:
                    raise CoreError("core:session-head")
                if now < int(previous_event["observed_at"]) + self.config.cadence_seconds:
                    raise CoreConflictError("core:observation-cadence")
            connection.execute("INSERT INTO core_slots(session_id,slot_number,result_digest,result_raw) VALUES(?,?,?,?)", (session_id, slot_number, observation["result_digest"], result_raw))
            raw = self._append(connection, kind="OBSERVATION", operation_id=operation_id, subject_id=session_id, request_digest=_digest("observation-request", {"session_id": session_id, "slot_number": slot_number}), prior_state="RUNNING", next_state="RUNNING", attempt=0, observed_at=now, material={"observation": observation}, payload_digest=observation["result_digest"], payload_length=len(result_raw), stream_kind="SESSION", stream_id=session_id, head_ref=session_id)
            event = independent._parse(raw, "core:event-raw")
            connection.execute("UPDATE core_sessions SET last_slot=?,head_root=? WHERE session_id=?", (slot_number, event["stream_after_root"], session_id))
            commit_attempted = True
            connection.commit()
            commit_succeeded = True
            return self._receipt(raw)
        except (CoreError, CoreConflictError):
            _finalize_core_connection(
                connection,
                commit_attempted=commit_attempted,
                commit_succeeded=commit_succeeded,
                close=False,
                continue_after_cleanup=True,
            )
            raise
        except sqlite3.Error as exc:
            _finalize_core_connection(
                connection,
                commit_attempted=commit_attempted,
                commit_succeeded=commit_succeeded,
                close=False,
                continue_after_cleanup=True,
            )
            _sqlite_error(exc)
        finally:
            _finalize_core_connection(
                connection,
                commit_attempted=commit_attempted,
                commit_succeeded=commit_succeeded,
                identity_check=self._assert_database_identity,
                cleanup_code="core:database",
            )
        raise CoreError("core:database")

    @_mutation
    def pause_if_stale(self, session_id: str) -> CoreReceipt:
        _require_digest(session_id, "core:pause-input")
        operation_id = _digest("pause-operation", {"session_id": session_id, "trigger": "RECONCILE"})
        request_digest = _digest("pause-request", {"session_id": session_id, "trigger": "RECONCILE"})
        connection = self._open()
        commit_attempted = False
        commit_succeeded = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._event(connection, operation_id)
            if existing is not None:
                commit_attempted = True
                connection.commit()
                commit_succeeded = True
                return self._receipt(existing)
            row = self._session(connection, session_id)
            if row["state"] == "PAUSED":
                receipt = self._latest_pause_receipt(connection, session_id)
                commit_attempted = True
                connection.commit()
                commit_succeeded = True
                return receipt
            if row["state"] not in {"OPEN", "RUNNING"}:
                raise CoreConflictError("core:pause-state")
            now = self._owner_now(connection)
            receipt = self._append_pause(
                connection,
                row,
                operation_id=operation_id,
                request_digest=request_digest,
                trigger="RECONCILE",
                observed_at=now,
            )
            commit_attempted = True
            connection.commit()
            commit_succeeded = True
            return receipt
        except (CoreError, CoreConflictError):
            _finalize_core_connection(
                connection,
                commit_attempted=commit_attempted,
                commit_succeeded=commit_succeeded,
                close=False,
                continue_after_cleanup=True,
            )
            raise
        except sqlite3.Error as exc:
            _finalize_core_connection(
                connection,
                commit_attempted=commit_attempted,
                commit_succeeded=commit_succeeded,
                close=False,
                continue_after_cleanup=True,
            )
            _sqlite_error(exc)
        finally:
            _finalize_core_connection(
                connection,
                commit_attempted=commit_attempted,
                commit_succeeded=commit_succeeded,
                identity_check=self._assert_database_identity,
                cleanup_code="core:database",
            )
        raise CoreError("core:database")


__all__ = ["CoreConfigV2", "CoreReceipt", "CoreError", "CoreConflictError", "CoreBusyError", "CoreIndeterminateError", "CoreServiceV2", "SCHEMA", "SCHEMA_VERSION", "TABLES", "ARTIFACT_KINDS", "FIXED_FLAGS", "MAX_DATABASE_BYTES", "MAX_ARTIFACT_BYTES", "MAX_EVENT_BYTES"]


# ---------------------------------------------------------------------------
# Core V5 clean-break multi-profile owner
# ---------------------------------------------------------------------------

from dataclasses import dataclass as _dataclass

from app.mirror import profile_governance_v1 as _profile_governance


V5_SCHEMA = independent.V5_SCHEMA
V5_SCHEMA_VERSION = independent.V5_SCHEMA_VERSION
V5_TABLES = independent.V5_TABLES
V5_FIXED_FLAGS = dict(independent.V5_FIXED_FLAGS)


@_dataclass(frozen=True)
class CoreConfigV5:
    database_id: str
    chain_id: str
    ingress_database_id: str
    ingress_chain_id: str
    ingress_config_digest: str
    profile_registry_digest: str
    max_sessions: int = 8
    max_slots_per_session: int = 16
    cadence_seconds: int = 60

    def __post_init__(self) -> None:
        for value in (self.database_id, self.chain_id, self.ingress_database_id, self.ingress_chain_id):
            _safe_identifier(value, "core-v5:config")
        for value in (self.ingress_config_digest, self.profile_registry_digest):
            if type(value) is not str or len(value) != 128 or any(char not in "0123456789abcdef" for char in value):
                raise CoreError("core-v5:config")
        if type(self.max_sessions) is not int or not 1 <= self.max_sessions <= 64 or type(self.max_slots_per_session) is not int or not 1 <= self.max_slots_per_session <= 256 or type(self.cadence_seconds) is not int or self.cadence_seconds <= 0:
            raise CoreError("core-v5:config")

    def material(self) -> dict[str, object]:
        return {
            "schema": V5_SCHEMA, "schema_version": V5_SCHEMA_VERSION,
            "database_id": self.database_id, "chain_id": self.chain_id,
            "ingress_database_id": self.ingress_database_id,
            "ingress_chain_id": self.ingress_chain_id,
            "ingress_config_digest": self.ingress_config_digest,
            "profile_registry_digest": self.profile_registry_digest,
            "max_sessions": self.max_sessions,
            "max_slots_per_session": self.max_slots_per_session,
            "cadence_seconds": self.cadence_seconds, "flags": dict(V5_FIXED_FLAGS),
        }

    @property
    def digest(self) -> str:
        return independent._v5_digest("config", self.material())


@_dataclass(frozen=True)
class CoreReceiptV5:
    raw: bytes
    operation_id: str
    event_id: str
    profile_id: str
    session_id: str
    next_state: str
    sequence: int
    after_root: str


def _v5_sqlite_error(exc: sqlite3.Error, *, busy: bool = False) -> None:
    error_name = getattr(exc, "sqlite_errorname", "")
    if error_name in {"SQLITE_FULL", "SQLITE_TOOBIG"}:
        raise_redacted(CoreError, "core-v5:capacity")
    if busy and error_name in {"SQLITE_BUSY", "SQLITE_LOCKED"}:
        raise_redacted(CoreBusyError, "core-v5:busy")
    raise_redacted(CoreError, "core-v5:database")


def _v5_init(path: Path, config: CoreConfigV5, profile_registry: Mapping[str, object], *, ingress_path: str | Path | None = None) -> tuple[int, int]:
    existing = _path_identity(path, allow_missing=True)
    if existing is not None:
        try:
            independent.verify_database_v5(
                path,
                expected_database_id=config.database_id,
                expected_config_digest=config.digest,
                profile_registry=profile_registry,
                ingress_path=ingress_path,
            )
        except independent.CoreVerificationError:
            # The read-only verifier ran before any writable SQLite connection;
            # an old V4/legacy file is therefore byte-preserved on rejection.
            _require_path_identity(path, existing)
            raise CoreError("core-v5:legacy-schema")
        _require_path_identity(path, existing)
        return existing

    connection = _connection(path, create=True)
    try:
        initial_identity = _path_identity(path, allow_missing=False)
    except CoreError:
        _finalize_core_connection(connection, transactional=False, cleanup_code="core-v5:database-open")
        raise
    if initial_identity is None:
        _finalize_core_connection(connection, transactional=False, cleanup_code="core-v5:database-open")
        raise CoreError("core-v5:database-open")
    commit_attempted = False
    commit_succeeded = False

    def _postcommit_identity() -> None:
        _require_path_identity(path, initial_identity)

    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("CREATE TABLE core_meta(meta_id INTEGER PRIMARY KEY CHECK(meta_id=1),schema TEXT NOT NULL,schema_version INTEGER NOT NULL,database_id TEXT NOT NULL,chain_id TEXT NOT NULL,config_digest TEXT NOT NULL,config_raw BLOB NOT NULL,sequence INTEGER NOT NULL,head_root TEXT NOT NULL,ingress_database_id TEXT NOT NULL,ingress_watermark INTEGER NOT NULL)")
        connection.execute("CREATE TABLE core_profile_artifacts(artifact_id TEXT PRIMARY KEY,profile_id TEXT NOT NULL,profile_version INTEGER NOT NULL,profile_digest TEXT NOT NULL,kind TEXT NOT NULL,raw BLOB NOT NULL,current_state TEXT NOT NULL,created_event_sequence INTEGER NOT NULL)")
        connection.execute("CREATE TABLE core_profile_heads(stream_kind TEXT NOT NULL,profile_id TEXT NOT NULL,profile_version INTEGER NOT NULL,head_ref TEXT NOT NULL,head_root TEXT NOT NULL,event_sequence INTEGER NOT NULL,PRIMARY KEY(stream_kind,profile_id,profile_version))")
        connection.execute("CREATE TABLE core_sessions_v5(session_id TEXT PRIMARY KEY,state TEXT NOT NULL,profile_id TEXT NOT NULL,profile_version INTEGER NOT NULL,profile_digest TEXT NOT NULL,governance_artifact_id TEXT NOT NULL,observation_artifact_id TEXT NOT NULL,head_root TEXT NOT NULL,last_slot INTEGER NOT NULL)")
        connection.execute("CREATE TABLE core_slots_v5(session_id TEXT NOT NULL,slot_number INTEGER NOT NULL,result_digest TEXT NOT NULL,result_raw BLOB NOT NULL,PRIMARY KEY(session_id,slot_number),FOREIGN KEY(session_id) REFERENCES core_sessions_v5(session_id))")
        connection.execute("CREATE TABLE core_events_v5(sequence INTEGER PRIMARY KEY,event_id TEXT NOT NULL UNIQUE,event_kind TEXT NOT NULL,operation_id TEXT NOT NULL UNIQUE,profile_id TEXT NOT NULL,session_id TEXT NOT NULL,event_raw BLOB NOT NULL,receipt_digest TEXT NOT NULL)")
        connection.execute("CREATE INDEX core_profile_artifacts_profile_kind_event_idx ON core_profile_artifacts(profile_id,kind,created_event_sequence)")
        connection.execute("INSERT INTO core_meta(meta_id,schema,schema_version,database_id,chain_id,config_digest,config_raw,sequence,head_root,ingress_database_id,ingress_watermark) VALUES(1,?,?,?,?,?,?,?,?,?,?)", (V5_SCHEMA, V5_SCHEMA_VERSION, config.database_id, config.chain_id, config.digest, _canonical(config.material()), 0, independent.GENESIS_ROOT, config.ingress_database_id, 0))
        commit_attempted = True
        connection.commit()
        commit_succeeded = True
    except CoreError:
        _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, close=False, continue_after_cleanup=True)
        raise
    except sqlite3.OperationalError as exc:
        _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, close=False, continue_after_cleanup=True)
        _v5_sqlite_error(exc, busy=True)
    except sqlite3.Error as exc:
        _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, close=False, continue_after_cleanup=True)
        _v5_sqlite_error(exc)
    finally:
        _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, identity_check=_postcommit_identity, cleanup_code="core-v5:database-initialize")
    _require_path_identity(path, initial_identity)
    try:
        independent.verify_database_v5(path, expected_database_id=config.database_id, expected_config_digest=config.digest, profile_registry=profile_registry, ingress_path=ingress_path)
    except independent.CoreVerificationError:
        _require_path_identity(path, initial_identity)
        raise CoreError("core-v5:database")
    _require_path_identity(path, initial_identity)
    return initial_identity


class CoreServiceV5:
    """Core-owned V5 state for independently verified public profiles."""

    def __init__(self, path: str | Path, config: CoreConfigV5, *, profile_registry: Mapping[str, object], ingress_path: str | Path | None = None, clock: object | None = None, authority: writer_authority.WriterAuthority) -> None:
        if not isinstance(config, CoreConfigV5) or not isinstance(profile_registry, Mapping) or not profile_registry:
            raise CoreError("core-v5:composition")
        try:
            registry_digest = _profile_governance.profile_registry_digest(profile_registry)
        except Exception:
            raise_redacted(CoreError, "core-v5:composition")
        if registry_digest != config.profile_registry_digest:
            raise CoreError("core-v5:profile-registry")
        if not isinstance(authority, writer_authority.WriterAuthority):
            raise CoreError("core-v5:authority")
        self.path = Path(path)
        self.config = config
        self.profile_registry = dict(profile_registry)
        if ingress_path is not None and not isinstance(ingress_path, (str, Path)):
            raise CoreError("core-v5:ingress")
        self.ingress_path = None if ingress_path is None else Path(ingress_path)
        self._authority = authority
        self.clock = clock if clock is not None else time.time_ns
        self._identity = _v5_init(self.path, self.config, self.profile_registry, ingress_path=self.ingress_path)

    def _assert_database_identity(self) -> None:
        _require_path_identity(self.path, self._identity)

    def _open(self) -> sqlite3.Connection:
        return _connection(self.path, expected_identity=self._identity)

    def _now(self, connection: sqlite3.Connection) -> int:
        self._authority.assert_live()
        try:
            value = self.clock()
        except Exception:
            raise_redacted(CoreError, "core-v5:clock")
        if type(value) is not int or value < 0:
            raise CoreError("core-v5:clock")
        row = connection.execute("SELECT event_raw FROM core_events_v5 ORDER BY sequence DESC LIMIT 1").fetchone()
        if row is not None:
            latest = independent._v5_parse(row[0], "core-v5:event-raw")["observed_at"]
            if type(latest) is not int or value < latest:
                raise CoreConflictError("core-v5:clock-rewind")
        return value

    @staticmethod
    def _event(connection: sqlite3.Connection, operation_id: str) -> bytes | None:
        row = connection.execute("SELECT event_raw FROM core_events_v5 WHERE operation_id=?", (operation_id,)).fetchone()
        if row is None:
            return None
        if type(row[0]) is not bytes or len(row[0]) > independent.V5_MAX_EVENT_BYTES:
            raise CoreError("core-v5:receipt")
        return bytes(row[0])

    @staticmethod
    def _receipt(raw: bytes) -> CoreReceiptV5:
        value = independent._v5_parse(raw, "core-v5:receipt")
        return CoreReceiptV5(raw=raw, operation_id=str(value["operation_id"]), event_id=str(value["event_id"]), profile_id=str(value["profile_id"]), session_id=str(value["session_id"]), next_state=str(value["next_state"]), sequence=int(value["sequence"]), after_root=str(value["after_root"]))

    @staticmethod
    def _profile_key(profile_id: str, profile_version: int) -> str:
        return profile_id + ":" + str(profile_version)

    def _profile(self, profile_id: str, profile_version: int) -> object:
        if type(profile_id) is not str or profile_id not in self.profile_registry or type(profile_version) is not int:
            raise CoreConflictError("core-v5:profile")
        profile = self.profile_registry[profile_id]
        if int(getattr(profile, "version", -1)) != profile_version:
            raise CoreConflictError("core-v5:profile")
        return profile

    def _head(self, connection: sqlite3.Connection, stream_kind: str, profile_id: str, profile_version: int) -> sqlite3.Row | None:
        return connection.execute("SELECT * FROM core_profile_heads WHERE stream_kind=? AND profile_id=? AND profile_version=?", (stream_kind, profile_id, profile_version)).fetchone()

    def profile_head(self, profile_id: str, profile_version: int, *, stream_kind: str = "GOVERNANCE") -> dict[str, object] | None:
        self._profile(profile_id, profile_version)
        if stream_kind not in {"GOVERNANCE", "OBSERVATION"}:
            raise CoreConflictError("core-v5:head")
        connection = self._open()
        try:
            row = self._head(connection, stream_kind, profile_id, profile_version)
            return dict(row) if row is not None else None
        finally:
            _finalize_core_connection(connection, transactional=False, cleanup_code="core-v5:database")

    def _append(self, connection: sqlite3.Connection, *, event_kind: str, operation_id: str, profile_id: str, session_id: str, request_digest: str, prior_state: str, next_state: str, observed_at: int, material: Mapping[str, object], payload_digest: str, payload_length: int, stream_kind: str, stream_id: str, head_ref: str | None = None) -> bytes:
        meta = connection.execute("SELECT * FROM core_meta WHERE meta_id=1").fetchone()
        if meta is None:
            raise CoreError("core-v5:meta")
        latest = connection.execute("SELECT event_raw FROM core_events_v5 ORDER BY sequence DESC LIMIT 1").fetchone()
        if latest is not None and observed_at < independent._v5_parse(latest[0], "core-v5:event-raw")["observed_at"]:
            raise CoreConflictError("core-v5:clock-rewind")
        sequence = int(meta["sequence"]) + 1
        prior = connection.execute("SELECT event_raw FROM core_events_v5 WHERE sequence=?", (sequence - 1,)).fetchone()
        before_root = independent.GENESIS_ROOT if prior is None else str(independent._v5_parse(prior[0], "core-v5:event-raw")["after_root"])
        stream_row = connection.execute("SELECT event_raw FROM core_events_v5 WHERE event_kind IN ('PROFILE_ARTIFACT','OBSERVATION_ARTIFACT','SESSION_OPEN','SESSION_START','OBSERVATION','SESSION_PAUSE') ORDER BY sequence DESC").fetchall()
        stream_before = independent.GENESIS_ROOT
        for row in stream_row:
            event = independent._v5_parse(row[0], "core-v5:event-raw")
            if event["stream_kind"] == stream_kind and event["stream_id"] == stream_id:
                stream_before = str(event["stream_after_root"])
                break
        body: dict[str, object] = {
            "schema": V5_SCHEMA, "schema_version": V5_SCHEMA_VERSION,
            "database_id": self.config.database_id, "chain_id": self.config.chain_id,
            "sequence": sequence, "event_id": "", "event_kind": event_kind,
            "stream_kind": stream_kind, "stream_id": stream_id,
            "operation_id": operation_id, "profile_id": profile_id,
            "session_id": session_id, "request_digest": request_digest,
            "prior_state": prior_state, "next_state": next_state, "attempt": 0,
            "observed_at": observed_at, "material": dict(material),
            "material_digest": independent._v5_digest("material", material),
            "payload_digest": payload_digest, "payload_length": payload_length,
            "before_root": before_root, "after_root": "",
            "stream_before_root": stream_before, "stream_after_root": "",
        }
        body["event_id"] = independent._v5_digest("event-id", {key: body[key] for key in independent.V5_EVENT_KEYS if key not in {"event_id", "after_root", "stream_after_root"}})
        body["after_root"] = independent._v5_event_root(body)
        body["stream_after_root"] = independent._v5_stream_root(body)
        raw = _canonical(body)
        if len(raw) > independent.V5_MAX_EVENT_BYTES:
            raise CoreConflictError("core-v5:capacity")
        connection.execute("INSERT INTO core_events_v5(sequence,event_id,event_kind,operation_id,profile_id,session_id,event_raw,receipt_digest) VALUES(?,?,?,?,?,?,?,?)", (sequence, body["event_id"], event_kind, operation_id, profile_id, session_id, raw, independent._v5_raw_digest("receipt", raw)))
        connection.execute("UPDATE core_meta SET sequence=?,head_root=? WHERE meta_id=1", (sequence, body["after_root"]))
        if stream_kind in {"GOVERNANCE", "OBSERVATION"}:
            connection.execute("INSERT INTO core_profile_heads(stream_kind,profile_id,profile_version,head_ref,head_root,event_sequence) VALUES(?,?,?,?,?,?) ON CONFLICT(stream_kind,profile_id,profile_version) DO UPDATE SET head_ref=excluded.head_ref,head_root=excluded.head_root,event_sequence=excluded.event_sequence", (stream_kind, profile_id, int(getattr(self.profile_registry[profile_id], "version")), head_ref or "", body["stream_after_root"], sequence))
        return raw

    def _governance_value(self, raw: bytes) -> dict[str, object]:
        try:
            from app.mirror import profile_governance_v1_independent as verifier
            verifier.verify_bytes(raw, self.profile_registry)
            return verifier._parse(raw)
        except Exception:
            raise CoreConflictError("core-v5:governance") from None

    @staticmethod
    def _governance_stage(value: Mapping[str, object]) -> Mapping[str, object]:
        if value.get("schema") == _profile_governance.WITHDRAWAL_SCHEMA:
            return {"stage_kind": _profile_governance.ACTION_WITHDRAWN, "stage_id": value.get("withdrawal_id"), "stage_root": value.get("withdrawal_root")}
        stages = value.get("stages")
        if not isinstance(stages, list) or not stages or not isinstance(stages[-1], dict):
            raise CoreConflictError("core-v5:governance")
        return stages[-1]

    def _admit_profile_artifact_inner(self, connection: sqlite3.Connection, raw: bytes, now: int) -> CoreReceiptV5:
        if type(raw) is not bytes or not raw or len(raw) > MAX_ARTIFACT_BYTES:
            raise CoreConflictError("core-v5:artifact")
        value = self._governance_value(raw)
        if value.get("schema") == _profile_governance.WITHDRAWAL_SCHEMA:
            profile_value = value.get("profile")
            kind = "WITHDRAWAL"
            state = _profile_governance.ACTION_WITHDRAWN
        else:
            profile_value = value.get("profile")
            kind = "GOVERNANCE"
            state = value.get("current_stage_kind")
        if not isinstance(profile_value, dict):
            raise CoreConflictError("core-v5:governance")
        profile_id = str(profile_value.get("profile_id")); profile_version = profile_value.get("version"); profile_digest = profile_value.get("profile_digest")
        profile = self._profile(profile_id, profile_version if type(profile_version) is int else -1)
        if profile_digest != _profile_governance.profile_descriptor(profile)["profile_digest"]:
            raise CoreConflictError("core-v5:profile")
        raw_digest = independent._v5_raw_digest("artifact-bytes", raw)
        operation_id = independent._v5_digest("profile-artifact-operation", {"profile_id": profile_id, "profile_version": profile_version, "kind": kind, "raw_digest": raw_digest})
        request_digest = independent._v5_digest("profile-artifact-request", {"profile_id": profile_id, "profile_version": profile_version, "kind": kind, "raw_digest": raw_digest})
        existing_event = self._event(connection, operation_id)
        artifact_id = independent._v5_digest("artifact-row-id", {"profile_id": profile_id, "profile_version": profile_version, "profile_digest": profile_digest, "kind": kind, "raw": raw_digest, "current_state": state})
        material = {"artifact_id": artifact_id, "kind": kind, "raw_digest": raw_digest, "raw_length": len(raw), "profile_id": profile_id, "profile_version": profile_version, "profile_digest": profile_digest, "current_state": state, "prior_head_ref": None, "prior_head_root": None}
        head = self._head(connection, "GOVERNANCE", profile_id, int(profile_version))
        if existing_event is not None:
            event = independent._v5_parse(existing_event, "core-v5:event-raw")
            existing_material = event.get("material")
            if event.get("event_kind") != "PROFILE_ARTIFACT" or not isinstance(existing_material, dict) or any(existing_material.get(key) != material[key] for key in ("artifact_id", "kind", "raw_digest", "raw_length", "profile_id", "profile_version", "profile_digest", "current_state")):
                raise CoreConflictError("core-v5:operation-conflict")
            return self._receipt(existing_event)
        if head is not None:
            prior_value_row = connection.execute("SELECT raw,current_state FROM core_profile_artifacts WHERE artifact_id=?", (head["head_ref"],)).fetchone()
            if prior_value_row is None:
                raise CoreError("core-v5:head")
            prior_raw = bytes(prior_value_row["raw"])
            prior_value = self._governance_value(prior_raw)
            prior_state = self._governance_stage(prior_value)
            if prior_state.get("stage_kind") == _profile_governance.ACTION_WITHDRAWN:
                raise CoreConflictError("core-v5:governance-withdrawn")
            new_stage = self._governance_stage(value)
            if kind == "GOVERNANCE":
                if new_stage.get("prior_stage_id") != prior_state.get("stage_id") or new_stage.get("prior_stage_root") != prior_state.get("stage_root"):
                    raise CoreConflictError("core-v5:stale-head")
            elif kind == "WITHDRAWAL":
                # Core's row key is an opaque storage identity derived from
                # the admitted bytes.  Governance binds a withdrawal to the
                # intrinsic artifact_id carried by the approved artifact, so
                # compare against the parsed predecessor rather than the
                # opaque row key.
                if (
                    prior_state.get("stage_kind") != _profile_governance.STAGE_APPROVED
                    or value.get("approved_artifact_id") != prior_value.get("artifact_id")
                ):
                    raise CoreConflictError("core-v5:stale-head")
            material["prior_head_ref"] = head["head_ref"]
            material["prior_head_root"] = head["head_root"]
        if head is None and (kind != "GOVERNANCE" or state != _profile_governance.STAGE_CANDIDATE):
            raise CoreConflictError("core-v5:governance-stage")
        if kind == "GOVERNANCE" and state not in _profile_governance.STAGE_KINDS:
            raise CoreConflictError("core-v5:governance-stage")
        if kind == "WITHDRAWAL" and state != _profile_governance.ACTION_WITHDRAWN:
            raise CoreConflictError("core-v5:governance-stage")
        connection.execute("INSERT INTO core_profile_artifacts(artifact_id,profile_id,profile_version,profile_digest,kind,raw,current_state,created_event_sequence) VALUES(?,?,?,?,?,?,?,0)", (artifact_id, profile_id, profile_version, profile_digest, kind, raw, state))
        event_raw = self._append(connection, event_kind="PROFILE_ARTIFACT", operation_id=operation_id, profile_id=profile_id, session_id="", request_digest=request_digest, prior_state="NONE" if head is None else str(head["head_ref"]), next_state=str(state), observed_at=now, material=material, payload_digest=artifact_id, payload_length=len(raw), stream_kind="GOVERNANCE", stream_id=self._profile_key(profile_id, int(profile_version)), head_ref=artifact_id)
        sequence = independent._v5_parse(event_raw, "core-v5:event-raw")["sequence"]
        connection.execute("UPDATE core_profile_artifacts SET created_event_sequence=? WHERE artifact_id=?", (sequence, artifact_id))
        return self._receipt(event_raw)

    @_mutation
    def admit_profile_artifact(self, raw: bytes) -> CoreReceiptV5:
        connection = self._open(); commit_attempted = False; commit_succeeded = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            now = self._now(connection)
            receipt = self._admit_profile_artifact_inner(connection, raw, now)
            commit_attempted = True; connection.commit(); commit_succeeded = True
            return receipt
        except (CoreError, CoreConflictError):
            _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, close=False, continue_after_cleanup=True); raise
        except sqlite3.OperationalError as exc:
            _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, close=False, continue_after_cleanup=True); _v5_sqlite_error(exc, busy=True)
        except sqlite3.Error as exc:
            _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, close=False, continue_after_cleanup=True); _v5_sqlite_error(exc)
        finally:
            _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, identity_check=self._assert_database_identity, cleanup_code="core-v5:database")
        raise CoreError("core-v5:database")

    def _stored_observation_value(self, artifact: Mapping[str, object], profile_id: str, profile_version: int) -> tuple[bytes, str, int, int]:
        try:
            profile = self._profile(profile_id, profile_version)
            profile_digest = _profile_governance.profile_descriptor(profile)["profile_digest"]
            observation_raw = artifact["observation"]
            verification_receipt_raw = artifact["verification_receipt"]
            if type(observation_raw) is not bytes or type(verification_receipt_raw) is not bytes:
                raise ValueError
            checked = ingress.verify_observation_pair(
                observation_raw,
                verification_receipt_raw,
                expected_profile_id=ingress.NC_MEDICAID_PROFILE.source_profile_id,
                expected_profile_version=3,
            )
            if (
                artifact.get("terminal_state") != "QUARANTINED"
                or artifact.get("terminal_event_kind") != "ADMIT"
                or artifact.get("artifact_id") is None
                or artifact.get("observation_id") != checked["observation_id"]
                or artifact.get("event_sequence") != artifact.get("terminal_event_sequence")
                or artifact.get("event_after_root") != artifact.get("head_root")
                or artifact.get("database_id") != self.config.ingress_database_id
                or artifact.get("chain_id") != self.config.ingress_chain_id
                or artifact.get("config_digest") != self.config.ingress_config_digest
                or type(artifact.get("event_sequence")) is not int
                or int(artifact["event_sequence"]) <= 0
            ):
                raise ValueError
            envelope = {
                "schema": independent.V5_OBSERVATION_SCHEMA,
                "schema_version": 1,
                "kind": "OBSERVATION",
                "profile_id": profile_id,
                "profile_version": profile_version,
                "profile_digest": profile_digest,
                "observation": checked["observation"],
                "verification_receipt": checked["verification_receipt"],
                "observation_digest": independent._v5_raw_digest("sanitized-observation", observation_raw),
                "ingress_database_id": artifact["database_id"],
                "ingress_chain_id": artifact["chain_id"],
                "ingress_config_digest": artifact["config_digest"],
                "ingress_artifact_id": artifact["artifact_id"],
                "ingress_observation_id": checked["observation_id"],
                "ingress_event_sequence": artifact["event_sequence"],
                "ingress_prefix_root": artifact["event_prefix_root"],
                "ingress_after_root": artifact["event_after_root"],
                "ingress_head_root": artifact["head_root"],
                "flags": dict(V5_FIXED_FLAGS),
            }
            raw = _canonical(envelope)
            independent._v5_verify_observation(raw, profile_id, profile_version)
            return raw, profile_id, profile_version, int(checked["observation"]["observation_time"])
        except CoreConflictError:
            raise
        except Exception:
            raise CoreConflictError("core-v5:ingress") from None

    def _ingest_observation_envelope_inner(self, connection: sqlite3.Connection, envelope_raw: bytes, now: int) -> CoreReceiptV5:
        try:
            envelope = independent._v5_parse(envelope_raw, "core-v5:observation")
            profile_id = str(envelope["profile_id"])
            profile_version = int(envelope["profile_version"])
            profile_digest = str(envelope["profile_digest"])
            independent._v5_verify_observation(envelope_raw, profile_id, profile_version)
            observation_time = int(envelope["observation"]["observation_time"])
        except Exception:
            raise CoreConflictError("core-v5:observation") from None
        if observation_time > now:
            raise CoreConflictError("core-v5:observation-future")
        raw_digest = independent._v5_raw_digest("artifact-bytes", envelope_raw)
        artifact_id = independent._v5_digest("artifact-row-id", {"profile_id": profile_id, "profile_version": profile_version, "profile_digest": profile_digest, "kind": "OBSERVATION", "raw": raw_digest, "current_state": "OBSERVED"})
        operation_id = independent._v5_digest("observation-artifact-operation", {"profile_id": profile_id, "profile_version": profile_version, "raw_digest": raw_digest})
        request_digest = independent._v5_digest("observation-artifact-request", {"profile_id": profile_id, "profile_version": profile_version, "raw_digest": raw_digest})
        existing_event = self._event(connection, operation_id)
        head = self._head(connection, "OBSERVATION", profile_id, profile_version)
        material = {"artifact_id": artifact_id, "kind": "OBSERVATION", "raw_digest": raw_digest, "raw_length": len(envelope_raw), "profile_id": profile_id, "profile_version": profile_version, "profile_digest": profile_digest, "observation_time": observation_time, "prior_head_ref": None, "prior_head_root": None}
        if existing_event is not None:
            event = independent._v5_parse(existing_event, "core-v5:event-raw")
            existing_material = event.get("material")
            if event.get("event_kind") != "OBSERVATION_ARTIFACT" or not isinstance(existing_material, dict) or any(existing_material.get(key) != material[key] for key in ("artifact_id", "kind", "raw_digest", "raw_length", "profile_id", "profile_version", "profile_digest", "observation_time")):
                raise CoreConflictError("core-v5:operation-conflict")
            return self._receipt(existing_event)
        if head is not None:
            prior_row = connection.execute("SELECT raw FROM core_profile_artifacts WHERE artifact_id=?", (head["head_ref"],)).fetchone()
            if prior_row is None:
                raise CoreError("core-v5:head")
            prior = independent._v5_parse(prior_row[0], "core-v5:observation")
            prior_time = int(prior["observation"]["observation_time"])
            if observation_time <= prior_time:
                raise CoreConflictError("core-v5:observation-chronology")
            material["prior_head_ref"] = head["head_ref"]; material["prior_head_root"] = head["head_root"]
        connection.execute("INSERT INTO core_profile_artifacts(artifact_id,profile_id,profile_version,profile_digest,kind,raw,current_state,created_event_sequence) VALUES(?,?,?,?,?,?,?,0)", (artifact_id, profile_id, profile_version, profile_digest, "OBSERVATION", envelope_raw, "OBSERVED"))
        event_raw = self._append(connection, event_kind="OBSERVATION_ARTIFACT", operation_id=operation_id, profile_id=profile_id, session_id="", request_digest=request_digest, prior_state="NONE" if head is None else str(head["head_ref"]), next_state="OBSERVED", observed_at=now, material=material, payload_digest=artifact_id, payload_length=len(envelope_raw), stream_kind="OBSERVATION", stream_id=self._profile_key(profile_id, profile_version), head_ref=artifact_id)
        sequence = independent._v5_parse(event_raw, "core-v5:event-raw")["sequence"]
        connection.execute("UPDATE core_profile_artifacts SET created_event_sequence=? WHERE artifact_id=?", (sequence, artifact_id))
        ingress_event_sequence = int(envelope["ingress_event_sequence"])
        connection.execute("UPDATE core_meta SET ingress_watermark=MAX(ingress_watermark,?) WHERE meta_id=1", (ingress_event_sequence,))
        return self._receipt(event_raw)

    @_mutation
    def ingest_observation(self, observation_raw: bytes, verification_receipt_raw: bytes, *, profile_digest: str) -> CoreReceiptV5:
        del observation_raw, verification_receipt_raw, profile_digest
        raise CoreConflictError("core-v5:ingress-required")

    @_mutation
    def ingest_observation_from_ingress(
        self,
        ingress_path: str | Path,
        artifact_id: str,
        *,
        profile_id: str,
        profile_version: int,
    ) -> CoreReceiptV5:
        if not isinstance(ingress_path, (str, Path)):
            raise CoreConflictError("core-v5:ingress")
        self._profile(profile_id, profile_version)
        try:
            result = ingress.verify_database(
                ingress_path,
                expected_database_id=self.config.ingress_database_id,
                expected_config_digest=self.config.ingress_config_digest,
                include_observation=True,
                artifact_id=artifact_id,
            )
            artifact = result.get("current_artifact")
            if (
                result.get("current_artifact_id") != artifact_id
                or not isinstance(artifact, Mapping)
            ):
                raise ValueError
            artifact = dict(artifact)
            artifact.update({
                "database_id": result["database_id"],
                "chain_id": result["chain_id"],
                "config_digest": result["config_digest"],
                "head_root": artifact.get("event_after_root"),
            })
            envelope_raw, _profile_id, _profile_version, _observation_time = self._stored_observation_value(artifact, profile_id, profile_version)
        except CoreConflictError:
            raise
        except Exception:
            raise CoreConflictError("core-v5:ingress") from None
        self.ingress_path = Path(ingress_path)
        connection = self._open(); commit_attempted = False; commit_succeeded = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            now = self._now(connection)
            receipt = self._ingest_observation_envelope_inner(connection, envelope_raw, now)
            commit_attempted = True; connection.commit(); commit_succeeded = True
            return receipt
        except (CoreError, CoreConflictError):
            _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, close=False, continue_after_cleanup=True); raise
        except sqlite3.Error as exc:
            _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, close=False, continue_after_cleanup=True); _v5_sqlite_error(exc)
        finally:
            _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, identity_check=self._assert_database_identity, cleanup_code="core-v5:database")
        raise CoreError("core-v5:database")

    def _session(self, connection: sqlite3.Connection, session_id: str) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM core_sessions_v5 WHERE session_id=?", (session_id,)).fetchone()
        if row is None:
            raise CoreConflictError("core-v5:session")
        return row

    def _authority_staleness(self, connection: sqlite3.Connection, row: sqlite3.Row, now: int) -> tuple[str | None, sqlite3.Row | None, sqlite3.Row | None]:
        gov = self._head(connection, "GOVERNANCE", str(row["profile_id"]), int(row["profile_version"]))
        obs = self._head(connection, "OBSERVATION", str(row["profile_id"]), int(row["profile_version"]))
        if gov is None or obs is None:
            return "AUTHORITY_SUPERSEDED", gov, obs
        if obs["head_ref"] != row["observation_artifact_id"]:
            return "AUTHORITY_SUPERSEDED", gov, obs
        gov_row = connection.execute("SELECT raw,current_state FROM core_profile_artifacts WHERE artifact_id=?", (gov["head_ref"],)).fetchone()
        if gov_row is None:
            return "AUTHORITY_MISSING", gov, obs
        value = self._governance_value(gov_row["raw"])
        if value.get("schema") == _profile_governance.WITHDRAWAL_SCHEMA:
            return "AUTHORITY_WITHDRAWN", gov, obs
        if gov["head_ref"] != row["governance_artifact_id"]:
            return "AUTHORITY_SUPERSEDED", gov, obs
        stage = self._governance_stage(value)
        if stage.get("stage_kind") != _profile_governance.STAGE_APPROVED:
            return "AUTHORITY_NOT_APPROVED", gov, obs
        if now < int(stage["effective_start"]):
            return "AUTHORITY_NOT_EFFECTIVE", gov, obs
        if now >= int(stage["effective_end"]):
            return "AUTHORITY_EXPIRED", gov, obs
        return None, gov, obs

    def _append_pause(self, connection: sqlite3.Connection, row: sqlite3.Row, *, operation_id: str, request_digest: str, trigger: str, now: int, slot_number: int | None = None, observation_digest: str | None = None) -> CoreReceiptV5:
        reason, gov, obs = self._authority_staleness(connection, row, now)
        if reason is None:
            raise CoreConflictError("core-v5:pause-current")
        material = {"state": "PAUSED", "reason": reason, "trigger": trigger, "current_governance_artifact_id": None if gov is None else gov["head_ref"], "current_observation_artifact_id": None if obs is None else obs["head_ref"], "slot_number": slot_number, "observation_digest": observation_digest}
        event_raw = self._append(connection, event_kind="SESSION_PAUSE", operation_id=operation_id, profile_id=str(row["profile_id"]), session_id=str(row["session_id"]), request_digest=request_digest, prior_state=str(row["state"]), next_state="PAUSED", observed_at=now, material=material, payload_digest=independent._v5_digest("pause-reason", {"reason": reason}), payload_length=0, stream_kind="SESSION", stream_id=str(row["session_id"]))
        event = independent._v5_parse(event_raw, "core-v5:event-raw")
        connection.execute("UPDATE core_sessions_v5 SET state=?,head_root=? WHERE session_id=?", ("PAUSED", event["stream_after_root"], row["session_id"]))
        return self._receipt(event_raw)

    @_mutation
    def open_session(self, profile_id: str, profile_version: int, *, observation_artifact_id: str | None = None) -> CoreReceiptV5:
        profile = self._profile(profile_id, profile_version)
        connection = self._open(); commit_attempted = False; commit_succeeded = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            now = self._now(connection)
            gov = self._head(connection, "GOVERNANCE", profile_id, profile_version); obs = self._head(connection, "OBSERVATION", profile_id, profile_version)
            if gov is None or obs is None or observation_artifact_id is not None and obs["head_ref"] != observation_artifact_id:
                raise CoreConflictError("core-v5:authority-head")
            gov_row = connection.execute("SELECT raw FROM core_profile_artifacts WHERE artifact_id=?", (gov["head_ref"],)).fetchone()
            if gov_row is None:
                raise CoreConflictError("core-v5:authority-missing")
            gov_value = self._governance_value(gov_row["raw"]); stage = self._governance_stage(gov_value)
            if stage.get("stage_kind") != _profile_governance.STAGE_APPROVED:
                raise CoreConflictError("core-v5:governance-not-approved")
            if now < int(stage["stage_time"]) or now < int(stage["effective_start"]) or now >= int(stage["effective_end"]):
                raise CoreConflictError("core-v5:governance-expired")
            session_id = independent._v5_digest("session-id", {"profile_id": profile_id, "profile_version": profile_version, "profile_digest": _profile_governance.profile_descriptor(profile)["profile_digest"], "governance_artifact_id": gov["head_ref"], "observation_artifact_id": obs["head_ref"], "config_digest": self.config.profile_registry_digest})
            operation_id = independent._v5_digest("session-operation", {"session_id": session_id, "action": "OPEN"})
            existing = self._event(connection, operation_id)
            if existing is not None:
                commit_attempted = True; connection.commit(); commit_succeeded = True; return self._receipt(existing)
            count = int(connection.execute("SELECT COUNT(*) FROM core_sessions_v5").fetchone()[0])
            if count >= self.config.max_sessions:
                raise CoreConflictError("core-v5:capacity")
            connection.execute("INSERT INTO core_sessions_v5(session_id,state,profile_id,profile_version,profile_digest,governance_artifact_id,observation_artifact_id,head_root,last_slot) VALUES(?,?,?,?,?,?,?,?,?)", (session_id, "OPEN", profile_id, profile_version, _profile_governance.profile_descriptor(profile)["profile_digest"], gov["head_ref"], obs["head_ref"], independent.GENESIS_ROOT, -1))
            event_raw = self._append(connection, event_kind="SESSION_OPEN", operation_id=operation_id, profile_id=profile_id, session_id=session_id, request_digest=independent._v5_digest("session-request", {"session_id": session_id, "action": "OPEN"}), prior_state="NONE", next_state="OPEN", observed_at=now, material={"session_id": session_id, "state": "OPEN", "governance_artifact_id": gov["head_ref"], "observation_artifact_id": obs["head_ref"], "last_slot": -1}, payload_digest=session_id, payload_length=0, stream_kind="SESSION", stream_id=session_id)
            event = independent._v5_parse(event_raw, "core-v5:event-raw")
            connection.execute("UPDATE core_sessions_v5 SET head_root=? WHERE session_id=?", (event["stream_after_root"], session_id))
            commit_attempted = True; connection.commit(); commit_succeeded = True; return self._receipt(event_raw)
        except (CoreError, CoreConflictError):
            _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, close=False, continue_after_cleanup=True); raise
        except sqlite3.Error as exc:
            _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, close=False, continue_after_cleanup=True); _v5_sqlite_error(exc)
        finally:
            _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, identity_check=self._assert_database_identity, cleanup_code="core-v5:database")
        raise CoreError("core-v5:database")

    @_mutation
    def start_session(self, session_id: str) -> CoreReceiptV5:
        connection = self._open(); commit_attempted = False; commit_succeeded = False
        try:
            connection.execute("BEGIN IMMEDIATE"); row = self._session(connection, session_id)
            operation_id = independent._v5_digest("session-operation", {"session_id": session_id, "action": "START"}); existing = self._event(connection, operation_id)
            if existing is not None:
                commit_attempted = True; connection.commit(); commit_succeeded = True; return self._receipt(existing)
            if row["state"] == "PAUSED":
                raise CoreConflictError("core-v5:session-paused")
            if row["state"] != "OPEN":
                raise CoreConflictError("core-v5:session-state")
            now = self._now(connection); reason, _gov, _obs = self._authority_staleness(connection, row, now)
            if reason is not None:
                receipt = self._append_pause(connection, row, operation_id=operation_id, request_digest=independent._v5_digest("session-request", {"session_id": session_id, "action": "START"}), trigger="START", now=now); commit_attempted = True; connection.commit(); commit_succeeded = True; return receipt
            event_raw = self._append(connection, event_kind="SESSION_START", operation_id=operation_id, profile_id=str(row["profile_id"]), session_id=session_id, request_digest=independent._v5_digest("session-request", {"session_id": session_id, "action": "START"}), prior_state="OPEN", next_state="RUNNING", observed_at=now, material={"state": "RUNNING"}, payload_digest=session_id, payload_length=0, stream_kind="SESSION", stream_id=session_id)
            event = independent._v5_parse(event_raw, "core-v5:event-raw"); connection.execute("UPDATE core_sessions_v5 SET state=?,head_root=? WHERE session_id=?", ("RUNNING", event["stream_after_root"], session_id)); commit_attempted = True; connection.commit(); commit_succeeded = True; return self._receipt(event_raw)
        except (CoreError, CoreConflictError):
            _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, close=False, continue_after_cleanup=True); raise
        except sqlite3.Error as exc:
            _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, close=False, continue_after_cleanup=True); _v5_sqlite_error(exc)
        finally:
            _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, identity_check=self._assert_database_identity, cleanup_code="core-v5:database")
        raise CoreError("core-v5:database")

    @_mutation
    def observe(self, session_id: str, slot_number: int, result: str, *, counts: Mapping[str, int] | None = None) -> CoreReceiptV5:
        if type(slot_number) is not int or slot_number < 0 or slot_number >= self.config.max_slots_per_session or result not in independent.OBSERVATION_RESULTS:
            raise CoreConflictError("core-v5:observation-input")
        values = dict(counts or {"observed": 0, "changed": 0})
        if set(values) != {"observed", "changed"} or any(type(item) is not int or item < 0 or item > 64 for item in values.values()):
            raise CoreConflictError("core-v5:observation-input")
        body = {"schema": "mirror-core-v5-observation-result-v1", "schema_version": 1, "session_id": session_id, "slot_number": slot_number, "result": result, "counts": {"changed": values["changed"], "observed": values["observed"]}, "flags": dict(V5_FIXED_FLAGS)}
        body["result_digest"] = independent._v5_digest("observation-result", {key: body[key] for key in body if key != "result_digest"})
        result_raw = _canonical(body); operation_id = independent._v5_digest("observation-operation", {"session_id": session_id, "slot_number": slot_number})
        connection = self._open(); commit_attempted = False; commit_succeeded = False
        try:
            connection.execute("BEGIN IMMEDIATE"); existing = self._event(connection, operation_id)
            if existing is not None:
                event = independent._v5_parse(existing, "core-v5:event-raw")
                if event.get("event_kind") != "OBSERVATION" or event.get("material", {}).get("observation") != body:
                    raise CoreConflictError("core-v5:observation-conflict")
                commit_attempted = True; connection.commit(); commit_succeeded = True; return self._receipt(existing)
            row = self._session(connection, session_id)
            if row["state"] == "PAUSED":
                raise CoreConflictError("core-v5:session-paused")
            if row["state"] != "RUNNING" or slot_number != int(row["last_slot"]) + 1:
                raise CoreConflictError("core-v5:observation-order")
            now = self._now(connection); reason, _gov, _obs = self._authority_staleness(connection, row, now)
            if reason is not None:
                receipt = self._append_pause(connection, row, operation_id=operation_id, request_digest=independent._v5_digest("observation-request", {"session_id": session_id, "slot_number": slot_number}), trigger="OBSERVATION", now=now, slot_number=slot_number, observation_digest=body["result_digest"]); commit_attempted = True; connection.commit(); commit_succeeded = True; return receipt
            if int(row["last_slot"]) >= 0:
                previous = connection.execute("SELECT event_raw FROM core_events_v5 WHERE event_kind='OBSERVATION' AND session_id=? ORDER BY sequence DESC LIMIT 1", (session_id,)).fetchone()
                if previous is None or now < int(independent._v5_parse(previous[0], "core-v5:event-raw")["observed_at"]) + self.config.cadence_seconds:
                    raise CoreConflictError("core-v5:observation-cadence")
            connection.execute("INSERT INTO core_slots_v5(session_id,slot_number,result_digest,result_raw) VALUES(?,?,?,?)", (session_id, slot_number, body["result_digest"], result_raw))
            event_raw = self._append(connection, event_kind="OBSERVATION", operation_id=operation_id, profile_id=str(row["profile_id"]), session_id=session_id, request_digest=independent._v5_digest("observation-request", {"session_id": session_id, "slot_number": slot_number}), prior_state="RUNNING", next_state="RUNNING", observed_at=now, material={"observation": body}, payload_digest=body["result_digest"], payload_length=len(result_raw), stream_kind="SESSION", stream_id=session_id)
            event = independent._v5_parse(event_raw, "core-v5:event-raw"); connection.execute("UPDATE core_sessions_v5 SET last_slot=?,head_root=? WHERE session_id=?", (slot_number, event["stream_after_root"], session_id)); commit_attempted = True; connection.commit(); commit_succeeded = True; return self._receipt(event_raw)
        except (CoreError, CoreConflictError):
            _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, close=False, continue_after_cleanup=True); raise
        except sqlite3.Error as exc:
            _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, close=False, continue_after_cleanup=True); _v5_sqlite_error(exc)
        finally:
            _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, identity_check=self._assert_database_identity, cleanup_code="core-v5:database")
        raise CoreError("core-v5:database")

    @_mutation
    def pause_if_stale(self, session_id: str) -> CoreReceiptV5:
        connection = self._open(); commit_attempted = False; commit_succeeded = False
        try:
            connection.execute("BEGIN IMMEDIATE"); row = self._session(connection, session_id); operation_id = independent._v5_digest("pause-operation", {"session_id": session_id, "trigger": "RECONCILE"}); existing = self._event(connection, operation_id)
            if existing is not None:
                commit_attempted = True; connection.commit(); commit_succeeded = True; return self._receipt(existing)
            if row["state"] == "PAUSED":
                raise CoreConflictError("core-v5:session-paused")
            now = self._now(connection); receipt = self._append_pause(connection, row, operation_id=operation_id, request_digest=independent._v5_digest("pause-request", {"session_id": session_id, "trigger": "RECONCILE"}), trigger="RECONCILE", now=now); commit_attempted = True; connection.commit(); commit_succeeded = True; return receipt
        except (CoreError, CoreConflictError):
            _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, close=False, continue_after_cleanup=True); raise
        except sqlite3.Error as exc:
            _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, close=False, continue_after_cleanup=True); _v5_sqlite_error(exc)
        finally:
            _finalize_core_connection(connection, commit_attempted=commit_attempted, commit_succeeded=commit_succeeded, identity_check=self._assert_database_identity, cleanup_code="core-v5:database")
        raise CoreError("core-v5:database")

    def verify(self) -> dict[str, object]:
        self._assert_database_identity()
        try:
            result = independent.verify_database_v5(self.path, expected_database_id=self.config.database_id, expected_config_digest=self.config.digest, profile_registry=self.profile_registry, ingress_path=self.ingress_path)
        except independent.CoreVerificationError:
            self._assert_database_identity(); raise
        self._assert_database_identity(); return result

    def logical_export(self) -> bytes:
        return independent.logical_export_v5(self.verify())

    def support(self) -> dict[str, object]:
        result = self.verify()
        return {"schema": "mirror-core-support-v5", "artifact_count": result["artifact_count"], "profile_head_count": result["profile_head_count"], "session_count": result["session_count"], "slot_count": result["slot_count"], "event_count": result["event_count"], "profiles": [list(item) for item in result["profiles"]], "structural_valid": result["structural_valid"], "flags": dict(V5_FIXED_FLAGS)}


__all__ += ["CoreConfigV5", "CoreReceiptV5", "CoreServiceV5", "V5_SCHEMA", "V5_SCHEMA_VERSION", "V5_TABLES", "V5_FIXED_FLAGS"]
