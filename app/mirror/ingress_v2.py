"""The single durable owner for sanitized Mirror observations.

Raw source captures are deliberately not part of this module's API.  Source
adapters and their independent source verifiers finish before this owner is
called.  Ingress independently reparses the bounded observation/receipt pair,
then owns the slot transaction, lease, event chain, and recovery-visible
state.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3
import time
from typing import Callable

from app.mirror import ingress_v2_independent as independent
from app.mirror.nc_medicaid_fhir_profile import NC_MEDICAID_PROFILE
from app.mirror.error_boundary import raise_redacted
from app.mirror import writer_authority


SCHEMA = independent.SCHEMA
SCHEMA_VERSION = independent.SCHEMA_VERSION
TABLES = independent.TABLES
STATES = independent.STATES
FIXED_FLAGS = dict(independent.FIXED_FLAGS)
MAX_DATABASE_BYTES = independent.MAX_DATABASE_BYTES
MAX_EVENT_BYTES = independent.MAX_EVENT_BYTES
MAX_CONFIG_BYTES = independent.MAX_CONFIG_BYTES
MAX_IDENTIFIER_BYTES = independent.MAX_IDENTIFIER_BYTES
MAX_OBSERVATION_BYTES = independent.MAX_OBSERVATION_BYTES
MAX_VERIFICATION_RECEIPT_BYTES = independent.MAX_VERIFICATION_RECEIPT_BYTES
_MIN_LEASE_TOKEN_BYTES = 32


class IngressError(ValueError):
    """Public-safe ingress failure."""


class IngressConflictError(IngressError):
    """A stale or conflicting state transition."""


class IngressBusyError(IngressError):
    """A bounded writer contention failure."""


class IngressIndeterminateError(IngressError):
    """A transaction outcome that cannot be established."""


def _safe_identifier(value: object, label: str) -> str:
    if type(value) is not str or not value or len(value) > MAX_IDENTIFIER_BYTES:
        raise IngressError(label)
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        raise IngressError(label) from None
    if any(not (c.isalnum() or c in "._:-") for c in value):
        raise IngressError(label)
    return value


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=True, allow_nan=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise IngressError("ingress:noncanonical") from None


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((independent.DOMAIN + label + "\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _raw_digest(label: str, raw: bytes) -> str:
    digest = hashlib.sha3_512()
    digest.update((independent.DOMAIN + label + "\0").encode("ascii"))
    digest.update(raw)
    return digest.hexdigest()


def _safe_rollback(connection: sqlite3.Connection) -> None:
    failed = False
    try:
        connection.rollback()
    except BaseException:
        failed = True
    if failed:
        raise_redacted(IngressIndeterminateError, "ingress:transaction-indeterminate")


def _safe_close(connection: sqlite3.Connection) -> None:
    failed = False
    try:
        connection.close()
    except BaseException:
        failed = True
    if failed:
        raise_redacted(IngressIndeterminateError, "ingress:transaction-indeterminate")


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
    source_contract_digest: str = NC_MEDICAID_PROFILE.profile_digest

    def __post_init__(self) -> None:
        _safe_identifier(self.database_id, "ingress:config")
        _safe_identifier(self.chain_id, "ingress:config")
        for value in (
            self.policy_digest,
            self.authorization_digest,
            self.terms_digest,
            self.source_contract_digest,
        ):
            if type(value) is not str or len(value) != 128 or any(c not in "0123456789abcdef" for c in value):
                raise IngressError("ingress:config")
        if self.source_contract_digest != NC_MEDICAID_PROFILE.profile_digest:
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
            "source_contract_digest": self.source_contract_digest,
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
        return _digest("config", self.material())


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


@dataclass(frozen=True)
class EligibleSlotV1:
    slot_id: str
    scheduled_at: int
    attempt: int
    state: str


_SCHEMA_DDL = (
    """CREATE TABLE ingress_meta(
        meta_id INTEGER PRIMARY KEY CHECK(meta_id=1),
        schema TEXT NOT NULL,
        schema_version INTEGER NOT NULL,
        database_id TEXT NOT NULL,
        chain_id TEXT NOT NULL,
        config_digest TEXT NOT NULL,
        config_raw BLOB NOT NULL,
        sequence INTEGER NOT NULL,
        head_root TEXT NOT NULL,
        watermark INTEGER NOT NULL,
        slot_count INTEGER NOT NULL
    )""",
    """CREATE TABLE ingress_slots(
        slot_id TEXT PRIMARY KEY,
        scheduled_at INTEGER NOT NULL UNIQUE,
        state TEXT NOT NULL,
        attempt INTEGER NOT NULL,
        lease_token TEXT,
        lease_until INTEGER,
        artifact_id TEXT,
        operation_id TEXT
    )""",
    """CREATE TABLE ingress_artifacts(
        artifact_id TEXT PRIMARY KEY,
        observation BLOB NOT NULL,
        profile_id TEXT NOT NULL,
        profile_version INTEGER NOT NULL,
        observation_time INTEGER NOT NULL,
        effective_start INTEGER NOT NULL,
        effective_end INTEGER NOT NULL,
        source_count INTEGER NOT NULL,
        complete_source_count INTEGER NOT NULL,
        record_count INTEGER NOT NULL,
        finding_count INTEGER NOT NULL,
        discrepancy_count INTEGER NOT NULL,
        outcome TEXT NOT NULL,
        source_status TEXT NOT NULL,
        freshness TEXT NOT NULL,
        page_complete INTEGER NOT NULL,
        page_count INTEGER NOT NULL,
        resource_count INTEGER NOT NULL,
        verification_receipt BLOB NOT NULL,
        event_sequence INTEGER NOT NULL
    )""",
    """CREATE TABLE ingress_heads(
        stream_kind TEXT NOT NULL,
        stream_id TEXT NOT NULL,
        artifact_id TEXT,
        head_root TEXT NOT NULL,
        event_sequence INTEGER NOT NULL,
        PRIMARY KEY(stream_kind,stream_id),
        FOREIGN KEY(artifact_id) REFERENCES ingress_artifacts(artifact_id)
    )""",
    """CREATE TABLE ingress_events(
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
        observed_at INTEGER NOT NULL,
        material_digest TEXT NOT NULL,
        payload_digest TEXT NOT NULL,
        payload_length INTEGER NOT NULL,
        before_root TEXT NOT NULL,
        after_root TEXT NOT NULL,
        stream_before_root TEXT NOT NULL,
        stream_after_root TEXT NOT NULL,
        event_raw BLOB NOT NULL,
        receipt_digest TEXT NOT NULL,
        FOREIGN KEY(slot_id) REFERENCES ingress_slots(slot_id)
    )""",
    "CREATE INDEX ingress_slots_due_idx ON ingress_slots(state,lease_until,slot_id)",
    "CREATE UNIQUE INDEX ingress_events_chain_idx ON ingress_events(chain_id,sequence)",
    "CREATE INDEX ingress_events_operation_idx ON ingress_events(operation_id,event_kind)",
    "CREATE INDEX ingress_events_observed_at_idx ON ingress_events(observed_at,sequence)",
)


def _connection(path: Path, *, create: bool = False) -> sqlite3.Connection:
    try:
        connection = sqlite3.connect(str(path), isolation_level=None, timeout=0.25)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=delete")
        connection.execute("PRAGMA synchronous=full")
        connection.execute("PRAGMA busy_timeout=250")
        if create:
            connection.execute("PRAGMA max_page_count=16384")
        return connection
    except sqlite3.OperationalError as exc:
        if "locked" in str(exc).lower() or "busy" in str(exc).lower():
            raise IngressBusyError("ingress:busy") from None
        raise IngressError("ingress:database") from None
    except (OSError, sqlite3.Error):
        raise IngressError("ingress:database") from None


def _table_names(connection: sqlite3.Connection) -> tuple[str, ...]:
    return tuple(row[0] for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall())


def _path_ready(path: Path) -> bool:
    return path.exists() and path.is_file()


def _init(path: Path, config: IngressConfigV2) -> tuple[int, int]:
    path.parent.mkdir(parents=True, exist_ok=True)
    creating = not _path_ready(path)
    if not creating:
        connection = _connection(path)
        try:
            current = _table_names(connection)
            if current:
                if current != tuple(sorted(TABLES)):
                    raise IngressError("ingress:legacy-schema")
                try:
                    independent.verify_database(
                        path,
                        expected_database_id=config.database_id,
                        expected_config_digest=config.digest,
                    )
                except independent.IngressVerificationError:
                    raise IngressError("ingress:legacy-schema") from None
            else:
                creating = True
        finally:
            _safe_close(connection)
    if creating:
        connection = _connection(path, create=True)
        try:
            connection.execute("BEGIN IMMEDIATE")
            for statement in _SCHEMA_DDL:
                connection.execute(statement)
            config_raw = _canonical(config.material())
            if len(config_raw) > MAX_CONFIG_BYTES:
                raise IngressError("ingress:config")
            connection.execute(
                "INSERT INTO ingress_meta VALUES(1,?,?,?,?,?,?,?,?,?,?)",
                (
                    SCHEMA, SCHEMA_VERSION, config.database_id, config.chain_id,
                    config.digest, config_raw, 0, independent.GENESIS_ROOT, 0, 0,
                ),
            )
            connection.commit()
        except IngressError:
            _safe_rollback(connection)
            raise
        except sqlite3.Error:
            _safe_rollback(connection)
            raise IngressError("ingress:database-initialize") from None
        finally:
            _safe_close(connection)
    try:
        info = path.stat()
        return int(info.st_dev), int(info.st_ino)
    except OSError:
        raise IngressError("ingress:database") from None


class IngressServiceV2:
    """Owns only sanitized observation state and its event transaction."""

    def __init__(
        self,
        path: str | Path,
        config: IngressConfigV2,
        *,
        clock: Callable[[], int] | None = None,
        authority: writer_authority.WriterAuthority,
    ) -> None:
        if clock is not None and not callable(clock):
            raise IngressError("ingress:clock")
        if not isinstance(authority, writer_authority.WriterAuthority):
            raise IngressError("ingress:writer")
        self.path = Path(path)
        self.config = config
        self._clock = clock or (lambda: int(time.time()))
        self._authority = authority
        try:
            authority.assert_database_parent(self.path)
            with authority.mutation_scope(self.path):
                self._database_identity = _init(self.path, config)
        except writer_authority.WriterAuthorityError:
            raise
        self._assert_database_identity()

    def close(self) -> None:
        return None

    def _assert_database_identity(self) -> None:
        self._authority.assert_database_parent(self.path)
        try:
            info = self.path.stat()
            if (int(info.st_dev), int(info.st_ino)) != self._database_identity:
                raise IngressError("ingress:database-identity")
        except OSError:
            raise IngressError("ingress:database-identity") from None

    def _owner_now(self) -> int:
        self._authority.assert_live()
        try:
            value = self._clock()
        except Exception:
            raise IngressError("ingress:clock") from None
        if type(value) is not int or value < 0:
            raise IngressError("ingress:clock")
        return value

    def verify(self, *, include_observation: bool = False) -> dict[str, object]:
        self._assert_database_identity()
        try:
            result = independent.verify_database(
                self.path,
                expected_database_id=self.config.database_id,
                expected_config_digest=self.config.digest,
                include_observation=include_observation,
            )
        except independent.IngressVerificationError:
            self._assert_database_identity()
            raise
        self._assert_database_identity()
        return result

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
        observed_at: int,
        material: dict[str, object],
        payload_digest: str,
        payload_length: int,
        stream_kind: str = "SLOT",
        stream_id: str | None = None,
        head_artifact_id: str | None = None,
    ) -> bytes:
        meta = connection.execute("SELECT * FROM ingress_meta WHERE meta_id=1").fetchone()
        if meta is None:
            raise IngressError("ingress:meta")
        if type(observed_at) is not int or observed_at < 0:
            raise IngressConflictError("ingress:clock")
        latest = connection.execute(
            "SELECT observed_at FROM ingress_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        if latest is not None and observed_at < int(latest[0]):
            raise IngressConflictError("ingress:clock-rewind")
        sequence = int(meta["sequence"]) + 1
        stream_id = str(stream_id or slot_id)
        old_head = connection.execute(
            "SELECT head_root,artifact_id FROM ingress_heads WHERE stream_kind=? AND stream_id=?",
            (stream_kind, stream_id),
        ).fetchone()
        stream_before = str(old_head["head_root"]) if old_head is not None else independent.GENESIS_ROOT
        if head_artifact_id is None and old_head is not None:
            head_artifact_id = old_head["artifact_id"]
        body: dict[str, object] = {
            "schema": SCHEMA, "schema_version": SCHEMA_VERSION,
            "database_id": self.config.database_id, "chain_id": self.config.chain_id,
            "sequence": sequence, "event_id": "", "event_kind": kind,
            "stream_kind": stream_kind, "stream_id": stream_id,
            "operation_id": operation_id, "request_digest": request_digest,
            "slot_id": slot_id, "prior_state": prior_state,
            "next_state": next_state, "attempt": attempt,
            "lease_token": lease_token, "lease_until": lease_until,
            "observed_at": observed_at, "material": dict(material),
            "material_digest": _digest("material", material),
            "payload_digest": payload_digest, "payload_length": payload_length,
            "before_root": meta["head_root"], "after_root": "",
            "stream_before_root": stream_before, "stream_after_root": "",
        }
        body["event_id"] = _digest("event-id", {
            key: body[key] for key in independent.EVENT_KEYS
            if key not in {"event_id", "after_root", "stream_after_root"}
        })
        body["after_root"] = independent._event_root(
            sequence=sequence, previous=str(meta["head_root"]),
            event_id=str(body["event_id"]), event_kind=kind,
            stream_kind=stream_kind, stream_id=stream_id, slot_id=slot_id,
            next_state=next_state, observed_at=observed_at,
            material_digest=str(body["material_digest"]),
        )
        body["stream_after_root"] = independent._stream_root(
            sequence=sequence, previous=stream_before,
            event_id=str(body["event_id"]), stream_kind=stream_kind,
            stream_id=stream_id, next_state=next_state,
            observed_at=observed_at, material_digest=str(body["material_digest"]),
        )
        raw = _canonical(body)
        if len(raw) > MAX_EVENT_BYTES:
            raise IngressConflictError("ingress:capacity")
        connection.execute(
            "INSERT INTO ingress_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                sequence, body["event_id"], kind, self.config.database_id,
                self.config.chain_id, stream_kind, stream_id, operation_id,
                request_digest, slot_id, prior_state, next_state, attempt,
                lease_token, lease_until, observed_at, body["material_digest"],
                payload_digest, payload_length, body["before_root"],
                body["after_root"], body["stream_before_root"],
                body["stream_after_root"], raw, _raw_digest("receipt", raw),
            ),
        )
        connection.execute(
            "INSERT INTO ingress_heads(stream_kind,stream_id,artifact_id,head_root,event_sequence) VALUES(?,?,?,?,?) "
            "ON CONFLICT(stream_kind,stream_id) DO UPDATE SET artifact_id=COALESCE(excluded.artifact_id,ingress_heads.artifact_id),head_root=excluded.head_root,event_sequence=excluded.event_sequence",
            (stream_kind, stream_id, head_artifact_id, body["stream_after_root"], sequence),
        )
        connection.execute(
            "UPDATE ingress_meta SET sequence=?,head_root=?,watermark=? WHERE meta_id=1",
            (sequence, body["after_root"], sequence),
        )
        return raw

    def _receipt(self, raw: bytes, *, artifact_id: str | None, next_state: str) -> IngressReceipt:
        try:
            value = independent._parse(raw, "ingress:receipt")
        except independent.IngressVerificationError:
            raise IngressError("ingress:receipt") from None
        return IngressReceipt(
            raw=raw, event_id=str(value["event_id"]),
            operation_id=str(value["operation_id"]), artifact_id=artifact_id,
            next_state=next_state, sequence=int(value["sequence"]),
            after_root=str(value["after_root"]), database_id=self.config.database_id,
        )

    def ensure_slot(self, scheduled_at: int) -> IngressReceipt:
        with self._authority.mutation_scope(self.path):
            return self._ensure_slot(scheduled_at)

    def _ensure_slot(self, scheduled_at: int) -> IngressReceipt:
        if type(scheduled_at) is not int or not self.config.effective_start <= scheduled_at <= self.config.effective_end or (scheduled_at - self.config.effective_start) % self.config.cadence_seconds != 0:
            raise IngressConflictError("ingress:schedule")
        connection = _connection(self.path)
        indeterminate = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute("SELECT slot_id FROM ingress_slots WHERE scheduled_at=?", (scheduled_at,)).fetchone()
            if existing is not None:
                event = connection.execute(
                    "SELECT event_raw FROM ingress_events WHERE slot_id=? AND event_kind='CREATE_SLOT'",
                    (existing["slot_id"],),
                ).fetchone()
                if event is None:
                    raise IngressError("ingress:slot")
                connection.commit()
                return self._receipt(bytes(event[0]), artifact_id=None, next_state="DUE")
            if int(connection.execute("SELECT COUNT(*) FROM ingress_slots").fetchone()[0]) >= self.config.max_slots:
                raise IngressConflictError("ingress:capacity")
            now = self._owner_now()
            slot_id = _digest("slot-id", {"config_digest": self.config.digest, "scheduled_at": scheduled_at})
            operation = _digest("slot-operation", {"slot_id": slot_id})
            request = _digest("request", {"operation_id": operation, "scheduled_at": scheduled_at})
            payload = _digest("slot-payload", {"slot_id": slot_id, "scheduled_at": scheduled_at})
            connection.execute(
                "INSERT INTO ingress_slots(slot_id,scheduled_at,state,attempt,lease_token,lease_until,artifact_id,operation_id) VALUES(?,?,?,?,?,?,?,?)",
                (slot_id, scheduled_at, "DUE", 0, None, None, None, operation),
            )
            raw = self._append(
                connection, kind="CREATE_SLOT", operation_id=operation,
                request_digest=request, slot_id=slot_id, prior_state="NONE",
                next_state="DUE", attempt=0, lease_token=None, lease_until=None,
                observed_at=now,
                material={"slot_id": slot_id, "scheduled_at": scheduled_at, "operation_id": operation},
                payload_digest=payload, payload_length=0,
            )
            connection.execute("UPDATE ingress_meta SET slot_count=slot_count+1 WHERE meta_id=1")
            connection.commit()
            return self._receipt(raw, artifact_id=None, next_state="DUE")
        except IngressError:
            _safe_rollback(connection)
            raise
        except sqlite3.OperationalError as exc:
            _safe_rollback(connection)
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise IngressBusyError("ingress:busy") from None
            raise IngressError("ingress:database") from None
        except sqlite3.Error:
            _safe_rollback(connection)
            raise IngressError("ingress:database") from None
        except Exception:
            _safe_rollback(connection)
            indeterminate = True
        finally:
            _safe_close(connection)
        if indeterminate:
            raise_redacted(IngressIndeterminateError, "ingress:transaction-indeterminate")

    def claim_slot(self, slot_id: str, *, lease_token: str) -> IngressReceipt:
        with self._authority.mutation_scope(self.path):
            return self._claim_slot(slot_id, lease_token=lease_token)

    def _claim_slot(self, slot_id: str, *, lease_token: str) -> IngressReceipt:
        if type(slot_id) is not str or len(slot_id) != 128 or any(c not in "0123456789abcdef" for c in slot_id):
            raise IngressConflictError("ingress:slot")
        if type(lease_token) is not str or len(lease_token) > 256:
            raise IngressConflictError("ingress:lease")
        try:
            token_bytes = lease_token.encode("ascii")
        except UnicodeEncodeError:
            raise IngressConflictError("ingress:lease") from None
        if len(token_bytes) < _MIN_LEASE_TOKEN_BYTES:
            raise IngressConflictError("ingress:lease")
        connection = _connection(self.path)
        indeterminate = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            slot = connection.execute("SELECT * FROM ingress_slots WHERE slot_id=?", (slot_id,)).fetchone()
            if slot is None:
                raise IngressConflictError("ingress:slot")
            now = self._owner_now()
            if now < int(slot["scheduled_at"]):
                raise IngressConflictError("ingress:lease")
            if slot["state"] not in {"DUE", "LEASED"} or (slot["state"] == "LEASED" and (slot["lease_until"] is None or int(slot["lease_until"]) > now)):
                raise IngressConflictError("ingress:lease")
            attempt = int(slot["attempt"]) + 1
            if attempt > self.config.max_attempts:
                if slot["state"] != "LEASED" or slot["lease_token"] is None or slot["lease_until"] is None:
                    raise IngressConflictError("ingress:attempt")
                operation = str(slot["operation_id"])
                payload = _digest("lease-recovery", {"slot_id": slot_id, "attempt": slot["attempt"]})
                hold_raw = self._append(
                    connection, kind="HOLD", operation_id=operation,
                    request_digest=_digest("request", {"slot_id": slot_id, "action": "HOLD"}),
                    slot_id=slot_id, prior_state="LEASED", next_state="HELD",
                    attempt=int(slot["attempt"]), lease_token=str(slot["lease_token"]),
                    lease_until=int(slot["lease_until"]), observed_at=now,
                    material={"slot_id": slot_id, "action": "HOLD", "attempt": int(slot["attempt"]), "operation_id": operation},
                    payload_digest=payload, payload_length=0,
                )
                connection.execute(
                    "UPDATE ingress_slots SET state='HELD',lease_token=NULL,lease_until=NULL WHERE slot_id=?",
                    (slot_id,),
                )
                connection.commit()
                return self._receipt(hold_raw, artifact_id=None, next_state="HELD")
            token_digest = independent._lease_token_digest(self.config.database_id, self.config.digest, slot_id, attempt, lease_token)
            lease_until = now + self.config.lease_seconds
            operation = str(slot["operation_id"])
            request = _digest("request", {"slot_id": slot_id, "action": "LEASE", "attempt": attempt})
            payload = _digest("lease-payload", {"slot_id": slot_id, "attempt": attempt, "lease_token": token_digest, "lease_until": lease_until, "operation_id": operation})
            raw = self._append(
                connection, kind="LEASE", operation_id=operation,
                request_digest=request, slot_id=slot_id,
                prior_state=str(slot["state"]), next_state="LEASED",
                attempt=attempt, lease_token=token_digest, lease_until=lease_until,
                observed_at=now,
                material={"slot_id": slot_id, "attempt": attempt, "lease_token": token_digest, "lease_until": lease_until, "operation_id": operation},
                payload_digest=payload, payload_length=0,
            )
            connection.execute("UPDATE ingress_slots SET state='LEASED',attempt=?,lease_token=?,lease_until=? WHERE slot_id=?", (attempt, token_digest, lease_until, slot_id))
            connection.commit()
            return self._receipt(raw, artifact_id=None, next_state="LEASED")
        except IngressError:
            _safe_rollback(connection)
            raise
        except sqlite3.OperationalError as exc:
            _safe_rollback(connection)
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise IngressBusyError("ingress:busy") from None
            raise IngressError("ingress:database") from None
        except sqlite3.Error:
            _safe_rollback(connection)
            raise IngressError("ingress:database") from None
        except Exception:
            _safe_rollback(connection)
            indeterminate = True
        finally:
            _safe_close(connection)
        if indeterminate:
            raise_redacted(IngressIndeterminateError, "ingress:transaction-indeterminate")

    def admit_observation(
        self,
        observation_raw: bytes,
        verification_receipt_raw: bytes,
        *,
        scheduled_at: int,
        attempt: int,
        lease_token: str,
        operation_id: str | None = None,
        **legacy_fields: object,
    ) -> IngressReceipt:
        with self._authority.mutation_scope(self.path):
            return self._admit_observation(
                observation_raw,
                verification_receipt_raw,
                scheduled_at=scheduled_at,
                attempt=attempt,
                lease_token=lease_token,
                operation_id=operation_id,
                **legacy_fields,
            )

    def _admit_observation(
        self,
        observation: bytes,
        verification_receipt: bytes,
        *,
        scheduled_at: int,
        attempt: int,
        lease_token: str,
        operation_id: str | None = None,
        **legacy_fields: object,
    ) -> IngressReceipt:
        if legacy_fields:
            raise IngressConflictError("ingress:legacy-raw-api")
        if type(observation) is not bytes or type(verification_receipt) is not bytes:
            raise IngressConflictError("ingress:observation")
        if len(observation) > MAX_OBSERVATION_BYTES or len(verification_receipt) > MAX_VERIFICATION_RECEIPT_BYTES:
            raise IngressConflictError("ingress:capacity")
        try:
            checked = independent.verify_observation_pair(
                observation, verification_receipt,
                expected_profile_id=NC_MEDICAID_PROFILE.source_profile_id,
                expected_profile_version=3,
            )
        except independent.IngressVerificationError:
            raise IngressConflictError("ingress:observation-reject") from None
        if (
            type(scheduled_at) is not int
            or type(attempt) is not int
            or not 1 <= attempt <= self.config.max_attempts
            or type(lease_token) is not str
        ):
            raise IngressConflictError("ingress:admission")
        if len(lease_token) > 256:
            raise IngressConflictError("ingress:lease")
        if checked["observation"]["observation_time"] != scheduled_at:
            raise IngressConflictError("ingress:observation-slot")
        observation_id = str(checked["observation_id"])
        artifact_id = _digest("artifact-id", {
            "observation_digest": observation_id,
            "profile_id": checked["observation"]["profile_id"],
            "profile_version": checked["observation"]["profile_version"],
            "observation_time": checked["observation"]["observation_time"],
        })
        expected_operation = _digest("capture-operation", {"slot_id": _digest("slot-id", {"config_digest": self.config.digest, "scheduled_at": scheduled_at}), "artifact_id": artifact_id})
        if operation_id is not None and operation_id != expected_operation:
            raise IngressConflictError("ingress:operation")
        operation_id = expected_operation
        connection = _connection(self.path)
        indeterminate = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            prior_event = connection.execute(
                "SELECT event_raw FROM ingress_events WHERE operation_id=? AND event_kind='CAPTURE'",
                (operation_id,),
            ).fetchone()
            if prior_event is not None:
                value = independent._parse(prior_event[0], "ingress:receipt")
                material = value.get("material")
                if not isinstance(material, dict) or material.get("artifact_id") != artifact_id or material.get("observation_id") != observation_id:
                    raise IngressConflictError("ingress:retry-conflict")
                stored = connection.execute(
                    "SELECT observation,verification_receipt,event_sequence FROM ingress_artifacts WHERE artifact_id=?",
                    (artifact_id,),
                ).fetchone()
                if (
                    stored is None
                    or bytes(stored["observation"]) != observation
                    or bytes(stored["verification_receipt"]) != verification_receipt
                ):
                    raise IngressConflictError("ingress:retry-conflict")
                terminal = connection.execute(
                    "SELECT event_raw FROM ingress_events WHERE sequence=? AND event_kind='ADMIT'",
                    (stored["event_sequence"],),
                ).fetchone()
                if terminal is None:
                    raise IngressIndeterminateError("ingress:retry-indeterminate")
                connection.commit()
                return self._receipt(bytes(terminal[0]), artifact_id=artifact_id, next_state="QUARANTINED")
            slot_id = _digest("slot-id", {"config_digest": self.config.digest, "scheduled_at": scheduled_at})
            slot = connection.execute("SELECT * FROM ingress_slots WHERE slot_id=?", (slot_id,)).fetchone()
            if slot is None or slot["state"] != "LEASED" or int(slot["attempt"]) != attempt:
                raise IngressConflictError("ingress:slot")
            token_digest = independent._lease_token_digest(self.config.database_id, self.config.digest, slot_id, attempt, lease_token)
            if slot["lease_token"] != token_digest:
                raise IngressConflictError("ingress:lease")
            now = self._owner_now()
            if slot["lease_until"] is None or now > int(slot["lease_until"]):
                raise IngressConflictError("ingress:lease-expired")
            existing = connection.execute("SELECT * FROM ingress_artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()
            if existing is not None:
                if bytes(existing["observation"]) != observation or bytes(existing["verification_receipt"]) != verification_receipt:
                    raise IngressConflictError("ingress:artifact-conflict")
                raise IngressConflictError("ingress:retry-conflict")
            value = checked["observation"]
            connection.execute(
                "INSERT INTO ingress_artifacts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    artifact_id, observation, value["profile_id"], value["profile_version"],
                    value["observation_time"], value["effective_start"], value["effective_end"],
                    value["source_count"], value["complete_source_count"], value["record_count"],
                    value["finding_count"], value["discrepancy_count"], value["outcome"],
                    value["source_status"], value["freshness"], 1 if value["page_complete"] else 0,
                    value["page_count"], value["resource_count"], verification_receipt, 0,
                ),
            )
            capture_material = {
                "slot_id": slot_id, "artifact_id": artifact_id,
                "observation_id": observation_id, "outcome": value["outcome"],
                "operation_id": operation_id, "lease_token_digest": token_digest,
            }
            capture_request = _digest("request", {"operation_id": operation_id, "slot_id": slot_id, "artifact_id": artifact_id})
            capture_raw = self._append(
                connection, kind="CAPTURE", operation_id=operation_id,
                request_digest=capture_request, slot_id=slot_id,
                prior_state="LEASED", next_state="CAPTURED",
                attempt=attempt, lease_token=token_digest,
                lease_until=int(slot["lease_until"]), observed_at=now,
                material=capture_material, payload_digest=artifact_id,
                payload_length=len(observation), head_artifact_id=artifact_id,
            )
            begin_operation = _digest("quarantine-operation", {"capture_operation": operation_id, "decision": "BEGIN"})
            begin_raw = self._append(
                connection, kind="BEGIN_QUARANTINE", operation_id=begin_operation,
                request_digest=_digest("request", {"operation_id": begin_operation, "slot_id": slot_id, "artifact_id": artifact_id}),
                slot_id=slot_id, prior_state="CAPTURED", next_state="QUARANTINE_PENDING",
                attempt=attempt, lease_token=token_digest, lease_until=int(slot["lease_until"]),
                observed_at=now,
                material={"artifact_id": artifact_id, "decision": "QUARANTINE_PENDING", "operation_id": begin_operation},
                payload_digest=artifact_id, payload_length=len(observation),
                head_artifact_id=artifact_id,
            )
            admit_operation = _digest("quarantine-operation", {"capture_operation": operation_id, "decision": "ADMIT"})
            final_raw = self._append(
                connection, kind="ADMIT", operation_id=admit_operation,
                request_digest=_digest("request", {"operation_id": admit_operation, "slot_id": slot_id, "artifact_id": artifact_id}),
                slot_id=slot_id, prior_state="QUARANTINE_PENDING", next_state="QUARANTINED",
                attempt=attempt, lease_token=token_digest, lease_until=int(slot["lease_until"]),
                observed_at=now,
                material={"artifact_id": artifact_id, "decision": "QUARANTINED", "operation_id": admit_operation},
                payload_digest=artifact_id, payload_length=len(observation),
                stream_kind="QUARANTINE", stream_id=self.config.chain_id,
                head_artifact_id=artifact_id,
            )
            sequence = int(independent._parse(final_raw, "ingress:receipt")["sequence"])
            connection.execute("UPDATE ingress_artifacts SET event_sequence=? WHERE artifact_id=?", (sequence, artifact_id))
            connection.execute("UPDATE ingress_slots SET state='QUARANTINED',artifact_id=?,lease_token=NULL,lease_until=NULL WHERE slot_id=?", (artifact_id, slot_id))
            connection.commit()
            return self._receipt(final_raw, artifact_id=artifact_id, next_state="QUARANTINED")
        except IngressError:
            _safe_rollback(connection)
            raise
        except sqlite3.OperationalError as exc:
            _safe_rollback(connection)
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise IngressBusyError("ingress:busy") from None
            raise IngressError("ingress:database") from None
        except sqlite3.Error:
            _safe_rollback(connection)
            raise IngressError("ingress:database") from None
        except Exception:
            _safe_rollback(connection)
            indeterminate = True
        finally:
            _safe_close(connection)
        if indeterminate:
            raise_redacted(IngressIndeterminateError, "ingress:transaction-indeterminate")

    def current(self, *, include_observation: bool = False) -> dict[str, object]:
        return self.verify(include_observation=include_observation)

    def _operational_quarantined_artifact_ids(self, limit: int) -> tuple[str, ...]:
        self._authority.assert_database_parent(self.path)
        if type(limit) is not int or not 1 <= limit <= self.config.max_slots:
            raise IngressConflictError("ingress:projection-limit")
        result = self.verify()
        connection = _connection(self.path)
        try:
            rows = connection.execute(
                "SELECT artifact_id,event_sequence FROM ingress_artifacts WHERE event_sequence>0 ORDER BY event_sequence,artifact_id LIMIT ?",
                (limit + 1,),
            ).fetchall()
            if len(rows) > limit:
                raise IngressConflictError("ingress:projection-capacity")
            return tuple(str(row["artifact_id"]) for row in rows)
        finally:
            connection.close()

    def eligible_slots(self, limit: int) -> tuple[EligibleSlotV1, ...]:
        self._authority.assert_database_parent(self.path)
        if type(limit) is not int or not 1 <= limit <= 16:
            raise IngressConflictError("ingress:eligible-limit")
        now = self._owner_now()
        connection = _connection(self.path)
        try:
            rows = connection.execute(
                "SELECT slot_id,scheduled_at,attempt,state FROM ingress_slots "
                "WHERE (state='LEASED' AND lease_until IS NOT NULL AND lease_until<=?) OR (state='DUE' AND scheduled_at<=?) "
                "ORDER BY CASE WHEN state='LEASED' THEN 0 ELSE 1 END,scheduled_at,slot_id LIMIT ?",
                (now, now, limit),
            ).fetchall()
            return tuple(EligibleSlotV1(str(row["slot_id"]), int(row["scheduled_at"]), int(row["attempt"]), str(row["state"])) for row in rows)
        finally:
            connection.close()

    def logical_export(self) -> bytes:
        return independent.logical_export(self.verify())

    def support(self) -> dict[str, object]:
        result = self.verify()
        return {
            "schema": "mirror-ingress-support-v3",
            "states": result["state_counts"],
            "slot_count": result["slot_count"],
            "artifact_count": result["artifact_count"],
            "event_count": result["event_count"],
            "flags": dict(FIXED_FLAGS),
        }


__all__ = [
    "IngressConfigV2", "IngressReceipt", "EligibleSlotV1", "IngressError",
    "IngressConflictError", "IngressBusyError", "IngressIndeterminateError",
    "IngressServiceV2", "SCHEMA", "SCHEMA_VERSION", "TABLES", "STATES",
    "FIXED_FLAGS", "MAX_IDENTIFIER_BYTES", "MAX_OBSERVATION_BYTES",
    "MAX_VERIFICATION_RECEIPT_BYTES",
]
