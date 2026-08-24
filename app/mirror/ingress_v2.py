"""The single five-table durable ingress owner for Mirror V2."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import stat
import time
from typing import Callable, Mapping

from app.mirror import external_source_adapter as external
from app.mirror import external_source_adapter_independent as external_independent
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
MAX_EVENT_BYTES = independent.MAX_EVENT_BYTES
MAX_CONFIG_BYTES = independent.MAX_CONFIG_BYTES
MAX_IDENTIFIER_BYTES = independent.MAX_IDENTIFIER_BYTES
MAX_COMPLETE_FRAME_BYTES = independent.MAX_COMPLETE_FRAME_BYTES
INTAKE_MAGIC = independent.INTAKE_MAGIC
INTAKE_VERSION = independent.INTAKE_VERSION
INTAKE_FLAGS = independent.INTAKE_FLAGS
INTAKE_HEADER_BYTES = independent.INTAKE_HEADER_BYTES
INTAKE_DIRECTORY_ENTRY_BYTES = independent.INTAKE_DIRECTORY_ENTRY_BYTES
DEFAULT_PAGE_SIZE = 4096
_SQLITE_PAGE_OVERHEAD_PAGES = 16
TERMINAL_RESERVE_BYTES = 2 * MAX_EVENT_BYTES + _SQLITE_PAGE_OVERHEAD_PAGES * DEFAULT_PAGE_SIZE
_LIVE_STATES = (
    "DUE", "LEASED", "CAPTURED", "QUARANTINE_PENDING", "QUARANTINE_UNCONFIRMED",
)
_REPARSE_POINT = 0x400
_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")
_MAX_CALLER_STRING_BYTES = 1024
_MAX_OPERATION_VALUE_BYTES = 256
_MIN_LEASE_TOKEN_BYTES = 32


def _utc_epoch_seconds() -> int:
    return int(time.time())


class IngressError(ValueError):
    """Public-safe ingress boundary."""


class IngressConflictError(IngressError):
    """A stale, conflicting, or rebound ingress request."""


class IngressBusyError(IngressError):
    """A bounded writer contention failure."""


def _safe_identifier(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise IngressError(label)
    if len(value) > MAX_IDENTIFIER_BYTES:
        raise IngressError(label)
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError:
        raise IngressError(label) from None
    if (
        len(raw) > MAX_IDENTIFIER_BYTES
        or not ("A" <= value[0] <= "Z" or "a" <= value[0] <= "z" or "0" <= value[0] <= "9")
        or any(
            not (
                "A" <= character <= "Z"
                or "a" <= character <= "z"
                or "0" <= character <= "9"
                or character in "._:-"
            )
            for character in value
        )
    ):
        raise IngressError(label)
    return value


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
    external_capture_schema: str = fhir.ENVELOPE_SCHEMA
    external_capture_schema_version: int = fhir.ENVELOPE_SCHEMA_VERSION
    external_logical_endpoint_id: str = "nc-medicaid-fhir-endpoint"
    external_source_roles: tuple[str, ...] = ("FHIR_CAPTURE",)
    external_verifier_id: str = "SYNTH_EXTERNAL_SOURCE_VERIFIER_V2"
    external_verifier_epoch: int = 2
    freshness_grace_seconds: int = 30
    max_capture_bytes: int = external.MAX_CAPTURE_BYTES
    max_page_count: int = 4

    def __post_init__(self) -> None:
        _safe_identifier(self.database_id, "ingress:config")
        _safe_identifier(self.chain_id, "ingress:config")
        for value in (self.policy_digest, self.authorization_digest, self.terms_digest):
            if type(value) is not str or len(value) != 128 or any(
                char not in "0123456789abcdef" for char in value
            ):
                raise IngressError("ingress:config")
        if self.source_contract_digest != NC_MEDICAID_PROFILE.profile_digest:
            raise IngressError("ingress:config")
        if self.external_capture_schema != fhir.ENVELOPE_SCHEMA or self.external_capture_schema_version != fhir.ENVELOPE_SCHEMA_VERSION:
            raise IngressError("ingress:config")
        _safe_identifier(self.external_logical_endpoint_id, "ingress:config")
        if (
            type(self.external_source_roles) is not tuple
            or not self.external_source_roles
            or len(set(self.external_source_roles)) != len(self.external_source_roles)
            or any(type(role) is not str for role in self.external_source_roles)
        ):
            raise IngressError("ingress:config")
        for role in self.external_source_roles:
            _safe_identifier(role, "ingress:config")
        _safe_identifier(self.external_verifier_id, "ingress:config")
        if type(self.external_verifier_epoch) is not int or self.external_verifier_epoch < 1:
            raise IngressError("ingress:config")
        if type(self.freshness_grace_seconds) is not int or not 0 <= self.freshness_grace_seconds <= 31_536_000:
            raise IngressError("ingress:config")
        if type(self.max_capture_bytes) is not int or not 1 <= self.max_capture_bytes <= external.MAX_CAPTURE_BYTES:
            raise IngressError("ingress:config")
        if type(self.max_page_count) is not int or not 1 <= self.max_page_count <= 32:
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
        policy = self.external_policy()
        return {
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "database_id": self.database_id,
            "chain_id": self.chain_id,
            "policy_digest": self.policy_digest,
            "authorization_digest": self.authorization_digest,
            "terms_digest": self.terms_digest,
            "source_contract": NC_MEDICAID_PROFILE.material(),
            "source_contract_digest": self.source_contract_digest,
            "external_policy": policy.material(),
            "external_policy_digest": policy.digest,
            "cadence_seconds": self.cadence_seconds,
            "effective_start": self.effective_start,
            "effective_end": self.effective_end,
            "max_slots": self.max_slots,
            "max_attempts": self.max_attempts,
            "lease_seconds": self.lease_seconds,
            "flags": dict(FIXED_FLAGS),
        }

    def external_policy(self) -> external.ExternalSourcePolicyV2:
        return external.ExternalSourcePolicyV2(
            source_contract_digest=self.source_contract_digest,
            capture_schema=self.external_capture_schema,
            capture_schema_version=self.external_capture_schema_version,
            logical_endpoint_id=self.external_logical_endpoint_id,
            source_roles=self.external_source_roles,
            verifier_id=self.external_verifier_id,
            verifier_epoch=self.external_verifier_epoch,
            authorization_artifact_digest=self.authorization_digest,
            terms_artifact_digest=self.terms_digest,
            effective_start=self.effective_start,
            effective_end=self.effective_end,
            expected_cadence_seconds=self.cadence_seconds,
            freshness_grace_seconds=self.freshness_grace_seconds,
            max_capture_bytes=self.max_capture_bytes,
            max_page_count=self.max_page_count,
            profile_id=NC_MEDICAID_PROFILE.source_profile_id,
            version=NC_MEDICAID_PROFILE.version,
        )

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


def _pack_intake_frame(evidence_raw: bytes, envelope_raw: bytes, page_digests: tuple[str, ...]) -> bytes:
    if (
        type(evidence_raw) is not bytes
        or type(envelope_raw) is not bytes
        or not evidence_raw
        or not envelope_raw
        or len(evidence_raw) > independent.MAX_EXTERNAL_ARTIFACT_BYTES
        or len(envelope_raw) > fhir.NC_MEDICAID_PROFILE.transport_caps["max_envelope_bytes"]
        or type(page_digests) is not tuple
        or not 1 <= len(page_digests) <= fhir.NC_MEDICAID_PROFILE.transport_caps["max_pages"]
    ):
        raise IngressError("ingress:intake-frame")
    try:
        envelope = json.loads(envelope_raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        raise IngressError("ingress:intake-frame") from None
    pages = envelope.get("pages") if isinstance(envelope, dict) else None
    if not isinstance(pages, list) or len(pages) != len(page_digests):
        raise IngressError("ingress:intake-frame")
    directory = bytearray()
    aggregate = bytearray()
    search_from = 0
    for index, expected_digest in enumerate(page_digests):
        page = pages[index]
        page_raw = _canonical(page)
        page_offset = envelope_raw.find(page_raw, search_from)
        if page_offset < search_from or page_offset + len(page_raw) > len(envelope_raw):
            raise IngressError("ingress:intake-frame")
        if not isinstance(page, dict) or page.get("sequence") != index or page.get("body_digest") != expected_digest:
            raise IngressError("ingress:intake-frame")
        try:
            digest_bytes = bytes.fromhex(str(expected_digest))
        except ValueError:
            raise IngressError("ingress:intake-frame") from None
        if len(digest_bytes) != 64:
            raise IngressError("ingress:intake-frame")
        directory.extend(index.to_bytes(4, "big"))
        directory.extend(page_offset.to_bytes(4, "big"))
        directory.extend(len(page_raw).to_bytes(4, "big"))
        directory.extend(digest_bytes)
        aggregate.extend(page_raw)
        search_from = page_offset + len(page_raw)
    aggregate_digest = bytes.fromhex(_raw_digest("frame-pages", bytes(aggregate)))
    header = (
        INTAKE_MAGIC
        + INTAKE_VERSION.to_bytes(4, "big")
        + INTAKE_FLAGS.to_bytes(4, "big")
        + len(evidence_raw).to_bytes(4, "big")
        + len(envelope_raw).to_bytes(4, "big")
        + len(pages).to_bytes(4, "big")
        + len(aggregate).to_bytes(4, "big")
        + aggregate_digest
    )
    frame = header + bytes(directory) + evidence_raw + envelope_raw
    if len(frame) > MAX_COMPLETE_FRAME_BYTES:
        raise IngressConflictError("ingress:capacity")
    return frame


def _bounded_string(
    value: object,
    label: str,
    *,
    max_bytes: int = _MAX_CALLER_STRING_BYTES,
    min_bytes: int = 1,
    ascii_only: bool = False,
) -> str:
    if type(value) is not str or not value:
        raise IngressError(label)
    if len(value) > max_bytes:
        raise IngressError(label)
    try:
        encoded = value.encode("ascii" if ascii_only else "utf-8")
        if not min_bytes <= len(encoded) <= max_bytes:
            raise IngressError(label)
    except UnicodeEncodeError:
        raise IngressError(label) from None
    return value


def _bounded_digest_string(value: object, label: str) -> str:
    value = _bounded_string(value, label, max_bytes=128)
    if len(value) != 128 or any(character not in "0123456789abcdef" for character in value):
        raise IngressError(label)
    return value


def _lease_token_digest(config: IngressConfigV2, slot_id: str, attempt: int, raw_token: str) -> str:
    return independent._lease_token_digest(
        config.database_id,
        config.digest,
        slot_id,
        attempt,
        raw_token,
    )


def _is_reparse(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)


def _sidecar_present(database: Path) -> bool:
    return any(os.path.lexists(os.fspath(database) + suffix) for suffix in _SIDECAR_SUFFIXES)


def _path_identity(database: Path, *, allow_missing: bool) -> tuple[int, int, int, int] | None:
    try:
        parent = os.lstat(database.parent)
    except FileNotFoundError:
        raise IngressError("ingress:database-open") from None
    except IngressError:
        raise
    except OSError:
        raise_redacted(IngressError, "ingress:database-open")
    if not stat.S_ISDIR(parent.st_mode) or _is_reparse(parent):
        raise IngressError("ingress:database-open")
    if _sidecar_present(database):
        raise IngressError("ingress:database-open")
    try:
        info = os.lstat(database)
    except FileNotFoundError:
        if allow_missing:
            return None
        raise IngressError("ingress:database-open") from None
    except OSError:
        raise_redacted(IngressError, "ingress:database-open")
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or _is_reparse(info)
        or info.st_nlink != 1
        or info.st_size > MAX_DATABASE_BYTES
    ):
        raise IngressError("ingress:database-open")
    return (int(info.st_dev), int(info.st_ino), int(info.st_nlink), int(info.st_size))


def _configure_page_limit(connection: sqlite3.Connection) -> tuple[int, int, int]:
    try:
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        if page_size <= 0 or page_count < 0 or page_count * page_size > MAX_DATABASE_BYTES:
            raise IngressError("ingress:capacity")
        max_pages = MAX_DATABASE_BYTES // page_size
        if max_pages <= 0:
            raise IngressError("ingress:capacity")
        configured = int(connection.execute(f"PRAGMA max_page_count={max_pages}").fetchone()[0])
        if configured <= 0 or configured > max_pages or configured * page_size > MAX_DATABASE_BYTES:
            raise IngressError("ingress:capacity")
        if int(connection.execute("PRAGMA page_count").fetchone()[0]) > configured:
            raise IngressError("ingress:capacity")
        return page_size, page_count, configured
    except IngressError:
        raise
    except (OSError, sqlite3.Error, TypeError, ValueError):
        raise_redacted(IngressError, "ingress:capacity")


def _connection(
    path: Path,
    *,
    timeout: float = 0.25,
    configure_cap: bool = True,
    expected_identity: tuple[int, int] | None = None,
    create: bool = False,
) -> sqlite3.Connection:
    database = Path(path)
    if create and expected_identity is not None:
        raise IngressError("ingress:database-open")
    before = _path_identity(database, allow_missing=create)
    if not create and before is None:
        raise IngressError("ingress:database-open")
    if expected_identity is not None and (
        before is None or (before[0], before[1]) != expected_identity
    ):
        raise IngressError("ingress:database-open")
    connection: sqlite3.Connection | None = None
    try:
        if create:
            connection = sqlite3.connect(database, timeout=timeout, isolation_level=None)
        else:
            connection = sqlite3.connect(
                database.absolute().as_uri() + "?mode=rw",
                uri=True,
                timeout=timeout,
                isolation_level=None,
            )
        after_connect = _path_identity(database, allow_missing=False)
        if (
            after_connect is None
            or (before is not None and (after_connect[0], after_connect[1]) != (before[0], before[1]))
            or (expected_identity is not None and (after_connect[0], after_connect[1]) != expected_identity)
        ):
            raise IngressError("ingress:database-open")
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=250")
        journal_mode = str(connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0]).lower()
        if journal_mode != "delete":
            raise IngressError("ingress:database-open")
        connection.execute("PRAGMA synchronous=FULL")
        if int(connection.execute("PRAGMA synchronous").fetchone()[0]) != 2:
            raise IngressError("ingress:database-open")
        if configure_cap:
            _configure_page_limit(connection)
        else:
            page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
            page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
            if page_size <= 0 or page_count < 0 or page_count * page_size > MAX_DATABASE_BYTES:
                raise IngressError("ingress:capacity")
        after = _path_identity(database, allow_missing=False)
        if after is None or (before is not None and (after[0], after[1]) != (before[0], before[1])):
            raise IngressError("ingress:database-open")
        if expected_identity is not None and (after[0], after[1]) != expected_identity:
            raise IngressError("ingress:database-open")
        return connection
    except IngressError:
        if connection is not None:
            connection.close()
        raise
    except sqlite3.OperationalError as exc:
        if connection is not None:
            connection.close()
        if _is_capacity_error(exc):
            raise_redacted(IngressError, "ingress:capacity")
        raise_redacted(IngressError, "ingress:database-open")
    except (OSError, sqlite3.Error):
        if connection is not None:
            connection.close()
        raise_redacted(IngressError, "ingress:database-open")


def _is_capacity_error(exc: BaseException) -> bool:
    code = getattr(exc, "sqlite_errorcode", None)
    if code in {getattr(sqlite3, "SQLITE_FULL", 13), getattr(sqlite3, "SQLITE_TOOBIG", 18)}:
        return True
    text = str(exc).lower()
    return any(marker in text for marker in ("database or disk is full", "max_page_count", "too big", "page count"))


def _table_names(connection: sqlite3.Connection) -> tuple[str, ...]:
    return tuple(row[0] for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall())


def _columns(connection: sqlite3.Connection, table: str) -> tuple[str, ...]:
    return tuple(row[1] for row in connection.execute(
        "SELECT * FROM pragma_table_info(?) ORDER BY cid", (table,)
    ).fetchall())


def _index_names(connection: sqlite3.Connection) -> tuple[str, ...]:
    return tuple(row[0] for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='index' "
        "AND name NOT LIKE 'sqlite_autoindex_%' ORDER BY name"
    ).fetchall())


def _schema_matches(connection: sqlite3.Connection) -> bool:
    if _table_names(connection) != tuple(sorted(TABLES)):
        return False
    if any(_columns(connection, table) != columns for table, columns in independent.TABLE_COLUMNS.items()):
        return False
    try:
        return independent._index_definitions(connection) == independent.INDEX_DEFINITIONS
    except (independent.IngressVerificationError, sqlite3.Error, TypeError, ValueError):
        return False


def _is_uninitialized_database(path: Path) -> bool:
    connection: sqlite3.Connection | None = None
    try:
        connection = independent._open(path)
        return connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' LIMIT 1"
        ).fetchone() is None
    except (independent.IngressVerificationError, OSError, sqlite3.Error, TypeError, ValueError):
        return False
    finally:
        if connection is not None:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            connection.close()


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
        source_id TEXT,
        page_index INTEGER,
        transport_attempt INTEGER,
        receipt_bytes BLOB,
        FOREIGN KEY(slot_id) REFERENCES ingress_slots(slot_id)
    )""",
    "CREATE INDEX ingress_slots_due_idx ON ingress_slots(state,lease_until,slot_id)",
    "CREATE UNIQUE INDEX ingress_events_chain_idx ON ingress_events(chain_id,sequence)",
    "CREATE INDEX ingress_events_operation_idx ON ingress_events(operation_id,event_kind)",
    "CREATE INDEX ingress_events_observed_at_idx ON ingress_events(observed_at,sequence)",
    "CREATE UNIQUE INDEX ingress_fetch_natural_key_idx ON ingress_events(source_id,slot_id,page_index,transport_attempt) WHERE event_kind='FETCH_ATTESTATION'",
)


def _init(path: Path, config: IngressConfigV2) -> None:
    existing = _path_identity(path, allow_missing=True)
    creating = existing is None or _is_uninitialized_database(path)
    if not creating:
        try:
            independent.verify_database(
                path,
                expected_database_id=config.database_id,
                expected_config_digest=config.digest,
            )
        except independent.IngressVerificationError:
            raise IngressError("ingress:database") from None
    connection = _connection(
        path,
        configure_cap=False,
        expected_identity=None if existing is None else (existing[0], existing[1]),
        create=existing is None,
    )
    try:
        current = _table_names(connection)
        if current and current != tuple(sorted(TABLES)):
            raise IngressError("ingress:legacy-schema")
        if not current:
            _configure_page_limit(connection)
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
        else:
            if not _schema_matches(connection):
                raise IngressError("ingress:legacy-schema")
            row = connection.execute("SELECT * FROM ingress_meta").fetchone()
            count = int(connection.execute("SELECT COUNT(*) FROM ingress_meta").fetchone()[0])
            if row is None or count != 1 or row["schema"] != SCHEMA or row["schema_version"] != SCHEMA_VERSION or row["database_id"] != config.database_id or row["chain_id"] != config.chain_id or row["config_digest"] != config.digest:
                raise IngressError("ingress:identity")
            _configure_page_limit(connection)
    except IngressError:
        if connection.in_transaction:
            connection.rollback()
        raise
    except sqlite3.OperationalError as exc:
        if connection.in_transaction:
            connection.rollback()
        if _is_capacity_error(exc):
            raise_redacted(IngressError, "ingress:capacity")
        raise_redacted(IngressError, "ingress:database-initialize")
    except sqlite3.Error:
        if connection.in_transaction:
            connection.rollback()
        raise_redacted(IngressError, "ingress:database-initialize")
    finally:
        connection.close()


class IngressServiceV2:
    """Owns scheduling, raw envelope custody, fetch attestations, and quarantine state."""

    def __init__(
        self,
        path: str | Path,
        config: IngressConfigV2,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        if clock is not None and not callable(clock):
            raise IngressError("ingress:clock")
        self.path = Path(path)
        self.config = config
        self._clock = clock or _utc_epoch_seconds
        _init(self.path, config)
        before = _path_identity(self.path, allow_missing=False)
        if before is None:
            raise IngressError("ingress:database-open")
        try:
            independent.verify_database(
                self.path,
                expected_database_id=config.database_id,
                expected_config_digest=config.digest,
            )
        except independent.IngressVerificationError:
            raise IngressError("ingress:database") from None
        after = _path_identity(self.path, allow_missing=False)
        if after is None or (after[0], after[1]) != (before[0], before[1]):
            raise IngressError("ingress:database-open")
        self._database_identity = (before[0], before[1])

    def close(self) -> None:
        return None

    def _assert_database_identity(self) -> None:
        current = _path_identity(self.path, allow_missing=False)
        if current is None or (current[0], current[1]) != self._database_identity:
            raise IngressError("ingress:database-open")

    def _writer_connection(self) -> sqlite3.Connection:
        self._assert_database_identity()
        return _connection(self.path, expected_identity=self._database_identity)

    def verify(self, *, include_raw: bool = False) -> dict[str, object]:
        self._assert_database_identity()
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
        observed_at: int,
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
        if (
            type(receipt_bytes) is not bytes
            or not receipt_bytes
            or len(receipt_bytes) > MAX_EVENT_BYTES
        ) and receipt_bytes is not None:
            raise IngressConflictError("ingress:capacity")
        if type(payload_length) is not int or payload_length < 0 or payload_length > MAX_EVENT_BYTES:
            raise IngressConflictError("ingress:capacity")
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
            "observed_at": observed_at,
            "material": dict(material),
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
            observed_at=observed_at,
            material_digest=str(body["material_digest"]),
        )
        body["stream_after_root"] = independent._stream_root(
            sequence=sequence,
            previous=stream_before_root,
            event_id=str(body["event_id"]),
            stream_kind=stream_kind,
            stream_id=stream_id,
            next_state=next_state,
            observed_at=observed_at,
            material_digest=str(body["material_digest"]),
        )
        try:
            raw = _canonical(body)
        except (UnicodeDecodeError, AttributeError):
            raise IngressError("ingress:event")
        if len(raw) > MAX_EVENT_BYTES:
            raise IngressConflictError("ingress:capacity")
        receipt_digest = _raw_digest("receipt", raw)
        connection.execute(
            "INSERT INTO ingress_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                sequence, body["event_id"], kind, self.config.database_id,
                self.config.chain_id, body["stream_kind"], body["stream_id"], operation_id, request_digest, slot_id,
                prior_state, next_state, attempt, lease_token, lease_until, observed_at,
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
        try:
            value = independent._parse(raw, "ingress:receipt")
        except independent.IngressVerificationError:
            raise IngressError("ingress:receipt") from None
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

    def _owner_now(self) -> int:
        try:
            value = self._clock()
        except Exception:
            raise_redacted(IngressError, "ingress:clock")
        if type(value) is not int or value < 0:
            raise IngressError("ingress:clock")
        return value

    def _last_observed_at(self, connection: sqlite3.Connection) -> int | None:
        row = connection.execute(
            "SELECT observed_at FROM ingress_events ORDER BY observed_at DESC,sequence DESC LIMIT 1"
        ).fetchone()
        if row is None or row[0] is None:
            return None
        value = row[0]
        if type(value) is not int or value < 0:
            raise IngressError("ingress:event-time")
        return value

    def _page_snapshot(self, connection: sqlite3.Connection) -> tuple[int, int, int]:
        try:
            page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
            page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
            max_pages = int(connection.execute("PRAGMA max_page_count").fetchone()[0])
        except (sqlite3.Error, TypeError, ValueError):
            raise_redacted(IngressError, "ingress:capacity")
        if (
            page_size <= 0
            or page_count < 0
            or max_pages <= 0
            or page_count > max_pages
            or page_size * page_count > MAX_DATABASE_BYTES
            or page_size * max_pages > MAX_DATABASE_BYTES
        ):
            raise IngressError("ingress:capacity")
        return page_size, page_count, max_pages

    def _live_slot_count(self, connection: sqlite3.Connection) -> int:
        placeholders = ",".join("?" for _ in _LIVE_STATES)
        try:
            row = connection.execute(
                f"SELECT COUNT(*) FROM ingress_slots WHERE state IN ({placeholders})",
                _LIVE_STATES,
            ).fetchone()
            value = int(row[0]) if row is not None else -1
        except (sqlite3.Error, TypeError, ValueError):
            raise_redacted(IngressError, "ingress:capacity")
        if value < 0:
            raise IngressError("ingress:capacity")
        return value

    def _capacity_available(
        self,
        connection: sqlite3.Connection,
        *,
        event_count: int,
        raw_artifact_bytes: int,
        terminal_live_slots: int,
    ) -> bool:
        page_size, page_count, max_pages = self._page_snapshot(connection)
        if (
            type(event_count) is not int
            or event_count < 0
            or type(raw_artifact_bytes) is not int
            or not 0 <= raw_artifact_bytes <= MAX_COMPLETE_FRAME_BYTES
            or type(terminal_live_slots) is not int
            or terminal_live_slots < 0
        ):
            raise IngressError("ingress:capacity")
        event_bound = 2 * MAX_EVENT_BYTES + _SQLITE_PAGE_OVERHEAD_PAGES * page_size
        page_overhead = _SQLITE_PAGE_OVERHEAD_PAGES * page_size
        required_bytes = event_count * event_bound + raw_artifact_bytes + page_overhead
        reserve_bytes = max(TERMINAL_RESERVE_BYTES, event_bound)
        required_pages = (required_bytes + reserve_bytes * terminal_live_slots + page_size - 1) // page_size
        return page_count + required_pages <= max_pages

    def _capacity_hold_receipt(
        self,
        connection: sqlite3.Connection,
        *,
        slot: sqlite3.Row,
        artifact_id: str,
        operation_id: str,
        operation_value_digest: str | None,
        request_digest: str,
        lease_token: str,
        owner_now: int,
    ) -> IngressReceipt:
        receipt_bytes = _canonical({
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "kind": "CAPACITY_HOLD",
            "slot_id": str(slot["slot_id"]),
            "artifact_id": artifact_id,
            "reason": "CAPACITY",
        })
        material = {
            "slot_id": str(slot["slot_id"]),
            "artifact_id": artifact_id,
            "operation_id": operation_id,
            "decision": "HELD",
            "reason": "CAPACITY",
        }
        if operation_value_digest is not None:
            material["operation_value_digest"] = operation_value_digest
        raw = self._append(
            connection,
            kind="HOLD",
            operation_id=operation_id,
            request_digest=request_digest,
            slot_id=str(slot["slot_id"]),
            prior_state="LEASED",
            next_state="HELD",
            attempt=int(slot["attempt"]),
            lease_token=lease_token,
            lease_until=int(slot["lease_until"]),
            observed_at=owner_now,
            material=material,
            payload_digest=artifact_id,
            payload_length=0,
            stream_kind="QUARANTINE",
            stream_id=self.config.chain_id,
            receipt_bytes=receipt_bytes,
        )
        connection.execute(
            "UPDATE ingress_slots SET state='HELD',lease_token=NULL,lease_until=NULL WHERE slot_id=?",
            (str(slot["slot_id"]),),
        )
        connection.commit()
        return self._receipt(raw, artifact_id=artifact_id, next_state="HELD")

    def _capacity_hold_after_full(
        self,
        connection: sqlite3.Connection,
        *,
        slot_id: str,
        artifact_id: str,
        operation_id: str,
        operation_value_digest: str | None,
        request_digest: str,
        attempt: int,
        lease_token_digest: str,
    ) -> IngressReceipt:
        try:
            connection.execute("BEGIN IMMEDIATE")
            slot = connection.execute(
                "SELECT * FROM ingress_slots WHERE slot_id=?", (slot_id,)
            ).fetchone()
            if (
                slot is None
                or slot["state"] != "LEASED"
                or slot["attempt"] != attempt
                or type(slot["lease_token"]) is not str
                or not hmac.compare_digest(slot["lease_token"], lease_token_digest)
                or type(slot["lease_until"]) is not int
            ):
                raise IngressConflictError("ingress:capacity")
            owner_now = self._owner_now()
            last_observed_at = self._last_observed_at(connection)
            if last_observed_at is not None and owner_now < last_observed_at:
                raise IngressConflictError("ingress:clock-rewind")
            if owner_now >= int(slot["lease_until"]):
                raise IngressConflictError("ingress:lease-expired")
            return self._capacity_hold_receipt(
                connection,
                slot=slot,
                artifact_id=artifact_id,
                operation_id=operation_id,
                operation_value_digest=operation_value_digest,
                request_digest=request_digest,
                lease_token=lease_token_digest,
                owner_now=owner_now,
            )
        except (IngressConflictError, IngressError):
            if connection.in_transaction:
                connection.rollback()
            raise
        except sqlite3.OperationalError as exc:
            if connection.in_transaction:
                connection.rollback()
            if _is_capacity_error(exc):
                raise_redacted(IngressConflictError, "ingress:capacity")
            raise_redacted(IngressError, "ingress:database")
        except sqlite3.Error:
            if connection.in_transaction:
                connection.rollback()
            raise_redacted(IngressError, "ingress:database")

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
        connection = self._writer_connection()
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
            live_slots = self._live_slot_count(connection)
            if not self._capacity_available(
                connection,
                event_count=1,
                raw_artifact_bytes=0,
                terminal_live_slots=live_slots + 1,
            ):
                raise IngressConflictError("ingress:capacity")
            owner_now = self._owner_now()
            last_observed_at = self._last_observed_at(connection)
            if last_observed_at is not None and owner_now < last_observed_at:
                raise IngressConflictError("ingress:clock-rewind")
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
                observed_at=owner_now,
                material={"slot_id": slot_id, "scheduled_at": scheduled_at, "operation_id": operation_id},
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
            if _is_capacity_error(exc):
                raise_redacted(IngressConflictError, "ingress:capacity")
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise_redacted(IngressBusyError, "ingress:busy")
            raise_redacted(IngressError, "ingress:database")
        except sqlite3.Error as exc:
            connection.rollback()
            if _is_capacity_error(exc):
                raise_redacted(IngressConflictError, "ingress:capacity")
            raise_redacted(IngressError, "ingress:database")
        finally:
            connection.close()

    def claim_slot(self, slot_id: str, *, lease_token: str) -> IngressReceipt:
        slot_id = _bounded_digest_string(slot_id, "ingress:lease")
        lease_token = _bounded_string(
            lease_token,
            "ingress:lease",
            min_bytes=_MIN_LEASE_TOKEN_BYTES,
            ascii_only=True,
        )
        connection = self._writer_connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM ingress_slots WHERE slot_id=?", (slot_id,)).fetchone()
            if row is None:
                raise IngressConflictError("ingress:slot-missing")
            owner_now = self._owner_now()
            last_observed_at = self._last_observed_at(connection)
            if last_observed_at is not None and owner_now < last_observed_at:
                raise IngressConflictError("ingress:clock-rewind")
            current_token_digest: str | None = None
            if row["state"] == "LEASED" and row["lease_until"] is not None:
                current_token_digest = _lease_token_digest(
                    self.config, slot_id, int(row["attempt"]), lease_token,
                )
                stored_token_digest = row["lease_token"]
                if (
                    type(stored_token_digest) is not str
                    or len(stored_token_digest) != 128
                    or any(character not in "0123456789abcdef" for character in stored_token_digest)
                ):
                    raise IngressConflictError("ingress:lease-token")
                expired = int(row["lease_until"]) <= owner_now
                if not expired:
                    if not hmac.compare_digest(stored_token_digest, current_token_digest):
                        raise IngressConflictError("ingress:lease-token")
                    event = connection.execute(
                        "SELECT event_raw FROM ingress_events WHERE slot_id=? AND event_kind='LEASE' AND attempt=? AND lease_token=? AND operation_id=? ORDER BY sequence DESC LIMIT 1",
                        (slot_id, int(row["attempt"]), stored_token_digest, row["operation_id"]),
                    ).fetchone()
                    if event is None:
                        raise IngressError("ingress:lease-receipt")
                    connection.commit()
                    return self._receipt(bytes(event[0]), artifact_id=row["artifact_id"], next_state="LEASED")
            live_slots = self._live_slot_count(connection)
            expired = row["state"] == "LEASED" and row["lease_until"] is not None and int(row["lease_until"]) <= owner_now
            if expired and int(row["attempt"]) >= self.config.max_attempts:
                required_events = 1
                terminal_live_slots = max(0, live_slots - 1)
            elif expired:
                required_events = 2
                terminal_live_slots = live_slots
            elif row["state"] == "DUE":
                required_events = 1
                terminal_live_slots = live_slots
            else:
                required_events = 0
                terminal_live_slots = live_slots
            if required_events and not self._capacity_available(
                connection,
                event_count=required_events,
                raw_artifact_bytes=0,
                terminal_live_slots=terminal_live_slots,
            ):
                raise IngressConflictError("ingress:capacity")
            if row["state"] == "LEASED" and row["lease_until"] is not None and row["lease_until"] <= owner_now:
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
                    observed_at=owner_now,
                    material={"slot_id": slot_id, "action": kind, "attempt": row["attempt"], "operation_id": row["operation_id"]},
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
            if row["state"] != "DUE" or row["scheduled_at"] > owner_now:
                raise IngressConflictError("ingress:lease-state")
            attempt = int(row["attempt"]) + 1
            if attempt > self.config.max_attempts:
                raise IngressConflictError("ingress:attempt-exhausted")
            lease_until = owner_now + self.config.lease_seconds
            token_digest = _lease_token_digest(self.config, slot_id, attempt, lease_token)
            request_digest = _digest("request", {"slot_id": slot_id, "action": "LEASE", "attempt": attempt})
            material = {"slot_id": slot_id, "attempt": attempt, "lease_token": token_digest, "lease_until": lease_until, "operation_id": row["operation_id"]}
            raw = self._append(
                connection, kind="LEASE", operation_id=str(row["operation_id"]),
                request_digest=request_digest, slot_id=slot_id, prior_state="DUE",
                next_state="LEASED", attempt=attempt, lease_token=token_digest,
                lease_until=lease_until, material=material,
                observed_at=owner_now,
                payload_digest=_digest("lease-payload", material), payload_length=0,
            )
            connection.execute(
                "UPDATE ingress_slots SET state='LEASED',attempt=?,lease_token=?,lease_until=? WHERE slot_id=?",
                (attempt, token_digest, lease_until, slot_id),
            )
            connection.commit()
            return self._receipt(raw, artifact_id=row["artifact_id"], next_state="LEASED")
        except (IngressConflictError, IngressError):
            connection.rollback()
            raise
        except sqlite3.OperationalError as exc:
            connection.rollback()
            if _is_capacity_error(exc):
                raise_redacted(IngressConflictError, "ingress:capacity")
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise_redacted(IngressBusyError, "ingress:busy")
            raise_redacted(IngressError, "ingress:database")
        except sqlite3.Error as exc:
            connection.rollback()
            if _is_capacity_error(exc):
                raise_redacted(IngressConflictError, "ingress:capacity")
            raise_redacted(IngressError, "ingress:database")
        finally:
            connection.close()

    def admit_capture(
        self,
        envelope_raw: bytes,
        *,
        evidence_raw: bytes,
        scheduled_at: int,
        attempt: int,
        lease_token: str,
        operation_id: str | None = None,
    ) -> IngressReceipt:
        operation_value = None
        if operation_id is not None:
            operation_value = _bounded_string(
                operation_id,
                "ingress:operation",
                max_bytes=_MAX_OPERATION_VALUE_BYTES,
            )
        lease_token = _bounded_string(
            lease_token,
            "ingress:envelope",
            min_bytes=_MIN_LEASE_TOKEN_BYTES,
            ascii_only=True,
        )
        if type(attempt) is not int or not 1 <= attempt <= self.config.max_attempts:
            raise IngressConflictError("ingress:attempt")
        raw_snapshot = envelope_raw if type(envelope_raw) is bytes else b""
        evidence_snapshot = evidence_raw if type(evidence_raw) is bytes else b""
        if (
            not raw_snapshot
            or len(raw_snapshot) > fhir.NC_MEDICAID_PROFILE.transport_caps["max_envelope_bytes"]
            or not evidence_snapshot
            or len(evidence_snapshot) > independent.MAX_EXTERNAL_ARTIFACT_BYTES
            or type(scheduled_at) is not int
        ):
            raise IngressError("ingress:envelope")
        try:
            result = fhir.verify_bytes(raw_snapshot)
        except Exception:
            raise_redacted(IngressError, "ingress:envelope-reject")
        try:
            external_result = external_independent.verify_artifact(
                evidence_snapshot,
                policy=self.config.external_policy().material(),
                capture_raw=raw_snapshot,
            )
        except Exception:
            raise_redacted(IngressError, "ingress:external-evidence-reject")
        context = result.get("capture_context")
        if not isinstance(context, Mapping):
            raise IngressConflictError("ingress:capture-context")
        if (
            external_result["derived_status"] not in external_independent.STATUSES
            or external_result["payload_sha3_512"] != external_independent._raw_digest(raw_snapshot)
            or external_result["observed_at"] != result["observation_time"]
            or external_result["fetched_at"] != result["fetched_at"]
            or external_result.get("transport_evidence_classification") != external_independent.TRANSPORT_EVIDENCE_CLASSIFICATION
            or tuple(result["page_digests"]) != tuple(digest for _index, digest in external_result["page_bindings"])
            or any(context.get(key) != external_result[key] for key in ("subject_id", "credential_id", "enrollment_id", "subject_locator_digest"))
        ):
            raise IngressConflictError("ingress:capture-binding")
        if result["observation_time"] != scheduled_at:
            raise IngressConflictError("ingress:observation-slot")
        frame = _pack_intake_frame(evidence_snapshot, raw_snapshot, tuple(result["page_digests"]))
        artifact_id = _digest(
            "artifact-id",
            {
                "intake_digest": _raw_digest("intake", frame),
                "envelope_digest": _raw_digest("envelope", raw_snapshot),
                "envelope_id": result["envelope_id"],
                "external_artifact_id": external_result["artifact_id"],
                "external_artifact_digest": independent._raw_digest("external-artifact", evidence_snapshot),
                "profile_digest": NC_MEDICAID_PROFILE.profile_digest,
                "observation_time": result["observation_time"],
                "snapshot_id": result["snapshot_id"],
            },
        )
        slot_id = _digest("slot-id", {"config_digest": self.config.digest, "scheduled_at": scheduled_at})
        operation_value_digest = None
        if operation_value is None:
            operation_id = _digest("capture-operation", {"slot_id": slot_id, "artifact_id": artifact_id})
        else:
            operation_value_digest = _digest(
                "caller-operation-value",
                {
                    "database_id": self.config.database_id,
                    "config_digest": self.config.digest,
                    "value": operation_value,
                },
            )
            operation_id = _digest(
                "caller-operation",
                {
                    "database_id": self.config.database_id,
                    "config_digest": self.config.digest,
                    "value_digest": operation_value_digest,
                },
            )
        request_digest = _digest("request", {"operation_id": operation_id, "slot_id": slot_id, "artifact_id": artifact_id})
        submitted_token_digest = _lease_token_digest(self.config, slot_id, attempt, lease_token)
        connection = self._writer_connection()
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
                capacity_hold = existing["event_kind"] == "HOLD" and existing["receipt_bytes"] is not None
                capture = connection.execute(
                    "SELECT * FROM ingress_events WHERE operation_id=? AND event_kind='CAPTURE' ORDER BY sequence DESC LIMIT 1",
                    (operation_id,),
                ).fetchone()
                lease = None
                if capture is not None:
                    lease = connection.execute(
                        "SELECT * FROM ingress_events WHERE slot_id=? AND event_kind='LEASE' AND attempt=? ORDER BY sequence DESC LIMIT 1",
                        (slot_id, capture["attempt"]),
                    ).fetchone()
                committed_attempt = int(existing["attempt"])
                if attempt != committed_attempt:
                    raise IngressConflictError("ingress:operation-conflict")
                if (
                    existing["slot_id"] != slot_id
                    or existing["operation_id"] != operation_id
                    or existing["request_digest"] != request_digest
                    or existing["payload_digest"] != artifact_id
                    or type(existing["lease_token"]) is not str
                    or not hmac.compare_digest(str(existing["lease_token"]), submitted_token_digest)
                    or (
                        not capacity_hold
                        and (
                            capture is None
                            or capture["slot_id"] != slot_id
                            or capture["operation_id"] != operation_id
                            or capture["request_digest"] != request_digest
                            or capture["payload_digest"] != artifact_id
                            or capture["lease_token"] != submitted_token_digest
                            or lease is None
                            or lease["lease_token"] != submitted_token_digest
                        )
                    )
                ):
                    raise IngressConflictError("ingress:operation-conflict")
                if capacity_hold:
                    receipt_raw = existing["receipt_bytes"]
                    if type(receipt_raw) is not bytes:
                        raise IngressConflictError("ingress:operation-conflict")
                    try:
                        independent._verify_capacity_hold_receipt(
                            receipt_raw,
                            slot_id=slot_id,
                            artifact_id=artifact_id,
                        )
                    except independent.IngressVerificationError:
                        raise IngressConflictError("ingress:operation-conflict") from None
                connection.commit()
                return self._receipt(bytes(existing["event_raw"]), artifact_id=artifact_id, next_state=str(existing["next_state"]))
            owner_now = self._owner_now()
            last_observed_at = self._last_observed_at(connection)
            if last_observed_at is not None and owner_now < last_observed_at:
                raise IngressConflictError("ingress:clock-rewind")
            if owner_now < scheduled_at:
                raise IngressConflictError("ingress:lease-state")
            if slot["state"] != "LEASED":
                raise IngressConflictError("ingress:slot-state")
            if type(slot["lease_token"]) is not str:
                raise IngressConflictError("ingress:lease-token")
            if attempt != int(slot["attempt"]):
                raise IngressConflictError("ingress:attempt")
            token_digest = submitted_token_digest
            if not hmac.compare_digest(str(slot["lease_token"]), token_digest):
                raise IngressConflictError("ingress:lease-token")
            if slot["lease_until"] is None:
                raise IngressConflictError("ingress:lease-state")
            if owner_now >= int(slot["lease_until"]):
                raise IngressConflictError("ingress:lease-expired")
            if int(slot["attempt"]) < 1 or int(slot["attempt"]) > self.config.max_attempts:
                raise IngressConflictError("ingress:attempt-exhausted")
            page_evidence = result.get("page_evidence")
            if not isinstance(page_evidence, tuple):
                raise IngressError("ingress:envelope-evidence")
            attestation_receipts: list[tuple[dict[str, object], bytes]] = []
            for page in page_evidence:
                attempts = page.get("attempts") if isinstance(page, Mapping) else None
                if not isinstance(attempts, tuple):
                    raise IngressError("ingress:envelope-evidence")
                for attempt_record in attempts:
                    if not isinstance(attempt_record, Mapping):
                        raise IngressError("ingress:envelope-evidence")
                    material = {
                        "artifact_id": artifact_id,
                        "page_index": int(page["page_index"]),
                        "lease_attempt": int(slot["attempt"]),
                        "transport_attempt": int(attempt_record["transport_attempt"]),
                        "request_identity": page["request_identity"],
                        "response_digest": attempt_record["response_digest"],
                        "status": attempt_record["status"],
                        "retry_after_seconds": attempt_record["retry_after_seconds"],
                        "response_url": attempt_record["response_url"],
                        "redirect": attempt_record["redirect"],
                        "failure_code": attempt_record["failure_code"],
                        "transport_error": attempt_record["transport_error"],
                        "evidence_class": "SYNTHETIC_FIXTURE_UNAUTHENTICATED",
                        "selected": attempt_record["selected"],
                        "observed_at": owner_now,
                    }
                    material["attestation_digest"] = independent._attestation_digest(material)
                    receipt = {
                        "schema": SCHEMA,
                        "schema_version": SCHEMA_VERSION,
                        **material,
                        "source_id": NC_MEDICAID_PROFILE.source_profile_id,
                        "slot_id": slot_id,
                    }
                    attestation_receipts.append((material, _canonical(receipt)))
            complete = (
                result["source_status"] == "COMPLETE"
                and result["page_complete"] is True
                and result["freshness"] == "FRESH"
                and result["failure_code"] is None
                and external_result["derived_status"] == "OBSERVATION_ADMITTED"
                and external_result["complete"] is True
                and external_result["failure_code"] == "NONE"
            )
            if not self._capacity_available(
                connection,
                event_count=len(attestation_receipts) + (3 if complete else 2),
                raw_artifact_bytes=MAX_COMPLETE_FRAME_BYTES,
                terminal_live_slots=self._live_slot_count(connection),
            ):
                return self._capacity_hold_receipt(
                    connection,
                    slot=slot,
                    artifact_id=artifact_id,
                    operation_id=str(operation_id),
                    operation_value_digest=operation_value_digest,
                    request_digest=request_digest,
                    lease_token=token_digest,
                    owner_now=owner_now,
                )
            row = connection.execute("SELECT * FROM ingress_artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()
            if row is not None and bytes(row["raw"]) != frame:
                raise IngressConflictError("ingress:artifact-conflict")
            if row is None:
                connection.execute(
                    "INSERT INTO ingress_artifacts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        artifact_id, result["envelope_id"], _raw_digest("envelope", raw_snapshot),
                        frame, NC_MEDICAID_PROFILE.source_profile_id, NC_MEDICAID_PROFILE.version,
                        NC_MEDICAID_PROFILE.profile_digest, result["observation_time"], result["fetched_at"],
                        result["source_status"], result["failure_code"], result["freshness"],
                        1 if result["page_complete"] else 0, result["snapshot_id"], result["snapshot_root"],
                        independent.content_root(result["resources"]), result["page_count"],
                        result["resource_count"], 0,
                    ),
                )
            for material, receipt_raw in attestation_receipts:
                fetch_operation = _digest(
                    "fetch-operation",
                    {"operation_id": operation_id, "page_index": material["page_index"], "transport_attempt": material["transport_attempt"]},
                )
                event_material = dict(material)
                event_material.pop("attestation_digest", None)
                event_material["capture_operation_id"] = operation_id
                self._append(
                    connection,
                    kind="FETCH_ATTESTATION",
                    operation_id=fetch_operation,
                    request_digest=str(material["request_identity"]),
                    slot_id=slot_id,
                    prior_state=str(slot["state"]),
                    next_state=str(slot["state"]),
                    attempt=int(slot["attempt"]),
                    lease_token=token_digest,
                    lease_until=slot["lease_until"],
                    observed_at=owner_now,
                    material=event_material,
                    payload_digest=_digest("fetch-payload", event_material),
                    payload_length=len(receipt_raw),
                    stream_kind="FETCH",
                    stream_id=slot_id,
                    source_id=str(receipt["source_id"]),
                    page_index=int(material["page_index"]),
                    transport_attempt=int(material["transport_attempt"]),
                    receipt_bytes=receipt_raw,
                    head_artifact_id=artifact_id,
                )
            capture_material = {
                "artifact_id": artifact_id,
                "envelope_digest": _raw_digest("envelope", raw_snapshot),
                "intake_digest": _raw_digest("intake", frame),
                "external_artifact_id": external_result["artifact_id"],
                "external_artifact_digest": independent._raw_digest("external-artifact", evidence_snapshot),
                "source_contract_digest": external_result["source_contract_digest"],
                "capture_id": external_result["capture_id"],
                "capture_context": {
                    "subject_id": external_result["subject_id"],
                    "credential_id": external_result["credential_id"],
                    "enrollment_id": external_result["enrollment_id"],
                    "subject_locator_digest": external_result["subject_locator_digest"],
                    "observed_at": external_result["observed_at"],
                    "fetched_at": external_result["fetched_at"],
                },
                "page_bindings": [list(item) for item in external_result["page_bindings"]],
                "slot_id": slot_id,
                "lease_token_digest": token_digest,
                "operation_id": operation_id,
            }
            if operation_value_digest is not None:
                capture_material["operation_value_digest"] = operation_value_digest
            capture_raw = self._append(
                connection, kind="CAPTURE", operation_id=operation_id,
                request_digest=request_digest, slot_id=slot_id,
                prior_state=str(slot["state"]), next_state="CAPTURED",
                attempt=int(slot["attempt"]), lease_token=token_digest,
                lease_until=slot["lease_until"], material=capture_material,
                observed_at=owner_now,
                payload_digest=artifact_id, payload_length=len(frame),
                 head_artifact_id=artifact_id,
            )
            if complete:
                self._append(
                    connection, kind="BEGIN_QUARANTINE", operation_id=operation_id,
                    request_digest=request_digest, slot_id=slot_id,
                    prior_state="CAPTURED", next_state="QUARANTINE_PENDING",
                    attempt=int(slot["attempt"]), lease_token=token_digest,
                    lease_until=slot["lease_until"], material={"artifact_id": artifact_id, "decision": "QUARANTINE_PENDING", "operation_id": operation_id},
                    observed_at=owner_now,
                    payload_digest=artifact_id, payload_length=len(frame),
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
                attempt=int(slot["attempt"]), lease_token=token_digest,
                lease_until=slot["lease_until"], material={"artifact_id": artifact_id, "decision": next_state, "operation_id": operation_id},
                observed_at=owner_now,
                payload_digest=artifact_id, payload_length=len(frame),
                 stream_kind="QUARANTINE", stream_id=self.config.chain_id,
                 head_artifact_id=artifact_id,
            )
            sequence = int(json.loads(final_raw.decode("ascii"))["sequence"])
            connection.execute(
                "UPDATE ingress_artifacts SET event_sequence=? WHERE artifact_id=?",
                (sequence, artifact_id),
            )
            connection.execute(
                "UPDATE ingress_slots SET state=?,artifact_id=?,lease_token=NULL,lease_until=NULL WHERE slot_id=?",
                (next_state, artifact_id, slot_id),
            )
            connection.commit()
            return self._receipt(final_raw, artifact_id=artifact_id, next_state=next_state)
        except (IngressConflictError, IngressError):
            connection.rollback()
            raise
        except sqlite3.OperationalError as exc:
            connection.rollback()
            if _is_capacity_error(exc):
                return self._capacity_hold_after_full(
                    connection,
                    slot_id=slot_id,
                    artifact_id=artifact_id,
                    operation_id=operation_id,
                    operation_value_digest=operation_value_digest,
                    request_digest=request_digest,
                    attempt=attempt,
                    lease_token_digest=submitted_token_digest,
                )
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise_redacted(IngressBusyError, "ingress:busy")
            raise_redacted(IngressError, "ingress:database")
        except sqlite3.Error as exc:
            connection.rollback()
            if _is_capacity_error(exc):
                return self._capacity_hold_after_full(
                    connection,
                    slot_id=slot_id,
                    artifact_id=artifact_id,
                    operation_id=operation_id,
                    operation_value_digest=operation_value_digest,
                    request_digest=request_digest,
                    attempt=attempt,
                    lease_token_digest=submitted_token_digest,
                )
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
    "MAX_IDENTIFIER_BYTES",
]
