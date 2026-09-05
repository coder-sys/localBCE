"""Three-table, catalog-only recovery owner for the Mirror V2 stores.

The catalog owns only bounded identities, event-derived lifecycle state, and
opaque recovery receipts.  Component images exist only in bounded process
memory, fresh restore targets, and opaque storage/custody ports.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from functools import wraps
import json
import os
from pathlib import Path
import sqlite3
import stat
from typing import Mapping, Protocol

from app.mirror import core_v2_independent as core
from app.mirror import ingress_v2_independent as ingress
from app.mirror import recovery_v2_independent as independent
from app.mirror import restore_publication
from app.mirror.error_boundary import raise_redacted
from app.mirror import writer_authority


SCHEMA = independent.SCHEMA
SCHEMA_VERSION = independent.SCHEMA_VERSION
TABLES = ("recovery_meta", "recovery_points", "recovery_events")
FIXED_FLAGS = dict(independent.FIXED_FLAGS)
MAX_DATABASE_BYTES = independent.MAX_DATABASE_BYTES
MAX_EVENT_BYTES = independent.MAX_EVENT_BYTES
MAX_CUSTODY_OVERHEAD_BYTES = independent.MAX_CUSTODY_OVERHEAD_BYTES
MAX_RECOVERY_POINTS = independent.MAX_RECOVERY_POINTS


class RecoveryError(ValueError):
    """Fixed public recovery failure."""


class RecoveryConflictError(RecoveryError):
    """A stale, conflicting, or no-clobber request."""


class RecoveryIndeterminateError(RecoveryError):
    """An external storage/custody result was not safely knowable."""


def _mutation(method):
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        with self._authority.mutation_scope(self.path):
            return method(self, *args, **kwargs)
    return wrapped


class StorageNotFound(LookupError):
    """The only storage read result that permits a create attempt."""


@dataclass(frozen=True)
class RecoveryKey:
    key_id: str
    key_epoch: int
    state: str


@dataclass(frozen=True)
class StorageReceipt:
    storage_id: str
    object_id: str
    result: str
    byte_length: int
    sealed_digest: str
    key_id: str
    key_epoch: int


class KeyCustodyPort(Protocol):
    custody_id: str

    def current_key(self) -> RecoveryKey: ...
    def state(self, key_id: str, key_epoch: int) -> str: ...
    def seal(self, plaintext: bytes, key_id: str, key_epoch: int) -> bytes: ...
    def open(self, sealed: bytes, key_id: str, key_epoch: int) -> bytes: ...


class RecoveryStoragePort(Protocol):
    storage_id: str

    def get(self, object_id: str) -> bytes: ...
    def put_if_absent(self, object_id: str, sealed: bytes, *, key_id: str, key_epoch: int) -> StorageReceipt: ...


@dataclass(frozen=True)
class RecoveryConfigV2:
    database_id: str
    chain_id: str
    profile_digest: str
    custody_id: str
    storage_id: str
    ingress_database_id: str
    core_database_id: str
    ingress_config_digest: str
    core_config_digest: str
    max_bundle_bytes: int = 16 * 1024 * 1024

    def __post_init__(self) -> None:
        if any(type(value) is not str or not value or len(value) > 256 for value in (self.database_id, self.chain_id, self.custody_id, self.storage_id, self.ingress_database_id, self.core_database_id)):
            raise RecoveryError("recovery:config")
        for value in (self.profile_digest, self.ingress_config_digest, self.core_config_digest):
            if type(value) is not str or len(value) != 128 or any(char not in "0123456789abcdef" for char in value):
                raise RecoveryError("recovery:config")
        if type(self.max_bundle_bytes) is not int or not 1024 <= self.max_bundle_bytes <= independent.MAX_BUNDLE_BYTES:
            raise RecoveryError("recovery:config")

    def material(self) -> dict[str, object]:
        return {
            "schema": SCHEMA, "schema_version": SCHEMA_VERSION,
            "database_id": self.database_id, "chain_id": self.chain_id,
            "profile_digest": self.profile_digest, "custody_id": self.custody_id,
            "storage_id": self.storage_id, "ingress_database_id": self.ingress_database_id,
            "core_database_id": self.core_database_id,
            "ingress_config_digest": self.ingress_config_digest,
            "core_config_digest": self.core_config_digest,
            "max_bundle_bytes": self.max_bundle_bytes, "flags": dict(FIXED_FLAGS),
        }

    @property
    def digest(self) -> str:
        return independent._digest("config", self.material())


@dataclass(frozen=True)
class RecoveryReceipt:
    raw: bytes
    point_id: str
    operation_id: str
    event_id: str
    state: str
    sequence: int
    after_root: str


def _canonical(value: object) -> bytes:
    return independent._canonical(value)


def _digest(label: str, value: object) -> str:
    return independent._digest(label, value)


def _raw_digest(label: str, raw: bytes) -> str:
    return independent._raw_digest(label, raw)


def _capacity() -> None:
    raise_redacted(RecoveryError, "recovery:capacity")


def _sqlite_is_capacity(error: sqlite3.Error) -> bool:
    return getattr(error, "sqlite_errorname", "") in {"SQLITE_FULL", "SQLITE_TOOBIG"}


def _safe_regular(info: os.stat_result) -> bool:
    reparse = getattr(info, "st_file_attributes", 0) & 0x400
    return stat.S_ISREG(info.st_mode) and getattr(info, "st_nlink", 1) == 1 and not reparse


def _has_sidecar(path: Path) -> bool:
    return any(os.path.lexists(os.fspath(path) + suffix) for suffix in ("-wal", "-shm", "-journal"))


if os.name == "nt":
    import ctypes
    import msvcrt
    from ctypes import wintypes

    _WIN_KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _WIN_GENERIC_READ = 0x80000000
    _WIN_FILE_SHARE_READ = 0x00000001
    _WIN_FILE_SHARE_WRITE = 0x00000002
    _WIN_OPEN_EXISTING = 3
    _WIN_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _WIN_FILE_ATTRIBUTE_NORMAL = 0x00000080
    _WIN_INVALID_HANDLE = ctypes.c_void_p(-1).value
    _WIN_CreateFileW = _WIN_KERNEL32.CreateFileW
    _WIN_CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    _WIN_CreateFileW.restype = wintypes.HANDLE
    _WIN_CloseHandle = _WIN_KERNEL32.CloseHandle
    _WIN_CloseHandle.argtypes = (wintypes.HANDLE,)
    _WIN_CloseHandle.restype = wintypes.BOOL

    def _win_readonly_nofollow(path: Path) -> int:
        handle = _WIN_CreateFileW(
            str(path),
            _WIN_GENERIC_READ,
            _WIN_FILE_SHARE_READ | _WIN_FILE_SHARE_WRITE,
            None,
            _WIN_OPEN_EXISTING,
            _WIN_FILE_FLAG_OPEN_REPARSE_POINT | _WIN_FILE_ATTRIBUTE_NORMAL,
            None,
        )
        value = ctypes.cast(handle, ctypes.c_void_p).value
        if value in {None, _WIN_INVALID_HANDLE}:
            raise OSError(ctypes.get_last_error(), "CreateFileW")
        try:
            return msvcrt.open_osfhandle(value, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        except Exception:
            _WIN_CloseHandle(handle)
            raise


def _path_identity(path: Path, *, allow_missing: bool, allow_journal: bool = False) -> tuple[int, int, int] | None:
    try:
        parent = os.lstat(path.parent)
        if not stat.S_ISDIR(parent.st_mode) or getattr(parent, "st_file_attributes", 0) & 0x400:
            raise RecoveryError("recovery:database-open")
        if not allow_journal and _has_sidecar(path):
            raise RecoveryError("recovery:database-open")
        info = os.lstat(path)
    except FileNotFoundError:
        if allow_missing:
            return None
        raise RecoveryError("recovery:database-open") from None
    except RecoveryError:
        raise
    except OSError:
        raise_redacted(RecoveryError, "recovery:database-open")
    if not _safe_regular(info):
        raise RecoveryError("recovery:database-open")
    if info.st_size > MAX_DATABASE_BYTES:
        _capacity()
    return int(info.st_dev), int(info.st_ino), int(info.st_nlink)


def _connection(path: Path, *, expected_identity: tuple[int, int, int] | None = None, create: bool | None = None) -> sqlite3.Connection:
    before = _path_identity(path, allow_missing=True)
    if create is None:
        create = before is None
    if create and before is not None:
        raise RecoveryError("recovery:database-open")
    if not create and before is None:
        raise RecoveryError("recovery:database-open")
    if expected_identity is not None and before != expected_identity:
        raise RecoveryError("recovery:database-open")
    connection: sqlite3.Connection | None = None
    try:
        if create:
            connection = sqlite3.connect(path, timeout=0.25, isolation_level=None)
        else:
            connection = sqlite3.connect(path.absolute().as_uri() + "?mode=rw", uri=True, timeout=0.25, isolation_level=None)
        after_connect = _path_identity(path, allow_missing=False)
        if after_connect is None or (expected_identity is not None and after_connect != expected_identity) or (before is not None and after_connect != before):
            raise RecoveryError("recovery:database-open")
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=250")
        connection.execute("PRAGMA page_size=4096")
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        if page_size <= 0:
            _capacity()
        page_limit = MAX_DATABASE_BYTES // page_size
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        if page_count * page_size > MAX_DATABASE_BYTES:
            _capacity()
        configured = int(connection.execute(f"PRAGMA max_page_count={page_limit}").fetchone()[0])
        if configured != page_limit:
            _capacity()
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        after_setup = _path_identity(path, allow_missing=False)
        if after_setup != after_connect or (expected_identity is not None and after_setup != expected_identity):
            raise RecoveryError("recovery:database-open")
        return connection
    except RecoveryError as error:
        if connection is None:
            raise
        _finish_initialization_transaction(connection, commit=False, error=error)
    except sqlite3.Error as error:
        mapped = RecoveryError("recovery:capacity" if _sqlite_is_capacity(error) else "recovery:database-open")
        if connection is None:
            raise_redacted(type(mapped), str(mapped))
        _finish_initialization_transaction(connection, commit=False, error=mapped)
    except (OSError, TypeError, ValueError) as error:
        mapped = RecoveryError("recovery:database-open")
        if connection is None:
            raise_redacted(type(mapped), str(mapped))
        _finish_initialization_transaction(connection, commit=False, error=mapped)


def _finish_initialization_transaction(connection: sqlite3.Connection, *, commit: bool, error: BaseException | None = None) -> None:
    if commit:
        if error is not None:
            _finish_initialization_transaction(connection, commit=False, error=error)
        try:
            connection.commit()
        except BaseException:
            try:
                connection.close()
            except BaseException:
                pass
            raise_redacted(RecoveryIndeterminateError, "recovery:transaction-indeterminate")
        try:
            connection.close()
        except BaseException:
            raise_redacted(RecoveryIndeterminateError, "recovery:transaction-indeterminate")
        return

    rollback_failed = False
    try:
        connection.rollback()
    except BaseException:
        rollback_failed = True
    try:
        connection.close()
    except BaseException:
        raise_redacted(RecoveryIndeterminateError, "recovery:transaction-indeterminate")
    if rollback_failed:
        raise_redacted(RecoveryIndeterminateError, "recovery:transaction-indeterminate")
    if error is None:
        return
    raise_redacted(type(error), str(error))


def _init(path: Path, config: RecoveryConfigV2) -> None:
    existing_identity = _path_identity(path, allow_missing=True)
    connection = _connection(path)
    try:
        opened_identity = _path_identity(path, allow_missing=False)
    except RecoveryError as error:
        _finish_initialization_transaction(connection, commit=False, error=error)
    except Exception:
        _finish_initialization_transaction(connection, commit=False, error=RecoveryError("recovery:database-open"))
    if opened_identity is None or (existing_identity is not None and opened_identity != existing_identity):
        _finish_initialization_transaction(connection, commit=False, error=RecoveryError("recovery:database-open"))
    created = False
    try:
        existing = tuple(row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall())
        if existing and existing != tuple(sorted(TABLES)):
            raise RecoveryError("recovery:legacy-schema")
        if not existing:
            created = True
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("""
                CREATE TABLE recovery_meta(
                    meta_id INTEGER PRIMARY KEY CHECK(meta_id=1), schema TEXT NOT NULL,
                    schema_version INTEGER NOT NULL, database_id TEXT NOT NULL,
                    chain_id TEXT NOT NULL, config_digest TEXT NOT NULL,
                    sequence INTEGER NOT NULL, head_root TEXT NOT NULL,
                    profile_digest TEXT NOT NULL, key_custody_id_digest TEXT NOT NULL,
                    storage_id_digest TEXT NOT NULL, ingress_database_id TEXT NOT NULL,
                    core_database_id TEXT NOT NULL, current_generation INTEGER NOT NULL
                )
            """)
            connection.execute("""
                CREATE TABLE recovery_points(
                    point_id TEXT PRIMARY KEY, generation INTEGER NOT NULL UNIQUE,
                    state TEXT NOT NULL, object_id TEXT NOT NULL UNIQUE,
                    bundle_digest TEXT NOT NULL, bundle_length INTEGER NOT NULL,
                    ingress_database_id TEXT NOT NULL, ingress_config_digest TEXT NOT NULL,
                    ingress_head_root TEXT NOT NULL, ingress_watermark INTEGER NOT NULL,
                    core_database_id TEXT NOT NULL, core_config_digest TEXT NOT NULL,
                    core_head_root TEXT NOT NULL, core_watermark INTEGER NOT NULL,
                    key_id TEXT NOT NULL, key_epoch INTEGER NOT NULL, key_state TEXT NOT NULL,
                    storage_id TEXT NOT NULL, prior_point_id TEXT, prior_root TEXT NOT NULL,
                    operation_id TEXT NOT NULL UNIQUE, request_digest TEXT NOT NULL,
                    sequence INTEGER NOT NULL, updated_sequence INTEGER NOT NULL
                )
            """)
            connection.execute("""
                CREATE TABLE recovery_events(
                    sequence INTEGER PRIMARY KEY, event_id TEXT NOT NULL UNIQUE,
                    event_kind TEXT NOT NULL, database_id TEXT NOT NULL,
                    chain_id TEXT NOT NULL, stream_kind TEXT NOT NULL,
                    stream_id TEXT NOT NULL, point_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL, request_digest TEXT NOT NULL,
                    prior_state TEXT NOT NULL, next_state TEXT NOT NULL,
                    attempt INTEGER NOT NULL, before_root TEXT NOT NULL,
                    after_root TEXT NOT NULL, material_digest TEXT NOT NULL,
                    payload_digest TEXT NOT NULL, payload_length INTEGER NOT NULL,
                    event_raw BLOB NOT NULL, receipt_digest TEXT NOT NULL,
                    FOREIGN KEY(point_id) REFERENCES recovery_points(point_id)
                )
            """)
            connection.execute("CREATE INDEX recovery_points_state_idx ON recovery_points(state,generation)")
            connection.execute("CREATE UNIQUE INDEX recovery_events_chain_idx ON recovery_events(chain_id,sequence)")
            connection.execute("CREATE INDEX recovery_events_operation_idx ON recovery_events(operation_id,event_kind)")
            connection.execute(
                "INSERT INTO recovery_meta VALUES(1,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (SCHEMA, SCHEMA_VERSION, config.database_id, config.chain_id, config.digest, 0, independent.GENESIS_ROOT, config.profile_digest, _digest("custody-id", config.custody_id), _digest("storage-id", config.storage_id), config.ingress_database_id, config.core_database_id, 0),
            )
        else:
            row = connection.execute("SELECT * FROM recovery_meta WHERE meta_id=1").fetchone()
            if row is None or row["database_id"] != config.database_id or row["chain_id"] != config.chain_id or row["config_digest"] != config.digest or row["profile_digest"] != config.profile_digest or row["key_custody_id_digest"] != _digest("custody-id", config.custody_id) or row["storage_id_digest"] != _digest("storage-id", config.storage_id) or row["ingress_database_id"] != config.ingress_database_id or row["core_database_id"] != config.core_database_id:
                raise RecoveryError("recovery:identity")
    except RecoveryError as error:
        _finish_initialization_transaction(connection, commit=False, error=error)
    except sqlite3.Error as error:
        mapped = RecoveryError("recovery:capacity" if _sqlite_is_capacity(error) else "recovery:database-initialize")
        _finish_initialization_transaction(connection, commit=False, error=mapped)
    except Exception:
        _finish_initialization_transaction(connection, commit=False, error=RecoveryError("recovery:database-initialize"))
    else:
        _finish_initialization_transaction(connection, commit=created)
    if not created:
        try:
            independent.verify_database(path, expected_database_id=config.database_id, expected_config_digest=config.digest)
        except independent.RecoveryVerificationError:
            raise RecoveryError("recovery:existing-invalid") from None


def _same_identity(first: os.stat_result, second: os.stat_result) -> bool:
    return (first.st_dev, first.st_ino, first.st_size, getattr(first, "st_nlink", 1)) == (second.st_dev, second.st_ino, second.st_size, getattr(second, "st_nlink", 1))


def _bounded_image(path: Path, cap: int, label: str) -> bytes:
    descriptor: int | None = None
    try:
        if _has_sidecar(path):
            raise RecoveryError("recovery:sidecar")
        before = os.lstat(path)
        if not _safe_regular(before) or before.st_size > cap:
            raise RecoveryError(label)
        if os.name == "nt":
            descriptor = _win_readonly_nofollow(path)
        else:
            nofollow = getattr(os, "O_NOFOLLOW", None)
            if nofollow is None:
                raise RecoveryError(label)
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | nofollow
            descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not _safe_regular(opened) or not _same_identity(before, opened):
            raise RecoveryError(label)
        data = bytearray()
        while len(data) <= cap:
            chunk = os.read(descriptor, cap + 1 - len(data))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > cap:
                raise RecoveryError(label)
        after = os.fstat(descriptor)
        if not _safe_regular(after) or not _same_identity(opened, after) or len(data) != after.st_size:
            raise RecoveryError(label)
        os.close(descriptor)
        descriptor = None
        final = os.lstat(path)
        if not _safe_regular(final) or not _same_identity(before, final) or _has_sidecar(path):
            raise RecoveryError(label)
        return bytes(data)
    except RecoveryError:
        raise
    except (OSError, ValueError, TypeError):
        raise_redacted(RecoveryError, label)
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


class RecoveryServiceV2:
    def __init__(
        self,
        path: str | Path,
        config: RecoveryConfigV2,
        custody: KeyCustodyPort,
        storage: RecoveryStoragePort,
        *,
        authority: writer_authority.WriterAuthority,
    ) -> None:
        if type(config) is not RecoveryConfigV2:
            raise RecoveryError("recovery:config")
        if not isinstance(authority, writer_authority.WriterAuthority):
            raise RecoveryError("recovery:writer")
        self.path = Path(path)
        self.config = config
        self._authority = authority
        authority.assert_database_parent(self.path)
        self.custody = custody
        self.storage = storage
        self._assert_port_identity()
        with authority.mutation_scope(self.path):
            _init(self.path, config)
        identity = _path_identity(self.path, allow_missing=False)
        if identity is None:
            raise RecoveryError("recovery:database-open")
        self._database_identity = identity
        self._assert_database_identity()

    def _assert_database_identity(self, *, allow_journal: bool = False) -> None:
        self._authority.assert_database_parent(self.path)
        current = _path_identity(self.path, allow_missing=False, allow_journal=allow_journal)
        if current is None or current != self._database_identity:
            raise RecoveryError("recovery:database-open")

    def _assert_port_identity(self) -> None:
        try:
            custody_id = getattr(self.custody, "custody_id")
            storage_id = getattr(self.storage, "storage_id")
        except Exception:
            raise RecoveryError("recovery:port-identity") from None
        if type(custody_id) is not str or custody_id != self.config.custody_id or type(storage_id) is not str or storage_id != self.config.storage_id:
            raise RecoveryError("recovery:port-identity")

    def _open(self) -> sqlite3.Connection:
        self._assert_database_identity()
        connection = _connection(self.path, expected_identity=self._database_identity)
        try:
            self._assert_database_identity()
        except Exception:
            try:
                connection.close()
            except BaseException:
                raise_redacted(RecoveryIndeterminateError, "recovery:transaction-indeterminate")
            raise
        return connection

    def _begin(self, connection: sqlite3.Connection) -> None:
        self._assert_database_identity()
        try:
            connection.execute("BEGIN IMMEDIATE")
        except Exception:
            self._assert_database_identity(allow_journal=True)
            raise
        self._assert_database_identity(allow_journal=True)

    def _commit(self, connection: sqlite3.Connection) -> None:
        connection.commit()

    def _close(self, connection: sqlite3.Connection) -> None:
        failure: BaseException | None = None
        try:
            connection.close()
        except BaseException as error:
            failure = error
        try:
            self._assert_database_identity()
        except BaseException as error:
            if failure is None:
                failure = error
        if failure is not None:
            raise_redacted(RecoveryIndeterminateError, "recovery:transaction-indeterminate")

    def _finish_transaction(self, connection: sqlite3.Connection, *, commit: bool = True, error: BaseException | None = None) -> None:
        """Finalize one service mutation without exposing transaction uncertainty."""
        if commit:
            if error is not None:
                self._finish_transaction(connection, commit=False, error=error)
            try:
                self._assert_database_identity(allow_journal=True)
            except RecoveryError as precommit_error:
                self._finish_transaction(connection, commit=False, error=precommit_error)
            except BaseException:
                self._finish_transaction(connection, commit=False, error=RecoveryError("recovery:database"))
            try:
                self._commit(connection)
            except BaseException:
                try:
                    self._close(connection)
                except BaseException:
                    pass
                raise_redacted(RecoveryIndeterminateError, "recovery:transaction-indeterminate")
            try:
                self._assert_database_identity(allow_journal=True)
            except BaseException:
                try:
                    self._close(connection)
                except BaseException:
                    pass
                raise_redacted(RecoveryIndeterminateError, "recovery:transaction-indeterminate")
            try:
                self._close(connection)
            except BaseException:
                raise_redacted(RecoveryIndeterminateError, "recovery:transaction-indeterminate")
            return

        rollback_failed = False
        try:
            connection.rollback()
        except BaseException:
            rollback_failed = True
        try:
            self._close(connection)
        except BaseException:
            raise_redacted(RecoveryIndeterminateError, "recovery:transaction-indeterminate")
        if rollback_failed:
            raise_redacted(RecoveryIndeterminateError, "recovery:transaction-indeterminate")
        if error is None:
            return
        error.__cause__ = None
        error.__context__ = None
        error.__suppress_context__ = True
        raise error

    def _select_point(self, *args: object, **kwargs: object) -> dict[str, object]:
        self._assert_database_identity()
        try:
            result = independent.select_point(*args, **kwargs)
        finally:
            self._assert_database_identity()
        return result

    def _custody_call(self, method: str, *args: object) -> object:
        self._assert_port_identity()
        try:
            with self._authority.external_scope():
                result = getattr(self.custody, method)(*args)
        except Exception:
            self._assert_port_identity()
            raise_redacted(RecoveryIndeterminateError, "recovery:custody-indeterminate")
        self._assert_port_identity()
        return result

    def _storage_call(self, method: str, *args: object, **kwargs: object) -> object:
        self._assert_port_identity()
        try:
            with self._authority.external_scope():
                result = getattr(self.storage, method)(*args, **kwargs)
        except StorageNotFound as error:
            if type(error) is not StorageNotFound:
                self._assert_port_identity()
                raise_redacted(RecoveryIndeterminateError, "recovery:storage-indeterminate")
            raise
        except Exception:
            self._assert_port_identity()
            raise_redacted(RecoveryIndeterminateError, "recovery:storage-indeterminate")
        self._assert_port_identity()
        return result

    def _custody_state(self, key_id: str, key_epoch: int) -> str:
        value = self._custody_call("state", key_id, key_epoch)
        if type(value) is not str or value not in {"ACTIVE", "REVOKED", "UNKNOWN"}:
            raise RecoveryIndeterminateError("recovery:custody-indeterminate")
        return value

    def verify(self) -> dict[str, object]:
        self._authority.assert_live()
        self._assert_database_identity()
        try:
            return independent.verify_database(self.path, expected_database_id=self.config.database_id, expected_config_digest=self.config.digest)
        finally:
            self._assert_database_identity()

    @staticmethod
    def _receipt(raw: bytes) -> RecoveryReceipt:
        value = independent._parse(raw, "recovery:receipt")
        return RecoveryReceipt(raw=raw, point_id=str(value["point_id"]), operation_id=str(value["operation_id"]), event_id=str(value["event_id"]), state=str(value["next_state"]), sequence=int(value["sequence"]), after_root=str(value["after_root"]))

    def _append(self, connection: sqlite3.Connection, *, kind: str, point_id: str, operation_id: str, request_digest: str, prior_state: str, next_state: str, material: Mapping[str, object], payload_digest: str, payload_length: int) -> bytes:
        if type(payload_length) is not int or not 0 <= payload_length <= independent.MAX_BUNDLE_BYTES + MAX_CUSTODY_OVERHEAD_BYTES:
            raise RecoveryError("recovery:event-range")
        try:
            material_raw = _canonical(material)
        except Exception:
            raise RecoveryError("recovery:event-material") from None
        if len(material_raw) > MAX_EVENT_BYTES:
            raise RecoveryError("recovery:event-cap")
        meta = connection.execute("SELECT * FROM recovery_meta WHERE meta_id=1").fetchone()
        if meta is None:
            raise RecoveryError("recovery:meta")
        sequence = int(meta["sequence"]) + 1
        body: dict[str, object] = {
            "schema": SCHEMA, "schema_version": SCHEMA_VERSION,
            "database_id": self.config.database_id, "chain_id": self.config.chain_id,
            "sequence": sequence, "event_id": "", "event_kind": kind,
            "stream_kind": "POINT", "stream_id": point_id,
            "point_id": point_id, "operation_id": operation_id,
            "request_digest": request_digest, "prior_state": prior_state,
            "next_state": next_state, "attempt": 0,
            "before_root": meta["head_root"], "after_root": "",
            "material": material, "material_digest": _digest("material", material),
            "payload_digest": payload_digest, "payload_length": payload_length,
        }
        body["event_id"] = _digest("event-id", {key: body[key] for key in body if key not in {"event_id", "after_root"}})
        body["after_root"] = independent._event_root(sequence, str(meta["head_root"]), str(body["event_id"]), kind, point_id, next_state, str(body["material_digest"]), str(body["stream_kind"]), str(body["stream_id"]))
        raw = _canonical(body)
        if len(raw) > MAX_EVENT_BYTES:
            raise RecoveryError("recovery:event-cap")
        connection.execute("INSERT INTO recovery_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (sequence, body["event_id"], kind, self.config.database_id, self.config.chain_id, body["stream_kind"], body["stream_id"], point_id, operation_id, request_digest, prior_state, next_state, 0, body["before_root"], body["after_root"], body["material_digest"], payload_digest, payload_length, raw, _raw_digest("receipt", raw)))
        connection.execute("UPDATE recovery_meta SET sequence=?,head_root=? WHERE meta_id=1", (sequence, body["after_root"]))
        return raw

    def _read_pair(self, ingress_path: Path, core_path: Path) -> tuple[dict[str, object], dict[str, object], bytes, bytes]:
        try:
            ing_raw = _bounded_image(ingress_path, ingress.MAX_DATABASE_BYTES, "recovery:ingress-image")
            core_raw = _bounded_image(core_path, core.MAX_DATABASE_BYTES, "recovery:core-image")
            ing = ingress.verify_bytes(ing_raw, expected_database_id=self.config.ingress_database_id, expected_config_digest=self.config.ingress_config_digest)
            cor = core.verify_bytes(core_raw, expected_database_id=self.config.core_database_id, expected_config_digest=self.config.core_config_digest, ingress_bytes=ing_raw)
            if cor["ingress_database_id"] != ing["database_id"] or cor["ingress_watermark"] > ing["sequence"]:
                raise RecoveryConflictError("recovery:watermark")
            return ing, cor, ing_raw, core_raw
        except (RecoveryError, ingress.IngressVerificationError, core.CoreVerificationError):
            raise
        except Exception:
            raise_redacted(RecoveryError, "recovery:source")

    def _bundle(self, ing: Mapping[str, object], cor: Mapping[str, object], ing_raw: bytes, cor_raw: bytes, generation: int, prior_root: str) -> bytes:
        ingress_component = {"database_id": ing["database_id"], "chain_id": ing["chain_id"], "config_digest": ing["config_digest"], "head_root": ing["head_root"], "watermark": ing["sequence"], "image_digest": _raw_digest("ingress-image", ing_raw), "image_length": len(ing_raw)}
        core_component = {"database_id": cor["database_id"], "chain_id": cor["chain_id"], "config_digest": cor["config_digest"], "head_root": cor["head_root"], "watermark": cor["ingress_watermark"], "image_digest": _raw_digest("core-image", cor_raw), "image_length": len(cor_raw)}
        value = {"schema": "mirror-recovery-bundle-v2", "schema_version": 2, "generation": generation, "prior_recovery_root": prior_root, "ingress": ingress_component, "core": core_component, "ingress_image": base64.b64encode(ing_raw).decode("ascii"), "core_image": base64.b64encode(cor_raw).decode("ascii"), "flags": dict(FIXED_FLAGS)}
        raw = _canonical(value)
        if len(raw) > self.config.max_bundle_bytes:
            raise RecoveryError("recovery:bundle-cap")
        try:
            independent.parse_bundle(raw, max_bundle_bytes=self.config.max_bundle_bytes, expected_generation=generation, expected_prior_root=prior_root, expected_ingress=ingress_component, expected_core=core_component)
        except independent.RecoveryVerificationError:
            raise RecoveryError("recovery:bundle") from None
        return raw

    def _prepare_material(self, point: Mapping[str, object], ing: Mapping[str, object], cor: Mapping[str, object], ing_raw: bytes, core_raw: bytes) -> dict[str, object]:
        material = {"point_id": point["point_id"], "generation": point["generation"], "object_id": point["object_id"], "bundle_digest": point["bundle_digest"], "bundle_length": point["bundle_length"], "ingress": {"database_id": ing["database_id"], "chain_id": ing["chain_id"], "config_digest": ing["config_digest"], "head_root": ing["head_root"], "watermark": ing["sequence"], "image_digest": _raw_digest("ingress-image", ing_raw), "image_length": len(ing_raw)}, "core": {"database_id": cor["database_id"], "chain_id": cor["chain_id"], "config_digest": cor["config_digest"], "head_root": cor["head_root"], "watermark": cor["ingress_watermark"], "image_digest": _raw_digest("core-image", core_raw), "image_length": len(core_raw)}, "key_id": point["key_id"], "key_epoch": point["key_epoch"], "key_state": point["key_state"], "storage_id": point["storage_id"], "prior_point_id": point["prior_point_id"], "prior_root": point["prior_root"], "operation_id": point["operation_id"], "request_digest": point["request_digest"]}
        return material

    def _invalidate(self, point_id: str, reason: str) -> None:
        if reason != "key-revoked":
            raise RecoveryConflictError("recovery:invalidation")
        connection = self._open()
        try:
            self._begin(connection)
            row = connection.execute("SELECT * FROM recovery_points WHERE point_id=?", (point_id,)).fetchone()
            if row is None or row["state"] != "OBJECT_PENDING":
                transaction = connection
                connection = None
                self._finish_transaction(transaction, commit=False)
                return
            material = {"point_id": row["point_id"], "object_id": row["object_id"], "key_id": row["key_id"], "key_epoch": row["key_epoch"], "reason": "key-revoked"}
            raw = self._append(connection, kind="INVALIDATED", point_id=str(row["point_id"]), operation_id=str(row["operation_id"]), request_digest=str(row["request_digest"]), prior_state="OBJECT_PENDING", next_state="INVALIDATED", material=material, payload_digest=str(row["object_id"]), payload_length=0)
            sequence = independent._parse(raw, "recovery:receipt")["sequence"]
            connection.execute("UPDATE recovery_points SET state='INVALIDATED',updated_sequence=? WHERE point_id=?", (sequence, point_id))
        except RecoveryError as error:
            self._finish_transaction(connection, commit=False, error=error)
        except sqlite3.Error as error:
            mapped = RecoveryError("recovery:capacity" if _sqlite_is_capacity(error) else "recovery:invalidate")
            self._finish_transaction(connection, commit=False, error=mapped)
        except Exception:
            self._finish_transaction(connection, commit=False, error=RecoveryError("recovery:invalidate"))
        else:
            self._finish_transaction(connection)

    @staticmethod
    def _bounded_bytes(value: object, maximum: int, label: str) -> bytes:
        if type(value) is not bytes or not value or len(value) > maximum:
            raise RecoveryConflictError(label)
        return value

    def _verify_stored_bundle(self, stored: bytes, point: Mapping[str, object], expected_bundle: bytes | None = None) -> bytes:
        self._bounded_bytes(stored, self.config.max_bundle_bytes + MAX_CUSTODY_OVERHEAD_BYTES, "recovery:storage-size")
        if self._custody_state(str(point["key_id"]), int(point["key_epoch"])) != "ACTIVE":
            if point["state"] == "OBJECT_PENDING":
                self._invalidate(str(point["point_id"]), "key-revoked")
            raise RecoveryConflictError("recovery:key-revoked")
        try:
            opened = self._custody_call("open", stored, str(point["key_id"]), int(point["key_epoch"]))
        except Exception:
            if self._custody_state(str(point["key_id"]), int(point["key_epoch"])) != "ACTIVE":
                if point["state"] == "OBJECT_PENDING":
                    self._invalidate(str(point["point_id"]), "key-revoked")
                raise RecoveryConflictError("recovery:key-revoked") from None
            raise RecoveryIndeterminateError("recovery:custody-indeterminate") from None
        self._bounded_bytes(opened, self.config.max_bundle_bytes, "recovery:bundle-size")
        if (expected_bundle is not None and opened != expected_bundle) or _raw_digest("bundle", opened) != point["bundle_digest"]:
            raise RecoveryConflictError("recovery:bundle-conflict")
        try:
            parsed, _ing_raw, _core_raw = independent.parse_bundle(opened, max_bundle_bytes=self.config.max_bundle_bytes, expected_generation=int(point["generation"]), expected_prior_root=str(point["prior_root"]))
        except independent.RecoveryVerificationError:
            raise RecoveryConflictError("recovery:bundle") from None
        if parsed["ingress"]["database_id"] != point["ingress_database_id"] or parsed["ingress"]["config_digest"] != point["ingress_config_digest"] or parsed["ingress"]["head_root"] != point["ingress_head_root"] or parsed["ingress"]["watermark"] != point["ingress_watermark"] or parsed["core"]["database_id"] != point["core_database_id"] or parsed["core"]["config_digest"] != point["core_config_digest"] or parsed["core"]["head_root"] != point["core_head_root"] or parsed["core"]["watermark"] != point["core_watermark"]:
            raise RecoveryConflictError("recovery:bundle-binding")
        if self._custody_state(str(point["key_id"]), int(point["key_epoch"])) != "ACTIVE":
            if point["state"] == "OBJECT_PENDING":
                self._invalidate(str(point["point_id"]), "key-revoked")
            raise RecoveryConflictError("recovery:key-revoked")
        return opened

    def _same_point_immutable(self, first: Mapping[str, object], second: Mapping[str, object]) -> bool:
        columns = ("point_id", "generation", "object_id", "bundle_digest", "bundle_length", "ingress_database_id", "ingress_config_digest", "ingress_head_root", "ingress_watermark", "core_database_id", "core_config_digest", "core_head_root", "core_watermark", "key_id", "key_epoch", "key_state", "storage_id", "prior_point_id", "prior_root", "operation_id", "request_digest")
        return all(first[key] == second[key] for key in columns)

    def _commit_verified(self, point: Mapping[str, object]) -> RecoveryReceipt:
        connection = self._open()
        try:
            self._begin(connection)
            current = connection.execute("SELECT * FROM recovery_points WHERE point_id=?", (point["point_id"],)).fetchone()
            if current is None or not self._same_point_immutable(point, current):
                raise RecoveryConflictError("recovery:point-conflict")
            if current["state"] in {"VERIFIED", "PUBLISHED"}:
                event = connection.execute("SELECT event_raw FROM recovery_events WHERE point_id=? AND next_state=? ORDER BY sequence DESC LIMIT 1", (point["point_id"], current["state"])).fetchone()
                if event is None:
                    raise RecoveryError("recovery:receipt")
                receipt = self._receipt(event[0])
                transaction = connection
                connection = None
                self._finish_transaction(transaction)
                return receipt
            if current["state"] != "OBJECT_PENDING" or dict(current) != dict(point):
                raise RecoveryConflictError("recovery:state")
            material = {"point_id": point["point_id"], "object_id": point["object_id"], "bundle_digest": point["bundle_digest"], "bundle_length": point["bundle_length"], "storage_id": point["storage_id"], "key_id": point["key_id"], "key_epoch": point["key_epoch"]}
            raw = self._append(connection, kind="VERIFIED", point_id=str(point["point_id"]), operation_id=str(point["operation_id"]), request_digest=str(point["request_digest"]), prior_state="OBJECT_PENDING", next_state="VERIFIED", material=material, payload_digest=str(point["object_id"]), payload_length=0)
            sequence = independent._parse(raw, "recovery:receipt")["sequence"]
            connection.execute("UPDATE recovery_points SET state='VERIFIED',updated_sequence=? WHERE point_id=?", (sequence, point["point_id"]))
            receipt = self._receipt(raw)
        except (RecoveryError, RecoveryConflictError) as error:
            self._finish_transaction(connection, commit=False, error=error)
        except sqlite3.Error as error:
            mapped = RecoveryError("recovery:capacity" if _sqlite_is_capacity(error) else "recovery:database")
            self._finish_transaction(connection, commit=False, error=mapped)
        except Exception:
            self._finish_transaction(connection, commit=False, error=RecoveryError("recovery:database"))
        else:
            self._finish_transaction(connection)
            return receipt

    def _complete_storage(self, point: Mapping[str, object], bundle: bytes, sealed: bytes) -> RecoveryReceipt:
        key_id, key_epoch, object_id = str(point["key_id"]), int(point["key_epoch"]), str(point["object_id"])
        expected_object = _digest("object-id", {"bundle_digest": point["bundle_digest"], "profile_digest": self.config.profile_digest, "key_id": key_id, "key_epoch": key_epoch})
        if expected_object != object_id:
            raise RecoveryConflictError("recovery:object-rebound")
        self._bounded_bytes(sealed, self.config.max_bundle_bytes + MAX_CUSTODY_OVERHEAD_BYTES, "recovery:sealed-size")
        if self._custody_state(key_id, key_epoch) != "ACTIVE":
            self._invalidate(str(point["point_id"]), "key-revoked")
            raise RecoveryConflictError("recovery:key-revoked")
        receipt: StorageReceipt | None = None
        try:
            try:
                stored = self._storage_call("get", object_id)
                self._bounded_bytes(stored, self.config.max_bundle_bytes + MAX_CUSTODY_OVERHEAD_BYTES, "recovery:storage-size")
            except StorageNotFound:
                if self._custody_state(key_id, key_epoch) != "ACTIVE":
                    self._invalidate(str(point["point_id"]), "key-revoked")
                    raise RecoveryConflictError("recovery:key-revoked")
                receipt = self._storage_call("put_if_absent", object_id, sealed, key_id=key_id, key_epoch=key_epoch)
                if (
                    type(receipt) is not StorageReceipt
                    or type(receipt.storage_id) is not str
                    or type(receipt.object_id) is not str
                    or type(receipt.result) is not str
                    or type(receipt.byte_length) is not int
                    or receipt.byte_length < 0
                    or type(receipt.sealed_digest) is not str
                    or type(receipt.key_id) is not str
                    or type(receipt.key_epoch) is not int
                    or receipt.result not in {"CREATED", "EXISTING_SAME"}
                    or receipt.object_id != object_id
                    or receipt.storage_id != self.config.storage_id
                    or receipt.key_id != key_id
                    or receipt.key_epoch != key_epoch
                ):
                    if type(receipt) is StorageReceipt and type(receipt.result) is str and receipt.result == "EXISTING_DIFFERENT":
                        raise RecoveryConflictError("recovery:storage-conflict")
                    raise RecoveryConflictError("recovery:storage-receipt")
                try:
                    stored = self._storage_call("get", object_id)
                except StorageNotFound:
                    raise RecoveryIndeterminateError("recovery:storage-indeterminate")
                self._bounded_bytes(stored, self.config.max_bundle_bytes + MAX_CUSTODY_OVERHEAD_BYTES, "recovery:storage-size")
            self._verify_stored_bundle(stored, point, bundle)
            if receipt is not None and (receipt.byte_length != len(stored) or receipt.sealed_digest != _raw_digest("sealed", stored)):
                raise RecoveryConflictError("recovery:storage-receipt")
        except (RecoveryConflictError, RecoveryIndeterminateError):
            raise
        except StorageNotFound:
            raise RecoveryIndeterminateError("recovery:storage-indeterminate") from None
        except Exception:
            raise_redacted(RecoveryIndeterminateError, "recovery:storage-indeterminate")
        return self._commit_verified(point)

    def _capacity_and_existing(self, generation: int) -> dict[str, object] | None:
        connection = self._open()
        try:
            self._begin(connection)
            pending_rows = connection.execute(
                "SELECT generation FROM recovery_points WHERE state='OBJECT_PENDING' ORDER BY generation"
            ).fetchall()
            if len(pending_rows) > 1:
                raise RecoveryError("recovery:pending")
            if pending_rows and int(pending_rows[0]["generation"]) != generation:
                raise RecoveryConflictError("recovery:pending")
            row = connection.execute("SELECT * FROM recovery_points WHERE generation=?", (generation,)).fetchone()
            if row is None and connection.execute("SELECT point_id FROM recovery_points ORDER BY generation,point_id LIMIT 1 OFFSET ?", (MAX_RECOVERY_POINTS - 1,)).fetchone() is not None:
                raise RecoveryError("recovery:capacity")
            result = dict(row) if row is not None else None
        except (RecoveryError, RecoveryConflictError) as error:
            self._finish_transaction(connection, commit=False, error=error)
        except sqlite3.Error as error:
            mapped = RecoveryError("recovery:capacity" if _sqlite_is_capacity(error) else "recovery:database")
            self._finish_transaction(connection, commit=False, error=mapped)
        except Exception:
            self._finish_transaction(connection, commit=False, error=RecoveryError("recovery:database"))
        else:
            self._finish_transaction(connection)
            return result

    def _finish_existing(self, selected: Mapping[str, object], ingress_path: Path, core_path: Path) -> RecoveryReceipt:
        point = selected["point"]
        state = str(point["state"])
        key_id, key_epoch = str(point["key_id"]), int(point["key_epoch"])
        try:
            key_state = self._custody_state(key_id, key_epoch)
        except Exception:
            raise_redacted(RecoveryIndeterminateError, "recovery:custody-indeterminate")
        if state in {"VERIFIED", "PUBLICATION_PENDING", "PUBLISHED"}:
            if key_state != "ACTIVE":
                raise RecoveryConflictError("recovery:key-revoked")
            return self._receipt(bytes(selected["receipt"]))
        if state == "INVALIDATED":
            raise RecoveryConflictError("recovery:point-invalidated")
        if state != "OBJECT_PENDING":
            raise RecoveryConflictError("recovery:point-state")
        if key_state != "ACTIVE":
            self._invalidate(str(point["point_id"]), "key-revoked")
            raise RecoveryConflictError("recovery:key-revoked")
        try:
            stored = self._storage_call("get", str(point["object_id"]))
        except StorageNotFound:
            ing, cor, ing_raw, core_raw = self._read_pair(ingress_path, core_path)
            bundle = self._bundle(ing, cor, ing_raw, core_raw, int(point["generation"]), str(point["prior_root"]))
            if _raw_digest("bundle", bundle) != point["bundle_digest"]:
                raise RecoveryConflictError("recovery:source-drift")
            if self._custody_state(key_id, key_epoch) != "ACTIVE":
                self._invalidate(str(point["point_id"]), "key-revoked")
                raise RecoveryConflictError("recovery:key-revoked")
            try:
                sealed = self._custody_call("seal", bundle, key_id, key_epoch)
            except Exception:
                raise_redacted(RecoveryIndeterminateError, "recovery:custody-indeterminate")
            self._bounded_bytes(sealed, self.config.max_bundle_bytes + MAX_CUSTODY_OVERHEAD_BYTES, "recovery:sealed-size")
            return self._complete_storage(point, bundle, sealed)
        except (RecoveryError, RecoveryConflictError, RecoveryIndeterminateError):
            raise
        except Exception:
            raise_redacted(RecoveryIndeterminateError, "recovery:storage-indeterminate")
        self._verify_stored_bundle(stored, point)
        return self._commit_verified(point)

    @_mutation
    def create_point(self, ingress_path: str | Path, core_path: str | Path, *, generation: int) -> RecoveryReceipt:
        return self._create_point(ingress_path, core_path, generation=generation)

    def _create_point(self, ingress_path: str | Path, core_path: str | Path, *, generation: int) -> RecoveryReceipt:
        if type(generation) is not int or not 1 <= generation <= MAX_RECOVERY_POINTS:
            raise RecoveryError("recovery:input")
        existing = self._capacity_and_existing(generation)
        if existing is not None:
            selected = self._select_point(self.path, generation=generation, expected_database_id=self.config.database_id, expected_config_digest=self.config.digest)
            return self._finish_existing(selected, Path(ingress_path), Path(core_path))
        ing, cor, ing_raw, core_raw = self._read_pair(Path(ingress_path), Path(core_path))
        key = self._custody_call("current_key")
        if type(key) is not RecoveryKey or type(key.key_id) is not str or not key.key_id or type(key.key_epoch) is not int or key.key_epoch < 0 or type(key.state) is not str or key.state != "ACTIVE" or self._custody_state(key.key_id, key.key_epoch) != "ACTIVE":
            raise RecoveryConflictError("recovery:key-unavailable")
        connection = self._open()
        try:
            self._begin(connection)
            meta = connection.execute("SELECT * FROM recovery_meta WHERE meta_id=1").fetchone()
            if meta is None:
                raise RecoveryError("recovery:meta")
            existing_row = connection.execute("SELECT * FROM recovery_points WHERE generation=?", (generation,)).fetchone()
            if existing_row is not None:
                transaction = connection
                connection = None
                self._finish_transaction(transaction, commit=False)
                selected = self._select_point(self.path, generation=generation, expected_database_id=self.config.database_id, expected_config_digest=self.config.digest)
                return self._finish_existing(selected, Path(ingress_path), Path(core_path))
            if connection.execute("SELECT point_id FROM recovery_points ORDER BY generation,point_id LIMIT 1 OFFSET ?", (MAX_RECOVERY_POINTS - 1,)).fetchone() is not None:
                raise RecoveryError("recovery:capacity")
            current_generation = int(meta["current_generation"])
            expected_generation = current_generation + 1 if current_generation else 1
            if generation != expected_generation:
                raise RecoveryConflictError("recovery:generation")
            prior_point = connection.execute("SELECT * FROM recovery_points ORDER BY generation DESC LIMIT 1").fetchone()
            prior_root = str(meta["head_root"])
            if current_generation == 0:
                if prior_point is not None or prior_root != independent.GENESIS_ROOT:
                    raise RecoveryConflictError("recovery:generation")
            else:
                if prior_point is None or int(prior_point["generation"]) != current_generation:
                    raise RecoveryConflictError("recovery:generation")
                prior_event = connection.execute("SELECT after_root FROM recovery_events WHERE sequence=?", (prior_point["updated_sequence"],)).fetchone()
                if prior_event is None or prior_event["after_root"] != prior_root:
                    raise RecoveryConflictError("recovery:generation")
            bundle = self._bundle(ing, cor, ing_raw, core_raw, generation, prior_root)
            bundle_digest = _raw_digest("bundle", bundle)
            point_id = _digest("point-id", {"config_digest": self.config.digest, "generation": generation})
            object_id = _digest("object-id", {"bundle_digest": bundle_digest, "profile_digest": self.config.profile_digest, "key_id": key.key_id, "key_epoch": key.key_epoch})
            operation_id = _digest("operation-id", {"point_id": point_id})
            request_digest = _digest("request", {"point_id": point_id, "bundle_digest": bundle_digest, "object_id": object_id})
            point = {"point_id": point_id, "generation": generation, "state": "PREPARED", "object_id": object_id, "bundle_digest": bundle_digest, "bundle_length": len(bundle), "ingress_database_id": ing["database_id"], "ingress_config_digest": ing["config_digest"], "ingress_head_root": ing["head_root"], "ingress_watermark": ing["sequence"], "core_database_id": cor["database_id"], "core_config_digest": cor["config_digest"], "core_head_root": cor["head_root"], "core_watermark": cor["ingress_watermark"], "key_id": key.key_id, "key_epoch": key.key_epoch, "key_state": key.state, "storage_id": self.config.storage_id, "prior_point_id": prior_point["point_id"] if prior_point is not None else None, "prior_root": prior_root, "operation_id": operation_id, "request_digest": request_digest, "sequence": 0, "updated_sequence": 0}
            connection.execute("INSERT INTO recovery_points VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", tuple(point[column] for column in independent._POINT_COLUMNS))
            prepare = self._append(connection, kind="PREPARE", point_id=point_id, operation_id=operation_id, request_digest=request_digest, prior_state="NONE", next_state="PREPARED", material=self._prepare_material(point, ing, cor, ing_raw, core_raw), payload_digest=bundle_digest, payload_length=len(bundle))
            prepare_sequence = int(independent._parse(prepare, "recovery:receipt")["sequence"])
            connection.execute("UPDATE recovery_points SET sequence=?,updated_sequence=? WHERE point_id=?", (prepare_sequence, prepare_sequence, point_id))
            pending_material = {"point_id": point_id, "object_id": object_id, "storage_id": self.config.storage_id, "key_id": key.key_id, "key_epoch": key.key_epoch}
            pending = self._append(connection, kind="OBJECT_PENDING", point_id=point_id, operation_id=operation_id, request_digest=request_digest, prior_state="PREPARED", next_state="OBJECT_PENDING", material=pending_material, payload_digest=object_id, payload_length=0)
            pending_sequence = int(independent._parse(pending, "recovery:receipt")["sequence"])
            connection.execute("UPDATE recovery_points SET state='OBJECT_PENDING',updated_sequence=? WHERE point_id=?", (pending_sequence, point_id))
            connection.execute("UPDATE recovery_meta SET current_generation=? WHERE meta_id=1", (generation,))
            point["state"] = "OBJECT_PENDING"
            point["sequence"] = prepare_sequence
            point["updated_sequence"] = pending_sequence
        except RecoveryError as error:
            if connection is None:
                error.__cause__ = None
                error.__context__ = None
                error.__suppress_context__ = True
                raise error
            self._finish_transaction(connection, commit=False, error=error)
        except sqlite3.IntegrityError:
            if connection is None:
                raise_redacted(RecoveryConflictError, "recovery:conflict")
            self._finish_transaction(connection, commit=False, error=RecoveryConflictError("recovery:conflict"))
        except sqlite3.Error as error:
            mapped = RecoveryError("recovery:capacity" if _sqlite_is_capacity(error) else "recovery:database")
            if connection is None:
                raise mapped from None
            self._finish_transaction(connection, commit=False, error=mapped)
        except Exception:
            if connection is None:
                raise_redacted(RecoveryError, "recovery:database")
            self._finish_transaction(connection, commit=False, error=RecoveryError("recovery:database"))
        else:
            self._finish_transaction(connection)
            connection = None
        if self._custody_state(key.key_id, key.key_epoch) != "ACTIVE":
            self._invalidate(point_id, "key-revoked")
            raise RecoveryConflictError("recovery:key-revoked")
        try:
            point = self._select_point(self.path, point_id=point_id, expected_database_id=self.config.database_id, expected_config_digest=self.config.digest, allowed_states=("OBJECT_PENDING",))["point"]
        except independent.RecoveryVerificationError:
            raise RecoveryConflictError("recovery:point") from None
        try:
            sealed = self._custody_call("seal", bundle, key.key_id, key.key_epoch)
        except Exception:
            raise_redacted(RecoveryIndeterminateError, "recovery:custody-indeterminate")
        self._bounded_bytes(sealed, self.config.max_bundle_bytes + MAX_CUSTODY_OVERHEAD_BYTES, "recovery:sealed-size")
        return self._complete_storage(point, bundle, sealed)

    def _require_active_key(self, point: Mapping[str, object]) -> None:
        try:
            state = self._custody_state(str(point["key_id"]), int(point["key_epoch"]))
        except Exception:
            raise_redacted(RecoveryIndeterminateError, "recovery:custody-indeterminate")
        if state != "ACTIVE":
            raise RecoveryConflictError("recovery:key-revoked")

    def _bundle_images(self, point: Mapping[str, object]) -> tuple[dict[str, object], bytes, bytes]:
        try:
            sealed = self._storage_call("get", str(point["object_id"]))
            self._bounded_bytes(sealed, self.config.max_bundle_bytes + MAX_CUSTODY_OVERHEAD_BYTES, "recovery:storage-size")
            expected_object = _digest("object-id", {"bundle_digest": point["bundle_digest"], "profile_digest": self.config.profile_digest, "key_id": point["key_id"], "key_epoch": point["key_epoch"]})
            if expected_object != point["object_id"] or self._custody_state(str(point["key_id"]), int(point["key_epoch"])) != "ACTIVE":
                raise RecoveryConflictError("recovery:key-or-object")
            bundle = self._custody_call("open", sealed, str(point["key_id"]), int(point["key_epoch"]))
            self._bounded_bytes(bundle, self.config.max_bundle_bytes, "recovery:bundle-size")
            if _raw_digest("bundle", bundle) != point["bundle_digest"] or len(bundle) != point["bundle_length"]:
                raise RecoveryConflictError("recovery:bundle")
            parsed, ing_raw, core_raw = independent.parse_bundle(bundle, max_bundle_bytes=self.config.max_bundle_bytes, expected_generation=int(point["generation"]), expected_prior_root=str(point["prior_root"]))
            if parsed["ingress"]["database_id"] != point["ingress_database_id"] or parsed["ingress"]["config_digest"] != point["ingress_config_digest"] or parsed["ingress"]["head_root"] != point["ingress_head_root"] or parsed["ingress"]["watermark"] != point["ingress_watermark"] or parsed["core"]["database_id"] != point["core_database_id"] or parsed["core"]["config_digest"] != point["core_config_digest"] or parsed["core"]["head_root"] != point["core_head_root"] or parsed["core"]["watermark"] != point["core_watermark"]:
                raise RecoveryConflictError("recovery:bundle-binding")
            if self._custody_state(str(point["key_id"]), int(point["key_epoch"])) != "ACTIVE":
                raise RecoveryConflictError("recovery:key-revoked")
            return parsed, ing_raw, core_raw
        except (RecoveryError, RecoveryConflictError):
            raise
        except StorageNotFound:
            raise RecoveryConflictError("recovery:object-missing")
        except Exception:
            raise_redacted(RecoveryIndeterminateError, "recovery:restore-indeterminate")

    @staticmethod
    def _publication_target(value: str | Path, point_id: str, role: str) -> tuple[Path, str]:
        path = restore_publication._target(value)
        target_identity = restore_publication._target_identity(path)
        binding = _digest("publication-target-binding", {
            "point_id": point_id,
            "role": role,
            "target_identity": target_identity,
        })
        return path, binding

    @staticmethod
    def _publication_claim(point: Mapping[str, object], ingress_raw: bytes, core_raw: bytes, ingress_binding: str, core_binding: str) -> dict[str, object]:
        material: dict[str, object] = {
            "point_id": point["point_id"], "object_id": point["object_id"],
            "bundle_digest": point["bundle_digest"], "bundle_length": point["bundle_length"],
            "storage_id": point["storage_id"], "key_id": point["key_id"], "key_epoch": point["key_epoch"],
            "ingress_database_id": point["ingress_database_id"], "ingress_config_digest": point["ingress_config_digest"],
            "ingress_head_root": point["ingress_head_root"], "ingress_watermark": point["ingress_watermark"],
            "core_database_id": point["core_database_id"], "core_config_digest": point["core_config_digest"],
            "core_head_root": point["core_head_root"], "core_watermark": point["core_watermark"],
            "ingress_image_digest": _raw_digest("ingress-image", ingress_raw), "ingress_image_length": len(ingress_raw),
            "core_image_digest": _raw_digest("core-image", core_raw), "core_image_length": len(core_raw),
            "ingress_target_binding": ingress_binding, "core_target_binding": core_binding,
        }
        material["pair_operation_id"] = _digest("pair-publication-operation", material)
        return material

    @staticmethod
    def _require_publication_targets(event: Mapping[str, object], ingress_binding: str, core_binding: str) -> None:
        material = event.get("material")
        if not isinstance(material, dict) or material.get("ingress_target_binding") != ingress_binding or material.get("core_target_binding") != core_binding:
            raise RecoveryConflictError("recovery:publication-claim")

    def _verify_published_targets(
        self,
        claim: Mapping[str, object],
        ingress_path: Path,
        core_path: Path,
        ingress_raw: bytes,
        core_raw: bytes,
    ) -> None:
        if (
            claim.get("ingress_image_digest") != _raw_digest("ingress-image", ingress_raw)
            or claim.get("ingress_image_length") != len(ingress_raw)
            or claim.get("core_image_digest") != _raw_digest("core-image", core_raw)
            or claim.get("core_image_length") != len(core_raw)
        ):
            raise RecoveryConflictError("recovery:publication-claim")
        try:
            restore_publication.verify_pair_read_only(
                ingress_target=ingress_path,
                core_target=core_path,
                ingress_image=ingress_raw,
                core_image=core_raw,
                pair_operation_id=claim["pair_operation_id"],
                ingress_file_digest=restore_publication._file_digest(ingress_raw),
                ingress_file_length=claim["ingress_image_length"],
                core_file_digest=restore_publication._file_digest(core_raw),
                core_file_length=claim["core_image_length"],
                ingress_expected={
                    "database_id": claim["ingress_database_id"],
                    "config_digest": claim["ingress_config_digest"],
                    "head_root": claim["ingress_head_root"],
                    "sequence": claim["ingress_watermark"],
                },
                core_expected={
                    "database_id": claim["core_database_id"],
                    "config_digest": claim["core_config_digest"],
                    "head_root": claim["core_head_root"],
                    "ingress_database_id": claim["ingress_database_id"],
                    "ingress_watermark": claim["core_watermark"],
                },
                verify_ingress=lambda image: ingress.verify_bytes(
                    image,
                    expected_database_id=self.config.ingress_database_id,
                    expected_config_digest=self.config.ingress_config_digest,
                ),
                verify_core=lambda image, exact_ingress: core.verify_bytes(
                    image,
                    expected_database_id=self.config.core_database_id,
                    expected_config_digest=self.config.core_config_digest,
                    ingress_bytes=exact_ingress,
                ),
            )
        except restore_publication.RestorePublicationConflict:
            raise_redacted(RecoveryConflictError, "recovery:publication-conflict")
        except restore_publication.RestorePublicationError:
            raise_redacted(RecoveryError, "recovery:publication")

    @_mutation
    def restore_point(self, point_id: str, ingress_target: str | Path, core_target: str | Path) -> RecoveryReceipt:
        try:
            selected = self._select_point(self.path, point_id=point_id, expected_database_id=self.config.database_id, expected_config_digest=self.config.digest, allowed_states=("VERIFIED", "PUBLICATION_PENDING", "PUBLISHED"))
        except independent.RecoveryVerificationError:
            raise_redacted(RecoveryConflictError, "recovery:catalog")
        point = selected["point"]
        selected_receipt = bytes(selected["receipt"])
        ingress_path, ingress_binding = self._publication_target(ingress_target, str(point["point_id"]), "ingress")
        core_path, core_binding = self._publication_target(core_target, str(point["point_id"]), "core")
        if point["state"] in {"PUBLICATION_PENDING", "PUBLISHED"}:
            self._require_publication_targets(selected["event"], ingress_binding, core_binding)
        self._require_active_key(point)
        _bundle, ing_raw, core_raw = self._bundle_images(point)
        claim = self._publication_claim(point, ing_raw, core_raw, ingress_binding, core_binding)
        if point["state"] == "PUBLISHED":
            selected_material = selected["event"].get("material")
            if not isinstance(selected_material, dict) or any(selected_material.get(key) != claim[key] for key in claim):
                raise RecoveryConflictError("recovery:publication-claim")
            self._verify_published_targets(claim, ingress_path, core_path, ing_raw, core_raw)
            return self._receipt(selected_receipt)
        if point["state"] == "PUBLICATION_PENDING":
            pending_material = selected["event"].get("material")
            if pending_material != claim:
                raise RecoveryConflictError("recovery:publication-claim")

        pending_event: dict[str, object]
        connection: sqlite3.Connection | None = self._open()
        try:
            self._begin(connection)
            current = connection.execute("SELECT * FROM recovery_points WHERE point_id=?", (point_id,)).fetchone()
            if current is None or not self._same_point_immutable(point, current):
                raise RecoveryConflictError("recovery:point-conflict")
            if current["state"] == "PUBLISHED":
                transaction = connection
                connection = None
                self._finish_transaction(transaction, commit=False)
                current_selected = self._select_point(self.path, point_id=point_id, expected_database_id=self.config.database_id, expected_config_digest=self.config.digest, allowed_states=("PUBLISHED",))
                current_material = current_selected["event"].get("material")
                if not isinstance(current_material, dict) or any(current_material.get(key) != claim[key] for key in claim):
                    raise RecoveryConflictError("recovery:publication-claim")
                self._verify_published_targets(claim, ingress_path, core_path, ing_raw, core_raw)
                return self._receipt(bytes(current_selected["receipt"]))
            if current["state"] not in {"VERIFIED", "PUBLICATION_PENDING"}:
                raise RecoveryConflictError("recovery:point-state")
            pending_row = connection.execute("SELECT event_raw FROM recovery_events WHERE sequence=?", (current["updated_sequence"],)).fetchone()
            if current["state"] == "PUBLICATION_PENDING":
                if pending_row is None:
                    raise RecoveryConflictError("recovery:publication-claim")
                pending_event = independent._parse(bytes(pending_row[0]), "recovery:publication")
                if pending_event.get("event_kind") != "PUBLICATION_PENDING" or pending_event.get("material") != claim:
                    raise RecoveryConflictError("recovery:publication-claim")
            else:
                pending_raw = self._append(connection, kind="PUBLICATION_PENDING", point_id=point_id, operation_id=str(current["operation_id"]), request_digest=str(current["request_digest"]), prior_state="VERIFIED", next_state="PUBLICATION_PENDING", material=claim, payload_digest=str(current["object_id"]), payload_length=0)
                pending_event = independent._parse(pending_raw, "recovery:publication")
                pending_sequence = int(pending_event["sequence"])
                connection.execute("UPDATE recovery_points SET state='PUBLICATION_PENDING',updated_sequence=? WHERE point_id=?", (pending_sequence, point_id))
        except (RecoveryError, RecoveryConflictError) as error:
            if connection is None:
                error.__cause__ = None
                error.__context__ = None
                error.__suppress_context__ = True
                raise error
            self._finish_transaction(connection, commit=False, error=error)
        except sqlite3.Error as error:
            mapped = RecoveryError("recovery:capacity" if _sqlite_is_capacity(error) else "recovery:database")
            if connection is None:
                raise mapped from None
            self._finish_transaction(connection, commit=False, error=mapped)
        except Exception:
            if connection is None:
                raise_redacted(RecoveryError, "recovery:database")
            self._finish_transaction(connection, commit=False, error=RecoveryError("recovery:database"))
        else:
            self._finish_transaction(connection)
            connection = None

        try:
            self._assert_database_identity()
            try:
                with self._authority.external_scope():
                    restore_publication.publish_pair_create_only(
                        ingress_target=ingress_path,
                        core_target=core_path,
                        ingress_image=ing_raw,
                        core_image=core_raw,
                        pair_operation_id=str(claim["pair_operation_id"]),
                        ingress_expected={
                            "database_id": point["ingress_database_id"], "config_digest": point["ingress_config_digest"],
                            "head_root": point["ingress_head_root"], "sequence": point["ingress_watermark"],
                        },
                        core_expected={
                            "database_id": point["core_database_id"], "config_digest": point["core_config_digest"],
                            "head_root": point["core_head_root"], "ingress_database_id": point["ingress_database_id"],
                            "ingress_watermark": point["core_watermark"],
                        },
                        verify_ingress=lambda image: ingress.verify_bytes(image, expected_database_id=self.config.ingress_database_id, expected_config_digest=self.config.ingress_config_digest),
                        verify_core=lambda image, ingress_image: core.verify_bytes(image, expected_database_id=self.config.core_database_id, expected_config_digest=self.config.core_config_digest, ingress_bytes=ingress_image),
                    )
            finally:
                self._assert_database_identity()
        except restore_publication.RestorePublicationConflict:
            raise_redacted(RecoveryConflictError, "recovery:publication-conflict")
        except restore_publication.RestorePublicationError:
            raise_redacted(RecoveryError, "recovery:publication")
        self._require_active_key(point)
        self._verify_published_targets(claim, ingress_path, core_path, ing_raw, core_raw)
        connection = self._open()
        try:
            self._begin(connection)
            current = connection.execute("SELECT * FROM recovery_points WHERE point_id=?", (point_id,)).fetchone()
            if current is None or not self._same_point_immutable(point, current):
                raise RecoveryConflictError("recovery:point-conflict")
            if current["state"] == "PUBLISHED":
                transaction = connection
                connection = None
                self._finish_transaction(transaction, commit=False)
                current_selected = self._select_point(self.path, point_id=point_id, expected_database_id=self.config.database_id, expected_config_digest=self.config.digest, allowed_states=("PUBLISHED",))
                current_material = current_selected["event"].get("material")
                if not isinstance(current_material, dict) or any(current_material.get(key) != claim[key] for key in claim):
                    raise RecoveryConflictError("recovery:publication-claim")
                self._verify_published_targets(claim, ingress_path, core_path, ing_raw, core_raw)
                return self._receipt(bytes(current_selected["receipt"]))
            if current["state"] != "PUBLICATION_PENDING":
                raise RecoveryConflictError("recovery:point-state")
            pending_row = connection.execute("SELECT event_raw FROM recovery_events WHERE sequence=?", (current["updated_sequence"],)).fetchone()
            if pending_row is None:
                raise RecoveryConflictError("recovery:publication-claim")
            pending_event = independent._parse(bytes(pending_row[0]), "recovery:publication")
            if pending_event.get("event_kind") != "PUBLICATION_PENDING" or pending_event.get("material") != claim:
                raise RecoveryConflictError("recovery:publication-claim")
            published_material = dict(claim)
            published_material.update({"pending_event_id": pending_event["event_id"], "pending_sequence": pending_event["sequence"], "pending_after_root": pending_event["after_root"]})
            raw = self._append(connection, kind="PUBLISHED", point_id=point_id, operation_id=str(current["operation_id"]), request_digest=str(current["request_digest"]), prior_state="PUBLICATION_PENDING", next_state="PUBLISHED", material=published_material, payload_digest=str(current["object_id"]), payload_length=0)
            sequence = independent._parse(raw, "recovery:receipt")["sequence"]
            connection.execute("UPDATE recovery_points SET state='PUBLISHED',updated_sequence=? WHERE point_id=?", (sequence, point_id))
            receipt = self._receipt(raw)
        except (RecoveryError, RecoveryConflictError) as error:
            if connection is None:
                error.__cause__ = None
                error.__context__ = None
                error.__suppress_context__ = True
                raise error
            self._finish_transaction(connection, commit=False, error=error)
        except sqlite3.Error as error:
            mapped = RecoveryError("recovery:capacity" if _sqlite_is_capacity(error) else "recovery:database")
            if connection is None:
                raise mapped from None
            self._finish_transaction(connection, commit=False, error=mapped)
        except Exception:
            if connection is None:
                raise_redacted(RecoveryError, "recovery:database")
            self._finish_transaction(connection, commit=False, error=RecoveryError("recovery:database"))
        else:
            self._finish_transaction(connection)
            connection = None
            return receipt

    def bootstrap(self, point_id: str) -> bytes:
        try:
            selected = self._select_point(self.path, point_id=point_id, expected_database_id=self.config.database_id, expected_config_digest=self.config.digest, allowed_states=("VERIFIED", "PUBLISHED"))
        except independent.RecoveryVerificationError:
            raise_redacted(RecoveryConflictError, "recovery:catalog")
        point = selected["point"]
        try:
            key_state = self._custody_state(str(point["key_id"]), int(point["key_epoch"]))
        except Exception:
            raise_redacted(RecoveryIndeterminateError, "recovery:custody-indeterminate")
        if key_state != "ACTIVE":
            raise RecoveryConflictError("recovery:key-revoked")
        body = {"schema": "mirror-recovery-bootstrap-v3", "schema_version": 3, "verifier_id": independent.VERIFIER_ID, "catalog_id": _digest("catalog-id", self.config.database_id), "point_id": point["point_id"], "generation": point["generation"], "object_id": point["object_id"], "bundle_digest": point["bundle_digest"], "bundle_length": point["bundle_length"], "key_id": point["key_id"], "key_epoch": point["key_epoch"], "storage_id": point["storage_id"], "ingress_database_id": point["ingress_database_id"], "core_database_id": point["core_database_id"], "ingress_head_root": point["ingress_head_root"], "core_head_root": point["core_head_root"], "ingress_watermark": point["ingress_watermark"], "core_watermark": point["core_watermark"], "publication_receipt_digest": _raw_digest("receipt", bytes(selected["receipt"])), "flags": dict(FIXED_FLAGS)}
        body["bootstrap_id"] = _digest("bootstrap-id", {key: body[key] for key in body if key not in {"bootstrap_id", "flags"}})
        raw = _canonical(body)
        if len(raw) > independent.MAX_BOOTSTRAP_BYTES:
            raise RecoveryError("recovery:bootstrap-cap")
        return raw

    def logical_export(self) -> bytes:
        return independent.logical_export(self.verify())

    def support(self) -> dict[str, object]:
        result = self.verify()
        return {"schema": "mirror-recovery-support-v3", "states": result["states"], "point_count": result["point_count"], "event_count": result["event_count"], "sequence": result["sequence"], "flags": dict(FIXED_FLAGS)}


__all__ = ["RecoveryConfigV2", "RecoveryServiceV2", "RecoveryReceipt", "RecoveryKey", "StorageReceipt", "KeyCustodyPort", "RecoveryStoragePort", "StorageNotFound", "RecoveryError", "RecoveryConflictError", "RecoveryIndeterminateError", "SCHEMA", "SCHEMA_VERSION", "TABLES", "FIXED_FLAGS", "MAX_DATABASE_BYTES", "MAX_EVENT_BYTES", "MAX_CUSTODY_OVERHEAD_BYTES", "MAX_RECOVERY_POINTS"]
