"""Deterministic state-owned export and fresh-database restore for the local candidate."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import threading
import time
from contextlib import contextmanager
from typing import Mapping

from app.mirror import continuity_store as store
from app.mirror import continuity_store_independent as independent
from app.mirror import contract_mirror as contract_mirror
from app.mirror import contract_mirror_independent as contract_mirror_independent
from app.mirror import discrepancy_case as discrepancy_case
from app.mirror import discrepancy_case_independent as discrepancy_case_independent
from app.mirror import denominator_ledger as denominator_ledger
from app.mirror import denominator_ledger_independent as denominator_ledger_independent
from app.mirror import source_evidence_custody as source_custody
from app.mirror import source_evidence_custody_independent as source_custody_independent
from app.mirror import source_reconciliation as source_reconciliation
from app.mirror import source_reconciliation_independent as source_reconciliation_independent
from app.mirror import transaction_mirror as transaction_mirror
from app.mirror import transaction_mirror_independent as transaction_mirror_independent


EXPORT_SCHEMA = "mirror-continuity-state-export-v2"
EXPORT_DOMAIN = "BL/MIRROR/CONTINUITY-EXPORT-V2/"
MAX_EXPORT_BYTES = 20 * 1024 * 1024
MAX_EXPORT_ARTIFACTS = 16
MAX_EXPORT_EVENTS = 32
MAX_EXPORT_RECEIPTS = 32
MAX_HEX_BYTES = 2 * store.MAX_ARTIFACT_BYTES

EXPORT_KEYS = {
    "schema",
    "schema_version",
    "software",
    "meta",
    "artifacts",
    "operations",
    "receipts",
    "events",
    "heads",
    "state_root",
    "state_owned",
    "support_safe",
    "synthetic_only",
    "production_usable",
    "export_root",
}
ROW_KEYS = {
    "meta": {"key", "value"},
    "artifacts": set(independent.TABLE_COLUMNS["artifacts"]) - {"payload"} | {"payload_hex"},
    "operations": set(independent.TABLE_COLUMNS["operations"]),
    "receipts": set(independent.TABLE_COLUMNS["receipts"]) - {"receipt"} | {"receipt_hex"},
    "events": set(independent.TABLE_COLUMNS["events"]),
    "heads": set(independent.TABLE_COLUMNS["heads"]),
}


class ContinuityExportError(ValueError):
    pass


class InjectedRestoreFault(ContinuityExportError):
    """Private test-only restore interruption."""


RESTORE_STAGE_SCHEMA = "mirror-continuity-restore-stage-v1"
RESTORE_STAGE_VERSION = 1
RESTORE_STAGE_DOMAIN = "BL/MIRROR/CONTINUITY-RESTORE-V1/"
RESTORE_STAGE_MARKER_BYTES = 2048
RESTORE_WAIT_ATTEMPTS = 40
RESTORE_WAIT_SECONDS = 0.025
MAX_RESTORE_STAGE_CANDIDATES = 64
RESTORE_FAULT_POINTS = (
    "before_staging_creation",
    "after_empty_staging_db_creation",
    "after_snapshot_transaction",
    "after_independent_verification_checkpoint",
    "after_atomic_publication_before_response",
)
_restore_fault_point: str | None = None
_restore_locks_guard = threading.Lock()
MAX_RESTORE_LOCKS = 64


class _RestoreLockEntry:
    __slots__ = ("lock", "users")

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.users = 0


_restore_locks: dict[str, _RestoreLockEntry] = {}


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise ContinuityExportError("export:noncanonical-value") from exc


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((EXPORT_DOMAIN + label + "/v2\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _module_identity(path: str | Path) -> str:
    raw = Path(path).read_bytes()
    digest = hashlib.sha3_512()
    digest.update((EXPORT_DOMAIN + "MODULE-SOURCE/v2\0").encode("ascii"))
    digest.update(raw)
    return digest.hexdigest()


SOFTWARE_IDENTITIES = {
    "store_module_identity": _module_identity(store.__file__),
    "independent_module_identity": _module_identity(independent.__file__),
    "source_custody_module_identity": _module_identity(source_custody.__file__),
    "source_custody_independent_identity": _module_identity(source_custody_independent.__file__),
    "source_reconciliation_module_identity": _module_identity(source_reconciliation.__file__),
    "source_reconciliation_independent_identity": _module_identity(source_reconciliation_independent.__file__),
    "discrepancy_case_module_identity": _module_identity(discrepancy_case.__file__),
    "discrepancy_case_independent_identity": _module_identity(discrepancy_case_independent.__file__),
    "denominator_ledger_module_identity": _module_identity(denominator_ledger.__file__),
    "denominator_ledger_independent_identity": _module_identity(denominator_ledger_independent.__file__),
    "contract_mirror_module_identity": _module_identity(contract_mirror.__file__),
    "contract_mirror_independent_identity": _module_identity(contract_mirror_independent.__file__),
    "transaction_mirror_module_identity": _module_identity(transaction_mirror.__file__),
    "transaction_mirror_independent_identity": _module_identity(transaction_mirror_independent.__file__),
    "export_module_identity": _module_identity(__file__),
}


def _decode_hex(value: object, label: str, *, maximum: int) -> bytes:
    if not isinstance(value, str) or len(value) % 2 or len(value) > maximum * 2:
        raise ContinuityExportError(f"export:{label}-hex")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ContinuityExportError(f"export:{label}-hex") from exc
    if raw.hex() != value:
        raise ContinuityExportError(f"export:{label}-canonical")
    return raw


def _encode_rows(rows: Mapping[str, list[Mapping[str, object]]]) -> dict[str, list[dict[str, object]]]:
    result: dict[str, list[dict[str, object]]] = {}
    for table in independent.SNAPSHOT_TABLES:
        output: list[dict[str, object]] = []
        for source in rows[table]:
            item = dict(source)
            if table == "artifacts":
                payload = item.pop("payload")
                if type(payload) is not bytes:
                    raise ContinuityExportError("export:artifact-bytes")
                item["payload_hex"] = payload.hex()
            elif table == "receipts":
                receipt = item.pop("receipt")
                if type(receipt) is not bytes:
                    raise ContinuityExportError("export:receipt-bytes")
                item["receipt_hex"] = receipt.hex()
            if set(item) != ROW_KEYS[table]:
                raise ContinuityExportError(f"export:{table}-keys")
            output.append(item)
        result[table] = output
    return result


def _decode_rows(value: Mapping[str, object]) -> dict[str, list[dict[str, object]]]:
    result: dict[str, list[dict[str, object]]] = {}
    caps = {
        "meta": 2,
        "artifacts": MAX_EXPORT_ARTIFACTS,
        "operations": MAX_EXPORT_EVENTS,
        "receipts": MAX_EXPORT_RECEIPTS,
        "events": MAX_EXPORT_EVENTS,
        "heads": MAX_EXPORT_ARTIFACTS,
    }
    for table in independent.SNAPSHOT_TABLES:
        rows = value[table]
        if not isinstance(rows, list) or len(rows) > caps.get(table, MAX_EXPORT_ARTIFACTS):
            raise ContinuityExportError(f"export:{table}-count")
        decoded: list[dict[str, object]] = []
        for item in rows:
            if not isinstance(item, dict) or set(item) != ROW_KEYS[table]:
                raise ContinuityExportError(f"export:{table}-keys")
            row = dict(item)
            for key in ("event_sequence", "sequence"):
                if key in row and type(row[key]) is not int:
                    raise ContinuityExportError(f"export:{table}-integer")
            if table == "artifacts":
                row["payload"] = _decode_hex(row.pop("payload_hex"), "artifact", maximum=store.MAX_ARTIFACT_BYTES)
            elif table == "receipts":
                row["receipt"] = _decode_hex(row.pop("receipt_hex"), "receipt", maximum=store.MAX_RECEIPT_BYTES)
            decoded.append(row)
        result[table] = decoded
    if result["meta"] != sorted(result["meta"], key=lambda item: str(item["key"])):
        raise ContinuityExportError("export:meta-order")
    if result["artifacts"] != sorted(result["artifacts"], key=lambda item: (str(item["kind"]), str(item["artifact_id"]))):
        raise ContinuityExportError("export:artifact-order")
    if result["operations"] != sorted(result["operations"], key=lambda item: int(item["event_sequence"])):
        raise ContinuityExportError("export:operation-order")
    if result["receipts"] != sorted(result["receipts"], key=lambda item: str(item["operation_id"])):
        raise ContinuityExportError("export:receipt-order")
    if result["events"] != sorted(result["events"], key=lambda item: int(item["sequence"])):
        raise ContinuityExportError("export:event-order")
    if result["heads"] != sorted(result["heads"], key=lambda item: str(item["chain_id"])):
        raise ContinuityExportError("export:head-order")
    return result


def _decode_and_verify(
    raw: bytes,
    *,
    graph_profile_registry: Mapping[str, object] | None = None,
) -> tuple[dict[str, object], dict[str, list[dict[str, object]]], dict[str, object]]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_EXPORT_BYTES:
        raise ContinuityExportError("export:byte-cap")
    try:
        value = independent._parse_canonical(raw, maximum=MAX_EXPORT_BYTES, max_string_bytes=MAX_HEX_BYTES * 2)
    except independent.IndependentStoreError as exc:
        raise ContinuityExportError(str(exc)) from exc
    if set(value) != EXPORT_KEYS:
        raise ContinuityExportError("export:keys")
    if value["schema"] != EXPORT_SCHEMA or type(value["schema_version"]) is not int or value["schema_version"] != store.SCHEMA_VERSION:
        raise ContinuityExportError("export:schema")
    if value["software"] != SOFTWARE_IDENTITIES:
        raise ContinuityExportError("export:software")
    if value["state_owned"] is not True or value["support_safe"] is not False or value["synthetic_only"] is not True or value["production_usable"] is not False:
        raise ContinuityExportError("export:authority-flags")
    if not isinstance(value["state_root"], str) or not independent._HEX128.fullmatch(value["state_root"]):
        raise ContinuityExportError("export:state-root")
    snapshot = _decode_rows(value)
    try:
        result = independent.verify_snapshot(snapshot, graph_profile_registry=graph_profile_registry)
    except independent.IndependentStoreError as exc:
        raise ContinuityExportError(f"export:state:{exc}") from exc
    if result["state_root"] != value["state_root"]:
        raise ContinuityExportError("export:state-root-binding")
    body = dict(value)
    body.pop("export_root")
    if value["export_root"] != _digest("export-root", body):
        raise ContinuityExportError("export:root")
    return value, snapshot, result


def _restore_fault(point: str) -> None:
    global _restore_fault_point
    if _restore_fault_point == point:
        _restore_fault_point = None
        raise InjectedRestoreFault(f"restore:injected:{point}")


def _restore_destination(destination: str | Path) -> Path:
    if not isinstance(destination, (str, Path)):
        raise ContinuityExportError("restore:destination")
    try:
        value = os.fspath(destination)
    except TypeError as exc:
        raise ContinuityExportError("restore:destination") from exc
    if isinstance(value, bytes):
        raise ContinuityExportError("restore:destination")
    target = Path(value)
    if not target.is_absolute():
        target = Path.cwd() / target
    target = Path(os.path.abspath(os.fspath(target)))
    if not target.name or len(target.name.encode("utf-8")) > 128:
        raise ContinuityExportError("restore:target-name")
    parent = target.parent
    if not os.path.lexists(os.fspath(parent)):
        raise ContinuityExportError("restore:parent-missing")
    if parent.is_symlink() or not parent.is_dir():
        raise ContinuityExportError("restore:parent-object")
    if os.path.lexists(os.fspath(target)) and (target.is_symlink() or target.is_dir() or not target.is_file()):
        raise ContinuityExportError("restore:target-object")
    return target


def _restore_sidecar(path: Path, suffix: str, label: str) -> Path | None:
    sidecar = Path(str(path) + suffix)
    if not os.path.lexists(os.fspath(sidecar)):
        return None
    if sidecar.is_symlink() or sidecar.is_dir() or not sidecar.is_file():
        raise ContinuityExportError(f"restore:{label}-sidecar-object")
    try:
        size = sidecar.stat().st_size
    except OSError as exc:
        raise ContinuityExportError(f"restore:{label}-sidecar") from exc
    if size > store.MAX_WAL_BYTES:
        raise ContinuityExportError(f"restore:{label}-sidecar-cap")
    return sidecar


def _restore_sidecars(path: Path, label: str) -> tuple[Path | None, Path | None]:
    return (
        _restore_sidecar(path, "-wal", label),
        _restore_sidecar(path, "-shm", label),
    )


def _restore_reject_destination_sidecars(target: Path) -> None:
    wal, shm = _restore_sidecars(target, "target")
    if wal is not None or shm is not None:
        raise ContinuityExportError("restore:target-sidecar-existing")


def _restore_stage_paths(target: Path, export_root: str) -> tuple[Path, Path]:
    if not independent._HEX128.fullmatch(export_root):
        raise ContinuityExportError("restore:stage-identity")
    stage = target.with_name(f".{target.name}.restore-v1-{export_root}.db")
    marker = Path(str(stage) + ".marker")
    if len(stage.name.encode("utf-8")) > 220:
        raise ContinuityExportError("restore:stage-name")
    return stage, marker


def _restore_reject_foreign_stage_artifacts(target: Path, stage: Path, marker: Path) -> None:
    prefix = os.path.normcase(f".{target.name}.restore-v1-")
    known = {
        os.path.normcase(stage.name),
        os.path.normcase(stage.name + "-wal"),
        os.path.normcase(stage.name + "-shm"),
        os.path.normcase(marker.name),
        os.path.normcase(_restore_lock_path(marker).name),
    }
    candidates = 0
    try:
        for item in target.parent.iterdir():
            if not os.path.normcase(item.name).startswith(prefix):
                continue
            candidates += 1
            if candidates > MAX_RESTORE_STAGE_CANDIDATES:
                raise ContinuityExportError("restore:staging-directory-cap")
            if os.path.normcase(item.name) not in known:
                raise ContinuityExportError("restore:staging-foreign")
    except ContinuityExportError:
        raise
    except OSError as exc:
        raise ContinuityExportError("restore:staging-scan") from exc


def _restore_marker_value(target: Path, stage: Path, value: Mapping[str, object]) -> dict[str, object]:
    return {
        "schema": RESTORE_STAGE_SCHEMA,
        "schema_version": RESTORE_STAGE_VERSION,
        "export_root": value["export_root"],
        "state_root": value["state_root"],
        "target_name": target.name,
        "stage_name": stage.name,
    }


def _restore_marker_bytes(target: Path, stage: Path, value: Mapping[str, object]) -> bytes:
    return _canonical(_restore_marker_value(target, stage, value))


def _restore_lock_path(marker: Path) -> Path:
    return Path(str(marker) + ".lock")


def _restore_lock_value(target: Path, stage: Path, value: Mapping[str, object]) -> dict[str, object]:
    return {
        "schema": RESTORE_STAGE_SCHEMA,
        "schema_version": RESTORE_STAGE_VERSION,
        "export_root": value["export_root"],
        "state_root": value["state_root"],
        "target_name": target.name,
        "stage_name": stage.name,
        "purpose": "restore-coordination",
    }


def _restore_lock_bytes(target: Path, stage: Path, value: Mapping[str, object]) -> bytes:
    return _canonical(_restore_lock_value(target, stage, value))


def _restore_validate_lock(stream, lock_path: Path, target: Path, stage: Path, value: Mapping[str, object]) -> None:
    expected = _restore_lock_bytes(target, stage, value)
    try:
        stream.seek(0)
        raw = stream.read(len(expected))
        size = os.fstat(stream.fileno()).st_size
    except OSError as exc:
        raise ContinuityExportError("restore:lock-read") from exc
    if raw != expected or size != len(expected) + 1 or len(raw) > RESTORE_STAGE_MARKER_BYTES:
        raise ContinuityExportError("restore:lock-binding")


@contextmanager
def _restore_stage_process_lock(target: Path, stage: Path, marker: Path, value: Mapping[str, object]):
    """Hold a deterministic OS lock so separate restore processes cannot race SQLite startup."""

    lock_path = _restore_lock_path(marker)
    expected = _restore_lock_bytes(target, stage, value)
    lock_bytes = expected + b"\0"
    stream = None
    descriptor = -1
    try:
        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_BINARY", 0)
        created = True
        try:
            descriptor = os.open(os.fspath(lock_path), flags, 0o600)
        except FileExistsError:
            created = False
            descriptor = os.open(os.fspath(lock_path), os.O_RDWR | getattr(os, "O_BINARY", 0))
        stream = os.fdopen(descriptor, "r+b", buffering=0)
        descriptor = -1
        if created:
            stream.write(lock_bytes)
            stream.flush()
            os.fsync(stream.fileno())
        else:
            for attempt in range(RESTORE_WAIT_ATTEMPTS):
                if os.fstat(stream.fileno()).st_size != 0:
                    break
                if attempt + 1 < RESTORE_WAIT_ATTEMPTS:
                    time.sleep(RESTORE_WAIT_SECONDS)
        _restore_validate_lock(stream, lock_path, target, stage, value)
        locked = False
        for attempt in range(RESTORE_WAIT_ATTEMPTS):
            stream.seek(len(expected))
            try:
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except (OSError, PermissionError):
                if attempt + 1 < RESTORE_WAIT_ATTEMPTS:
                    time.sleep(RESTORE_WAIT_SECONDS)
                    continue
                raise ContinuityExportError("restore:lock-busy")
        if not locked:
            raise ContinuityExportError("restore:lock-busy")
        try:
            yield
        finally:
            try:
                stream.seek(len(expected))
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
            finally:
                stream.close()
                stream = None
    except Exception:
        if stream is not None:
            stream.close()
            stream = None
        raise
    finally:
        if descriptor != -1:
            os.close(descriptor)


def _restore_validate_marker(marker: Path, target: Path, stage: Path, value: Mapping[str, object]) -> None:
    if marker.is_symlink() or marker.is_dir() or not marker.is_file():
        raise ContinuityExportError("restore:staging-marker-object")
    try:
        raw = marker.read_bytes()
    except OSError as exc:
        raise ContinuityExportError("restore:staging-marker") from exc
    if not raw or len(raw) > RESTORE_STAGE_MARKER_BYTES:
        raise ContinuityExportError("restore:staging-marker-cap")
    try:
        parsed = independent._parse_canonical(raw, maximum=RESTORE_STAGE_MARKER_BYTES, max_string_bytes=512)
    except independent.IndependentStoreError as exc:
        raise ContinuityExportError("restore:staging-marker") from exc
    expected = _restore_marker_value(target, stage, value)
    if parsed != expected or raw != _canonical(expected):
        raise ContinuityExportError("restore:staging-marker-binding")


def _restore_create_marker(marker: Path, target: Path, stage: Path, value: Mapping[str, object]) -> bool:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(os.fspath(marker), flags, 0o600)
    except FileExistsError:
        return False
    try:
        raw = _restore_marker_bytes(target, stage, value)
        if len(raw) > RESTORE_STAGE_MARKER_BYTES:
            raise ContinuityExportError("restore:staging-marker-cap")
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        if descriptor != -1:
            os.close(descriptor)
        raise
    return True


def _restore_wait_for_stage(stage: Path, marker: Path) -> None:
    for _ in range(RESTORE_WAIT_ATTEMPTS):
        if os.path.lexists(os.fspath(stage)):
            return
        if not os.path.lexists(os.fspath(marker)):
            raise ContinuityExportError("restore:staging-state")
        time.sleep(RESTORE_WAIT_SECONDS)
    raise ContinuityExportError("restore:staging-incomplete")


def _restore_stage_classification(
    stage: Path,
    raw: bytes,
    expected: Mapping[str, object],
    graph_profile_registry: Mapping[str, object] | None = None,
) -> tuple[str, dict[str, object]]:
    if stage.is_symlink() or stage.is_dir() or not stage.is_file():
        raise ContinuityExportError("restore:staging-object")
    _restore_sidecars(stage, "staging")
    actual: dict[str, object] | None = None
    last_error: independent.IndependentStoreError | None = None
    for attempt in range(RESTORE_WAIT_ATTEMPTS):
        try:
            actual = independent.verify_database(stage, graph_profile_registry=graph_profile_registry)
            break
        except independent.IndependentStoreError as exc:
            last_error = exc
            if attempt + 1 < RESTORE_WAIT_ATTEMPTS:
                time.sleep(RESTORE_WAIT_SECONDS)
    if actual is None:
        raise ContinuityExportError("restore:staging-invalid") from last_error
    if actual == expected:
        try:
            if export_database(stage, graph_profile_registry=graph_profile_registry) != raw:
                raise ContinuityExportError("restore:staging-export-mismatch")
        except ContinuityExportError:
            raise
        except Exception as exc:
            raise ContinuityExportError("restore:staging-export-mismatch") from exc
        return "verified", actual
    if all(actual.get(key) == 0 for key in ("artifact_count", "event_count", "receipt_count", "head_count")):
        return "empty", actual
    raise ContinuityExportError("restore:staging-conflict")


def _restore_checkpoint(stage: Path) -> None:
    for attempt in range(RESTORE_WAIT_ATTEMPTS):
        connection: sqlite3.Connection | None = None
        busy = False
        try:
            connection = sqlite3.connect(stage, timeout=store.BUSY_TIMEOUT_MS / 1000, isolation_level=None)
            connection.execute(f"PRAGMA busy_timeout={store.BUSY_TIMEOUT_MS}")
            connection.execute("PRAGMA synchronous=FULL")
            row = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            busy = row is not None and int(row[0]) != 0
        except sqlite3.OperationalError:
            busy = True
        except (sqlite3.DatabaseError, OSError) as exc:
            raise ContinuityExportError("restore:staging-checkpoint") from exc
        finally:
            if connection is not None:
                connection.close()
        try:
            wal, shm = _restore_sidecars(stage, "staging")
            sidecars_clear = all(sidecar is None or sidecar.stat().st_size == 0 for sidecar in (wal, shm))
        except OSError:
            sidecars_clear = False
        if not busy and sidecars_clear:
            return
        if attempt + 1 < RESTORE_WAIT_ATTEMPTS:
            time.sleep(RESTORE_WAIT_SECONDS)
    raise ContinuityExportError("restore:staging-sidecar-nonempty")


def _restore_prepare_stage(
    target: Path,
    value: Mapping[str, object],
    raw: bytes,
    snapshot: Mapping[str, list[Mapping[str, object]]],
    expected: Mapping[str, object],
    graph_profile_registry: Mapping[str, object] | None = None,
) -> tuple[Path, Path, dict[str, object]]:
    stage, marker = _restore_stage_paths(target, str(value["export_root"]))
    stage_exists = os.path.lexists(os.fspath(stage))
    marker_exists = os.path.lexists(os.fspath(marker))
    stage_wal, stage_shm = _restore_sidecars(stage, "staging")
    if not marker_exists and (stage_exists or stage_wal is not None or stage_shm is not None):
        raise ContinuityExportError("restore:staging-state")
    if marker_exists:
        _restore_validate_marker(marker, target, stage, value)
        _restore_wait_for_stage(stage, marker)
    else:
        _restore_fault("before_staging_creation")
        if not _restore_create_marker(marker, target, stage, value):
            _restore_validate_marker(marker, target, stage, value)
            _restore_wait_for_stage(stage, marker)
        try:
            store.ContinuityStore(stage, graph_profile_registry=graph_profile_registry)
        except (store.ContinuityStoreError, OSError) as exc:
            raise ContinuityExportError("restore:staging-create") from exc
        _restore_fault("after_empty_staging_db_creation")
    state, actual = _restore_stage_classification(stage, raw, expected, graph_profile_registry)
    if state == "empty":
        try:
            restored = store.ContinuityStore(stage, graph_profile_registry=graph_profile_registry)
            restored._restore_snapshot(snapshot)
        except store.StoreConflictError:
            state, actual = _restore_stage_classification(stage, raw, expected, graph_profile_registry)
            if state != "verified":
                raise ContinuityExportError("restore:staging-race")
        except (store.ContinuityStoreError, OSError) as exc:
            raise ContinuityExportError("restore:staging-write") from exc
        _restore_fault("after_snapshot_transaction")
        state, actual = _restore_stage_classification(stage, raw, expected, graph_profile_registry)
    if state != "verified":
        raise ContinuityExportError("restore:staging-verification")
    _restore_checkpoint(stage)
    _restore_fault("after_independent_verification_checkpoint")
    state, actual = _restore_stage_classification(stage, raw, expected, graph_profile_registry)
    if state != "verified":
        raise ContinuityExportError("restore:staging-verification")
    _restore_checkpoint(stage)
    return stage, marker, actual


def _restore_cleanup_owned_stage(
    stage: Path,
    marker: Path,
    target: Path,
    value: Mapping[str, object],
    raw: bytes,
    expected: Mapping[str, object],
    graph_profile_registry: Mapping[str, object] | None = None,
) -> None:
    if os.path.lexists(os.fspath(marker)):
        _restore_validate_marker(marker, target, stage, value)
    if os.path.lexists(os.fspath(stage)):
        state, _actual = _restore_stage_classification(stage, raw, expected, graph_profile_registry)
        if state != "verified":
            raise ContinuityExportError("restore:staging-conflict")
        _restore_checkpoint(stage)
        for sidecar in _restore_sidecars(stage, "staging"):
            if sidecar is not None and sidecar.stat().st_size != 0:
                raise ContinuityExportError("restore:staging-sidecar-nonempty")
            if sidecar is not None:
                sidecar.unlink()
        stage.unlink()
    if os.path.lexists(os.fspath(marker)):
        marker.unlink()


def _restore_existing_target(
    target: Path,
    stage: Path,
    marker: Path,
    value: Mapping[str, object],
    raw: bytes,
    expected: Mapping[str, object],
    graph_profile_registry: Mapping[str, object] | None = None,
) -> dict[str, object] | None:
    if not os.path.lexists(os.fspath(target)):
        return None
    if target.is_symlink() or target.is_dir() or not target.is_file():
        raise ContinuityExportError("restore:target-object")
    _restore_sidecars(target, "target")
    for sidecar in _restore_sidecars(target, "target"):
        if sidecar is not None and sidecar.stat().st_size != 0:
            raise ContinuityExportError("restore:target-sidecar-nonempty")
    stage_exists = os.path.lexists(os.fspath(stage))
    marker_exists = os.path.lexists(os.fspath(marker))
    if stage_exists or marker_exists or _restore_sidecars(stage, "staging") != (None, None):
        if not marker_exists:
            raise ContinuityExportError("restore:staging-state")
        _restore_validate_marker(marker, target, stage, value)
        if stage_exists:
            _restore_stage_classification(stage, raw, expected, graph_profile_registry)
    try:
        actual = independent.verify_database(target, graph_profile_registry=graph_profile_registry)
        current = export_database(target, graph_profile_registry=graph_profile_registry)
    except Exception as exc:
        raise ContinuityExportError("restore:target-conflict") from exc
    if current != raw or actual != expected:
        raise ContinuityExportError("restore:target-conflict")
    if marker_exists:
        try:
            _restore_cleanup_owned_stage(stage, marker, target, value, raw, expected, graph_profile_registry)
        except OSError:
            pass
    return {"accepted": True, "restored": True, **actual}


def _restore_publish_no_clobber(stage: Path, target: Path) -> bool:
    for attempt in range(RESTORE_WAIT_ATTEMPTS):
        try:
            os.rename(stage, target)
            return True
        except FileExistsError:
            return False
        except OSError as exc:
            if os.path.lexists(os.fspath(target)):
                return False
            if attempt + 1 < RESTORE_WAIT_ATTEMPTS:
                time.sleep(RESTORE_WAIT_SECONDS)
                continue
            raise ContinuityExportError("restore:publish") from exc
    raise ContinuityExportError("restore:publish")


@contextmanager
def _restore_lock_for(target: Path):
    key = os.path.normcase(os.fspath(target))
    with _restore_locks_guard:
        entry = _restore_locks.get(key)
        if entry is None:
            if len(_restore_locks) >= MAX_RESTORE_LOCKS:
                raise ContinuityExportError("restore:lock-cap")
            entry = _RestoreLockEntry()
            _restore_locks[key] = entry
        entry.users += 1
    acquired = False
    try:
        entry.lock.acquire()
        acquired = True
        yield
    finally:
        if acquired:
            entry.lock.release()
        with _restore_locks_guard:
            entry.users -= 1
            if entry.users == 0 and _restore_locks.get(key) is entry:
                del _restore_locks[key]


def _restore_import_locked_body(
    raw: bytes,
    value: Mapping[str, object],
    snapshot: Mapping[str, list[Mapping[str, object]]],
    expected: Mapping[str, object],
    target: Path,
    stage: Path,
    marker: Path,
    graph_profile_registry: Mapping[str, object] | None = None,
) -> dict[str, object]:
    existing = _restore_existing_target(target, stage, marker, value, raw, expected, graph_profile_registry)
    if existing is not None:
        return existing
    _restore_reject_destination_sidecars(target)
    stage, marker, _actual = _restore_prepare_stage(target, value, raw, snapshot, expected, graph_profile_registry)
    _restore_sidecars(stage, "staging")
    if os.path.lexists(os.fspath(target)):
        existing = _restore_existing_target(target, stage, marker, value, raw, expected, graph_profile_registry)
        if existing is not None:
            return existing
        raise ContinuityExportError("restore:target-conflict")
    if not _restore_publish_no_clobber(stage, target):
        existing = _restore_existing_target(target, stage, marker, value, raw, expected, graph_profile_registry)
        if existing is not None:
            return existing
        raise ContinuityExportError("restore:target-conflict")
    _restore_fault("after_atomic_publication_before_response")
    result = _restore_existing_target(target, stage, marker, value, raw, expected, graph_profile_registry)
    if result is None:
        raise ContinuityExportError("restore:published-missing")
    return result


def _restore_import_locked(
    raw: bytes,
    value: Mapping[str, object],
    snapshot: Mapping[str, list[Mapping[str, object]]],
    expected: Mapping[str, object],
    target: Path,
    graph_profile_registry: Mapping[str, object] | None = None,
) -> dict[str, object]:
    stage, marker = _restore_stage_paths(target, str(value["export_root"]))
    _restore_reject_foreign_stage_artifacts(target, stage, marker)
    with _restore_stage_process_lock(target, stage, marker, value):
        _restore_reject_foreign_stage_artifacts(target, stage, marker)
        result = _restore_import_locked_body(raw, value, snapshot, expected, target, stage, marker, graph_profile_registry)
    # The deterministic coordination file is retained as a canonical,
    # non-sensitive recovery sentinel. Its byte-range lock is released by the
    # context manager, including on process death; removing it would race a
    # peer that has already opened it for the same retry.
    return result


def verify_export_bytes(
    raw: bytes,
    graph_profile_registry: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Independently verify a complete canonical portability artifact."""

    _value, _snapshot, result = _decode_and_verify(raw, graph_profile_registry=graph_profile_registry)
    return {
        "accepted": True,
        "schema_version": store.SCHEMA_VERSION,
        "artifact_count": result["artifact_count"],
        "event_count": result["event_count"],
        "receipt_count": result["receipt_count"],
        "head_count": result["head_count"],
        "export_bytes": len(raw),
    }


def export_database(
    path: str | Path,
    graph_profile_registry: Mapping[str, object] | None = None,
) -> bytes:
    """Export exactly the independently verified state of one candidate database."""

    verified = independent.verify_database(path, graph_profile_registry=graph_profile_registry)
    source_store = store.ContinuityStore(path, graph_profile_registry=graph_profile_registry)
    rows = _encode_rows(source_store._snapshot_rows())
    body: dict[str, object] = {
        "schema": EXPORT_SCHEMA,
        "schema_version": store.SCHEMA_VERSION,
        "software": dict(SOFTWARE_IDENTITIES),
        **rows,
        "state_root": verified["state_root"],
        "state_owned": True,
        "support_safe": False,
        "synthetic_only": True,
        "production_usable": False,
    }
    value = {**body, "export_root": _digest("export-root", body)}
    raw = _canonical(value)
    if len(raw) > MAX_EXPORT_BYTES:
        raise ContinuityExportError("export:byte-cap")
    verify_export_bytes(raw, graph_profile_registry=graph_profile_registry)
    return raw


def import_export(
    raw: bytes,
    destination: str | Path,
    graph_profile_registry: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Restore a verified export through a deterministic, no-clobber stage."""

    value, snapshot, expected = _decode_and_verify(raw, graph_profile_registry=graph_profile_registry)
    target = _restore_destination(destination)
    with _restore_lock_for(target):
        return _restore_import_locked(raw, value, snapshot, expected, target, graph_profile_registry)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("REJECT usage", file=sys.stderr)
        return 2
    try:
        raw = Path(args[0]).read_bytes()
        print(_canonical(verify_export_bytes(raw)).decode("ascii"))
        return 0
    except Exception as exc:
        print(f"REJECT {type(exc).__name__}:{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
