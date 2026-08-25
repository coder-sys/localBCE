"""Independent reconstruction for AUTHORITATIVE_ASSERTION V1 state data."""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Final

from app.minimal_clearance_authoritative_assertion import (
    AuthoritativeAssertionError,
    AuthoritativeAssertionResultV1,
    AuthoritativeAssertionTemplateV1,
    AuthoritativeBatchStatementV1,
    AuthoritativeIssuedOperationV1,
    LIFETIME_ACCEPTANCE_CAP,
    MEMBER_COUNT,
    MODE,
    QUALIFICATION_FLAGS,
    RESERVATION_UNITS,
    SIGNATURE_PROFILE_VERSION,
    SOURCE_AUTH_PROFILE_ID,
    VERIFIER_PROFILE_VERSION,
    parse_result,
)


class IndependentAuthoritativeAssertionError(RuntimeError):
    pass


def _fail(code: str) -> None:
    error = IndependentAuthoritativeAssertionError(code)
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    raise error


_OPERATION_COLUMNS: Final[tuple[str, ...]] = (
    "operation_ref", "batch_root", "batch_position", "assertion_identifier", "assertion_version",
    "state_profile_version", "valid_from_ms", "valid_until_ms", "approved_source_registry_root",
    "qualification_flags", "status", "updated_ms",
)
_BATCH_COLUMNS: Final[tuple[str, ...]] = (
    "batch_root", "member_count", "status", "state_profile_version", "source_auth_profile_id",
    "signature_profile_version", "source_key_epoch", "reservation_units", "reservation_before",
    "reservation_after", "created_ms", "updated_ms", "last_error_code",
)
_RESULT_COLUMNS: Final[tuple[str, ...]] = (
    "batch_root", "assertion_accepted", "receipt_bytes", "receipt_digest", "outcome_code",
    "error_code", "resource_code", "created_ms",
)
_LEDGER_COLUMNS: Final[tuple[str, ...]] = (
    "profile_id", "lifetime_cap", "computational_units_used", "statistical_units_used", "last_key_epoch",
)
_TOKEN = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")


@dataclass(frozen=True, slots=True)
class IndependentAuthoritativeAssertionJob:
    operation_ref: bytes
    batch_root: bytes
    batch_position: int
    assertion_identifier: str
    assertion_version: int
    state_profile_version: str
    valid_from_ms: int
    valid_until_ms: int
    approved_source_registry_root: bytes | None
    qualification_flags: tuple[str, ...]
    status: str
    assertion_accepted: bool


@dataclass(frozen=True, slots=True)
class IndependentAuthoritativeAssertionBatch:
    batch: AuthoritativeBatchStatementV1
    status: str
    jobs: tuple[IndependentAuthoritativeAssertionJob, ...]
    result: AuthoritativeAssertionResultV1 | None = None


def _columns(connection: sqlite3.Connection, table: str) -> tuple[str, ...]:
    return tuple(str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})"))


def _blob(value: object, size: int, code: str) -> bytes:
    if type(value) is not bytes or len(value) != size:
        _fail(code)
    return bytes(value)


def _token(value: object, code: str) -> str:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        _fail(code)
    return value


def _parse_result(raw: bytes) -> AuthoritativeAssertionResultV1:
    if type(raw) is not bytes or not raw or len(raw) > 16 * 1024:
        _fail("authoritative_receipt_bounds")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("authoritative_receipt_encoding")
    if type(value) is not dict or raw != json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii"):
        _fail("authoritative_receipt_encoding")
    try:
        result = parse_result(value)
    except AuthoritativeAssertionError:
        _fail("authoritative_receipt_shape")
    return result


def _read(connection: sqlite3.Connection, batch_root: bytes | None, expected_status: str | None) -> IndependentAuthoritativeAssertionBatch:
    if batch_root is not None:
        _blob(batch_root, 64, "authoritative_batch_root")
        batch_row = connection.execute("SELECT * FROM authoritative_batches WHERE batch_root=?", (batch_root,)).fetchone()
    else:
        batch_row = connection.execute("SELECT * FROM authoritative_batches ORDER BY created_ms,batch_root LIMIT 1").fetchone()
    if batch_row is None or len(batch_row) != len(_BATCH_COLUMNS):
        _fail("authoritative_batch_unknown")
    if _columns(connection, "authoritative_batches") != _BATCH_COLUMNS or _columns(connection, "authoritative_operations") != _OPERATION_COLUMNS or _columns(connection, "authoritative_results") != _RESULT_COLUMNS:
        _fail("authoritative_schema")
    root = _blob(bytes(batch_row[0]), 64, "authoritative_batch_root")
    member_count = int(batch_row[1])
    status = str(batch_row[2])
    if member_count != MEMBER_COUNT or status not in {"ISSUED", "RESERVED", "HELD", "APPLIED"} or (expected_status is not None and status != expected_status):
        _fail("authoritative_batch_status")
    if str(batch_row[4]) != SOURCE_AUTH_PROFILE_ID or str(batch_row[5]) != SIGNATURE_PROFILE_VERSION or int(batch_row[7]) != RESERVATION_UNITS or int(batch_row[8]) < 0 or int(batch_row[9]) not in {int(batch_row[8]), int(batch_row[8]) + RESERVATION_UNITS}:
        _fail("authoritative_reservation")
    if int(batch_row[6]) < 0 or str(batch_row[3]) != str(batch_row[3]) or _TOKEN.fullmatch(str(batch_row[3])) is None:
        _fail("authoritative_batch_profile")
    rows = [tuple(row) for row in connection.execute("SELECT * FROM authoritative_operations WHERE batch_root=? ORDER BY batch_position", (root,)).fetchall()]
    if len(rows) != MEMBER_COUNT or any(len(row) != len(_OPERATION_COLUMNS) for row in rows):
        _fail("authoritative_batch_cardinality")
    statements: list[AuthoritativeIssuedOperationV1] = []
    jobs: list[IndependentAuthoritativeAssertionJob] = []
    for expected_position, row in enumerate(rows):
        ref = _blob(row[0], 32, "authoritative_operation_ref")
        row_root = _blob(row[1], 64, "authoritative_operation_root")
        position = int(row[2])
        if row_root != root or position != expected_position:
            _fail("authoritative_batch_order")
        flags_raw = _blob(row[9], len(b"authoritative_assertion_v1"), "authoritative_flags")
        if flags_raw != b"authoritative_assertion_v1":
            _fail("authoritative_flags")
        registry = None if row[8] is None else _blob(row[8], 64, "authoritative_registry_root")
        template = AuthoritativeAssertionTemplateV1(str(row[3]), int(row[4]), str(row[5]), int(row[6]), int(row[7]), registry)
        statement = AuthoritativeIssuedOperationV1(ref, template, position, root)
        op_status = str(row[10])
        if op_status != status or op_status not in {"ISSUED", "RESERVED", "HELD", "APPLIED"}:
            _fail("authoritative_mixed_batch")
        statements.append(statement)
        jobs.append(IndependentAuthoritativeAssertionJob(ref, root, position, template.assertion_identifier, template.assertion_version, template.state_profile_version, template.valid_from_ms, template.valid_until_ms, registry, QUALIFICATION_FLAGS, op_status, status == "APPLIED"))
    batch = AuthoritativeBatchStatementV1(tuple(statements), root, int(batch_row[6]))
    result: AuthoritativeAssertionResultV1 | None = None
    result_row = connection.execute("SELECT * FROM authoritative_results WHERE batch_root=?", (root,)).fetchone()
    if status == "APPLIED":
        if result_row is None or int(result_row[1]) != 1 or result_row[2] is None or result_row[3] is None:
            _fail("authoritative_result_missing")
        receipt = bytes(result_row[2])
        result = _parse_result(receipt)
        if not result.assertion_accepted or result.batch_root != root or bytes(result_row[3]) != result.receipt_digest:
            _fail("authoritative_result_binding")
    elif status in {"ISSUED", "RESERVED"}:
        if result_row is not None:
            _fail("authoritative_result_unexpected")
    elif status == "HELD":
        if result_row is not None:
            if int(result_row[1]) != 0 or result_row[2] is None or result_row[3] is None:
                _fail("authoritative_result_missing")
            result = _parse_result(bytes(result_row[2]))
            if result.batch_root != root or result.assertion_accepted or bytes(result_row[3]) != result.receipt_digest:
                _fail("authoritative_result_binding")
    return IndependentAuthoritativeAssertionBatch(batch, status, tuple(jobs), result)


def read_authoritative_batch(path: Path, batch_root: bytes | None = None, *, expected_status: str | None = None) -> IndependentAuthoritativeAssertionBatch:
    if not isinstance(path, Path) or not path.is_file() or path.is_symlink():
        _fail("authoritative_database_path")
    try:
        with closing(sqlite3.connect(str(path), timeout=5.0)) as connection:
            return _read(connection, batch_root, expected_status)
    except sqlite3.Error:
        _fail("authoritative_database_sqlite")


def verify_authoritative_database(path: Path) -> dict[str, Any]:
    if not isinstance(path, Path) or not path.is_file() or path.is_symlink():
        _fail("authoritative_database_path")
    try:
        with closing(sqlite3.connect(str(path), timeout=5.0)) as connection:
            if _columns(connection, "authoritative_profile_ledger") != _LEDGER_COLUMNS:
                _fail("authoritative_schema")
            ledger = connection.execute("SELECT * FROM authoritative_profile_ledger WHERE profile_id=?", (SOURCE_AUTH_PROFILE_ID,)).fetchone()
            if ledger is None or int(ledger[1]) != LIFETIME_ACCEPTANCE_CAP or int(ledger[2]) < 0 or int(ledger[3]) != 0 or int(ledger[4]) < 0 or int(ledger[2]) > int(ledger[1]):
                _fail("authoritative_ledger")
            roots = [bytes(row[0]) for row in connection.execute("SELECT batch_root FROM authoritative_batches ORDER BY created_ms,batch_root").fetchall()]
            for root in roots:
                _read(connection, root, None)
            return {"mode": MODE, "batch_count": len(roots), "lifetime_cap": LIFETIME_ACCEPTANCE_CAP, "computational_units_used": int(ledger[2]), "statistical_units_used": int(ledger[3]), "proof_suite_id": None, "production_usable": False, "activation": False}
    except sqlite3.Error:
        _fail("authoritative_database_sqlite")


__all__ = ("IndependentAuthoritativeAssertionBatch", "IndependentAuthoritativeAssertionError", "IndependentAuthoritativeAssertionJob", "read_authoritative_batch", "verify_authoritative_database")
