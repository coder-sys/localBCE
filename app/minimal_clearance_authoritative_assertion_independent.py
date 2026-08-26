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
    compute_reservation_after,
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
    "reservation_after", "cryptographic_attempted", "verification_time_ms", "created_ms", "updated_ms",
    "last_error_code",
)
_RESULT_COLUMNS: Final[tuple[str, ...]] = (
    "batch_root", "assertion_accepted", "receipt_bytes", "receipt_digest", "outcome_code",
    "error_code", "created_ms",
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
    reservation_before: int
    reservation_after: int
    cryptographic_attempted: bool
    verification_time_ms: int | None
    created_ms: int
    last_error_code: str | None
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


def _integer(value: object, code: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
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


def _result_row_matches(row: tuple[Any, ...], parsed: AuthoritativeAssertionResultV1) -> bool:
    return (
        len(row) == len(_RESULT_COLUMNS)
        and type(row[1]) is int
        and bytes(row[0]) == parsed.batch_root
        and int(row[1]) == int(parsed.assertion_accepted)
        and row[2] is not None
        and bytes(row[3]) == parsed.receipt_digest
        and str(row[4]) == parsed.outcome_code
        and row[5] == parsed.error_code
        and type(row[6]) is int
        and int(row[6]) == parsed.verification_time_ms
    )


def _read(connection: sqlite3.Connection, batch_root: bytes | None, expected_status: str | None) -> IndependentAuthoritativeAssertionBatch:
    if _columns(connection, "authoritative_batches") != _BATCH_COLUMNS or _columns(connection, "authoritative_operations") != _OPERATION_COLUMNS or _columns(connection, "authoritative_results") != _RESULT_COLUMNS:
        _fail("authoritative_schema")
    if batch_root is not None:
        _blob(batch_root, 64, "authoritative_batch_root")
        batch_row = connection.execute("SELECT * FROM authoritative_batches WHERE batch_root=?", (batch_root,)).fetchone()
    else:
        batch_row = connection.execute("SELECT * FROM authoritative_batches ORDER BY created_ms,batch_root LIMIT 1").fetchone()
    if batch_row is None or len(batch_row) != len(_BATCH_COLUMNS):
        _fail("authoritative_batch_unknown")
    root = _blob(bytes(batch_row[0]), 64, "authoritative_batch_root")
    member_count = _integer(batch_row[1], "authoritative_batch_cardinality")
    status = str(batch_row[2])
    if member_count != MEMBER_COUNT or status not in {"ISSUED", "RESERVED", "HELD", "APPLIED"} or (expected_status is not None and status != expected_status):
        _fail("authoritative_batch_status")
    if str(batch_row[4]) != SOURCE_AUTH_PROFILE_ID or str(batch_row[5]) != SIGNATURE_PROFILE_VERSION or _integer(batch_row[7], "authoritative_reservation") != RESERVATION_UNITS:
        _fail("authoritative_reservation")
    source_key_epoch = _integer(batch_row[6], "authoritative_batch_epoch")
    reservation_before = _integer(batch_row[8], "authoritative_reservation")
    reservation_after = _integer(batch_row[9], "authoritative_reservation")
    cryptographic_attempted = _integer(batch_row[10], "authoritative_reservation")
    if cryptographic_attempted not in (0, 1):
        _fail("authoritative_reservation")
    verification_time = None if batch_row[11] is None else _integer(batch_row[11], "authoritative_verification_time")
    created_ms = _integer(batch_row[12], "authoritative_batch_time")
    _integer(batch_row[13], "authoritative_batch_time")
    last_error_code = None if batch_row[14] is None else _token(batch_row[14], "authoritative_batch_error")
    state_profile_version = _token(batch_row[3], "authoritative_batch_profile")
    if status == "ISSUED":
        if cryptographic_attempted != 0 or verification_time is not None or reservation_after != reservation_before or last_error_code is not None:
            _fail("authoritative_reservation")
    elif cryptographic_attempted == 0:
        if status != "HELD" or verification_time is None or reservation_after != reservation_before or last_error_code not in {"authoritative_validity_window", "authoritative_clock_rewind"}:
            _fail("authoritative_reservation")
    else:
        if verification_time is None or verification_time < created_ms:
            _fail("authoritative_verification_time")
        try:
            expected_after = compute_reservation_after(reservation_before)
        except AuthoritativeAssertionError:
            _fail("authoritative_reservation")
        if reservation_after != expected_after:
            _fail("authoritative_reservation")
        if status in {"RESERVED", "APPLIED"} and last_error_code is not None:
            _fail("authoritative_batch_error")
    if not state_profile_version:
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
    batch = AuthoritativeBatchStatementV1(tuple(statements), root, source_key_epoch)
    if batch.state_profile_version != state_profile_version:
        _fail("authoritative_batch_profile")
    if cryptographic_attempted == 1:
        if verification_time is None or any(not statement.template.valid_from_ms <= verification_time < statement.template.valid_until_ms for statement in statements):
            _fail("authoritative_validity_window")
    elif status == "HELD" and verification_time is not None:
        valid_now = all(statement.template.valid_from_ms <= verification_time < statement.template.valid_until_ms for statement in statements)
        if last_error_code == "authoritative_validity_window" and valid_now:
            _fail("authoritative_validity_window")
        if last_error_code == "authoritative_clock_rewind" and verification_time >= created_ms:
            _fail("authoritative_verification_time")
    result: AuthoritativeAssertionResultV1 | None = None
    result_rows = connection.execute("SELECT * FROM authoritative_results WHERE batch_root=?", (root,)).fetchall()
    if len(result_rows) > 1:
        _fail("authoritative_result_duplicate")
    result_row = None if not result_rows else tuple(result_rows[0])
    if status == "APPLIED":
        if cryptographic_attempted != 1 or result_row is None or int(result_row[1]) != 1 or result_row[2] is None or result_row[3] is None:
            _fail("authoritative_result_missing")
        receipt = bytes(result_row[2])
        result = _parse_result(receipt)
        if not result.assertion_accepted or result.batch_root != root or result.member_count != MEMBER_COUNT or result.source_key_epoch != source_key_epoch or result.verification_time_ms != verification_time or result.source_auth_profile_id != SOURCE_AUTH_PROFILE_ID or result.signature_profile_version != SIGNATURE_PROFILE_VERSION or not _result_row_matches(result_row, result):
            _fail("authoritative_result_binding")
    elif status in {"ISSUED", "RESERVED"}:
        if result_row is not None:
            _fail("authoritative_result_unexpected")
    elif status == "HELD":
        if cryptographic_attempted == 0:
            if result_row is not None:
                _fail("authoritative_result_unexpected")
        elif result_row is not None:
            if int(result_row[1]) != 0 or result_row[2] is None or result_row[3] is None:
                _fail("authoritative_result_missing")
            result = _parse_result(bytes(result_row[2]))
            if result.batch_root != root or result.assertion_accepted or result.member_count != MEMBER_COUNT or result.source_key_epoch != source_key_epoch or result.verification_time_ms != verification_time or result.source_auth_profile_id != SOURCE_AUTH_PROFILE_ID or result.signature_profile_version != SIGNATURE_PROFILE_VERSION or last_error_code != result.error_code or not _result_row_matches(result_row, result):
                _fail("authoritative_result_binding")
        else:
            if last_error_code not in {"fresh_batch_required", "authoritative_validity_window", "authoritative_clock_rewind"}:
                _fail("authoritative_result_missing")
    return IndependentAuthoritativeAssertionBatch(batch, status, tuple(jobs), reservation_before, reservation_after, bool(cryptographic_attempted), verification_time, created_ms, last_error_code, result)


def read_authoritative_batch(path: Path, batch_root: bytes | None = None, *, expected_status: str | None = None) -> IndependentAuthoritativeAssertionBatch:
    if not isinstance(path, Path) or not path.is_file() or path.is_symlink():
        _fail("authoritative_database_path")
    try:
        with closing(sqlite3.connect(str(path), timeout=5.0)) as connection:
            return _read(connection, batch_root, expected_status)
    except sqlite3.Error:
        _fail("authoritative_database_sqlite")


def verify_authoritative_connection(connection: sqlite3.Connection) -> dict[str, Any]:
    if not isinstance(connection, sqlite3.Connection) or _columns(connection, "authoritative_profile_ledger") != _LEDGER_COLUMNS:
        _fail("authoritative_schema")
    ledger = connection.execute("SELECT * FROM authoritative_profile_ledger WHERE profile_id=?", (SOURCE_AUTH_PROFILE_ID,)).fetchone()
    if ledger is None or len(ledger) != len(_LEDGER_COLUMNS) or str(ledger[0]) != SOURCE_AUTH_PROFILE_ID or _integer(ledger[1], "authoritative_ledger") != LIFETIME_ACCEPTANCE_CAP or _integer(ledger[2], "authoritative_ledger") > int(ledger[1]) or _integer(ledger[3], "authoritative_ledger") != 0:
        _fail("authoritative_ledger")
    used = _integer(ledger[2], "authoritative_ledger")
    last_key_epoch = _integer(ledger[4], "authoritative_ledger")
    expected_used = 0
    maximum_batch_epoch = 0
    rows = connection.execute("SELECT batch_root FROM authoritative_batches ORDER BY reservation_before,cryptographic_attempted,created_ms,batch_root").fetchall()
    for row in rows:
        root = _blob(row[0], 64, "authoritative_batch_root")
        batch = _read(connection, root, None)
        if batch.reservation_before != expected_used:
            _fail("authoritative_ledger_chain")
        if batch.cryptographic_attempted:
            try:
                expected_after = compute_reservation_after(batch.reservation_before)
            except AuthoritativeAssertionError:
                _fail("authoritative_ledger_chain")
            if batch.reservation_after != expected_after:
                _fail("authoritative_ledger_chain")
            expected_used = batch.reservation_after
        elif batch.reservation_after != batch.reservation_before:
            _fail("authoritative_ledger_chain")
        maximum_batch_epoch = max(maximum_batch_epoch, batch.batch.source_key_epoch)
    if used != expected_used or last_key_epoch < maximum_batch_epoch:
        _fail("authoritative_ledger_disagreement")
    return {"mode": MODE, "batch_count": len(rows), "lifetime_cap": LIFETIME_ACCEPTANCE_CAP, "computational_units_used": used, "statistical_units_used": int(ledger[3]), "proof_suite_id": None, "production_usable": False, "activation": False}


def verify_authoritative_database(path: Path) -> dict[str, Any]:
    if not isinstance(path, Path) or not path.is_file() or path.is_symlink():
        _fail("authoritative_database_path")
    try:
        with closing(sqlite3.connect(str(path), timeout=5.0)) as connection:
            return verify_authoritative_connection(connection)
    except sqlite3.Error:
        _fail("authoritative_database_sqlite")


__all__ = ("IndependentAuthoritativeAssertionBatch", "IndependentAuthoritativeAssertionError", "IndependentAuthoritativeAssertionJob", "read_authoritative_batch", "verify_authoritative_connection", "verify_authoritative_database")
