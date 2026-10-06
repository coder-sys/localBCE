"""Bounded synthetic receiver-file proposal and isolated preview, with one owner writer."""

from contextlib import closing, contextmanager
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import shutil
import sqlite3
import tempfile
import time
from typing import Any

from app.right_rail_financial_canonical_json import decode, encode
from app.right_rail_financial_owner import FinancialBusyError, FinancialConflictError, FinancialIntegrityError, FinancialOwner, FinancialOwnerConfig, FinancialRevisionError, FinancialStaleError, _TABLE_COLUMNS, _checker_authority
from app.right_rail_financial_cash_file_independent import MAX_ROWS, REFUSALS, CashFileCheck, CashFileError, CashFilePreview


MAX_FILE_BYTES = 1_048_576
PLAN_WINDOW_MS = 60_000  # a plan commits only while the live clock is within this of the plan's own last reading
_DERIVED = ("history_pending", "history_open")  # the owner's triggers keep these: replayed rows rebuild them, never written directly
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


def _refuse(_value):
    raise CashFileError("cash_file_format")


def _fields(value, names):
    if type(value) is not dict or set(value) != set(names.split()):
        raise CashFileError("cash_file_format")


def _identifier(value):
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise CashFileError("cash_file_format")


def _integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise CashFileError("cash_file_format")


def _propose(source_bytes, baseline_bytes):
    if type(baseline_bytes) is not bytes or not 0 < len(baseline_bytes) <= MAX_FILE_BYTES or type(source_bytes) is not bytes or not 0 < len(source_bytes) <= MAX_FILE_BYTES:
        raise CashFileError("cash_file_format")
    try:
        value = decode(source_bytes, "ascii", _refuse, _refuse)
        canonical = encode(value)
    except (ValueError, UnicodeError, RecursionError):
        raise CashFileError("cash_file_format") from None
    if canonical != source_bytes:
        raise CashFileError("cash_file_format")
    source, rows = _header(value)
    local_ref = hashlib.sha256(source_bytes).hexdigest().upper() + hashlib.sha256(baseline_bytes).hexdigest().upper()
    commands, payments, evidence, origins = [], set(), set(), set()
    for row in rows:
        _fields(row, "item_id payment_id common_origin_id evidence_id amount_cents event_at_ms pays_action_id expected_revision")
        for key in ("item_id", "payment_id", "common_origin_id", "evidence_id"):
            _identifier(row[key])
        if row["pays_action_id"] is not None:
            _identifier(row["pays_action_id"])
        _integer(row["amount_cents"], 1, 2**63 - 1)
        _integer(row["event_at_ms"], 0, source["captured_at_ms"])
        _integer(row["expected_revision"], 0, 9999)
        origin = (row["item_id"], row["common_origin_id"])
        if row["payment_id"] in payments or row["evidence_id"] in evidence or origin in origins:
            raise CashFileError("cash_file_format")
        payments.add(row["payment_id"])
        evidence.add(row["evidence_id"])
        origins.add(origin)
        commands.append(("record_payment_evidence", {**row, "source_id": source["source_id"], "source_version": source["version"], "local_ref": local_ref}))
    if sum(row["amount_cents"] for row in rows) != value["total_cents"]:
        raise CashFileError("cash_file_format")
    return commands


def _header(value):
    """A file's container (everything but its rows' own fields): its source block and rows, or cash_file_format / cash_file_row_cap."""
    _fields(value, "contract source_class scope source row_count total_cents rows")
    if value["contract"] != "RR/FINANCIAL/RECEIVER-CASH-FILE/v1" or value["source_class"] != "SYNTHETIC_RECEIVER_CASH":
        raise CashFileError("cash_file_format")
    _fields(value["scope"], "state_id deployment_id program_id period_id currency")
    for item in value["scope"].values():
        _identifier(item)
    if value["scope"]["currency"] != "USD":
        raise CashFileError("cash_file_format")
    source = value["source"]
    _fields(source, "source_id version receiver_system_id capture_id captured_at_ms")
    for key in ("source_id", "version", "receiver_system_id", "capture_id"):
        _identifier(source[key])
    _integer(source["captured_at_ms"], 0, 2**63 - 1)
    if type(value["row_count"]) is int and value["row_count"] > MAX_ROWS:
        raise CashFileError("cash_file_row_cap")
    _integer(value["row_count"], 1, MAX_ROWS)
    _integer(value["total_cents"], 1, 2**63 - 1)
    rows = value["rows"]
    if type(rows) is not list or len(rows) != value["row_count"]:
        raise CashFileError("cash_file_format")
    return source, rows


def prepare_cash_file(source_bytes, baseline_bytes, *, expected_source_sha256,
                      expected_baseline_sha256, expected_scope, expected_source,
                      expected_owner_id, expected_mode, trusted_authority):
    """Propose commands, checking external review bindings before any writer opens."""
    commands = _propose(source_bytes, baseline_bytes)
    context = {
        "source_bytes": source_bytes, "baseline_bytes": baseline_bytes,
        "expected_source_sha256": expected_source_sha256,
        "expected_baseline_sha256": expected_baseline_sha256,
        "expected_scope": expected_scope, "expected_source": expected_source,
        "expected_authority": _checker_authority(trusted_authority),
        "expected_owner_id": expected_owner_id, "expected_mode": expected_mode,
        "preview": False,
    }
    checked = CashFileCheck(commands, context)
    return list(checked.commands), context


@contextmanager
def _copy_owner(context, path, trusted_authority, clock):
    """An owner over a private copy of the live store, beside it (not the system temp folder); the live file is only read."""
    folder = Path(path).resolve().with_name(Path(path).name + ".cash-preview")
    folder.mkdir(exist_ok=True)
    for stale in folder.iterdir():  # a copy a crash left behind is swept by the next one
        if time.time() - stale.stat().st_mtime > 3600:
            shutil.rmtree(stale, ignore_errors=True)
    with tempfile.TemporaryDirectory(dir=folder) as directory:
        store = Path(directory) / "preview.sqlite"
        with closing(sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)) as live, closing(sqlite3.connect(store)) as target:
            live.backup(target)  # a consistent snapshot
        with FinancialOwner(path=store, config=FinancialOwnerConfig(**context["expected_scope"]), trusted_authority=trusted_authority, clock=clock,
                            mode=context["expected_mode"], owner_id=context["expected_owner_id"], existing_only=True) as owner:
            yield owner


def preview_cash_file(commands, context, *, path, trusted_authority, clock=None):
    """Run the checked file on a private copy of the live store and roll it back; publish only after the copy is removed."""
    try:
        with _copy_owner(context, path, trusted_authority, clock) as owner:
            owner.run_batch(commands, cash_file_context={**context, "preview": True})
    except CashFilePreview as preview:
        return preview.args[0]
    except Exception as error:
        raise CashFileError(refusal(error)) from None
    raise CashFileError("cash_file_failed")  # a preview that finished without its checked receipt


@dataclass(frozen=True)
class CashPlan:
    """A checked file run on a private copy: the rows it wrote, each table's shape after, and the store it started from."""
    commands: tuple
    context: dict
    results: tuple
    baseline: tuple  # (sequence, history_head, segment count) of the store the copy was taken from
    last_ms: int | None  # the last owner-clock reading the file took on the copy
    writes: tuple  # (table, rowid, last image) in first-write order
    tables: dict[str, Any]  # every table: (row count, max rowid, None without one)
    seal: tuple | None  # a segment sealed inside the file: the copy's final pending rows and open counts, which replayed inserts cannot rebuild


class _Reading:
    def __init__(self, clock):
        self.clock, self.last = clock, None

    def now_ms(self):
        self.last = self.clock.now_ms()
        return self.last


def table_shapes(connection):
    return {name: (connection.execute(f'SELECT count(*) FROM "{name}"').fetchone()[0], None if "WITHOUT ROWID" in sql.upper() else connection.execute(f'SELECT max(rowid) FROM "{name}"').fetchone()[0])
            for name, sql in connection.execute("SELECT name,sql FROM sqlite_schema WHERE type='table'").fetchall()}


def plan_cash_file(commands, context, *, path, trusted_authority, clock=None):
    """Run the checked file on a private copy, recording every row it writes, so only a replay holds the live write lock. Writes nothing live."""
    try:
        with _copy_owner(context, path, trusted_authority, clock) as owner:
            connection, results, real = owner._writer, [], owner.record_payment_evidence
            owner.clock = reading = _Reading(owner.clock)
            owner.record_payment_evidence = lambda **arguments: results.append(real(**arguments)) or results[-1]  # the file's own results, for the live checker
            connection.execute("CREATE TEMP TABLE rr_plan(id INTEGER PRIMARY KEY, tbl TEXT NOT NULL, op TEXT NOT NULL, rid INTEGER)")
            for (name,) in connection.execute("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall():
                for op, row in (("INSERT", "NEW"), ("UPDATE", "NEW"), ("DELETE", "OLD")):
                    if name not in _DERIVED or op == "DELETE":
                        connection.execute(f"CREATE TEMP TRIGGER rr_plan_{name}_{op} AFTER {op} ON main.\"{name}\" BEGIN INSERT INTO rr_plan(tbl,op,rid) VALUES ('{name}','{op}',{0 if name in _DERIVED else row + '.rowid'}); END")
            baseline = _baseline(connection)
            owner.run_batch(commands, cash_file_context=context)
            log = connection.execute("SELECT tbl,op,rid FROM temp.rr_plan ORDER BY id").fetchall()
            if any(op == "DELETE" and table not in _DERIVED for table, op, _ in log):
                raise CashFileError("cash_file_failed")  # a file deletes nothing; the direct path says why
            seal = (tuple(tuple(row) for row in connection.execute("SELECT * FROM history_pending ORDER BY 1,2")), tuple(connection.execute("SELECT * FROM history_open").fetchone())) if any(op == "DELETE" for _, op, _ in log) else None
            writes = tuple((table, rowid, tuple(connection.execute(f'SELECT * FROM "{table}" WHERE rowid=?', (rowid,)).fetchone())) for table, rowid in dict.fromkeys((table, rowid) for table, op, rowid in log if op != "DELETE"))
            return CashPlan(tuple(commands), context, tuple(results), baseline, reading.last, writes, table_shapes(connection), seal)
    except (CashFileError, FinancialBusyError, FinancialRevisionError, FinancialConflictError, sqlite3.Error) as error:
        raise CashFileError(refusal(error)) from None  # an integrity error is not a refusal: it propagates; a raw sqlite error on the copy (disk full) is cash_file_failed


def _baseline(connection):
    return tuple(connection.execute("SELECT sequence,history_head,(SELECT count(*) FROM history_segments) FROM financial_meta").fetchone())


def _identity(row):
    return row["table"], row["key"] if "key" in row else row["row"][_TABLE_COLUMNS[row["table"]][0]]


def commit_cash_plan(owner, plan):
    """Inside the owner's one write, refuse a stale plan, begin the live check, replay the rows, prove the live store has the copy's shape and rows, and finish the check on them."""
    check = CashFileCheck(list(plan.commands), plan.context)
    def finished(connection):
        owner._batch.evaluated = done = check.finish(connection, list(plan.results))
        return done
    with owner._write(before_commit=finished) as connection:
        now = owner._now()
        if plan.writes and (plan.last_ms is None or not plan.last_ms <= now < plan.last_ms + PLAN_WINDOW_MS or connection.execute(
                "SELECT 1 FROM obligations WHERE due_at_ms BETWEEN ?1 AND ?2 UNION ALL SELECT 1 FROM claimed_adjustments WHERE deadline_ms BETWEEN ?1 AND ?2 UNION ALL SELECT 1 FROM cases WHERE due_at_ms BETWEEN ?1 AND ?2 LIMIT 1", (plan.last_ms, now)).fetchone()) or _baseline(connection) != plan.baseline:
            raise FinancialStaleError("cash_plan_stale")  # before any statement, so the verified writer is kept; also stale: a deadline fell between the plan's clock and this one, so a direct run would decide it differently
        check.begin(connection)
        statements, order = {}, {}
        for table, rowid, values in sorted(plan.writes, key=lambda write: order.setdefault(write[0], len(order))):  # a table at a time: once a child row is in, SQLite scans every child table on each deferred-key parent insert
            if table not in statements:
                info = connection.execute(f'PRAGMA table_info("{table}")').fetchall()
                alias = {row[0] for row in info if row[5] and row[2].upper() == "INTEGER" and sum(1 for other in info if other[5]) == 1}  # an INTEGER PRIMARY KEY is the rowid
                names = [f'"{row[1]}"' for row in info if row[0] not in alias]
                statements[table] = (alias, f'INSERT INTO "{table}"(rowid,{",".join(names)}) VALUES ({",".join("?" * (len(names) + 1))}) ON CONFLICT(rowid) DO UPDATE SET {",".join(f"{name}=excluded.{name}" for name in names)}')
            alias, sql = statements[table]
            connection.execute(sql, (rowid, *(value for index, value in enumerate(values) if index not in alias)))
        if plan.seal is not None:
            connection.execute("DELETE FROM history_pending")
            connection.execute("UPDATE history_open SET event_count=0,byte_count=0")
            connection.executemany("INSERT INTO history_pending VALUES (?,?,?)", plan.seal[0])  # its trigger rebuilds the open counts
        if table_shapes(connection) != plan.tables or plan.seal is not None and tuple(connection.execute("SELECT * FROM history_open").fetchone()) != plan.seal[1] or any(tuple(connection.execute(f'SELECT * FROM "{table}" WHERE rowid=?', (rowid,)).fetchone() or ()) != values for table, rowid, values in plan.writes):
            raise FinancialIntegrityError("cash_plan_rows")
        carried = {_identity(row) for (payload,) in connection.execute("SELECT payload_json FROM financial_events WHERE event_sequence>?", (plan.baseline[0],)) for row in json.loads(payload).get("rows", ())}
        if not {_identity(json.loads(image)) for (image,) in connection.execute("SELECT image FROM temp.rr_captured_rows")} <= carried:
            raise FinancialIntegrityError("cash_plan_captured")  # a replayed row no event carries
        connection.execute("DELETE FROM temp.rr_captured_rows")  # the replayed events carry what these triggers captured
    return check.receipt


def apply_cash_file(owner, commands, context):
    """The one production apply (design (d)): plan on a private copy, commit the plan under the live lock; a stale plan is made again, 3 plans at most."""
    for _ in range(3):
        try:
            return commit_cash_plan(owner, plan_cash_file(commands, context, path=owner.path, trusted_authority=owner.trusted_authority, clock=owner.clock))
        except FinancialStaleError:
            continue
        except sqlite3.Error:
            raise CashFileError("cash_file_failed") from None  # a raw error on the live write (disk full): rolled back, a fixed class
    raise CashFileError("cash_file_busy")  # nothing written: resend the same file


def refusal(error):
    """The fixed class of a refused cash file, never its input or error text (docs/CORE_REDESIGN.md "Cash-file refusals")."""
    if type(error) is CashFileError and str(error) in REFUSALS:
        return str(error)
    for kind, code in ((FinancialBusyError, "cash_file_busy"), (FinancialRevisionError, "cash_file_stale"), (FinancialConflictError, "cash_file_conflict")):
        if isinstance(error, kind):
            return code
    return "cash_file_failed"
