"""Bounded synthetic receiver-file proposal and isolated preview, with one owner writer."""

from contextlib import closing
import hashlib
import json
from pathlib import Path
import re
import shutil
import sqlite3
import tempfile
import time

from app.right_rail_financial_owner import FinancialBusyError, FinancialConflictError, FinancialOwner, FinancialOwnerConfig, FinancialRevisionError, _checker_authority
from app.right_rail_financial_cash_file_independent import MAX_ROWS, REFUSALS, CashFileCheck, CashFileError, CashFilePreview


MAX_FILE_BYTES = 1_048_576
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise CashFileError("cash_file_format")
        value[key] = item
    return value


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
        value = json.loads(source_bytes.decode("ascii"), object_pairs_hook=_object)
        canonical = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    except (ValueError, UnicodeError, RecursionError):
        raise CashFileError("cash_file_format") from None
    if canonical != source_bytes:
        raise CashFileError("cash_file_format")
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


def preview_cash_file(commands, context, *, path, trusted_authority, clock=None):
    """Run the checked file on a private copy of the live store and roll it back; publish only after the copy is removed."""
    try:
        folder = Path(path).resolve().with_name(Path(path).name + ".cash-preview")  # owner-controlled, beside the store, not the system temp folder
        folder.mkdir(exist_ok=True)
        for stale in folder.iterdir():  # a copy a crash left behind is swept by the next preview
            if time.time() - stale.stat().st_mtime > 3600:
                shutil.rmtree(stale, ignore_errors=True)
        with tempfile.TemporaryDirectory(dir=folder) as directory:
            store = Path(directory) / "preview.sqlite"
            with closing(sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)) as live, closing(sqlite3.connect(store)) as target:
                live.backup(target)  # a consistent snapshot; the live file is only read
            FinancialOwner(path=store, config=FinancialOwnerConfig(**context["expected_scope"]), trusted_authority=trusted_authority, clock=clock,
                           mode=context["expected_mode"], owner_id=context["expected_owner_id"], existing_only=True).run_batch(commands, cash_file_context={**context, "preview": True})
    except CashFilePreview as preview:
        return preview.args[0]
    except Exception as error:
        raise CashFileError(refusal(error)) from None
    raise CashFileError("cash_file_failed")  # a preview that finished without its checked receipt


def refusal(error):
    """The fixed class of a refused cash file, never its input or error text (docs/CORE_REDESIGN.md "Cash-file refusals")."""
    if type(error) is CashFileError and str(error) in REFUSALS:
        return str(error)
    for kind, code in ((FinancialBusyError, "cash_file_busy"), (FinancialRevisionError, "cash_file_stale"), (FinancialConflictError, "cash_file_conflict")):
        if isinstance(error, kind):
            return code
    return "cash_file_failed"
