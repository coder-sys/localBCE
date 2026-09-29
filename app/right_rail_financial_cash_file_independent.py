"""Independent, transaction-local acceptance of fictional receiver cash files.

This module never imports the producer or financial writer, and never writes SQL.
The owner calls begin under its write lock and finish after sealing, before COMMIT.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Mapping
from functools import wraps
from types import MappingProxyType

from app import right_rail_financial_owner_independent as ledger


_MAX_CENTS = 2**63 - 1
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA = re.compile(r"[0-9A-F]{64}\Z")
_SCOPE = {"state_id", "deployment_id", "program_id", "period_id", "currency"}
_SOURCE = {"source_id", "version", "receiver_system_id", "capture_id", "captured_at_ms"}
_ROW = {"item_id", "payment_id", "common_origin_id", "evidence_id", "amount_cents", "event_at_ms", "pays_action_id", "expected_revision"}
_CONTEXT = {
    "source_bytes", "baseline_bytes", "expected_source_sha256", "expected_baseline_sha256",
    "expected_scope", "expected_source", "expected_authority", "expected_owner_id",
    "expected_mode", "execution_baseline_bytes", "execution_owner_id",
}


class CashFileError(ValueError):
    """A fixed local refusal code, with no input value or underlying error text."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise CashFileError(code)


def _fixed_errors(method):
    @wraps(method)
    def checked(*args, **kwargs):
        try:
            return method(*args, **kwargs)
        except CashFileError:
            raise
        except Exception:
            raise CashFileError("cash_file_invalid") from None
    return checked


def _freeze(value: object, depth: int = 0, budget: list[int] | None = None) -> object:
    budget = [250_000] if budget is None else budget
    budget[0] -= 1
    _require(depth <= 32 and budget[0] >= 0, "cash_file_shape")
    if type(value) is dict:
        _require(all(type(key) is str for key in value), "cash_file_shape")
        return MappingProxyType({key: _freeze(item, depth + 1, budget) for key, item in value.items()})
    if type(value) in (list, tuple):
        return tuple(_freeze(item, depth + 1, budget) for item in value)
    _require(type(value) in (str, int, bool, bytes, type(None)), "cash_file_shape")
    return value


def _keys(value: object, keys: set[str]) -> None:
    _require(type(value) is dict and set(value) == keys, "cash_file_fields")


def _id(value: object) -> None:
    _require(type(value) is str and _ID.fullmatch(value) is not None, "cash_file_id")


def _integer(value: object, low: int, high: int) -> None:
    _require(type(value) is int and low <= value <= high, "cash_file_integer")


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = dict(pairs)
    _require(len(result) == len(pairs), "cash_file_duplicate_key")
    return result


def _source(raw: bytes) -> dict[str, object]:
    _require(type(raw) is bytes and 0 < len(raw) <= 1024 * 1024, "cash_file_size")
    value = json.loads(raw.decode("ascii"), object_pairs_hook=_unique)
    _keys(value, {"contract", "source_class", "scope", "source", "row_count", "total_cents", "rows"})
    _require(value["contract"] == "RR/FINANCIAL/RECEIVER-CASH-FILE/v1" and value["source_class"] == "SYNTHETIC_RECEIVER_CASH", "cash_file_contract")
    _keys(value["scope"], _SCOPE)
    _keys(value["source"], _SOURCE)
    _require(value["scope"]["currency"] == "USD", "cash_file_scope")
    for key in _SCOPE - {"currency"}:
        _id(value["scope"][key])
    for key in _SOURCE - {"captured_at_ms"}:
        _id(value["source"][key])
    _integer(value["source"]["captured_at_ms"], 0, _MAX_CENTS)
    _integer(value["row_count"], 1, 1000)
    _integer(value["total_cents"], 1, _MAX_CENTS)
    rows = value["rows"]
    _require(type(rows) is list and len(rows) == value["row_count"], "cash_file_count")
    seen_payment, seen_evidence, seen_origin = set(), set(), set()
    for row in rows:
        _keys(row, _ROW)
        for key in ("item_id", "payment_id", "common_origin_id", "evidence_id"):
            _id(row[key])
        if row["pays_action_id"] is not None:
            _id(row["pays_action_id"])
        _integer(row["amount_cents"], 1, _MAX_CENTS)
        _integer(row["event_at_ms"], 0, value["source"]["captured_at_ms"])
        _integer(row["expected_revision"], 0, 9999)
        for seen, key in ((seen_payment, row["payment_id"]), (seen_evidence, row["evidence_id"]), (seen_origin, (row["item_id"], row["common_origin_id"]))):
            _require(key not in seen, "cash_file_duplicate_row")
            seen.add(key)
    _require(sum(row["amount_cents"] for row in rows) == value["total_cents"], "cash_file_total")
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    _require(raw == canonical, "cash_file_canonical")
    return value


def _index(rows: Mapping, table: str, key: str) -> dict:
    return {row[key]: row for row in rows[table]}


def _unchanged(old: Mapping, new: Mapping, except_fields: set[str] = frozenset()) -> None:
    _require(set(old) == set(new) and all(new[key] == value for key, value in old.items() if key not in except_fields), "cash_file_other_change")


class CashFileCheck:
    """Single-use fixed verifier. A successful finish is still not a commit receipt."""

    @_fixed_errors
    def __init__(self, commands: object, context: object):
        _keys(context, _CONTEXT)
        source = _source(context["source_bytes"])
        for field in ("expected_source_sha256", "expected_baseline_sha256"):
            _require(type(context[field]) is str and _SHA.fullmatch(context[field]) is not None, "cash_file_hash")
        _require(type(context["baseline_bytes"]) is bytes and 0 < len(context["baseline_bytes"]) <= ledger.MAX_PACKAGE_BYTES, "cash_file_baseline")
        self._source_sha = hashlib.sha256(context["source_bytes"]).hexdigest().upper()
        self._baseline_sha = hashlib.sha256(context["baseline_bytes"]).hexdigest().upper()
        _require(self._source_sha == context["expected_source_sha256"] and self._baseline_sha == context["expected_baseline_sha256"], "cash_file_hash")
        _keys(context["expected_scope"], _SCOPE)
        _keys(context["expected_source"], _SOURCE)
        for actual, expected in ((source["scope"], context["expected_scope"]), (source["source"], context["expected_source"])):
            _require(all(type(expected[key]) is type(value) and expected[key] == value for key, value in actual.items()), "cash_file_context")
        _id(context["expected_owner_id"])
        _require(type(context["expected_mode"]) is str and context["expected_mode"] in ("LIVE", "TEST", "SHADOW"), "cash_file_owner")
        self._context = _freeze(context)
        self._source = _freeze(source)
        baseline = self._package(context["baseline_bytes"])
        meta = baseline["_decoded_rows"]["financial_meta"][0]
        _require(meta["owner_id"] == context["expected_owner_id"] and meta["mode"] == context["expected_mode"], "cash_file_owner")
        self._baseline = _freeze(baseline)
        self._preview = context["execution_baseline_bytes"] is not None
        _require(self._preview == (context["execution_owner_id"] is not None), "cash_file_execution")
        self._execution = context["execution_baseline_bytes"] if self._preview else context["baseline_bytes"]
        if self._preview:
            _id(context["execution_owner_id"])
            self._package(self._execution)
        _require(type(commands) is list and len(commands) == source["row_count"], "cash_file_commands")
        frozen_commands = []
        for entry, row in zip(commands, source["rows"]):
            arguments = {**row, "source_id": source["source"]["source_id"], "source_version": source["source"]["version"], "local_ref": self._source_sha + self._baseline_sha}
            _require(type(entry) is tuple and len(entry) == 2 and type(entry[0]) is str and entry[0] == "record_payment_evidence" and type(entry[1]) in (dict, MappingProxyType), "cash_file_commands")
            _require(set(entry[1]) == set(arguments) and all(type(entry[1][key]) is type(value) and entry[1][key] == value for key, value in arguments.items()), "cash_file_commands")
            frozen_commands.append(("record_payment_evidence", MappingProxyType(arguments)))
        self.commands = tuple(frozen_commands)
        self.receipt = None
        self._connection = None
        self._finished = False

    def _package(self, raw: bytes) -> dict:
        return ledger.verify_continuity_package(raw, expected_scope=self._context["expected_scope"], expected_authority=self._context["expected_authority"], _include_rows=True)

    def _expectations(self) -> dict:
        return {
            "expected_scope": self._context["expected_scope"],
            "expected_authority": self._context["expected_authority"],
            "expected_mode": "TEST" if self._preview else self._context["expected_mode"],
            "expected_owner_id": self._context["execution_owner_id"] if self._preview else self._context["expected_owner_id"],
            "expected_continuity_epoch": self._baseline["continuity_epoch"],
        }

    def _snapshot(self, connection: sqlite3.Connection, raw: bytes) -> tuple[dict, dict]:
        verified = ledger.verify_database_connection(connection, current_snapshot_package=raw, **self._expectations())
        return verified, self._package(raw)["_decoded_rows"]

    @_fixed_errors
    def begin(self, connection: sqlite3.Connection, current_bytes: bytes) -> None:
        _require(self._connection is None and not self._finished and isinstance(connection, sqlite3.Connection) and connection.in_transaction, "cash_file_transaction")
        _require(self._preview or self._context["expected_mode"] in ("LIVE", "TEST"), "cash_file_owner")
        verified, rows = self._snapshot(connection, current_bytes)
        if self._preview:
            ledger.verify_database_connection(connection, restore_source_package=self._context["baseline_bytes"], **self._expectations())
            _require(current_bytes == self._execution and verified["sequence"] == self._baseline["sequence"] and verified["history_head"] == self._baseline["history_head"], "cash_file_execution")
        else:
            _require(rows["financial_identity"] == list(self._baseline["_decoded_rows"]["financial_identity"]), "cash_file_ancestor")
            sequence = self._baseline["sequence"]
            events = _index(rows, "financial_events", "event_sequence")
            ancestor = rows["financial_identity"][0]["genesis_head"] if sequence == 0 else events.get(sequence, {}).get("head")
            _require(sequence <= verified["sequence"] and ancestor == bytes.fromhex(self._baseline["history_head"]), "cash_file_ancestor")
        self._stale = current_bytes != self._execution
        _require(not self._stale or self._baseline["sequence"] < verified["sequence"], "cash_file_ancestor")
        self._before = _freeze(rows)
        self._verified_before = _freeze(verified)
        self._before_bytes = current_bytes
        self._changes = connection.total_changes
        self._connection = connection

    def _payment_binding(self, rows: Mapping, argument: Mapping, payments: Mapping, evidence: Mapping, events: Mapping) -> tuple[Mapping, Mapping]:
        payment = payments[argument["payment_id"]]
        fact = evidence[argument["evidence_id"]]
        event, payload = events[argument["payment_id"]]
        for key in ("payment_id", "item_id", "evidence_id", "common_origin_id", "amount_cents", "event_at_ms"):
            _require(payment[key] == argument[key], "cash_file_payment")
        expected_fact = {key: argument[key] for key in ("evidence_id", "item_id", "common_origin_id", "source_id", "source_version", "local_ref", "event_at_ms", "amount_cents")}
        expected_fact.update(kind="PAYMENT_CONFIRMATION", applicable_at_ms=argument["event_at_ms"], reversal_of=None, supersedes=None)
        _require(all(fact[key] == value for key, value in expected_fact.items()), "cash_file_evidence")
        expected_payload = {key: argument[key] for key in ("payment_id", "evidence_id", "amount_cents", "common_origin_id")}
        if argument["pays_action_id"] is not None:
            expected_payload["pays_action_id"] = argument["pays_action_id"]
            action = _index(rows, "actions", "action_id")[argument["pays_action_id"]]
            _require(action["kind"] == "CORRECTION_PAYMENT_REQUEST" and action["obligation_id"] == payment["obligation_id"], "cash_file_action")
        evaluation_fields = {"evaluation_id", "evaluation_input_digest", "evaluation_result_digest", "evaluation_receipt_digest"}
        _require(set(payload) - {"rows"} == set(expected_payload) | evaluation_fields and all(payload[key] == value for key, value in expected_payload.items()), "cash_file_event")
        _require(event["aggregate_type"] == "OBLIGATION" and event["aggregate_id"] == payment["obligation_id"] and event["before_revision"] == argument["expected_revision"] and event["after_revision"] == argument["expected_revision"] + 1, "cash_file_revision")
        return payment, event

    @_fixed_errors
    def finish(self, connection: sqlite3.Connection, current_bytes: bytes, results: object) -> None:
        _require(connection is self._connection and connection.in_transaction and not self._finished, "cash_file_transaction")
        self._finished = True
        verified, rows = self._snapshot(connection, current_bytes)
        _require(type(results) is list and len(results) == len(self.commands), "cash_file_results")
        old_payments = _index(self._before, "payments", "payment_id")
        payments = _index(rows, "payments", "payment_id")
        evidence = _index(rows, "evidence", "evidence_id")
        events = {}
        for event in rows["financial_events"]:
            if event["kind"] == "PAYMENT_RECEIVED":
                payload = json.loads(event["payload_json"])
                _require(payload["payment_id"] not in events, "cash_file_event")
                events[payload["payment_id"]] = (event, payload)
        recorded, new_events, new_evidence, new_evaluations, deltas = [], [], set(), set(), {}
        revisions = {row["obligation_id"]: row["revision"] for row in self._before["obligations"]}
        for (_, argument), result in zip(self.commands, results):
            status = "DUPLICATE" if argument["payment_id"] in old_payments else "RECORDED"
            _require(type(result) is dict and result.get("status") == status and result.get("payment_id") == argument["payment_id"], "cash_file_result")
            payment, event = self._payment_binding(rows, argument, payments, evidence, events)
            if status == "RECORDED":
                _require(not self._stale and payment["active"] == 1 and payment["reversed_by_evidence_id"] is None, "cash_file_stale")
                obligation = payment["obligation_id"]
                _require(argument["expected_revision"] == revisions[obligation], "cash_file_revision")
                revisions[obligation] += 1
                deltas[obligation] = deltas.get(obligation, 0) + argument["amount_cents"]
                recorded.append(argument["payment_id"])
                new_events.append(event["event_sequence"])
                new_evidence.add(argument["evidence_id"])
                new_evaluations.add(events[argument["payment_id"]][1]["evaluation_id"])
        before_sequence = self._verified_before["sequence"]
        _require(new_events == list(range(before_sequence + 1, before_sequence + len(recorded) + 1)) and verified["sequence"] == before_sequence + len(recorded), "cash_file_order")
        for table, key, additions in (("payments", "payment_id", set(recorded)), ("evidence", "evidence_id", new_evidence), ("evaluations", "evaluation_id", new_evaluations), ("financial_events", "event_sequence", set(new_events))):
            old, new = _index(self._before, table, key), _index(rows, table, key)
            _require(set(new) == set(old) | additions and all(new[key] == value for key, value in old.items()), "cash_file_other_change")
        old_obligations, obligations = _index(self._before, "obligations", "obligation_id"), _index(rows, "obligations", "obligation_id")
        _require(set(old_obligations) == set(obligations), "cash_file_other_change")
        changed = {"revision", "received_cash_cents", "shortfall_cents", "overage_cents", "cash_satisfied", "amount_satisfied", "timely", "verification_status", "case_status", "current_evaluation_id", "updated_at_ms"}
        for key, old in old_obligations.items():
            new = obligations[key]
            _unchanged(old, new, changed if key in deltas else frozenset())
            _require(new["received_cash_cents"] - old["received_cash_cents"] == deltas.get(key, 0) and new["revision"] == revisions[key], "cash_file_cash")
        old_cases, cases = _index(self._before, "cases", "case_id"), _index(rows, "cases", "case_id")
        _require(set(old_cases) == set(cases), "cash_file_other_change")
        for key, old in old_cases.items():
            _unchanged(old, cases[key], {"status", "updated_at_ms"} if old["obligation_id"] in deltas else frozenset())
        variable = {"payments", "evidence", "evaluations", "financial_events", "financial_meta", "obligations", "cases"}
        for table in set(rows) - variable:
            _require(tuple(rows[table]) == self._before[table], "cash_file_other_change")
        _unchanged(self._before["financial_meta"][0], rows["financial_meta"][0], {"sequence", "history_head"})
        recorded_cents = sum(deltas.values())
        before_cash = self._verified_before["totals"]["received_cash_cents"]
        after_cash = verified["totals"]["received_cash_cents"]
        _require(after_cash - before_cash == recorded_cents, "cash_file_cash")
        if not recorded:
            _require(current_bytes == self._before_bytes and connection.total_changes == self._changes, "cash_file_duplicate_write")
        self.receipt = {
            "contract": "RR/FINANCIAL/RECEIVER-CASH-RECEIPT/v1",
            "mode": "PREVIEW" if self._preview else "APPLIED",
            "source_sha256": self._source_sha, "baseline_sha256": self._baseline_sha,
            "row_count": len(self.commands), "recorded_count": len(recorded),
            "duplicate_count": len(self.commands) - len(recorded),
            "file_total_cents": self._source["total_cents"], "recorded_cents": recorded_cents,
            "duplicate_cents": self._source["total_cents"] - recorded_cents,
            "cash_before_cents": before_cash, "cash_after_cents": after_cash,
            "cash_delta_cents": recorded_cents, "proofSuiteId": None,
            "production_usable": False, "activation": False,
        }
