"""Independent, transaction-local acceptance of fictional receiver cash files.

This module never imports the producer or financial writer, and writes no package row: its only writes are its own TEMP log and triggers.
The owner calls begin under its write lock and finish after sealing, before COMMIT.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections import Counter
from collections.abc import Mapping
from functools import wraps
from types import MappingProxyType

from app import right_rail_financial_owner_independent as ledger


_MAX_CENTS = 2**63 - 1
# docs/CORE_REDESIGN.md "Cash-file capacity": a file is one run_batch (at most 500 commands), and each payment
# re-binds every earlier payment of its item, so one file names an item at most MAX_ITEM_ROWS times.
MAX_ROWS = 500
MAX_ITEM_ROWS = 6
REFUSALS = frozenset(f"cash_file_{name}" for name in ("input", "format", "row_cap", "binding", "stale", "conflict", "already_recorded", "busy", "failed"))
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA = re.compile(r"[0-9A-F]{64}\Z")
_SCOPE = {"state_id", "deployment_id", "program_id", "period_id", "currency"}
_SOURCE = {"source_id", "version", "receiver_system_id", "capture_id", "captured_at_ms"}
_ROW = {"item_id", "payment_id", "common_origin_id", "evidence_id", "amount_cents", "event_at_ms", "pays_action_id", "expected_revision"}
_CONTEXT = {
    "source_bytes", "baseline_bytes", "expected_source_sha256", "expected_baseline_sha256",
    "expected_scope", "expected_source", "expected_authority", "expected_owner_id",
    "expected_mode", "preview", "intake",
}
_EVALUATION = {"evaluation_id", "evaluation_input_digest", "evaluation_result_digest", "evaluation_receipt_digest"}


class CashFileError(ValueError):
    """A fixed refusal class from REFUSALS, with no input value or underlying error text."""


class CashFilePreview(Exception):
    """Raised by finish when a preview's checks pass, so its owner transaction rolls back; args[0] is the receipt."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise CashFileError(code)


def _fixed_errors(method):
    @wraps(method)
    def checked(*args, **kwargs):
        try:
            return method(*args, **kwargs)
        except (CashFileError, CashFilePreview):
            raise
        except Exception:
            raise CashFileError("cash_file_failed") from None
    return checked


def _freeze(value: object, depth: int = 0, budget: list[int] | None = None) -> object:
    budget = [250_000] if budget is None else budget
    budget[0] -= 1
    _require(depth <= 32 and budget[0] >= 0, "cash_file_format")
    if type(value) is dict:
        _require(all(type(key) is str for key in value), "cash_file_format")
        return MappingProxyType({key: _freeze(item, depth + 1, budget) for key, item in value.items()})
    if type(value) in (list, tuple):
        return tuple(_freeze(item, depth + 1, budget) for item in value)
    _require(type(value) in (str, int, bool, bytes, type(None)), "cash_file_format")
    return value


def _keys(value: object, keys: set[str]) -> None:
    _require(type(value) is dict and set(value) == keys, "cash_file_format")


def _id(value: object) -> None:
    _require(type(value) is str and _ID.fullmatch(value) is not None, "cash_file_format")


def _integer(value: object, low: int, high: int) -> None:
    _require(type(value) is int and low <= value <= high, "cash_file_format")


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = dict(pairs)
    _require(len(result) == len(pairs), "cash_file_format")
    return result


def _source(raw: bytes) -> dict[str, object]:
    _require(type(raw) is bytes and 0 < len(raw) <= 1024 * 1024, "cash_file_format")
    value = json.loads(raw.decode("ascii"), object_pairs_hook=_unique)
    _keys(value, {"contract", "source_class", "scope", "source", "row_count", "total_cents", "rows"})
    _require(value["contract"] == "RR/FINANCIAL/RECEIVER-CASH-FILE/v1" and value["source_class"] == "SYNTHETIC_RECEIVER_CASH", "cash_file_format")
    _keys(value["scope"], _SCOPE)
    _keys(value["source"], _SOURCE)
    _require(value["scope"]["currency"] == "USD", "cash_file_format")
    for key in _SCOPE - {"currency"}:
        _id(value["scope"][key])
    for key in _SOURCE - {"captured_at_ms"}:
        _id(value["source"][key])
    _integer(value["source"]["captured_at_ms"], 0, _MAX_CENTS)
    _require(type(value["row_count"]) is not int or value["row_count"] <= MAX_ROWS, "cash_file_row_cap")
    _integer(value["row_count"], 1, MAX_ROWS)
    _integer(value["total_cents"], 1, _MAX_CENTS)
    rows = value["rows"]
    _require(type(rows) is list and len(rows) == value["row_count"], "cash_file_format")
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
            _require(key not in seen, "cash_file_format")
            seen.add(key)
    _require(max(Counter(row["item_id"] for row in rows).values()) <= MAX_ITEM_ROWS, "cash_file_row_cap")
    _require(sum(row["amount_cents"] for row in rows) == value["total_cents"], "cash_file_format")
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    _require(raw == canonical, "cash_file_format")
    return value


_INSERTS = ("payments", "evidence", "evaluations", "financial_events")
_UPDATES = ("financial_meta", "obligations", "cases")
_LOGGED = frozenset({(table, "INSERT") for table in _INSERTS} | {(table, "UPDATE") for table in _UPDATES})  # every other write to a package table is refused
_SCHEMA = "PRAGMA temp.schema_version"  # moved by every CREATE or DROP in temp, an identical re-create included


def _counts(connection: sqlite3.Connection) -> dict[str, int]:
    counts = {table: connection.execute(f"SELECT COUNT(*) FROM main.{table}").fetchone()[0] for table in ledger.PACKAGE_TABLES}
    _require(max(counts.values()) <= ledger.MAX_ROWS, "cash_file_failed")
    return counts


def _table(connection: sqlite3.Connection, table: str, rowids: list[int] | None = None) -> dict[int, dict]:
    """{rowid: row} for every row of one package table in rowid order, or for the given rowids: read from the table's own b-tree, never an index."""
    cursor = connection.cursor()
    cursor.row_factory = None
    columns = ledger.TABLE_COLUMNS[table]
    sql = f"SELECT rowid,{','.join(columns)} FROM main.{table}"
    stored = cursor.execute(sql + " ORDER BY rowid").fetchall() if rowids is None else [row for rowid in rowids for row in cursor.execute(sql + " WHERE rowid=?", (rowid,))]
    return {row[0]: dict(zip(columns, row[1:])) for row in stored}


def _index(rows: Mapping, table: str, key: str) -> dict:
    return {row[key]: row for row in rows[table]}


def _unchanged(old: Mapping, new: Mapping, except_fields: set[str] = frozenset()) -> None:
    _require(set(old) == set(new) and all(new[key] == value for key, value in old.items() if key not in except_fields), "cash_file_failed")


def _fact(argument: Mapping) -> dict:
    """The evidence row a confirmation from this file is stored as (its receipt time and digests aside)."""
    fact = {key: argument[key] for key in ("evidence_id", "item_id", "common_origin_id", "source_id", "source_version", "local_ref", "event_at_ms", "amount_cents")}
    return {**fact, "kind": "PAYMENT_CONFIRMATION", "applicable_at_ms": argument["event_at_ms"], "reversal_of": None, "supersedes": None}


def _held(argument: Mapping, reason: str) -> dict:
    return {"status": "HELD", "payment_id": argument["payment_id"], "reason": reason}


def _matches(row: Mapping | None, expected: Mapping) -> bool:
    return row is not None and all(row[key] == value for key, value in expected.items())


def _payment_events(events: list) -> tuple[dict, dict]:
    """PAYMENT_RECEIVED events by payment_id, and each stored alias confirmation's evidence_id -> the payment it repeats."""
    received, aliases = {}, {}
    for event in events:
        if event["kind"] in ("PAYMENT_RECEIVED", "PAYMENT_DUPLICATE_EVIDENCE"):
            payload = json.loads(event["payload_json"])
            if event["kind"] == "PAYMENT_DUPLICATE_EVIDENCE":
                aliases[payload["candidate_evidence_id"]] = payload["existing_payment_id"]
                continue
            _require(payload["payment_id"] not in received, "cash_file_failed")
            received[payload["payment_id"]] = (event, payload)
    return received, aliases


def _recorded(argument: Mapping, payment: Mapping, fact: Mapping | None, event: Mapping | None, payload: Mapping | None, actions: Mapping) -> bool:
    """This row's payment, its confirmation and its PAYMENT_RECEIVED event are stored exactly as the row states."""
    expected = {key: argument[key] for key in ("payment_id", "evidence_id", "amount_cents", "common_origin_id")}
    if argument["pays_action_id"] is not None:
        expected["pays_action_id"] = argument["pays_action_id"]
        action = actions.get(argument["pays_action_id"])
        if action is None or (action["kind"], action["obligation_id"]) != ("CORRECTION_PAYMENT_REQUEST", payment["obligation_id"]):
            return False
    return (event is not None and all(payment[key] == argument[key] for key in ("payment_id", "item_id", "evidence_id", "common_origin_id", "amount_cents", "event_at_ms"))
            and _matches(fact, _fact(argument)) and set(payload) - {"rows"} == set(expected) | _EVALUATION
            and all(payload[key] == value for key, value in expected.items())
            and (event["aggregate_type"], event["aggregate_id"]) == ("OBLIGATION", payment["obligation_id"])
            and (event["before_revision"], event["after_revision"]) == (argument["expected_revision"], argument["expected_revision"] + 1))


class CashFileCheck:
    """Single-use fixed verifier. A successful finish is still not a commit receipt."""

    @_fixed_errors
    def __init__(self, commands: object, context: object):
        _keys(context, _CONTEXT)
        source = _source(context["source_bytes"])
        for field in ("expected_source_sha256", "expected_baseline_sha256"):
            _require(type(context[field]) is str and _SHA.fullmatch(context[field]) is not None, "cash_file_binding")
        _require(type(context["baseline_bytes"]) is bytes and 0 < len(context["baseline_bytes"]) <= ledger.MAX_JSON_BYTES, "cash_file_format")
        self._source_sha = hashlib.sha256(context["source_bytes"]).hexdigest().upper()
        self._baseline_sha = hashlib.sha256(context["baseline_bytes"]).hexdigest().upper()
        _require(self._source_sha == context["expected_source_sha256"] and self._baseline_sha == context["expected_baseline_sha256"], "cash_file_binding")
        _keys(context["expected_scope"], _SCOPE)
        _keys(context["expected_source"], _SOURCE)
        for actual, expected in ((source["scope"], context["expected_scope"]), (source["source"], context["expected_source"])):
            _require(all(type(expected[key]) is type(value) and expected[key] == value for key, value in actual.items()), "cash_file_binding")
        _id(context["expected_owner_id"])
        _require(type(context["expected_mode"]) is str and context["expected_mode"] in ("LIVE", "TEST") and type(context["preview"]) is bool, "cash_file_binding")
        intake = context["intake"]  # None, or the intake facts of the raw file this file was derived from, stored with every row's outcome
        _require(intake is None or type(intake) is dict and intake.get("derived_sha256") == self._source_sha and type(intake.get("source_sha256")) is str and _SHA.fullmatch(intake["source_sha256"]) is not None, "cash_file_binding")
        self.intake = None if intake is None else json.loads(ledger._canonical(intake))
        self._context = _freeze(context)
        self._source = _freeze(source)
        manifest = json.loads(context["baseline_bytes"].decode("ascii"), object_pairs_hook=_unique)  # B: the owner's history-export manifest (docs/CORE_REDESIGN.md "History segments")
        _require(context["baseline_bytes"] == ledger._canonical(manifest), "cash_file_format")
        try:  # the export verifier's own manifest checks: shape, digest, meta, authority, scope, identity
            meta = ledger._verify_manifest(manifest, context["expected_authority"], context["expected_scope"])[0]
        except ledger.IndependentFinancialError as error:
            raise CashFileError("cash_file_format" if str(error) in ("history:manifest", "history:manifest-digest") else "cash_file_binding") from None
        _require((meta["owner_id"], meta["mode"]) == (context["expected_owner_id"], context["expected_mode"]) and type(meta["sequence"]) is int and type(meta["history_head"]) is bytes
                 and type(manifest["segment_count"]) is int and manifest["segment_count"] >= 0 and type(manifest["last_segment_digest"]) is str, "cash_file_binding")
        self._anchor = (ledger._verify_package_rows([manifest["identity"]], "financial_identity"), meta["sequence"], meta["history_head"], manifest["segment_count"], manifest["last_segment_digest"])
        self._epoch = meta["continuity_epoch"]
        self._preview = context["preview"]
        _require(type(commands) is list and len(commands) == source["row_count"], "cash_file_binding")
        frozen_commands = []
        for entry, row in zip(commands, source["rows"]):
            arguments = {**row, "source_id": source["source"]["source_id"], "source_version": source["source"]["version"], "local_ref": self._source_sha + self._baseline_sha}
            _require(type(entry) is tuple and len(entry) == 2 and type(entry[0]) is str and entry[0] == "record_payment_evidence" and type(entry[1]) in (dict, MappingProxyType), "cash_file_binding")
            _require(set(entry[1]) == set(arguments) and all(type(entry[1][key]) is type(value) and entry[1][key] == value for key, value in arguments.items()), "cash_file_binding")
            frozen_commands.append(("record_payment_evidence", MappingProxyType(arguments)))
        self.commands = tuple(frozen_commands)
        self.receipt = None
        self._connection = None
        self._finished = False

    def _expectations(self) -> dict:
        return {
            "expected_scope": self._context["expected_scope"],
            "expected_authority": self._context["expected_authority"],
            "expected_mode": self._context["expected_mode"],
            "expected_owner_id": self._context["expected_owner_id"],
            "expected_continuity_epoch": self._epoch,
        }

    def _arm(self, connection: sqlite3.Connection) -> None:
        """TEMP triggers log every row write to a package table; the log's own skip an UPDATE, DELETE or REPLACE of an entry. All die with finish or the connection."""
        connection.execute("CREATE TEMP TABLE rr_cfc_log(id INTEGER PRIMARY KEY, tbl TEXT NOT NULL, op TEXT NOT NULL, old_rowid INTEGER, new_rowid INTEGER)")
        for op, when in (("INSERT", " WHEN EXISTS (SELECT 1 FROM rr_cfc_log WHERE id=NEW.id)"), ("UPDATE", ""), ("DELETE", "")):
            connection.execute(f"CREATE TEMP TRIGGER rr_cfc_log_{op} BEFORE {op} ON temp.rr_cfc_log{when} BEGIN SELECT RAISE(IGNORE); END")
        for table in sorted(ledger.PACKAGE_TABLES):
            for op, old, new in (("INSERT", "NULL", "NEW.rowid"), ("UPDATE", "OLD.rowid", "NEW.rowid"), ("DELETE", "OLD.rowid", "NULL")):
                connection.execute(f"CREATE TEMP TRIGGER rr_cfc_{table}_{op} AFTER {op} ON main.{table} BEGIN INSERT INTO rr_cfc_log(tbl,op,old_rowid,new_rowid) VALUES ('{table}','{op}',{old},{new}); END")
        self._schema = connection.execute(_SCHEMA).fetchone()[0]

    def _log(self, connection: sqlite3.Connection) -> dict[tuple[str, str], list[tuple]]:
        """The writes this file made, once the TEMP schema is as begin left it, every write is one a file may make, and each count is start plus logged inserts (no deletes)."""
        _require(connection.execute(_SCHEMA).fetchone()[0] == self._schema, "cash_file_failed")
        log: dict[tuple[str, str], list] = {}
        for table, op, old, new in connection.execute("SELECT tbl,op,old_rowid,new_rowid FROM temp.rr_cfc_log ORDER BY id"):
            log.setdefault((table, op), []).append((old, new))
        after = _counts(connection)
        _require(set(log) <= _LOGGED and all(after[table] == self._counts[table] + len(log.get((table, "INSERT"), ())) for table in after)
                 and all(old == new for table in _UPDATES for old, new in log.get((table, "UPDATE"), ())), "cash_file_failed")
        return log

    def _disarm(self, connection: sqlite3.Connection) -> None:
        for kind, name in connection.execute("SELECT type,name FROM sqlite_temp_master WHERE name LIKE 'rr_cfc_%' ORDER BY type DESC").fetchall():  # triggers, then the log
            connection.execute(f"DROP {kind} temp.{name}")

    @_fixed_errors
    def begin(self, connection: sqlite3.Connection) -> None:
        _require(self._connection is None and not self._finished and isinstance(connection, sqlite3.Connection) and connection.in_transaction, "cash_file_failed")
        self._counts = _counts(connection)
        stored = {table: _table(connection, table) for table in ("financial_identity", "financial_meta", "financial_events", "payments", "evidence", "actions", "obligations", "cases")}  # what classification and finish compare against
        rows = {table: list(values.values()) for table, values in stored.items()}
        identity, sequence, head, count, last = self._anchor
        meta = rows["financial_meta"][0]
        ancestor = rows["financial_identity"][0]["genesis_head"] if sequence == 0 else _index(rows, "financial_events", "event_sequence").get(sequence, {}).get("head")
        sealed = connection.execute("SELECT last_sequence,segment_digest FROM main.history_segments WHERE segment_index=?", (count - 1,)).fetchone()  # the manifest's last segment is the store's, sealed at the baseline's sequence
        _require(rows["financial_identity"] == identity and ancestor == head and ((count, last) == (0, ledger.ZERO_DIGEST.hex().upper()) if sealed is None else (sealed[0], bytes(sealed[1]).hex().upper()) == (sequence, last)), "cash_file_binding")  # the store descends from the reviewed baseline: the same identity, event head and last sealed segment
        if self.intake is not None:  # one raw file is received once; its stored outcome is the answer to any resend of the same bytes
            _require(all((event["aggregate_type"], event["aggregate_id"]) != ("INTAKE", self.intake["source_sha256"]) for event in rows["financial_events"]), "cash_file_conflict")
        self._received, self._aliases = _payment_events(rows["financial_events"])
        self._plan = self._classify(rows, sequence)
        self._meta, self._obligations, self._cases = next(iter(stored["financial_meta"].items())), stored["obligations"], stored["cases"]
        self._payments, self._actions = _index(rows, "payments", "payment_id"), _index(rows, "actions", "action_id")
        self._arm(connection)
        self._changes, self._connection = connection.total_changes, connection
        return [skip for _, _, skip in self._plan]

    def _classify(self, rows: Mapping, baseline: int) -> tuple[tuple[str, str | None, dict | None], ...]:
        """Per row, before any write, (kind, the payment_id the owner must answer, the outcome it gets without running):
        RETRY of this row's own payment or ALIAS (its stored repeat of another) answer DUPLICATE unrun; OVERLAP (a new
        repeat: DUPLICATE, no cash) and NEW run. Any other reuse of a recorded id, an origin recorded with another amount
        or link, an item not in the period, or a new write to an obligation moved since the baseline is HELD (L3)."""
        payments, evidence, actions = (_index(rows, table, key) for table, key in (("payments", "payment_id"), ("evidence", "evidence_id"), ("actions", "action_id")))
        origins = {(row["obligation_id"], row["common_origin_id"]): row for row in rows["payments"]}
        obligations = {row["item_id"]: row["obligation_id"] for row in rows["obligations"] if row["period_id"] == self._context["expected_scope"]["period_id"]}
        later = [event for event in rows["financial_events"] if event["event_sequence"] > baseline]
        moved = {event["aggregate_id"] for event in later if event["aggregate_type"] == "OBLIGATION"}
        foreign = any(event["aggregate_type"] not in ("OBLIGATION", "INTAKE") for event in later)  # a rule or population change since the baseline moves every row
        plan = []
        for _, argument in self.commands:
            if argument["item_id"] not in obligations:
                plan.append(("HELD", None, _held(argument, "unknown_item")))
                continue
            obligation = obligations[argument["item_id"]]
            existing = origins.get((obligation, argument["common_origin_id"]))
            stored = evidence.get(argument["evidence_id"])
            restated = {**argument, "local_ref": stored["local_ref"]} if stored is not None else argument  # the same fact sent again in another file is still the same fact
            if argument["payment_id"] in payments:
                same = stored is not None and _recorded(restated, payments[argument["payment_id"]], stored, *self._received.get(argument["payment_id"], (None, None)), actions)
                kind, answer = ("RETRY", argument["payment_id"]) if same else ("already_recorded", None)
            elif existing is None:
                kind, answer = ("NEW", argument["payment_id"]) if stored is None else ("already_recorded", None)
            elif not (existing["amount_cents"] == argument["amount_cents"] and argument["pays_action_id"] in (None, self._received[existing["payment_id"]][1].get("pays_action_id"))
                      and (stored is not None or existing["active"] == 1 or argument["event_at_ms"] <= evidence[existing["reversed_by_evidence_id"]]["event_at_ms"])):  # a new repeat of a reversed payment is DUPLICATE only if it predates the reversal: later may be a re-presentment
                kind, answer = "conflict", None
            elif stored is None:
                kind, answer = "OVERLAP", existing["payment_id"]
            else:
                same = self._aliases.get(argument["evidence_id"]) == existing["payment_id"] and _matches(stored, _fact(restated))
                kind, answer = ("ALIAS", existing["payment_id"]) if same else ("already_recorded", None)
            if kind in ("NEW", "OVERLAP") and (foreign or obligation in moved):
                kind, answer = "stale", None
            skip = {"status": "DUPLICATE", "payment_id": answer, "reason": None} if kind in ("RETRY", "ALIAS") else None if answer else _held(argument, kind)
            plan.append(("HELD" if answer is None else kind, answer, skip))
        return tuple(plan)

    @_fixed_errors
    def finish(self, connection: sqlite3.Connection, results: object) -> set[str]:
        _require(connection is self._connection and connection.in_transaction and not self._finished and type(results) is list and len(results) == len(self.commands), "cash_file_failed")
        self._finished = True
        log = self._log(connection)
        added = {table: _table(connection, table, [new for _, new in log.get((table, "INSERT"), ())]) for table in _INSERTS}  # the rows this file inserted
        payments = {**self._payments, **{row["payment_id"]: row for row in added["payments"].values()}}
        evidence, events = ({row[key]: row for row in added[table].values()} for table, key in (("evidence", "evidence_id"), ("financial_events", "event_sequence")))
        actions, old_meta = self._actions, self._meta[1]
        first = sequence = old_meta["sequence"]
        head = old_meta["history_head"]
        revisions = {row["obligation_id"]: row["revision"] for row in self._obligations.values()}
        recorded, new_evidence, new_evaluations, deltas, touched, held = set(), set(), set(), {}, set(), set()
        held_cents = 0
        for (_, argument), (kind, answer, skip), result in zip(self.commands, self._plan, results):
            _require(type(result) is dict, "cash_file_failed")
            if skip is None and argument["item_id"] in held:
                skip = _held(argument, "depends_on_held")  # its expected_revision assumed the held row before it
            if skip is None and result.get("status") == "HELD":  # the owner refused the row; its savepoint rolled the row back
                _require(type(result.get("reason")) is str and _ID.fullmatch(result["reason"]) is not None, "cash_file_failed")
                skip = _held(argument, result["reason"])
            if skip is not None:
                _require(result == skip, "cash_file_failed")  # wrote nothing: the log, the event chain and total_changes below prove it
                if skip["status"] == "HELD":
                    held.add(argument["item_id"])
                    held_cents += argument["amount_cents"]
                continue
            _require(result == {"status": "RECORDED" if kind == "NEW" else "DUPLICATE", "payment_id": answer, "reason": None}, "cash_file_failed")
            sequence += 1  # each NEW or OVERLAP row appends exactly the next event, verified onto the chain
            event, obligation = events[sequence], payments[answer]["obligation_id"]
            head = ledger._verify_event(event, sequence, head)
            payload = json.loads(event["payload_json"])
            _require(event["before_revision"] == argument["expected_revision"] == revisions[obligation] and _matches(evidence.get(argument["evidence_id"]), _fact(argument)), "cash_file_failed")
            new_evidence.add(argument["evidence_id"])
            touched.add(obligation)
            if kind == "OVERLAP":  # exactly the alias label _verify_duplicate_evidence accepts; the repeated payment is unchanged
                alias = {"candidate_evidence_id": argument["evidence_id"], "existing_payment_id": answer, "common_origin_id": argument["common_origin_id"]}
                _require((event["kind"], event["aggregate_type"], event["aggregate_id"], event["after_revision"]) == ("PAYMENT_DUPLICATE_EVIDENCE", "OBLIGATION", obligation, revisions[obligation])
                         and {key: value for key, value in payload.items() if key != "rows"} == alias, "cash_file_failed")
                continue
            payment = payments[answer]
            _require(event["kind"] == "PAYMENT_RECEIVED" and payment["active"] == 1 and payment["reversed_by_evidence_id"] is None and _recorded(argument, payment, evidence[argument["evidence_id"]], event, payload, actions), "cash_file_failed")
            revisions[obligation] += 1
            deltas[obligation] = deltas.get(obligation, 0) + argument["amount_cents"]
            recorded.add(answer)
            new_evaluations.add(payload["evaluation_id"])
        if self.intake is not None:  # last, the raw file's intake facts with every row's outcome, as one event
            sequence += 1
            event = events[sequence]
            head = ledger._verify_event(event, sequence, head)
            _require((event["aggregate_type"], event["aggregate_id"], event["kind"], event["before_revision"], event["after_revision"]) == ("INTAKE", self.intake["source_sha256"], "INTAKE_RECEIVED", 0, 0)
                     and json.loads(event["payload_json"]) == {"intake": self.intake, "results": results}, "cash_file_failed")
        new_meta =_table(connection, "financial_meta", [self._meta[0]])[self._meta[0]]
        _require((new_meta["sequence"], new_meta["history_head"]) == (sequence, head), "cash_file_failed")
        _unchanged(old_meta, new_meta, {"sequence", "history_head"})
        for table, key, additions in (("payments", "payment_id", recorded), ("evidence", "evidence_id", new_evidence), ("evaluations", "evaluation_id", new_evaluations), ("financial_events", "event_sequence", set(range(first + 1, sequence + 1)))):
            keys = [row[key] for row in added[table].values()]
            _require(len(keys) == len(additions) and set(keys) == additions, "cash_file_failed")  # exactly the rows the file names: the log shows no other write to these tables
        changed = {"revision", "received_cash_cents", "shortfall_cents", "overage_cents", "cash_satisfied", "amount_satisfied", "timely", "verification_status", "case_status", "current_evaluation_id", "updated_at_ms"}
        rowids = {old for old, _ in log.get(("obligations", "UPDATE"), ())} | {rowid for rowid, row in self._obligations.items() if row["obligation_id"] in deltas}  # a row of an untouched obligation that was not written passes every check below
        now = _table(connection, "obligations", sorted(rowids))
        for rowid in rowids:
            old, new = self._obligations[rowid], now[rowid]
            key = old["obligation_id"]
            _unchanged(old, new, changed if key in deltas else frozenset())
            _require(new["received_cash_cents"] - old["received_cash_cents"] == deltas.get(key, 0) and new["revision"] == revisions[key], "cash_file_failed")
        rowids = [old for old, _ in log.get(("cases", "UPDATE"), ())]
        now = _table(connection, "cases", rowids)
        for rowid in rowids:
            old = self._cases[rowid]
            _unchanged(old, now[rowid], {"status", "updated_at_ms"} if old["obligation_id"] in deltas else frozenset())
        ledger.verify_obligation_connection(connection, *sorted(touched), **self._expectations())  # schema and meta once, then each touched obligation
        _require(bool(new_evidence) or self.intake is not None or connection.total_changes == self._changes, "cash_file_failed")  # a file of repeats writes nothing (III.3)
        self._disarm(connection)
        recorded_cents = sum(deltas.values())
        cash_before = sum(row["received_cash_cents"] for row in self._obligations.values())
        held_count = sum(result["status"] == "HELD" for result in results)
        self.receipt = {
            "contract": "RR/FINANCIAL/RECEIVER-CASH-RECEIPT/v3",
            "mode": "PREVIEW" if self._preview else "APPLIED",
            "source_sha256": self._source_sha, "baseline_sha256": self._baseline_sha,
            "row_count": len(self.commands), "recorded_count": len(recorded), "held_count": held_count,
            "duplicate_count": len(self.commands) - len(recorded) - held_count,
            "file_total_cents": self._source["total_cents"], "recorded_cents": recorded_cents, "held_cents": held_cents,
            "duplicate_cents": self._source["total_cents"] - recorded_cents - held_cents, "rows": list(results),
            "cash_before_cents": cash_before, "cash_after_cents": cash_before + recorded_cents,
            "cash_delta_cents": recorded_cents, "proofSuiteId": None,
            "production_usable": False, "activation": False,
        }
        if self._preview:  # never committed: the owner rolls the copy back (docs/CORE_REDESIGN.md "Cash-file capacity")
            _require(not connection.execute("PRAGMA foreign_key_check").fetchall(), "cash_file_failed")  # the deferred keys COMMIT would check
        return touched  # the obligations verified above, with nothing written since

    def conclude(self) -> None:
        """After the owner's own pre-COMMIT check: a preview ends here, so its copy rolls back with that check already passed."""
        if self._preview:
            raise CashFilePreview(self.receipt)
