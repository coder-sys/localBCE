"""Hostile-data intake for receiver cash files: the absorb ladder, slice 1 (rrb/designs/hostile-data-corpus-v1.md).

L0 keeps the raw bytes under their SHA-256. L1 makes logged, reversible repairs, each naming its rule. L3 holds a row
it cannot take as-is, naming the missing fact, whose fault it is and the fix. L4 refuses a container it cannot trust
(unparseable, wrong contract or bindings, row count or control total wrong) whole, keeping only its raw bytes.
The applied and repaired rows form a canonical derived cash file that goes through the unchanged gate
(prepare_cash_file + apply_cash_file); a held row never reaches it, so it moves no money (I.3) and its cents are
receipted as unallocated (D3). No repair guesses: an amount or date in a sender's own format is held for a sender
profile, never converted blind (D5).
"""

import base64
from collections import Counter
from contextlib import closing
import hashlib
import os
from pathlib import Path
import re
import sqlite3

from app.right_rail_financial_canonical_json import decode, encode
from app.right_rail_financial_cash_file import MAX_FILE_BYTES, _header, _identifier, _integer, _refuse, apply_cash_file, prepare_cash_file
from app.right_rail_financial_cash_file_independent import MAX_ITEM_ROWS, CashFileError

ADAPTER = "receiver-cash-file@1"
RULES = {"amount_digits": 1, "bom": 1}
RULESET_DIGEST = hashlib.sha256(encode(RULES)).hexdigest().upper()
BOM = b"\xef\xbb\xbf"
ROW_FIELDS = {"item_id", "payment_id", "common_origin_id", "evidence_id", "amount_cents", "event_at_ms", "pays_action_id", "expected_revision"}
_DIGITS = re.compile(r"[0-9]{1,19}\Z")
_LOCAL_AMOUNT = re.compile(r"[0-9][0-9.,]*\Z")  # 1.000,00 or 1,000.00: dollars or cents, which mark is decimal is the sender's to say
_SENDER_RESEND = ("sender", "resend_row")
FAULTS = {
    "shape": _SENDER_RESEND, "identifier": _SENDER_RESEND, "amount": _SENDER_RESEND, "event_time": _SENDER_RESEND,
    "revision": _SENDER_RESEND, "duplicate": _SENDER_RESEND,
    "amount_format": ("sender", "sender_profile:amount_format"), "date_format": ("sender", "sender_profile:date_format"),
    "item_cap": ("state", "next_file"),
}
_SCHEMA = """
CREATE TABLE IF NOT EXISTS intake_receipts(
  source_sha256 TEXT NOT NULL, adapter TEXT NOT NULL, ruleset_digest TEXT NOT NULL, sender TEXT NOT NULL,
  received_at_ms INTEGER NOT NULL, received INTEGER NOT NULL, applied INTEGER NOT NULL, repaired INTEGER NOT NULL,
  held INTEGER NOT NULL, unallocated_cents INTEGER NOT NULL, receipt_json TEXT NOT NULL, receipt_digest TEXT NOT NULL,
  PRIMARY KEY(source_sha256, adapter), CHECK(received = applied + repaired + held), CHECK(unallocated_cents >= 0)) STRICT;
CREATE TABLE IF NOT EXISTS intake_holds(
  source_sha256 TEXT NOT NULL, adapter TEXT NOT NULL, row_index INTEGER NOT NULL, payment_id TEXT, reason TEXT NOT NULL,
  fault TEXT NOT NULL, fix TEXT NOT NULL, depends_on INTEGER,
  PRIMARY KEY(source_sha256, adapter, row_index), FOREIGN KEY(source_sha256, adapter) REFERENCES intake_receipts) STRICT;
CREATE TRIGGER IF NOT EXISTS intake_receipts_kept BEFORE UPDATE ON intake_receipts BEGIN SELECT RAISE(ABORT, 'intake_append_only'); END;
CREATE TRIGGER IF NOT EXISTS intake_receipts_kept_d BEFORE DELETE ON intake_receipts BEGIN SELECT RAISE(ABORT, 'intake_append_only'); END;
CREATE TRIGGER IF NOT EXISTS intake_holds_kept BEFORE UPDATE ON intake_holds BEGIN SELECT RAISE(ABORT, 'intake_append_only'); END;
CREATE TRIGGER IF NOT EXISTS intake_holds_kept_d BEFORE DELETE ON intake_holds BEGIN SELECT RAISE(ABORT, 'intake_append_only'); END;
"""


def _sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def _fact(rule, row_index, where, before, after):
    """One L1 repair: bytes `before` at `where` became `after`; undo puts `before` back. A row fact's `where` is a field name and its bytes are the canonical JSON of the value."""
    return {"rule_id": rule, "rule_version": RULES[rule], "row_index": row_index, "where": where,
            "before_b64": base64.b64encode(before).decode("ascii"), "after_b64": base64.b64encode(after).decode("ascii")}


def _ok(check, *args):
    try:
        check(*args)
        return True
    except CashFileError:
        return False


def _row(row, captured_at_ms):
    """(reason or None, amount in cents or None, repaired) for one row; the gate's own field checks, applied per row."""
    if type(row) is not dict or set(row) != ROW_FIELDS:
        return "shape", None, False
    if not all(_ok(_identifier, row[key]) for key in ("item_id", "payment_id", "common_origin_id", "evidence_id")) or not (row["pays_action_id"] is None or _ok(_identifier, row["pays_action_id"])):
        return "identifier", None, False
    amount = row["amount_cents"]
    repaired = type(amount) is str and _DIGITS.fullmatch(amount) is not None
    if repaired:
        amount = int(amount)  # zero-padded digits: one reading only
    elif type(amount) is str and _LOCAL_AMOUNT.fullmatch(amount):
        return "amount_format", None, False
    if not _ok(_integer, amount, 1, 2**63 - 1):
        return "amount", None, False
    if type(row["event_at_ms"]) is str:
        return "date_format", amount, False  # 01/02/2026: which is the month is the sender's to say
    if not _ok(_integer, row["event_at_ms"], 0, captured_at_ms):
        return "event_time", amount, False
    if not _ok(_integer, row["expected_revision"], 0, 9999):
        return "revision", amount, False
    return None, amount, repaired


def _same(left, right):
    try:
        return encode(left) == encode(right)
    except (ValueError, TypeError, RecursionError):
        return False


def absorb(raw, expected_scope, expected_source):
    """Sort a raw cash file into (derived file bytes or None, receipt fields), or refuse its container whole (CashFileError)."""
    repairs, text = [], raw
    if text.startswith(BOM):
        text = text[len(BOM):]
        repairs.append(_fact("bom", None, 0, BOM, b""))
    try:
        value = decode(text, "ascii", _refuse, _refuse)  # whitespace and CR/LF fall away in the parse; the derived file is canonical
    except (ValueError, UnicodeError, RecursionError):
        raise CashFileError("cash_file_format") from None
    source, rows = _header(value)
    if not _same(value["scope"], expected_scope) or not _same(source, expected_source):
        raise CashFileError("cash_file_binding")
    checked = [_row(row, source["captured_at_ms"]) for row in rows]
    known = [amount for _, amount, _ in checked if amount is not None]
    if sum(known) + len(rows) - len(known) > value["total_cents"] or len(known) == len(rows) and sum(known) != value["total_cents"]:
        raise CashFileError("cash_file_format")  # the control total is the container's own check: a held row's cents must still fit it
    reasons = [reason for reason, _, _ in checked]
    keyed = [i for i, reason in enumerate(reasons) if reason not in ("shape", "identifier")]
    keys = {i: (("payment", rows[i]["payment_id"]), ("evidence", rows[i]["evidence_id"]), ("origin", rows[i]["item_id"], rows[i]["common_origin_id"])) for i in keyed}
    seen = Counter(key for i in keyed for key in keys[i])
    for i in keyed:
        if reasons[i] is None and any(seen[key] > 1 for key in keys[i]):
            reasons[i] = "duplicate"  # which copy is real is the sender's to say
    depends, blocked, per_item = {}, {}, Counter()
    for i, row in enumerate(rows):
        item = row.get("item_id") if type(row) is dict and _ok(_identifier, row.get("item_id")) else None
        if reasons[i] is None and item in blocked:
            reasons[i], depends[i] = "depends_on_held", blocked[item]  # its expected revision counts on the held row
        elif reasons[i] is None:
            per_item[item] += 1
            reasons[i] = "item_cap" if per_item[item] > MAX_ITEM_ROWS else None
        if reasons[i] is not None and item is not None:
            blocked.setdefault(item, i)
    clean, holds = [], []
    for i, (reason, (_, amount, repaired)) in enumerate(zip(reasons, checked)):
        if reason is None:
            if repaired:
                repairs.append(_fact("amount_digits", i, "amount_cents", encode(rows[i]["amount_cents"]), encode(amount)))
            clean.append({**rows[i], "amount_cents": amount})
            continue
        fault, fix = FAULTS[reasons[depends[i]]] if i in depends else FAULTS[reason]
        payment = rows[i].get("payment_id") if type(rows[i]) is dict and _ok(_identifier, rows[i].get("payment_id")) else None
        holds.append({"row_index": i, "payment_id": payment, "reason": reason, "fault": fault, "fix": "release_row" if i in depends else fix, "depends_on": depends.get(i)})
    fixed = sum(1 for fact in repairs if fact["row_index"] is not None)
    applied_cents = sum(row["amount_cents"] for row in clean)
    derived = encode({**value, "row_count": len(clean), "total_cents": applied_cents, "rows": clean}) if clean else None
    return derived, {"sender": source["receiver_system_id"], "received": len(rows), "applied": len(clean) - fixed, "repaired": fixed,
                     "held": len(holds), "unallocated_cents": value["total_cents"] - applied_cents, "repairs": repairs, "holds": holds}


def intake_folder(owner):
    path = Path(owner.path).resolve()
    return path.with_name(path.name + ".intake")


def _keep(folder, sha, raw):
    """L0: the raw bytes, content-addressed, written whole or not at all."""
    target = folder / "raw" / sha
    if not target.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(sha + ".tmp")
        with open(temporary, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)


def _open(folder):
    connection = sqlite3.connect(folder / "intake.sqlite", isolation_level=None)
    connection.execute("PRAGMA foreign_keys=ON")
    connection.executescript(_SCHEMA)
    return connection


def _stored(connection, sha):
    row = connection.execute("SELECT receipt_json FROM intake_receipts WHERE source_sha256=? AND adapter=?", (sha, ADAPTER)).fetchone()
    return None if row is None else decode(row[0].encode("ascii"), "ascii", _refuse, _refuse)


def ingest_cash_file(owner, raw, baseline_bytes, *, expected_source_sha256, expected_baseline_sha256, expected_scope,
                     expected_source, expected_owner_id, expected_mode, trusted_authority):
    """Absorb one receiver cash file: keep it, apply its clean and repaired rows through the gate, hold the rest, receipt it.

    The same bytes again return the first receipt and write nothing. A refused container or gate refusal raises its
    fixed code with only the raw bytes kept, so the same file can be sent again.
    """
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_FILE_BYTES:
        raise CashFileError("cash_file_format")
    sha = _sha(raw)
    if sha != expected_source_sha256:
        raise CashFileError("cash_file_binding")
    folder = intake_folder(owner)
    _keep(folder, sha, raw)
    with closing(_open(folder)) as connection:
        done = _stored(connection, sha)
        if done is not None:
            return done
        derived, fields = absorb(raw, expected_scope, expected_source)
        gate = None
        if derived is not None:
            commands, context = prepare_cash_file(
                derived, baseline_bytes, expected_source_sha256=_sha(derived), expected_baseline_sha256=expected_baseline_sha256,
                expected_scope=expected_scope, expected_source=expected_source, expected_owner_id=expected_owner_id,
                expected_mode=expected_mode, trusted_authority=trusted_authority)
            gate = apply_cash_file(owner, commands, context)
        receipt = {"contract": "RR/FINANCIAL/INTAKE-RECEIPT/v1", "adapter": ADAPTER, "ruleset_digest": RULESET_DIGEST,
                   "source_sha256": sha, "derived_sha256": None if derived is None else _sha(derived),
                   "received_at_ms": owner.clock.now_ms(), **fields, "gate_receipt": gate}
        receipt["receipt_digest"] = _sha(encode(receipt))
        connection.execute("BEGIN IMMEDIATE")
        try:
            done = _stored(connection, sha)  # a racing ingest of the same bytes wrote first; the gate saw ours as its retry
            if done is not None:
                connection.execute("ROLLBACK")
                return done
            connection.execute("INSERT INTO intake_receipts VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (
                sha, ADAPTER, RULESET_DIGEST, receipt["sender"], receipt["received_at_ms"], receipt["received"], receipt["applied"],
                receipt["repaired"], receipt["held"], receipt["unallocated_cents"], encode(receipt).decode("ascii"), receipt["receipt_digest"]))
            connection.executemany("INSERT INTO intake_holds VALUES (?,?,?,?,?,?,?,?)", [
                (sha, ADAPTER, hold["row_index"], hold["payment_id"], hold["reason"], hold["fault"], hold["fix"], hold["depends_on"]) for hold in receipt["holds"]])
            connection.execute("COMMIT")
        except BaseException:
            connection.execute("ROLLBACK")
            raise
        return receipt
