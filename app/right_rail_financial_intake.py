"""Hostile-data intake for receiver cash files: the absorb ladder (rrb/designs/hostile-data-corpus-v1.md).

L0 keeps the raw bytes under their SHA-256. L1 makes logged, reversible repairs, each naming its rule. L2 resolves a
row the store already has to the payment it repeats. L3 holds a row it cannot take, naming the reason, whose fault it
is and the fix. L4 refuses a container it cannot trust (unparseable, wrong contract or bindings, row count or control
total wrong) whole, keeping only its raw bytes. The rows this module can read form a canonical derived cash file that
the gate judges row by row in the owner's one transaction (D2); the raw file's facts and every row's outcome land in
the same transaction as one INTAKE event, so a crash leaves all or nothing. A held row moves no money (I.3); its cents
stay unallocated (D3) until a named release. No repair guesses: an amount or date in a sender's own format is held for a sender profile, never converted blind (D5).
"""

import base64
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re

from app.right_rail_financial_canonical_json import decode, encode
from app.right_rail_financial_cash_file import MAX_FILE_BYTES, _header, _identifier, _integer, _refuse, apply_cash_file, prepare_cash_file
from app.right_rail_financial_cash_file_independent import MAX_ITEM_ROWS, CashFileError
from app.right_rail_financial_owner import FinancialConflictError

ADAPTER = "receiver-cash-file@1"
RULES = {"amount_digits": 1, "bom": 1, "number_text": 1}
RULESET_DIGEST = hashlib.sha256(encode(RULES)).hexdigest().upper()
BOM = b"\xef\xbb\xbf"
ROW_FIELDS = {"item_id", "payment_id", "common_origin_id", "evidence_id", "amount_cents", "event_at_ms", "pays_action_id", "expected_revision"}
_DIGITS = re.compile(r"[0-9]{1,19}\Z")
_LOCAL_AMOUNT = re.compile(r"[0-9][0-9.,]*\Z")  # 1.000,00 or 1,000.00: dollars or cents, which mark is decimal is the sender's to say
_TOKEN = re.compile(rb'"(?:[^"\\]|\\.)*"|-?[0-9][0-9.eE+-]*')  # a string (skipped whole) or a number
_LEADING_ZERO = re.compile(rb"-?0[0-9]")


def _sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def _fact(rule, row_index, where, before, after):
    """One L1 repair: bytes `before` became `after` at `where`; undo, newest first, puts `before` back. A byte fact's
    `where` is its offset in the bytes just after it; a row fact's is a field name and its bytes are canonical JSON."""
    return {"rule_id": rule, "rule_version": RULES[rule], "row_index": row_index, "where": where,
            "before_b64": base64.b64encode(before).decode("ascii"), "after_b64": base64.b64encode(after).decode("ascii")}


def _ok(check, *args):
    try:
        check(*args)
        return True
    except CashFileError:
        return False


def _readable(value):
    return value if _ok(_identifier, value) else None


def _row(row, captured_at_ms):
    """(reason or None, amount in cents or None, repaired) for one row; the gate's own field checks, applied per row."""
    if type(row) is not dict or set(row) != ROW_FIELDS:
        return "shape", None, False
    if any(type(value) is str and not value.isascii() for value in row.values()):
        return "encoding", None, False  # which characters the sender meant is the sender's to say
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
    """Sort a raw cash file into (derived file bytes, intake facts), or refuse its container whole (CashFileError). The derived file carries no row when every raw row is held."""
    repairs, text = [], raw
    if text.startswith(BOM):
        text = text[len(BOM):]
        repairs.append(_fact("bom", None, 0, BOM, b""))
    first = len(repairs)

    def quote(match):  # number_text: a leading-zero number, which JSON cannot read, kept as its text for the row checks
        token = match.group()
        if _LEADING_ZERO.match(token) is None:
            return token
        repairs.append(_fact("number_text", None, match.start() + 2 * (len(repairs) - first), token, b'"' + token + b'"'))
        return b'"' + token + b'"'
    try:
        value = decode(_TOKEN.sub(quote, text), "latin-1", _refuse, _refuse)  # every byte reads; a row's non-ASCII is held, a header's refused
    except (ValueError, UnicodeError, RecursionError):
        raise CashFileError("cash_file_format") from None
    source, rows = _header(value)
    if not _same(value["scope"], expected_scope) or not _same(source, expected_source):
        raise CashFileError("cash_file_binding")
    checked = [_row(row, source["captured_at_ms"]) for row in rows]
    amounts = [amount for _, amount, _ in checked]
    known = sum(amount for amount in amounts if amount is not None)
    if known + amounts.count(None) > value["total_cents"] or None not in amounts and known != value["total_cents"]:
        raise CashFileError("cash_file_format")  # the control total is the container's own check: a held row's cents must still fit it
    if amounts.count(None) == 1:
        amounts[amounts.index(None)] = value["total_cents"] - known  # the one unreadable amount, by the control total
    reasons = [reason for reason, _, _ in checked]
    keyed = [i for i, reason in enumerate(reasons) if reason not in ("shape", "encoding", "identifier")]
    keys = {i: (("payment", rows[i]["payment_id"]), ("evidence", rows[i]["evidence_id"]), ("origin", rows[i]["item_id"], rows[i]["common_origin_id"])) for i in keyed}
    seen = Counter(key for i in keyed for key in keys[i])
    for i in keyed:
        if reasons[i] is None and any(seen[key] > 1 for key in keys[i]):
            reasons[i] = "duplicate"  # which copy is real is the sender's to say
    items = [_readable(row.get("item_id")) if type(row) is dict else None for row in rows]
    blocked, per_item = set(), Counter()
    for i, item in enumerate(items):
        if reasons[i] is None and item in blocked:
            reasons[i] = "depends_on_held"  # its expected revision counts on the held row
        elif reasons[i] is None:
            per_item[item] += 1
            reasons[i] = "item_cap" if per_item[item] > MAX_ITEM_ROWS else None
        if reasons[i] is not None and item is not None:
            blocked.add(item)
    clean = []
    for i, (reason, (_, amount, repaired)) in enumerate(zip(reasons, checked)):
        if reason is None:
            if repaired:
                repairs.append(_fact("amount_digits", i, "amount_cents", encode(rows[i]["amount_cents"]), encode(amount)))
            clean.append({**rows[i], "amount_cents": amount})
    facts = [{"item_id": item, "payment_id": _readable(row.get("payment_id")) if type(row) is dict else None, "common_origin_id": _readable(row.get("common_origin_id")) if type(row) is dict else None, "amount_cents": amount, "reason": reason}
             for item, row, amount, reason in zip(items, rows, amounts, reasons)]
    derived = encode({**value, "row_count": len(clean), "total_cents": sum(row["amount_cents"] for row in clean), "rows": clean})
    return derived, {"sender": source["receiver_system_id"], "control_total_cents": value["total_cents"], "repairs": repairs, "rows": facts}


def _receipt(record):
    """The intake receipt, read only from the stored INTAKE event: the same bytes always get the same receipt."""
    payload = json.loads(record["payload_json"])
    receipt = {"contract": "RR/FINANCIAL/INTAKE-RECEIPT/v3", **{key: payload["intake"][key] for key in ("adapter", "ruleset_digest", "source_sha256", "derived_sha256", "sender", "repairs")},
               "received_at_ms": record["committed_at_ms"], **payload["totals"], "rows": payload["outcomes"]}
    receipt["receipt_digest"] = _sha(encode(receipt))
    return receipt


def held_cash(owner):
    """D3: the cash every intake holds unallocated, net of the holds a later file released by evidence: a row that went
    through with the same payment id and amount releases the earliest open hold for them; the original stays in history."""
    open_holds, released, unallocated = {}, [], 0
    for record in owner.intake_records():
        receipt = _receipt(record)
        unallocated += receipt["unallocated_cents"]
        for row in receipt["rows"]:
            waiting = open_holds.get((row["payment_id"], row["amount_cents"]))
            if row["status"] != "HELD" and waiting:
                released.append({**waiting.pop(0), "released_by": receipt["source_sha256"], "released_row": row["row_index"]})
                unallocated -= row["amount_cents"]
        for row in receipt["rows"]:
            if row["status"] == "HELD":
                open_holds.setdefault((row["payment_id"], row["amount_cents"]), []).append({"source_sha256": receipt["source_sha256"], "row_index": row["row_index"], "payment_id": row["payment_id"], "amount_cents": row["amount_cents"], "reason": row["basis"]})
    return {"unallocated_cents": unallocated, "holds": [hold for holds in open_holds.values() for hold in holds], "released": released}


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


def _stored(owner, sha):
    return next(iter(owner.intake_records(sha)), None)


def ingest_cash_file(owner, raw, baseline_bytes, *, expected_source_sha256, expected_baseline_sha256, expected_scope,
                     expected_source, expected_owner_id, expected_mode, trusted_authority):
    """Absorb one receiver cash file: keep it, let the gate judge every row it can read, hold the rest, receipt it.

    The same bytes again return the first receipt and write nothing. A refused container or gate refusal raises its
    fixed code with only the raw bytes kept, so the same file can be sent again.
    """
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_FILE_BYTES:
        raise CashFileError("cash_file_format")
    sha = _sha(raw)
    if sha != expected_source_sha256:
        raise CashFileError("cash_file_binding")
    _keep(intake_folder(owner), sha, raw)
    record = _stored(owner, sha)
    if record is None:
        derived, facts = absorb(raw, expected_scope, expected_source)
        facts = {"adapter": ADAPTER, "ruleset_digest": RULESET_DIGEST, "source_sha256": sha, "derived_sha256": _sha(derived), **facts}
        try:
            commands, context = prepare_cash_file(
                derived, baseline_bytes, expected_source_sha256=facts["derived_sha256"], expected_baseline_sha256=expected_baseline_sha256,
                expected_scope=expected_scope, expected_source=expected_source, expected_owner_id=expected_owner_id,
                expected_mode=expected_mode, trusted_authority=trusted_authority, intake=facts)
            apply_cash_file(owner, commands, context)
        except (CashFileError, FinancialConflictError):
            if _stored(owner, sha) is None:
                raise
        record = _stored(owner, sha)  # a racing ingest of the same bytes may have written first: its record is the answer
    return _receipt(record)
