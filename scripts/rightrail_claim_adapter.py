#!/usr/bin/env python3
"""Two pure functions for the live wiring: a localBCE claim as a RightRail payment request, and a RightRail decision
as a localBCE adjudication result.  Nothing here is wired into any workflow, runs RightRail, or decides anything.

Design: docs/integration/ELIG_EXTRACT_AND_WIRING_DESIGN.md part 2.  Synthetic, not legally verified, nonpayment.

`request_of(claim, secret)` reads a `claim_input.json` object as it is (the file's meaning does not change) and returns
a `Request` or a `SetAside`.  A claim is sent whole or not at all; nothing is corrected or guessed:

- shape the converter cannot read (`field`);
- the claim total is not the sum of the line charges (`total_mismatch`).  **The unit rule: `claim_amount` is in whole
  currency units (dollars) and `service_lines[].charge_cents` is in cents, so the check is
  `claim_amount * 100 == sum of the line charges`.**  A total that has cents cannot be written in `claim_amount`,
  so a claim whose lines do not sum to whole dollars never passes and is set aside;
- the billing NPI is not ten digits with a valid check digit (`bad_npi`);
- the service date cannot be converted (`service_date`).  The stated rule is rust-engine/rules.json `date_encoding`:
  an integer count of days since 1970-01-01.  A value that is not a whole number, is negative, or lands after year
  9999 is not converted.  A number that looks like `yyyymmdd` is never taken as a calendar date;
- a line's units are not a whole number above zero (`units`).

No decision flag crosses (`eligibility_active`, `aid_code`, `provider_enrolled` and the rest): RightRail takes none of
them from a claim.  Ids and the member key follow rightrail/app/right_rail_gate_ffs.py (`canonical_id`, `member_key`),
and the test compares them with that file.

**Assumption, for tests only: the rendering party is the billing NPI.**  localBCE's claim has no rendering provider.
RightRail's exclusion and provider-death rules check the rendering party, so this must be resolved before anything
real.  Every request carries the assumption by name.

`result_of(claim, decision)` returns the fields of `adjudication_result.json`.  **Only a RightRail ALLOW on every
line of the claim gives `APPROVED`.**  A hold, a review, an answered repeat and a set-aside never do.  The file has two
status values, so each of those is written `DENIED`, but **a RightRail hold is not a final denial**: the real outcome
is in the `rightrail_*` fields and `rightrail_final` says whether it can still change.  A decision that is missing,
incomplete or not understood raises `NoDecision`: no result is made, and never an approval.
"""
from __future__ import annotations

import datetime
import hashlib
import re
import sys
from pathlib import Path
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import g_rule_parity  # noqa: E402  the reason mapping, kept in one place

FLOW = "FFS_CLAIM"
DOLLAR = 100  # cents in one unit of `claim_amount`
RENDERING_ASSUMPTION = "rendering_party_is_billing_npi_test_only"
_IDS = b"RR/GATE/FFS-ID/v1\x00"
_MEMBER = b"RR/GATE/MEMBER-KEY/v1\x00"
_NPI = re.compile(r"[0-9]{10}\Z")
_EPOCH = datetime.date(1970, 1, 1)
_MAX_DAYS = (datetime.date(9999, 12, 31) - _EPOCH).days
OUTCOMES = ("ALLOW", "HOLD", "HUMAN_REVIEW", "ANSWERED")
FINAL = {"ALLOW": True, "ANSWERED": True, "HOLD": False, "HUMAN_REVIEW": False, "SET_ASIDE": False}
# A RightRail reason that exactly one localBCE denial maps onto (g_rule_parity.G_TO_LEAN read backwards).  A reason two
# denials share (MEMBER_NOT_ENROLLED: G1 and G3) has no entry: the RightRail name is given, never a guess.
_BACK: dict = {}
for _g, _reasons in g_rule_parity.G_TO_LEAN.items():
    for _r in _reasons:
        _BACK.setdefault(_r, set()).add(_g)
LOCAL_NAME = {r: next(iter(gs)) for r, gs in _BACK.items() if len(gs) == 1}


class Line(NamedTuple):
    line_id: str
    line_number: str
    flow: str
    member_key: str  # hex
    payee: str
    rendering: str
    date: int  # yyyymmdd
    procedure: str
    units: int
    cents: int


class Request(NamedTuple):
    claim_id: str
    payment_id: str
    flow: str
    member_key: str  # hex
    payee: str
    cents: int  # the claim total in cents: the sum of its line charges
    lines: tuple
    assumptions: tuple


class SetAside(NamedTuple):
    claim_id: str
    cause: str
    cents: int  # the claim's stated amount in cents (`claim_amount` * 100) when it is a whole number, else 0


class NoDecision(ValueError):
    """Nothing was decided for the claim: no result is made, and never an approval."""


def canonical_id(prefix: str, *parts: str) -> str:
    """rightrail/app/right_rail_gate_ffs.py `canonical_id`: the same claim always gets the same id."""
    body = b"".join(len(p.encode()).to_bytes(2, "big") + p.encode() for p in parts)
    return prefix + hashlib.sha3_256(_IDS + body).hexdigest()[:32]


def member_key(secret: bytes, member_id: str) -> bytes:
    """rightrail/app/right_rail_gate_ffs.py `member_key`: the key the eligibility extract's reader gives the member."""
    return hashlib.sha3_256(len(secret).to_bytes(2, "big") + secret + _MEMBER + member_id.encode()).digest()


def npi_ok(npi) -> bool:
    """rightrail/app/right_rail_reader_leie.py `npi_ok`: ten digits whose Luhn sum with the 80840 prefix is a multiple
    of ten."""
    if not isinstance(npi, str) or not _NPI.match(npi):
        return False
    total = 0
    for i, c in enumerate(reversed("80840" + npi)):
        d = int(c) * (2 if i % 2 else 1)
        total += d - 9 if d > 9 else d
    return total % 10 == 0


def service_day(days) -> int | None:
    """The calendar day `days` days after 1970-01-01, as yyyymmdd; None when the stated rule cannot convert it."""
    if type(days) is not int or not 0 <= days <= _MAX_DAYS:
        return None
    d = _EPOCH + datetime.timedelta(days)
    return d.year * 10000 + d.month * 100 + d.day


def _whole(v) -> bool:
    return type(v) is int and v >= 0


def _text(v) -> bool:
    return isinstance(v, str) and v != ""


def request_of(claim, secret: bytes):
    """The claim as a `Request`, or the `SetAside` that says why it is not sent."""
    if not isinstance(secret, bytes) or not secret:
        raise ValueError("the tenant's member-key secret is required")
    claim_id = claim.get("claim_id") if isinstance(claim, dict) else None
    amount = claim.get("claim_amount") if isinstance(claim, dict) else None

    def aside(cause: str) -> SetAside:
        return SetAside(claim_id if _text(claim_id) else "", cause, amount * DOLLAR if _whole(amount) else 0)

    if not isinstance(claim, dict):
        return aside("field")
    lines = claim.get("service_lines")
    if not (_text(claim_id) and _text(claim.get("member_id")) and _whole(amount) and isinstance(lines, list) and lines):
        return aside("field")
    for ln in lines:
        if not (isinstance(ln, dict) and _text(ln.get("procedure_code")) and _whole(ln.get("charge_cents"))
                and "units" in ln):
            return aside("field")
    total = sum(ln["charge_cents"] for ln in lines)
    if total != amount * DOLLAR:  # whole dollars against cents; never corrected
        return aside("total_mismatch")
    npi = claim.get("provider_npi")
    if not npi_ok(npi):
        return aside("bad_npi")
    day = service_day(claim.get("date_of_service_from"))
    if day is None:
        return aside("service_date")
    if any(type(ln["units"]) is not int or ln["units"] <= 0 for ln in lines):
        return aside("units")
    key = member_key(secret, claim["member_id"]).hex()
    out = tuple(Line(canonical_id("L", npi, claim_id, str(n)), str(n), FLOW, key, npi, npi, day, ln["procedure_code"],
                     ln["units"], ln["charge_cents"]) for n, ln in enumerate(lines, 1))
    return Request(claim_id, canonical_id("C", npi, claim_id), FLOW, key, npi, total, out, (RENDERING_ASSUMPTION,))


def claim_hash(claim_id: str, claim_amount: int) -> str:
    """rust-engine/src/main.rs `claim_hash_32`: SHA-256 of the claim id and the amount as eight big-endian bytes.  The
    amount is `claim_amount` exactly as the file gives it (whole dollars), as the Rust engine hashes it."""
    return "0x" + hashlib.sha256(claim_id.encode() + claim_amount.to_bytes(8, "big")).hexdigest()


def _base(claim) -> dict:
    if not (isinstance(claim, dict) and _text(claim.get("claim_id")) and _whole(claim.get("claim_amount"))
            and claim["claim_amount"] < 2 ** 64):
        raise NoDecision("the claim has no id or amount to report against")
    return {"claim_id": claim["claim_id"], "claim_hash": claim_hash(claim["claim_id"], claim["claim_amount"]),
            "tx_submitted": False, "tx_hash": None}


def _reason(outcome: str, reasons: list) -> str:
    """The `reason` text of a result that is not approved."""
    if outcome == "HOLD":
        mapped = [LOCAL_NAME[r] for r in reasons if r in LOCAL_NAME]
        return mapped[0] if mapped else reasons[0] if reasons else "RIGHTRAIL_HOLD"
    return "RIGHTRAIL_" + outcome


def result_of(claim, decision) -> dict:
    """The adjudication result for `claim` given `decision`: the claim's `Request` with RightRail's rows for it
    (`(request, rows)`, each row `(payment id, line position, outcome, reasons)` as `decide_claims` returns them), or
    the `SetAside` that kept it from being sent."""
    out = _base(claim)
    if isinstance(decision, SetAside):
        if decision.claim_id != out["claim_id"] or not _text(decision.cause):
            raise NoDecision("the set-aside is not this claim's")
        outcome, reasons, lines, payment, cause = "SET_ASIDE", [], [], None, decision.cause
    else:
        try:
            request, rows = decision
            rows = [tuple(r) for r in rows]
        except (TypeError, ValueError):
            raise NoDecision("no decision") from None
        if not isinstance(request, Request) or request.claim_id != out["claim_id"]:
            raise NoDecision("the decision is not this claim's")
        seen = {}
        for row in rows:
            if len(row) != 4:
                raise NoDecision("a decision row is not understood")
            pid, at, what, why = row
            if (pid != request.payment_id or type(at) is not int or not 0 <= at < len(request.lines) or at in seen
                    or what not in OUTCOMES or not isinstance(why, (tuple, list)) or not all(_text(x) for x in why)):
                raise NoDecision("a decision row is not understood")
            seen[at] = (what, sorted(set(why)))
        if len(seen) != len(request.lines):  # every line answered, once
            raise NoDecision("the decision does not cover every line")
        said = {what for what, _ in seen.values()}
        # the claim takes its worst line: a hold over a review over an answered repeat; ALLOW only when every line is
        outcome = next(o for o in ("HOLD", "HUMAN_REVIEW", "ANSWERED", "ALLOW") if o in said)
        reasons = sorted({r for what, why in seen.values() for r in why if what == outcome})
        lines = [{"line": at + 1, "outcome": seen[at][0], "reasons": seen[at][1]} for at in sorted(seen)]
        payment, cause = request.payment_id, None
    approved = outcome == "ALLOW"  # and nothing else, ever
    out.update(status="APPROVED" if approved else "DENIED", reason=None if approved else _reason(outcome, reasons),
               rightrail_outcome=outcome, rightrail_reasons=reasons, rightrail_final=FINAL[outcome],
               rightrail_payment_id=payment, rightrail_set_aside_cause=cause, rightrail_lines=lines)
    return out
