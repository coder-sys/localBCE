"""Steps shared by the read-only derived packs (line pack, follow-through pack).

A derived pack is built only from a Continuity package that the independent checker binds, row for
row, to a fully verified store opened read-only; it never writes to the store.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re

from app.right_rail_financial_custody import Custody
from app.right_rail_financial_owner_independent import MAX_CENTS, verify_continuity_package, verify_database
from app.right_rail_financial_switch import _canonical_json


NOT_HELD = (  # never in the Ledger; stated on every pack
    "not-held:clinical-and-medical-necessity-records",
    "not-held:eligibility-and-immigration-status",
    "not-held:mco-encounter-detail",
    "not-held:per-claim-service-date",
    "not-held:waiver-and-spa-coverage-determination",
)
_QUARTER_RE = re.compile(r"FFY([0-9]{4})Q([1-4])\Z")


class DerivedError(ValueError):
    """A derived builder's code; the builder prefixes it, and nothing partial is returned."""


def cents(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= MAX_CENTS:
        raise DerivedError(label)
    return value


def hex_upper(value: bytes) -> str:
    return value.hex().upper()


def signed_pack(record: dict, custody: object, database: object, maximum: int) -> bytes:
    """The pack's canonical bytes, signed with the owner's custody key at the custody log's tail (H2): ``signer``
    names the key and the custody record, ``signature`` covers every other byte (``custody.verify_pack``)."""
    if type(custody) is not Custody:
        raise DerivedError("custody-required")
    record["signer"] = custody.pack_signer(record["source"], Path(database))
    return _canonical_json({**record, "signature": custody.sign_pack(_canonical_json(record, maximum=maximum))}, maximum=maximum)


def quarter_window(quarter: str) -> tuple[int, int]:
    """[start, end) in UTC milliseconds for a federal fiscal quarter "FFYyyyyQn" (Q1 starts 1 October)."""
    match = _QUARTER_RE.fullmatch(quarter) if type(quarter) is str else None
    if match is None:
        raise DerivedError("quarter")
    year, number = int(match.group(1)), int(match.group(2))
    if not 1971 <= year <= 9998:
        raise DerivedError("quarter")
    months = [(year - 1, 10), (year, 1), (year, 4), (year, 7), (year, 10)]
    start, end = (datetime(y, m, 1, tzinfo=timezone.utc) for y, m in months[number - 1:number + 1])
    return int(start.timestamp()) * 1000, int(end.timestamp()) * 1000


def quarter_of(at_ms: int) -> str:
    moment = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=at_ms)
    return f"FFY{moment.year + (moment.month >= 10)}Q{(moment.month + 2) % 12 // 3 + 1}"


def bound_control_pack(rows: dict, prefix: str, content_sha256: str, *, version: int, before_ms: int, label: str) -> dict:
    """The one approved pack of ``version``, published before ``before_ms``, that lists ``prefix + content_sha256``, once."""
    published = {e["aggregate_id"]: e["committed_at_ms"] for e in rows["financial_events"] if e["kind"] == "CONTROL_PACK_PUBLISHED"}
    refs = lambda pack: json.loads(pack["source_refs_json"])["values"]
    bound = [pack for pack in rows["control_packs"] if pack["status"] == "APPROVED" and published[pack["pack_id"]] < before_ms
             and pack["version"] == version and prefix + content_sha256 in refs(pack)]
    if len(bound) != 1:
        raise DerivedError(f"{label}-not-in-approved-control-pack")
    if sum(ref.startswith(prefix) for ref in refs(bound[0])) != 1:
        raise DerivedError(f"{label}-ref-not-unique")
    return bound[0]


def verified_rows(database: object, package_bytes: bytes, *, trusted_authority: object, expected_scope: object, generated_at_ms: int) -> tuple[dict, dict, dict]:
    """(store, rows, source): the verified store, its checker-bound rows and the source dict every pack names."""
    cents(generated_at_ms, "generated-at")
    trust = {"expected_scope": expected_scope, "expected_authority": trusted_authority}
    store = verify_database(database, current_snapshot_package=package_bytes, **trust)
    rows = verify_continuity_package(package_bytes, **trust, _include_rows=True)["_decoded_rows"]
    if generated_at_ms < max([e["committed_at_ms"] for e in rows["financial_events"]] + [e["received_at_ms"] for e in rows["evidence"]], default=0):
        raise DerivedError("generated-before-package")
    scope = store["scope"]
    return store, rows, {
        "owner_id": store["owner_id"],
        "mode": store["mode"],
        "genesis_head": hex_upper(rows["financial_identity"][0]["genesis_head"]),
        "sequence": store["sequence"],
        "history_head": store["history_head"],
        "package_digest": store["continuity"]["package_digest"],
        "package_sha256": hashlib.sha256(package_bytes).hexdigest().upper(),
        **{key: scope[key] for key in ("state_id", "deployment_id", "program_id", "period_id", "currency")},
    }
