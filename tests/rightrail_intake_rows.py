"""The tests' one route for a payment row (R5): a one-row receiver cash file through real intake, answered as a direct
record was (RECORDED or DUPLICATE with the projection), or HELD with its reason. An exact resend returns its first answer."""

import hashlib
from pathlib import Path
import tempfile

from app import right_rail_financial_intake as intake
from app.right_rail_financial_canonical_json import encode

_STATUS = {"ADMITTED": "RECORDED", "REPAIRED": "RECORDED", "RESOLVED": "DUPLICATE", "HELD": "HELD"}


def pay(store, *, item_id, payment_id, common_origin_id, amount_cents, evidence_id, event_at_ms, expected_revision=None,
        pays_action_id=None, source_id="synthetic-payment-source", source_version="fixture-v1"):
    owner = getattr(store, "owner", store)
    if expected_revision is None:
        with owner._read_snapshot() as connection:
            expected_revision = owner._get_obligation_row(connection, item_id)["revision"]
    scope = owner._scope_value()
    source = {"source_id": source_id, "version": source_version, "receiver_system_id": "fixture-receiver",
              "capture_id": f"capture:{evidence_id}:{expected_revision}", "captured_at_ms": event_at_ms}
    row = {"item_id": item_id, "payment_id": payment_id, "common_origin_id": common_origin_id, "evidence_id": evidence_id,
           "amount_cents": amount_cents, "event_at_ms": event_at_ms, "pays_action_id": pays_action_id, "expected_revision": expected_revision}
    raw = encode({"contract": "RR/FINANCIAL/RECEIVER-CASH-FILE/v1", "source_class": "SYNTHETIC_RECEIVER_CASH", "scope": scope,
                  "source": source, "row_count": 1, "total_cents": amount_cents, "rows": [row]})
    baseline = owner.export_history(Path(tempfile.mkdtemp(dir=Path(owner.path).resolve().parent)) / "history")
    receipt = intake.ingest_cash_file(owner, raw, baseline, expected_source_sha256=hashlib.sha256(raw).hexdigest().upper(), expected_baseline_sha256=hashlib.sha256(baseline).hexdigest().upper(), expected_scope=scope,
                                      expected_source=source, expected_owner_id=owner.owner_id, expected_mode=owner.mode, trusted_authority=owner.trusted_authority)
    (outcome,) = receipt["rows"]
    answer = {"status": _STATUS[outcome["status"]]}
    if outcome["status"] == "HELD":
        answer["reason"] = outcome["basis"]
    else:
        answer["payment_id"] = outcome["basis"].removeprefix("duplicate_of:") if outcome["status"] == "RESOLVED" else payment_id
    with owner._read_snapshot() as connection:
        return {**answer, **owner._projection_for_row(owner._get_obligation_row(connection, item_id))}
