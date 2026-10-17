"""The tests' one route for a payment row (R5): a receiver cash file through real intake. pay() sends one row, answered
as a direct record was (RECORDED or DUPLICATE with the projection), or HELD with its reason; an exact resend returns its
first answer. ingest() sends many: a row without expected_revision is at its item's revision as the file reaches it."""

import hashlib

from app import right_rail_financial_intake as intake
from app.right_rail_financial_canonical_json import encode

_STATUS = {"ADMITTED": "RECORDED", "REPAIRED": "RECORDED", "RESOLVED": "DUPLICATE", "HELD": "HELD"}


def ingest(store, rows, source_id="synthetic-payment-source", source_version="fixture-v1"):
    owner, turn, full = getattr(store, "owner", store), {}, []
    with owner._read_snapshot() as connection:
        for row in rows:
            assert row.keys() <= intake.ROW_FIELDS, row  # a misspelt field is the test's error, never a held row
            revision = turn.setdefault(row["item_id"], owner._get_obligation_row(connection, row["item_id"])["revision"])
            full.append({"pays_action_id": None, **row, "expected_revision": revision if row.get("expected_revision") is None else row["expected_revision"]})
            turn[row["item_id"]] += 1
    scope, first = owner._scope_value(), full[0]
    source = {"source_id": source_id, "version": source_version, "receiver_system_id": "fixture-receiver",
              "capture_id": f"capture:{first['evidence_id']}:{first['expected_revision']}", "captured_at_ms": first["event_at_ms"]}
    raw = encode({"contract": "RR/FINANCIAL/RECEIVER-CASH-FILE/v1", "source_class": "SYNTHETIC_RECEIVER_CASH", "scope": scope,
                  "source": source, "row_count": len(full), "total_cents": sum(row["amount_cents"] for row in full), "rows": full})
    baseline = owner.history_baseline()  # read only: a payment adds no commit but its own
    return intake.ingest_cash_file(owner, raw, baseline, expected_source_sha256=hashlib.sha256(raw).hexdigest().upper(), expected_baseline_sha256=hashlib.sha256(baseline).hexdigest().upper(), expected_scope=scope,
                                   expected_source=source, expected_owner_id=owner.owner_id, expected_mode=owner.mode, trusted_authority=owner.trusted_authority)


def pay(store, *, source_id="synthetic-payment-source", source_version="fixture-v1", **row):
    (outcome,) = ingest(store, [row], source_id, source_version)["rows"]
    status, owner = outcome["status"], getattr(store, "owner", store)
    answer = {"status": _STATUS[status], **({"reason": outcome["basis"]} if status == "HELD" else {"payment_id": outcome["basis"].removeprefix("duplicate_of:") if status == "RESOLVED" else row["payment_id"]})}
    with owner._read_snapshot() as connection:
        return {**answer, **owner._projection_for_row(owner._get_obligation_row(connection, row["item_id"]))}
