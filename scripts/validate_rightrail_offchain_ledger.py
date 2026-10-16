#!/usr/bin/env python3
"""Run a dependency-free synthetic validation of the off-chain RightRail bridge."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bridge import rightrail_offchain as ledger  # noqa: E402


def main() -> int:
    config = json.loads((ROOT / "rust-engine" / "config.json").read_text(encoding="utf-8"))
    if config.get("proof_execution_enabled") is not False:
        raise ledger.LedgerError("proof_execution_enabled must remain false")
    if config.get("proof_backend") != "none":
        raise ledger.LedgerError("proof_backend must remain none")

    for schema_path in (
        ROOT / "interfaces" / "rightrail_offchain_ledger_event_v1.schema.json",
        ROOT / "interfaces" / "rightrail_offchain_remittance_event_v1.schema.json",
        ROOT / "interfaces" / "rightrail_offchain_reconciliation_report_v1.schema.json",
    ):
        value = json.loads(schema_path.read_text(encoding="utf-8"))
        if value.get("additionalProperties") is not False:
            raise ledger.LedgerError(f"{schema_path.name} must reject unknown fields")

    now = "2026-10-15T12:00:00Z"
    claim_hash = "0x" + "a" * 64
    with tempfile.TemporaryDirectory() as temporary_name:
        temporary = Path(temporary_name)
        ledger_path = temporary / "ledger.jsonl"
        result_path = temporary / "adjudication_result.json"
        result_path.write_text(
            json.dumps(
                {
                    "claim_id": "SYNTHETIC-VALIDATION-001",
                    "claim_hash": claim_hash,
                    "status": "APPROVED",
                    "reason": None,
                    "tx_submitted": False,
                    "tx_hash": None,
                }
            ),
            encoding="utf-8",
        )
        ledger.record_adjudication(
            ledger_path,
            result_path,
            owed_cents=10000,
            program="synthetic-medicaid",
            jurisdiction="US-TEST",
            recorded_at=now,
        )

        remittance_path = temporary / "remittance.json"
        remittance_path.write_text(
            json.dumps(
                {
                    "schema_version": ledger.REMITTANCE_SCHEMA,
                    "remittance_id": "SYNTHETIC-REM-001",
                    "claim_hash": claim_hash,
                    "event_kind": "PAYMENT",
                    "delta_cents": 10000,
                    "payer_trace_sha256": "b" * 64,
                    "source_artifact_sha256": "c" * 64,
                    "occurred_at": now,
                    "synthetic_data": True,
                }
            ),
            encoding="utf-8",
        )
        ledger.record_remittance(ledger_path, remittance_path, recorded_at=now)
        events = ledger.load_ledger(ledger_path)
        report = ledger.build_reconciliation_report(events, as_of=now)
        if report["claims"][0]["status"] != "RECONCILED":
            raise ledger.LedgerError("synthetic matching payment did not reconcile")
        if any(
            report[field] is not False
            for field in ("runtime_activation", "proof_binding", "proof_execution", "money_movement")
        ):
            raise ledger.LedgerError("off-chain report crossed a safety boundary")
        if report["settlement_backend"] != "none":
            raise ledger.LedgerError("off-chain report selected a settlement backend")

    print(
        json.dumps(
            {
                "status": "ok",
                "proof_execution_enabled": False,
                "event_count": report["ledger_event_count"],
                "ledger_head_sha256": report["ledger_head_sha256"],
                "report_sha256": report["report_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, json.JSONDecodeError, ledger.LedgerError) as error:
        print(json.dumps({"status": "error", "error": str(error)}, sort_keys=True))
        raise SystemExit(1) from None
