from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from bridge import rightrail_offchain as ledger


CLAIM_HASH = "0x" + "a" * 64
OTHER_CLAIM_HASH = "0x" + "b" * 64
NOW = "2026-10-15T12:00:00Z"


class RightRailOffchainLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.ledger_path = self.root / "state" / "ledger.jsonl"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_result(
        self,
        *,
        claim_hash: str = CLAIM_HASH,
        status: str = "APPROVED",
        reason: str | None = None,
        tx_submitted: bool = False,
        tx_hash: str | None = None,
    ) -> Path:
        path = self.root / "adjudication_result.json"
        path.write_text(
            json.dumps(
                {
                    "claim_id": "SYNTHETIC-CLAIM-001",
                    "claim_hash": claim_hash,
                    "status": status,
                    "reason": reason,
                    "tx_submitted": tx_submitted,
                    "tx_hash": tx_hash,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return path

    def write_remittance(
        self,
        *,
        remittance_id: str = "REM-001",
        claim_hash: str = CLAIM_HASH,
        event_kind: str = "PAYMENT",
        delta_cents: int = 2500,
    ) -> Path:
        path = self.root / f"{remittance_id}.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": ledger.REMITTANCE_SCHEMA,
                    "remittance_id": remittance_id,
                    "claim_hash": claim_hash,
                    "event_kind": event_kind,
                    "delta_cents": delta_cents,
                    "payer_trace_sha256": "c" * 64,
                    "source_artifact_sha256": "d" * 64,
                    "occurred_at": NOW,
                    "synthetic_data": True,
                }
            ),
            encoding="utf-8",
        )
        return path

    def record_approved(self, *, owed_cents: int = 2500) -> tuple[dict, bool]:
        return ledger.record_adjudication(
            self.ledger_path,
            self.write_result(),
            owed_cents=owed_cents,
            program="synthetic-medicaid",
            jurisdiction="US-TEST",
            recorded_at=NOW,
        )

    def test_matching_remittance_reconciles_without_proof_or_settlement(self) -> None:
        adjudication, appended = self.record_approved()
        self.assertTrue(appended)
        self.assertFalse(adjudication["payload"]["proof_execution"])
        self.assertEqual(adjudication["payload"]["settlement_backend"], "none")

        remittance, appended = ledger.record_remittance(
            self.ledger_path, self.write_remittance(), recorded_at=NOW
        )
        self.assertTrue(appended)
        self.assertEqual(remittance["sequence"], 2)

        events = ledger.load_ledger(self.ledger_path)
        report = ledger.build_reconciliation_report(events, as_of=NOW)
        self.assertEqual(report["claims"][0]["status"], "RECONCILED")
        self.assertEqual(report["claims"][0]["net_remittance_cents"], 2500)
        self.assertFalse(report["runtime_activation"])
        self.assertFalse(report["proof_binding"])
        self.assertFalse(report["proof_execution"])
        self.assertEqual(report["settlement_backend"], "none")
        self.assertFalse(report["money_movement"])

    def test_exact_retry_is_idempotent_and_changed_retry_conflicts(self) -> None:
        first, appended = self.record_approved()
        self.assertTrue(appended)

        second, appended = ledger.record_adjudication(
            self.ledger_path,
            self.root / "adjudication_result.json",
            owed_cents=2500,
            program="synthetic-medicaid",
            jurisdiction="US-TEST",
            recorded_at="2026-10-15T12:01:00Z",
        )
        self.assertFalse(appended)
        self.assertEqual(second["event_id"], first["event_id"])
        self.assertEqual(len(ledger.load_ledger(self.ledger_path)), 1)

        with self.assertRaisesRegex(ledger.LedgerConflictError, "idempotency_conflict"):
            self.record_approved(owed_cents=2501)

    def test_chain_tampering_is_detected(self) -> None:
        self.record_approved()
        event = json.loads(self.ledger_path.read_text(encoding="utf-8"))
        event["payload"]["owed_cents"] = 9999
        self.ledger_path.write_text(json.dumps(event) + "\n", encoding="utf-8")

        with self.assertRaisesRegex(ledger.LedgerError, "payload_sha256 mismatch"):
            ledger.load_ledger(self.ledger_path)

    def test_existing_writer_lock_fails_closed_without_a_write(self) -> None:
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.ledger_path.with_name(self.ledger_path.name + ".lock")
        lock_path.write_text("pid=synthetic-other-writer\n", encoding="ascii")

        with self.assertRaisesRegex(ledger.LedgerBusyError, "ledger_writer_busy"):
            self.record_approved()
        self.assertFalse(self.ledger_path.exists())

    def test_chain_submitted_result_is_rejected(self) -> None:
        result = self.write_result(tx_submitted=True, tx_hash="0x" + "1" * 64)
        with self.assertRaisesRegex(
            ledger.LedgerError, "proof or chain-submitted adjudication"
        ):
            ledger.record_adjudication(
                self.ledger_path,
                result,
                owed_cents=2500,
                program="synthetic-medicaid",
                jurisdiction="US-TEST",
                recorded_at=NOW,
            )

    def test_denied_claim_preserves_zero_obligation_and_flags_payment(self) -> None:
        result = self.write_result(status="DENIED", reason="G1_NOT_ELIGIBLE")
        ledger.record_adjudication(
            self.ledger_path,
            result,
            owed_cents=9999,
            program="synthetic-medicaid",
            jurisdiction="US-TEST",
            recorded_at=NOW,
        )
        ledger.record_remittance(
            self.ledger_path, self.write_remittance(), recorded_at=NOW
        )

        report = ledger.build_reconciliation_report(
            ledger.load_ledger(self.ledger_path), as_of=NOW
        )
        claim = report["claims"][0]
        self.assertEqual(claim["owed_cents"], 0)
        self.assertEqual(claim["status"], "HOLD_PAYMENT_FOR_DENIED_CLAIM")

    def test_orphan_remittance_is_held(self) -> None:
        ledger.record_remittance(
            self.ledger_path,
            self.write_remittance(claim_hash=OTHER_CLAIM_HASH),
            recorded_at=NOW,
        )
        report = ledger.build_reconciliation_report(
            ledger.load_ledger(self.ledger_path), as_of=NOW
        )
        self.assertEqual(report["claims"][0]["status"], "HOLD_ORPHAN_REMITTANCE")

    def test_float_amount_and_raw_unknown_fields_are_rejected(self) -> None:
        path = self.write_remittance()
        value = json.loads(path.read_text(encoding="utf-8"))
        value["delta_cents"] = 25.5
        path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(ledger.LedgerError, "delta_cents must be an integer"):
            ledger.record_remittance(self.ledger_path, path, recorded_at=NOW)

        value["delta_cents"] = 2500
        value["member_id"] = "raw-member-id"
        path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(ledger.LedgerError, "unknown=\['member_id'\]"):
            ledger.record_remittance(self.ledger_path, path, recorded_at=NOW)

    def test_reconciliation_is_deterministic(self) -> None:
        self.record_approved()
        events = ledger.load_ledger(self.ledger_path)
        first = ledger.build_reconciliation_report(events, as_of=NOW)
        second = ledger.build_reconciliation_report(events, as_of=NOW)
        self.assertEqual(first, second)
        self.assertEqual(
            first["report_sha256"],
            ledger.canonical_sha256(
                {key: value for key, value in first.items() if key != "report_sha256"}
            ),
        )


if __name__ == "__main__":
    unittest.main()
