from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PrivacyV2StatementTests(unittest.TestCase):
    def test_draft_statement_excludes_amount_count_and_payload_disclosures(self) -> None:
        statement = json.loads(
            (ROOT / "experiments" / "privacy_v2" / "public_inputs_v2.example.json").read_text(
                encoding="utf-8"
            )
        )
        fields = set(statement["fields"])
        forbidden = set(statement["forbidden_public_fields"])
        self.assertIn("valueConservationCommitment", fields)
        self.assertIn("opaqueBatchCommitment", fields)
        self.assertIn("settlementCommitment", fields)
        self.assertNotIn("privateDataCommitment", fields)
        self.assertTrue(fields.isdisjoint(forbidden))
        self.assertTrue(
            {
                "approvedAmountCents",
                "paymentAmountCents",
                "claimCount",
                "approvedCount",
                "deniedCount",
                "encryptedPayload",
            }.issubset(forbidden)
        )

    def test_draft_is_explicitly_not_the_active_production_statement(self) -> None:
        statement = json.loads(
            (ROOT / "experiments" / "privacy_v2" / "public_inputs_v2.example.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual("EXPERIMENTAL_NOT_FOR_PRODUCTION", statement["status"])


if __name__ == "__main__":
    unittest.main()
