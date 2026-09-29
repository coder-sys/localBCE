"""Constitution III.3: an exact retry that carries the original expected_revision is DUPLICATE and writes
nothing; a different payload at a stale revision still conflicts."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from app.right_rail_financial_owner import FinancialRevisionError
from tests.test_right_rail_financial_followthrough import RULES, _build_r_store, _history


class RetryOrderTests(unittest.TestCase):
    def test_exact_retry_is_duplicate_and_stale_change_conflicts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rr-retry-order-") as directory:
            store = _build_r_store(Path(directory), RULES)
            offset = dict(amount_cents=1_000, owner_role="CASE_OWNER", deadline_ms=store.clock.value + 86_400_000)
            payment = dict(amount_cents=5_000, event_at_ms=store.clock.value, source_id="state-collections")
            writes = {
                "support": ("item-r3", lambda item, tag, rev: store.record_support_evidence(item_id=item, evidence_id=f"evidence:support:{tag}", common_origin_id=f"origin:support:{tag}", expected_revision=rev)),
                "payment": ("item-r3", lambda item, tag, rev: store.record_payment_evidence(item_id=item, payment_id=f"payment:{tag}", common_origin_id=f"origin:pay:{tag}", evidence_id=f"evidence:pay:{tag}", expected_revision=rev, **payment)),
                "reversal": ("item-r1", lambda item, tag, rev: store.reverse_payment(item_id=item, payment_id="payment:r1", evidence_id=f"evidence:reversal:{tag}", expected_revision=rev)),
                "offset": ("item-r2", lambda item, tag, rev: store.record_offset_claim(item_id=item, claim_id=f"claim:{tag}", evidence_id=f"evidence:offset:{tag}", expected_revision=rev, **offset)),
            }
            for name, (item, write) in writes.items():
                with self.subTest(name):
                    original = store.obligation_detail(item)["revision"]
                    self.assertNotEqual(write(item, "a", original)["status"], "DUPLICATE")
                    self.assertGreater(store.obligation_detail(item)["revision"], original)
                    before, detail = _history(store), store.obligation_detail(item)
                    self.assertEqual(write(item, "a", original)["status"], "DUPLICATE")
                    self.assertEqual((_history(store), store.obligation_detail(item)), (before, detail))
                    with self.assertRaisesRegex(FinancialRevisionError, "^obligation_revision_conflict$"):
                        write(item, "b", original)
                    self.assertEqual((_history(store), store.obligation_detail(item)), (before, detail))


if __name__ == "__main__":
    unittest.main()
