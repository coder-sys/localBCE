"""Constitution III.3: an exact retry is DUPLICATE and writes nothing, even after the owner clock moved; support,
reversal and offset retries ignore expected_revision; a payment comes only through intake (R5), whose exact resend
returns the first answer; a different payload at a stale revision still conflicts, and a payment's is held. Also: canonical JSON and continuity packages never accept NaN or Infinity."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from app.right_rail_financial_owner import FinancialContinuityError, FinancialInputError, FinancialIntegrityError, FinancialOwner, FinancialRevisionError, _canonical
from tests.rightrail_intake_rows import pay
from tests.test_right_rail_financial_followthrough import RULES, _build_r_store, _history


class RetryOrderTests(unittest.TestCase):
    def test_exact_retry_is_duplicate_and_stale_change_conflicts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rr-retry-order-") as directory, _build_r_store(Path(directory), RULES) as store:
            offset = dict(amount_cents=1_000, owner_role="CASE_OWNER", deadline_ms=store.clock.value + 86_400_000)
            payment = dict(amount_cents=5_000, event_at_ms=store.clock.value, source_id="state-collections")
            writes = {
                "support": ("item-r3", lambda item, tag, rev: store.record_support_evidence(item_id=item, evidence_id=f"evidence:support:{tag}", common_origin_id=f"origin:support:{tag}", expected_revision=rev)),
                "payment": ("item-r3", lambda item, tag, rev: pay(store, item_id=item, payment_id=f"payment:{tag}", common_origin_id=f"origin:pay:{tag}", evidence_id=f"evidence:pay:{tag}", expected_revision=rev, **payment)),
                "reversal": ("item-r1", lambda item, tag, rev: store.reverse_payment(item_id=item, payment_id="payment:r1", evidence_id=f"evidence:reversal:{tag}", expected_revision=rev)),
                "offset": ("item-r2", lambda item, tag, rev: store.record_offset_claim(item_id=item, claim_id=f"claim:{tag}", evidence_id=f"evidence:offset:{tag}", expected_revision=rev, **offset)),
            }
            for name, (item, write) in writes.items():
                with self.subTest(name):
                    original = store.obligation_detail(item)["revision"]
                    self.assertNotEqual(write(item, "a", original)["status"], "DUPLICATE")
                    self.assertGreater(store.obligation_detail(item)["revision"], original)
                    store.clock.value += 60_000  # the owner clock moves before the retry (reversal takes its time from it)
                    before, detail = _history(store), store.obligation_detail(item)
                    self.assertEqual(write(item, "a", original)["status"], "RECORDED" if name == "payment" else "DUPLICATE")  # an intake resend: its first answer
                    if name != "payment":  # retry identity ignores expected_revision here, as for reporting and acknowledgment
                        for revision in (None, original + 1, detail["revision"]):
                            self.assertEqual(write(item, "a", revision)["status"], "DUPLICATE")
                    self.assertEqual((_history(store), store.obligation_detail(item)), (before, detail))
                    if name == "payment":  # held, not raised: the intake records the file and its held row, and no cash moves
                        self.assertEqual({key: write(item, "b", original)[key] for key in ("status", "reason")}, {"status": "HELD", "reason": "obligation_revision_conflict"})
                        self.assertEqual((_history(store)[0], store.obligation_detail(item)), (before[0] + 1, detail))
                        continue
                    with self.assertRaisesRegex(FinancialRevisionError, "^obligation_revision_conflict$"):
                        write(item, "b", original)
                    self.assertEqual((_history(store), store.obligation_detail(item)), (before, detail))

    def test_reversal_refuses_a_malformed_evidence_id_before_any_lookup(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rr-retry-order-") as directory, _build_r_store(Path(directory), RULES) as store:
            for bad in (["evidence:x"], {"id": 1}, 7, None):
                with self.subTest(bad=bad), self.assertRaisesRegex(FinancialInputError, "^evidence_id$"):
                    store.reverse_payment(item_id="item-r1", payment_id="payment:r1", evidence_id=bad)

    def test_canonical_json_rejects_nan_and_infinity(self) -> None:
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value), self.assertRaisesRegex(FinancialIntegrityError, "^canonical_json$"):
                _canonical({"amount": value})
            with self.subTest(package=value), self.assertRaisesRegex(FinancialContinuityError, "^continuity_package_canonical$"):
                FinancialOwner.validate_continuity_package(b'{"amount":%s}' % json.dumps(value).encode())
        for text in (b"1e999", b"-1E400"):  # float() overflows to infinity
            with self.subTest(package=text), self.assertRaisesRegex(FinancialContinuityError, "^continuity_package_canonical$"):
                FinancialOwner.validate_continuity_package(b'{"amount":' + text + b"}")


if __name__ == "__main__":
    unittest.main()
