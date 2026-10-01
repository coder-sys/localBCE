import BlindLedger.Financial.Payment.Rev12
import M3L
open BlindLedger.Financial BlindLedger.Financial.Payment BlindLedger.Financial.CorrectionTransition
namespace BlindLedger.Financial.Payment.Rev12

theorem alias_cap {r : PaymentRequest} {S : ItemState}
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hSab : S.anchorBytes = anchorItemLength r.input r.receipts) (e : EvidenceRecord) :
    withinCapacity r ⟨some e, none, none, none⟩ = true ↔
      ¬ (S.anchorBytes + (encodeEvidence e).length + maxCallTailBytes > maxTotalEncodedBytes) := by
  unfold withinCapacity
  rw [decide_eq_true_iff]
  unfold addedBytes
  simp only [evBytes, newPay, oldPay, cfBytes, receiptBytes, Option.map_some, Option.getD_some,
    Option.map_none, Option.getD_none, Option.bind_none]
  unfold anchorItemLength at hSab
  omega
end BlindLedger.Financial.Payment.Rev12
