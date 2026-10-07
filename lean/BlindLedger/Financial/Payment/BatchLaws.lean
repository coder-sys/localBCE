import BlindLedger.Financial.Payment.Batch
import BlindLedger.Financial.Payment.ChainLaws

namespace BlindLedger.Financial.Payment

open BlindLedger.Financial

/-- `erase` drops nothing section 11 stores: whenever today's projection (ChainLaws.lean:14) has a
    stored image, its stored part is the erased outcome. -/
theorem project_factors_erase (r : PaymentRequest) (o : PaymentOutcome) :
    (project r o).map Erased.ofStep = (project r o).map fun _ => erase o := by
  cases o <;> simp [project, erase, Erased.ofStep, Option.map_map, Function.comp_def]

/-- Section 11 step 2: running bytes. Insert or replace; a replacement must not shrink the row
    (true of `reversedImage`, which only adds a reversal evidence id). -/
theorem len_applyWrites (i : FinancialInput) (w : Writes)
    (hp : ∀ p, w.payment = some p → (findPayment i.payments p.paymentId).isSome = true →
      (i.payments.map Payment.paymentId).Nodup)
    (hgrow : oldPay i w ≤ newPay w) :
    (rawEncodeFinancialInput (applyWrites i w)).length =
      (rawEncodeFinancialInput i).length + addedBytes i w := by
  have := rawEncode_applyWrites_core i w hp
  simp only [addedBytes]
  omega

end BlindLedger.Financial.Payment
