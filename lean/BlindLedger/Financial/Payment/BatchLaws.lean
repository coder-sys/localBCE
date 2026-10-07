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

/-- REVERSE discharges `len_applyWrites`' `hgrow`: the reversed image only fills the empty
    reversal evidence slot (`[0]` becomes `1 :: encodeString id`) and swaps one status byte. -/
theorem oldPay_le_newPay_reversed (i : FinancialInput) (p : Payment) (c : ReverseCommand) (w : Writes)
    (hw : w.payment = some (reversedImage p c)) (hp : findPayment i.payments p.paymentId = some p)
    (hr : p.reversalEvidenceId = none) : oldPay i w ≤ newPay w := by
  simp [oldPay, newPay, hw, reversedImage, hp, encodePayment, encodeOptionString, hr]

end BlindLedger.Financial.Payment
