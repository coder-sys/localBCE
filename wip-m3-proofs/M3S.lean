import BlindLedger.Financial.Payment.Rev12
import M3R
import M3O
open BlindLedger.Financial BlindLedger.Financial.Payment BlindLedger.Financial.CorrectionTransition
namespace BlindLedger.Financial.Payment.Rev12

theorem new_lock {r : PaymentRequest} {V : PaymentView} {S : ItemState}
    (hwf : financialInputWellFormed r.input = true)
    (hrec : r.receipts.map Receipt.paymentId = r.input.payments.map Payment.paymentId)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hS : summarize r.input r.receipts (anchorItemLength r.input r.receipts) = some S)
    (hVenv : V.env = envOf r.input) {c : RecordCommand} (hc : commandWellFormed (.record c) = true)
    (h0 : c.amountCents ≠ 0) (hpid : findPayment r.input.payments c.paymentId = none)
    (hbyId : V.byId = none)
    (hbo : V.byOrigin = (r.input.payments.find? (·.commonOriginId = c.commonOriginId)).bind fun p =>
      ((receiptOf r.receipts p.paymentId).map fun k => (p, k)).map fun (p, k) =>
        (p, k, p.reversalEvidenceId.bind (findEvidence r.input.evidence)))
    (hev : V.evidence = findEvidence r.input.evidence c.evidenceId)
    (hcv : V.conflictVisible = r.input.conflicts.any (·.conflictId = conflictIdOf r.input c))
    (hfor : V.foreign = r.foreign) (hexp : V.expectedRevision = r.expectedRevision) :
    some (viewRecordNew V S c) = project r (recordNew r c) := by
  cases hex : r.input.payments.find? (·.commonOriginId = c.commonOriginId) with
  | none =>
    rw [hex] at hbo
    exact new_none hwf hrec hb hS hVenv hc h0 hpid hbyId hbo hev hcv hfor hexp hex
  | some p =>
    obtain ⟨k, hk⟩ := receipt_of_mem hwf hrec (List.mem_of_find?_eq_some hex)
    rw [hex] at hbo
    simp only [Option.bind_some, hk, Option.map_some] at hbo
    by_cases hs : p.amountCents = c.amountCents
    · exact new_same hwf hrec hb hS hVenv hc h0 hex hs hk hbo hev hcv hfor hexp
    · exact new_diff hwf hrec hb hS hVenv hc h0 hex hs hk hbo hev hcv hfor hexp

theorem stepView_eq' {r : PaymentRequest} (hr : requestWellFormed r = true)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length) {v : PaymentView}
    (hv : Faithful r v) : some (stepView v) = project r (paymentTransition r) := by
  obtain ⟨S, hS, habs, hVenv, hbyId, hbo, hev, hcv, hfor, hexp, hcmd⟩ := faithful_unpack hb hv
  simp only [requestWellFormed, Bool.and_eq_true] at hr
  obtain ⟨⟨⟨hwf, hrcp⟩, hcw⟩, -⟩ := hr
  have hrec : r.receipts.map Receipt.paymentId = r.input.payments.map Payment.paymentId := by
    simp only [receiptsWellFormed, Bool.and_eq_true, beq_iff_eq] at hrcp; exact hrcp.1
  unfold stepView paymentTransition
  dsimp only
  rw [habs, hcmd]
  cases hcm : r.command with
  | reverse c =>
    simp only [hcm, cmdPaymentId, cmdEvidenceId] at hbyId hev hcw
    exact rev_lock hwf hrec hb hS hVenv hcw hbyId hev hfor hexp
  | record c =>
    simp only [hcm, cmdPaymentId, cmdEvidenceId] at hbyId hev hbo hcv hcw
    dsimp only
    rw [hfor]
    unfold decideRecord
    by_cases h0 : c.amountCents = 0
    · simp only [h0, ↓reduceIte]; rfl
    · simp only [h0, ↓reduceIte]
      by_cases hf : r.foreign.paymentId = true
      · simp only [hf, ↓reduceIte]; rfl
      · simp only [hf, ↓reduceIte]
        cases hfp : findPayment r.input.payments c.paymentId with
        | some p =>
          obtain ⟨k, hk⟩ := receipt_of_mem hwf hrec (findPayment_mem hfp)
          rw [hfp] at hbyId
          simp only [Option.bind_some, hk, Option.map_some] at hbyId
          rw [hbyId]
          exact retry_lock hVenv hev hexp hk
        | none =>
          rw [hfp] at hbyId
          simp only [Option.bind_none] at hbyId
          rw [hbyId]
          exact new_lock hwf hrec hb hS hVenv hcw h0 hfp hbyId hbo hev hcv hfor hexp

end BlindLedger.Financial.Payment.Rev12
