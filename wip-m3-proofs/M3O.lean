import BlindLedger.Financial.Payment.Rev12
import M3N
open BlindLedger.Financial BlindLedger.Financial.Payment BlindLedger.Financial.CorrectionTransition
namespace BlindLedger.Financial.Payment.Rev12

theorem envOf_eval (i : FinancialInput) : (envOf i).evaluatedAt = i.evaluatedAt := rfl
theorem envOf_before (i : FinancialInput) : (envOf i).beforeRevision = i.beforeRevision := rfl

theorem rev_lock {r : PaymentRequest} {V : PaymentView} {S : ItemState}
    (hwf : financialInputWellFormed r.input = true)
    (hrec : r.receipts.map Receipt.paymentId = r.input.payments.map Payment.paymentId)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hS : summarize r.input r.receipts (anchorItemLength r.input r.receipts) = some S)
    (hVenv : V.env = envOf r.input) {c : ReverseCommand} (hc : commandWellFormed (.reverse c) = true)
    (hbyId : V.byId = (findPayment r.input.payments c.paymentId).bind
      (fun p => (receiptOf r.receipts p.paymentId).map fun k => (p, k)))
    (hev : V.evidence = findEvidence r.input.evidence c.evidenceId)
    (hfor : V.foreign = r.foreign) (hexp : V.expectedRevision = r.expectedRevision) :
    some (viewReverse V S c) = project r (decideReverse r c) := by
  have hnd := nodup_ids_of_wf hwf
  cases hfp : findPayment r.input.payments c.paymentId with
  | none =>
    rw [hfp] at hbyId
    simp only [viewReverse, decideReverse, hbyId, hfp, Option.bind_none]
    rfl
  | some p =>
    obtain ⟨k, hk⟩ := receipt_exists (L := ⟨r.input, r.receipts⟩) ⟨hnd, hrec⟩ hfp
    have hbyId' : V.byId = some (p, k) := by rw [hbyId, hfp]; simp [hk]
    unfold viewReverse decideReverse
    simp only [hbyId', hfp, hfor, hev, hVenv, head_rrec, envOf_eval, envOf_before, revisionOk, hexp]
    cases hfe : r.foreign.evidenceId with
    | true => simp only [hfe]; rfl
    | false =>
      simp only [hfe, Bool.false_eq_true, ↓reduceIte]
      generalize hT : c.eventAt.getD (((findEvidence r.input.evidence c.evidenceId).map (·.eventAt)).getD
        r.input.evaluatedAt) = time
      cases hform : formRefusal (reversalRecord r.input c p time) with
      | some f => simp only [hform]; rfl
      | none =>
        simp only [hform]
        by_cases hch : time > r.input.evaluatedAt
        · simp only [hch, ↓reduceIte]; rfl
        · simp only [hch, ↓reduceIte]
          have hs : slotOf false (findEvidence r.input.evidence c.evidenceId)
              (reversalRecord r.input c p time) = evidenceSlot r (reversalRecord r.input c p time) :=
            by rw [evidenceSlot_eq, hfe]; rfl
          rw [hs]
          cases hsl : evidenceSlot r (reversalRecord r.input c p time) with
          | clash => simp only [hsl]; rfl
          | same s => simp only [hsl]; rfl
          | fresh =>
            simp only [hsl]
            obtain ⟨-, hfs | ⟨s, hs', -⟩⟩ := slot_cases (r := r) (e := reversalRecord r.input c p time)
              (by rw [hsl]; intro h; cases h)
            · have hfe' : findEvidence r.input.evidence c.evidenceId = none := hfs.2
              by_cases hrv : (!r.expectedRevision.all fun x => decide (x = r.input.beforeRevision)) = true
              · simp only [hrv, ↓reduceIte]; rfl
              · simp only [hrv, ↓reduceIte]
                by_cases hst : p.status = .REVERSED
                · simp only [hst, ↓reduceIte]; rfl
                · simp only [hst, ↓reduceIte]
                  exact shape_reversed hwf hrec hb hS hVenv hc hfp hk hbyId' hst hfe' hform
                    (Nat.not_lt.1 hch)
            · rw [hsl] at hs'; cases hs'

end BlindLedger.Financial.Payment.Rev12
