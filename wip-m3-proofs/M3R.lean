import BlindLedger.Financial.Payment.Rev12
import M3Q
open BlindLedger.Financial BlindLedger.Financial.Payment BlindLedger.Financial.CorrectionTransition
namespace BlindLedger.Financial.Payment.Rev12

theorem receipt_of_mem {r : PaymentRequest} (hwf : financialInputWellFormed r.input = true)
    (hrec : r.receipts.map Receipt.paymentId = r.input.payments.map Payment.paymentId)
    {p : Payment} (hp : p ∈ r.input.payments) : ∃ k, receiptOf r.receipts p.paymentId = some k := by
  have hn : (r.receipts.map Receipt.paymentId).Nodup := by rw [hrec]; exact nodup_ids_of_wf hwf
  have : p.paymentId ∈ r.receipts.map Receipt.paymentId := by
    rw [hrec]; exact List.mem_map.2 ⟨p, hp, rfl⟩
  obtain ⟨k, hk, hkp⟩ := List.mem_map.1 this
  exact ⟨k, by rw [← hkp]; exact find_of_mem Receipt.paymentId hn hk⟩

theorem new_diff {r : PaymentRequest} {V : PaymentView} {S : ItemState}
    (hwf : financialInputWellFormed r.input = true)
    (hrec : r.receipts.map Receipt.paymentId = r.input.payments.map Payment.paymentId)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hS : summarize r.input r.receipts (anchorItemLength r.input r.receipts) = some S)
    (hVenv : V.env = envOf r.input) {c : RecordCommand} (hc : commandWellFormed (.record c) = true)
    (h0 : c.amountCents ≠ 0)
    {p : Payment} {k : Receipt} (hex : r.input.payments.find? (·.commonOriginId = c.commonOriginId) = some p)
    (hne : p.amountCents ≠ c.amountCents)
    (hk : receiptOf r.receipts p.paymentId = some k)
    (hbo : V.byOrigin = some (p, k, p.reversalEvidenceId.bind (findEvidence r.input.evidence)))
    (hev : V.evidence = findEvidence r.input.evidence c.evidenceId)
    (hcv : V.conflictVisible = r.input.conflicts.any (·.conflictId = conflictIdOf r.input c))
    (hfor : V.foreign = r.foreign) (hexp : V.expectedRevision = r.expectedRevision) :
    some (viewRecordNew V S c) = project r (recordNew r c) := by
  have hp := List.mem_of_find?_eq_some hex
  have hporig : p.commonOriginId = c.commonOriginId := by
    have := List.find?_some hex
    simpa using this
  unfold viewRecordNew recordNew
  simp only [decide_eq_false hne, hbo, hev, hcv, hfor, hexp, hVenv, hex, hk, head_conf, head_cid, head_rpay, head_rrcp, head_cimg,
    envOf_eval, envOf_before, revisionOk, evidenceSlot_eq, conf_evid, Option.any_some, Option.isSome_some,
    Option.bind_some, Option.map_some, Bool.false_and, Bool.and_false, Bool.not_false, Bool.true_and, Bool.false_or, Bool.or_false,
    Bool.false_eq_true, ↓reduceIte, Option.map_none, Option.getD_none]
  have hfp := findPayment_of_mem (nodup_ids_of_wf hwf) hp
  repeat' split
  all_goals (try rfl)
  all_goals
    rename_i _ _ _ hform hch _ hnc hcvf hid hfr
    have hev' := ev_leaf (slot := slotOf r.foreign.evidenceId (findEvidence r.input.evidence c.evidenceId)
      (confirmation r.input c r.input.evaluatedAt)) rfl hnc (fun _ => rfl) hform (Nat.not_lt.1 hch)
  · rw [if_pos hfr] at hev'
    exact shape_conflict hwf hb hS hVenv hc h0 hfp hporig hne (by simpa using hcvf) (by simpa using hid) hev'
  · rw [if_neg hfr] at hev'
    exact shape_conflict hwf hb hS hVenv hc h0 hfp hporig hne (by simpa using hcvf) (by simpa using hid) hev'

theorem new_same {r : PaymentRequest} {V : PaymentView} {S : ItemState}
    (hwf : financialInputWellFormed r.input = true)
    (hrec : r.receipts.map Receipt.paymentId = r.input.payments.map Payment.paymentId)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hS : summarize r.input r.receipts (anchorItemLength r.input r.receipts) = some S)
    (hVenv : V.env = envOf r.input) {c : RecordCommand} (hc : commandWellFormed (.record c) = true)
    (h0 : c.amountCents ≠ 0)
    {p : Payment} {k : Receipt} (hex : r.input.payments.find? (·.commonOriginId = c.commonOriginId) = some p)
    (hs : p.amountCents = c.amountCents)
    (hk : receiptOf r.receipts p.paymentId = some k)
    (hbo : V.byOrigin = some (p, k, p.reversalEvidenceId.bind (findEvidence r.input.evidence)))
    (hev : V.evidence = findEvidence r.input.evidence c.evidenceId)
    (hcv : V.conflictVisible = r.input.conflicts.any (·.conflictId = conflictIdOf r.input c))
    (hfor : V.foreign = r.foreign) (hexp : V.expectedRevision = r.expectedRevision) :
    some (viewRecordNew V S c) = project r (recordNew r c) := by
  have hp := List.mem_of_find?_eq_some hex
  have hporig : p.commonOriginId = c.commonOriginId := by
    have := List.find?_some hex
    simpa using this
  unfold viewRecordNew recordNew
  simp only [decide_eq_true hs, hbo, hev, hcv, hfor, hexp, hVenv, hex, hk, head_conf, head_cid, head_rpay, head_rrcp, head_cimg,
    envOf_eval, envOf_before, revisionOk, evidenceSlot_eq, conf_evid, Option.any_some, Option.isSome_some,
    Option.bind_some, Option.map_some, Bool.false_and, Bool.and_false, Bool.not_false, Bool.true_and, Bool.false_or, Bool.or_false,
    Bool.false_eq_true, ↓reduceIte, Option.map_none, Option.getD_none]
  repeat' split
  all_goals (try rfl)
  · rename_i _ _ _ h4 _ _ h3 _ _ _ _ h
    have hf0 : r.foreign.evidenceId = false := by
      cases hf : r.foreign.evidenceId
      · rfl
      · exact absurd (by simp [hf]) h4
    have hsome : (findEvidence r.input.evidence c.evidenceId).isSome = true := by simpa [hf0] using h3
    cases hsl : slotOf r.foreign.evidenceId (findEvidence r.input.evidence c.evidenceId)
        (confirmation r.input c ((Option.map (fun x => x.receivedAt) (findEvidence r.input.evidence c.evidenceId)).getD
          r.input.evaluatedAt)) with
    | clash => simp [hsl, Slot.isFresh] at h
    | same s => simp [hsl, Slot.isFresh] at h
    | fresh =>
      obtain ⟨-, hst⟩ := (slot_facts hsl).1 rfl
      rw [hst] at hsome
      cases hsome
  · rename_i _ _ _ _ _ heq h3 hch _ _ _ _
    rw [if_neg h3] at heq
    have hfe : findEvidence r.input.evidence c.evidenceId = none := by
      cases hh : findEvidence r.input.evidence c.evidenceId
      · rfl
      · exact absurd (by simp [hh]) h3
    exact shape_alias hwf hb hS hVenv hc hp hporig hs hfe heq (Nat.not_lt.1 hch) p.paymentId

end BlindLedger.Financial.Payment.Rev12
