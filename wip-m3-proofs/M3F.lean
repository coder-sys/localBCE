import BlindLedger.Financial.Payment.Rev12
import M3E
open BlindLedger.Financial BlindLedger.Financial.Payment BlindLedger.Financial.CorrectionTransition
namespace BlindLedger.Financial.Payment.Rev12

theorem accLam_mono {i j : FinancialInput} (hcl : j.claims = i.claims)
    (hp : ∀ q ∈ i.payments, ∃ q' ∈ j.payments, q'.evidenceId = q.evidenceId ∧
      q'.commonOriginId = q.commonOriginId ∧ q'.amountCents = q.amountCents)
    (hc : ∀ x ∈ i.conflicts, x ∈ j.conflicts)
    (hr : ∀ id q, findPayment i.payments id = some q → q.status = .REVERSED →
      findPayment j.payments id = some q)
    {x : EvidenceRecord} (h : accLam i x = true) : accLam j x = true := by
  unfold accLam at h ⊢
  by_cases h1 : x.kind = "PAYMENT_CONFIRMATION"
  · simp only [h1, ↓reduceIte] at h ⊢; exact accConf_mono hp hc h
  by_cases h2 : x.kind = "PAYMENT_REVERSAL"
  · simp only [h1, h2, ↓reduceIte] at h ⊢; exact accRev_mono hr h
  by_cases h3 : x.kind = "OFFSET_CLAIM"
  · simp only [h1, h2, h3, ↓reduceIte] at h ⊢; rw [hcl]; exact h
  · simp only [h1, h2, h3, ↓reduceIte] at h ⊢

theorem known_of_find {E : List EvidenceRecord} {id e} (h : findEvidence E id = some e) :
    (E.map EvidenceRecord.evidenceId).contains id = true :=
  List.contains_iff_mem.2 (List.mem_map.2 ⟨e, findEvidence_mem h, findEvidence_id h⟩)

theorem find_of_known {E : List EvidenceRecord} {id}
    (h : (E.map EvidenceRecord.evidenceId).contains id = true) : ∃ e, findEvidence E id = some e := by
  cases hf : findEvidence E id with
  | some e => exact ⟨e, rfl⟩
  | none =>
    obtain ⟨e, he, rfl⟩ := List.mem_map.1 (List.contains_iff_mem.1 h)
    exact absurd rfl (findEvidence_none_ne hf e he)

theorem wf_grow {i : FinancialInput} (hi : financialInputWellFormed i = true)
    {P : List Payment} {E : List EvidenceRecord} {C : List FinancialConflict}
    (hE : ∀ id ev, findEvidence i.evidence id = some ev → findEvidence E id = some ev)
    (hPf : ∀ id q, findPayment i.payments id = some q → ∃ q', findPayment P id = some q' ∧
      q'.commonOriginId = q.commonOriginId ∧ q'.amountCents = q.amountCents ∧ q'.evidenceId = q.evidenceId)
    (hPr : ∀ id q, findPayment i.payments id = some q → q.status = .REVERSED → findPayment P id = some q)
    (hCm : ∀ x ∈ i.conflicts, x ∈ C)
    (n20 : E.length ≤ maxRows) (n21 : C.length ≤ maxRows)
    (n25 : P.length ≤ maxRows → canonicalIdList (P.map Payment.paymentId) = true)
    (n28 : canonicalIdList (E.map EvidenceRecord.evidenceId) = true)
    (n29 : canonicalIdList (C.map FinancialConflict.conflictId) = true)
    (n55 : noDuplicates (P.map Payment.commonOriginId) = true)
    (hPnew : ∀ q ∈ P, q ∉ i.payments → paymentWellFormed i.context q = true ∧
      paymentEvidenceWellFormed (upd i P E C) q = true ∧ reversalEvidenceWellFormed (upd i P E C) q = true)
    (hEnew : ∀ x ∈ E, x ∉ i.evidence → evidenceWellFormed i.context x = true ∧
      x.receivedAt ≤ i.evaluatedAt ∧ accLam (upd i P E C) x = true)
    (hCnew : ∀ x ∈ C, x ∉ i.conflicts → conflictWellFormed (upd i P E C) x = true) :
    financialInputWellFormed (upd i P E C) = true := by
  have hi' := hi
  simp only [financialInputWellFormed, Bool.and_assoc, Bool.and_eq_true, decide_eq_true_eq] at hi'
  obtain ⟨h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11,h12,h13,h14,h15,h16,h17,h18,h19,h20,h21,h22,h23,h24,h25,h26,h27,h28,h29,h30,h31,h32,h33,h34,h35,h36,h37,h38,h39,h40,h41,h42,h43,h44,h45,h46,h47,h48,h49,h50,h51,h52,h53,h54,h55⟩ := hi'
  have hp : ∀ q ∈ i.payments, ∃ q' ∈ P, q'.evidenceId = q.evidenceId ∧
      q'.commonOriginId = q.commonOriginId ∧ q'.amountCents = q.amountCents := by
    intro q hq
    have hnd := nodup_ids_of_wf hi
    obtain ⟨q', hq', ho, ha, he⟩ := hPf q.paymentId q (findPayment_of_mem hnd hq)
    exact ⟨q', findPayment_mem hq', he, ho, ha⟩
  have hfp : ∀ id q, findPayment i.payments id = some q → ∃ q', findPayment (upd i P E C).payments id = some q' ∧
      q'.commonOriginId = q.commonOriginId ∧ q'.amountCents = q.amountCents := fun id q h =>
    let ⟨q', a, b, c, _⟩ := hPf id q h; ⟨q', a, b, c⟩
  have n39' : P.all (paymentEvidenceWellFormed (upd i P E C)) = true := by
    rw [List.all_eq_true] at h39 ⊢
    intro q hq
    by_cases hm : q ∈ i.payments
    · exact pew_mono (i := i) (j := upd i P E C) hE (h39 q hm)
    · exact (hPnew q hq hm).2.1
  have n40' : P.all (reversalEvidenceWellFormed (upd i P E C)) = true := by
    rw [List.all_eq_true] at h40 ⊢
    intro q hq
    by_cases hm : q ∈ i.payments
    · exact rew_mono (i := i) (j := upd i P E C) hE (h40 q hm)
    · exact (hPnew q hq hm).2.2
  have n41' : i.claims.all (claimEvidenceWellFormed (upd i P E C)) = true := by
    rw [List.all_eq_true] at h41 ⊢
    exact fun q hq => cew_mono (i := i) (j := upd i P E C) hE (h41 q hq)
  have n51' : allReferencesExist (E.map EvidenceRecord.evidenceId) (P.map Payment.evidenceId) = true := by
    unfold allReferencesExist
    rw [List.all_eq_true]
    intro id hid
    obtain ⟨q, hq, rfl⟩ := List.mem_map.1 hid
    have := List.all_eq_true.1 n39' q hq
    unfold paymentEvidenceWellFormed at this
    cases hf : findEvidence E q.evidenceId with
    | none => simp [upd, hf] at this
    | some e => exact known_of_find hf
  have n17 : P.length ≤ maxRows := Nat.le_trans (payments_le_evidence (post := upd i P E C) n39' n51' n55) n20
  refine wf_of_parts hi n17 n20 n21 (n25 n17) n28 n29 ?_ ?_ ?_ n39' n40' n41' ?_ ?_ n51' ?_ ?_ ?_ n55
  · rw [List.all_eq_true] at h32 ⊢
    intro q hq
    by_cases hm : q ∈ i.payments
    · exact h32 q hm
    · exact (hPnew q hq hm).1
  · rw [List.all_eq_true] at h34 ⊢
    intro x hx
    by_cases hm : x ∈ i.evidence
    · exact h34 x hm
    · exact (hEnew x hx hm).1
  · rw [List.all_eq_true] at h36 ⊢
    intro x hx
    by_cases hm : x ∈ i.conflicts
    · exact confl_mono (i := i) (j := upd i P E C) rfl hE hfp (h36 x hm)
    · exact hCnew x hx hm
  · rw [List.all_eq_true] at h48 ⊢
    intro x hx
    by_cases hm : x ∈ i.evidence
    · exact accLam_mono (i := i) (j := upd i P E C) rfl hp hCm hPr (h48 x hm)
    · exact (hEnew x hx hm).2.2
  · rw [List.all_eq_true] at h49 ⊢
    intro x hx
    by_cases hm : x ∈ i.evidence
    · exact h49 x hm
    · exact decide_eq_true (hEnew x hx hm).2.1
  · -- n52
    unfold allReferencesExist
    rw [List.all_eq_true]
    intro id hid
    obtain ⟨q, hq, hr⟩ := List.mem_filterMap.1 hid
    have := List.all_eq_true.1 n40' q hq
    unfold reversalEvidenceWellFormed at this
    rcases hs : q.status with _ | _ <;> rw [hs, hr] at this
    · simp at this
    · cases hf : findEvidence E id with
      | none => simp [upd, hf] at this
      | some e => exact known_of_find hf
  · -- n53
    unfold allReferencesExist
    rw [List.all_eq_true]
    intro id hid
    obtain ⟨q, hq, rfl⟩ := List.mem_map.1 hid
    have := List.all_eq_true.1 n41' q hq
    unfold claimEvidenceWellFormed at this
    cases hf : findEvidence E q.evidenceId with
    | none => simp [upd, hf] at this
    | some e => exact known_of_find hf
  · -- n54
    rw [List.all_eq_true] at h54 ⊢
    intro d hd
    have := h54 d hd
    unfold allReferencesExist at this ⊢
    rw [List.all_eq_true] at this ⊢
    intro id hid
    obtain ⟨e, he⟩ := find_of_known (this id hid)
    exact known_of_find (hE _ _ he)

end BlindLedger.Financial.Payment.Rev12
