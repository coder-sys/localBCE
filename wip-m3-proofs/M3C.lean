import BlindLedger.Financial.Payment.Rev12
import M3B
open BlindLedger.Financial BlindLedger.Financial.Payment BlindLedger.Financial.CorrectionTransition
namespace BlindLedger.Financial.Payment.Rev12

/-! ## Well-formedness of a post-state: the 19 conjuncts that read payments, evidence or conflicts -/

def upd (i : FinancialInput) (P : List Payment) (E : List EvidenceRecord)
    (C : List FinancialConflict) : FinancialInput :=
  { i with payments := P, evidence := E, conflicts := C }

theorem wf_of_parts {i : FinancialInput} (hi : financialInputWellFormed i = true)
    {P : List Payment} {E : List EvidenceRecord} {C : List FinancialConflict}
    (n17 : P.length ≤ maxRows) (n20 : E.length ≤ maxRows) (n21 : C.length ≤ maxRows)
    (n25 : canonicalIdList (P.map Payment.paymentId) = true)
    (n28 : canonicalIdList (E.map EvidenceRecord.evidenceId) = true)
    (n29 : canonicalIdList (C.map FinancialConflict.conflictId) = true)
    (n32 : P.all (paymentWellFormed i.context) = true)
    (n34 : E.all (evidenceWellFormed i.context) = true)
    (n36 : C.all (conflictWellFormed (upd i P E C)) = true)
    (n39 : P.all (paymentEvidenceWellFormed (upd i P E C)) = true)
    (n40 : P.all (reversalEvidenceWellFormed (upd i P E C)) = true)
    (n41 : i.claims.all (claimEvidenceWellFormed (upd i P E C)) = true)
    (n48 : E.all (fun evidence =>
      if evidence.kind = "PAYMENT_CONFIRMATION" then paymentConfirmationAccounted (upd i P E C) evidence
      else if evidence.kind = "PAYMENT_REVERSAL" then reversalEvidenceAccounted (upd i P E C) evidence
      else if evidence.kind = "OFFSET_CLAIM" then
        i.claims.any (fun claim => claim.evidenceId = evidence.evidenceId)
      else true) = true)
    (n49 : E.all (fun evidence => decide (evidence.receivedAt ≤ i.evaluatedAt)) = true)
    (n51 : allReferencesExist (E.map EvidenceRecord.evidenceId) (P.map Payment.evidenceId) = true)
    (n52 : allReferencesExist (E.map EvidenceRecord.evidenceId) (P.filterMap Payment.reversalEvidenceId) = true)
    (n53 : allReferencesExist (E.map EvidenceRecord.evidenceId) (i.claims.map Claim.evidenceId) = true)
    (n54 : i.determinations.all (fun determination =>
      allReferencesExist (E.map EvidenceRecord.evidenceId) determination.supportingEvidenceIds) = true)
    (n55 : noDuplicates (P.map Payment.commonOriginId) = true) :
    financialInputWellFormed (upd i P E C) = true := by
  simp only [financialInputWellFormed, Bool.and_assoc, Bool.and_eq_true, decide_eq_true_eq] at hi ⊢
  obtain ⟨h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11,h12,h13,h14,h15,h16,h17,h18,h19,h20,h21,h22,h23,h24,h25,h26,h27,h28,h29,h30,h31,h32,h33,h34,h35,h36,h37,h38,h39,h40,h41,h42,h43,h44,h45,h46,h47,h48,h49,h50,h51,h52,h53,h54,h55⟩ := hi
  exact ⟨h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11,h12,h13,h14,h15,h16,n17,h18,h19,n20,n21,h22,h23,h24,n25,h26,h27,n28,n29,h30,h31,n32,h33,n34,h35,n36,h37,h38,n39,n40,n41,h42,h43,h44,h45,h46,h47,n48,n49,h50,n51,n52,n53,n54,n55⟩

theorem noDup_iff : ∀ l : List String, noDuplicates l = true ↔ l.Nodup
  | [] => by simp [noDuplicates]
  | a :: l => by
    rw [noDuplicates, List.nodup_cons, ← noDup_iff l]
    simp [List.contains_iff_mem]

theorem payments_le_evidence {post : FinancialInput}
    (h39 : post.payments.all (paymentEvidenceWellFormed post) = true)
    (h51 : allReferencesExist (post.evidence.map EvidenceRecord.evidenceId) (post.payments.map Payment.evidenceId) = true)
    (h55 : noDuplicates (post.payments.map Payment.commonOriginId) = true) :
    post.payments.length ≤ post.evidence.length := by
  let g : String → String := fun id => ((findEvidence post.evidence id).map (·.commonOriginId)).getD ""
  have hg : post.payments.map Payment.commonOriginId = (post.payments.map Payment.evidenceId).map g := by
    rw [List.map_map]
    refine List.map_congr_left fun p hp => ?_
    have := List.all_eq_true.1 h39 p hp
    unfold paymentEvidenceWellFormed at this
    cases hf : findEvidence post.evidence p.evidenceId with
    | none => simp [hf] at this
    | some ev =>
      rw [hf] at this
      simp only [Bool.and_eq_true, decide_eq_true_eq] at this
      show _ = g p.evidenceId
      simp only [g, hf, Option.map_some, Option.getD_some]
      exact this.1.1.2.symm
  have hnd : (post.payments.map Payment.evidenceId).Nodup := by
    have := (noDup_iff _).1 h55
    rw [hg] at this
    exact List.Pairwise.of_map g (fun a b h e => h (by rw [e])) this
  have hsub : (post.payments.map Payment.evidenceId) ⊆ post.evidence.map EvidenceRecord.evidenceId := by
    intro x hx
    have := List.all_eq_true.1 h51 x hx
    simpa using this
  have := hnd.length_le_of_subset hsub
  simpa using this

end BlindLedger.Financial.Payment.Rev12
