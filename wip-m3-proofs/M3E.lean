import BlindLedger.Financial.Payment.Rev12
import M3D
open BlindLedger.Financial BlindLedger.Financial.Payment BlindLedger.Financial.CorrectionTransition
namespace BlindLedger.Financial.Payment.Rev12

/-! ## Lookup and list facts -/

theorem findEvidence_mem {l : List EvidenceRecord} {id e} (h : findEvidence l id = some e) : e ∈ l := by
  rw [findEvidence_eq] at h; exact List.mem_of_find?_eq_some h

theorem findEvidence_none_ne {l : List EvidenceRecord} {id} (h : findEvidence l id = none) :
    ∀ e ∈ l, e.evidenceId ≠ id := by
  rw [findEvidence_eq, List.find?_eq_none] at h
  intro e he eq; exact h e he (by simp [eq])

theorem findPayment_none_ne {l : List Payment} {id} (h : findPayment l id = none) :
    ∀ p ∈ l, p.paymentId ≠ id := by
  rw [findPayment_eq, List.find?_eq_none] at h
  intro e he eq; exact h e he (by simp [eq])

theorem length_insertBy {α} (key : α → String) (row : α) (l : List α) :
    (insertBy key row l).length = l.length + 1 := by
  rw [(insertBy_perm key row l).length_eq]; rfl

theorem all_insertBy {α} (key : α → String) (row : α) (f : α → Bool) {l : List α}
    (hr : f row = true) (hl : l.all f = true) : (insertBy key row l).all f = true := by
  rw [List.all_eq_true] at hl ⊢
  intro x hx
  rcases (mem_insertBy key row x l).1 hx with rfl | h
  · exact hr
  · exact hl x h

theorem mem_replace {P : List Payment} {new : Payment} {pid : String} {x : Payment}
    (hx : x ∈ P.map fun y => if y.paymentId = pid then new else y) : x = new ∨ x ∈ P := by
  obtain ⟨y, hy, rfl⟩ := List.mem_map.1 hx
  by_cases h : y.paymentId = pid
  · left; simp [h]
  · right; simpa [h] using hy

/-! ## Row predicates are monotone under growth of the evidence list -/

theorem pew_mono {i j : FinancialInput}
    (h : ∀ id ev, findEvidence i.evidence id = some ev → findEvidence j.evidence id = some ev)
    {q : Payment} (hq : paymentEvidenceWellFormed i q = true) : paymentEvidenceWellFormed j q = true := by
  unfold paymentEvidenceWellFormed at hq ⊢
  cases hf : findEvidence i.evidence q.evidenceId with
  | none => simp [hf] at hq
  | some ev => rw [hf] at hq; rw [h _ _ hf]; exact hq

theorem cew_mono {i j : FinancialInput}
    (h : ∀ id ev, findEvidence i.evidence id = some ev → findEvidence j.evidence id = some ev)
    {q : Claim} (hq : claimEvidenceWellFormed i q = true) : claimEvidenceWellFormed j q = true := by
  unfold claimEvidenceWellFormed at hq ⊢
  cases hf : findEvidence i.evidence q.evidenceId with
  | none => simp [hf] at hq
  | some ev => rw [hf] at hq; rw [h _ _ hf]; exact hq

theorem rew_mono {i j : FinancialInput}
    (h : ∀ id ev, findEvidence i.evidence id = some ev → findEvidence j.evidence id = some ev)
    {q : Payment} (hq : reversalEvidenceWellFormed i q = true) : reversalEvidenceWellFormed j q = true := by
  unfold reversalEvidenceWellFormed at hq ⊢
  rcases hs : q.status with _ | _ <;> rcases hr : q.reversalEvidenceId with _ | e <;>
    simp only [hs, hr] at hq ⊢
  · exact absurd hq (by decide)
  · exact absurd hq (by decide)
  cases hf : findEvidence i.evidence e with
  | none => simp [hf] at hq
  | some ev => rw [hf] at hq; rw [h _ _ hf]; exact hq

theorem confl_mono {i j : FinancialInput} (hc : j.context = i.context)
    (he : ∀ id ev, findEvidence i.evidence id = some ev → findEvidence j.evidence id = some ev)
    (hp : ∀ id q, findPayment i.payments id = some q → ∃ q', findPayment j.payments id = some q' ∧
      q'.commonOriginId = q.commonOriginId ∧ q'.amountCents = q.amountCents)
    {x : FinancialConflict} (hx : conflictWellFormed i x = true) : conflictWellFormed j x = true := by
  unfold conflictWellFormed at hx ⊢
  rw [hc]
  simp only [Bool.and_eq_true] at hx ⊢
  obtain ⟨hA, hB⟩ := hx
  refine ⟨hA, ?_⟩
  rcases hq : findPayment i.payments x.existingPaymentId with _ | q <;>
    rcases hq' : findEvidence i.evidence x.candidateEvidenceId with _ | ev <;> simp only [hq, hq'] at hB
  all_goals try exact absurd hB (by decide)
  obtain ⟨q', hq2, ho, ha⟩ := hp _ _ hq
  rw [hq2, he _ _ hq']
  simpa only [ho, ha] using hB

theorem accConf_mono {i j : FinancialInput}
    (hp : ∀ q ∈ i.payments, ∃ q' ∈ j.payments, q'.evidenceId = q.evidenceId ∧
      q'.commonOriginId = q.commonOriginId ∧ q'.amountCents = q.amountCents)
    (hc : ∀ x ∈ i.conflicts, x ∈ j.conflicts) {ev : EvidenceRecord}
    (h : paymentConfirmationAccounted i ev = true) : paymentConfirmationAccounted j ev = true := by
  unfold paymentConfirmationAccounted at h ⊢
  simp only [Bool.or_eq_true, List.any_eq_true, decide_eq_true_eq] at h ⊢
  rcases h with (⟨q, hq, hqe⟩ | ⟨x, hx, hxe⟩) | h
  · obtain ⟨q', hq', he, -, -⟩ := hp q hq
    exact Or.inl (Or.inl ⟨q', hq', he.trans hqe⟩)
  · exact Or.inl (Or.inr ⟨x, hc x hx, hxe⟩)
  · right
    cases ha : ev.amountCents with
    | none => simp [ha] at h
    | some a =>
      simp only [ha, List.any_eq_true, Bool.and_eq_true, decide_eq_true_eq] at h ⊢
      obtain ⟨q, hq, ho, hm⟩ := h
      obtain ⟨q', hq', -, ho', hm'⟩ := hp q hq
      exact ⟨q', hq', by rw [ho', ho], by rw [hm', hm]⟩

theorem accRev_mono {i j : FinancialInput}
    (hp : ∀ id q, findPayment i.payments id = some q → q.status = .REVERSED →
      findPayment j.payments id = some q)
    {ev : EvidenceRecord} (h : reversalEvidenceAccounted i ev = true) :
    reversalEvidenceAccounted j ev = true := by
  unfold reversalEvidenceAccounted at h ⊢
  cases hr : ev.reversalOf with
  | none => simp [hr] at h
  | some pid =>
    simp only [hr] at h ⊢
    cases hf : findPayment i.payments pid with
    | none => simp [hf] at h
    | some q =>
      simp only [hf] at h
      have hq : q.status = .REVERSED := by
        revert h; simp only [Bool.and_eq_true, decide_eq_true_eq]; intro h; exact h.1.1.1.1
      rw [hp pid q hf hq]
      exact h

/-- The evidence-accounted conjunct, as a function of the input (its `i.claims` is `j.claims`). -/
def accLam (j : FinancialInput) (evidence : EvidenceRecord) : Bool :=
  if evidence.kind = "PAYMENT_CONFIRMATION" then paymentConfirmationAccounted j evidence
  else if evidence.kind = "PAYMENT_REVERSAL" then reversalEvidenceAccounted j evidence
  else if evidence.kind = "OFFSET_CLAIM" then
    j.claims.any (fun claim => claim.evidenceId = evidence.evidenceId)
  else true

theorem wf_ctx {i : FinancialInput} (h : financialInputWellFormed i = true) :
    idWellFormed i.context.obligationId = true ∧ idWellFormed i.context.itemId = true ∧
      i.evaluatedAt ≤ maxTime := by
  simp only [financialInputWellFormed, Bool.and_assoc, Bool.and_eq_true, decide_eq_true_eq] at h
  obtain ⟨h1, -, -, -, -, -, h7, -⟩ := h
  have hc := h1
  unfold contextWellFormed at hc
  simp only [Bool.and_eq_true] at hc
  obtain ⟨⟨hall, -⟩, -⟩ := hc
  exact ⟨List.all_eq_true.1 hall _ (by simp), List.all_eq_true.1 hall _ (by simp), of_decide_eq_true h7⟩

end BlindLedger.Financial.Payment.Rev12
