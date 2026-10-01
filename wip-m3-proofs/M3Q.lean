import BlindLedger.Financial.Payment.Rev12
import M3O
open BlindLedger.Financial BlindLedger.Financial.Payment BlindLedger.Financial.CorrectionTransition
namespace BlindLedger.Financial.Payment.Rev12

theorem conf_evid (i : FinancialInput) (c : RecordCommand) (t : Nat) :
    (confirmation i c t).evidenceId = c.evidenceId := rfl

theorem slot_facts {foreign : Bool} {stored : Option EvidenceRecord} {e : EvidenceRecord} {slot : Slot}
    (h : slotOf foreign stored e = slot) :
    (slot = .fresh → foreign = false ∧ stored = none) ∧
    (∀ s, slot = .same s → foreign = false ∧ stored = some s ∧ e.eventAt ≤ s.receivedAt ∧
      { e with receivedAt := s.receivedAt } = s) := by
  unfold slotOf at h
  cases foreign with
  | true =>
    simp only [↓reduceIte] at h
    subst h
    exact ⟨fun h => (nomatch h), fun s h => nomatch h⟩
  | false =>
    cases stored with
    | none =>
      simp only [Bool.false_eq_true, ↓reduceIte] at h
      subst h
      exact ⟨fun _ => ⟨rfl, rfl⟩, fun s h => nomatch h⟩
    | some s0 =>
      simp only [Bool.false_eq_true, ↓reduceIte] at h
      by_cases hc : e.eventAt ≤ s0.receivedAt ∧ { e with receivedAt := s0.receivedAt } = s0
      · rw [if_pos hc] at h
        subst h
        refine ⟨fun h => (nomatch h), fun s h => ?_⟩
        cases h
        exact ⟨rfl, rfl, hc.1, hc.2⟩
      · rw [if_neg hc] at h
        subst h
        exact ⟨fun h => (nomatch h), fun s h => nomatch h⟩

theorem ev_leaf {i : FinancialInput} {c : RecordCommand} {R : Nat} {foreign : Bool} {slot : Slot}
    (hsl : slotOf foreign (findEvidence i.evidence c.evidenceId) (confirmation i c R) = slot)
    (hne : slot ≠ .clash) (hR : findEvidence i.evidence c.evidenceId = none → R = i.evaluatedAt)
    (hform : formRefusal (confirmation i c R) = none) (hle : c.eventAt ≤ R) :
    EvCase i c (if slot.isFresh = true then some (confirmation i c R) else none) := by
  obtain ⟨hf, hs⟩ := slot_facts hsl
  cases slot with
  | clash => exact absurd rfl hne
  | fresh =>
    obtain ⟨-, hst⟩ := hf rfl
    have := hR hst
    subst this
    exact Or.inl ⟨rfl, hst, hform, hle⟩
  | same s =>
    obtain ⟨-, hst, -, hs'⟩ := hs s rfl
    refine Or.inr ⟨rfl, s.receivedAt, ?_⟩
    rw [hst]
    exact congrArg some hs'.symm

theorem new_none {r : PaymentRequest} {V : PaymentView} {S : ItemState}
    (hwf : financialInputWellFormed r.input = true)
    (hrec : r.receipts.map Receipt.paymentId = r.input.payments.map Payment.paymentId)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hS : summarize r.input r.receipts (anchorItemLength r.input r.receipts) = some S)
    (hVenv : V.env = envOf r.input) {c : RecordCommand} (hc : commandWellFormed (.record c) = true)
    (h0 : c.amountCents ≠ 0) (hpid : findPayment r.input.payments c.paymentId = none)
    (hbyId : V.byId = none) (hbo : V.byOrigin = none)
    (hev : V.evidence = findEvidence r.input.evidence c.evidenceId)
    (hcv : V.conflictVisible = r.input.conflicts.any (·.conflictId = conflictIdOf r.input c))
    (hfor : V.foreign = r.foreign) (hexp : V.expectedRevision = r.expectedRevision)
    (hex : r.input.payments.find? (·.commonOriginId = c.commonOriginId) = none) :
    some (viewRecordNew V S c) = project r (recordNew r c) := by
  have hlink := linkRefusalView_eq hwf hS c
  have hno : ∀ q ∈ r.input.payments, q.commonOriginId ≠ c.commonOriginId :=
    fun q hq h => (List.find?_eq_none.1 hex q hq) (decide_eq_true h)
  unfold viewRecordNew recordNew
  simp only [hbo, hev, hcv, hfor, hexp, hVenv, hex, hlink, head_conf, head_cid, head_rpay, head_rrcp, head_cimg,
    envOf_eval, envOf_before, revisionOk, evidenceSlot_eq, conf_evid, Option.any_none, Option.isSome_none,
    Bool.false_and, Bool.and_false, Bool.not_false, Bool.true_and, Bool.false_or, Bool.or_false,
    Bool.false_eq_true, ↓reduceIte, Option.map_none, Option.getD_none]
  by_cases hrv : (!Option.all (fun x => decide (x = r.input.beforeRevision)) r.expectedRevision) = true
  · simp only [hrv, ↓reduceIte]; rfl
  · simp only [hrv, Bool.false_eq_true, ↓reduceIte]
    cases hform : formRefusal (confirmation r.input c r.input.evaluatedAt) with
    | some f => simp only [hform]; rfl
    | none =>
      simp only [hform]
      by_cases hch : c.eventAt > r.input.evaluatedAt
      · simp only [hch, ↓reduceIte]; rfl
      · simp only [hch, ↓reduceIte]
        cases hsl : slotOf r.foreign.evidenceId (findEvidence r.input.evidence c.evidenceId)
            (confirmation r.input c r.input.evaluatedAt) with
        | clash => simp only [hsl]; rfl
        | same s =>
          simp only [hsl]
          cases hlr : linkRefusal r.input r.receipts c with
          | some f => simp only [hlr]; rfl
          | none =>
            simp only [hlr]
            exact shape_recorded hwf hrec hb hS hVenv hbyId hc h0 hpid hno
              (ev_leaf hsl (by simp) (fun _ => rfl) hform (Nat.not_lt.1 hch))
        | fresh =>
          simp only [hsl]
          cases hlr : linkRefusal r.input r.receipts c with
          | some f => simp only [hlr]; rfl
          | none =>
            simp only [hlr]
            exact shape_recorded hwf hrec hb hS hVenv hbyId hc h0 hpid hno
              (ev_leaf hsl (by simp) (fun _ => rfl) hform (Nat.not_lt.1 hch))

end BlindLedger.Financial.Payment.Rev12
