import BlindLedger.Financial.Payment.Rev12
import M3H
open BlindLedger.Financial BlindLedger.Financial.Payment BlindLedger.Financial.CorrectionTransition
namespace BlindLedger.Financial.Payment.Rev12

/-! ## Facts read off a summary -/

theorem S_facts {i : FinancialInput} {rs b S} (h : summarize i rs b = some S) :
    S.evidenceIds = i.evidence.map EvidenceRecord.evidenceId ∧ S.conflictCount = i.conflicts.length ∧
    S.cash = activeCents i.payments ∧ S.cash + S.lawful ≤ maxCents ∧
    S.contributions = evalSortContributions (pcOf i.payments ++ dcOf i.determinations) ∧
    S.requests = (i.actions.filter (·.kind = "CORRECTION_PAYMENT_REQUEST")).map (fun a =>
      (⟨a.actionId, a.amountCents, linkedActivePaidCents i.payments (linksOf rs) a.actionId⟩ : RequestPaid)) ∧
    S.anchorBytes = b := by
  have hc := cash_eq h
  obtain ⟨t, ht, rfl⟩ := summarize_some h
  have := evaluateTotals_payments ht i.payments
  have e : ({ i with payments := i.payments } : FinancialInput) = i := rfl
  rw [e, ht] at this
  refine ⟨rfl, rfl, hc, ?_, rfl, rfl, rfl⟩
  by_cases hq : activeCents i.payments + t.lawful ≤ maxCents
  · rw [hc]; exact hq
  · rw [if_neg hq] at this; cases this

/-! ## The evidence write of a record: a fresh confirmation, or a stored retry of it -/

def EvCase (i : FinancialInput) (c : RecordCommand) (ev : Option EvidenceRecord) : Prop :=
  (ev = some (confirmation i c i.evaluatedAt) ∧ findEvidence i.evidence c.evidenceId = none ∧
    formRefusal (confirmation i c i.evaluatedAt) = none ∧ c.eventAt ≤ i.evaluatedAt) ∨
  (ev = none ∧ ∃ t, findEvidence i.evidence c.evidenceId = some (confirmation i c t))

theorem evCase_of {r : PaymentRequest} {c ev} (h : EvidenceWrite r c ev) : EvCase r.input c ev := by
  obtain ⟨hf, hle, -, h | h⟩ := h
  · exact Or.inl ⟨h.1, h.2, hf, hle⟩
  · obtain ⟨hn, s, hs, -, hc⟩ := h
    exact Or.inr ⟨hn, s.receivedAt, by rw [hc]; exact hs⟩

def evOf (i : FinancialInput) (ev : Option EvidenceRecord) : List EvidenceRecord :=
  (ev.map fun e => insertBy EvidenceRecord.evidenceId e i.evidence).getD i.evidence

theorem evOf_ids (i : FinancialInput) (ev : Option EvidenceRecord) :
    (evOf i ev).map EvidenceRecord.evidenceId =
      (ev.map fun e => insertBy (fun x => x) e.evidenceId (i.evidence.map EvidenceRecord.evidenceId)).getD
        (i.evidence.map EvidenceRecord.evidenceId) := by
  cases ev with
  | none => rfl
  | some e =>
    simp only [evOf, Option.map_some, Option.getD_some]
    exact map_insertBy EvidenceRecord.evidenceId EvidenceRecord.evidenceId (fun s => s) (fun _ => rfl) e _

theorem evOf_length (i : FinancialInput) (ev : Option EvidenceRecord) :
    (evOf i ev).length = i.evidence.length + (if ev.isSome then 1 else 0) := by
  cases ev with
  | none => rfl
  | some e => simp [evOf, length_insertBy]

theorem wf_canon {i : FinancialInput} (h : financialInputWellFormed i = true) :
    canonicalIdList (i.payments.map Payment.paymentId) = true ∧
    canonicalIdList (i.evidence.map EvidenceRecord.evidenceId) = true ∧
    canonicalIdList (i.conflicts.map FinancialConflict.conflictId) = true := by
  simp only [financialInputWellFormed, Bool.and_assoc, Bool.and_eq_true, decide_eq_true_eq] at h
  obtain ⟨h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11,h12,h13,h14,h15,h16,h17,h18,h19,h20,h21,h22,h23,h24,h25,h26,h27,h28,h29,h30,h31,h32,h33,h34,h35,h36,h37,h38,h39,h40,h41,h42,h43,h44,h45,h46,h47,h48,h49,h50,h51,h52,h53,h54,h55⟩ := h
  exact ⟨h25, h28, h29⟩

theorem ev_facts {i : FinancialInput} (hwf : financialInputWellFormed i = true) {c : RecordCommand}
    (hc : commandWellFormed (.record c) = true) {ev} (hev : EvCase i c ev) :
    (∀ id x, findEvidence i.evidence id = some x → findEvidence (evOf i ev) id = some x) ∧
    (∃ t, findEvidence (evOf i ev) c.evidenceId = some (confirmation i c t)) ∧
    (∀ x ∈ evOf i ev, x ∉ i.evidence → evidenceWellFormed i.context x = true ∧
      x.receivedAt ≤ i.evaluatedAt ∧ x.evidenceId = c.evidenceId ∧ x.kind = "PAYMENT_CONFIRMATION" ∧
      x.commonOriginId = c.commonOriginId ∧ x.amountCents = some c.amountCents) ∧
    (ev.isSome = true → (evOf i ev).length ≤ maxRows →
      canonicalIdList ((evOf i ev).map EvidenceRecord.evidenceId) = true) := by
  obtain ⟨hid1, hid2, hnow⟩ := wf_ctx hwf
  rcases hev with ⟨rfl, hf, hform, hle⟩ | ⟨rfl, t, ht⟩
  · have hf' : findEvidence i.evidence (confirmation i c i.evaluatedAt).evidenceId = none := hf
    have hfi : ∀ id, findEvidence (evOf i (some (confirmation i c i.evaluatedAt))) id =
        if c.evidenceId = id then some (confirmation i c i.evaluatedAt) else findEvidence i.evidence id :=
      fun id => findEvidence_insertBy hf'
    refine ⟨fun id x h => ?_, ⟨i.evaluatedAt, by rw [hfi]; simp⟩, fun x hx hn => ?_, fun _ hl => ?_⟩
    · rw [hfi]
      by_cases e : c.evidenceId = id
      · subst e; rw [hf] at h; cases h
      · rw [if_neg e]; exact h
    · have hx' : x ∈ insertBy EvidenceRecord.evidenceId (confirmation i c i.evaluatedAt) i.evidence := hx
      rcases (mem_insertBy _ _ x _).1 hx' with rfl | h
      · exact ⟨confirmation_wf ⟨hid1, hid2⟩ hc hform hle hnow, Nat.le_refl _, rfl, rfl, rfl, rfl⟩
      · exact absurd h hn
    · rw [evOf_ids]
      simp only [Option.map_some, Option.getD_some]
      refine canonical_insert (wf_canon hwf).2.1 (cmd_record hc).2.1 ?_ ?_
      · intro hm
        obtain ⟨x, hx⟩ := find_of_known (List.contains_iff_mem.2 hm)
        rw [hf'] at hx; cases hx
      · have := evOf_length i (some (confirmation i c i.evaluatedAt))
        simp only [Option.isSome_some, if_true] at this
        rw [List.length_map]; omega
  · exact ⟨fun id x h => h, ⟨t, ht⟩, fun x hx hn => absurd hx hn, fun h => by simp at h⟩

end BlindLedger.Financial.Payment.Rev12
