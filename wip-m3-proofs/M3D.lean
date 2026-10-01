import BlindLedger.Financial.Payment.Rev12
import M3C
open BlindLedger.Financial BlindLedger.Financial.Payment BlindLedger.Financial.CorrectionTransition
namespace BlindLedger.Financial.Payment.Rev12

theorem evalLatestCase_const (st : CaseStatus) (t : Nat) :
    ∀ K : List CaseRecord, K ≠ [] →
      evalLatestCase (K.map fun k => { k with status := st, updatedAt := t }) = st
  | [], h => absurd rfl h
  | [_], _ => rfl
  | _ :: k2 :: ks, _ => by
    simp only [List.map_cons]
    exact evalLatestCase_const st t (k2 :: ks) (by simp)

theorem summarize_some {i : FinancialInput} {rs b S} (h : summarize i rs b = some S) :
    ∃ t, evaluateTotals i = some t ∧
      S = { revision := i.beforeRevision, cash := t.cash, claimed := t.claimed, lawful := t.lawful,
            contributions := evalSortContributions (evalContributions i),
            latestCase := evalLatestCase i.cases, delivery := evalLatestDelivery i.actions,
            conflictCount := i.conflicts.length, evidenceIds := i.evidence.map (·.evidenceId),
            requests := (i.actions.filter (·.kind = "CORRECTION_PAYMENT_REQUEST")).map fun a =>
              ⟨a.actionId, a.amountCents, linkedActivePaidCents i.payments (linksOf rs) a.actionId⟩,
            anchorBytes := b } := by
  unfold summarize at h
  cases ht : evaluateTotals i with
  | none => simp [ht] at h
  | some t =>
    simp only [ht, Option.map_some, Option.some.injEq] at h
    exact ⟨t, rfl, h.symm⟩

theorem evaluate_after {i : FinancialInput} {res} (h : evaluate i = some res) :
    res.afterRevision = i.beforeRevision + 1 := by
  unfold evaluate at h
  split at h
  · unfold evaluateWellFormed at h
    cases hT : evaluateTotals i with
    | none => simp [hT] at h
    | some t => simp only [hT, Option.map_some, Option.some.injEq] at h; subst h; rfl
  · simp at h

theorem evaluate_none_of {i : FinancialInput}
    (h : financialInputWellFormed i = true → evaluateTotals i = none) : evaluate i = none := by
  unfold evaluate
  by_cases hw : financialInputWellFormed i = true
  · rw [if_pos hw]; unfold evaluateWellFormed; rw [h hw]; rfl
  · rw [if_neg hw]

theorem summary_commit {post : FinancialInput} {res : FinancialResult} {rs : List Receipt} {s' : ItemState}
    (hcases : post.cases ≠ [])
    (hs : summarize post rs (anchorItemLength post rs) = some s')
    (hres : res.afterRevision = post.beforeRevision + 1) :
    summaryOf (commitInput post res) rs = some (settle s' res) := by
  have hA : anchorItemLength (commitInput post res) rs = anchorItemLength post rs := by
    unfold anchorItemLength; rw [rawEncode_commit_length]
  unfold summaryOf
  rw [hA]
  obtain ⟨t, ht, rfl⟩ := summarize_some hs
  unfold summarize
  have hT : evaluateTotals (commitInput post res) = some t := ht
  rw [hT]
  simp only [Option.map_some, Option.some.injEq, settle, commitInput, hres]
  rw [evalLatestCase_const _ _ _ hcases]
  rfl

/-- The commit step, for any write set whose `advance` is the summary of the written post-state. -/
theorem commit_core {r : PaymentRequest} {V : PaymentView} {S : ItemState} {k : Mutation} {w : Writes}
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hS : summarize r.input r.receipts (anchorItemLength r.input r.receipts) = some S)
    (hVenv : V.env = envOf r.input)
    (hgrow : anchorGrowth V w = addedBytes r.input w + receiptBytes w)
    (hraw : (rawEncodeFinancialInput (applyWrites r.input w)).length =
      (rawEncodeFinancialInput r.input).length + addedBytes r.input w)
    (hcases : r.input.cases ≠ [])
    (hadv : ∀ s', advance V S w = some s' → financialInputWellFormed (applyWrites r.input w) = true)
    (hsum : financialInputWellFormed (applyWrites r.input w) = true →
      advance V S w = summarize (applyWrites r.input w) (commitReceipts r.receipts w)
        (S.anchorBytes + anchorGrowth V w)) :
    some (commitView V S k w) = project r (mutate r k w) := by
  have hSb : S.anchorBytes = anchorItemLength r.input r.receipts := by
    obtain ⟨t, -, rfl⟩ := summarize_some hS; rfl
  have hcr := commitReceipts_len r.receipts w
  have hcap : (S.anchorBytes + anchorGrowth V w + maxCallTailBytes > maxTotalEncodedBytes) ↔
      ¬ withinCapacity r w = true := by
    simp only [withinCapacity, anchorItemLength, decide_eq_true_eq] at hSb ⊢
    omega
  unfold commitView mutate
  rw [hVenv]
  by_cases hsh : r.input.context.mode = .SHADOW
  · simp [envOf, hsh, project]
  have hsh' : (envOf r.input).context.mode ≠ .SHADOW := hsh
  simp only [hsh', hsh, if_false]
  by_cases hcp : withinCapacity r w = true
  · have hc2 : ¬ (S.anchorBytes + anchorGrowth V w + maxCallTailBytes > maxTotalEncodedBytes) :=
      fun h => (hcap.1 h) hcp
    simp only [hc2, hcp, if_false, Bool.not_true, Bool.false_eq_true]
    cases hA : advance V S w with
    | none =>
      have hnone : evaluate (applyWrites r.input w) = none := by
        refine evaluate_none_of fun hw => ?_
        have := hsum hw
        rw [hA] at this
        unfold summarize at this
        cases ht : evaluateTotals (applyWrites r.input w) with
        | none => rfl
        | some t => simp [ht] at this
      simp [hnone, project]
    | some s' =>
      have hw := hadv s' hA
      have hs' := (hsum hw).symm.trans hA
      have hb' : S.anchorBytes + anchorGrowth V w =
          anchorItemLength (applyWrites r.input w) (commitReceipts r.receipts w) := by
        simp only [anchorItemLength, hraw, hSb, hgrow] at hcr ⊢
        omega
      rw [hb'] at hs'
      have hev : evaluateState (envOf r.input) s' = evaluate (applyWrites r.input w) :=
        evaluateState_summarize hw hs'
      dsimp only
      rw [hev]
      cases hE : evaluate (applyWrites r.input w) with
      | none => simp [project]
      | some res =>
        have hres := evaluate_after hE
        have hsc := summary_commit (post := applyWrites r.input w) hcases hs' hres
        simp [project, hsc]
  · have hc2 : S.anchorBytes + anchorGrowth V w + maxCallTailBytes > maxTotalEncodedBytes :=
      hcap.2 hcp
    simp [hc2, hcp, project]

end BlindLedger.Financial.Payment.Rev12
