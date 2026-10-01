import BlindLedger.Financial.Payment.Rev12
import M3J
open BlindLedger.Financial BlindLedger.Financial.Payment BlindLedger.Financial.CorrectionTransition
namespace BlindLedger.Financial.Payment.Rev12

theorem adv_cf (V : PaymentView) (S : ItemState) (ev : Option EvidenceRecord) (x : FinancialConflict) :
    advance V S ⟨ev, none, some x, none⟩ =
      if ((ev.map fun e => insertBy (fun x => x) e.evidenceId S.evidenceIds).getD S.evidenceIds).length > maxRows ||
          S.conflictCount + 1 > maxRows then none else
      some { S with
        evidenceIds := (ev.map fun e => insertBy (fun x => x) e.evidenceId S.evidenceIds).getD S.evidenceIds,
        conflictCount := S.conflictCount + 1,
        anchorBytes := S.anchorBytes + anchorGrowth V ⟨ev, none, some x, none⟩ } := by
  unfold advance
  rfl

theorem shape_conflict {r : PaymentRequest} {V : PaymentView} {S : ItemState}
    (hwf : financialInputWellFormed r.input = true)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hS : summarize r.input r.receipts (anchorItemLength r.input r.receipts) = some S)
    (hVenv : V.env = envOf r.input)
    {c : RecordCommand} (hc : commandWellFormed (.record c) = true) (h0 : c.amountCents ≠ 0)
    {p : Payment} (hp : findPayment r.input.payments p.paymentId = some p)
    (hporig : p.commonOriginId = c.commonOriginId) (hne : p.amountCents ≠ c.amountCents)
    (hcv : r.input.conflicts.any (·.conflictId = conflictIdOf r.input c) = false)
    (hcid : idWellFormed (conflictIdOf r.input c) = true)
    {ev : Option EvidenceRecord} (hev : EvCase r.input c ev) :
    some (commitView V S .CONFLICT_RECORDED ⟨ev, none, some (conflictImage r.input c p (conflictIdOf r.input c)), none⟩) =
      project r (mutate r .CONFLICT_RECORDED ⟨ev, none, some (conflictImage r.input c p (conflictIdOf r.input c)), none⟩) := by
  obtain ⟨hSe, hSc, hScash, hSle, hSctr, hSreq, hSab⟩ := S_facts hS
  obtain ⟨hE, ⟨t, hEt⟩, hEnew, hEcan⟩ := ev_facts hwf hc hev
  obtain ⟨hP1, hE1, hC1, hPwf, hPew, hPrew, hNo, hcases⟩ := wf_facts hwf
  obtain ⟨hcP, hcE, hcC⟩ := wf_canon hwf
  obtain ⟨hid1, hid2, hnow⟩ := wf_ctx hwf
  obtain ⟨hcid1, hcid2, hcid3, hcid4, hcid5, hcamt, hceve⟩ := cmd_record hc
  have hpm := findPayment_mem hp
  have hpwf := hPwf p hpm
  have hpwf' := hpwf
  simp only [paymentWellFormed, Bool.and_eq_true, decide_eq_true_eq, List.all_cons, List.all_nil,
    Bool.and_true, positiveAmountWellFormed, amountWellFormed] at hpwf'
  obtain ⟨⟨⟨⟨⟨⟨hp1, -, -, -, -⟩, -⟩, -⟩, ⟨hppos, hpamax⟩⟩, -⟩, -⟩ := hpwf'
  let x := conflictImage r.input c p (conflictIdOf r.input c)
  have hpost : applyWrites r.input ⟨ev, none, some x, none⟩ =
      upd r.input r.input.payments (evOf r.input ev) (insertBy FinancialConflict.conflictId x r.input.conflicts) :=
    rfl
  have hnc : conflictIdOf r.input c ∉ r.input.conflicts.map FinancialConflict.conflictId := by
    intro hm
    obtain ⟨y, hy, e⟩ := List.mem_map.1 hm
    have : r.input.conflicts.any (·.conflictId = conflictIdOf r.input c) = true :=
      List.any_eq_true.2 ⟨y, hy, decide_eq_true e⟩
    rw [hcv] at this; cases this
  have hwfpost : (evOf r.input ev).length ≤ maxRows → r.input.conflicts.length + 1 ≤ maxRows →
      financialInputWellFormed (upd r.input r.input.payments (evOf r.input ev)
        (insertBy FinancialConflict.conflictId x r.input.conflicts)) = true := fun hl hcl => by
    refine wf_grow hwf hE (fun id q h => ⟨q, h, rfl, rfl, rfl⟩) (fun id q h _ => h)
      (fun y hy => (mem_insertBy _ _ _ _).2 (Or.inr hy)) hl ?_ (fun _ => hcP) ?_ ?_ hNo
      (fun q hq hn => absurd hq hn) ?_ ?_
    · rw [length_insertBy]; exact hcl
    · exact evOf_canon hcE hEcan hl
    · have : (insertBy FinancialConflict.conflictId x r.input.conflicts).map FinancialConflict.conflictId =
          insertBy (fun s => s) x.conflictId (r.input.conflicts.map FinancialConflict.conflictId) :=
        map_insertBy _ _ (fun s => s) (fun _ => rfl) x _
      rw [this]
      refine canonical_insert hcC hcid hnc ?_
      rw [List.length_map]; omega
    · intro y hy hn
      obtain ⟨a, b, d, e, -, -⟩ := hEnew y hy hn
      refine ⟨a, b, ?_⟩
      have hany : (upd r.input r.input.payments (evOf r.input ev)
          (insertBy FinancialConflict.conflictId x r.input.conflicts)).conflicts.any
          (fun z => decide (z.candidateEvidenceId = y.evidenceId)) = true :=
        List.any_eq_true.2 ⟨x, (mem_insertBy _ _ _ _).2 (Or.inl rfl), decide_eq_true (by rw [d]; rfl)⟩
      unfold accLam
      rw [if_pos e]
      unfold paymentConfirmationAccounted
      simp [hany]
    · intro y hy hn
      rcases (mem_insertBy _ _ y _).1 hy with rfl | h
      · have hr : idWellFormed "CONFLICTING_COMMON_ORIGIN_AMOUNT" = true := id_reason
        have hpa : 0 < p.amountCents := hppos
        have hca : 0 < c.amountCents := Nat.pos_of_ne_zero h0
        simp [conflictWellFormed, x, conflictImage, confirmation, upd, positiveAmountWellFormed, amountWellFormed,
          timeWellFormed, hcid, hid1, hcid3, hp1, hcid2, hr, hp, hEt, hporig, hne, hpamax, hcamt, hnow, hpa, hca]
      · exact absurd h hn
  have hold : oldPay r.input ⟨ev, none, some x, none⟩ = 0 := by simp [oldPay]
  have hnew : newPay ⟨ev, none, some x, none⟩ = 0 := by simp [newPay]
  refine commit_core hb hS hVenv ?_ ?_ hcases ?_ ?_
  · unfold anchorGrowth addedBytes
    rw [hold, hnew]
    simp
  · have := rawEncode_applyWrites_core r.input ⟨ev, none, some x, none⟩ (fun q hq => by cases hq)
    unfold addedBytes
    simp only [x] at this
    rw [hold, hnew] at this ⊢
    omega
  · intro s' h
    rw [hpost]
    rw [adv_cf] at h
    by_cases h1 : ((ev.map fun e => insertBy (fun x => x) e.evidenceId S.evidenceIds).getD S.evidenceIds).length > maxRows ||
        S.conflictCount + 1 > maxRows
    · rw [if_pos h1] at h; cases h
    · rw [hSe, ← evOf_ids] at h1
      simp only [List.length_map, Bool.or_eq_true, decide_eq_true_eq, not_or, Nat.not_lt] at h1
      rw [hSc] at h1
      exact hwfpost h1.1 h1.2
  · intro hw
    rw [hpost] at hw ⊢
    obtain ⟨-, hl, hcl, -⟩ := wf_facts hw
    simp only [upd, length_insertBy] at hl hcl
    rw [summarize_upd hS, adv_cf]
    have hids : (ev.map fun e => insertBy (fun x => x) e.evidenceId S.evidenceIds).getD S.evidenceIds =
        (evOf r.input ev).map EvidenceRecord.evidenceId := by rw [evOf_ids, hSe]
    have h1 : ¬ (((ev.map fun e => insertBy (fun x => x) e.evidenceId S.evidenceIds).getD S.evidenceIds).length > maxRows ||
        S.conflictCount + 1 > maxRows) := by
      rw [hids, List.length_map, hSc]
      simp only [Bool.or_eq_true, decide_eq_true_eq, not_or, Nat.not_lt]
      exact ⟨hl, hcl⟩
    rw [if_neg h1, if_pos (by rw [← hScash]; exact hSle)]
    cases S with
    | mk rev cash claimed lawful contr lc dl cc eids reqs ab =>
      dsimp only at hScash hSe hSc hSctr hSreq hSab hids
      subst hScash hSctr hSreq hSe hSc
      simp only [Option.some.injEq, ItemState.mk.injEq, true_and, and_true]
      exact ⟨(length_insertBy _ _ _).symm, (evOf_ids _ _).symm, rfl⟩

end BlindLedger.Financial.Payment.Rev12
