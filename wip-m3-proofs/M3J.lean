import BlindLedger.Financial.Payment.Rev12
import M3I
open BlindLedger.Financial BlindLedger.Financial.Payment BlindLedger.Financial.CorrectionTransition
namespace BlindLedger.Financial.Payment.Rev12

/-! ## `advance` on the three write shapes -/

theorem adv_rec (V : PaymentView) (S : ItemState) (ev : Option EvidenceRecord) (p : Payment) (k : Receipt) :
    advance V S ⟨ev, some p, none, some k⟩ =
      if ((ev.map fun e => insertBy (fun x => x) e.evidenceId S.evidenceIds).getD S.evidenceIds).length > maxRows ||
          S.conflictCount > maxRows then none else
      if S.cash + p.amountCents + S.lawful > maxCents then none else
      some { S with
        evidenceIds := (ev.map fun e => insertBy (fun x => x) e.evidenceId S.evidenceIds).getD S.evidenceIds,
        anchorBytes := S.anchorBytes + anchorGrowth V ⟨ev, some p, none, some k⟩,
        cash := S.cash + p.amountCents,
        contributions := evalInsertContribution ⟨p.eventAt, p.paymentId, p.amountCents⟩ S.contributions,
        requests := S.requests.map fun q =>
          if k.paysActionId = some q.actionId then { q with paidCents := q.paidCents + p.amountCents } else q } := by
  unfold advance
  rfl

theorem evOf_canon {i : FinancialInput} {ev : Option EvidenceRecord}
    (hcE : canonicalIdList (i.evidence.map EvidenceRecord.evidenceId) = true)
    (hEcan : ev.isSome = true → (evOf i ev).length ≤ maxRows →
      canonicalIdList ((evOf i ev).map EvidenceRecord.evidenceId) = true)
    (hl : (evOf i ev).length ≤ maxRows) :
    canonicalIdList ((evOf i ev).map EvidenceRecord.evidenceId) = true := by
  by_cases hs : ev.isSome = true
  · exact hEcan hs hl
  · have : ev = none := by cases ev with | none => rfl | some _ => exact absurd rfl hs
    subst this
    exact hcE

theorem shape_recorded {r : PaymentRequest} {V : PaymentView} {S : ItemState}
    (hwf : financialInputWellFormed r.input = true)
    (hrec : r.receipts.map Receipt.paymentId = r.input.payments.map Payment.paymentId)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hS : summarize r.input r.receipts (anchorItemLength r.input r.receipts) = some S)
    (hVenv : V.env = envOf r.input) (hbyId : V.byId = none)
    {c : RecordCommand} (hc : commandWellFormed (.record c) = true) (h0 : c.amountCents ≠ 0)
    (hpid : findPayment r.input.payments c.paymentId = none)
    (hno : ∀ q ∈ r.input.payments, q.commonOriginId ≠ c.commonOriginId)
    {ev : Option EvidenceRecord} (hev : EvCase r.input c ev) :
    some (commitView V S .RECORDED ⟨ev, some (recordedPayment r.input c), none, some (recordedReceipt r.input c)⟩) =
      project r (mutate r .RECORDED ⟨ev, some (recordedPayment r.input c), none, some (recordedReceipt r.input c)⟩) := by
  obtain ⟨hSe, hSc, hScash, hSle, hSctr, hSreq, hSab⟩ := S_facts hS
  obtain ⟨hE, ⟨t, hEt⟩, hEnew, hEcan⟩ := ev_facts hwf hc hev
  obtain ⟨hP1, hE1, hC1, hPwf, hPew, hPrew, hNo, hcases⟩ := wf_facts hwf
  obtain ⟨hcP, hcE, hcC⟩ := wf_canon hwf
  obtain ⟨hid1, hid2, hnow⟩ := wf_ctx hwf
  have hnd := nodup_ids_of_wf hwf
  obtain ⟨hcid, -⟩ := cmd_record hc
  have hpost : applyWrites r.input ⟨ev, some (recordedPayment r.input c), none, some (recordedReceipt r.input c)⟩ =
      upd r.input (insertBy Payment.paymentId (recordedPayment r.input c) r.input.payments)
        (evOf r.input ev) r.input.conflicts := by
    unfold applyWrites upd evOf
    simp [recordedPayment, hpid]
  have hxact : (recordedPayment r.input c).status = .ACTIVE := rfl
  have hwfpost : (evOf r.input ev).length ≤ maxRows →
      financialInputWellFormed (upd r.input (insertBy Payment.paymentId (recordedPayment r.input c) r.input.payments)
        (evOf r.input ev) r.input.conflicts) = true := fun hl => by
    refine wf_grow hwf hE (fun id q h => ⟨q, ?_, rfl, rfl, rfl⟩) (fun id q h _ => ?_) (fun x hx => hx) hl hC1
      (fun hlen => ?_) ?_ hcC ?_ ?_ ?_ (fun q hq hn => absurd hq hn)
    · rw [findPayment_insertBy hpid]
      by_cases e : (recordedPayment r.input c).paymentId = id
      · exact absurd (e ▸ h) (by simp [recordedPayment, hpid])
      · rw [if_neg e]; exact h
    · rw [findPayment_insertBy hpid]
      by_cases e : (recordedPayment r.input c).paymentId = id
      · exact absurd (e ▸ h) (by simp [recordedPayment, hpid])
      · rw [if_neg e]; exact h
    · rw [ids_insert]
      refine canonical_insert hcP hcid ?_ ?_
      · intro hm
        obtain ⟨q, hq, e⟩ := List.mem_map.1 hm
        exact findPayment_none_ne hpid q hq e
      · rw [List.length_map]; rw [length_insertBy] at hlen; omega
    · exact evOf_canon hcE hEcan hl
    · rw [noDup_iff]
      refine ((insertBy_perm Payment.paymentId (recordedPayment r.input c) r.input.payments).map
        Payment.commonOriginId).nodup_iff.2 (List.nodup_cons.2 ⟨?_, (noDup_iff _).1 hNo⟩)
      intro hm
      obtain ⟨q, hq, e⟩ := List.mem_map.1 hm
      exact hno q hq e
    · intro q hq hn
      rcases (mem_insertBy _ _ q _).1 hq with rfl | h
      · refine ⟨recordedPayment_wf ⟨hid1, hid2⟩ hc h0, ?_, rfl⟩
        have hfe : findEvidence (evOf r.input ev) (recordedPayment r.input c).evidenceId =
            some (confirmation r.input c t) := hEt
        unfold paymentEvidenceWellFormed
        simp only [upd]
        rw [hfe]
        simp [confirmation, recordedPayment]
      · exact absurd h hn
    · intro x hx hn
      obtain ⟨a, b, d, e, -, -⟩ := hEnew x hx hn
      refine ⟨a, b, ?_⟩
      have hany : (upd r.input (insertBy Payment.paymentId (recordedPayment r.input c) r.input.payments)
          (evOf r.input ev) r.input.conflicts).payments.any (fun q => decide (q.evidenceId = x.evidenceId)) = true :=
        List.any_eq_true.2 ⟨recordedPayment r.input c, (mem_insertBy _ _ _ _).2 (Or.inl rfl),
          decide_eq_true (by rw [d]; rfl)⟩
      unfold accLam
      rw [if_pos e]
      unfold paymentConfirmationAccounted
      simp [hany]
  have hold : oldPay r.input ⟨ev, some (recordedPayment r.input c), none, some (recordedReceipt r.input c)⟩ = 0 := by
    simp [oldPay, recordedPayment, hpid]
  refine commit_core hb hS hVenv ?_ ?_ hcases ?_ ?_
  · unfold anchorGrowth addedBytes
    rw [hold, hbyId]
    simp
  · have := rawEncode_applyWrites_core r.input ⟨ev, some (recordedPayment r.input c), none, some (recordedReceipt r.input c)⟩
      (fun q hq hs => by simp [recordedPayment, hpid] at hq hs; subst hq; simp [hpid] at hs)
    unfold addedBytes
    rw [hold] at this ⊢
    omega
  · intro s' h
    rw [hpost]
    refine hwfpost ?_
    rw [adv_rec] at h
    by_cases h1 : ((ev.map fun e => insertBy (fun x => x) e.evidenceId S.evidenceIds).getD S.evidenceIds).length > maxRows ||
        S.conflictCount > maxRows
    · rw [if_pos h1] at h; cases h
    · rw [hSe, ← evOf_ids] at h1
      simp only [List.length_map, Bool.or_eq_true, decide_eq_true_eq, not_or, Nat.not_lt] at h1
      exact h1.1
  · intro hw
    rw [hpost] at hw ⊢
    have hl := (wf_facts hw).2.1
    simp only [upd] at hl
    rw [summarize_upd hS, adv_rec]
    have hids : (ev.map fun e => insertBy (fun x => x) e.evidenceId S.evidenceIds).getD S.evidenceIds =
        (evOf r.input ev).map EvidenceRecord.evidenceId := by rw [evOf_ids, hSe]
    have hcash := activeCents_insert hxact r.input.payments
    have h1 : ¬ (((ev.map fun e => insertBy (fun x => x) e.evidenceId S.evidenceIds).getD S.evidenceIds).length > maxRows ||
        S.conflictCount > maxRows) := by
      rw [hids, List.length_map, hSc]
      simp only [Bool.or_eq_true, decide_eq_true_eq, not_or, Nat.not_lt]
      exact ⟨hl, hC1⟩
    rw [if_neg h1]
    by_cases h2 : S.cash + (recordedPayment r.input c).amountCents + S.lawful > maxCents
    · rw [if_pos h2, if_neg]
      rw [hcash]; omega
    · rw [if_neg h2, if_pos]
      · have hcr : commitReceipts r.receipts ⟨ev, some (recordedPayment r.input c), none,
            some (recordedReceipt r.input c)⟩ = insertBy Receipt.paymentId (recordedReceipt r.input c) r.receipts := rfl
        rw [hcr]
        cases S with
        | mk rev cash claimed lawful contr lc dl cc eids reqs ab =>
          dsimp only at hScash hSe hSc hSctr hSreq hSab hcash hids
          subst hScash hSctr hSreq hSe hSc
          simp only [Option.some.injEq, ItemState.mk.injEq, true_and, and_true]
          refine ⟨?_, ?_, ?_, ?_⟩
          · rw [hcash]; omega
          · rw [contrib_insert _ _ _ hxact]; rfl
          · exact hids
          · rw [List.map_map]
            refine List.map_congr_left fun a _ => ?_
            have := paid_insert r.input (K := recordedReceipt r.input c) hnd hrec hxact rfl hpid a.actionId
            simp only [Function.comp]
            by_cases h : (recordedReceipt r.input c).paysActionId = some a.actionId <;> simp [h, this]
      · rw [hcash]; omega

end BlindLedger.Financial.Payment.Rev12
