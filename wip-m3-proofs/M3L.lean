import BlindLedger.Financial.Payment.Rev12
import M3K
open BlindLedger.Financial BlindLedger.Financial.Payment BlindLedger.Financial.CorrectionTransition
namespace BlindLedger.Financial.Payment.Rev12

theorem adv_rev (V : PaymentView) (S : ItemState) (e : EvidenceRecord) (p' q : Payment) (k : Receipt)
    (hb : V.byId = some (q, k)) :
    advance V S ⟨some e, some p', none, none⟩ =
      if (insertBy (fun x => x) e.evidenceId S.evidenceIds).length > maxRows || S.conflictCount > maxRows
      then none else
      some { S with
        evidenceIds := insertBy (fun x => x) e.evidenceId S.evidenceIds,
        anchorBytes := S.anchorBytes + anchorGrowth V ⟨some e, some p', none, none⟩,
        cash := S.cash - q.amountCents,
        contributions := S.contributions.erase ⟨q.eventAt, q.paymentId, q.amountCents⟩,
        requests := S.requests.map fun x =>
          if k.paysActionId = some x.actionId then { x with paidCents := x.paidCents - q.amountCents } else x } := by
  unfold advance
  simp only [hb]
  rfl

theorem enc_rev {p : Payment} (c : ReverseCommand) (h : p.reversalEvidenceId = none) :
    (encodePayment (reversedImage p c)).length = (encodePayment p).length + (encodeString c.evidenceId).length := by
  simp only [encodePayment, reversedImage, h, encodeOptionString, List.length_append, List.length_cons,
    List.length_singleton, List.length_nil]
  omega

theorem rep_map {P : List Payment} {new p : Payment} (hnd : (P.map Payment.paymentId).Nodup)
    (hp : findPayment P new.paymentId = some p) {β : Type} (f : Payment → β) (hf : f new = f p) :
    (P.map fun x => if x.paymentId = new.paymentId then new else x).map f = P.map f := by
  rw [List.map_map]
  refine List.map_congr_left fun x hx => ?_
  simp only [Function.comp]
  by_cases h : x.paymentId = new.paymentId
  · rw [if_pos h]
    have h1 := findPayment_of_mem hnd hx
    rw [h, hp] at h1
    rw [hf, ← Option.some.inj h1]
  · rw [if_neg h]

theorem rep_eq {P : List Payment} {new p q : Payment} (hnd : (P.map Payment.paymentId).Nodup)
    (hp : findPayment P new.paymentId = some p) (hq : q ∈ P) (h : q.paymentId = new.paymentId) : q = p := by
  have h1 := findPayment_of_mem hnd hq
  rw [h, hp] at h1
  exact (Option.some.inj h1).symm

theorem shape_reversed {r : PaymentRequest} {V : PaymentView} {S : ItemState}
    (hwf : financialInputWellFormed r.input = true)
    (hrec : r.receipts.map Receipt.paymentId = r.input.payments.map Payment.paymentId)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hS : summarize r.input r.receipts (anchorItemLength r.input r.receipts) = some S)
    (hVenv : V.env = envOf r.input)
    {c : ReverseCommand} (hc : commandWellFormed (.reverse c) = true)
    {p : Payment} {k : Receipt} (hp : findPayment r.input.payments c.paymentId = some p)
    (hk : receiptOf r.receipts p.paymentId = some k) (hbyId : V.byId = some (p, k))
    (hact : p.status ≠ .REVERSED) {time : Nat}
    (hfe : findEvidence r.input.evidence c.evidenceId = none)
    (hform : formRefusal (reversalRecord r.input c p time) = none) (htime : time ≤ r.input.evaluatedAt) :
    some (commitView V S .REVERSED ⟨some (reversalRecord r.input c p time), some (reversedImage p c), none, none⟩) =
      project r (mutate r .REVERSED ⟨some (reversalRecord r.input c p time), some (reversedImage p c), none, none⟩) := by
  let e := reversalRecord r.input c p time
  let new := reversedImage p c
  obtain ⟨hSe, hSc, hScash, hSle, hSctr, hSreq, hSab⟩ := S_facts hS
  obtain ⟨hP1, hE1, hC1, hPwf, hPew, hPrew, hNo, hcases⟩ := wf_facts hwf
  obtain ⟨hcP, hcE, hcC⟩ := wf_canon hwf
  obtain ⟨hid1, hid2, hnow⟩ := wf_ctx hwf
  have hnd := nodup_ids_of_wf hwf
  obtain ⟨hcid, hceid⟩ := cmd_reverse hc
  have hpc : p.paymentId = c.paymentId := findPayment_id _ _ _ hp
  have hp' : findPayment r.input.payments p.paymentId = some p := by rw [hpc]; exact hp
  have hpm := findPayment_mem hp
  have hpwf := hPwf p hpm
  have hpact : p.status = .ACTIVE := by
    cases h : p.status with
    | ACTIVE => rfl
    | REVERSED => exact absurd h hact
  have hpnone : p.reversalEvidenceId = none := by
    have := hPrew p hpm
    unfold reversalEvidenceWellFormed at this
    rw [hpact] at this
    cases h : p.reversalEvidenceId with
    | none => rfl
    | some _ => rw [h] at this; simp at this
  have hpitem : p.itemId = r.input.context.itemId := by
    simp only [paymentWellFormed, Bool.and_eq_true, decide_eq_true_eq, List.all_cons, List.all_nil,
      Bool.and_true] at hpwf
    exact hpwf.1.1.1.2
  have hnew : findPayment r.input.payments new.paymentId = some p := hp'
  have hnewst : new.status ≠ .ACTIVE := by simp [new, reversedImage]
  have hpost : applyWrites r.input ⟨some e, some new, none, none⟩ =
      upd r.input (r.input.payments.map fun x => if x.paymentId = new.paymentId then new else x)
        (insertBy EvidenceRecord.evidenceId e r.input.evidence) r.input.conflicts := by
    unfold applyWrites upd
    simp [hnew]
  have hfe' : findEvidence r.input.evidence e.evidenceId = none := hfe
  have hfe2 : findEvidence (insertBy EvidenceRecord.evidenceId e r.input.evidence) c.evidenceId = some e :=
    (findEvidence_insertBy hfe').trans (if_pos rfl)
  have hE : ∀ id x, findEvidence r.input.evidence id = some x →
      findEvidence (insertBy EvidenceRecord.evidenceId e r.input.evidence) id = some x := fun id x h => by
    rw [findEvidence_insertBy hfe']
    by_cases ee : e.evidenceId = id
    · subst ee; rw [hfe'] at h; cases h
    · rw [if_neg ee]; exact h
  have hfind : ∀ id, findPayment (r.input.payments.map fun x => if x.paymentId = new.paymentId then new else x) id =
      (findPayment r.input.payments id).map fun x => if x.paymentId = new.paymentId then new else x :=
    fun id => findPayment_replace _ new new rfl id
  have hwfpost : (insertBy EvidenceRecord.evidenceId e r.input.evidence).length ≤ maxRows →
      financialInputWellFormed (upd r.input (r.input.payments.map fun x => if x.paymentId = new.paymentId then new else x)
        (insertBy EvidenceRecord.evidenceId e r.input.evidence) r.input.conflicts) = true := fun hl => by
    refine wf_grow hwf hE (fun id q h => ?_) (fun id q h hr => ?_) (fun x hx => hx) hl hC1
      (fun _ => ?_) ?_ hcC ?_ ?_ ?_ (fun q hq hn => absurd hq hn)
    · have hq := findPayment_mem h
      have hid := findPayment_id _ _ _ h
      refine ⟨if q.paymentId = new.paymentId then new else q, by rw [hfind, h]; rfl, ?_⟩
      by_cases ee : q.paymentId = new.paymentId
      · rw [if_pos ee, rep_eq hnd hnew hq ee]; exact ⟨rfl, rfl, rfl⟩
      · rw [if_neg ee]; exact ⟨rfl, rfl, rfl⟩
    · have hq := findPayment_mem h
      rw [hfind, h]
      by_cases ee : q.paymentId = new.paymentId
      · have := rep_eq hnd hnew hq ee
        rw [this] at hr; exact absurd hr hact
      · simp [ee]
    · rw [List.map_map]
      have : (r.input.payments.map ((Payment.paymentId) ∘ fun x => if x.paymentId = new.paymentId then new else x)) =
          r.input.payments.map Payment.paymentId := by
        have := rep_map hnd hnew Payment.paymentId rfl
        rwa [List.map_map] at this
      rw [this]; exact hcP
    · have : (insertBy EvidenceRecord.evidenceId e r.input.evidence).map EvidenceRecord.evidenceId =
          insertBy (fun s => s) e.evidenceId (r.input.evidence.map EvidenceRecord.evidenceId) :=
        map_insertBy _ _ (fun s => s) (fun _ => rfl) e _
      rw [this]
      refine canonical_insert hcE hceid ?_ ?_
      · intro hm
        obtain ⟨x, hx⟩ := find_of_known (List.contains_iff_mem.2 hm)
        rw [hfe'] at hx; cases hx
      · rw [List.length_map]; rw [length_insertBy] at hl; omega
    · rw [noDup_iff]
      have := rep_map hnd hnew Payment.commonOriginId rfl
      rw [this]; exact (noDup_iff _).1 hNo
    · intro q hq hn
      rcases mem_replace hq with rfl | h
      · refine ⟨reversedImage_wf hpwf hc, ?_, ?_⟩
        · exact pew_mono (i := r.input) (j := upd r.input _ _ _) hE (hPew p hpm)
        · unfold reversalEvidenceWellFormed
          simp only [upd, new, reversedImage]
          rw [hfe2]
          simp [e, reversalRecord, hpitem]
      · exact absurd h hn
    · intro x hx hn
      rcases (mem_insertBy _ _ x _).1 hx with rfl | h
      · refine ⟨reversalRecord_wf ⟨hid1, hid2⟩ hnow hc hpwf hform htime, Nat.le_refl _, ?_⟩
        unfold accLam
        rw [if_neg (by simp [e, reversalRecord]), if_pos (by simp [e, reversalRecord])]
        unfold reversalEvidenceAccounted
        simp only [e, reversalRecord, upd]
        rw [hfind, hp']
        simp [new, reversedImage, hpitem]
      · exact absurd h hn
  have hold : oldPay r.input ⟨some e, some new, none, none⟩ = (encodePayment p).length := by
    simp [oldPay, new, reversedImage, hp']
  have hnewp : newPay ⟨some e, some new, none, none⟩ = (encodePayment new).length := by simp [newPay]
  have hlenle : (encodePayment new).length = (encodePayment p).length + (encodeString c.evidenceId).length :=
    enc_rev c hpnone
  have hrep := activeCents_replace hnd hnew hpact hnewst
  refine commit_core hb hS hVenv ?_ ?_ hcases ?_ ?_
  · unfold anchorGrowth addedBytes
    rw [hold, hbyId]
    simp [hnewp, receiptBytes]
  · have := rawEncode_applyWrites_core r.input ⟨some e, some new, none, none⟩ (fun q hq hs => hnd)
    unfold addedBytes
    rw [hold, hnewp] at this ⊢
    simp only [e, new] at this hlenle ⊢
    omega
  · intro s' h
    rw [hpost]
    rw [adv_rev V S e new p k hbyId] at h
    by_cases h1 : (insertBy (fun x => x) e.evidenceId S.evidenceIds).length > maxRows || S.conflictCount > maxRows
    · rw [if_pos h1] at h; cases h
    · rw [hSe] at h1
      simp only [length_insertBy, List.length_map, Bool.or_eq_true, decide_eq_true_eq, not_or, Nat.not_lt] at h1
      exact hwfpost (by rw [length_insertBy]; exact h1.1)
  · intro hw
    rw [hpost] at hw ⊢
    have hl := (wf_facts hw).2.1
    simp only [upd, length_insertBy] at hl
    rw [summarize_upd hS, adv_rev V S e new p k hbyId]
    have h1 : ¬ ((insertBy (fun x => x) e.evidenceId S.evidenceIds).length > maxRows || S.conflictCount > maxRows) := by
      rw [hSe, hSc]
      simp only [length_insertBy, List.length_map, Bool.or_eq_true, decide_eq_true_eq, not_or, Nat.not_lt]
      exact ⟨hl, hC1⟩
    have hcr : commitReceipts r.receipts ⟨some (reversalRecord r.input c p time), some (reversedImage p c), none, none⟩ = r.receipts := rfl
    rw [hcr, if_neg h1, if_pos (by omega)]
    cases S with
    | mk rev cash claimed lawful contr lc dl cc eids reqs ab =>
      dsimp only at hScash hSe hSc hSctr hSreq hSab hl
      subst hScash hSctr hSreq hSe hSc
      simp only [Option.some.injEq, ItemState.mk.injEq, true_and, and_true]
      refine ⟨?_, ?_, ?_, ?_, rfl⟩
      · omega
      · exact (contrib_replace _ _ new p hnewst hnd hnew hpact).symm
      · exact (map_insertBy _ _ (fun s => s) (fun _ => rfl) e _).symm
      · rw [List.map_map]
        refine List.map_congr_left fun a _ => ?_
        have := paid_replace r.input hnd hrec hnew hpact hnewst hk a.actionId
        simp only [Function.comp]
        by_cases h : k.paysActionId = some a.actionId
        · rw [if_pos h] at this
          simp only [if_pos h, RequestPaid.mk.injEq, eq_self, true_and]; omega
        · rw [if_neg h] at this
          simp only [if_neg h, RequestPaid.mk.injEq, eq_self, true_and]; omega

end BlindLedger.Financial.Payment.Rev12
