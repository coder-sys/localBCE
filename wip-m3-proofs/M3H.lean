import BlindLedger.Financial.Payment.Rev12
import M3G
open BlindLedger.Financial BlindLedger.Financial.Payment BlindLedger.Financial.CorrectionTransition
namespace BlindLedger.Financial.Payment.Rev12

/-! ## Paid totals under insert and replace (the `step_bridge` sums, on bare lists) -/

theorem paid_eq (i0 : FinancialInput) {P : List Payment} {R : List Receipt}
    (hn : (P.map Payment.paymentId).Nodup) (hR : R.map Receipt.paymentId = P.map Payment.paymentId)
    (a : String) : linkedActivePaidCents P (linksOf R) a = (P.map (paidOn R a)).sum :=
  ledgerPaid_eq (L := ⟨{ i0 with payments := P }, R⟩) ⟨hn, hR⟩ a

theorem ids_insert {x : Payment} {P : List Payment} :
    (insertBy Payment.paymentId x P).map Payment.paymentId = insertBy (fun s => s) x.paymentId (P.map Payment.paymentId) :=
  map_insertBy Payment.paymentId Payment.paymentId (fun s => s) (fun _ => rfl) x P

theorem ids_insert_nodup {x : Payment} {P : List Payment} (hn : (P.map Payment.paymentId).Nodup)
    (hf : findPayment P x.paymentId = none) :
    ((insertBy Payment.paymentId x P).map Payment.paymentId).Nodup := by
  have hp := (insertBy_perm Payment.paymentId x P).map Payment.paymentId
  rw [hp.nodup_iff, List.map_cons, List.nodup_cons]
  exact ⟨fun h => let ⟨q, hq, e⟩ := List.mem_map.1 h; findPayment_none_ne hf q hq e, hn⟩

theorem paid_insert (i0 : FinancialInput) {P : List Payment} {R : List Receipt}
    (hn : (P.map Payment.paymentId).Nodup) (hR : R.map Receipt.paymentId = P.map Payment.paymentId)
    {x : Payment} {K : Receipt} (hx : x.status = .ACTIVE) (hid : K.paymentId = x.paymentId)
    (hf : findPayment P x.paymentId = none) (a : String) :
    linkedActivePaidCents (insertBy Payment.paymentId x P) (linksOf (insertBy Receipt.paymentId K R)) a =
      linkedActivePaidCents P (linksOf R) a + (if K.paysActionId = some a then x.amountCents else 0) := by
  have hrn : receiptOf R K.paymentId = none := by
    rw [hid]; exact receiptOf_none (L := ⟨{ i0 with payments := P }, R⟩) ⟨hn, hR⟩ hf
  have hR' : (insertBy Receipt.paymentId K R).map Receipt.paymentId =
      (insertBy Payment.paymentId x P).map Payment.paymentId := by
    rw [ids_insert, map_insertBy Receipt.paymentId Receipt.paymentId (fun s => s) (fun _ => rfl) K R, hR, hid]
  rw [paid_eq i0 (ids_insert_nodup hn hf) hR', paid_eq i0 hn hR, sum_insertBy]
  have hne : ∀ q ∈ P, q.paymentId ≠ x.paymentId := findPayment_none_ne hf
  have hcongr : P.map (paidOn (insertBy Receipt.paymentId K R) a) = P.map (paidOn R a) :=
    List.map_congr_left fun q hq => by
      simp only [paidOn, receiptOf_insertBy hrn, if_neg (fun e : K.paymentId = q.paymentId =>
        hne q hq (e.symm.trans hid))]
  have hP : paidOn (insertBy Receipt.paymentId K R) a x = if K.paysActionId = some a then x.amountCents else 0 := by
    simp only [paidOn, receiptOf_insertBy hrn, hid, if_true, hx]
    by_cases h : K.paysActionId = some a <;> simp [h]
  rw [hcongr, hP]; omega

theorem paid_replace (i0 : FinancialInput) {P : List Payment} {R : List Receipt}
    (hn : (P.map Payment.paymentId).Nodup) (hR : R.map Receipt.paymentId = P.map Payment.paymentId)
    {q p0 : Payment} (hq : findPayment P p0.paymentId = some q) (hact : q.status = .ACTIVE)
    (hp0 : p0.status ≠ .ACTIVE) {k : Receipt} (hk : receiptOf R q.paymentId = some k) (a : String) :
    linkedActivePaidCents (P.map fun x => if x.paymentId = p0.paymentId then p0 else x) (linksOf R) a +
      (if k.paysActionId = some a then q.amountCents else 0) = linkedActivePaidCents P (linksOf R) a := by
  have hids : (P.map fun x => if x.paymentId = p0.paymentId then p0 else x).map Payment.paymentId =
      P.map Payment.paymentId := by
    rw [List.map_map]
    refine List.map_congr_left fun x _ => ?_
    simp only [Function.comp]
    by_cases h : x.paymentId = p0.paymentId <;> simp [h]
  rw [paid_eq i0 (hids ▸ hn) (hR.trans hids.symm), paid_eq i0 hn hR]
  have hs := sum_replace (paidOn R a) p0 P q hn hq
  have e1 : paidOn R a q = if k.paysActionId = some a then q.amountCents else 0 := by
    simp [paidOn, hk, hact]
  have e2 : paidOn R a p0 = 0 := by simp [paidOn, hp0]
  rw [e1, e2] at hs
  omega

/-! ## The summary of a grown input -/

theorem cash_eq {i : FinancialInput} {rs b S} (h : summarize i rs b = some S) :
    S.cash = activeCents i.payments := by
  obtain ⟨t, ht, rfl⟩ := summarize_some h
  have := evaluateTotals_payments ht i.payments
  have e : ({ i with payments := i.payments } : FinancialInput) = i := rfl
  rw [e, ht] at this
  by_cases hc : activeCents i.payments + t.lawful ≤ maxCents
  · rw [if_pos hc] at this
    simp only [Option.some.injEq] at this
    have := congrArg EvaluatedTotals.cash this
    exact this
  · rw [if_neg hc] at this; cases this

theorem summarize_upd {i : FinancialInput} {rs b0 S} (hS : summarize i rs b0 = some S)
    (P : List Payment) (E : List EvidenceRecord) (C : List FinancialConflict) (rs' : List Receipt) (b : Nat) :
    summarize (upd i P E C) rs' b =
      if activeCents P + S.lawful ≤ maxCents then
        some { S with
          cash := activeCents P,
          contributions := evalSortContributions (pcOf P ++ dcOf i.determinations),
          conflictCount := C.length, evidenceIds := E.map EvidenceRecord.evidenceId,
          requests := ((i.actions.filter (·.kind = "CORRECTION_PAYMENT_REQUEST")).map fun a =>
            ⟨a.actionId, a.amountCents, linkedActivePaidCents P (linksOf rs') a.actionId⟩),
          anchorBytes := b }
      else none := by
  obtain ⟨t, ht, rfl⟩ := summarize_some hS
  have e : evaluateTotals (upd i P E C) = evaluateTotals { i with payments := P } := rfl
  unfold summarize
  rw [e, evaluateTotals_payments ht P]
  by_cases hc : activeCents P + t.lawful ≤ maxCents
  · rw [if_pos hc, if_pos hc]; rfl
  · rw [if_neg hc, if_neg hc]; rfl

theorem activeCents_insert {x : Payment} (hx : x.status = .ACTIVE) (P : List Payment) :
    activeCents (insertBy Payment.paymentId x P) = x.amountCents + activeCents P := by
  rw [activeCents_eq, activeCents_eq, sum_insertBy, if_pos hx]

theorem activeCents_replace {P : List Payment} {q p0 : Payment} (hn : (P.map Payment.paymentId).Nodup)
    (hq : findPayment P p0.paymentId = some q) (hact : q.status = .ACTIVE) (hp0 : p0.status ≠ .ACTIVE) :
    activeCents (P.map fun x => if x.paymentId = p0.paymentId then p0 else x) + q.amountCents =
      activeCents P := by
  have := sum_replace (fun x : Payment => if x.status = .ACTIVE then x.amountCents else 0) p0 P q hn hq
  rw [activeCents_eq, activeCents_eq]
  simp only [if_pos hact, if_neg hp0] at this
  omega

end BlindLedger.Financial.Payment.Rev12
