import BlindLedger.Financial.Payment.Base
import BlindLedger.Financial.Payment.OpenLaws
import BlindLedger.Financial.CorrectionTransition.PaidSumTheorems
import BlindLedger.Financial.CodecLaws.CorrectionRecords

namespace BlindLedger.Financial.Payment

open BlindLedger.Financial BlindLedger.Financial.CorrectionTransition

/-! One transition (design 5.2).  Nothing here is called by the worker yet. -/

/-! ## Well-formedness facts -/

private theorem hist_mono {i : FinancialInput} {b : Nat} {x : OffsetDetermination}
    (h : determinationHistoryWellFormed i x = true) (hle : i.beforeRevision ≤ b) :
    determinationHistoryWellFormed { i with beforeRevision := b } x = true := by
  simp only [determinationHistoryWellFormed, Bool.and_eq_true, decide_eq_true_eq] at h ⊢
  omega

private theorem wfDet_hist {i : FinancialInput} {x : OffsetDetermination}
    (h : determinationWellFormed i x = true) : determinationHistoryWellFormed i x = true := by
  simp only [determinationWellFormed, Bool.and_eq_true] at h
  simp only [h]

private theorem wfDet_setRevision {i : FinancialInput} {b : Nat} {x : OffsetDetermination}
    (h : determinationWellFormed i x = true) (hle : i.beforeRevision ≤ b) :
    determinationWellFormed { i with beforeRevision := b } x = determinationWellFormed i x := by
  have h1 := wfDet_hist h
  have h2 := hist_mono h1 hle
  unfold determinationWellFormed
  rw [h1, h2]
  rfl

theorem wf_setRevision {i : FinancialInput} {b : Nat} (h : financialInputWellFormed i = true)
    (hle : i.beforeRevision ≤ b) (hb : b < maxRevision) :
    financialInputWellFormed { i with beforeRevision := b } = true := by
  have e : financialInputWellFormed { i with beforeRevision := b } = financialInputWellFormed i := by
    have henvi : envWellFormed (envOf i) = true := by
      simp only [financialInputWellFormed, Bool.and_eq_true, and_assoc] at h
      exact h.1
    have hd : i.determinations.all (determinationWellFormed i) = true := by
      simp only [financialInputWellFormed, Bool.and_eq_true, and_assoc] at h
      grind
    have hdet : i.determinations.all (determinationWellFormed { i with beforeRevision := b }) =
        i.determinations.all (determinationWellFormed i) := by
      apply Bool.eq_iff_iff.2
      simp only [List.all_eq_true]
      constructor <;> intro hh x hx
      · rw [← wfDet_setRevision (List.all_eq_true.1 hd x hx) hle]; exact hh x hx
      · rw [wfDet_setRevision (List.all_eq_true.1 hd x hx) hle]; exact hh x hx
    have h6' : revisionWellFormed b = true := by
      simp only [revisionWellFormed, decide_eq_true_eq]; omega
    have henv : envWellFormed (envOf { i with beforeRevision := b }) = envWellFormed (envOf i) := by
      rw [henvi]
      simp only [envWellFormed, envOf, Bool.and_eq_true, decide_eq_true_eq] at henvi ⊢
      grind
    simp only [financialInputWellFormed, henv, hdet]
    rfl
  rw [e]; exact h

/-! ## Shapes of a mutated outcome -/

namespace Base

theorem mutate_eq {r k w k' w' post res} (h : mutate r k w = .mutated k' w' post res) :
    k' = k ∧ w' = w ∧ post = applyWrites r.input w ∧ evaluate post = some res ∧
      withinCapacity r w = true := by
  unfold mutate at h
  by_cases hc : withinCapacity r w = true
  · simp only [hc, Bool.not_true, Bool.false_eq_true, ↓reduceIte] at h
    cases he : evaluate (applyWrites r.input w) with
    | none => simp [he] at h
    | some result =>
        simp only [he] at h
        cases h
        exact ⟨rfl, rfl, rfl, he, hc⟩
  · simp [hc] at h

end Base

theorem slot_fresh {r e} (h : evidenceSlot r e = .fresh) :
    findEvidence r.input.evidence e.evidenceId = none ∧ r.foreign.evidenceId = false := by
  unfold evidenceSlot slotOf at h
  by_cases hf : r.foreign.evidenceId = true
  · simp [hf] at h
  · simp only [hf, Bool.false_eq_true, ↓reduceIte] at h
    cases hs : findEvidence r.input.evidence e.evidenceId with
    | none => exact ⟨rfl, by simpa using hf⟩
    | some s => simp only [hs] at h; split at h <;> simp at h

namespace Base

theorem decideReverse_mutated {r c k w post res}
    (h : decideReverse r c = .mutated k w post res) :
    ∃ p e, k = .REVERSED ∧ findPayment r.input.payments c.paymentId = some p ∧
      p.status ≠ .REVERSED ∧
      w = ⟨some e, some (reversedImage p c), none, none⟩ ∧
      mutate r .REVERSED w = .mutated .REVERSED w post res ∧
      e = reversalRecord r.input c p (c.eventAt.getD r.input.evaluatedAt) ∧
      findEvidence r.input.evidence c.evidenceId = none ∧
      e.eventAt ≤ r.input.evaluatedAt ∧ formRefusal e = none := by
  unfold decideReverse at h
  cases hp : findPayment r.input.payments c.paymentId with
  | none => simp [hp] at h
  | some p =>
    simp only [hp] at h
    by_cases hf : r.foreign.evidenceId = true
    · simp [hf] at h
    · simp only [hf, Bool.false_eq_true, ↓reduceIte] at h
      split at h
      · simp at h
      · rename_i hform
        split at h
        · simp at h
        · rename_i hchron
          split at h
          · simp at h
          · simp at h
          · rename_i hslot
            split at h
            · simp at h
            · split at h
              · simp at h
              · rename_i hst
                have hfe : findEvidence r.input.evidence c.evidenceId = none := (slot_fresh hslot).1
                simp only [hfe, Option.map_none, Option.getD_none] at h hform hchron
                obtain ⟨rfl, rfl, -, -, -⟩ := mutate_eq h
                exact ⟨p, _, rfl, rfl, hst, rfl, h, rfl, hfe, by simpa [reversalRecord] using hchron, hform⟩

end Base

theorem slot_cases {r e} (h : evidenceSlot r e ≠ .clash) :
    r.foreign.evidenceId = false ∧
      ((evidenceSlot r e = .fresh ∧ findEvidence r.input.evidence e.evidenceId = none) ∨
       ∃ s, evidenceSlot r e = .same s ∧ findEvidence r.input.evidence e.evidenceId = some s ∧
         e.eventAt ≤ s.receivedAt ∧ { e with receivedAt := s.receivedAt } = s) := by
  unfold evidenceSlot slotOf at h ⊢
  by_cases hf : r.foreign.evidenceId = true
  · simp [hf] at h
  · simp only [hf, Bool.false_eq_true, ↓reduceIte] at h ⊢
    refine ⟨by simp, ?_⟩
    cases hs : findEvidence r.input.evidence e.evidenceId with
    | none => simp
    | some s =>
        simp only [hs] at h ⊢
        by_cases hc : e.eventAt ≤ s.receivedAt ∧ { e with receivedAt := s.receivedAt } = s
        · simp only [hc, and_self, ↓reduceIte]
          exact Or.inr ⟨s, rfl, rfl, hc⟩
        · simp [hc] at h

/-- The evidence a record writes: the fresh row, or nothing because the stored row is the
    same record.  Either way the stored row is the confirmation at its own received time. -/
def EvidenceWrite (r : PaymentRequest) (c : RecordCommand) (ev : Option EvidenceRecord) : Prop :=
  formRefusal (confirmation r.input c r.input.evaluatedAt) = none ∧
  c.eventAt ≤ r.input.evaluatedAt ∧ r.foreign.evidenceId = false ∧
  ((ev = some (confirmation r.input c r.input.evaluatedAt) ∧
      findEvidence r.input.evidence c.evidenceId = none) ∨
   (ev = none ∧ ∃ s, findEvidence r.input.evidence c.evidenceId = some s ∧
      c.eventAt ≤ s.receivedAt ∧ confirmation r.input c s.receivedAt = s))

theorem evidenceWrite_of_slot {r c slot}
    (hform : formRefusal (confirmation r.input c r.input.evaluatedAt) = none)
    (hchron : c.eventAt ≤ r.input.evaluatedAt)
    (hslot : evidenceSlot r (confirmation r.input c r.input.evaluatedAt) = slot)
    (hne : slot ≠ .clash) :
    EvidenceWrite r c (if slot.isFresh then some (confirmation r.input c r.input.evaluatedAt)
      else none) := by
  subst hslot
  obtain ⟨hf, hs⟩ := slot_cases hne
  refine ⟨hform, hchron, hf, ?_⟩
  rcases hs with ⟨hs, hfe⟩ | ⟨s, hs, hfe, hle, heq⟩
  · rw [hs]; exact Or.inl ⟨rfl, hfe⟩
  · rw [hs]; exact Or.inr ⟨rfl, s, hfe, hle, heq⟩

namespace Base

theorem aliasOf_ne_mutated {r pid e k w post res} : aliasOf r pid e ≠ .mutated k w post res := by
  unfold aliasOf
  dsimp only
  split
  · simp
  · split <;> simp

theorem alias_or_dup_ne {f : Bool} {r pid e k w post res} :
    (if f = true then aliasOf r pid e else PaymentOutcome.duplicate (some pid)) ≠
      .mutated k w post res := by
  cases f <;> simp [aliasOf_ne_mutated]

theorem recordNew_mutated {r c k w post res} (h : recordNew r c = .mutated k w post res) :
    mutate r k w = .mutated k w post res ∧ revisionOk r = true ∧ EvidenceWrite r c w.evidence ∧
    ((k = .RECORDED ∧ (∀ q ∈ r.input.payments, q.commonOriginId ≠ c.commonOriginId) ∧
        w.payment = some (recordedPayment r.input c) ∧ w.receipt = some (recordedReceipt r.input c) ∧
        w.conflict = none ∧ ∀ a, c.paysActionId = some a → ∃ x ∈ r.input.actions,
          x.actionId = a ∧ x.kind = "CORRECTION_PAYMENT_REQUEST" ∧
          linkedActivePaidCents r.input.payments (linksOf r.receipts) a + c.amountCents ≤
            x.amountCents) ∨
     (k = .CONFLICT_RECORDED ∧ ∃ p ∈ r.input.payments, p.commonOriginId = c.commonOriginId ∧
        p.amountCents ≠ c.amountCents ∧ w.payment = none ∧ w.receipt = none ∧
        w.conflict = some (conflictImage r.input c p
          ("conflict:" ++ r.input.context.itemId ++ ":" ++ c.commonOriginId ++ ":" ++ c.evidenceId)))) := by
  unfold recordNew at h
  dsimp only at h
  generalize hex : r.input.payments.find? (·.commonOriginId = c.commonOriginId) = existing at h
  generalize hsame : existing.any (·.amountCents = c.amountCents) = same at h
  generalize hprior : (same && ((findEvidence r.input.evidence c.evidenceId).isSome ||
    r.foreign.evidenceId)) = prior at h
  generalize hrecv : (if prior = true then
    ((findEvidence r.input.evidence c.evidenceId).map (·.receivedAt)).getD r.input.evaluatedAt
    else r.input.evaluatedAt) = receivedAt at h
  split at h
  · simp at h
  split at h
  · simp at h
  rename_i hC0 hC1
  split at h
  · simp at h
  rename_i hC2
  split at h
  · simp at h
  rename_i hC3
  split at h
  · simp at h
  rename_i hform
  split at h
  · simp at h
  rename_i hchron
  have hne : evidenceSlot r (confirmation r.input c receivedAt) ≠ .clash := by
    intro hc; simp only [hc] at h; simp at h
  generalize hslot : evidenceSlot r (confirmation r.input c receivedAt) = slot at h hne
  have hchron' : c.eventAt ≤ receivedAt := Nat.le_of_not_lt hchron
  cases slot
  case clash => exact absurd rfl hne
  all_goals
    dsimp only [Slot.isFresh] at h
    cases existing with
    | none =>
      dsimp only at h
      simp only [Option.any_none] at hsame
      subst hsame
      simp only [Bool.false_and] at hprior
      subst hprior
      simp only [Bool.false_eq_true, ↓reduceIte] at hrecv
      subst hrecv
      have hrev : revisionOk r = true := by simpa using hC2
      split at h
      · simp at h
      rename_i hlink
      obtain ⟨rfl, rfl, -, -, -⟩ := mutate_eq h
      refine ⟨h, hrev, by simpa [Slot.isFresh] using evidenceWrite_of_slot hform hchron' hslot hne,
        Or.inl ⟨rfl, fun q hq => ?_, rfl, rfl, rfl, fun a ha => ?_⟩⟩
      · simpa using List.find?_eq_none.1 hex q hq
      · rw [ha] at hlink
        simp only [Option.bind_some] at hlink
        split at hlink
        · simp at hlink
        · rename_i req hreq
          split at hlink
          · simp at hlink
          · rename_i hle
            have hk := List.find?_some hreq
            simp only [Bool.and_eq_true, decide_eq_true_eq] at hk
            exact ⟨req, List.mem_of_find?_eq_some hreq, hk.1, hk.2, Nat.le_of_not_lt hle⟩
    | some p =>
      dsimp only at h
      split at h
      · split at h
        · simp at h
        · exact absurd h alias_or_dup_ne
      · rename_i hsm
        have hsf : same = false := by simpa using hsm
        subst hsf
        simp only [Bool.false_and] at hprior
        subst hprior
        simp only [Bool.false_eq_true, ↓reduceIte] at hrecv
        subst hrecv
        have hrev : revisionOk r = true := by simpa using hC2
        split at h
        · simp at h
        split at h
        · simp at h
        obtain ⟨rfl, rfl, -, -, -⟩ := mutate_eq h
        have hp := List.find?_some hex
        simp only [decide_eq_true_eq] at hp
        simp only [Option.any_some, decide_eq_false_iff_not] at hsame
        exact ⟨h, hrev, by simpa [Slot.isFresh] using evidenceWrite_of_slot hform hchron' hslot hne,
          Or.inr ⟨rfl, p, List.mem_of_find?_eq_some hex, hp, hsame, rfl, rfl, rfl⟩⟩

end Base

/-- Outcomes that write nothing and return no post-state. -/
def PaymentOutcome.Plain : PaymentOutcome → Prop
  | .duplicate _ | .conflictUnchanged _ | .refused _ => True
  | _ => False

theorem recordRetry_plain (r c p) : (recordRetry r c p).Plain := by
  unfold recordRetry
  cases hf : findEvidence r.input.evidence c.evidenceId with
  | none => simp [hf, PaymentOutcome.Plain]
  | some s =>
    simp only [hf]
    cases hr : formRefusal (confirmation r.input c s.receivedAt) with
    | some f => simp [hr, PaymentOutcome.Plain]
    | none =>
      simp only [hr]
      split
      · simp [PaymentOutcome.Plain]
      · cases hk : receiptOf r.receipts p.paymentId with
        | none => simp [hk, PaymentOutcome.Plain]
        | some k' => simp only [hk]; split <;> simp [PaymentOutcome.Plain]

namespace Base

theorem decideRecord_mutated {r c k w post res} (h : decideRecord r c = .mutated k w post res) :
    findPayment r.input.payments c.paymentId = none ∧ recordNew r c = .mutated k w post res := by
  unfold decideRecord at h
  split at h
  · simp at h
  split at h
  · simp at h
  cases hp : findPayment r.input.payments c.paymentId with
  | none => simp only [hp] at h; exact ⟨rfl, h⟩
  | some p =>
    simp only [hp] at h
    have := recordRetry_plain r c p
    simp [h, PaymentOutcome.Plain] at this

theorem paymentTransition_cases {r k w post res}
    (h : paymentTransition r = .mutated k w post res) :
    (∃ c, r.command = .record c ∧ decideRecord r c = .mutated k w post res) ∨
    (∃ c, r.command = .reverse c ∧ decideReverse r c = .mutated k w post res) := by
  unfold paymentTransition at h
  cases hc : r.command with
  | record c => simp only [hc] at h; exact Or.inl ⟨c, rfl, h⟩
  | reverse c => simp only [hc] at h; exact Or.inr ⟨c, rfl, h⟩

theorem mutate_of_transition {r k w post res} (h : paymentTransition r = .mutated k w post res) :
    mutate r k w = .mutated k w post res := by
  rcases paymentTransition_cases h with ⟨c, -, hd⟩ | ⟨c, -, hd⟩
  · exact (recordNew_mutated (decideRecord_mutated hd).2).1
  · obtain ⟨p, e, rfl, -, -, -, hm, -⟩ := decideReverse_mutated hd
    exact hm

/-! ## Growth of `applyWrites` under BLFIN02 -/

end Base

theorem length_encodeList {α} (enc : α → Bytes) (l : List α) :
    (encodeList enc l).length = 2 + (l.map fun x => (enc x).length).sum := by
  simp [encodeList, length_natBE, List.length_flatMap]

theorem sum_insertBy {α} (key : α → String) (g : α → Nat) (row : α) :
    ∀ l : List α, ((insertBy key row l).map g).sum = g row + (l.map g).sum
  | [] => by simp [insertBy]
  | x :: xs => by
      unfold insertBy
      split
      · simp only [List.map_cons, List.sum_cons]
      · simp only [List.map_cons, List.sum_cons, sum_insertBy key g row xs]; omega

theorem sum_replace (g : Payment → Nat) (p : Payment) :
    ∀ (l : List Payment) (q : Payment), (l.map Payment.paymentId).Nodup →
      findPayment l p.paymentId = some q →
      ((l.map fun x => if x.paymentId = p.paymentId then p else x).map g).sum + g q =
        (l.map g).sum + g p
  | [], q, _, h => by simp [findPayment] at h
  | x :: xs, q, hn, h => by
      rw [List.map_cons, List.nodup_cons] at hn
      by_cases hx : x.paymentId = p.paymentId
      · simp only [findPayment, hx, ↓reduceIte, Option.some.injEq] at h
        subst h
        have hid : xs.map (fun y => if y.paymentId = p.paymentId then p else y) = xs := by
          refine (List.map_congr_left (g := id) fun y hy => ?_).trans (List.map_id _)
          have hy' : y.paymentId ≠ p.paymentId := fun e =>
            hn.1 (List.mem_map.2 ⟨y, hy, e.trans hx.symm⟩)
          simp [hy']
        simp only [List.map_cons, List.sum_cons, hx, ↓reduceIte, hid]
        omega
      · simp only [findPayment, hx, ↓reduceIte] at h
        have := sum_replace g p xs q hn.2 h
        simp only [List.map_cons, List.sum_cons, hx, ↓reduceIte]
        omega

theorem rawEncode_applyWrites_core (i : FinancialInput) (w : Writes)
    (hp : ∀ p, w.payment = some p → (findPayment i.payments p.paymentId).isSome = true →
      (i.payments.map Payment.paymentId).Nodup) :
    (rawEncodeFinancialInput (applyWrites i w)).length + oldPay i w =
      (rawEncodeFinancialInput i).length + evBytes w + newPay w + cfBytes w := by
  have hev : (encodeList encodeEvidence (applyWrites i w).evidence).length =
      (encodeList encodeEvidence i.evidence).length + evBytes w := by
    cases he : w.evidence <;> simp [applyWrites, evBytes, he, length_encodeList, sum_insertBy] <;> omega
  have hcf : (encodeList encodeConflict (applyWrites i w).conflicts).length =
      (encodeList encodeConflict i.conflicts).length + cfBytes w := by
    cases hc : w.conflict <;> simp [applyWrites, cfBytes, hc, length_encodeList, sum_insertBy] <;> omega
  have hpay : (encodeList encodePayment (applyWrites i w).payments).length + oldPay i w =
      (encodeList encodePayment i.payments).length + newPay w := by
    cases hw : w.payment with
    | none => simp [applyWrites, oldPay, newPay, hw]
    | some p =>
      cases hf : findPayment i.payments p.paymentId with
      | none =>
        simp [applyWrites, oldPay, newPay, hw, hf, length_encodeList, sum_insertBy]; omega
      | some q =>
        have := sum_replace (fun x => (encodePayment x).length) p i.payments q
          (hp p hw (by simp [hf])) hf
        simp only [applyWrites, oldPay, newPay, hw, hf, length_encodeList, List.map_map] at this ⊢
        simp [hf]
        omega
  simp only [rawEncodeFinancialInput, List.length_append]
  simp only [applyWrites] at hev hcf hpay ⊢
  omega

theorem rawEncode_applyWrites_length (i : FinancialInput) (w : Writes)
    (hfresh : ∀ p, w.payment = some p → findPayment i.payments p.paymentId = none) :
    (rawEncodeFinancialInput (applyWrites i w)).length =
      (rawEncodeFinancialInput i).length + addedBytes i w := by
  have hold : oldPay i w = 0 := by
    cases hw : w.payment with
    | none => simp [oldPay, hw]
    | some p => simp [oldPay, hw, hfresh p hw]
  have := rawEncode_applyWrites_core i w fun p hp hs => by simp [hfresh p hp] at hs
  unfold addedBytes
  omega

theorem nodup_ids_of_wf {i : FinancialInput} (hwf : financialInputWellFormed i = true) :
    (i.payments.map Payment.paymentId).Nodup := by
  have h1 : canonicalIdList (i.payments.map Payment.paymentId) = true := by
    simp only [financialInputWellFormed, Bool.and_eq_true, decide_eq_true_eq] at hwf
    simp only [hwf]
  exact (canonical_facts h1).2.2.imp fun {a b} h e => by subst e; exact String.lt_irrefl _ h

theorem ids_replace {i w p} (hw : w.payment = some p)
    (hs : (findPayment i.payments p.paymentId).isSome = true) :
    (applyWrites i w).payments.map Payment.paymentId = i.payments.map Payment.paymentId := by
  simp only [applyWrites, hw, hs, ↓reduceIte, List.map_map]
  refine List.map_congr_left fun q _ => ?_
  simp only [Function.comp]
  split <;> simp_all

theorem payments_nodup_of_replace {i w p}
    (hwf : financialInputWellFormed (applyWrites i w) = true) (hw : w.payment = some p)
    (hs : (findPayment i.payments p.paymentId).isSome = true) :
    (i.payments.map Payment.paymentId).Nodup := by
  rw [← ids_replace hw hs]; exact nodup_ids_of_wf hwf

/-! ## The one-transition theorems (design 5.2) -/

theorem evaluate_facts {i res} (h : evaluate i = some res) :
    financialInputWellFormed i = true ∧ res.beforeRevision = i.beforeRevision ∧
    res.evidenceIds = i.evidence.map EvidenceRecord.evidenceId ∧
    res.receivedCashCents = activeCents i.payments := by
  unfold evaluate at h
  split at h
  · rename_i hw
    unfold evaluateWellFormed evaluateTotals at h
    cases hc : evalPaymentSum i.payments with
    | none => simp [hc] at h
    | some cash =>
      cases hcl : evalClaimedSum i.claims with
      | none => simp [hc, hcl] at h
      | some cl =>
        cases hl : evalLawfulSum i.claims with
        | none => simp [hc, hcl, hl] at h
        | some la =>
          cases ht : evalAdd cash la with
          | none => simp [hc, hcl, hl, ht] at h
          | some t =>
            simp only [hc, hcl, hl, ht, Option.map_some, Option.some.injEq] at h
            subst h
            exact ⟨hw, rfl, rfl, ((evalPaymentSum_active _ _ hc).1).symm⟩
  · simp at h

namespace Base

theorem paymentTransition_mutated_post {r : PaymentRequest} {k w post result}
    (h : paymentTransition r = .mutated k w post result) :
    post = applyWrites r.input w ∧ financialInputWellFormed post = true ∧
    evaluate post = some result ∧ result.beforeRevision = r.input.beforeRevision ∧
    result.evidenceIds = post.evidence.map EvidenceRecord.evidenceId ∧
    (r.inputBytes = (rawEncodeFinancialInput r.input).length →
      (rawEncodeFinancialInput post).length ≤ maxTotalEncodedBytes) := by
  obtain ⟨-, -, hpost, hev, hcap⟩ := mutate_eq (mutate_of_transition h)
  obtain ⟨hwf, hb, hids, -⟩ := evaluate_facts hev
  refine ⟨hpost, hwf, hev, by rw [hb, hpost]; rfl, hids, fun hbytes => ?_⟩
  have hp : ∀ p, w.payment = some p → (findPayment r.input.payments p.paymentId).isSome = true →
      (r.input.payments.map Payment.paymentId).Nodup := fun p hw hs =>
    payments_nodup_of_replace (hpost ▸ hwf) hw hs
  have := rawEncode_applyWrites_core r.input w hp
  have hcap' := of_decide_eq_true (by simpa only [withinCapacity, addedBytes] using hcap)
  rw [hpost]
  omega

theorem paymentTransition_result_cash {r k w post result}
    (h : paymentTransition r = .mutated k w post result) :
    result.receivedCashCents = activeCents post.payments :=
  (evaluate_facts (mutate_eq (mutate_of_transition h)).2.2.2.1).2.2.2

theorem record_amount_zero {r c} (hc : r.command = .record c) (h0 : c.amountCents = 0) :
    paymentTransition r = .refused .AMOUNT_ZERO := by
  unfold paymentTransition
  simp [hc, decideRecord, h0]

theorem mutate_ne_alias {r k w pid e post} : mutate r k w ≠ .alias pid e post := by
  intro h
  unfold mutate at h
  by_cases hc : withinCapacity r w = true
  · simp only [hc, Bool.not_true, Bool.false_eq_true, ↓reduceIte] at h
    cases he : evaluate (applyWrites r.input w) <;> simp [he] at h
  · simp [hc] at h

theorem alias_or_dup_alias {f : Bool} {r pid e a b post}
    (h : (if f = true then aliasOf r pid e else PaymentOutcome.duplicate (some pid)) =
      .alias a b post) : f = true ∧ aliasOf r pid e = .alias a b post := by
  cases f <;> simp at h <;> exact ⟨rfl, h⟩

theorem aliasOf_alias {r pid e pid' e' post} (h : aliasOf r pid e = .alias pid' e' post) :
    pid' = pid ∧ e' = e ∧
      post = applyWrites r.input { evidence := some e, payment := none, conflict := none, receipt := none } ∧
      financialInputWellFormed post = true := by
  unfold aliasOf at h
  dsimp only at h
  split at h
  · simp at h
  · split at h
    · rename_i hw
      simp only [PaymentOutcome.alias.injEq] at h
      obtain ⟨rfl, rfl, rfl⟩ := h
      exact ⟨rfl, rfl, rfl, hw⟩
    · simp at h

theorem recordNew_alias {r c pid e post} (h : recordNew r c = .alias pid e post) :
    ∃ p, aliasOf r p e = .alias pid e post ∧ findEvidence r.input.evidence e.evidenceId = none := by
  unfold recordNew at h
  dsimp only at h
  generalize r.input.payments.find? (·.commonOriginId = c.commonOriginId) = existing at h
  generalize existing.any (·.amountCents = c.amountCents) = same at h
  generalize (same && ((findEvidence r.input.evidence c.evidenceId).isSome ||
    r.foreign.evidenceId)) = prior at h
  generalize (if prior = true then
    ((findEvidence r.input.evidence c.evidenceId).map (·.receivedAt)).getD r.input.evaluatedAt
    else r.input.evaluatedAt) = receivedAt at h
  split at h
  · simp at h
  split at h
  · simp at h
  split at h
  · simp at h
  split at h
  · simp at h
  split at h
  · simp at h
  split at h
  · simp at h
  generalize hslot : evidenceSlot r (confirmation r.input c receivedAt) = slot at h
  cases slot
  case clash => simp at h
  all_goals
    dsimp only [Slot.isFresh] at h
    cases existing with
    | none =>
      dsimp only at h
      split at h
      · simp at h
      · exact absurd h mutate_ne_alias
    | some p =>
      dsimp only at h
      split at h
      · split at h
        · simp at h
        · obtain ⟨hf, ha⟩ := alias_or_dup_alias h
          obtain ⟨-, rfl, -⟩ := aliasOf_alias ha
          first | exact ⟨_, ha, (slot_fresh hslot).1⟩ | cases hf
      · split at h
        · simp at h
        split at h
        · simp at h
        exact absurd h mutate_ne_alias

theorem decideReverse_ne_alias {r c pid e post} : decideReverse r c ≠ .alias pid e post := by
  intro h
  unfold decideReverse at h
  cases hp : findPayment r.input.payments c.paymentId with
  | none => simp [hp] at h
  | some p =>
    simp only [hp] at h
    repeat' split at h
    all_goals first
      | exact absurd h mutate_ne_alias
      | (simp at h; done)

theorem alias_shape {r pid e post} (h : paymentTransition r = .alias pid e post) :
    post = applyWrites r.input
        { evidence := some e, payment := none, conflict := none, receipt := none } ∧
      financialInputWellFormed post = true ∧ findEvidence r.input.evidence e.evidenceId = none := by
  unfold paymentTransition at h
  cases hc : r.command with
  | record c =>
    simp only [hc] at h
    unfold decideRecord at h
    split at h
    · simp at h
    split at h
    · simp at h
    cases hp : findPayment r.input.payments c.paymentId with
    | some p =>
      simp only [hp] at h
      have := recordRetry_plain r c p
      simp [h, PaymentOutcome.Plain] at this
    | none =>
      simp only [hp] at h
      obtain ⟨p, ha, hfe⟩ := recordNew_alias h
      obtain ⟨-, -, hpost, hwf⟩ := aliasOf_alias ha
      exact ⟨hpost, hwf, hfe⟩
  | reverse c => simp only [hc] at h; exact absurd h decideReverse_ne_alias

theorem paymentTransition_alias_post {r pid e post} (h : paymentTransition r = .alias pid e post) :
    post = applyWrites r.input
        { evidence := some e, payment := none, conflict := none, receipt := none } ∧
      financialInputWellFormed post = true ∧
      activeCents post.payments = activeCents r.input.payments := by
  obtain ⟨hpost, hwf, -⟩ := alias_shape h
  exact ⟨hpost, hwf, by rw [hpost]; rfl⟩

theorem record_link_within_request {r c w post result a}
    (hc : r.command = .record c) (ha : c.paysActionId = some a)
    (h : paymentTransition r = .mutated .RECORDED w post result) :
    ∃ x ∈ r.input.actions, x.actionId = a ∧ x.kind = "CORRECTION_PAYMENT_REQUEST" ∧
      linkedActivePaidCents r.input.payments (linksOf r.receipts) a + c.amountCents ≤ x.amountCents := by
  rcases paymentTransition_cases h with ⟨c', hc', hd⟩ | ⟨c', -, hd⟩
  · obtain rfl := Command.record.inj (hc.symm.trans hc')
    obtain ⟨-, -, -, ⟨-, -, -, -, -, hl⟩ | ⟨hk, -⟩⟩ := recordNew_mutated (decideRecord_mutated hd).2
    · exact hl a ha
    · cases hk
  · obtain ⟨-, -, hk, -⟩ := decideReverse_mutated hd
    cases hk

end Base

theorem findPayment_id : ∀ (l : List Payment) (id : String) (p : Payment),
    findPayment l id = some p → p.paymentId = id
  | [], _, _, h => by simp [findPayment] at h
  | x :: xs, id, p, h => by
      unfold findPayment at h
      split at h
      · simp only [Option.some.injEq] at h; subst h; assumption
      · exact findPayment_id xs id p h

theorem activeCents_eq : ∀ l : List Payment,
    activeCents l = (l.map fun x => if x.status = .ACTIVE then x.amountCents else 0).sum
  | [] => rfl
  | x :: xs => by
      have := activeCents_eq xs
      unfold activeCents at this ⊢
      by_cases h : x.status = .ACTIVE <;> simp [List.filter_cons, h, this]

theorem reversedCents_eq : ∀ l : List Payment,
    reversedCents l = (l.map fun x => if x.status = .REVERSED then x.amountCents else 0).sum
  | [] => rfl
  | x :: xs => by
      have := reversedCents_eq xs
      unfold reversedCents at this ⊢
      by_cases h : x.status = .REVERSED <;> simp [List.filter_cons, h, this]

namespace Base

theorem reverse_exact {r c w post result}
    (hc : r.command = .reverse c) (h : paymentTransition r = .mutated .REVERSED w post result) :
    ∃ p, findPayment r.input.payments c.paymentId = some p ∧ p.status = .ACTIVE ∧
      w.payment = some { p with status := .REVERSED, reversalEvidenceId := some c.evidenceId } ∧
      (w.evidence.map (·.amountCents)) = some (some p.amountCents) ∧
      activeCents post.payments + p.amountCents = activeCents r.input.payments ∧
      reversedCents post.payments = reversedCents r.input.payments + p.amountCents := by
  rcases paymentTransition_cases h with ⟨c', -, hd⟩ | ⟨c', hc', hd⟩
  · rcases (recordNew_mutated (decideRecord_mutated hd).2).2.2.2 with ⟨hk, -⟩ | ⟨hk, -⟩ <;> cases hk
  · obtain rfl := Command.reverse.inj (hc.symm.trans hc')
    obtain ⟨p, e, -, hp, hst, rfl, -, he, -, -, -⟩ := decideReverse_mutated hd
    have hst' : p.status = .ACTIVE := by
      cases hs : p.status
      · rfl
      · exact absurd hs hst
    have hid := findPayment_id _ _ _ hp
    obtain ⟨hpost, hwf, -⟩ := paymentTransition_mutated_post h
    have hfind : findPayment r.input.payments (reversedImage p c).paymentId = some p := hid ▸ hp
    have hnd := payments_nodup_of_replace (hpost ▸ hwf) rfl (by rw [hfind]; rfl)
    have hpay : post.payments = r.input.payments.map fun x =>
        if x.paymentId = (reversedImage p c).paymentId then reversedImage p c else x := by
      rw [hpost]; simp only [applyWrites, hfind, Option.isSome_some, ↓reduceIte]
    have h1 := sum_replace (fun x => if x.status = .ACTIVE then x.amountCents else 0)
      (reversedImage p c) _ p hnd hfind
    have h2 := sum_replace (fun x => if x.status = .REVERSED then x.amountCents else 0)
      (reversedImage p c) _ p hnd hfind
    refine ⟨p, hp, hst', rfl, by subst he; rfl, ?_, ?_⟩
    · rw [activeCents_eq, activeCents_eq, hpay]
      simpa [reversedImage, hst'] using h1
    · rw [reversedCents_eq, reversedCents_eq, hpay]
      simpa [reversedImage, hst'] using h2

theorem conflict_changes_no_cash {r w post result}
    (h : paymentTransition r = .mutated .CONFLICT_RECORDED w post result) :
    post.payments = r.input.payments ∧ w.receipt = none := by
  rcases paymentTransition_cases h with ⟨c, -, hd⟩ | ⟨c, -, hd⟩
  · obtain ⟨-, -, -, ⟨hk, -⟩ | ⟨-, p, -, -, -, hp, hr, -⟩⟩ :=
      recordNew_mutated (decideRecord_mutated hd).2
    · cases hk
    · refine ⟨?_, hr⟩
      rw [(paymentTransition_mutated_post h).1]
      simp [applyWrites, hp]
  · obtain ⟨-, -, hk, -⟩ := decideReverse_mutated hd
    cases hk

/-- Everything a mutated outcome can be, with the rows it writes (used by the ledger laws). -/
theorem mutated_shape {r k w post res} (h : paymentTransition r = .mutated k w post res) :
    (k = .RECORDED ∧ ∃ c, r.command = .record c ∧ findPayment r.input.payments c.paymentId = none ∧
      (∀ q ∈ r.input.payments, q.commonOriginId ≠ c.commonOriginId) ∧
      w.payment = some (recordedPayment r.input c) ∧ w.receipt = some (recordedReceipt r.input c) ∧
      w.conflict = none ∧ EvidenceWrite r c w.evidence ∧ revisionOk r = true) ∨
    (k = .CONFLICT_RECORDED ∧ ∃ c, r.command = .record c ∧ w.payment = none ∧ w.receipt = none ∧
      EvidenceWrite r c w.evidence) ∨
    (k = .REVERSED ∧ ∃ c p e, r.command = .reverse c ∧
      findPayment r.input.payments c.paymentId = some p ∧ p.status ≠ .REVERSED ∧
      w = ⟨some e, some (reversedImage p c), none, none⟩ ∧
      e = reversalRecord r.input c p (c.eventAt.getD r.input.evaluatedAt) ∧
      findEvidence r.input.evidence c.evidenceId = none ∧ e.eventAt ≤ r.input.evaluatedAt ∧
      formRefusal e = none) := by
  rcases paymentTransition_cases h with ⟨c, hc, hd⟩ | ⟨c, hc, hd⟩
  · obtain ⟨hf, hn⟩ := decideRecord_mutated hd
    obtain ⟨-, hrev, hew, ⟨hk, hq, hwp, hwr, hwc, -⟩ | ⟨hk, p, -, -, -, hwp, hwr, -⟩⟩ :=
      recordNew_mutated hn
    · exact Or.inl ⟨hk, c, hc, hf, hq, hwp, hwr, hwc, hew, hrev⟩
    · exact Or.inr (Or.inl ⟨hk, c, hc, hwp, hwr, hew⟩)
  · obtain ⟨p, e, hk, hp, hst, hw, -, he, hfe, hle, hform⟩ := decideReverse_mutated hd
    exact Or.inr (Or.inr ⟨hk, c, p, e, hc, hp, hst, hw, he, hfe, hle, hform⟩)

end Base

section TrLayer
open BlindLedger.Financial.CorrectionTransition

/-! ## Transfer: a non-refused rev 1.2 outcome is the old outcome (rev 1.2 only adds refusals) -/

theorem cap_tr {r w} (hc : withinCapacity r w = true) : Base.withinCapacity r w = true := by
  unfold withinCapacity at hc
  unfold Base.withinCapacity
  simp only [decide_eq_true_eq] at hc ⊢
  generalize maxTotalEncodedBytes = M at hc ⊢
  omega

/-- A shadow request has no mutated or alias outcome; a mutation or alias fits (D3). -/
abbrev Live (r : PaymentRequest) (o : PaymentOutcome) : Prop :=
  (r.input.context.mode = .SHADOW → (∀ k w p res, o ≠ .mutated k w p res) ∧ ∀ pid e p, o ≠ .alias pid e p) ∧
  (∀ k w p res, o = .mutated k w p res → withinCapacity r w = true) ∧
  ∀ pid e p, o = .alias pid e p →
    withinCapacity r { evidence := some e, payment := none, conflict := none, receipt := none } = true

theorem mutate_tr {r k w o} (h : mutate r k w = o) (hn : ∀ f, o ≠ .refused f) :
    Base.mutate r k w = o ∧ Live r o := by
  unfold mutate at h
  unfold Base.mutate
  split at h
  · exact absurd h.symm (hn _)
  split at h
  · exact absurd h.symm (hn _)
  rename_i hs hc
  simp only [Bool.not_eq_true, Bool.not_eq_false'] at hc
  dsimp only at h ⊢
  have h1 : Base.mutate r k w = o := by
    unfold Base.mutate
    dsimp only
    split
    · rename_i h2; simp [cap_tr hc] at h2
    · exact h
  refine ⟨h1, fun hs' => absurd hs' hs, fun k' w' p' res' ho => ?_, fun pid' e' p' ho => ?_⟩
  · obtain ⟨-, rfl, -⟩ := Base.mutate_eq (h1.trans ho); exact hc
  · exact absurd (h1.trans ho) Base.mutate_ne_alias

theorem alias_tr {r pid e o} (h : aliasOf r pid e = o) (hn : ∀ f, o ≠ .refused f) :
    Base.aliasOf r pid e = o ∧ Live r o := by
  unfold aliasOf at h
  unfold Base.aliasOf
  dsimp only at h ⊢
  split at h
  · exact absurd h.symm (hn _)
  split at h
  · exact absurd h.symm (hn _)
  rename_i hs hc
  simp only [Bool.not_eq_true, Bool.not_eq_false'] at hc
  have h1 : Base.aliasOf r pid e = o := by
    unfold Base.aliasOf
    dsimp only
    split
    · rename_i h2; simp [cap_tr hc] at h2
    · exact h
  refine ⟨h1, fun hs' => absurd hs' hs, fun k' w' p' res' ho => ?_, fun pid' e' p' ho => ?_⟩
  · exact absurd (h1.trans ho) Base.aliasOf_ne_mutated
  · obtain ⟨-, rfl, -⟩ := Base.aliasOf_alias (h1.trans ho); exact hc

/-- A recorded payment's link was not refused. -/
def LinkHolds (r : PaymentRequest) (c : RecordCommand) (o : PaymentOutcome) : Prop :=
  ∀ w post res, o = .mutated .RECORDED w post res → linkRefusal r.input r.receipts c = none

theorem facts_nm {r c x o} (h : x = o) (hm : ∀ k w p res, x ≠ .mutated k w p res)
    (ha : ∀ pid e p, x ≠ .alias pid e p) : x = o ∧ Live r o ∧ LinkHolds r c o :=
  ⟨h, ⟨fun _ => ⟨fun k w p res ho => hm k w p res (h.trans ho), fun pid e p ho => ha pid e p (h.trans ho)⟩,
    fun k w p res ho => absurd (h.trans ho) (hm k w p res), fun pid e p ho => absurd (h.trans ho) (ha pid e p)⟩,
   fun w p res ho => absurd (h.trans ho) (hm _ _ _ _)⟩

theorem dup_leaf {r c o pid} (h : PaymentOutcome.duplicate pid = o) :
    PaymentOutcome.duplicate pid = o ∧ Live r o ∧ LinkHolds r c o :=
  facts_nm h (fun _ _ _ _ => nofun) (fun _ _ _ => nofun)

set_option maxHeartbeats 2000000 in
theorem recordNew_tr {r c o} (h : recordNew r c = o) (hz : c.amountCents ≠ 0) (hn : ∀ f, o ≠ .refused f) :
    Base.recordNew r c = o ∧ Live r o ∧ LinkHolds r c o := by
  have nm : ∀ {x : PaymentOutcome}, x = o → (∀ k w p res, x ≠ .mutated k w p res) →
      (∀ pid e p, x ≠ .alias pid e p) → x = o ∧ Live r o ∧ LinkHolds r c o := facts_nm
  unfold recordNew at h
  unfold Base.recordNew
  unfold conflictIdOf at h
  dsimp only at h ⊢
  generalize r.input.payments.find? (·.commonOriginId = c.commonOriginId) = existing at h ⊢
  generalize existing.any (·.amountCents = c.amountCents) = same at h ⊢
  generalize findEvidence r.input.evidence c.evidenceId = stored at h ⊢
  generalize (same && (stored.isSome || r.foreign.evidenceId)) = prior at h ⊢
  generalize (if prior = true then (Option.map (fun x => x.receivedAt) stored).getD r.input.evaluatedAt
      else r.input.evaluatedAt) = receivedAt at h ⊢
  generalize (existing.any fun p => decide (p.status = PaymentStatus.REVERSED) &&
      Option.any (fun v => decide (v.eventAt < c.eventAt)) (p.reversalEvidenceId.bind (findEvidence r.input.evidence))) = rb at h ⊢
  generalize (r.input.conflicts.any fun x => decide (x.conflictId = "conflict:" ++ r.input.context.itemId ++ ":" ++ c.commonOriginId ++ ":" ++ c.evidenceId)) = cv at h ⊢
  generalize (evidenceSlot r (confirmation r.input c r.input.evaluatedAt)).isSame = iss at h ⊢
  generalize revisionOk r = rok at h ⊢
  generalize formRefusal (confirmation r.input c receivedAt) = fr at h ⊢
  generalize evidenceSlot r (confirmation r.input c receivedAt) = sl at h ⊢
  by_cases c1 : (same && !prior && rb) = true
  · rw [if_pos c1] at h ⊢; exact nm h (fun _ _ _ _ => nofun) (fun _ _ _ => nofun)
  rw [if_neg c1] at h ⊢
  by_cases c2 : (existing.isSome && !same && cv && iss) = true
  · rw [if_pos c2] at h ⊢; exact nm h (fun _ _ _ _ => nofun) (fun _ _ _ => nofun)
  rw [if_neg c2] at h ⊢
  by_cases c3 : (!prior && !rok) = true
  · rw [if_pos c3] at h ⊢; exact nm h (fun _ _ _ _ => nofun) (fun _ _ _ => nofun)
  rw [if_neg c3] at h ⊢
  by_cases c4 : (prior && r.foreign.evidenceId) = true
  · rw [if_pos c4] at h ⊢; exact nm h (fun _ _ _ _ => nofun) (fun _ _ _ => nofun)
  rw [if_neg c4] at h ⊢
  cases fr with
  | some f => exact nm h (fun _ _ _ _ => nofun) (fun _ _ _ => nofun)
  | none =>
  dsimp only at h ⊢
  by_cases c5 : c.eventAt > receivedAt
  · rw [if_pos c5] at h ⊢; exact nm h (fun _ _ _ _ => nofun) (fun _ _ _ => nofun)
  rw [if_neg c5] at h ⊢
  cases sl
  case clash => exact nm h (fun _ _ _ _ => nofun) (fun _ _ _ => nofun)
  all_goals
    simp only [Slot.isFresh, Bool.false_eq_true, ↓reduceIte] at h ⊢
    cases existing with
    | some p =>
      dsimp only at h ⊢
      by_cases s1 : same = true
      · rw [if_pos s1] at h ⊢
        by_cases c6 : (c.paysActionId.isSome &&
            decide (c.paysActionId ≠ (receiptOf r.receipts p.paymentId).bind fun x => x.paysActionId)) = true
        · rw [if_pos c6] at h ⊢; exact nm h (fun _ _ _ _ => nofun) (fun _ _ _ => nofun)
        rw [if_neg c6] at h ⊢
        first
          | (with_reducible exact dup_leaf h)
          | (obtain ⟨h1, h2⟩ := alias_tr (r := r) (pid := p.paymentId) (e := confirmation r.input c receivedAt) h hn
             unfold LinkHolds
             exact ⟨h1, h2, fun w' p' r' ho => absurd (h1.trans ho) (Base.aliasOf_ne_mutated (r := r) (pid := p.paymentId))⟩)
      · rw [if_neg s1] at h ⊢
        by_cases c7 : cv = true
        · rw [if_pos c7] at h ⊢; exact nm h (fun _ _ _ _ => nofun) (fun _ _ _ => nofun)
        rw [if_neg c7] at h ⊢
        by_cases c8 : (!idWellFormed ("conflict:" ++ r.input.context.itemId ++ ":" ++ c.commonOriginId ++ ":" ++ c.evidenceId)) = true
        · rw [if_pos c8] at h ⊢; exact nm h (fun _ _ _ _ => nofun) (fun _ _ _ => nofun)
        rw [if_neg c8] at h ⊢
        obtain ⟨h1, h2⟩ := mutate_tr h hn
        unfold LinkHolds
        exact ⟨h1, h2, fun w' p' r' ho => by
          have := (Base.mutate_eq (h1.trans ho)).1
          cases this⟩
    | none =>
      unfold LinkHolds
      dsimp only at h ⊢
      cases hl : linkRefusal r.input r.receipts c with
      | some f => simp only [hl] at h; exact absurd h.symm (hn _)
      | none =>
        simp only [hl] at h
        obtain ⟨h1, h2⟩ := mutate_tr h hn
        refine ⟨?_, h2, fun _ _ _ _ => rfl⟩
        cases hp : c.paysActionId with
        | none => simpa using h1
        | some a =>
          obtain ⟨x, hf, hlk, -⟩ := linkRefusal_find hp hz hl
          have hn1 : ¬ (linkedActivePaidCents r.input.payments (linksOf r.receipts) a + c.amountCents >
              x.amountCents) := by omega
          simp only [Option.bind_some, hf, hn1, ↓reduceIte]
          exact h1

theorem decideReverse_tr {r c o} (h : decideReverse r c = o) (hn : ∀ f, o ≠ .refused f) :
    Base.decideReverse r c = o ∧ Live r o := by
  have nm : ∀ {x : PaymentOutcome}, x = o → (∀ k w p res, x ≠ .mutated k w p res) →
      (∀ pid e p, x ≠ .alias pid e p) → x = o ∧ Live r o := fun h hm ha =>
    ⟨h, ⟨fun _ => ⟨fun k w p res ho => hm k w p res (h.trans ho), fun pid e p ho => ha pid e p (h.trans ho)⟩,
      fun k w p res ho => absurd (h.trans ho) (hm k w p res), fun pid e p ho => absurd (h.trans ho) (ha pid e p)⟩⟩
  unfold decideReverse at h
  unfold Base.decideReverse
  dsimp only at h ⊢
  generalize findPayment r.input.payments c.paymentId = fp at h ⊢
  cases fp with
  | none => exact nm h (fun _ _ _ _ => nofun) (fun _ _ _ => nofun)
  | some p =>
    dsimp only at h ⊢
    by_cases f1 : r.foreign.evidenceId = true
    · rw [if_pos f1] at h ⊢; exact nm h (fun _ _ _ _ => nofun) (fun _ _ _ => nofun)
    rw [if_neg f1] at h ⊢
    generalize c.eventAt.getD (((findEvidence r.input.evidence c.evidenceId).map (·.eventAt)).getD r.input.evaluatedAt) = time at h ⊢
    generalize formRefusal (reversalRecord r.input c p time) = fr at h ⊢
    generalize evidenceSlot r (reversalRecord r.input c p time) = sl at h ⊢
    cases fr with
    | some f => exact nm h (fun _ _ _ _ => nofun) (fun _ _ _ => nofun)
    | none =>
      dsimp only at h ⊢
      by_cases t1 : time > r.input.evaluatedAt
      · rw [if_pos t1] at h ⊢; exact nm h (fun _ _ _ _ => nofun) (fun _ _ _ => nofun)
      rw [if_neg t1] at h ⊢
      cases sl with
      | clash => exact nm h (fun _ _ _ _ => nofun) (fun _ _ _ => nofun)
      | same s => exact nm h (fun _ _ _ _ => nofun) (fun _ _ _ => nofun)
      | fresh =>
        dsimp only at h ⊢
        by_cases v1 : (!revisionOk r) = true
        · rw [if_pos v1] at h ⊢; exact nm h (fun _ _ _ _ => nofun) (fun _ _ _ => nofun)
        rw [if_neg v1] at h ⊢
        by_cases v2 : p.status = PaymentStatus.REVERSED
        · rw [if_pos v2] at h ⊢; exact nm h (fun _ _ _ _ => nofun) (fun _ _ _ => nofun)
        rw [if_neg v2] at h ⊢
        exact mutate_tr h hn

theorem decideRecord_tr {r c o} (h : decideRecord r c = o) (hn : ∀ f, o ≠ .refused f) :
    Base.decideRecord r c = o ∧ Live r o ∧ LinkHolds r c o := by
  unfold decideRecord at h
  unfold Base.decideRecord
  by_cases z : c.amountCents = 0
  · rw [if_pos z] at h ⊢; exact facts_nm h (fun _ _ _ _ => nofun) (fun _ _ _ => nofun)
  rw [if_neg z] at h ⊢
  by_cases f : r.foreign.paymentId = true
  · rw [if_pos f] at h ⊢; exact facts_nm h (fun _ _ _ _ => nofun) (fun _ _ _ => nofun)
  rw [if_neg f] at h ⊢
  generalize findPayment r.input.payments c.paymentId = fp at h ⊢
  cases fp with
  | some p =>
    dsimp only at h ⊢
    exact facts_nm h (fun _ _ _ _ hh => by have := recordRetry_plain r c p; rw [hh] at this; exact this)
      (fun _ _ _ hh => by have := recordRetry_plain r c p; rw [hh] at this; exact this)
  | none => exact recordNew_tr h z hn

theorem paymentTransition_tr {r o} (h : paymentTransition r = o) (hn : ∀ f, o ≠ .refused f) :
    Base.paymentTransition r = o ∧ Live r o := by
  unfold paymentTransition at h
  unfold Base.paymentTransition
  generalize r.command = cmd at h ⊢
  cases cmd with
  | record c => exact (fun x => ⟨x.1, x.2.1⟩) (decideRecord_tr h hn)
  | reverse c => exact decideReverse_tr h hn

theorem transition_cap {r k w post res} (h : paymentTransition r = .mutated k w post res) :
    withinCapacity r w = true :=
  (paymentTransition_tr h fun _ => nofun).2.2.1 k w post res rfl

theorem transition_alias_cap {r pid e post} (h : paymentTransition r = .alias pid e post) :
    withinCapacity r { evidence := some e, payment := none, conflict := none, receipt := none } = true :=
  (paymentTransition_tr h fun _ => nofun).2.2.2 pid e post rfl

theorem paymentTransition_link {r c o} (hc : r.command = .record c) (h : paymentTransition r = o)
    (hn : ∀ f, o ≠ .refused f) : LinkHolds r c o := by
  unfold paymentTransition at h
  rw [hc] at h
  exact (decideRecord_tr (c := c) h hn).2.2

end TrLayer

/-- R2 #6: a recorded payment that names a request fits that request's open amount, evaluated
    at the balance before the payment. -/
theorem record_link_within_open {r : PaymentRequest} {c : RecordCommand} {w : Writes}
    {post : FinancialInput} {result : FinancialResult} {a : String}
    (hc : r.command = .record c) (ha : c.paysActionId = some a)
    (h : paymentTransition r = .mutated .RECORDED w post result) :
    ∃ before x, evaluate r.input = some before ∧ x ∈ r.input.actions ∧ x.actionId = a ∧
      x.kind = "CORRECTION_PAYMENT_REQUEST" ∧
      c.amountCents ≤ openCents before.shortfallCents r.input.payments (linksOf r.receipts)
        r.input.actions x := by
  obtain ⟨x, hf, before, hE, hle⟩ := linkRefusal_none ha
    (paymentTransition_link hc h (fun f => nofun) w post result rfl)
  have hp := List.find?_some hf
  simp only [Bool.and_eq_true, decide_eq_true_eq] at hp
  exact ⟨before, x, hE, List.mem_of_find?_eq_some hf, hp.1, hp.2, hle⟩

-- 16.9 R1 (5.2) as signed
theorem record_link_within_shortfall {r : PaymentRequest} {c w post result a}
    (hc : r.command = .record c) (ha : c.paysActionId = some a)
    (h : paymentTransition r = .mutated .RECORDED w post result) :
    ∃ before, evaluate r.input = some before ∧ c.amountCents ≤ before.shortfallCents := by
  obtain ⟨before, x, hE, -, -, -, hle⟩ := record_link_within_open hc ha h
  exact ⟨before, hE, Nat.le_trans hle (openCents_le _ _ _ _ _).1⟩

-- 16.9 A2 (5.2), strengthened to aliases
theorem paymentTransition_shadow_refused (r : PaymentRequest)
    (hShadow : r.input.context.mode = .SHADOW) :
    (∀ k w post result, paymentTransition r ≠ .mutated k w post result) ∧
      ∀ pid e post, paymentTransition r ≠ .alias pid e post := by
  by_cases hn : ∃ f, paymentTransition r = .refused f
  · obtain ⟨f, hf⟩ := hn
    exact ⟨fun k w p res h => (by rw [hf] at h; cases h), fun pid e p h => (by rw [hf] at h; cases h)⟩
  · exact (paymentTransition_tr rfl fun f h => hn ⟨f, h⟩).2.1 hShadow

end BlindLedger.Financial.Payment
