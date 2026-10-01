import BlindLedger.Financial.Payment.Ledger

namespace BlindLedger.Financial.Payment

open BlindLedger.Financial BlindLedger.Financial.CorrectionTransition

/-! The cross-module law (design 5.4): what correction reads as paid on request `a` is what the
    payment history recorded to `a`, less what it reversed from `a`.  Nothing calls this yet. -/

def ledgerPaid (L : Ledger) (a : String) : Nat :=
  linkedActivePaidCents L.input.payments (linksOf L.receipts) a

def withinRequests (L : Ledger) : Prop :=
  ∀ x ∈ L.input.actions, x.kind = "CORRECTION_PAYMENT_REQUEST" → ledgerPaid L x.actionId ≤ x.amountCents

/-- Cents one outcome records to request `a`. -/
def recordedTo1 (a : String) : PaymentOutcome → Nat
  | .mutated .RECORDED w _ _ =>
      if w.receipt.bind (·.paysActionId) = some a then (w.payment.map (·.amountCents)).getD 0 else 0
  | _ => 0

/-- Cents one outcome reverses from request `a`, the payment's link read in `rs`. -/
def reversedFrom1 (a : String) (rs : List Receipt) : PaymentOutcome → Nat
  | .mutated .REVERSED w _ _ =>
      if (w.payment.bind fun p => (receiptOf rs p.paymentId).bind (·.paysActionId)) = some a then
        (w.payment.map (·.amountCents)).getD 0 else 0
  | _ => 0

def recordedTo (a : String) (os : List PaymentOutcome) : Nat := (os.map (recordedTo1 a)).sum
def reversedFrom (a : String) (rs : List Receipt) (os : List PaymentOutcome) : Nat :=
  (os.map (reversedFrom1 a rs)).sum

/-! ## The paid total as a sum over payments -/

/-- With one receipt per payment, a link to `a` is the payment's receipt naming `a`. -/
theorem link_iff {rs : List Receipt} (hn : (rs.map Receipt.paymentId).Nodup) {pid a : String} :
    (∃ l ∈ linksOf rs, l.paymentId = pid ∧ l.actionId = a) ↔
      (receiptOf rs pid).bind (·.paysActionId) = some a := by
  constructor
  · rintro ⟨l, hl, rfl, rfl⟩
    obtain ⟨k, hk, hs⟩ := List.mem_filterMap.1 hl
    cases hb : k.paysActionId with
    | none => simp [hb] at hs
    | some b =>
      simp only [hb, Option.map_some, Option.some.injEq] at hs
      subst hs
      have : receiptOf rs k.paymentId = some k := find_of_mem Receipt.paymentId hn hk
      simp [this, hb]
  · intro h
    cases hk : receiptOf rs pid with
    | none => simp [hk] at h
    | some k =>
      simp only [hk, Option.bind_some] at h
      have hk' : rs.find? (fun y => decide (y.paymentId = pid)) = some k := hk
      have hm : k ∈ rs := List.mem_of_find?_eq_some hk'
      have hp : k.paymentId = pid := by simpa using List.find?_some hk'
      exact ⟨⟨pid, a⟩, List.mem_filterMap.2 ⟨k, hm, by simp [h, hp]⟩, rfl, rfl⟩

def paidOn (rs : List Receipt) (a : String) (p : Payment) : Nat :=
  if p.status = .ACTIVE ∧ (receiptOf rs p.paymentId).bind (·.paysActionId) = some a then p.amountCents
  else 0

theorem ledgerPaid_eq {L : Ledger} (hI : Inv L) (a : String) :
    ledgerPaid L a = (L.input.payments.map (paidOn L.receipts a)).sum := by
  have hn : (L.receipts.map Receipt.paymentId).Nodup := by rw [hI.2]; exact hI.1
  unfold ledgerPaid
  rw [linkedActivePaidCents_eq_sum]
  congr 1
  exact List.map_congr_left fun q _ => by simp only [paidTerm, paidOn, link_iff hn]

theorem receipt_exists {L : Ledger} (hI : Inv L) {id p} (hf : findPayment L.input.payments id = some p) :
    ∃ k, receiptOf L.receipts p.paymentId = some k := by
  have hn : (L.receipts.map Receipt.paymentId).Nodup := by rw [hI.2]; exact hI.1
  have : p.paymentId ∈ L.receipts.map Receipt.paymentId := by
    rw [hI.2]; exact List.mem_map.2 ⟨p, findPayment_mem hf, rfl⟩
  obtain ⟨k, hk, hkp⟩ := List.mem_map.1 this
  exact ⟨k, by rw [← hkp]; exact find_of_mem Receipt.paymentId hn hk⟩

theorem Silent.zero {o} (hs : Silent o) (a : String) (rs : List Receipt) :
    recordedTo1 a o = 0 ∧ reversedFrom1 a rs o = 0 := by
  cases o with
  | mutated k w p r =>
    cases k with
    | RECORDED => exact absurd rfl (hs.1 w p r)
    | REVERSED => exact absurd rfl (hs.2 w p r)
    | CONFLICT_RECORDED => exact ⟨rfl, rfl⟩
  | _ => exact ⟨rfl, rfl⟩

/-! ## One step, then a run -/

/-- `R` is the receipt list a later reader sees: it still holds every receipt `L` holds. -/
theorem step_bridge {L : Ledger} (c : Call) (hI : Inv L) (a : String) {R : List Receipt}
    (hR : ∀ id k, receiptOf L.receipts id = some k → receiptOf R id = some k) :
    ledgerPaid (step L c) a + reversedFrom1 a R (L.outcome c) =
      ledgerPaid L a + recordedTo1 a (L.outcome c) := by
  have hS0 := ledgerPaid_eq hI a
  have hS := ledgerPaid_eq (step_Inv c hI) a
  rcases step_kind L c with ⟨hs, hp, hr⟩ |
    ⟨rc, w, post, res, -, ho, hp, hr, hf, -, -, -, -, hpay, hrec⟩ |
    ⟨vc, p, w, post, res, -, ho, hf, hst, hw, -, hpay, hrec, -⟩
  · have : ledgerPaid (step L c) a = ledgerPaid L a := by unfold ledgerPaid; rw [hp, hr]
    rw [this, (hs.zero a R).1, (hs.zero a R).2]
  · have hrn : receiptOf L.receipts rc.paymentId = none := receiptOf_none hI hf
    have hne : ∀ q ∈ L.input.payments, q.paymentId ≠ rc.paymentId := fun q hq e => by
      have := findPayment_of_mem hI.1 hq
      rw [e, hf] at this; cases this
    rw [hpay, hrec, sum_insertBy] at hS
    have hcongr : L.input.payments.map
        (paidOn (insertBy Receipt.paymentId (recordedReceipt (L.request c).input rc) L.receipts) a) =
        L.input.payments.map (paidOn L.receipts a) :=
      List.map_congr_left fun q hq => by
        simp only [paidOn, receiptOf_insertBy (K := recordedReceipt (L.request c).input rc) hrn,
          if_neg (fun e : (recordedReceipt (L.request c).input rc).paymentId = q.paymentId =>
            hne q hq e.symm)]
    have hP : paidOn (insertBy Receipt.paymentId (recordedReceipt (L.request c).input rc) L.receipts) a
        (recordedPayment (L.request c).input rc) = if rc.paysActionId = some a then rc.amountCents else 0 := by
      simp only [paidOn, receiptOf_insertBy (K := recordedReceipt (L.request c).input rc) hrn]
      simp [recordedPayment, recordedReceipt]
    have e4 : reversedFrom1 a R (.mutated .RECORDED w post res) = 0 := rfl
    have e5 : recordedTo1 a (.mutated .RECORDED w post res) =
        if rc.paysActionId = some a then rc.amountCents else 0 := by
      simp [recordedTo1, hp, hr, recordedReceipt, recordedPayment]
    rw [ho, hS, hcongr, hP, hS0, e4, e5]
    omega
  · have hact : p.status = .ACTIVE := by
      cases hs : p.status
      · rfl
      · exact absurd hs hst
    obtain ⟨k, hk⟩ := receipt_exists hI hf
    have hf' : findPayment L.input.payments p.paymentId = some p := by
      rw [findPayment_id _ _ _ hf]; exact hf
    have hsum : ((L.input.payments.map fun x => if x.paymentId = p.paymentId then reversedImage p vc else x).map
        (paidOn L.receipts a)).sum + paidOn L.receipts a p =
        (L.input.payments.map (paidOn L.receipts a)).sum + paidOn L.receipts a (reversedImage p vc) :=
      sum_replace (paidOn L.receipts a) (reversedImage p vc) _ p hI.1 hf'
    rw [hpay, hrec] at hS
    have e1 : paidOn L.receipts a p = if k.paysActionId = some a then p.amountCents else 0 := by
      simp [paidOn, hk, hact]
    have e2 : paidOn L.receipts a (reversedImage p vc) = 0 := by simp [paidOn, reversedImage]
    rw [e1, e2] at hsum
    have e3 : reversedFrom1 a R (.mutated .REVERSED w post res) =
        if k.paysActionId = some a then p.amountCents else 0 := by
      simp [reversedFrom1, hw, reversedImage, hR _ _ hk]
    have e4 : recordedTo1 a (.mutated .REVERSED w post res) = 0 := rfl
    rw [ho, hS, hS0, e3, e4]
    omega

theorem step_ledgerPaid (L) (hL : ledgerWellFormed L) (c : Call) (a : String) :
    ledgerPaid (step L c) a + reversedFrom a L.receipts [L.outcome c] =
      ledgerPaid L a + recordedTo a [L.outcome c] := by
  have := step_bridge c (Inv_of_wf hL) a (R := L.receipts) fun _ _ h => h
  simpa [reversedFrom, recordedTo] using this

theorem run_receipt : ∀ (calls : List Call) (L : Ledger), Inv L → ∀ (id : String) (k : Receipt),
    receiptOf L.receipts id = some k → receiptOf (run L calls).receipts id = some k
  | [], _, _, _, _, h => h
  | c :: cs, L, hI, id, k, h => run_receipt cs (step L c) (step_Inv c hI) id k (step_receipt c hI h)

theorem run_bridge (a : String) : ∀ (calls : List Call) (L : Ledger), Inv L →
    ledgerPaid (run L calls) a + reversedFrom a (run L calls).receipts (trace L calls) =
      ledgerPaid L a + recordedTo a (trace L calls)
  | [], L, _ => by simp [run, trace, reversedFrom, recordedTo]
  | c :: cs, L, hI => by
    have ih := run_bridge a cs (step L c) (step_Inv c hI)
    have h := step_bridge c hI a (R := (run (step L c) cs).receipts)
      fun id k hk => run_receipt cs (step L c) (step_Inv c hI) id k (step_receipt c hI hk)
    simp only [run_cons, trace, reversedFrom, recordedTo, List.map_cons, List.sum_cons] at ih ⊢
    omega

theorem run_ledgerPaid (L) (hL : ledgerWellFormed L) (calls) (a : String) :
    ledgerPaid (run L calls) a + reversedFrom a (run L calls).receipts (trace L calls) =
      ledgerPaid L a + recordedTo a (trace L calls) :=
  run_bridge a calls L (Inv_of_wf hL)

/-! ## No sequence pays more than a request asks -/

theorem step_actions (L c) : (step L c).input.actions = L.input.actions := by
  rcases step_cases L c with ⟨k, w, post, res, ho, he⟩ | ⟨pid, e, post, ho, he⟩ | ⟨-, -, he⟩ <;> rw [he]
  · dsimp only; rw [(paymentTransition_mutated_post ho).1]; rfl
  · dsimp only; rw [(alias_shape ho).1]; rfl

theorem step_within {L : Ledger} (c : Call) (hI : Inv L)
    (hA : (L.input.actions.map ActionRecord.actionId).Nodup) (hW : withinRequests L) :
    withinRequests (step L c) := by
  intro x hx hk
  rw [step_actions] at hx
  have h0 := hW x hx hk
  have e := step_bridge c hI x.actionId (R := L.receipts) fun _ _ h => h
  rcases step_kind L c with ⟨hs, -⟩ | ⟨rc, w, post, res, hcmd, ho, hp, hr, -, -, -, -, -, -, -⟩ |
    ⟨vc, p, w, post, res, -, ho, -⟩
  · rw [(hs.zero x.actionId L.receipts).1, (hs.zero x.actionId L.receipts).2] at e
    omega
  · rw [ho] at e
    have e4 : reversedFrom1 x.actionId L.receipts (.mutated .RECORDED w post res) = 0 := rfl
    have e5 : recordedTo1 x.actionId (.mutated .RECORDED w post res) =
        if rc.paysActionId = some x.actionId then rc.amountCents else 0 := by
      simp [recordedTo1, hp, hr, recordedReceipt, recordedPayment]
    by_cases hpa : rc.paysActionId = some x.actionId
    · have hm : paymentTransition (L.request c) = .mutated .RECORDED w post res := ho
      obtain ⟨x', hx', hid, -, hle⟩ := record_link_within_request (r := L.request c) hcmd hpa hm
      have := eq_of_nodup_map hA hx' hx hid
      subst this
      rw [e4, e5, if_pos hpa] at e
      have hle' : ledgerPaid L x'.actionId + rc.amountCents ≤ x'.amountCents := hle
      omega
    · rw [e4, e5, if_neg hpa] at e
      omega
  · rw [ho] at e
    have e4 : recordedTo1 x.actionId (.mutated .REVERSED w post res) = 0 := rfl
    rw [e4] at e
    omega

theorem run_within : ∀ (calls : List Call) (L : Ledger), Inv L →
    (L.input.actions.map ActionRecord.actionId).Nodup → withinRequests L → withinRequests (run L calls)
  | [], _, _, _, hW => hW
  | c :: cs, L, hI, hA, hW =>
    run_within cs (step L c) (step_Inv c hI) (by rw [step_actions]; exact hA) (step_within c hI hA hW)

theorem run_within_requests (L) (hL : ledgerWellFormed L) (hW : withinRequests L) (calls) :
    withinRequests (run L calls) :=
  run_within calls L (Inv_of_wf hL) (nodup_actions_of_wf hL.1) hW

/-- The paid total correction reads is the one the payment transitions recorded. -/
theorem applyCorrectionTransition_paid_eq_ledger (L : Ledger) (hL : ledgerWellFormed L)
    (request : CorrectionTransitionRequest) (mutation : CorrectionMutation)
    (hRows : request.currentInput.payments = L.input.payments)
    (hLinks : request.command.paymentLinks = linksOf L.receipts)
    (hMutation : (applyCorrectionTransition request).mutation = some mutation) (a : String) :
    correctionPaidCents mutation.dependencies.correctionPaid a = ledgerPaid L a := by
  unfold ledgerPaid
  rw [applyCorrectionTransition_paid_eq_linked request mutation hMutation a, hRows, hLinks]

end BlindLedger.Financial.Payment
