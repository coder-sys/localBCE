import BlindLedger.Financial.Payment.Laws

namespace BlindLedger.Financial.Payment

open BlindLedger.Financial BlindLedger.Financial.CorrectionTransition

/-! Command sequences (design 5.3).  The single-obligation model: `step` is exactly what the
    adapter commits, re-read by the next snapshot (carry premise A1).  Nothing calls this yet. -/

structure Call where
  now : Nat
  expectedRevision : Option Nat
  command : Command

structure Ledger where
  input : FinancialInput
  receipts : List Receipt

/-- The single-obligation model: no foreign ids; inputBytes is the canonical length. -/
def Ledger.request (L : Ledger) (c : Call) : PaymentRequest :=
  { input := { L.input with evaluatedAt := c.now },
    inputBytes := (rawEncodeFinancialInput { L.input with evaluatedAt := c.now }).length,
    receipts := L.receipts, foreign := ⟨false, false⟩,
    expectedRevision := c.expectedRevision, command := c.command }

def Ledger.outcome (L : Ledger) (c : Call) : PaymentOutcome := paymentTransition (L.request c)

def step (L : Ledger) (c : Call) : Ledger :=
  match L.outcome c with
  | .mutated _ w post _ =>
      { input := { post with beforeRevision := post.beforeRevision + 1 },
        receipts := (w.receipt.map fun k => insertBy Receipt.paymentId k L.receipts).getD L.receipts }
  | .alias _ _ post => { L with input := post }
  | _ => L

def run (L : Ledger) (calls : List Call) : Ledger := calls.foldl step L

def trace : Ledger → List Call → List PaymentOutcome
  | _, [] => []
  | L, c :: cs => L.outcome c :: trace (step L c) cs

def ledgerWellFormed (L : Ledger) : Prop :=
  financialInputWellFormed L.input = true ∧ receiptsWellFormed L.input L.receipts = true

def clocksOk (L : Ledger) (calls : List Call) : Prop :=
  (L.input.evaluatedAt :: calls.map Call.now).Pairwise (· ≤ ·) ∧ calls.all (·.now < 2 ^ 63)

/-! What an outcome records, for the "once" and conservation laws. -/

def recordedPaymentId? : PaymentOutcome → Option String
  | .mutated .RECORDED w _ _ => w.payment.map (·.paymentId)
  | _ => none

def recordedOrigin? : PaymentOutcome → Option String
  | .mutated .RECORDED w _ _ => w.payment.map (·.commonOriginId)
  | _ => none

def reversedPaymentId? : PaymentOutcome → Option String
  | .mutated .REVERSED w _ _ => w.payment.map (·.paymentId)
  | _ => none

def insertedEvidenceId? : PaymentOutcome → Option String
  | .mutated _ w _ _ => w.evidence.map (·.evidenceId)
  | .alias _ e _ => some e.evidenceId
  | _ => none

def recordedCent : PaymentOutcome → Nat
  | .mutated .RECORDED w _ _ => (w.payment.map (·.amountCents)).getD 0
  | _ => 0

def reversedCent : PaymentOutcome → Nat
  | .mutated .REVERSED w _ _ => (w.payment.map (·.amountCents)).getD 0
  | _ => 0

def recordedCents (os : List PaymentOutcome) : Nat := (os.map recordedCent).sum
def reversedOutcomeCents (os : List PaymentOutcome) : Nat := (os.map reversedCent).sum

/-! ## List facts -/

theorem mem_insertBy {α} (key : α → String) (row x : α) :
    ∀ l : List α, x ∈ insertBy key row l ↔ x = row ∨ x ∈ l
  | [] => by simp [insertBy]
  | y :: ys => by
      unfold insertBy
      split
      · simp only [List.mem_cons]
      · simp only [List.mem_cons, mem_insertBy key row x ys]; exact or_left_comm

theorem find_insertBy {α} (key : α → String) (row : α) (id : String) :
    ∀ l : List α, l.find? (fun x => decide (key x = key row)) = none →
      (insertBy key row l).find? (fun x => decide (key x = id)) =
        if key row = id then some row else l.find? (fun x => decide (key x = id))
  | [], _ => by simp [insertBy]
  | y :: ys, hf => by
      by_cases hky : key y = key row
      · simp [List.find?_cons, hky] at hf
      · have hys : ys.find? (fun x => decide (key x = key row)) = none := by
          simpa [List.find?_cons, hky] using hf
        unfold insertBy
        split
        · by_cases hr : key row = id <;> simp [List.find?_cons, hr]
        · by_cases hy : key y = id
          · have : key row ≠ id := fun e => hky (hy.trans e.symm)
            simp [List.find?_cons, hy, this]
          · simp [List.find?_cons, hy, find_insertBy key row id ys hys]

theorem map_insertBy {α β} (f : α → β) (ka : α → String) (kb : β → String)
    (hk : ∀ x, kb (f x) = ka x) (row : α) :
    ∀ l : List α, (insertBy ka row l).map f = insertBy kb (f row) (l.map f)
  | [] => by simp [insertBy]
  | y :: ys => by
      simp only [insertBy, List.map_cons, hk]
      by_cases hlt : ka row < ka y <;> simp [hlt, map_insertBy f ka kb hk row ys]

theorem findPayment_eq (l : List Payment) (id : String) :
    findPayment l id = l.find? (fun x => decide (x.paymentId = id)) := by
  induction l with
  | nil => rfl
  | cons x xs ih => by_cases h : x.paymentId = id <;> simp [findPayment, List.find?_cons, h, ih]

theorem findEvidence_eq (l : List EvidenceRecord) (id : String) :
    findEvidence l id = l.find? (fun x => decide (x.evidenceId = id)) := by
  induction l with
  | nil => rfl
  | cons x xs ih => by_cases h : x.evidenceId = id <;> simp [findEvidence, List.find?_cons, h, ih]

theorem findPayment_mem : ∀ {l : List Payment} {id p}, findPayment l id = some p → p ∈ l
  | [], _, _, h => by simp [findPayment] at h
  | x :: xs, _, p, h => by
      unfold findPayment at h
      split at h
      · simp only [Option.some.injEq] at h; subst h; exact List.mem_cons_self ..
      · exact List.mem_cons_of_mem _ (findPayment_mem h)

theorem find_of_mem {α} (key : α → String) : ∀ {l : List α} {x : α},
    (l.map key).Nodup → x ∈ l → l.find? (fun y => decide (key y = key x)) = some x
  | y :: ys, x, hn, hm => by
      rw [List.map_cons, List.nodup_cons] at hn
      by_cases h : key y = key x
      · rcases List.mem_cons.1 hm with rfl | hm'
        · simp [List.find?_cons]
        · exact absurd (by rw [h]; exact List.mem_map.2 ⟨x, hm', rfl⟩) hn.1
      · rcases List.mem_cons.1 hm with rfl | hm'
        · exact absurd rfl h
        · simp [List.find?_cons, h, find_of_mem key hn.2 hm']

theorem findPayment_of_mem {l : List Payment} {x : Payment}
    (hn : (l.map Payment.paymentId).Nodup) (hm : x ∈ l) : findPayment l x.paymentId = some x := by
  rw [findPayment_eq]; exact find_of_mem Payment.paymentId hn hm

theorem applyWrites_payments_insert {i w p} (hw : w.payment = some p)
    (hf : findPayment i.payments p.paymentId = none) :
    (applyWrites i w).payments = insertBy Payment.paymentId p i.payments := by
  simp [applyWrites, hw, hf]

theorem applyWrites_payments_none {i w} (hw : w.payment = none) :
    (applyWrites i w).payments = i.payments := by
  simp [applyWrites, hw]

theorem found_reversed {l : List Payment} {p c} (hf : findPayment l c.paymentId = some p) :
    findPayment l (reversedImage p c).paymentId = some p := by
  show findPayment l p.paymentId = some p
  rw [findPayment_id l c.paymentId p hf]; exact hf

/-! ## One step -/

deriving instance Inhabited for OwnerMode, Provenance, VerificationStatus, CaseStatus, DeliveryStatus,
  FinancialContext, FinancialResult, EvidenceRecord

/-- Neither a payment record nor a reversal: no cash, origin or payment id moves. -/
def Silent (o : PaymentOutcome) : Prop :=
  (∀ w p r, o ≠ .mutated .RECORDED w p r) ∧ (∀ w p r, o ≠ .mutated .REVERSED w p r)

theorem silent_of_ne {o} (h : ∀ k w p r, o ≠ .mutated k w p r) : Silent o :=
  ⟨fun w p r => h _ w p r, fun w p r => h _ w p r⟩

theorem Silent.fields {o} (h : Silent o) : recordedPaymentId? o = none ∧ recordedOrigin? o = none ∧
    reversedPaymentId? o = none ∧ recordedCent o = 0 ∧ reversedCent o = 0 := by
  rcases o with ⟨k, w, p, r⟩ | _ | _ | _ | _
  · cases k
    · exact absurd rfl (h.1 w p r)
    · exact absurd rfl (h.2 w p r)
    · exact ⟨rfl, rfl, rfl, rfl, rfl⟩
  all_goals exact ⟨rfl, rfl, rfl, rfl, rfl⟩

theorem step_cases (L : Ledger) (c : Call) :
    (∃ k w post res, L.outcome c = .mutated k w post res ∧ step L c =
      { input := { post with beforeRevision := post.beforeRevision + 1 },
        receipts := (w.receipt.map fun k => insertBy Receipt.paymentId k L.receipts).getD
          L.receipts }) ∨
    (∃ pid e post, L.outcome c = .alias pid e post ∧ step L c = { L with input := post }) ∨
    (Silent (L.outcome c) ∧ insertedEvidenceId? (L.outcome c) = none ∧ step L c = L) := by
  unfold step
  cases ho : L.outcome c with
  | mutated k w post res => exact Or.inl ⟨k, w, post, res, rfl, rfl⟩
  | alias pid e post => exact Or.inr (Or.inl ⟨pid, e, post, rfl, rfl⟩)
  | _ => exact Or.inr (Or.inr ⟨silent_of_ne fun _ _ _ _ h => (by cases h), rfl, rfl⟩)

theorem step_unchanged_of_quiet (L c) (h : ∀ k w post res pid e post', L.outcome c ≠ .mutated k w post res ∧
    L.outcome c ≠ .alias pid e post') : step L c = L := by
  unfold step
  cases ho : L.outcome c with
  | mutated k w post res => exact absurd ho (h k w post res "" default post).1
  | alias pid e post => exact absurd ho (h .RECORDED ⟨none, none, none, none⟩ post default pid e post).2
  | _ => rfl

theorem step_context (L c) : (step L c).input.context = L.input.context := by
  rcases step_cases L c with ⟨k, w, post, res, ho, he⟩ | ⟨pid, e, post, ho, he⟩ | ⟨-, -, he⟩ <;> rw [he]
  · dsimp only; rw [(paymentTransition_mutated_post ho).1]; rfl
  · dsimp only; rw [(alias_shape ho).1]; rfl

theorem mutated_fresh {r k w post res} (h : paymentTransition r = .mutated k w post res) :
    ∀ e, w.evidence = some e → findEvidence r.input.evidence e.evidenceId = none := by
  intro e he
  rcases mutated_shape h with
    ⟨-, c, -, -, -, -, -, -, hew, -⟩ | ⟨-, c, -, -, -, hew⟩ | ⟨-, c, p, e', -, -, -, hw, hr, hfe, -, -⟩
  · rcases hew.2.2.2 with ⟨h1, h2⟩ | ⟨h1, -⟩
    · rw [h1] at he; cases he; exact h2
    · rw [h1] at he; cases he
  · rcases hew.2.2.2 with ⟨h1, h2⟩ | ⟨h1, -⟩
    · rw [h1] at he; cases he; exact h2
    · rw [h1] at he; cases he
  · subst hw; cases he; rw [hr]; exact hfe

theorem findEvidence_applyWrites {i w id s}
    (hfresh : ∀ e, w.evidence = some e → findEvidence i.evidence e.evidenceId = none)
    (h : findEvidence i.evidence id = some s) :
    findEvidence (applyWrites i w).evidence id = some s := by
  cases hw : w.evidence with
  | none => simpa [applyWrites, hw] using h
  | some e =>
    have hf := hfresh e hw
    simp only [applyWrites, hw, Option.map_some, Option.getD_some]
    rw [findEvidence_eq] at hf h ⊢
    rw [find_insertBy EvidenceRecord.evidenceId e id i.evidence hf]
    have hne : e.evidenceId ≠ id := fun eq => by rw [eq, h] at hf; simp at hf
    simpa [hne] using h

theorem step_evidence (L c) {id s} (h : findEvidence L.input.evidence id = some s) :
    findEvidence (step L c).input.evidence id = some s := by
  rcases step_cases L c with ⟨k, w, post, res, ho, he⟩ | ⟨pid, e, post, ho, he⟩ | ⟨-, -, he⟩ <;> rw [he]
  · dsimp only; rw [(paymentTransition_mutated_post ho).1]
    exact findEvidence_applyWrites (mutated_fresh ho) h
  · dsimp only; rw [(alias_shape ho).1]
    exact findEvidence_applyWrites (fun e' hw => by cases hw; exact (alias_shape ho).2.2) h
  · exact h

theorem findPayment_insertBy {p : Payment} {l pid} (hf : findPayment l p.paymentId = none) :
    findPayment (insertBy Payment.paymentId p l) pid =
      if p.paymentId = pid then some p else findPayment l pid := by
  rw [findPayment_eq, findPayment_eq, find_insertBy _ p pid l (by rwa [← findPayment_eq])]

theorem findPayment_replace (l : List Payment) (p0 p' : Payment) (hid : p'.paymentId = p0.paymentId)
    (pid : String) :
    findPayment (l.map fun x => if x.paymentId = p0.paymentId then p' else x) pid =
      (findPayment l pid).map fun x => if x.paymentId = p0.paymentId then p' else x := by
  induction l with
  | nil => rfl
  | cons x xs ih =>
    have hfx : (if x.paymentId = p0.paymentId then p' else x).paymentId = x.paymentId := by
      by_cases hx : x.paymentId = p0.paymentId <;> simp [hx, hid]
    simp only [List.map_cons, findPayment, hfx]
    by_cases h : x.paymentId = pid <;> simp [h, ih]

/-- Every step is silent, records one payment, or reverses one. -/
theorem step_kind (L : Ledger) (c : Call) :
    (Silent (L.outcome c) ∧ (step L c).input.payments = L.input.payments ∧
      (step L c).receipts = L.receipts) ∨
    (∃ rc w post res, c.command = .record rc ∧ L.outcome c = .mutated .RECORDED w post res ∧
      w.payment = some (recordedPayment (L.request c).input rc) ∧
      w.receipt = some (recordedReceipt (L.request c).input rc) ∧
      findPayment L.input.payments rc.paymentId = none ∧
      (∀ q ∈ L.input.payments, q.commonOriginId ≠ rc.commonOriginId) ∧
      revisionOk (L.request c) = true ∧ EvidenceWrite (L.request c) rc w.evidence ∧
      ((step L c).input.payments.map Payment.paymentId).Nodup ∧
      (step L c).input.payments =
        insertBy Payment.paymentId (recordedPayment (L.request c).input rc) L.input.payments ∧
      (step L c).receipts =
        insertBy Receipt.paymentId (recordedReceipt (L.request c).input rc) L.receipts) ∨
    (∃ vc p w post res, c.command = .reverse vc ∧ L.outcome c = .mutated .REVERSED w post res ∧
      findPayment L.input.payments vc.paymentId = some p ∧ p.status ≠ .REVERSED ∧
      w.payment = some (reversedImage p vc) ∧ ((step L c).input.payments.map Payment.paymentId).Nodup ∧
      (step L c).input.payments = L.input.payments.map
        (fun x => if x.paymentId = p.paymentId then reversedImage p vc else x) ∧
      (step L c).receipts = L.receipts) := by
  rcases step_cases L c with ⟨k, w, post, res, ho, he⟩ | ⟨pid, e, post, ho, he⟩ | ⟨hs, -, he⟩
  · have h : paymentTransition (L.request c) = .mutated k w post res := ho
    obtain ⟨hpost, hwf, -⟩ := paymentTransition_mutated_post h
    have hnd : ((step L c).input.payments.map Payment.paymentId).Nodup := by
      rw [he]; exact nodup_ids_of_wf (i := post) hwf
    rcases mutated_shape h with
      ⟨rfl, rc, hcmd, hf, hor, hp, hr, -, hew, hrev⟩ | ⟨rfl, rc, -, hp, hr, -⟩ |
      ⟨rfl, vc, p, e, hcmd, hf, hst, hw, -, -, -, -⟩
    · refine Or.inr (Or.inl ⟨rc, w, post, res, hcmd, ho, hp, hr, hf, hor, hrev, hew, hnd, ?_, ?_⟩)
      · rw [he]; show post.payments = _
        rw [hpost]; exact applyWrites_payments_insert hp hf
      · rw [he]; simp only [hr, Option.map_some, Option.getD_some]
    · refine Or.inl ⟨by rw [ho]; exact ⟨fun _ _ _ h => (by cases h), fun _ _ _ h => (by cases h)⟩, ?_, ?_⟩
      · rw [he]; exact (conflict_changes_no_cash h).1
      · rw [he]; simp only [hr, Option.map_none, Option.getD_none]
    · subst hw
      have hs : (findPayment (L.request c).input.payments p.paymentId).isSome = true := by simp [findPayment_id _ _ _ hf, hf]
      refine Or.inr (Or.inr ⟨vc, p, _, post, res, hcmd, ho, hf, hst, rfl, hnd, ?_, ?_⟩)
      · rw [he]; show post.payments = _
        rw [hpost]
        simp only [applyWrites, hs, ↓reduceIte, reversedImage] <;> rfl
      · rw [he]; simp only [Option.map_none, Option.getD_none]
  · refine Or.inl ⟨by rw [ho]; exact ⟨fun _ _ _ h => (by cases h), fun _ _ _ h => (by cases h)⟩, ?_, by rw [he]⟩
    rw [he]; show post.payments = _
    rw [(alias_shape ho).1]; rfl
  · exact Or.inl ⟨hs, by rw [he], by rw [he]⟩

theorem step_find (L c) {pid p} (h : findPayment L.input.payments pid = some p) :
    ∃ q, findPayment (step L c).input.payments pid = some q ∧
      (q = p ∨ ∃ e, q = { p with status := .REVERSED, reversalEvidenceId := some e }) := by
  rcases step_kind L c with ⟨-, hp, -⟩ | ⟨rc, w, post, res, -, -, -, -, hf, -, -, -, -, hp, -⟩ |
    ⟨vc, p0, w, post, res, -, -, hf, -, -, -, hp, -⟩
  · exact ⟨p, by rw [hp]; exact h, Or.inl rfl⟩
  · have hne : (recordedPayment (L.request c).input rc).paymentId ≠ pid := fun e => by
      have e' : rc.paymentId = pid := e
      rw [e', h] at hf; exact absurd hf (by simp)
    refine ⟨p, ?_, Or.inl rfl⟩
    rw [hp, findPayment_insertBy (p := recordedPayment (L.request c).input rc) hf, if_neg hne, h]
  · have hid := findPayment_id _ _ _ hf
    rw [hp, findPayment_replace L.input.payments p0 (reversedImage p0 vc) rfl, h]
    by_cases hpp : p.paymentId = p0.paymentId
    · have hpv : pid = vc.paymentId := (findPayment_id _ _ _ h).symm.trans (hpp.trans hid)
      subst hpv
      have hp0 : p0 = p := Option.some.inj (hf.symm.trans h)
      subst hp0
      exact ⟨_, by simp [reversedImage], Or.inr ⟨vc.evidenceId, rfl⟩⟩
    · exact ⟨p, by simp [hpp], Or.inl rfl⟩

theorem findPayment_reversed {l : List Payment} {p vc} (hf : findPayment l vc.paymentId = some p) :
    findPayment (l.map fun x => if x.paymentId = p.paymentId then reversedImage p vc else x)
      vc.paymentId = some (reversedImage p vc) := by
  rw [findPayment_replace l p (reversedImage p vc) rfl, hf]; simp

theorem step_payments_mutated {L c k w post res} (ho : L.outcome c = .mutated k w post res) :
    (step L c).input.payments = post.payments := by
  simp only [step, ho]

theorem step_recorded {L c w post res} (h : L.outcome c = .mutated .RECORDED w post res) :
    ∃ rc, c.command = .record rc ∧ w.payment = some (recordedPayment (L.request c).input rc) ∧
      w.receipt = some (recordedReceipt (L.request c).input rc) ∧
      findPayment L.input.payments rc.paymentId = none ∧ revisionOk (L.request c) = true ∧
      EvidenceWrite (L.request c) rc w.evidence ∧
      (step L c).input.payments =
        insertBy Payment.paymentId (recordedPayment (L.request c).input rc) L.input.payments ∧
      (step L c).receipts =
        insertBy Receipt.paymentId (recordedReceipt (L.request c).input rc) L.receipts := by
  rcases step_kind L c with ⟨hs, -⟩ | ⟨rc, w', post', res', hcmd, ho, hp, hr, hf, -, hrev, hew, -, hpay, hrec⟩ |
    ⟨_, _, _, _, _, _, ho, _⟩
  · exact absurd h (hs.1 w post res)
  · cases h.symm.trans ho; exact ⟨rc, hcmd, hp, hr, hf, hrev, hew, hpay, hrec⟩
  · cases h.symm.trans ho

/-! ## The invariant every step keeps -/

def Inv (L : Ledger) : Prop :=
  (L.input.payments.map Payment.paymentId).Nodup ∧
    L.receipts.map Receipt.paymentId = L.input.payments.map Payment.paymentId

theorem Inv_of_wf {L} (hL : ledgerWellFormed L) : Inv L := by
  refine ⟨nodup_ids_of_wf hL.1, ?_⟩
  have := hL.2
  simp only [receiptsWellFormed, Bool.and_eq_true, beq_iff_eq] at this
  exact this.1

theorem step_Inv {L : Ledger} (c) (hI : Inv L) : Inv (step L c) := by
  rcases step_kind L c with ⟨-, hp, hr⟩ | ⟨rc, w, post, res, -, -, -, -, -, -, -, -, hnd, hp, hr⟩ |
    ⟨vc, p, w, post, res, -, -, -, -, -, hnd, hp, hr⟩
  · unfold Inv; rw [hp, hr]; exact hI
  · refine ⟨hnd, ?_⟩
    rw [hr, hp, map_insertBy Receipt.paymentId Receipt.paymentId id (fun _ => rfl),
      map_insertBy Payment.paymentId Payment.paymentId id (fun _ => rfl), hI.2] <;> rfl
  · refine ⟨hnd, ?_⟩
    rw [hr, hp, hI.2, List.map_map]
    exact List.map_congr_left fun x _ => by
      by_cases hx : x.paymentId = p.paymentId <;> simp [Function.comp, hx, reversedImage]

theorem run_cons (L c cs) : run L (c :: cs) = run (step L c) cs := rfl

theorem run_Inv {L : Ledger} (hI : Inv L) : ∀ calls, Inv (run L calls)
  | [] => hI
  | c :: cs => run_Inv (step_Inv c hI) cs

theorem receiptOf_none {L : Ledger} (hI : Inv L) {id} (hf : findPayment L.input.payments id = none) :
    receiptOf L.receipts id = none := by
  unfold receiptOf
  rw [List.find?_eq_none]
  intro x hx hxe
  have hm : x.paymentId ∈ L.input.payments.map Payment.paymentId := by
    rw [← hI.2]; exact List.mem_map.2 ⟨x, hx, rfl⟩
  obtain ⟨y, hy, hyx⟩ := List.mem_map.1 hm
  rw [findPayment_eq, List.find?_eq_none] at hf
  exact hf y hy (by simp [hyx, of_decide_eq_true hxe])

theorem receiptOf_insertBy {K : Receipt} {rs id} (hf : receiptOf rs K.paymentId = none) :
    receiptOf (insertBy Receipt.paymentId K rs) id =
      if K.paymentId = id then some K else receiptOf rs id :=
  find_insertBy _ K id rs hf

theorem step_receipt {L : Ledger} (c) (hI : Inv L) {id k} (h : receiptOf L.receipts id = some k) :
    receiptOf (step L c).receipts id = some k := by
  rcases step_kind L c with ⟨-, -, hr⟩ | ⟨rc, w, post, res, -, -, -, -, hf, -, -, -, -, -, hr⟩ |
    ⟨-, -, -, -, -, -, -, -, -, -, -, -, hr⟩
  · rw [hr]; exact h
  · have hn := receiptOf_none hI hf
    have hne : (recordedReceipt (L.request c).input rc).paymentId ≠ id := fun e => by
      have e' : rc.paymentId = id := e
      rw [e', h] at hn; exact absurd hn (by simp)
    rw [hr, receiptOf_insertBy (K := recordedReceipt (L.request c).input rc) hn, if_neg hne]
    exact h
  · rw [hr]; exact h

/-! ## Something happens once -/

theorem findEvidence_insertBy {e : EvidenceRecord} {l id} (hf : findEvidence l e.evidenceId = none) :
    findEvidence (insertBy EvidenceRecord.evidenceId e l) id =
      if e.evidenceId = id then some e else findEvidence l id := by
  rw [findEvidence_eq, findEvidence_eq, find_insertBy _ e id l (by rwa [← findEvidence_eq])]

theorem step_inserts {L c eid} (hE : insertedEvidenceId? (L.outcome c) = some eid) :
    findEvidence L.input.evidence eid = none ∧ (findEvidence (step L c).input.evidence eid).isSome = true := by
  rcases step_cases L c with ⟨k, w, post, res, ho, he⟩ | ⟨pid, e, post, ho, he⟩ | ⟨-, hn, -⟩
  · rw [ho] at hE
    cases hw : w.evidence with
    | none => simp [insertedEvidenceId?, hw] at hE
    | some e =>
      simp only [insertedEvidenceId?, hw, Option.map_some, Option.some.injEq] at hE
      subst hE
      have hf := mutated_fresh ho e hw
      refine ⟨hf, ?_⟩
      rw [he]; dsimp only; rw [(paymentTransition_mutated_post ho).1]
      simp only [applyWrites, hw, Option.map_some, Option.getD_some]
      rw [findEvidence_insertBy hf, if_pos rfl]; rfl
  · rw [ho] at hE
    simp only [insertedEvidenceId?, Option.some.injEq] at hE
    subst hE
    obtain ⟨hpost, -, hf⟩ := alias_shape ho
    refine ⟨hf, ?_⟩
    rw [he]; dsimp only; rw [hpost]
    simp only [applyWrites, Option.map_some, Option.getD_some]
    rw [findEvidence_insertBy hf, if_pos rfl]; rfl
  · rw [hn] at hE; cases hE

/-- If a thing can only appear once it is absent, it stays once it is there, and every
    step that makes it appear finds it absent. -/
theorem once_generic (Has : Ledger → Bool) (E : PaymentOutcome → Bool)
    (mono : ∀ L c, Inv L → Has L = true → Has (step L c) = true)
    (ev : ∀ L c, Inv L → E (L.outcome c) = true → Has L = false ∧ Has (step L c) = true) :
    ∀ (calls : List Call) (L : Ledger), Inv L →
      ((trace L calls).filter E).length + (if Has L = true then 1 else 0) ≤ 1
  | [], L, _ => by split <;> simp [trace]
  | c :: cs, L, hI => by
    have ih := once_generic Has E mono ev cs (step L c) (step_Inv c hI)
    have hm : (if Has L = true then 1 else 0) ≤ (if Has (step L c) = true then 1 else 0) := by
      by_cases h : Has L = true
      · simp [h, mono L c hI h]
      · simp [h]
    simp only [trace, List.filter_cons]
    cases hE : E (L.outcome c)
    · simp only [Bool.false_eq_true, ↓reduceIte]; omega
    · obtain ⟨h0, h1⟩ := ev L c hI hE
      simp [h0, h1] at ih ⊢
      omega

theorem run_records_payment_once (L : Ledger) (hL : ledgerWellFormed L) (calls) (hc : clocksOk L calls)
    (pid : String) :
    ((trace L calls).filter (recordedPaymentId? · = some pid)).length +
      (if (findPayment L.input.payments pid).isSome then 1 else 0) ≤ 1 :=
  once_generic (fun L => (findPayment L.input.payments pid).isSome)
    (fun o => decide (recordedPaymentId? o = some pid))
    (fun L c _ h => by
      obtain ⟨p, hp⟩ := Option.isSome_iff_exists.1 h
      obtain ⟨q, hq, -⟩ := step_find L c hp
      simp [hq])
    (fun L c _ hE => by
      rcases step_kind L c with ⟨hs, -⟩ | ⟨rc, w, post, res, -, ho, hp, -, hf, -, -, -, -, hpay, -⟩ |
        ⟨_, _, _, _, _, _, ho, _⟩
      · simp [hs.fields.1] at hE
      · simp only [ho, hp, recordedPaymentId?, Option.map_some, decide_eq_true_eq,
          Option.some.injEq] at hE
        subst hE
        refine ⟨?_, ?_⟩
        · show (findPayment L.input.payments rc.paymentId).isSome = false
          simp [hf]
        · rw [hpay, findPayment_insertBy (p := recordedPayment (L.request c).input rc) hf]; simp
      · simp [ho, recordedPaymentId?] at hE)
    calls L (Inv_of_wf hL)

theorem run_records_origin_once (L) (hL : ledgerWellFormed L) (calls) (hc : clocksOk L calls) (o : String) :
    ((trace L calls).filter (recordedOrigin? · = some o)).length +
      (if L.input.payments.any (·.commonOriginId = o) then 1 else 0) ≤ 1 :=
  once_generic (fun L => L.input.payments.any (·.commonOriginId = o))
    (fun x => decide (recordedOrigin? x = some o))
    (fun L c hI h => by
      obtain ⟨x, hx, hxo⟩ := List.any_eq_true.1 h
      obtain ⟨q, hq, hc⟩ := step_find L c (findPayment_of_mem hI.1 hx)
      have hqo : q.commonOriginId = x.commonOriginId := by rcases hc with rfl | ⟨e, rfl⟩ <;> rfl
      exact List.any_eq_true.2 ⟨q, findPayment_mem hq, by simpa [hqo] using hxo⟩)
    (fun L c _ hE => by
      rcases step_kind L c with ⟨hs, -⟩ | ⟨rc, w, post, res, -, ho, hp, -, -, hor, -, -, -, hpay, -⟩ |
        ⟨_, _, _, _, _, _, ho, _⟩
      · simp [hs.fields.2.1] at hE
      · simp only [ho, hp, recordedOrigin?, Option.map_some, decide_eq_true_eq,
          Option.some.injEq] at hE
        subst hE
        refine ⟨?_, ?_⟩
        · rw [Bool.eq_false_iff]
          intro h
          obtain ⟨q, hq, hqo⟩ := List.any_eq_true.1 h
          exact hor q hq (of_decide_eq_true hqo)
        · exact List.any_eq_true.2 ⟨recordedPayment (L.request c).input rc,
            by rw [hpay]; exact (mem_insertBy _ _ _ _).2 (Or.inl rfl), by simp⟩
      · simp [ho, recordedOrigin?] at hE)
    calls L (Inv_of_wf hL)

theorem run_reverses_once (L) (hL : ledgerWellFormed L) (calls) (hc : clocksOk L calls) (pid : String) :
    ((trace L calls).filter (reversedPaymentId? · = some pid)).length +
      (if (findPayment L.input.payments pid).any (·.status = .REVERSED) then 1 else 0) ≤ 1 :=
  once_generic (fun L => (findPayment L.input.payments pid).any (·.status = .REVERSED))
    (fun x => decide (reversedPaymentId? x = some pid))
    (fun L c _ h => by
      cases hp : findPayment L.input.payments pid with
      | none => simp [hp] at h
      | some p =>
        simp only [hp, Option.any_some, decide_eq_true_eq] at h
        obtain ⟨q, hq, hc⟩ := step_find L c hp
        have hqs : q.status = .REVERSED := by
          rcases hc with rfl | ⟨e, rfl⟩
          · exact h
          · rfl
        simp [hq, hqs])
    (fun L c _ hE => by
      rcases step_kind L c with ⟨hs, -⟩ | ⟨_, _, _, _, _, ho, _⟩ |
        ⟨vc, p, w, post, res, -, ho, hf, hst, hw, -, hpay, -⟩
      · simp [hs.fields.2.2.1] at hE
      · simp [ho, reversedPaymentId?] at hE
      · simp only [ho, hw, reversedPaymentId?, Option.map_some, decide_eq_true_eq,
          Option.some.injEq] at hE
        have e : pid = vc.paymentId := hE.symm.trans (findPayment_id _ _ p hf)
        subst e
        refine ⟨?_, ?_⟩
        · rw [hf]; simp [hst]
        · rw [hpay, findPayment_reversed hf]; simp [reversedImage])
    calls L (Inv_of_wf hL)

theorem run_inserts_evidence_once (L) (hL : ledgerWellFormed L) (calls) (hc : clocksOk L calls)
    (eid : String) :
    ((trace L calls).filter (insertedEvidenceId? · = some eid)).length +
      (if (findEvidence L.input.evidence eid).isSome then 1 else 0) ≤ 1 :=
  once_generic (fun L => (findEvidence L.input.evidence eid).isSome)
    (fun x => decide (insertedEvidenceId? x = some eid))
    (fun L c _ h => by
      obtain ⟨s, hs⟩ := Option.isSome_iff_exists.1 h
      simp [step_evidence L c hs])
    (fun L c _ hE => by
      obtain ⟨h0, h1⟩ := step_inserts (of_decide_eq_true hE)
      exact ⟨by simp [h0], h1⟩)
    calls L (Inv_of_wf hL)

end BlindLedger.Financial.Payment
