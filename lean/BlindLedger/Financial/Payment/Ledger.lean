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
      (step L c).receipts = L.receipts ∧
      ∃ e, w.evidence = some e ∧
        e = reversalRecord (L.request c).input vc p (vc.eventAt.getD (L.request c).input.evaluatedAt) ∧
        findEvidence L.input.evidence vc.evidenceId = none ∧
        e.eventAt ≤ (L.request c).input.evaluatedAt ∧ formRefusal e = none) := by
  rcases step_cases L c with ⟨k, w, post, res, ho, he⟩ | ⟨pid, e, post, ho, he⟩ | ⟨hs, -, he⟩
  · have h : paymentTransition (L.request c) = .mutated k w post res := ho
    obtain ⟨hpost, hwf, -⟩ := paymentTransition_mutated_post h
    have hnd : ((step L c).input.payments.map Payment.paymentId).Nodup := by
      rw [he]; exact nodup_ids_of_wf (i := post) hwf
    rcases mutated_shape h with
      ⟨rfl, rc, hcmd, hf, hor, hp, hr, -, hew, hrev⟩ | ⟨rfl, rc, -, hp, hr, -⟩ |
      ⟨rfl, vc, p, e, hcmd, hf, hst, hw, he', hfe, hle, hform⟩
    · refine Or.inr (Or.inl ⟨rc, w, post, res, hcmd, ho, hp, hr, hf, hor, hrev, hew, hnd, ?_, ?_⟩)
      · rw [he]; show post.payments = _
        rw [hpost]; exact applyWrites_payments_insert hp hf
      · rw [he]; simp only [hr, Option.map_some, Option.getD_some]
    · refine Or.inl ⟨by rw [ho]; exact ⟨fun _ _ _ h => (by cases h), fun _ _ _ h => (by cases h)⟩, ?_, ?_⟩
      · rw [he]; exact (conflict_changes_no_cash h).1
      · rw [he]; simp only [hr, Option.map_none, Option.getD_none]
    · subst hw
      have hs : (findPayment (L.request c).input.payments p.paymentId).isSome = true := by simp [findPayment_id _ _ _ hf, hf]
      refine Or.inr (Or.inr ⟨vc, p, _, post, res, hcmd, ho, hf, hst, rfl, hnd, ?_, ?_, e, rfl, he', hfe, hle, hform⟩)
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
    ⟨vc, p, w, post, res, -, -, -, -, -, hnd, hp, hr, -⟩
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
    ⟨-, -, -, -, -, -, -, -, -, -, -, -, hr, -⟩
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

theorem step_mutated {L c k w post res} (ho : L.outcome c = .mutated k w post res) :
    (step L c).input = { post with beforeRevision := post.beforeRevision + 1 } := by
  simp only [step, ho]

theorem step_mutated_evidence {L c k w post res e} (ho : L.outcome c = .mutated k w post res)
    (hw : w.evidence = some e) : findEvidence (step L c).input.evidence e.evidenceId = some e := by
  have hf := mutated_fresh ho e hw
  rw [step_mutated ho, (paymentTransition_mutated_post ho).1]
  simp only [applyWrites, hw, Option.map_some, Option.getD_some]
  rw [findEvidence_insertBy hf, if_pos rfl]

theorem step_inserts {L c eid} (hE : insertedEvidenceId? (L.outcome c) = some eid) :
    findEvidence L.input.evidence eid = none ∧ (findEvidence (step L c).input.evidence eid).isSome = true := by
  rcases step_cases L c with ⟨k, w, post, res, ho, he⟩ | ⟨pid, e, post, ho, he⟩ | ⟨-, hn, -⟩
  · rw [ho] at hE
    cases hw : w.evidence with
    | none => simp [insertedEvidenceId?, hw] at hE
    | some e =>
      simp only [insertedEvidenceId?, hw, Option.map_some, Option.some.injEq] at hE
      subst hE
      refine ⟨mutated_fresh ho e hw, ?_⟩
      rw [step_mutated_evidence ho hw]; rfl
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
      obtain ⟨q, hq, hcq⟩ := step_find L c (findPayment_of_mem hI.1 hx)
      have hqo : q.commonOriginId = x.commonOriginId := by rcases hcq with rfl | ⟨e, rfl⟩ <;> rfl
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

/-! ## Rows only grow; cash is conserved -/

theorem step_rows {L : Ledger} (c) (hI : Inv L) {x} (hx : x ∈ L.input.payments) :
    ∃ q ∈ (step L c).input.payments, q.paymentId = x.paymentId ∧
      { q with status := x.status, reversalEvidenceId := x.reversalEvidenceId } = x := by
  obtain ⟨q, hq, hc⟩ := step_find L c (findPayment_of_mem hI.1 hx)
  refine ⟨q, findPayment_mem hq, findPayment_id _ _ _ hq, ?_⟩
  rcases hc with rfl | ⟨e, rfl⟩ <;> rfl

theorem run_rows {L : Ledger} (hI : Inv L) : ∀ (calls : List Call), ∀ p ∈ L.input.payments,
    ∃ q ∈ (run L calls).input.payments, q.paymentId = p.paymentId ∧
      { q with status := p.status, reversalEvidenceId := p.reversalEvidenceId } = p
  | [], p, hp => ⟨p, hp, rfl, rfl⟩
  | c :: cs, p, hp => by
    obtain ⟨q1, hq1, hid1, heq1⟩ := step_rows c hI hp
    obtain ⟨q2, hq2, hid2, heq2⟩ := run_rows (step_Inv c hI) cs q1 hq1
    refine ⟨q2, hq2, hid2.trans hid1, ?_⟩
    have : { q2 with status := p.status, reversalEvidenceId := p.reversalEvidenceId } =
        { q1 with status := p.status, reversalEvidenceId := p.reversalEvidenceId } := by
      rw [← heq2] <;> rfl
    exact this.trans heq1

theorem run_rows_append_only (L) (hL : ledgerWellFormed L) (calls) (hc : clocksOk L calls) :
    ∀ p ∈ L.input.payments, ∃ q ∈ (run L calls).input.payments, q.paymentId = p.paymentId ∧
      { q with status := p.status, reversalEvidenceId := p.reversalEvidenceId } = p :=
  run_rows (Inv_of_wf hL) calls

theorem step_conserve (L c) :
    activeCents (step L c).input.payments + reversedCent (L.outcome c) =
      activeCents L.input.payments + recordedCent (L.outcome c) := by
  rcases step_kind L c with ⟨hs, hp, -⟩ | ⟨rc, w, post, res, -, ho, hp, -, -, -, -, -, -, hpay, -⟩ |
    ⟨vc, _, w, post, res, hcmd, ho, _⟩
  · rw [hp, hs.fields.2.2.2.1, hs.fields.2.2.2.2]
  · have e1 : reversedCent (L.outcome c) = 0 := by rw [ho]; rfl
    have e2 : recordedCent (L.outcome c) = (recordedPayment (L.request c).input rc).amountCents := by
      rw [ho]; simp [recordedCent, hp]
    rw [e1, e2, hpay, activeCents_eq, activeCents_eq, sum_insertBy]
    simp [recordedPayment] <;> omega
  · obtain ⟨p', -, -, hw', -, hact, -⟩ := reverse_exact (r := L.request c) hcmd ho
    have e1 : reversedCent (L.outcome c) = p'.amountCents := by rw [ho]; simp [reversedCent, hw']
    have e2 : recordedCent (L.outcome c) = 0 := by rw [ho]; rfl
    have hact' : activeCents post.payments + p'.amountCents = activeCents L.input.payments := hact
    rw [step_payments_mutated ho, e1, e2]; omega

theorem conserve_gen : ∀ (calls : List Call) (L : Ledger),
    activeCents (run L calls).input.payments + reversedOutcomeCents (trace L calls) =
      activeCents L.input.payments + recordedCents (trace L calls)
  | [], L => by simp [run, trace, reversedOutcomeCents, recordedCents]
  | c :: cs, L => by
    have ih := conserve_gen cs (step L c)
    have h := step_conserve L c
    simp only [run_cons, trace, reversedOutcomeCents, recordedCents, List.map_cons,
      List.sum_cons] at ih ⊢
    omega

theorem run_conservation (L : Ledger) (hL : ledgerWellFormed L) (calls) (hc : clocksOk L calls) :
    activeCents (run L calls).input.payments + reversedOutcomeCents (trace L calls) =
      activeCents L.input.payments + recordedCents (trace L calls) :=
  conserve_gen calls L

theorem mem_trace : ∀ (calls : List Call) (L : Ledger) {o}, o ∈ trace L calls →
    ∃ (M : Ledger) (c : Call), o = M.outcome c
  | [], _, _, h => by simp [trace] at h
  | c :: cs, L, o, h => by
    simp only [trace, List.mem_cons] at h
    rcases h with rfl | h
    · exact ⟨L, c, rfl⟩
    · exact mem_trace cs (step L c) h

/-- From an obligation with no payments: the paid total is recorded minus reversed, and
    it is exactly what every evaluation Lean returned reports as received cash. -/
theorem run_paid_total (L) (hL : ledgerWellFormed L) (h0 : L.input.payments = []) (calls)
    (hc : clocksOk L calls) :
    activeCents (run L calls).input.payments + reversedOutcomeCents (trace L calls) =
      recordedCents (trace L calls) ∧
    ∀ o ∈ trace L calls, ∀ k w post res, o = .mutated k w post res →
      res.receivedCashCents = activeCents post.payments := by
  refine ⟨?_, fun o ho k w post res h => ?_⟩
  · have := conserve_gen calls L
    rw [h0] at this
    simpa [activeCents] using this
  · obtain ⟨M, c, rfl⟩ := mem_trace calls L ho
    exact paymentTransition_result_cash h

theorem record_then_reverse_restores (L) (hL : ledgerWellFormed L) (rc : RecordCommand)
    (vc : ReverseCommand) (c1 c2 : Call) (h1 : c1.command = .record rc) (h2 : c2.command = .reverse vc)
    (hp : vc.paymentId = rc.paymentId)
    (hm1 : ∃ w post res, L.outcome c1 = .mutated .RECORDED w post res)
    (hm2 : ∃ w post res, (step L c1).outcome c2 = .mutated .REVERSED w post res) :
    activeCents (step (step L c1) c2).input.payments = activeCents L.input.payments := by
  obtain ⟨w1, post1, res1, ho1⟩ := hm1
  obtain ⟨w2, post2, res2, ho2⟩ := hm2
  obtain ⟨rc', hcmd', -, -, hf, -, -, hpay, -⟩ := step_recorded ho1
  have hrc : rc' = rc := Command.record.inj (hcmd'.symm.trans h1)
  have e : findPayment (step L c1).input.payments rc'.paymentId =
      some (recordedPayment (L.request c1).input rc') := by
    rw [hpay, findPayment_insertBy (p := recordedPayment (L.request c1).input rc') hf,
      if_pos (show (recordedPayment (L.request c1).input rc').paymentId = rc'.paymentId from rfl)]
  obtain ⟨p2, hf2, -, -, -, hact2, -⟩ := reverse_exact (r := (step L c1).request c2) h2 ho2
  have hf2' : findPayment (step L c1).input.payments rc'.paymentId = some p2 := by
    rw [← hrc] at hp; rw [← hp]; exact hf2
  have hp2 : p2 = recordedPayment (L.request c1).input rc' := Option.some.inj (hf2'.symm.trans e)
  have hamt : p2.amountCents = rc'.amountCents := by rw [hp2]; rfl
  have hA : activeCents (step L c1).input.payments = rc'.amountCents + activeCents L.input.payments := by
    rw [hpay, activeCents_eq, activeCents_eq, sum_insertBy]; simp [recordedPayment]
  have hact2' : activeCents post2.payments + p2.amountCents = activeCents (step L c1).input.payments :=
    hact2
  rw [step_payments_mutated ho2]; omega

/-! ## Retries (III.3): a repeat of a recorded command is a duplicate, for any calls between -/

theorem confirmation_ctx {i j : FinancialInput} (h : i.context = j.context) (c t) :
    confirmation i c t = confirmation j c t := by simp only [confirmation, h]

theorem reversalRecord_congr {i j : FinancialInput} {p q : Payment} (hc : i.context = j.context)
    (hi : p.paymentId = q.paymentId) (ha : p.amountCents = q.amountCents) (c t a) :
    { reversalRecord i c p t with receivedAt := a } = { reversalRecord j c q t with receivedAt := a } := by
  simp only [reversalRecord, hc, hi, ha]

/-- What a form check reads (origin and local reference) does not depend on when or where. -/
theorem formRefusal_of_conf {i j c t u s} (hc : confirmation i c t = s)
    (h : formRefusal (confirmation j c u) = none) : formRefusal s = none := by
  subst hc
  exact Eq.trans (rfl : formRefusal (confirmation i c t) = formRefusal (confirmation j c u)) h

theorem recordRetry_dup {r c p s k}
    (hs : findEvidence r.input.evidence c.evidenceId = some s) (hfs : formRefusal s = none)
    (hle : c.eventAt ≤ s.receivedAt) (hk : receiptOf r.receipts p.paymentId = some k)
    (hrev : r.expectedRevision = some k.recordedRevision) (hact : k.paysActionId = c.paysActionId)
    (he : p.evidenceId = c.evidenceId) (ho : p.commonOriginId = c.commonOriginId)
    (ha : p.amountCents = c.amountCents) (ht : p.eventAt = c.eventAt)
    (hc : confirmation r.input c s.receivedAt = s) :
    recordRetry r c p = .duplicate (some c.paymentId) := by
  simp [recordRetry, hs, hfs, hk, Nat.not_lt.2 hle, hrev, hact, he, ho, ha, ht, hc]

theorem decideRecord_retry {r c p} (hz : c.amountCents ≠ 0) (hfor : r.foreign.paymentId = false)
    (hp : findPayment r.input.payments c.paymentId = some p) : decideRecord r c = recordRetry r c p := by
  simp [decideRecord, hz, hfor, hp]

/-- A recorded command, as the next snapshot sees it. -/
def Rec (M : Ledger) (c : RecordCommand) (rev : Nat) : Prop :=
  Inv M ∧ c.amountCents ≠ 0 ∧
  (∃ p, findPayment M.input.payments c.paymentId = some p ∧ p.evidenceId = c.evidenceId ∧
    p.commonOriginId = c.commonOriginId ∧ p.amountCents = c.amountCents ∧ p.eventAt = c.eventAt) ∧
  (∃ k, receiptOf M.receipts c.paymentId = some k ∧ k.recordedRevision = rev ∧
    k.paysActionId = c.paysActionId) ∧
  (∃ s, findEvidence M.input.evidence c.evidenceId = some s ∧ c.eventAt ≤ s.receivedAt ∧
    confirmation M.input c s.receivedAt = s ∧ formRefusal s = none)

theorem rec_duplicate {M : Ledger} {c rev} (now' : Nat) (h : Rec M c rev) :
    M.outcome ⟨now', some rev, .record c⟩ = .duplicate (some c.paymentId) := by
  obtain ⟨-, hz, ⟨p, hp, he, ho, ha, ht⟩, ⟨k, hk, hkr, hkp⟩, ⟨s, hs, hle, hce, hfs⟩⟩ := h
  show decideRecord (M.request ⟨now', some rev, .record c⟩) c = _
  rw [decideRecord_retry (r := M.request ⟨now', some rev, .record c⟩) hz rfl hp]
  have hk' : receiptOf (M.request ⟨now', some rev, .record c⟩).receipts p.paymentId = some k := by
    rw [findPayment_id _ _ _ hp]; exact hk
  exact recordRetry_dup hs hfs hle hk' (by simp [Ledger.request, hkr]) hkp he ho ha ht hce

theorem Rec_step {M c rev} (h : Rec M c rev) (c') : Rec (step M c') c rev := by
  obtain ⟨hI, hz, ⟨p, hp, he, ho, ha, ht⟩, ⟨k, hk, hkr, hkp⟩, ⟨s, hs, hle, hce, hfs⟩⟩ := h
  refine ⟨step_Inv c' hI, hz, ?_, ⟨k, step_receipt c' hI hk, hkr, hkp⟩,
    ⟨s, step_evidence M c' hs, hle, ?_, hfs⟩⟩
  · obtain ⟨q, hq, hc⟩ := step_find M c' hp
    rcases hc with rfl | ⟨e, rfl⟩ <;> exact ⟨_, hq, he, ho, ha, ht⟩
  · rw [confirmation_ctx (step_context M c') c s.receivedAt]; exact hce

theorem run_Rec {M c rev} (h : Rec M c rev) : ∀ calls, Rec (run M calls) c rev
  | [] => h
  | c' :: cs => run_Rec (Rec_step h c') cs

theorem Rec_init {L : Ledger} (hI : Inv L) {c : RecordCommand} {c0 : Call} {rev w post res}
    (hcmd : c0.command = .record c) (hexp : c0.expectedRevision = some rev)
    (h : L.outcome c0 = .mutated .RECORDED w post res) : Rec (step L c0) c rev := by
  obtain ⟨rc, hcmd', -, -, hf, hrev, hew, hpay, hrec⟩ := step_recorded h
  obtain rfl : rc = c := Command.record.inj (hcmd'.symm.trans hcmd)
  have hz : rc.amountCents ≠ 0 := fun h0 => by
    have h' : paymentTransition (L.request c0) = .mutated .RECORDED w post res := h
    rw [record_amount_zero (r := L.request c0) hcmd h0] at h'
    cases h'
  have hrv : rev = L.input.beforeRevision := by
    simpa [revisionOk, Ledger.request, hexp] using hrev
  refine ⟨step_Inv c0 hI, hz, ⟨recordedPayment (L.request c0).input rc, ?_, rfl, rfl, rfl, rfl⟩,
    ⟨recordedReceipt (L.request c0).input rc, ?_, hrv.symm, rfl⟩, ?_⟩
  · rw [hpay, findPayment_insertBy (p := recordedPayment (L.request c0).input rc) hf,
      if_pos (show (recordedPayment (L.request c0).input rc).paymentId = rc.paymentId from rfl)]
  · rw [hrec, receiptOf_insertBy (K := recordedReceipt (L.request c0).input rc) (receiptOf_none hI hf),
      if_pos (show (recordedReceipt (L.request c0).input rc).paymentId = rc.paymentId from rfl)]
  · obtain ⟨hform, hle, -, hcase⟩ := hew
    rcases hcase with ⟨hw, -⟩ | ⟨-, s, hs, hle', hce⟩
    · refine ⟨_, step_mutated_evidence h hw, hle, ?_, hform⟩
      exact (confirmation_ctx (step_context L c0) rc _).trans
        (confirmation_ctx (i := L.input) (j := (L.request c0).input) rfl rc _)
    · refine ⟨s, step_evidence L c0 hs, hle', ?_, formRefusal_of_conf hce hform⟩
      exact (confirmation_ctx (step_context L c0) rc _).trans
        ((confirmation_ctx (i := L.input) (j := (L.request c0).input) rfl rc _).trans hce)

theorem run_record_retry_duplicate (L) (hL : ledgerWellFormed L) (c : RecordCommand) (now rev : Nat)
    (calls) (now' : Nat)
    (hc : clocksOk L (⟨now, some rev, .record c⟩ :: calls ++ [⟨now', some rev, .record c⟩]))
    (h : ∃ w post res, L.outcome ⟨now, some rev, .record c⟩ = .mutated .RECORDED w post res) :
    (run (step L ⟨now, some rev, .record c⟩) calls).outcome ⟨now', some rev, .record c⟩ =
      .duplicate (some c.paymentId) := by
  obtain ⟨w, post, res, ho⟩ := h
  exact rec_duplicate now' (run_Rec (Rec_init (Inv_of_wf hL) rfl rfl ho) calls)

/-! ## The same for a reversal -/

theorem evidenceSlot_same {r : PaymentRequest} {e s} (hf : r.foreign.evidenceId = false)
    (hs : findEvidence r.input.evidence e.evidenceId = some s) (hle : e.eventAt ≤ s.receivedAt)
    (heq : { e with receivedAt := s.receivedAt } = s) : evidenceSlot r e = .same s := by
  simp [evidenceSlot, slotOf, hf, hs, hle, heq]

theorem decideReverse_dup {r c p s} (hp : findPayment r.input.payments c.paymentId = some p)
    (hf : r.foreign.evidenceId = false) (hs : findEvidence r.input.evidence c.evidenceId = some s)
    (ht : ∀ t, c.eventAt = some t → t = s.eventAt)
    (hfe : formRefusal (reversalRecord r.input c p s.eventAt) = none)
    (hle : s.eventAt ≤ r.input.evaluatedAt) (hle2 : s.eventAt ≤ s.receivedAt)
    (heq : { reversalRecord r.input c p s.eventAt with receivedAt := s.receivedAt } = s) :
    decideReverse r c = .duplicate none := by
  have htime : c.eventAt.getD (((findEvidence r.input.evidence c.evidenceId).map (·.eventAt)).getD
      r.input.evaluatedAt) = s.eventAt := by
    rw [hs]
    cases hce : c.eventAt with
    | none => rfl
    | some t => exact ht t hce
  have hslot : evidenceSlot r (reversalRecord r.input c p s.eventAt) = .same s :=
    evidenceSlot_same hf hs hle2 heq
  simp [decideReverse, hp, hf, htime, hfe, Nat.not_lt.2 hle, hslot]

def RevDone (M : Ledger) (c : ReverseCommand) (b : Nat) : Prop :=
  ∃ p s, findPayment M.input.payments c.paymentId = some p ∧ p.status = .REVERSED ∧
    findEvidence M.input.evidence c.evidenceId = some s ∧ s.eventAt ≤ s.receivedAt ∧
    s.receivedAt ≤ b ∧ (∀ t, c.eventAt = some t → t = s.eventAt) ∧
    { reversalRecord M.input c p s.eventAt with receivedAt := s.receivedAt } = s ∧ formRefusal s = none

theorem revDone_duplicate {M : Ledger} {c b} (exp' : Option Nat) (h : RevDone M c b) :
    M.outcome ⟨b, exp', .reverse c⟩ = .duplicate none := by
  obtain ⟨p, s, hp, -, hs, hle, hb, ht, hrr, hfs⟩ := h
  have hfe : formRefusal (reversalRecord (M.request ⟨b, exp', .reverse c⟩).input c p s.eventAt) = none :=
    (congrArg formRefusal hrr).trans hfs
  exact decideReverse_dup (r := M.request ⟨b, exp', .reverse c⟩) hp rfl hs ht hfe (Nat.le_trans hle hb) hle hrr

theorem RevDone_step {M c b} (h : RevDone M c b) (c') : RevDone (step M c') c b := by
  obtain ⟨p, s, hp, hst, hs, h1, h2, ht, hrr, hfs⟩ := h
  obtain ⟨q, hq, hc⟩ := step_find M c' hp
  have hqp : q.paymentId = p.paymentId ∧ q.amountCents = p.amountCents := by
    rcases hc with rfl | ⟨e, rfl⟩ <;> exact ⟨rfl, rfl⟩
  have hqs : q.status = .REVERSED := by
    rcases hc with rfl | ⟨e, rfl⟩
    · exact hst
    · rfl
  exact ⟨q, s, hq, hqs, step_evidence M c' hs, h1, h2, ht,
    (reversalRecord_congr (step_context M c') hqp.1 hqp.2 c s.eventAt s.receivedAt).trans hrr, hfs⟩

theorem run_RevDone {M c b} (h : RevDone M c b) : ∀ calls, RevDone (run M calls) c b
  | [] => h
  | c' :: cs => run_RevDone (RevDone_step h c') cs

theorem step_reversed {L c w post res} (h : L.outcome c = .mutated .REVERSED w post res) :
    ∃ vc p e, c.command = .reverse vc ∧ findPayment L.input.payments vc.paymentId = some p ∧
      w.evidence = some e ∧
      e = reversalRecord (L.request c).input vc p (vc.eventAt.getD (L.request c).input.evaluatedAt) ∧
      e.eventAt ≤ (L.request c).input.evaluatedAt ∧ formRefusal e = none ∧
      (step L c).input.payments = L.input.payments.map
        (fun x => if x.paymentId = p.paymentId then reversedImage p vc else x) := by
  rcases step_kind L c with ⟨hs, -⟩ | ⟨_, _, _, _, _, ho, _⟩ |
    ⟨vc, p, w', post', res', hcmd, ho, hf, -, hw, -, hpay, -, e, hwe, he, -, hle, hform⟩
  · exact absurd h (hs.2 w post res)
  · cases h.symm.trans ho
  · cases h.symm.trans ho
    exact ⟨vc, p, e, hcmd, hf, hwe, he, hle, hform, hpay⟩

theorem RevDone_init {L : Ledger} {c : ReverseCommand} {c0 : Call} {b w post res}
    (hcmd : c0.command = .reverse c) (hb : c0.now ≤ b)
    (h : L.outcome c0 = .mutated .REVERSED w post res) : RevDone (step L c0) c b := by
  obtain ⟨vc, p, e, hcmd', hf, hw, he, hle, hform, hpay⟩ := step_reversed h
  obtain rfl : vc = c := Command.reverse.inj (hcmd'.symm.trans hcmd)
  subst he
  refine ⟨reversedImage p vc, _, ?_, rfl, step_mutated_evidence h hw, hle, hb, ?_, ?_, hform⟩
  · rw [hpay]; exact findPayment_reversed hf
  · intro t ht; simp [reversalRecord, ht]
  · exact (reversalRecord_congr (step_context L c0) rfl rfl vc _ _).trans
      (reversalRecord_congr (i := L.input) (j := (L.request c0).input) rfl rfl rfl vc _ _)

theorem run_reverse_retry_duplicate (L) (hL : ledgerWellFormed L) (c : ReverseCommand) (now : Nat)
    (exp exp' : Option Nat) (calls) (now' : Nat)
    (hc : clocksOk L (⟨now, exp, .reverse c⟩ :: calls ++ [⟨now', exp', .reverse c⟩]))
    (h : ∃ w post res, L.outcome ⟨now, exp, .reverse c⟩ = .mutated .REVERSED w post res) :
    (run (step L ⟨now, exp, .reverse c⟩) calls).outcome ⟨now', exp', .reverse c⟩ = .duplicate none := by
  obtain ⟨w, post, res, ho⟩ := h
  have hnow : now ≤ now' := by
    obtain ⟨-, h2⟩ := List.pairwise_cons.1 hc.1
    exact (List.pairwise_cons.1 h2).1 now'
      (List.mem_map.2 ⟨_, List.mem_append_right _ (List.mem_singleton_self _), rfl⟩)
  exact revDone_duplicate exp' (run_RevDone (RevDone_init rfl hnow ho) calls)

end BlindLedger.Financial.Payment
