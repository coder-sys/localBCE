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

theorem findPayment_of_mem : ∀ {l : List Payment} {x : Payment},
    (l.map Payment.paymentId).Nodup → x ∈ l → findPayment l x.paymentId = some x
  | y :: ys, x, hn, hm => by
      rw [List.map_cons, List.nodup_cons] at hn
      unfold findPayment
      by_cases h : y.paymentId = x.paymentId
      · rw [if_pos h]
        rcases List.mem_cons.1 hm with rfl | hm'
        · rfl
        · exact absurd (by rw [h]; exact List.mem_map.2 ⟨x, hm', rfl⟩) hn.1
      · rw [if_neg h]
        rcases List.mem_cons.1 hm with rfl | hm'
        · exact absurd rfl h
        · exact findPayment_of_mem hn.2 hm'

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

theorem step_cases (L : Ledger) (c : Call) :
    (∃ k w post res, L.outcome c = .mutated k w post res ∧ step L c =
      { input := { post with beforeRevision := post.beforeRevision + 1 },
        receipts := (w.receipt.map fun k => insertBy Receipt.paymentId k L.receipts).getD
          L.receipts }) ∨
    (∃ pid e post, L.outcome c = .alias pid e post ∧ step L c = { L with input := post }) ∨
    step L c = L := by
  unfold step
  cases ho : L.outcome c with
  | mutated k w post res => exact Or.inl ⟨k, w, post, res, rfl, rfl⟩
  | alias pid e post => exact Or.inr (Or.inl ⟨pid, e, post, rfl, rfl⟩)
  | duplicate _ => exact Or.inr (Or.inr rfl)
  | conflictUnchanged _ => exact Or.inr (Or.inr rfl)
  | refused _ => exact Or.inr (Or.inr rfl)

theorem step_context (L c) : (step L c).input.context = L.input.context := by
  rcases step_cases L c with ⟨k, w, post, res, ho, he⟩ | ⟨pid, e, post, ho, he⟩ | he <;> rw [he]
  · dsimp only; rw [(paymentTransition_mutated_post ho).1]; rfl
  · dsimp only; rw [(alias_shape ho).1]; rfl

theorem step_evaluatedAt (L c) :
    (step L c).input.evaluatedAt = L.input.evaluatedAt ∨ (step L c).input.evaluatedAt = c.now := by
  rcases step_cases L c with ⟨k, w, post, res, ho, he⟩ | ⟨pid, e, post, ho, he⟩ | he <;> rw [he]
  · exact Or.inr (by dsimp only; rw [(paymentTransition_mutated_post ho).1]; rfl)
  · exact Or.inr (by dsimp only; rw [(alias_shape ho).1]; rfl)
  · exact Or.inl rfl

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
  rcases step_cases L c with ⟨k, w, post, res, ho, he⟩ | ⟨pid, e, post, ho, he⟩ | he <;> rw [he]
  · dsimp only; rw [(paymentTransition_mutated_post ho).1]
    exact findEvidence_applyWrites (mutated_fresh ho) h
  · dsimp only; rw [(alias_shape ho).1]
    exact findEvidence_applyWrites (fun e' hw => by cases hw; exact (alias_shape ho).2.2) h
  · exact h

end BlindLedger.Financial.Payment
