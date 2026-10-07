import Std.Data.TreeMap
import Std.Data.TreeSet
import BlindLedger.Financial.Payment.BatchLaws

namespace BlindLedger.Financial.Payment

open BlindLedger.Financial BlindLedger.Financial.CorrectionTransition

/-! Owner batch, fast lane (S1g). `batchFast` runs the fast lane only where the premises of
    `chain_fold_eq_full` hold (`ok`) and `evaluateTotals` succeeds, and `trace` otherwise, so
    `batchFast_eq_trace` is premise-free.
    The fast lane keeps of the item state only what a stored call (`Erased`) reads: no contributions,
    no sorted evidence-id list, no evaluation per call. -/

/-- `clocksOk` as a Bool: the clocks never go back and stay below `2 ^ 63`. -/
def clocksFrom : Nat → List Call → Bool
  | _, [] => true
  | t, c :: cs => decide (t ≤ c.now) && decide (c.now < 2 ^ 63) && clocksFrom c.now cs

/-- The premises `hL`, `hc`, `hR`, `hw` of `chain_fold_eq_full`, decided (`ok_spec`). -/
def ok (L : Ledger) (calls : List Call) : Bool :=
  financialInputWellFormed L.input && receiptsWellFormed L.input L.receipts &&
    clocksFrom L.input.evaluatedAt calls &&
    decide (L.input.beforeRevision + calls.length ≤ maxRevision) &&
    calls.all fun c => commandWellFormed c.command && c.expectedRevision.all (· < 2 ^ 63)

theorem clocksFrom_spec : ∀ (t : Nat) (cs : List Call), clocksFrom t cs = true →
    (t :: cs.map Call.now).Pairwise (· ≤ ·) ∧ cs.all (·.now < 2 ^ 63) = true
  | _, [], _ => ⟨List.pairwise_singleton _ _, rfl⟩
  | t, c :: cs, h => by
    simp only [clocksFrom, Bool.and_eq_true, decide_eq_true_eq] at h
    obtain ⟨⟨h1, h2⟩, h3⟩ := h
    obtain ⟨ih1, ih2⟩ := clocksFrom_spec c.now cs h3
    rw [List.map_cons]
    refine ⟨List.Pairwise.cons (fun b hb => ?_) ih1, ?_⟩
    · rcases List.mem_cons.1 hb with rfl | hb
      · exact h1
      · exact Nat.le_trans h1 ((List.pairwise_cons.1 ih1).1 b hb)
    · simp only [List.all_cons, Bool.and_eq_true, decide_eq_true_eq]; exact ⟨h2, ih2⟩

/-- `ok` decides exactly `hL`, `hc`, `hR` of `chain_fold_eq_full`, and `hw` at the call level
    (`faithful_unpack` gives `v.command = c.command` and `v.expectedRevision = c.expectedRevision`). -/
theorem ok_spec {L : Ledger} {calls : List Call} (h : ok L calls = true) :
    ledgerWellFormed L ∧ clocksOk L calls ∧ L.input.beforeRevision + calls.length ≤ maxRevision ∧
      (calls.all fun c => commandWellFormed c.command && c.expectedRevision.all (· < 2 ^ 63)) = true := by
  simp only [ok, Bool.and_eq_true, decide_eq_true_eq] at h
  obtain ⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, h5⟩ := h
  exact ⟨⟨h1, h2⟩, clocksFrom_spec _ _ h3, h4, h5⟩

/-- The carried state. Each index answers the list read of `viewOfAnchor` it replaces. -/
structure Fast where
  env : Env
  cash : Nat
  lawful : Nat
  evidence : Nat
  conflicts : Nat
  requests : List RequestPaid
  anchorBytes : Nat
  pays : Std.TreeMap String Payment
  rcpts : Std.TreeMap String Receipt
  origins : Std.TreeMap String String
  rows : Std.TreeMap String EvidenceRecord
  conflictIds : Std.TreeSet String

/-- `PaymentView` without the state (carried in `Fast`) and without `foreign` (always false). -/
structure FView where
  env : Env
  byId : Option (Payment × Receipt)
  byOrigin : Option (Payment × Receipt × Option EvidenceRecord)
  evidence : Option EvidenceRecord
  conflictVisible : Bool
  expectedRevision : Option Nat
  command : Command

/-- The carried state of `L`, whose totals `t` are `evaluateTotals L.input` (`batchFast`). -/
def Fast.init (L : Ledger) (t : EvaluatedTotals) : Fast :=
  let i := L.input
  { env := envOf i, cash := t.cash, lawful := t.lawful,
    evidence := i.evidence.length, conflicts := i.conflicts.length,
    requests := (i.actions.filter (·.kind = "CORRECTION_PAYMENT_REQUEST")).map
      (requestPaidOf i.payments (linksOf L.receipts)),
    anchorBytes := anchorItemLength i L.receipts,
    pays := i.payments.foldr (fun p m => m.insert p.paymentId p) ∅,
    rcpts := L.receipts.foldr (fun k m => m.insert k.paymentId k) ∅,
    origins := i.payments.foldr (fun p m => m.insert p.commonOriginId p.paymentId) ∅,
    rows := i.evidence.foldr (fun e m => m.insert e.evidenceId e) ∅,
    conflictIds := i.conflicts.foldr (fun x s => s.insert x.conflictId) ∅ }

/-- `viewOfAnchor (L.request c)` by lookups. -/
def Fast.view (F : Fast) (c : Call) : FView :=
  let withReceipt (p : Payment) := (F.rcpts.get? p.paymentId).map fun k => (p, k)
  let env := { F.env with evaluatedAt := c.now }
  { env,
    byId := (F.pays.get? (cmdPaymentId c.command)).bind withReceipt,
    byOrigin := match c.command with
      | .record r => ((F.origins.get? r.commonOriginId).bind F.pays.get?).bind fun p =>
          (withReceipt p).map fun (p, k) => (p, k, p.reversalEvidenceId.bind F.rows.get?)
      | .reverse _ => none,
    evidence := F.rows.get? (cmdEvidenceId c.command),
    conflictVisible := match c.command with
      | .record r => F.conflictIds.contains (conflictIdOf env.head r)
      | .reverse _ => false,
    expectedRevision := c.expectedRevision, command := c.command }

/-- `anchorGrowth` over the fast view. -/
def growthF (v : FView) (w : Writes) : Nat :=
  evBytes w + (newPay w - (v.byId.map fun q => (encodePayment q.1).length).getD 0) + cfBytes w + receiptBytes w

/-- `commitView`: `advance` + `evaluateState` decided by `deltaOk` on the carried counts. -/
def commitFast (F : Fast) (v : FView) (k : Mutation) (w : Writes) : Erased :=
  if v.env.context.mode = .SHADOW then .refused .SHADOW_READ_ONLY else
  if F.anchorBytes + growthF v w + maxCallTailBytes > maxTotalEncodedBytes then .refused .CAPACITY else
  if deltaOk ⟨F.evidence, F.conflicts, F.cash, some F.lawful⟩ w
  then .mutated k w v.env.beforeRevision (v.env.beforeRevision + 1) else .refused .POST_REJECTED

def aliasFast (F : Fast) (v : FView) (pid : String) (e : EvidenceRecord) : Erased :=
  if v.env.context.mode = .SHADOW then .refused .SHADOW_READ_ONLY else
  if F.anchorBytes + (encodeEvidence e).length + maxCallTailBytes > maxTotalEncodedBytes then .refused .CAPACITY else
  if F.evidence < maxRows then .alias pid e else .refused .POST_REJECTED

def retryFast (v : FView) (c : RecordCommand) (p : Payment) (k : Receipt) : Erased :=
  match v.evidence with
  | none => .refused .REQUEST_CONFLICT
  | some s =>
    let e := confirmation v.env.head c s.receivedAt
    match formRefusal e with
    | some f => .refused f
    | none =>
      if c.eventAt > s.receivedAt then .refused .CHRONOLOGY else
      if v.expectedRevision = some k.recordedRevision ∧ k.paysActionId = c.paysActionId ∧
         p.evidenceId = c.evidenceId ∧ p.commonOriginId = c.commonOriginId ∧
         p.amountCents = c.amountCents ∧ p.eventAt = c.eventAt ∧ e = s
      then .duplicate (some c.paymentId) else .refused .REQUEST_CONFLICT

/-- `linkRefusalView`: the shortfall is `owed - total` when `evalAdd cash lawful = some total`. -/
def linkFast (F : Fast) (v : FView) (c : RecordCommand) : Option Refusal :=
  c.paysActionId.bind fun a =>
    match F.requests.find? (·.actionId = a) with
    | none => some .LINK_UNKNOWN
    | some q =>
      if (evalAdd F.cash F.lawful).any fun t =>
          c.amountCents ≤ openState (v.env.obligation.owedCents - t) F.requests q
      then none else some .LINK_EXCEEDS_UNPAID

def newFast (F : Fast) (v : FView) (c : RecordCommand) : Erased :=
  let i := v.env.head
  let now := v.env.evaluatedAt
  let existing := v.byOrigin
  let same := existing.any (·.1.amountCents = c.amountCents)
  let stored := v.evidence
  let prior := same && stored.isSome
  let conflictId := conflictIdOf i c
  let reversedBefore := existing.any fun x => x.1.status = .REVERSED && x.2.2.any (·.eventAt < c.eventAt)
  if same && !prior && reversedBefore then .refused .ORIGIN_REVERSED else
  if existing.isSome && !same && v.conflictVisible && (slotOf false stored (confirmation i c now)).isSame
  then .conflictUnchanged conflictId else
  if !prior && !v.expectedRevision.all (· = v.env.beforeRevision) then .refused .REVISION_CONFLICT else
  let receivedAt := if prior then (stored.map (·.receivedAt)).getD now else now
  let e := confirmation i c receivedAt
  match formRefusal e with
  | some f => .refused f
  | none =>
  if c.eventAt > receivedAt then .refused .CHRONOLOGY else
  match slotOf false stored e with
  | .clash => .refused .EVIDENCE_CONFLICT
  | slot =>
    let fresh := slot.isFresh
    match existing with
    | some (p, k, _) =>
      if same then
        if c.paysActionId.isSome && c.paysActionId ≠ k.paysActionId then .refused .REQUEST_CONFLICT
        else if fresh then aliasFast F v p.paymentId e else .duplicate (some p.paymentId)
      else if v.conflictVisible then .conflictUnchanged conflictId
      else if !idWellFormed conflictId then .refused .CONFLICT_ID_FORM
      else commitFast F v .CONFLICT_RECORDED
        { evidence := if fresh then some e else none, payment := none, receipt := none,
          conflict := some (conflictImage i c p conflictId) }
    | none =>
      match linkFast F v c with
      | some f => .refused f
      | none => commitFast F v .RECORDED
        { evidence := if fresh then some e else none, conflict := none,
          payment := some (recordedPayment i c), receipt := some (recordedReceipt i c) }

def reverseFast (F : Fast) (v : FView) (c : ReverseCommand) : Erased :=
  let i := v.env.head
  let now := v.env.evaluatedAt
  match v.byId with
  | none => .refused .PAYMENT_MISSING
  | some (p, _) =>
    let time := c.eventAt.getD ((v.evidence.map (·.eventAt)).getD now)
    let e := reversalRecord i c p time
    match formRefusal e with
    | some f => .refused f
    | none =>
    if time > now then .refused .CHRONOLOGY else
    match slotOf false v.evidence e with
    | .clash => .refused .EVIDENCE_CONFLICT
    | .same _ => .duplicate none
    | .fresh =>
      if !v.expectedRevision.all (· = v.env.beforeRevision) then .refused .REVISION_CONFLICT else
      if p.status = .REVERSED then .refused .ALREADY_REVERSED else
      commitFast F v .REVERSED
        { evidence := some e, conflict := none, receipt := none, payment := some (reversedImage p c) }

/-- `stepView` with `foreign = ⟨false, false⟩`, stored part only. -/
def stepFast (F : Fast) (v : FView) : Erased :=
  match v.command with
  | .record c =>
    if c.amountCents = 0 then .refused .AMOUNT_ZERO else
    match v.byId with
    | some (p, k) => retryFast v c p k
    | none => newFast F v c
  | .reverse c => reverseFast F v c

/-- The carried state after the stored call: `advance` + `settle` (mutated), `absorb` (alias). -/
def Fast.post (F : Fast) (v : FView) : Erased → Fast
  | .mutated _ w _ _ =>
    let pay (a : Option String) (f : Nat → Nat) : List RequestPaid :=
      if a.isNone then F.requests else
      F.requests.map fun q => if a = some q.actionId then { q with paidCents := f q.paidCents } else q
    let cr : Nat × List RequestPaid := match w.payment, w.receipt, v.byId with
      | some p, some k, _ => (F.cash + p.amountCents, pay k.paysActionId (· + p.amountCents))
      | some _, none, some (q, k) => (F.cash - q.amountCents, pay k.paysActionId (· - q.amountCents))
      | _, _, _ => (F.cash, F.requests)
    { F with
      env := { v.env with beforeRevision := v.env.beforeRevision + 1 },
      cash := cr.1, requests := cr.2,
      evidence := F.evidence + (if w.evidence.isSome then 1 else 0),
      conflicts := F.conflicts + (if w.conflict.isSome then 1 else 0),
      anchorBytes := F.anchorBytes + growthF v w,
      pays := match w.payment with
        | some p => F.pays.insert p.paymentId p
        | none => F.pays,
      rcpts := match w.receipt with
        | some k => F.rcpts.insertIfNew k.paymentId k
        | none => F.rcpts,
      origins := match w.payment with
        | some p => F.origins.insertIfNew p.commonOriginId p.paymentId
        | none => F.origins,
      rows := match w.evidence with
        | some e => F.rows.insertIfNew e.evidenceId e
        | none => F.rows,
      conflictIds := match w.conflict with
        | some x => F.conflictIds.insert x.conflictId
        | none => F.conflictIds }
  | .alias _ e =>
    { F with env := v.env, evidence := F.evidence + 1,
             anchorBytes := F.anchorBytes + (encodeEvidence e).length,
             rows := F.rows.insertIfNew e.evidenceId e }
  | _ => F

def fastFrom : Fast → List Call → List Erased
  | _, [] => []
  | F, c :: cs =>
    let v := F.view c
    let o := stepFast F v
    o :: fastFrom (F.post v o) cs

/-- The batch: the fast lane where its premises hold and the ledger has totals (so the trace has a
    view to agree with), `trace` otherwise. The totals are computed once and seed `Fast.init`. -/
def batchFast (L : Ledger) (calls : List Call) : List Erased :=
  match evaluateTotals L.input, ok L calls with
  | some t, true => fastFrom (Fast.init L t) calls
  | _, _ => (trace L calls).map erase

/-! ## The fast step is the view step on a state that agrees with the carried scalars -/

/-- The `PaymentView` of a fast view over the item state `s`, with `foreign = ⟨false, false⟩`. -/
def FView.toView (v : FView) (s : ItemState) : PaymentView :=
  { env := v.env, state := s, pending := [], byId := v.byId, byOrigin := v.byOrigin, evidence := v.evidence,
    conflictVisible := v.conflictVisible, foreign := ⟨false, false⟩, expectedRevision := v.expectedRevision,
    command := v.command }

/-- The carried scalars of `F` are those of the item state `s`. -/
structure Agree (F : Fast) (s : ItemState) : Prop where
  cash : s.cash = F.cash
  lawful : s.lawful = F.lawful
  evidence : s.evidenceIds.length = F.evidence
  conflicts : s.conflictCount = F.conflicts
  requests : s.requests = F.requests
  anchorBytes : s.anchorBytes = F.anchorBytes

theorem evaluateState_isSome (e : Env) (s : ItemState) :
    (evaluateState e s).isSome = decide (s.cash + s.lawful ≤ maxCents) := by
  unfold evaluateState
  rw [evalAdd_eq']
  split <;> simp_all

theorem evaluateState_rev {e : Env} {s : ItemState} {r : FinancialResult} (h : evaluateState e s = some r) :
    r.beforeRevision = e.beforeRevision ∧ r.afterRevision = e.beforeRevision + 1 := by
  unfold evaluateState at h
  cases ht : evalAdd s.cash s.lawful with
  | none => rw [ht] at h; cases h
  | some t => rw [ht] at h; cases h; exact ⟨rfl, rfl⟩

/-- `advance` then `evaluateState` succeed exactly where `deltaOk` holds on the carried scalars. A
    payment write without a receipt (REVERSED) replaces the `byId` row by an image of equal amount. -/
theorem advance_eval_isSome {F : Fast} {s : ItemState} (hA : Agree F s) (v : FView) (w : Writes)
    (hrev : ∀ p, w.payment = some p → w.receipt = none →
      ∃ q k', v.byId = some (q, k') ∧ p.amountCents = q.amountCents) :
    ((advance (v.toView s) s w).bind (evaluateState v.env)).isSome =
      deltaOk ⟨F.evidence, F.conflicts, F.cash, some F.lawful⟩ w := by
  obtain ⟨hc, hl, he, hf, -, -⟩ := hA
  obtain ⟨we, wp, wc, wr⟩ := w
  simp only at hrev
  cases wp with
  | none =>
    cases we <;> cases wc <;>
      simp only [advance, deltaOk, FView.toView, Option.map_none, Option.map_some, Option.getD_none,
        Option.getD_some, Option.isSome_none, Option.isSome_some, length_insertBy] <;>
      (repeat' split) <;> (try simp_all [evaluateState_isSome]) <;> omega
  | some p =>
    cases wr with
    | some r =>
      cases we <;> cases wc <;>
        simp only [advance, deltaOk, FView.toView, Option.map_none, Option.map_some, Option.getD_none,
          Option.getD_some, Option.isSome_none, Option.isSome_some, length_insertBy] <;>
        (repeat' split) <;> (try simp_all [evaluateState_isSome]) <;> omega
    | none =>
      obtain ⟨q, k', hq, hamt⟩ := hrev p rfl rfl
      clear hrev
      cases we <;> cases wc <;>
        simp only [advance, deltaOk, FView.toView, hq, hamt, Option.map_none, Option.map_some, Option.getD_none,
          Option.getD_some, Option.isSome_none, Option.isSome_some, length_insertBy] <;>
        clear hq hamt <;> (repeat' split) <;> (try simp_all [evaluateState_isSome]) <;> omega

theorem commitFast_eq {F : Fast} {s : ItemState} (hA : Agree F s) (v : FView) (k : Mutation) (w : Writes)
    (hrev : ∀ p, w.payment = some p → w.receipt = none →
      ∃ q k', v.byId = some (q, k') ∧ p.amountCents = q.amountCents) :
    commitFast F v k w = Erased.ofStep (commitView (v.toView s) s k w) := by
  have hD := advance_eval_isSome hA v w hrev
  have hg : anchorGrowth (v.toView s) w = growthF v w := rfl
  have henv : (v.toView s).env = v.env := rfl
  unfold commitFast commitView
  simp only [hg, henv, hA.anchorBytes]
  by_cases h1 : v.env.context.mode = .SHADOW
  · simp only [h1, ↓reduceIte, Erased.ofStep]
  · simp only [h1, ↓reduceIte]
    by_cases h2 : F.anchorBytes + growthF v w + maxCallTailBytes > maxTotalEncodedBytes
    · simp only [h2, ↓reduceIte, Erased.ofStep]
    · simp only [h2, ↓reduceIte]
      rw [← hD]
      cases ha : advance (v.toView s) s w with
      | none => simp only [Option.bind_none, Option.isSome_none, Bool.false_eq_true, ↓reduceIte, Erased.ofStep]
      | some s' =>
        cases hr : evaluateState v.env s' with
        | none =>
          simp only [Option.bind_some, hr, Option.isSome_none, Bool.false_eq_true, ↓reduceIte, Erased.ofStep]
        | some r =>
          obtain ⟨e1, e2⟩ := evaluateState_rev hr
          simp only [Option.bind_some, hr, Option.isSome_some, ↓reduceIte, Erased.ofStep, e1, e2]

theorem aliasFast_eq {F : Fast} {s : ItemState} (hA : Agree F s) (v : FView) (pid : String)
    (e : EvidenceRecord) : aliasFast F v pid e = Erased.ofStep (aliasView (v.toView s) s pid e) := by
  unfold aliasFast aliasView
  rw [hA.anchorBytes, hA.evidence]
  (repeat' split) <;> simp_all [FView.toView, Erased.ofStep]

/-- The link refusal reads only `cash`, `lawful` and `requests`; its shortfall is `owed - total`. -/
theorem linkFast_eq {F : Fast} {s : ItemState} (hA : Agree F s) (v : FView) (c : RecordCommand) :
    linkFast F v c = linkRefusalView v.env s c := by
  unfold linkFast linkRefusalView
  rw [← hA.requests, ← hA.cash, ← hA.lawful]
  congr 1
  funext a
  cases List.find? (fun x => decide (x.actionId = a)) s.requests with
  | none => rfl
  | some q =>
    unfold evaluateState
    cases evalAdd s.cash s.lawful with
    | none => rfl
    | some t =>
      by_cases ht : v.env.obligation.owedCents > t
      · simp [ht]
      · have h0 : v.env.obligation.owedCents - t = 0 := by omega
        simp [ht, h0]

theorem ofStep_refused (r : Refusal) : Erased.ofStep (.refused r) = .refused r := rfl
theorem ofStep_duplicate (p : Option String) : Erased.ofStep (.duplicate p) = .duplicate p := rfl
theorem ofStep_conflictUnchanged (x : String) :
    Erased.ofStep (.conflictUnchanged x) = .conflictUnchanged x := rfl

section
variable (v : FView) (s : ItemState)
theorem FView.toView_env : (v.toView s).env = v.env := rfl
theorem FView.toView_byId : (v.toView s).byId = v.byId := rfl
theorem FView.toView_byOrigin : (v.toView s).byOrigin = v.byOrigin := rfl
theorem FView.toView_evidence : (v.toView s).evidence = v.evidence := rfl
theorem FView.toView_conflictVisible : (v.toView s).conflictVisible = v.conflictVisible := rfl
theorem FView.toView_expectedRevision : (v.toView s).expectedRevision = v.expectedRevision := rfl
theorem FView.toView_foreign_evidenceId : (v.toView s).foreign.evidenceId = false := rfl
theorem FView.toView_foreign_paymentId : (v.toView s).foreign.paymentId = false := rfl
end

/-- Split the left side; each split's hypotheses rewrite the matching branch of the right side. -/
macro "split_both" : tactic => `(tactic|
  (repeat' (split <;> (try simp only [*, ofStep_refused, ofStep_duplicate, ofStep_conflictUnchanged,
      Bool.false_eq_true, ↓reduceIte] at ⊢))))

theorem retryFast_eq (v : FView) (s : ItemState) (c : RecordCommand) (p : Payment) (k : Receipt) :
    retryFast v c p k = Erased.ofStep (viewRecordRetry (v.toView s) c p k) := by
  unfold retryFast viewRecordRetry
  dsimp only [FView.toView_env, FView.toView_evidence, FView.toView_expectedRevision]
  split_both
  all_goals (first | contradiction | (simp_all [ofStep_refused, ofStep_duplicate]; done))

theorem newFast_eq {F : Fast} {s : ItemState} (hA : Agree F s) (v : FView) (c : RecordCommand) :
    newFast F v c = Erased.ofStep (viewRecordNew (v.toView s) s c) := by
  have hAl : ∀ pid e, aliasFast F v pid e = Erased.ofStep (aliasView (v.toView s) s pid e) := aliasFast_eq hA v
  have hCf : ∀ k (w : Writes), w.payment = none →
      commitFast F v k w = Erased.ofStep (commitView (v.toView s) s k w) :=
    fun k w hw => commitFast_eq hA v k w fun _ h _ => by simp [hw] at h
  have hCr : ∀ k (w : Writes), w.receipt.isSome = true →
      commitFast F v k w = Erased.ofStep (commitView (v.toView s) s k w) :=
    fun k w hw => commitFast_eq hA v k w fun _ _ h => by simp [h] at hw
  unfold newFast viewRecordNew
  rw [linkFast_eq hA v c]
  rw [FView.toView_env, FView.toView_byOrigin, FView.toView_evidence, FView.toView_conflictVisible,
    FView.toView_expectedRevision, FView.toView_foreign_evidenceId]
  simp only [Bool.or_false, Bool.and_false, Bool.false_eq_true, ↓reduceIte]
  clear hA
  cases hO : v.byOrigin with
  | none =>
    simp only [Option.any_none, Option.isSome_none, Bool.false_and, Bool.not_false, Bool.true_and,
      Bool.false_eq_true, ↓reduceIte]
    split_both
    all_goals first
      | contradiction
      | (refine hCr _ _ ?_; rfl)
      | (simp_all [ofStep_refused, ofStep_duplicate, ofStep_conflictUnchanged]; done)
      | skip
  | some x =>
    obtain ⟨p, k, r⟩ := x
    simp only [Option.any_some, Option.isSome_some, Bool.true_and]
    by_cases hs : decide (p.amountCents = c.amountCents) = true <;>
      by_cases he : v.evidence.isSome = true <;>
      (try simp only [Bool.not_eq_true] at hs he) <;>
      (try simp only [hs, he, Bool.true_and, Bool.false_and, Bool.and_true, Bool.and_false, Bool.not_true,
        Bool.not_false, Bool.false_eq_true, ↓reduceIte]) <;>
      split_both
    all_goals first
      | contradiction
      | exact hAl _ _
      | (refine hCf _ _ ?_; rfl)
      | (simp_all [ofStep_refused, ofStep_duplicate, ofStep_conflictUnchanged]; done)
      | skip

theorem reverseFast_eq {F : Fast} {s : ItemState} (hA : Agree F s) (v : FView) (c : ReverseCommand) :
    reverseFast F v c = Erased.ofStep (viewReverse (v.toView s) s c) := by
  cases hb : v.byId with
  | none => simp only [reverseFast, viewReverse, FView.toView, hb, Erased.ofStep]
  | some pk =>
    obtain ⟨p, k'⟩ := pk
    have hC : ∀ k (w : Writes), w.payment = some (reversedImage p c) →
        commitFast F v k w = Erased.ofStep (commitView (v.toView s) s k w) :=
      fun k w hw => commitFast_eq hA v k w fun q hq _ => ⟨p, k', hb, by rw [hw] at hq; cases hq; rfl⟩
    unfold reverseFast viewReverse
    rw [FView.toView_env, FView.toView_byId, FView.toView_evidence, FView.toView_expectedRevision,
      FView.toView_foreign_evidenceId]
    simp only [hb, Bool.false_eq_true, ↓reduceIte]
    clear hA
    split_both
    all_goals first
      | contradiction
      | (refine hC _ _ ?_; rfl)
      | (simp_all [ofStep_refused, ofStep_duplicate]; done)

/-- The fast step is the stored part of the view step on any item state that agrees with `F`. -/
theorem stepFast_eq {F : Fast} {s : ItemState} (hA : Agree F s) (v : FView) :
    stepFast F v = Erased.ofStep (stepView (v.toView s)) := by
  have habs : absorb (v.toView s).state (v.toView s).pending = s := rfl
  have hcmd : (v.toView s).command = v.command := rfl
  unfold stepFast stepView
  simp only [habs, hcmd, FView.toView_foreign_paymentId, FView.toView_byId, Bool.false_eq_true, ↓reduceIte]
  cases v.command with
  | record c =>
    by_cases h0 : c.amountCents = 0
    · simp only [h0, ↓reduceIte, Erased.ofStep]
    · simp only [h0, ↓reduceIte]
      cases v.byId with
      | some pk => exact retryFast_eq v s c pk.1 pk.2
      | none => exact newFast_eq hA v c
  | reverse c => exact reverseFast_eq hA v c

/-- The foreign flags are false on every call the trace steps, with or without `ok`:
    `Ledger.request` sets `foreign := ⟨false, false⟩`, so `FView.toView` drops nothing. -/
theorem viewOfAnchor_foreign (L : Ledger) (c : Call) {v : PaymentView}
    (h : viewOfAnchor (L.request c) = some v) : v.foreign = ⟨false, false⟩ := by
  obtain ⟨S, -, rfl⟩ := Option.map_eq_some_iff.1 h
  rfl

/-! ## The carried state answers every read `viewOfAnchor` makes of the ledger -/

/-- Each index of `F` is the list read of `M` it replaces, and the scalars agree with `M`'s summary. -/
structure Rel (F : Fast) (M : Ledger) : Prop where
  env : F.env = envOf M.input
  pays : F.pays.get? = findPayment M.input.payments
  rcpts : F.rcpts.get? = receiptOf M.receipts
  origins : ∀ o, (F.origins.get? o).bind (findPayment M.input.payments) =
    M.input.payments.find? (·.commonOriginId = o)
  rows : F.rows.get? = findEvidence M.input.evidence
  conflicts : ∀ x, F.conflictIds.contains x = M.input.conflicts.any (·.conflictId = x)
  agree : ∃ S, summaryOf M.input M.receipts = some S ∧ Agree F S

/-- The request's summary is the ledger's: only `evaluatedAt` moves, and no summary field reads it. -/
theorem summarize_request (M : Ledger) (c : Call) :
    summarize (M.request c).input (M.request c).receipts
      (anchorOverhead + (M.request c).inputBytes + (encodeList encodeReceipt (M.request c).receipts).length) =
    summaryOf M.input M.receipts := by
  simp only [Ledger.request, summaryOf, anchorItemLength, rawEncode_evaluatedAt]
  rfl

theorem view_link {F : Fast} {M : Ledger} (hR : Rel F M) (c : Call) :
    ∃ S, Agree F S ∧ viewOfAnchor (M.request c) = some ((F.view c).toView S) := by
  obtain ⟨S, hS, hA⟩ := hR.agree
  refine ⟨S, hA, ?_⟩
  unfold viewOfAnchor
  dsimp only
  rw [summarize_request, hS]
  simp only [Option.map_some, Option.some.injEq, Ledger.request, Fast.view, FView.toView]
  rw [hR.pays, hR.rcpts, hR.rows, hR.env]
  cases c.command with
  | record r =>
    dsimp only
    rw [hR.origins, hR.conflicts]
    rfl
  | reverse r => rfl

/-- One call: under `Rel`, the fast step is the erased trace outcome (stepView_eq, project_factors_erase). -/
theorem link_step {F : Fast} {M : Ledger} (hR : Rel F M) (c : Call)
    (hr : requestWellFormed (M.request c) = true) : stepFast F (F.view c) = erase (M.outcome c) := by
  obtain ⟨S, hA, hv⟩ := view_link hR c
  have h1 := stepView_eq hr rfl (v := (F.view c).toView S) hv
  have h2 := project_factors_erase (M.request c) (paymentTransition (M.request c))
  rw [← h1] at h2
  simp only [Option.map_some, Option.some.injEq] at h2
  rw [stepFast_eq hA]
  exact h2

theorem fast_eq_trace_of_ok {L : Ledger} {calls : List Call} {t : EvaluatedTotals}
    (ht : evaluateTotals L.input = some t) (h : ok L calls = true) :
    fastFrom (Fast.init L t) calls = (trace L calls).map erase := by
  sorry

theorem batchFast_eq_trace (L : Ledger) (calls : List Call) :
    batchFast L calls = (trace L calls).map erase := by
  unfold batchFast
  cases ht : evaluateTotals L.input with
  | none => rfl
  | some t =>
    cases h : ok L calls with
    | false => rfl
    | true => exact fast_eq_trace_of_ok ht h

end BlindLedger.Financial.Payment
