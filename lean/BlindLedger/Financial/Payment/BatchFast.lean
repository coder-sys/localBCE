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
  origins : ∀ o, F.origins.get? o = (M.input.payments.find? (·.commonOriginId = o)).map (·.paymentId)
  rows : F.rows.get? = findEvidence M.input.evidence
  conflicts : ∀ x, F.conflictIds.contains x = M.input.conflicts.any (·.conflictId = x)
  agree : ∃ S, summaryOf M.input M.receipts = some S ∧ Agree F S
  inv : Inv M

/-- The origin index read through the payment index, as `viewOfAnchor` reads it. -/
theorem Rel.origins_bind {F : Fast} {M : Ledger} (hR : Rel F M) (o : String) :
    (F.origins.get? o).bind (findPayment M.input.payments) = M.input.payments.find? (·.commonOriginId = o) := by
  rw [hR.origins o]
  cases hf : M.input.payments.find? (fun x => decide (x.commonOriginId = o)) with
  | none => rfl
  | some p => exact findPayment_of_mem hR.inv.1 (List.mem_of_find?_eq_some hf)

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
    rw [hR.origins_bind, hR.conflicts]
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

/-! ## The initial carried state -/

/-- A `foldr` of inserts answers a lookup with the first row of that key. -/
theorem get?_foldr_insert {α β} (key : α → String) (val : α → β) (id : String) :
    ∀ xs : List α, Std.TreeMap.get? (xs.foldr (fun x (m : Std.TreeMap String β) => m.insert (key x) (val x)) ∅) id =
      (xs.find? fun x => decide (key x = id)).map val
  | [] => by
    simp only [List.foldr_nil, Std.TreeMap.get?_eq_getElem?, Std.TreeMap.getElem?_emptyc, List.find?_nil,
      Option.map_none]
  | x :: xs => by
    have ih := get?_foldr_insert key val id xs
    simp only [List.foldr_cons, Std.TreeMap.get?_eq_getElem?, Std.TreeMap.getElem?_insert,
      Std.LawfulEqCmp.compare_eq_iff_eq, List.find?_cons] at ih ⊢
    rw [ih]
    by_cases h : key x = id <;> simp [h]

theorem contains_foldr_insert {α} (key : α → String) (id : String) :
    ∀ xs : List α, Std.TreeSet.contains (xs.foldr (fun x (s : Std.TreeSet String) => s.insert (key x)) ∅) id =
      xs.any fun x => decide (key x = id)
  | [] => by simp only [List.foldr_nil, Std.TreeSet.contains_emptyc, List.any_nil]
  | x :: xs => by
    simp only [List.foldr_cons, Std.TreeSet.contains_insert, List.any_cons, contains_foldr_insert key id xs]
    by_cases h : key x = id
    · subst h; simp
    · have hc : compare (key x) id ≠ .eq := fun e => h (Std.LawfulEqCmp.compare_eq_iff_eq.1 e)
      cases hx : compare (key x) id <;> simp only [h, decide_false] <;> first | exact absurd hx hc | rfl

theorem map_self {α} (o : Option α) : o.map (fun x => x) = o := by cases o <;> rfl

/-- The carried state built from `L` and its totals answers every read of `L`. -/
theorem Rel_init {L : Ledger} (hI : Inv L) {t : EvaluatedTotals} (ht : evaluateTotals L.input = some t) :
    Rel (Fast.init L t) L where
  env := rfl
  pays := funext fun pid => by
    rw [findPayment_eq]; exact (get?_foldr_insert Payment.paymentId (fun p => p) pid _).trans (map_self _)
  rcpts := funext fun pid => (get?_foldr_insert Receipt.paymentId (fun k => k) pid _).trans (map_self _)
  origins o := get?_foldr_insert Payment.commonOriginId Payment.paymentId o _
  rows := funext fun id => by
    rw [findEvidence_eq]; exact (get?_foldr_insert EvidenceRecord.evidenceId (fun e => e) id _).trans (map_self _)
  conflicts x := contains_foldr_insert FinancialConflict.conflictId x _
  agree := by
    rw [summaryOf, summarize, ht, Option.map_some]
    exact ⟨_, rfl, rfl, rfl, by simp only [Fast.init, List.length_map], rfl, rfl, rfl⟩
  inv := hI

/-! ## Preservation -/

/-- Refused, duplicate and conflict-unchanged calls leave both states as they are. -/
theorem Rel_post_other {F : Fast} {M : Ledger} {c : Call} (hR : Rel F M)
    (hr : requestWellFormed (M.request c) = true)
    (hm : ∀ k w post res, M.outcome c ≠ .mutated k w post res)
    (ha : ∀ pid e post, M.outcome c ≠ .alias pid e post) :
    Rel (F.post (F.view c) (stepFast F (F.view c))) (step M c) := by
  rw [link_step hR c hr]
  unfold step
  cases h : M.outcome c with
  | mutated k w post res => exact absurd h (hm k w post res)
  | alias pid e post => exact absurd h (ha pid e post)
  | duplicate _ => exact hR
  | conflictUnchanged _ => exact hR
  | refused _ => exact hR

/-- `insertIfNew` at a key the map lacks answers like an insert. -/
theorem get?_insertIfNew_fresh {β} {m : Std.TreeMap String β} {k : String} {v : β}
    (hk : m.get? k = none) (id : String) :
    (m.insertIfNew k v).get? id = if k = id then some v else m.get? id := by
  have hn : ¬ k ∈ m := by
    rw [Std.TreeMap.mem_iff_isSome_getElem?, ← Std.TreeMap.get?_eq_getElem?, hk]; simp
  rw [Std.TreeMap.get?_eq_getElem?, Std.TreeMap.getElem?_insertIfNew, Std.TreeMap.get?_eq_getElem?]
  by_cases h : k = id
  · subst h; simp [hn]
  · have hc : compare k id ≠ .eq := fun e => h (Std.LawfulEqCmp.compare_eq_iff_eq.1 e)
    simp [hc, h]

/-- An alias call inserts one fresh evidence row: `absorb` on the summary, `insertIfNew` on the rows. -/
theorem Rel_alias {F : Fast} {M : Ledger} {c : Call} {pid e post} (hR : Rel F M)
    (hr : requestWellFormed (M.request c) = true) (ho : M.outcome c = .alias pid e post) :
    Rel (F.post (F.view c) (stepFast F (F.view c))) (step M c) := by
  have hS' := absorb_summarize M c ho
  have hstep : step M c = { M with input := post } := by simp only [step, ho]
  obtain ⟨hpost, -, hfresh⟩ := alias_shape ho
  have hfresh' : findEvidence M.input.evidence e.evidenceId = none := hfresh
  rw [hstep] at hS'
  rw [link_step hR c hr, ho, hstep]
  obtain ⟨S, hS, hA⟩ := hR.agree
  rw [hS, Option.map_some] at hS'
  subst hpost
  show Rel
    { F with env := (F.view c).env, evidence := F.evidence + 1,
             anchorBytes := F.anchorBytes + (encodeEvidence e).length,
             rows := F.rows.insertIfNew e.evidenceId e } _
  exact {
    env := by show { F.env with evaluatedAt := c.now } = _; rw [hR.env]; rfl
    pays := hR.pays
    rcpts := hR.rcpts
    origins := hR.origins
    rows := funext fun id => by
      show _ = findEvidence (insertBy EvidenceRecord.evidenceId e M.input.evidence) id
      rw [findEvidence_insertBy hfresh', ← hR.rows]
      exact get?_insertIfNew_fresh (by rw [hR.rows]; exact hfresh') id
    conflicts := hR.conflicts
    inv := hR.inv
    agree := ⟨_, hS'.symm, hA.cash, hA.lawful,
      by show (insertBy (fun x => x) e.evidenceId S.evidenceIds).length = F.evidence + 1
         rw [length_insertBy, hA.evidence],
      hA.conflicts, hA.requests,
      by show S.anchorBytes + (encodeEvidence e).length = F.anchorBytes + (encodeEvidence e).length
         rw [hA.anchorBytes]⟩ }

/-! ## Mutated calls -/

/-- A mutated view outcome is `settle` of an `advance` of the view's item state (Fits pattern, ChainLaws). -/
def Settles (v : PaymentView) (s : ItemState) (o : StepOutcome) : Prop :=
  ∀ k w s' r, o = .mutated k w s' r → ∃ s0, advance v s w = some s0 ∧ s' = settle s0 r

theorem settles_commit {v s k w} : Settles v s (commitView v s k w) := by
  intro k' w' s' r h
  by_cases hs : v.env.context.mode = .SHADOW
  · simp [commitView, hs] at h
  by_cases hc : s.anchorBytes + anchorGrowth v w + maxCallTailBytes > maxTotalEncodedBytes
  · simp [commitView, hs, hc] at h
  cases hadv : advance v s w with
  | none => simp [commitView, hs, hc, hadv] at h
  | some s2 =>
    cases hev : evaluateState v.env s2 with
    | none => simp [commitView, hs, hc, hadv, hev] at h
    | some r2 =>
      simp only [commitView, hs, hc, hadv, hev, ↓reduceIte] at h
      cases h
      exact ⟨s2, hadv, rfl⟩
theorem settles_refused {v s x} : Settles v s (.refused x) := fun _ _ _ _ h => by cases h
theorem settles_dup {v s x} : Settles v s (.duplicate x) := fun _ _ _ _ h => by cases h
theorem settles_cu {v s x} : Settles v s (.conflictUnchanged x) := fun _ _ _ _ h => by cases h
theorem settles_alias {v s x y} : Settles v s (.alias x y) := fun _ _ _ _ h => by cases h

theorem settles_ite {v s} {c : Prop} [Decidable c] {a b : StepOutcome} (ha : Settles v s a)
    (hb : Settles v s b) : Settles v s (if c then a else b) := by
  by_cases h : c
  · rw [if_pos h]; exact ha
  · rw [if_neg h]; exact hb

theorem settles_aliasView {v s v' s' p e} : Settles v s (aliasView v' s' p e) := by
  unfold aliasView
  refine settles_ite settles_refused (settles_ite settles_refused (settles_ite settles_alias settles_refused))

set_option maxHeartbeats 1000000 in
theorem settles_reverse {v s c} : Settles v s (viewReverse v s c) := by
  unfold viewReverse; dsimp only; repeat' split
  all_goals first | exact settles_refused | exact settles_dup | exact settles_commit | skip

set_option maxHeartbeats 1000000 in
theorem settles_retry {v s v' c p k} : Settles v s (viewRecordRetry v' c p k) := by
  unfold viewRecordRetry; dsimp only; repeat' split
  all_goals first | exact settles_refused | exact settles_dup | skip

set_option maxHeartbeats 1000000 in
theorem settles_new {v s c} : Settles v s (viewRecordNew v s c) := by
  unfold viewRecordNew
  dsimp only
  refine settles_ite settles_refused (settles_ite settles_cu (settles_ite settles_refused
    (settles_ite settles_refused ?_)))
  split
  · exact settles_refused
  · refine settles_ite settles_refused ?_
    split
    · exact settles_refused
    · split
      · exact settles_ite (settles_ite settles_refused (settles_ite settles_aliasView settles_dup))
          (settles_ite settles_cu (settles_ite settles_refused settles_commit))
      · split
        · exact settles_refused
        · exact settles_commit

theorem settles_step {v : PaymentView} : Settles v (absorb v.state v.pending) (stepView v) := by
  unfold stepView
  dsimp only
  split
  · refine settles_ite settles_refused (settles_ite settles_refused ?_)
    split
    · exact settles_retry
    · exact settles_new
  · exact settles_reverse

/-- The carried scalars after a mutated call agree with `settle` of the `advance` it stored. -/
theorem advance_agree {F : Fast} {v : FView} {S s0 : ItemState} {w : Writes} (k : Mutation) (b a : Nat)
    (hA : Agree F S) (h : advance (v.toView S) S w = some s0) (r : FinancialResult) :
    Agree (F.post v (.mutated k w b a)) (settle s0 r) := by
  obtain ⟨hc, hl, he, hcf, hrq, hab⟩ := hA
  obtain ⟨env, byId, byOrigin, evid, cv, er, cmd⟩ := v
  obtain ⟨we, wp, wc, wk⟩ := w
  have hev : ((we.map fun e => insertBy (fun x => x) e.evidenceId S.evidenceIds).getD S.evidenceIds).length =
      F.evidence + (if we.isSome then 1 else 0) := by
    cases we <;> simp [length_insertBy, he]
  have hpay : ∀ (x : Option String) (f : Nat → Nat),
      S.requests.map (fun q => if x = some q.actionId then { q with paidCents := f q.paidCents } else q) =
        (if x.isNone then F.requests else
          F.requests.map fun q => if x = some q.actionId then { q with paidCents := f q.paidCents } else q) := by
    intro x f; rw [hrq]; cases x <;> simp
  rcases wp with _ | p <;> rcases wk with _ | kk <;> rcases byId with _ | ⟨q, k'⟩ <;>
    rcases wc with _ | x <;>
    simp only [advance, FView.toView, Option.isSome_none, Option.isSome_some, Bool.false_eq_true,
      ↓reduceIte] at h <;>
    (repeat' split at h) <;> cases h <;>
    exact ⟨by first | exact hc | exact congrArg (· + _) hc | exact congrArg (· - _) hc, hl, hev,
      by first | exact congrArg (· + 1) hcf | exact congrArg (· + 0) hcf | exact hcf,
      by first | exact hrq | exact hpay kk.paysActionId (· + p.amountCents)
               | exact hpay k'.paysActionId (· - q.amountCents),
      congrArg (· + _) hab⟩

/-! ### Index updates of a mutated call -/

theorem get?_insert_eq {β} (m : Std.TreeMap String β) (k : String) (v : β) (id : String) :
    (m.insert k v).get? id = if k = id then some v else m.get? id := by
  rw [Std.TreeMap.get?_eq_getElem?, Std.TreeMap.getElem?_insert, Std.TreeMap.get?_eq_getElem?]
  by_cases h : k = id
  · subst h; simp
  · have hc : compare k id ≠ .eq := fun e => h (Std.LawfulEqCmp.compare_eq_iff_eq.1 e)
    simp [hc, h]

/-- `insertIfNew` at a key the map has changes nothing. -/
theorem get?_insertIfNew_mem {β} {m : Std.TreeMap String β} {k : String} {v : β}
    (hk : (m.get? k).isSome) (id : String) : (m.insertIfNew k v).get? id = m.get? id := by
  have hm : k ∈ m := by
    rw [Std.TreeMap.mem_iff_isSome_getElem?, ← Std.TreeMap.get?_eq_getElem?]; exact hk
  rw [Std.TreeMap.get?_eq_getElem?, Std.TreeMap.getElem?_insertIfNew, Std.TreeMap.get?_eq_getElem?]
  simp [hm]

theorem contains_insert_eq (s : Std.TreeSet String) (k id : String) :
    (s.insert k).contains id = (decide (k = id) || s.contains id) := by
  rw [Std.TreeSet.contains_insert]
  by_cases h : k = id
  · subst h; simp
  · have hc : compare k id ≠ .eq := fun e => h (Std.LawfulEqCmp.compare_eq_iff_eq.1 e)
    cases hx : compare k id <;> simp only [h, decide_false] <;> first | exact absurd hx hc | rfl

theorem any_insertBy {α} (key : α → String) (row : α) (p : α → Bool) :
    ∀ l : List α, (insertBy key row l).any p = (p row || l.any p)
  | [] => by simp only [insertBy, List.any_cons, List.any_nil]
  | x :: xs => by
    simp only [insertBy]
    split
    · simp only [List.any_cons]
    · rw [List.any_cons, any_insertBy key row p xs, List.any_cons]
      cases p x <;> cases p row <;> rfl

theorem find?_insertBy_other {α} (key : α → String) (row : α) (p : α → Bool) (h : p row = false) :
    ∀ l : List α, (insertBy key row l).find? p = l.find? p
  | [] => by simp only [insertBy, List.find?_cons, h, List.find?_nil]
  | x :: xs => by
    simp only [insertBy]
    split
    · simp only [List.find?_cons, h]
    · simp only [List.find?_cons, find?_insertBy_other key row p h xs]

theorem find?_insertBy_unique {α} (key : α → String) (row : α) (p : α → Bool) (h : p row = true) :
    ∀ l : List α, (∀ x ∈ l, p x = false) → (insertBy key row l).find? p = some row
  | [], _ => by simp only [insertBy, List.find?_cons, h]
  | x :: xs, hl => by
    simp only [insertBy]
    split
    · simp only [List.find?_cons, h]
    · simp only [List.find?_cons, hl x (List.mem_cons.2 (Or.inl rfl))]
      exact find?_insertBy_unique key row p h xs fun y hy => hl y (List.mem_cons.2 (Or.inr hy))

theorem find?_map_preserve {α} (f : α → α) (P : α → Bool) :
    ∀ l : List α, (∀ x ∈ l, P (f x) = P x) → (l.map f).find? P = (l.find? P).map f
  | [], _ => rfl
  | x :: xs, h => by
    rw [List.map_cons, List.find?_cons, List.find?_cons, h x (List.mem_cons.2 (Or.inl rfl))]
    cases P x with
    | true => rfl
    | false => exact find?_map_preserve f P xs fun y hy => h y (List.mem_cons.2 (Or.inr hy))

/-- The payment write answers its id with the new row and every other id as before. -/
theorem findPayment_write {i : FinancialInput} {w : Writes} {p : Payment} (hp : w.payment = some p)
    (id : String) :
    findPayment (applyWrites i w).payments id = if p.paymentId = id then some p else findPayment i.payments id := by
  cases hf : findPayment i.payments p.paymentId with
  | none => rw [applyWrites_payments_insert hp hf, findPayment_insertBy hf]
  | some q =>
    have hq := findPayment_id _ _ _ hf
    simp only [applyWrites, hp, hf, Option.isSome_some, ↓reduceIte]
    rw [findPayment_replace i.payments p p rfl id]
    by_cases h : p.paymentId = id
    · subst h; rw [hf]; simp [hq]
    · rw [if_neg h]
      cases hx : findPayment i.payments id with
      | none => rfl
      | some x =>
        have hne : ¬ x.paymentId = p.paymentId := fun e => h (e.symm.trans (findPayment_id _ _ _ hx))
        simp only [Option.map_some, hne, ↓reduceIte]

theorem post_pays {F : Fast} {v : FView} {k w b a} {i : FinancialInput}
    (h : F.pays.get? = findPayment i.payments) :
    (F.post v (.mutated k w b a)).pays.get? = findPayment (applyWrites i w).payments := by
  funext id
  cases hp : w.payment with
  | none => simp only [Fast.post, applyWrites, hp]; rw [h]
  | some p => simp only [Fast.post, hp]; rw [get?_insert_eq, h, findPayment_write hp]

theorem post_rcpts {F : Fast} {v : FView} {k w b a} {rs : List Receipt}
    (h : F.rcpts.get? = receiptOf rs) (hf : ∀ kk, w.receipt = some kk → receiptOf rs kk.paymentId = none) :
    (F.post v (.mutated k w b a)).rcpts.get? = receiptOf (commitReceipts rs w) := by
  funext id
  cases hk : w.receipt with
  | none => simp only [Fast.post, commitReceipts, hk, Option.map_none, Option.getD_none]; rw [h]
  | some kk =>
    have hn := hf kk hk
    simp only [Fast.post, commitReceipts, hk, Option.map_some, Option.getD_some]
    rw [receiptOf_insertBy hn, ← h]
    exact get?_insertIfNew_fresh (by rw [h]; exact hn) id

theorem post_rows {F : Fast} {v : FView} {k w b a} {i : FinancialInput}
    (h : F.rows.get? = findEvidence i.evidence)
    (hf : ∀ e, w.evidence = some e → findEvidence i.evidence e.evidenceId = none) :
    (F.post v (.mutated k w b a)).rows.get? = findEvidence (applyWrites i w).evidence := by
  funext id
  cases he : w.evidence with
  | none => simp only [Fast.post, applyWrites, he, Option.map_none, Option.getD_none]; rw [h]
  | some e =>
    have hn := hf e he
    simp only [Fast.post, applyWrites, he, Option.map_some, Option.getD_some]
    rw [findEvidence_insertBy hn, ← h]
    exact get?_insertIfNew_fresh (by rw [h]; exact hn) id

theorem post_conflicts {F : Fast} {v : FView} {k w b a} {i : FinancialInput}
    (h : ∀ x, F.conflictIds.contains x = i.conflicts.any (·.conflictId = x)) (x : String) :
    (F.post v (.mutated k w b a)).conflictIds.contains x =
      (applyWrites i w).conflicts.any (·.conflictId = x) := by
  cases hc : w.conflict with
  | none => simp only [Fast.post, applyWrites, hc, Option.map_none, Option.getD_none]; exact h x
  | some y =>
    simp only [Fast.post, applyWrites, hc, Option.map_some, Option.getD_some]
    rw [contains_insert_eq, any_insertBy, h x]

theorem post_origins_none {F : Fast} {v : FView} {k w b a} {i : FinancialInput}
    (h : ∀ o, F.origins.get? o = (i.payments.find? (·.commonOriginId = o)).map (·.paymentId))
    (hp : w.payment = none) (o : String) :
    (F.post v (.mutated k w b a)).origins.get? o =
      ((applyWrites i w).payments.find? (·.commonOriginId = o)).map (·.paymentId) := by
  simp only [Fast.post, applyWrites, hp]
  exact h o

/-- RECORDED: a new id with a new origin. -/
theorem post_origins_insert {F : Fast} {v : FView} {k w b a} {i : FinancialInput} {P : Payment}
    (h : ∀ o, F.origins.get? o = (i.payments.find? (·.commonOriginId = o)).map (·.paymentId))
    (hp : w.payment = some P) (hf : findPayment i.payments P.paymentId = none)
    (hno : ∀ q ∈ i.payments, q.commonOriginId ≠ P.commonOriginId) (o : String) :
    (F.post v (.mutated k w b a)).origins.get? o =
      ((applyWrites i w).payments.find? (·.commonOriginId = o)).map (·.paymentId) := by
  have hk : F.origins.get? P.commonOriginId = none := by
    rw [h, List.find?_eq_none.2 (fun q hq => by simpa using hno q hq), Option.map_none]
  simp only [Fast.post, hp]
  rw [applyWrites_payments_insert hp hf, get?_insertIfNew_fresh hk, h]
  by_cases ho : P.commonOriginId = o
  · subst ho
    rw [if_pos rfl, find?_insertBy_unique Payment.paymentId P
      (fun x => decide (x.commonOriginId = P.commonOriginId)) (by simp) i.payments
      (fun q hq => by simpa using hno q hq)] <;> rfl
  · rw [if_neg ho, find?_insertBy_other Payment.paymentId P (fun x => decide (x.commonOriginId = o))
      (by simp [ho])]

/-- REVERSED: the row of an existing id is replaced, its origin kept. -/
theorem post_origins_replace {F : Fast} {v : FView} {k w b a} {i : FinancialInput} {P p : Payment}
    (h : ∀ o, F.origins.get? o = (i.payments.find? (·.commonOriginId = o)).map (·.paymentId))
    (hn : (i.payments.map Payment.paymentId).Nodup)
    (hp : w.payment = some P) (hf : findPayment i.payments P.paymentId = some p)
    (hid : P.paymentId = p.paymentId) (hor : P.commonOriginId = p.commonOriginId) (o : String) :
    (F.post v (.mutated k w b a)).origins.get? o =
      ((applyWrites i w).payments.find? (·.commonOriginId = o)).map (·.paymentId) := by
  have hmem : p ∈ i.payments := List.mem_of_find?_eq_some (by rw [← findPayment_eq]; exact hf)
  have hk : (F.origins.get? P.commonOriginId).isSome := by
    rw [h, hor]
    cases hx : i.payments.find? (fun x => decide (x.commonOriginId = p.commonOriginId)) with
    | none => exact (List.find?_eq_none.1 hx p hmem (by simp)).elim
    | some y => rfl
  have hpay : (applyWrites i w).payments = i.payments.map fun q => if q.paymentId = P.paymentId then P else q := by
    simp only [applyWrites, hp, hf, Option.isSome_some, ↓reduceIte]
  have hpres : ∀ q ∈ i.payments,
      (fun x => decide (x.commonOriginId = o)) ((fun q => if q.paymentId = P.paymentId then P else q) q) =
        (fun x => decide (x.commonOriginId = o)) q := by
    intro q hq
    show decide ((if q.paymentId = P.paymentId then P else q).commonOriginId = o) = decide (q.commonOriginId = o)
    by_cases hq' : q.paymentId = P.paymentId
    · have h1 := findPayment_of_mem hn hq
      rw [hq', hf] at h1
      rw [if_pos hq', hor, ← Option.some.inj h1]
    · rw [if_neg hq']
  simp only [Fast.post, hp]
  rw [get?_insertIfNew_mem hk, h, hpay, find?_map_preserve _ _ i.payments hpres]
  cases i.payments.find? (fun x => decide (x.commonOriginId = o)) with
  | none => rfl
  | some y =>
    show some y.paymentId = some (if y.paymentId = P.paymentId then P else y).paymentId
    by_cases hy : y.paymentId = P.paymentId
    · rw [if_pos hy, hy]
    · rw [if_neg hy]

/-- A mutated call keeps `Rel`: scalars by `advance_agree`, indexes by the write shape. -/
theorem Rel_mutated {F : Fast} {M : Ledger} {c : Call} {k w post res} (hR : Rel F M)
    (hr : requestWellFormed (M.request c) = true) (ho : M.outcome c = .mutated k w post res) :
    Rel (F.post (F.view c) (stepFast F (F.view c))) (step M c) := by
  have h : paymentTransition (M.request c) = .mutated k w post res := ho
  have hstep : step M c = { input := commitInput post res, receipts := commitReceipts M.receipts w } := by
    simp only [step, ho]
  have hI' : Inv (step M c) := step_Inv c hR.inv
  rw [hstep] at hI'
  obtain ⟨S, hA, hv⟩ := view_link hR c
  have h1 := stepView_eq hr rfl (v := (F.view c).toView S) hv
  rw [h] at h1
  have h2 : some (stepView ((F.view c).toView S)) =
      (summaryOf (commitInput post res) (commitReceipts M.receipts w)).map
        fun s => StepOutcome.mutated k w s res := h1
  have hfr : ∀ kk, w.receipt = some kk → receiptOf M.receipts kk.paymentId = none := by
    intro kk hk
    rcases mutated_shape h with ⟨-, c', -, hf, -, -, hrc, -⟩ | ⟨-, c', -, -, hrc, -⟩ |
      ⟨-, c', p, e', -, -, -, hw, -⟩
    · rw [hrc] at hk; cases hk; exact receiptOf_none hR.inv hf
    · rw [hrc] at hk; cases hk
    · subst hw; cases hk
  cases hsum : summaryOf (commitInput post res) (commitReceipts M.receipts w) with
  | none => rw [hsum, Option.map_none] at h2; cases h2
  | some S' =>
    rw [hsum, Option.map_some, Option.some.injEq] at h2
    obtain ⟨s0, hadv, hS'⟩ := settles_step (v := (F.view c).toView S) k w S' res h2
    obtain ⟨hpost, -⟩ := paymentTransition_mutated_post h
    subst hpost
    rw [link_step hR c hr, ho, hstep]
    exact {
      env := by
        show { { F.env with evaluatedAt := c.now } with beforeRevision := F.env.beforeRevision + 1 } = _
        rw [hR.env]; rfl
      pays := post_pays (i := (M.request c).input) hR.pays
      rcpts := post_rcpts hR.rcpts hfr
      origins := by
        rcases mutated_shape h with ⟨-, c', -, hf, hno, hpay, -⟩ | ⟨-, c', -, hpay, -⟩ |
          ⟨-, c', p, e', -, hfp, -, hw, -⟩
        · exact post_origins_insert (i := (M.request c).input) hR.origins hpay hf hno
        · exact post_origins_none (i := (M.request c).input) hR.origins hpay
        · exact post_origins_replace (i := (M.request c).input) (P := reversedImage p c') (p := p)
            hR.origins hR.inv.1 (by subst hw; rfl)
            (by rw [show (reversedImage p c').paymentId = c'.paymentId from findPayment_id _ _ p hfp]; exact hfp)
            rfl rfl
      rows := post_rows (i := (M.request c).input) hR.rows (mutated_fresh h)
      conflicts := post_conflicts (i := (M.request c).input) hR.conflicts
      agree := ⟨S', hsum, by rw [hS']; exact advance_agree k _ _ hA hadv res⟩
      inv := hI' }

/-- Every well-formed call keeps `Rel`. -/
theorem Rel_step {F : Fast} {M : Ledger} {c : Call} (hR : Rel F M)
    (hr : requestWellFormed (M.request c) = true) :
    Rel (F.post (F.view c) (stepFast F (F.view c))) (step M c) := by
  cases ho : M.outcome c
  case mutated k w post res => exact Rel_mutated hR hr ho
  case alias pid e post => exact Rel_alias hR hr ho
  all_goals exact Rel_post_other hR hr (fun _ _ _ _ h => by rw [ho] at h; cases h) (fun _ _ _ h => by rw [ho] at h; cases h)

/-- Under `Rel` and the premises `ok` decides (carried as in `chain_fold_eq_full`), the fast lane is
    the erased trace: `link_step` per call, `Rel_step` + `step_wellFormed` to the next. -/
theorem fast_eq_trace_of_rel (calls : List Call) (F : Fast) (M : Ledger) (hR : Rel F M)
    (hL : ledgerWellFormed M) (hc : clocksOk M calls) (hRv : M.input.beforeRevision + calls.length ≤ maxRevision)
    (hw : (calls.all fun c => commandWellFormed c.command && c.expectedRevision.all (· < 2 ^ 63)) = true) :
    fastFrom F calls = (trace M calls).map erase := by
  induction calls generalizing F M with
  | nil => rfl
  | cons c cs ih =>
    simp only [List.all_cons, Bool.and_eq_true] at hw
    obtain ⟨⟨hcmd, hexp⟩, hw2⟩ := hw
    have hpw := (List.pairwise_cons.1 hc.1).1 c.now (by simp)
    have hnow : c.now < 2 ^ 63 := by
      have := hc.2
      simp only [List.all_cons, Bool.and_eq_true, decide_eq_true_eq] at this
      exact this.1
    have hmax : c.now ≤ maxTime := by simp only [maxTime, maxCents]; omega
    have hrq : requestWellFormed (M.request c) = true := by
      simp only [requestWellFormed, Bool.and_eq_true]
      exact ⟨⟨⟨wf_now hL.1 hpw hmax, hL.2⟩, hcmd⟩, hexp⟩
    show stepFast F (F.view c) :: fastFrom (F.post (F.view c) (stepFast F (F.view c))) cs =
      erase (M.outcome c) :: (trace (step M c) cs).map erase
    refine List.cons_eq_cons.2 ⟨link_step hR c hrq, ?_⟩
    cases cs with
    | nil => rfl
    | cons c' cs' =>
      have hRs : M.input.beforeRevision + 1 < maxRevision := by
        simp only [List.length_cons] at hRv; omega
      have hclk : clocksOk M [c] := ⟨by simp [List.pairwise_cons, hpw], by simpa using hnow⟩
      refine ih _ _ (Rel_step hR hrq) (step_wellFormed M hL c hclk hRs) ?_ ?_ hw2
      · obtain ⟨hp1, hp2⟩ := hc
        simp only [List.all_cons, Bool.and_eq_true] at hp2
        refine ⟨?_, by simp only [List.all_cons, Bool.and_eq_true]; exact hp2.2⟩
        have h1 := List.pairwise_cons.1 hp1
        have h2 := List.pairwise_cons.1 h1.2
        refine List.pairwise_cons.2 ⟨fun b hb => ?_, h2.2⟩
        rcases step_eval M c with he | he <;> rw [he]
        · exact h1.1 b (List.mem_cons_of_mem _ hb)
        · exact h2.1 b hb
      · have := step_before_le M c
        simp only [List.length_cons] at hRv ⊢; omega

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
