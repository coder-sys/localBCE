import Std.Data.TreeMap
import Std.Data.TreeSet
import BlindLedger.Financial.Payment.BatchLaws

namespace BlindLedger.Financial.Payment

open BlindLedger.Financial BlindLedger.Financial.CorrectionTransition

/-! Owner batch, fast lane (S1g). `batchFast` runs the fast lane only where the premises of
    `chain_fold_eq_full` hold (`ok`), and `trace` otherwise, so `batchFast_eq_trace` is premise-free.
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

def Fast.init (L : Ledger) : Fast :=
  let i := L.input
  let t := evaluateTotals i
  { env := envOf i, cash := (t.map (·.cash)).getD 0, lawful := (t.map (·.lawful)).getD 0,
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

def fast (L : Ledger) (calls : List Call) : List Erased := fastFrom (Fast.init L) calls

/-- The batch: the fast lane where its premises hold, `trace` otherwise. -/
def batchFast (L : Ledger) (calls : List Call) : List Erased :=
  if ok L calls then fast L calls else (trace L calls).map erase

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

theorem fast_eq_trace_of_ok {L : Ledger} {calls : List Call} (h : ok L calls = true) :
    fast L calls = (trace L calls).map erase := by
  sorry

theorem batchFast_eq_trace (L : Ledger) (calls : List Call) :
    batchFast L calls = (trace L calls).map erase := by
  unfold batchFast
  split
  · exact fast_eq_trace_of_ok ‹_›
  · rfl

end BlindLedger.Financial.Payment
