import BlindLedger.Financial.Payment.Transition

namespace BlindLedger.Financial.Payment

open BlindLedger.Financial BlindLedger.Financial.CorrectionTransition

/-! ## 16.7 Chain state, view and step -/

structure ItemState where
  revision : Nat
  cash : Nat
  claimed : Nat
  lawful : Nat
  contributions : List EvalContribution
  latestCase : CaseStatus                 -- evalLatestCase (wf: at least one case row)
  delivery : DeliveryStatus
  conflictCount : Nat
  evidenceIds : List String
  requests : List RequestPaid
  anchorBytes : Nat                       -- anchorItemLength of this state (D3)
deriving DecidableEq, Repr

/-- The head as an input with no rows: the row builders (`confirmation`, `reversalRecord`,
    `recordedPayment`, `recordedReceipt`, `conflictImage`) read only these fields. -/
def _root_.BlindLedger.Financial.Env.head (e : Env) : FinancialInput :=
  { context := e.context, authority := e.authority, pack := e.pack, obligation := e.obligation,
    beforeRevision := e.beforeRevision, evaluatedAt := e.evaluatedAt, payments := [], claims := [],
    determinations := [], evidence := [], conflicts := [], cases := [], actions := [] }

structure PaymentView where
  env : Env
  state : ItemState
  pending : List EvidenceRecord
  byId : Option (Payment × Receipt)
  byOrigin : Option (Payment × Receipt × Option EvidenceRecord)
  evidence : Option EvidenceRecord
  conflictVisible : Bool
  foreign : Foreign
  expectedRevision : Option Nat
  command : Command
deriving DecidableEq, Repr

def summarize (i : FinancialInput) (rs : List Receipt) (anchorBytes : Nat) : Option ItemState :=
  (evaluateTotals i).map fun t =>
    { revision := i.beforeRevision, cash := t.cash, claimed := t.claimed, lawful := t.lawful,
      contributions := evalSortContributions (evalContributions i),
      latestCase := evalLatestCase i.cases, delivery := evalLatestDelivery i.actions,
      conflictCount := i.conflicts.length, evidenceIds := i.evidence.map (·.evidenceId),
      requests := (i.actions.filter (·.kind = "CORRECTION_PAYMENT_REQUEST")).map
        (requestPaidOf i.payments (linksOf rs)),
      anchorBytes }

def summaryOf (i : FinancialInput) (rs : List Receipt) : Option ItemState :=
  summarize i rs (anchorItemLength i rs)

def evaluateState (e : Env) (s : ItemState) : Option FinancialResult := do
  let total ← evalAdd s.cash s.lawful
  let owed := e.obligation.owedCents
  let completion := match evalCompletionLoop owed 0 s.contributions with
    | some t => some t
    | none => if total ≥ owed then evalLatestContributionTime s.contributions else none
  let amountSatisfied := total ≥ owed
  pure { context := e.context, authorityId := e.authority.authorityId,
         authorityEpoch := e.authority.epoch, authorityDigest := e.authority.digest,
         packId := e.pack.packId, packDigest := e.pack.digest,
         beforeRevision := e.beforeRevision, afterRevision := e.beforeRevision + 1,
         evaluatedAt := e.evaluatedAt, ruleVersion := e.obligation.ruleVersion,
         evidenceIds := s.evidenceIds, completionAt := completion, owedCents := owed,
         claimedAdjustmentCents := s.claimed, lawfulAdjustmentCents := s.lawful,
         receivedCashCents := s.cash,
         shortfallCents := if owed > total then owed - total else 0,
         overageCents := if total > owed then total - owed else 0,
         cashSatisfied := s.cash ≥ owed, amountSatisfied,
         timely := completion.any (· ≤ e.obligation.dueAt),
         reportingComplete := e.obligation.reportingComplete,
         verificationStatus := if s.conflictCount = 0 then
             (if s.evidenceIds.isEmpty then .MISSING_EVIDENCE else .SUPPORTED) else .CONFLICT_VISIBLE,
         caseStatus := caseStatusFrom s.latestCase e.obligation.reportingComplete amountSatisfied,
         deliveryStatus := s.delivery }

/-- Alias evidence rows written since the head link. -/
def absorb (s : ItemState) (pending : List EvidenceRecord) : ItemState :=
  pending.foldl (fun s e => { s with evidenceIds := insertBy (fun x => x) e.evidenceId s.evidenceIds,
                                     anchorBytes := s.anchorBytes + (encodeEvidence e).length }) s

/-- `addedBytes + receiptBytes`, with the replaced row read from the view. -/
def anchorGrowth (v : PaymentView) (w : Writes) : Nat :=
  evBytes w + (newPay w - (v.byId.map fun q => (encodePayment q.1).length).getD 0) + cfBytes w + receiptBytes w

/-- The state after the adapter writes `w`, before the case update. `none` exactly where
    `evaluate (applyWrites i w)` is `none` for a well-formed pre-state (a row count past
    `maxRows`, or cash + lawful past `maxCents`); `stepView_eq` is the proof obligation. -/
def advance (v : PaymentView) (s : ItemState) (w : Writes) : Option ItemState :=
  let s := { s with
    evidenceIds := (w.evidence.map fun e => insertBy (fun x => x) e.evidenceId s.evidenceIds).getD s.evidenceIds,
    conflictCount := s.conflictCount + (if w.conflict.isSome then 1 else 0),
    anchorBytes := s.anchorBytes + anchorGrowth v w }
  if s.evidenceIds.length > maxRows || s.conflictCount > maxRows then none else
  let pay (a : Option String) (f : Nat → Nat) : List RequestPaid :=
    s.requests.map fun q => if a = some q.actionId then { q with paidCents := f q.paidCents } else q
  match w.payment, w.receipt, v.byId with
  | some p, some k, _ =>
    if s.cash + p.amountCents + s.lawful > maxCents then none else
    some { s with cash := s.cash + p.amountCents,
                  contributions := evalInsertContribution ⟨p.eventAt, p.paymentId, p.amountCents⟩ s.contributions,
                  requests := pay k.paysActionId (· + p.amountCents) }
  | some _, none, some (q, k) =>
    some { s with cash := s.cash - q.amountCents,
                  contributions := s.contributions.erase ⟨q.eventAt, q.paymentId, q.amountCents⟩,
                  requests := pay k.paysActionId (· - q.amountCents) }
  | some _, none, none => none
  | none, _, _ => some s

def settle (s : ItemState) (r : FinancialResult) : ItemState :=
  { s with revision := r.afterRevision, latestCase := r.caseStatus }

inductive StepOutcome where
  | mutated (kind : Mutation) (writes : Writes) (state : ItemState) (result : FinancialResult)
  | alias (paymentId : String) (evidence : EvidenceRecord)
  | duplicate (paymentId : Option String)
  | conflictUnchanged (conflictId : String)
  | refused (reason : Refusal)
deriving DecidableEq, Repr

/-- `mutate` over the view. -/
def commitView (v : PaymentView) (s : ItemState) (k : Mutation) (w : Writes) : StepOutcome :=
  if v.env.context.mode = .SHADOW then .refused .SHADOW_READ_ONLY else
  if s.anchorBytes + anchorGrowth v w + maxCallTailBytes > maxTotalEncodedBytes then .refused .CAPACITY else
  match advance v s w with
  | none => .refused .POST_REJECTED
  | some s' =>
    match evaluateState v.env s' with
    | none => .refused .POST_REJECTED
    | some r => .mutated k w (settle s' r) r

/-- `aliasOf` over the view: the post-state is well-formed iff the evidence count fits. -/
def aliasView (v : PaymentView) (s : ItemState) (pid : String) (e : EvidenceRecord) : StepOutcome :=
  if v.env.context.mode = .SHADOW then .refused .SHADOW_READ_ONLY else
  if s.anchorBytes + (encodeEvidence e).length + maxCallTailBytes > maxTotalEncodedBytes then .refused .CAPACITY else
  if s.evidenceIds.length < maxRows then .alias pid e else .refused .POST_REJECTED

def viewRecordRetry (v : PaymentView) (c : RecordCommand) (p : Payment) (k : Receipt) : StepOutcome :=
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

/-- `linkRefusal` over the state. -/
def linkRefusalView (e : Env) (s : ItemState) (c : RecordCommand) : Option Refusal :=
  c.paysActionId.bind fun a =>
    match s.requests.find? (·.actionId = a) with
    | none => some .LINK_UNKNOWN
    | some q =>
      if (evaluateState e s).any fun b => c.amountCents ≤ openState b.shortfallCents s.requests q
      then none else some .LINK_EXCEEDS_UNPAID

def viewRecordNew (v : PaymentView) (s : ItemState) (c : RecordCommand) : StepOutcome :=
  let i := v.env.head
  let now := v.env.evaluatedAt
  let existing := v.byOrigin
  let same := existing.any (·.1.amountCents = c.amountCents)
  let stored := v.evidence
  let prior := same && (stored.isSome || v.foreign.evidenceId)
  let conflictId := conflictIdOf i c
  let reversedBefore := existing.any fun x => x.1.status = .REVERSED && x.2.2.any (·.eventAt < c.eventAt)
  if same && !prior && reversedBefore then .refused .ORIGIN_REVERSED else
  if existing.isSome && !same && v.conflictVisible &&
     (slotOf v.foreign.evidenceId stored (confirmation i c now)).isSame
  then .conflictUnchanged conflictId else
  if !prior && !v.expectedRevision.all (· = v.env.beforeRevision) then .refused .REVISION_CONFLICT else
  if prior && v.foreign.evidenceId then .refused .EVIDENCE_CONFLICT else
  let receivedAt := if prior then (stored.map (·.receivedAt)).getD now else now
  let e := confirmation i c receivedAt
  match formRefusal e with
  | some f => .refused f
  | none =>
  if c.eventAt > receivedAt then .refused .CHRONOLOGY else
  match slotOf v.foreign.evidenceId stored e with
  | .clash => .refused .EVIDENCE_CONFLICT
  | slot =>
    let fresh := slot.isFresh
    match existing with
    | some (p, k, _) =>
      if same then
        if c.paysActionId.isSome && c.paysActionId ≠ k.paysActionId then .refused .REQUEST_CONFLICT
        else if fresh then aliasView v s p.paymentId e else .duplicate (some p.paymentId)
      else if v.conflictVisible then .conflictUnchanged conflictId
      else if !idWellFormed conflictId then .refused .CONFLICT_ID_FORM
      else commitView v s .CONFLICT_RECORDED
        { evidence := if fresh then some e else none, payment := none, receipt := none,
          conflict := some (conflictImage i c p conflictId) }
    | none =>
      match linkRefusalView v.env s c with
      | some f => .refused f
      | none => commitView v s .RECORDED
        { evidence := if fresh then some e else none, conflict := none,
          payment := some (recordedPayment i c), receipt := some (recordedReceipt i c) }

def viewReverse (v : PaymentView) (s : ItemState) (c : ReverseCommand) : StepOutcome :=
  let i := v.env.head
  let now := v.env.evaluatedAt
  match v.byId with
  | none => .refused .PAYMENT_MISSING
  | some (p, _) =>
    if v.foreign.evidenceId then .refused .EVIDENCE_CONFLICT else
    let time := c.eventAt.getD ((v.evidence.map (·.eventAt)).getD now)
    let e := reversalRecord i c p time
    match formRefusal e with
    | some f => .refused f
    | none =>
    if time > now then .refused .CHRONOLOGY else
    match slotOf v.foreign.evidenceId v.evidence e with
    | .clash => .refused .EVIDENCE_CONFLICT
    | .same _ => .duplicate none
    | .fresh =>
      if !v.expectedRevision.all (· = v.env.beforeRevision) then .refused .REVISION_CONFLICT else
      if p.status = .REVERSED then .refused .ALREADY_REVERSED else
      commitView v s .REVERSED
        { evidence := some e, conflict := none, receipt := none, payment := some (reversedImage p c) }

/-- `paymentTransition` line for line, each list read replaced by the view field that names
    the same row, `mutate`/`aliasOf` by `commitView`/`aliasView`. -/
def stepView (v : PaymentView) : StepOutcome :=
  let s := absorb v.state v.pending
  match v.command with
  | .record c =>
    if c.amountCents = 0 then .refused .AMOUNT_ZERO else
    if v.foreign.paymentId then .refused .REQUEST_CONFLICT else
    match v.byId with
    | some (p, k) => viewRecordRetry v c p k
    | none => viewRecordNew v s c
  | .reverse c => viewReverse v s c

def cmdPaymentId : Command → String
  | .record c => c.paymentId
  | .reverse c => c.paymentId

def cmdEvidenceId : Command → String
  | .record c => c.evidenceId
  | .reverse c => c.evidenceId

/-- Form A: the view Lean builds from the whole input (O(input)). -/
def viewOfAnchor (r : PaymentRequest) : Option PaymentView :=
  let i := r.input
  let withReceipt (p : Payment) := (receiptOf r.receipts p.paymentId).map fun k => (p, k)
  (summarize i r.receipts (anchorOverhead + r.inputBytes + (encodeList encodeReceipt r.receipts).length)).map
    fun state =>
      { env := envOf i, state, pending := [],
        byId := (findPayment i.payments (cmdPaymentId r.command)).bind withReceipt,
        byOrigin := match r.command with
          | .record c => (i.payments.find? (·.commonOriginId = c.commonOriginId)).bind fun p =>
              (withReceipt p).map fun (p, k) => (p, k, p.reversalEvidenceId.bind (findEvidence i.evidence))
          | .reverse _ => none,
        evidence := findEvidence i.evidence (cmdEvidenceId r.command),
        conflictVisible := match r.command with
          | .record c => i.conflicts.any (·.conflictId = conflictIdOf i c)
          | .reverse _ => false,
        foreign := r.foreign, expectedRevision := r.expectedRevision, command := r.command }

def absorbed (v : PaymentView) : PaymentView := { v with state := absorb v.state v.pending, pending := [] }

end BlindLedger.Financial.Payment
