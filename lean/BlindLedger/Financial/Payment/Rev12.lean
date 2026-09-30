import BlindLedger.Financial.Payment.Bridge
import BlindLedger.Financial.Payment.Codec
import BlindLedger.Financial.Theorems.Vectors

/-! Design rev 1.2 (rrb/designs/lean-live-m3-v1.md section 16), type-checked with `sorry` proofs.
    Scratch only (branch m3-rev12): the builder ports each definition in place at M3 step 2.
    Names that already exist in `Payment` are the rev 1.2 replacements of those definitions;
    every other name is new (Chain.lean / ChainLaws.lean). Nothing calls this. -/

namespace BlindLedger.Financial.Payment.Rev12

/-! ## 16.1 Shared refactors (definitional; the `rfl` proofs show no behaviour changes) -/

def caseStatusFrom (prior : CaseStatus) (reportingComplete amountSatisfied : Bool) : CaseStatus :=
  if amountSatisfied && reportingComplete then .RESOLVED
  else if amountSatisfied then .ACTIONED
  else if prior = .CORRECTION_REQUIRED then .CORRECTION_REQUIRED
  else if prior = .AUTHORIZED then .AUTHORIZED
  else .OPEN

theorem evalCaseStatus_eq (i : FinancialInput) (a : Bool) :
    evalCaseStatus i a = caseStatusFrom (evalLatestCase i.cases) i.obligation.reportingComplete a := rfl

def slotOf (foreign : Bool) (stored : Option EvidenceRecord) (e : EvidenceRecord) : Slot :=
  if foreign then .clash else
  match stored with
  | none => .fresh
  | some s => if e.eventAt ≤ s.receivedAt ∧ { e with receivedAt := s.receivedAt } = s
              then .same s else .clash

theorem evidenceSlot_eq (r : PaymentRequest) (e : EvidenceRecord) :
    evidenceSlot r e = slotOf r.foreign.evidenceId (findEvidence r.input.evidence e.evidenceId) e := rfl

def conflictIdOf (i : FinancialInput) (c : RecordCommand) : String :=
  "conflict:" ++ i.context.itemId ++ ":" ++ c.commonOriginId ++ ":" ++ c.evidenceId

/-! ## 16.4 D3: capacity is the next anchor item, for any well-formed next call -/

def anchorOverhead : Nat := paymentMagic.length + 1 + 4
def maxCallTailBytes : Nat := 1024
def receiptBytes (w : Writes) : Nat := (w.receipt.map fun k => (encodeReceipt k).length).getD 0

def anchorItemLength (i : FinancialInput) (rs : List Receipt) : Nat :=
  anchorOverhead + (rawEncodeFinancialInput i).length + (encodeList encodeReceipt rs).length

def withinCapacity (r : PaymentRequest) (w : Writes) : Bool :=
  anchorOverhead + r.inputBytes + (encodeList encodeReceipt r.receipts).length + addedBytes r.input w +
    receiptBytes w + maxCallTailBytes ≤ maxTotalEncodedBytes

/-! ## Reference transition, rev 1.2 (D3 capacity, A2 in the write gates, R1 in the link rule) -/

def mutate (r : PaymentRequest) (k : Mutation) (w : Writes) : PaymentOutcome :=
  if r.input.context.mode = .SHADOW then .refused .SHADOW_READ_ONLY else
  if !withinCapacity r w then .refused .CAPACITY else
  let post := applyWrites r.input w
  match evaluate post with
  | none => .refused .POST_REJECTED
  | some result => .mutated k w post result

def aliasOf (r : PaymentRequest) (pid : String) (e : EvidenceRecord) : PaymentOutcome :=
  let w : Writes := { evidence := some e, payment := none, conflict := none, receipt := none }
  if r.input.context.mode = .SHADOW then .refused .SHADOW_READ_ONLY else
  if !withinCapacity r w then .refused .CAPACITY else
  let post := applyWrites r.input w
  if financialInputWellFormed post then .alias pid e post else .refused .POST_REJECTED

/-- The one link rule, R1: within the request and within the balance still owed. -/
def linkRefusal (i : FinancialInput) (rs : List Receipt) (c : RecordCommand) : Option Refusal :=
  c.paysActionId.bind fun a =>
    match i.actions.find? (fun x => x.actionId = a && x.kind = "CORRECTION_PAYMENT_REQUEST") with
    | none => some .LINK_UNKNOWN
    | some req =>
      if CorrectionTransition.linkedActivePaidCents i.payments (linksOf rs) a + c.amountCents >
           req.amountCents || !(evaluate i).any (c.amountCents ≤ ·.shortfallCents)
      then some .LINK_EXCEEDS_UNPAID else none

def recordNew (r : PaymentRequest) (c : RecordCommand) : PaymentOutcome :=
  let i := r.input
  let now := i.evaluatedAt
  let existing := i.payments.find? (·.commonOriginId = c.commonOriginId)
  let same := existing.any (·.amountCents = c.amountCents)
  let stored := findEvidence i.evidence c.evidenceId
  let prior := same && (stored.isSome || r.foreign.evidenceId)
  let conflictId := conflictIdOf i c
  let reversedBefore := existing.any fun p => p.status = .REVERSED &&
    ((p.reversalEvidenceId.bind (findEvidence i.evidence)).any fun v => v.eventAt < c.eventAt)
  if same && !prior && reversedBefore then .refused .ORIGIN_REVERSED else
  if existing.isSome && !same && i.conflicts.any (·.conflictId = conflictId) &&
     (evidenceSlot r (confirmation i c now)).isSame
  then .conflictUnchanged conflictId else
  if !prior && !revisionOk r then .refused .REVISION_CONFLICT else
  if prior && r.foreign.evidenceId then .refused .EVIDENCE_CONFLICT else
  let receivedAt := if prior then (stored.map (·.receivedAt)).getD now else now
  let e := confirmation i c receivedAt
  match formRefusal e with
  | some f => .refused f
  | none =>
  if c.eventAt > receivedAt then .refused .CHRONOLOGY else
  match evidenceSlot r e with
  | .clash => .refused .EVIDENCE_CONFLICT
  | slot =>
    let fresh := slot.isFresh
    match existing with
    | some p =>
      if same then
        if c.paysActionId.isSome &&
           c.paysActionId ≠ ((receiptOf r.receipts p.paymentId).bind (·.paysActionId))
        then .refused .REQUEST_CONFLICT
        else if fresh then aliasOf r p.paymentId e else .duplicate (some p.paymentId)
      else if i.conflicts.any (·.conflictId = conflictId) then .conflictUnchanged conflictId
      else if !idWellFormed conflictId then .refused .CONFLICT_ID_FORM
      else mutate r .CONFLICT_RECORDED
        { evidence := if fresh then some e else none, payment := none, receipt := none,
          conflict := some (conflictImage i c p conflictId) }
    | none =>
      match linkRefusal i r.receipts c with
      | some f => .refused f
      | none => mutate r .RECORDED
        { evidence := if fresh then some e else none, conflict := none,
          payment := some (recordedPayment i c), receipt := some (recordedReceipt i c) }

def decideRecord (r : PaymentRequest) (c : RecordCommand) : PaymentOutcome :=
  if c.amountCents = 0 then .refused .AMOUNT_ZERO else
  if r.foreign.paymentId then .refused .REQUEST_CONFLICT else
  match findPayment r.input.payments c.paymentId with
  | some p => recordRetry r c p
  | none => recordNew r c

def decideReverse (r : PaymentRequest) (c : ReverseCommand) : PaymentOutcome :=
  let i := r.input
  let now := i.evaluatedAt
  match findPayment i.payments c.paymentId with
  | none => .refused .PAYMENT_MISSING
  | some p =>
    if r.foreign.evidenceId then .refused .EVIDENCE_CONFLICT else
    let time := c.eventAt.getD (((findEvidence i.evidence c.evidenceId).map (·.eventAt)).getD now)
    let e := reversalRecord i c p time
    match formRefusal e with
    | some f => .refused f
    | none =>
    if time > now then .refused .CHRONOLOGY else
    match evidenceSlot r e with
    | .clash => .refused .EVIDENCE_CONFLICT
    | .same _ => .duplicate none
    | .fresh =>
      if !revisionOk r then .refused .REVISION_CONFLICT else
      if p.status = .REVERSED then .refused .ALREADY_REVERSED else
      mutate r .REVERSED
        { evidence := some e, conflict := none, receipt := none, payment := some (reversedImage p c) }

def paymentTransition (r : PaymentRequest) : PaymentOutcome :=
  match r.command with
  | .record c => decideRecord r c
  | .reverse c => decideReverse r c

/-! ## 16.3 The ledger commits the owner's case update (carry premise A1, owner line 2805) -/

def outcome (L : Ledger) (c : Call) : PaymentOutcome := paymentTransition (L.request c)

def commitInput (post : FinancialInput) (res : FinancialResult) : FinancialInput :=
  { post with beforeRevision := post.beforeRevision + 1,
              cases := post.cases.map fun k => { k with status := res.caseStatus, updatedAt := post.evaluatedAt } }

def commitReceipts (rs : List Receipt) (w : Writes) : List Receipt :=
  (w.receipt.map fun k => insertBy Receipt.paymentId k rs).getD rs

def step (L : Ledger) (c : Call) : Ledger :=
  match outcome L c with
  | .mutated _ w post res => { input := commitInput post res, receipts := commitReceipts L.receipts w }
  | .alias _ _ post => { L with input := post }
  | _ => L

def run (L : Ledger) (calls : List Call) : Ledger := calls.foldl step L

def trace : Ledger → List Call → List PaymentOutcome
  | _, [] => []
  | L, c :: cs => outcome L c :: trace (step L c) cs

def ledgers : Ledger → List Call → List Ledger
  | _, [] => []
  | L, c :: cs => L :: ledgers (step L c) cs

/-! ## 16.7 Chain state, view and step -/

structure RequestPaid where
  actionId : String
  amountCents : Nat
  paidCents : Nat
deriving DecidableEq, Repr

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

structure Env where
  context : FinancialContext
  authority : TrustedAuthority
  pack : ControlPack
  obligation : Obligation
  beforeRevision : Nat
  evaluatedAt : Nat
deriving DecidableEq, Repr

def envOf (i : FinancialInput) : Env :=
  ⟨i.context, i.authority, i.pack, i.obligation, i.beforeRevision, i.evaluatedAt⟩

/-- The head as an input with no rows: the row builders (`confirmation`, `reversalRecord`,
    `recordedPayment`, `recordedReceipt`, `conflictImage`) read only these fields. -/
def Env.head (e : Env) : FinancialInput :=
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
      requests := (i.actions.filter (·.kind = "CORRECTION_PAYMENT_REQUEST")).map fun a =>
        ⟨a.actionId, a.amountCents,
          CorrectionTransition.linkedActivePaidCents i.payments (linksOf rs) a.actionId⟩,
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
      if q.paidCents + c.amountCents > q.amountCents ||
         !(evaluateState e s).any (c.amountCents ≤ ·.shortfallCents)
      then some .LINK_EXCEEDS_UNPAID else none

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

/-! ## Views from a full snapshot, faithfulness and projection -/

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

/-- The owner's point reads return the rows the snapshot `r` holds, and its stored state plus
    pending aliases is that snapshot's summary. Carry premise (keys, coherence, checker; R20). -/
def Faithful (r : PaymentRequest) (v : PaymentView) : Prop := viewOfAnchor r = some (absorbed v)

/-- The stored-row image of a reference outcome: `post` replaced by the committed summary. -/
def project (r : PaymentRequest) : PaymentOutcome → Option StepOutcome
  | .mutated k w post res =>
      (summaryOf (commitInput post res) (commitReceipts r.receipts w)).map fun s => .mutated k w s res
  | .alias pid e _ => some (.alias pid e)
  | .duplicate pid => some (.duplicate pid)
  | .conflictUnchanged id => some (.conflictUnchanged id)
  | .refused f => some (.refused f)

def ChainFaithful (L : Ledger) (calls : List Call) (vs : List PaymentView) : Prop :=
  vs.length = calls.length ∧ ∀ (n : Nat) (M : Ledger) (c : Call) (v : PaymentView), (ledgers L calls)[n]? = some M → calls[n]? = some c →
    vs[n]? = some v → Faithful (M.request c) v

/-! ## 16.8 Codecs: form B, the answer, and the worker entry -/

def encodeOpt {α : Type} (f : α → Bytes) : Option α → Bytes
  | none => [UInt8.ofNat 0]
  | some a => UInt8.ofNat 1 :: f a

def readOpt {α : Type} (f : Bytes → Option (α × Bytes)) (b : Bytes) : Option (Option α × Bytes) := do
  let (tag, b) ← readByte b
  if tag.toNat = 0 then pure (none, b)
  else if tag.toNat = 1 then do
    let (a, b) ← f b
    pure (some a, b)
  else none

def encodeEnv (e : Env) : Bytes :=
  encodeContext e.context ++ encodeAuthority e.authority ++ encodeControlPack e.pack ++
    encodeObligation e.obligation ++ natBE 8 e.beforeRevision ++ natBE 8 e.evaluatedAt

def readEnv (b : Bytes) : Option (Env × Bytes) := do
  let (context, b) ← decodeContext b
  let (authority, b) ← decodeAuthority b
  let (pack, b) ← decodeControlPack b
  let (obligation, b) ← decodeObligation b
  let (beforeRevision, b) ← readNatBE 8 b
  let (evaluatedAt, b) ← readNatBE 8 b
  pure (⟨context, authority, pack, obligation, beforeRevision, evaluatedAt⟩, b)

def encodeContribution (x : EvalContribution) : Bytes :=
  natBE 8 x.time ++ encodeString x.identity ++ natBE 8 x.amountCents

def readContribution (b : Bytes) : Option (EvalContribution × Bytes) := do
  let (time, b) ← readNatBE 8 b
  let (identity, b) ← readString b
  let (amountCents, b) ← readNatBE 8 b
  pure (⟨time, identity, amountCents⟩, b)

def encodeRequestPaid (q : RequestPaid) : Bytes :=
  encodeString q.actionId ++ natBE 8 q.amountCents ++ natBE 8 q.paidCents

def readRequestPaid (b : Bytes) : Option (RequestPaid × Bytes) := do
  let (actionId, b) ← readString b
  let (amountCents, b) ← readNatBE 8 b
  let (paidCents, b) ← readNatBE 8 b
  pure (⟨actionId, amountCents, paidCents⟩, b)

/-- Contributions: u16 count up to 2 * maxRows (payments plus determinations). -/
def encodeItemState (s : ItemState) : Bytes :=
  natBE 8 s.revision ++ natBE 8 s.cash ++ natBE 8 s.claimed ++ natBE 8 s.lawful ++
    encodeList encodeContribution s.contributions ++
    [encodeCaseStatus s.latestCase, encodeDeliveryStatus s.delivery] ++ natBE 2 s.conflictCount ++
    encodeList encodeString s.evidenceIds ++ encodeList encodeRequestPaid s.requests ++ natBE 4 s.anchorBytes

def readItemState (b : Bytes) : Option (ItemState × Bytes) := do
  let (revision, b) ← readNatBE 8 b
  let (cash, b) ← readNatBE 8 b
  let (claimed, b) ← readNatBE 8 b
  let (lawful, b) ← readNatBE 8 b
  let (n, b) ← readNatBE 2 b
  let (contributions, b) ← if n > 2 * maxRows then none else readMany readContribution n b
  let (caseByte, b) ← readByte b
  let latestCase ← decodeCaseStatus caseByte
  let (deliveryByte, b) ← readByte b
  let delivery ← decodeDeliveryStatus deliveryByte
  let (conflictCount, b) ← readNatBE 2 b
  let (evidenceIds, b) ← readList readString b
  let (requests, b) ← readList readRequestPaid b
  let (anchorBytes, b) ← readNatBE 4 b
  pure ({ revision, cash, claimed, lawful, contributions, latestCase, delivery, conflictCount,
          evidenceIds, requests, anchorBytes }, b)

def encodeFormB (v : PaymentView) : Bytes :=
  paymentMagic ++ [UInt8.ofNat 2] ++ encodeEnv v.env ++ encodeItemState v.state ++
    encodeList encodeEvidence v.pending ++
    encodeOpt (fun (x : Payment × Receipt) => encodePayment x.1 ++ encodeReceipt x.2) v.byId ++
    encodeOpt (fun (x : Payment × Receipt × Option EvidenceRecord) =>
      encodePayment x.1 ++ encodeReceipt x.2.1 ++ encodeOpt encodeEvidence x.2.2) v.byOrigin ++
    encodeOpt encodeEvidence v.evidence ++ encodeBool v.conflictVisible ++
    encodeForeign v.foreign ++ encodeOptionNat v.expectedRevision ++ encodeCommand v.command

def parseFormB (w : Bytes) : Option PaymentView := do
  let (env, b) ← readEnv (w.drop (paymentMagic.length + 1))
  let (state, b) ← readItemState b
  let (pending, b) ← readList decodeEvidence b
  let (byId, b) ← readOpt (fun b => do
    let (p, b) ← decodePayment b
    let (k, b) ← readReceipt b
    pure ((p, k), b)) b
  let (byOrigin, b) ← readOpt (fun b => do
    let (p, b) ← decodePayment b
    let (k, b) ← readReceipt b
    let (e, b) ← readOpt decodeEvidence b
    pure ((p, k, e), b)) b
  let (evidence, b) ← readOpt decodeEvidence b
  let (conflictVisible, b) ← readBool b
  let (foreign, b) ← readForeign b
  let (expectedRevision, b) ← readOptionNat b
  let (command, _) ← readCommand b
  pure { env, state, pending, byId, byOrigin, evidence, conflictVisible, foreign, expectedRevision, command }

/-- The head conjuncts of `financialInputWellFormed` (the port extracts them there, once). -/
def envWellFormed (e : Env) : Bool :=
  contextWellFormed e.context && authorityWellFormed e.authority &&
    controlPackWellFormed e.pack && obligationWellFormed e.obligation &&
    e.beforeRevision < maxRevision && revisionWellFormed e.beforeRevision &&
    timeWellFormed e.evaluatedAt &&
    e.pack.stateId = e.context.stateId && e.pack.deploymentId = e.context.deploymentId &&
    e.pack.programId = e.context.programId && e.pack.periodId = e.context.periodId &&
    e.pack.currency = e.context.currency &&
    e.obligation.populationId = e.context.populationId && e.obligation.itemId = e.context.itemId &&
    e.obligation.obligationId = e.context.obligationId && e.obligation.ruleVersion = e.pack.version

def stateWellFormed (s : ItemState) : Bool :=
  s.revision < maxRevision && s.cash ≤ maxCents && s.claimed ≤ maxCents && s.lawful ≤ maxCents &&
    s.contributions.length ≤ 2 * maxRows &&
    s.contributions.all (fun x => timeWellFormed x.time && idWellFormed x.identity && x.amountCents ≤ maxCents) &&
    s.conflictCount ≤ maxRows && s.evidenceIds.length ≤ maxRows && canonicalIdList s.evidenceIds &&
    s.requests.length ≤ maxRows &&
    s.requests.all (fun q => idWellFormed q.actionId && q.amountCents ≤ maxCents && q.paidCents ≤ maxCents) &&
    s.anchorBytes ≤ maxTotalEncodedBytes

def viewWellFormed (v : PaymentView) : Bool :=
  let ctx := v.env.context
  let rowOk (p : Payment) (k : Receipt) := paymentWellFormed ctx p && k.paymentId = p.paymentId &&
    k.recordedRevision < v.env.beforeRevision && k.paysActionId.all idWellFormed
  envWellFormed v.env && stateWellFormed v.state && v.pending.length ≤ maxRows &&
    canonicalIdList (v.pending.map (·.evidenceId)) && v.pending.all (evidenceWellFormed ctx) &&
    v.byId.all (fun x => rowOk x.1 x.2) &&
    v.byOrigin.all (fun x => rowOk x.1 x.2.1 && x.2.2.all (evidenceWellFormed ctx)) &&
    v.evidence.all (evidenceWellFormed ctx) &&
    commandWellFormed v.command && v.expectedRevision.all (· < 2 ^ 63)

/-- Section 2.6 coherence: the rows are the ones the command names, and agree with the state. -/
def coherent (v : PaymentView) : Bool :=
  let contributes (p : Payment) :=
    decide (p.status = .ACTIVE) == v.state.contributions.contains ⟨p.eventAt, p.paymentId, p.amountCents⟩
  v.state.revision = v.env.beforeRevision &&
    v.byId.all (fun x => x.1.paymentId = cmdPaymentId v.command && contributes x.1) &&
    v.evidence.all (·.evidenceId = cmdEvidenceId v.command) &&
    v.pending.all (fun e => !v.state.evidenceIds.contains e.evidenceId) &&
    (match v.command with
     | .record c => v.byOrigin.all fun x => x.1.commonOriginId = c.commonOriginId && contributes x.1 &&
         x.2.2.all fun e => some e.evidenceId = x.1.reversalEvidenceId
     | .reverse _ => v.byOrigin.isNone && !v.conflictVisible)

def decodePaymentItem (w : Bytes) : Option PaymentView :=
  match w.drop paymentMagic.length with
  | f :: _ =>
    if f.toNat = 1 then (decodePaymentRequest w).bind viewOfAnchor
    else if f.toNat = 2 then
      (parseFormB w).filter fun v => viewWellFormed v && coherent v && encodeFormB v == w
    else none
  | [] => none

def answerMagic : Bytes := "BLFPRS01".toUTF8.toList
def mutations : List Mutation := [.RECORDED, .REVERSED, .CONFLICT_RECORDED]
def refusals : List Refusal :=
  [.AMOUNT_ZERO, .REQUEST_CONFLICT, .ORIGIN_REVERSED, .REVISION_CONFLICT, .EVIDENCE_CONFLICT,
   .CHRONOLOGY, .LINK_UNKNOWN, .LINK_EXCEEDS_UNPAID, .PAYMENT_MISSING, .ALREADY_REVERSED,
   .ORIGIN_FORM, .LOCAL_REF_FORM, .CONFLICT_ID_FORM, .CAPACITY, .POST_REJECTED, .SHADOW_READ_ONLY]

def rawEncodeStepOutcome : StepOutcome → Bytes
  | .mutated k w s r =>
    let res := rawEncodeFinancialResult r
    answerMagic ++ [UInt8.ofNat (mutations.findIdx (· == k) + 1)] ++
      encodeOpt encodeEvidence w.evidence ++ encodeOpt encodePayment w.payment ++
      encodeOpt encodeConflict w.conflict ++ encodeOpt encodeReceipt w.receipt ++
      encodeItemState s ++ natBE 4 res.length ++ res
  | .conflictUnchanged id => answerMagic ++ [UInt8.ofNat 4] ++ encodeString id
  | .alias pid e => answerMagic ++ [UInt8.ofNat 5] ++ encodeString pid ++ encodeEvidence e
  | .duplicate pid => answerMagic ++ [UInt8.ofNat 6] ++ encodeOptionString pid
  | .refused f => answerMagic ++ [UInt8.ofNat 7, UInt8.ofNat (refusals.findIdx (· == f) + 1)]

def parseStepOutcome (b : Bytes) : Option StepOutcome := do
  let (tag, b) ← readByte (b.drop answerMagic.length)
  if tag.toNat = 4 then return .conflictUnchanged (← readString b).1
  if tag.toNat = 5 then
    let (pid, b) ← readString b
    let (e, _) ← decodeEvidence b
    return .alias pid e
  if tag.toNat = 6 then return .duplicate (← readOptionString b).1
  if tag.toNat = 7 then
    let (f, _) ← readByte b
    return .refused (← refusals[f.toNat - 1]?)
  let k ← mutations[tag.toNat - 1]?
  let (evidence, b) ← readOpt decodeEvidence b
  let (payment, b) ← readOpt decodePayment b
  let (conflict, b) ← readOpt decodeConflict b
  let (receipt, b) ← readOpt readReceipt b
  let (s, b) ← readItemState b
  let (m, b) ← readNatBE 4 b
  let r ← decodeFinancialResult (b.take m)
  return .mutated k { evidence, payment, conflict, receipt } s r

/-- Canonical by re-encoding, as `decodePaymentRequest`. -/
def decodeStepOutcome (b : Bytes) : Option StepOutcome :=
  (parseStepOutcome b).filter fun o => rawEncodeStepOutcome o == b

/-- An answer is sent only if it decodes to exactly the outcome; otherwise worker byte 3. -/
def encodeStepOutcome (o : StepOutcome) : Option Bytes :=
  let b := rawEncodeStepOutcome o
  if decodeStepOutcome b = some o then some b else none

def paymentRespond (w : Bytes) : Bytes :=
  match decodePaymentItem w with
  | none => [UInt8.ofNat 1]
  | some v =>
    match encodeStepOutcome (stepView v) with
    | none => [UInt8.ofNat 3]
    | some b => UInt8.ofNat 0 :: b

section TrLayer
open BlindLedger.Financial.CorrectionTransition

/-! ## Transfer: a non-refused rev 1.2 outcome is the old outcome (rev 1.2 only adds refusals) -/

theorem cap_tr {r w} (hc : Rev12.withinCapacity r w = true) : Payment.withinCapacity r w = true := by
  unfold Rev12.withinCapacity at hc
  unfold Payment.withinCapacity
  simp only [decide_eq_true_eq] at hc ⊢
  generalize maxTotalEncodedBytes = M at hc ⊢
  omega

/-- A shadow request has no mutated or alias outcome; a mutation or alias fits (D3). -/
abbrev Live (r : PaymentRequest) (o : PaymentOutcome) : Prop :=
  (r.input.context.mode = .SHADOW → (∀ k w p res, o ≠ .mutated k w p res) ∧ ∀ pid e p, o ≠ .alias pid e p) ∧
  (∀ k w p res, o = .mutated k w p res → withinCapacity r w = true) ∧
  ∀ pid e p, o = .alias pid e p →
    withinCapacity r { evidence := some e, payment := none, conflict := none, receipt := none } = true

theorem mutate_tr {r k w o} (h : Rev12.mutate r k w = o) (hn : ∀ f, o ≠ .refused f) :
    Payment.mutate r k w = o ∧ Live r o := by
  unfold Rev12.mutate at h
  unfold Payment.mutate
  split at h
  · exact absurd h.symm (hn _)
  split at h
  · exact absurd h.symm (hn _)
  rename_i hs hc
  simp only [Bool.not_eq_true, Bool.not_eq_false'] at hc
  dsimp only at h ⊢
  have h1 : Payment.mutate r k w = o := by
    unfold Payment.mutate
    dsimp only
    split
    · rename_i h2; simp [cap_tr hc] at h2
    · exact h
  refine ⟨h1, fun hs' => absurd hs' hs, fun k' w' p' res' ho => ?_, fun pid' e' p' ho => ?_⟩
  · obtain ⟨-, rfl, -⟩ := mutate_eq (h1.trans ho); exact hc
  · exact absurd (h1.trans ho) mutate_ne_alias

theorem alias_tr {r pid e o} (h : Rev12.aliasOf r pid e = o) (hn : ∀ f, o ≠ .refused f) :
    Payment.aliasOf r pid e = o ∧ Live r o := by
  unfold Rev12.aliasOf at h
  unfold Payment.aliasOf
  dsimp only at h ⊢
  split at h
  · exact absurd h.symm (hn _)
  split at h
  · exact absurd h.symm (hn _)
  rename_i hs hc
  simp only [Bool.not_eq_true, Bool.not_eq_false'] at hc
  have h1 : Payment.aliasOf r pid e = o := by
    unfold Payment.aliasOf
    dsimp only
    split
    · rename_i h2; simp [cap_tr hc] at h2
    · exact h
  refine ⟨h1, fun hs' => absurd hs' hs, fun k' w' p' res' ho => ?_, fun pid' e' p' ho => ?_⟩
  · exact absurd (h1.trans ho) aliasOf_ne_mutated
  · obtain ⟨-, rfl, -⟩ := aliasOf_alias (h1.trans ho); exact hc

def R1Holds (r : PaymentRequest) (c : RecordCommand) (o : PaymentOutcome) : Prop :=
  ∀ w post res, o = .mutated .RECORDED w post res → ∀ a, c.paysActionId = some a →
    (evaluate r.input).any (fun x => decide (c.amountCents ≤ x.shortfallCents)) = true

theorem facts_nm {r c x o} (h : x = o) (hm : ∀ k w p res, x ≠ .mutated k w p res)
    (ha : ∀ pid e p, x ≠ .alias pid e p) : x = o ∧ Live r o ∧ R1Holds r c o :=
  ⟨h, ⟨fun _ => ⟨fun k w p res ho => hm k w p res (h.trans ho), fun pid e p ho => ha pid e p (h.trans ho)⟩,
    fun k w p res ho => absurd (h.trans ho) (hm k w p res), fun pid e p ho => absurd (h.trans ho) (ha pid e p)⟩,
   fun w p res ho => absurd (h.trans ho) (hm _ _ _ _)⟩

theorem dup_leaf {r c o pid} (h : PaymentOutcome.duplicate pid = o) :
    PaymentOutcome.duplicate pid = o ∧ Live r o ∧ R1Holds r c o :=
  facts_nm h (fun _ _ _ _ => nofun) (fun _ _ _ => nofun)

set_option maxHeartbeats 2000000 in
theorem recordNew_tr {r c o} (h : Rev12.recordNew r c = o) (hn : ∀ f, o ≠ .refused f) :
    Payment.recordNew r c = o ∧ Live r o ∧ R1Holds r c o := by
  have nm : ∀ {x : PaymentOutcome}, x = o → (∀ k w p res, x ≠ .mutated k w p res) →
      (∀ pid e p, x ≠ .alias pid e p) → x = o ∧ Live r o ∧ R1Holds r c o := facts_nm
  unfold Rev12.recordNew at h
  unfold Payment.recordNew
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
             unfold R1Holds
             exact ⟨h1, h2, fun w' p' r' ho => absurd (h1.trans ho) (aliasOf_ne_mutated (r := r) (pid := p.paymentId))⟩)
      · rw [if_neg s1] at h ⊢
        by_cases c7 : cv = true
        · rw [if_pos c7] at h ⊢; exact nm h (fun _ _ _ _ => nofun) (fun _ _ _ => nofun)
        rw [if_neg c7] at h ⊢
        by_cases c8 : (!idWellFormed ("conflict:" ++ r.input.context.itemId ++ ":" ++ c.commonOriginId ++ ":" ++ c.evidenceId)) = true
        · rw [if_pos c8] at h ⊢; exact nm h (fun _ _ _ _ => nofun) (fun _ _ _ => nofun)
        rw [if_neg c8] at h ⊢
        obtain ⟨h1, h2⟩ := mutate_tr h hn
        unfold R1Holds
        exact ⟨h1, h2, fun w' p' r' ho => by
          have := (mutate_eq (h1.trans ho)).1
          cases this⟩
    | none =>
      unfold R1Holds
      dsimp only at h ⊢
      unfold linkRefusal at h
      generalize c.paysActionId = pa at h ⊢
      cases pa with
      | none =>
        obtain ⟨h1, h2⟩ := mutate_tr h hn
        exact ⟨h1, h2, fun w' p' r' ho a ha => by cases ha⟩
      | some a =>
        simp only [Option.bind_some] at h ⊢
        generalize List.find? (fun x => decide (x.actionId = a) && decide (x.kind = "CORRECTION_PAYMENT_REQUEST")) r.input.actions = fo at h ⊢
        cases fo with
        | none => dsimp only at h ⊢; exact ⟨h, ⟨fun _ => ⟨fun k w p res ho => (nomatch h.trans ho), fun pid e p ho => (nomatch h.trans ho)⟩, fun k w p res ho => (nomatch h.trans ho), fun pid e p ho => (nomatch h.trans ho)⟩, fun w p res ho => (nomatch h.trans ho)⟩
        | some req =>
          dsimp only at h ⊢
          generalize Option.any (fun x => decide (c.amountCents ≤ x.shortfallCents)) (evaluate r.input) = B at h ⊢
          by_cases a1 : linkedActivePaidCents r.input.payments (linksOf r.receipts) a + c.amountCents > req.amountCents
          · simp only [a1, decide_true, Bool.true_or, ↓reduceIte] at h ⊢
            exact ⟨h, ⟨fun _ => ⟨fun k w p res ho => (nomatch h.trans ho), fun pid e p ho => (nomatch h.trans ho)⟩, fun k w p res ho => (nomatch h.trans ho), fun pid e p ho => (nomatch h.trans ho)⟩, fun w p res ho => (nomatch h.trans ho)⟩
          · simp only [a1, decide_false, Bool.false_or, ↓reduceIte] at h ⊢
            by_cases b1 : (!B) = true
            · simp only [b1, ↓reduceIte] at h; exact absurd h.symm (hn _)
            · simp only [b1] at h
              obtain ⟨h1, h2⟩ := mutate_tr h hn
              refine ⟨h1, h2, fun w' p' r' ho a' ha => ?_⟩
              simpa using b1

theorem decideReverse_tr {r c o} (h : Rev12.decideReverse r c = o) (hn : ∀ f, o ≠ .refused f) :
    Payment.decideReverse r c = o ∧ Live r o := by
  have nm : ∀ {x : PaymentOutcome}, x = o → (∀ k w p res, x ≠ .mutated k w p res) →
      (∀ pid e p, x ≠ .alias pid e p) → x = o ∧ Live r o := fun h hm ha =>
    ⟨h, ⟨fun _ => ⟨fun k w p res ho => hm k w p res (h.trans ho), fun pid e p ho => ha pid e p (h.trans ho)⟩,
      fun k w p res ho => absurd (h.trans ho) (hm k w p res), fun pid e p ho => absurd (h.trans ho) (ha pid e p)⟩⟩
  unfold Rev12.decideReverse at h
  unfold Payment.decideReverse
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

theorem decideRecord_tr {r c o} (h : Rev12.decideRecord r c = o) (hn : ∀ f, o ≠ .refused f) :
    Payment.decideRecord r c = o ∧ Live r o ∧ R1Holds r c o := by
  unfold Rev12.decideRecord at h
  unfold Payment.decideRecord
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
  | none => exact recordNew_tr h hn

theorem paymentTransition_tr {r o} (h : Rev12.paymentTransition r = o) (hn : ∀ f, o ≠ .refused f) :
    Payment.paymentTransition r = o ∧ Live r o := by
  unfold Rev12.paymentTransition at h
  unfold Payment.paymentTransition
  generalize r.command = cmd at h ⊢
  cases cmd with
  | record c => exact (fun x => ⟨x.1, x.2.1⟩) (decideRecord_tr h hn)
  | reverse c => exact decideReverse_tr h hn

theorem transition_cap {r k w post res} (h : Rev12.paymentTransition r = .mutated k w post res) :
    Rev12.withinCapacity r w = true :=
  (paymentTransition_tr h fun _ => nofun).2.2.1 k w post res rfl

theorem transition_alias_cap {r pid e post} (h : Rev12.paymentTransition r = .alias pid e post) :
    Rev12.withinCapacity r { evidence := some e, payment := none, conflict := none, receipt := none } = true :=
  (paymentTransition_tr h fun _ => nofun).2.2.2 pid e post rfl

theorem paymentTransition_r1 {r c o} (hc : r.command = .record c) (h : Rev12.paymentTransition r = o)
    (hn : ∀ f, o ≠ .refused f) : R1Holds r c o := by
  unfold Rev12.paymentTransition at h
  rw [hc] at h
  exact (decideRecord_tr (c := c) h hn).2.2

end TrLayer

section LedgerLayer
open BlindLedger.Financial.CorrectionTransition

/-! ## Ledger layer: the old one-step laws, restated for rev 1.2's `step` (commitInput, extra refusals) -/

theorem trm {r k w post res} (h : paymentTransition r = .mutated k w post res) :
    Payment.paymentTransition r = .mutated k w post res := (paymentTransition_tr h fun _ => nofun).1

theorem tra {r pid e post} (h : paymentTransition r = .alias pid e post) :
    Payment.paymentTransition r = .alias pid e post := (paymentTransition_tr h fun _ => nofun).1

theorem mutated_shape {r k w post res} (h : paymentTransition r = .mutated k w post res) :
    type_of% (Payment.mutated_shape (trm h)) := Payment.mutated_shape (trm h)

theorem paymentTransition_mutated_post {r k w post res} (h : paymentTransition r = .mutated k w post res) :
    type_of% (Payment.paymentTransition_mutated_post (trm h)) := Payment.paymentTransition_mutated_post (trm h)

theorem conflict_changes_no_cash {r w post result}
    (h : paymentTransition r = .mutated .CONFLICT_RECORDED w post result) :
    type_of% (Payment.conflict_changes_no_cash (trm h)) := Payment.conflict_changes_no_cash (trm h)

theorem alias_shape {r pid e post} (h : paymentTransition r = .alias pid e post) :
    type_of% (Payment.alias_shape (tra h)) := Payment.alias_shape (tra h)

theorem reverse_exact {r c w post result}
    (hc : r.command = .reverse c) (h : paymentTransition r = .mutated .REVERSED w post result) :
    type_of% (Payment.reverse_exact hc (trm h)) := Payment.reverse_exact hc (trm h)

theorem record_amount_zero {r c} (hc : r.command = .record c) (h0 : c.amountCents = 0) :
    paymentTransition r = .refused .AMOUNT_ZERO := by
  unfold paymentTransition
  simp [hc, decideRecord, h0]

theorem run_cons (L c cs) : run L (c :: cs) = run (step L c) cs := rfl

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

theorem step_cases (L : Ledger) (c : Call) :
    (∃ k w post res, outcome L c = .mutated k w post res ∧ step L c =
      { input := commitInput post res,
        receipts := (w.receipt.map fun k => insertBy Receipt.paymentId k L.receipts).getD
          L.receipts }) ∨
    (∃ pid e post, outcome L c = .alias pid e post ∧ step L c = { L with input := post }) ∨
    (Silent (outcome L c) ∧ insertedEvidenceId? (outcome L c) = none ∧ step L c = L) := by
  unfold step
  cases ho : outcome L c with
  | mutated k w post res => exact Or.inl ⟨k, w, post, res, rfl, rfl⟩
  | alias pid e post => exact Or.inr (Or.inl ⟨pid, e, post, rfl, rfl⟩)
  | _ => exact Or.inr (Or.inr ⟨silent_of_ne fun _ _ _ _ h => (by cases h), rfl, rfl⟩)

theorem step_context (L c) : (step L c).input.context = L.input.context := by
  rcases step_cases L c with ⟨k, w, post, res, ho, he⟩ | ⟨pid, e, post, ho, he⟩ | ⟨-, -, he⟩ <;> rw [he]
  · dsimp only; rw [(paymentTransition_mutated_post ho).1]; rfl
  · dsimp only; rw [(alias_shape ho).1]; rfl

theorem step_evidence (L c) {id s} (h : findEvidence L.input.evidence id = some s) :
    findEvidence (step L c).input.evidence id = some s := by
  rcases step_cases L c with ⟨k, w, post, res, ho, he⟩ | ⟨pid, e, post, ho, he⟩ | ⟨-, -, he⟩ <;> rw [he]
  · dsimp only; rw [(paymentTransition_mutated_post ho).1]
    exact findEvidence_applyWrites (mutated_fresh ho) h
  · dsimp only; rw [(alias_shape ho).1]
    exact findEvidence_applyWrites (fun e' hw => by cases hw; exact (alias_shape ho).2.2) h
  · exact h

/-- Every step is silent, records one payment, or reverses one. -/
theorem step_kind (L : Ledger) (c : Call) :
    (Silent (outcome L c) ∧ (step L c).input.payments = L.input.payments ∧
      (step L c).receipts = L.receipts) ∨
    (∃ rc w post res, c.command = .record rc ∧ outcome L c = .mutated .RECORDED w post res ∧
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
    (∃ vc p w post res, c.command = .reverse vc ∧ outcome L c = .mutated .REVERSED w post res ∧
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

theorem step_payments_mutated {L c k w post res} (ho : outcome L c = .mutated k w post res) :
    (step L c).input.payments = post.payments := by
  simp only [step, ho]
  rfl

theorem step_recorded {L c w post res} (h : outcome L c = .mutated .RECORDED w post res) :
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

theorem step_mutated {L c k w post res} (ho : outcome L c = .mutated k w post res) :
    (step L c).input = commitInput post res := by
  simp only [step, ho]

theorem step_mutated_evidence {L c k w post res e} (ho : outcome L c = .mutated k w post res)
    (hw : w.evidence = some e) : findEvidence (step L c).input.evidence e.evidenceId = some e := by
  have hf := mutated_fresh ho e hw
  rw [step_mutated ho, (paymentTransition_mutated_post ho).1]
  simp only [applyWrites, hw, Option.map_some, Option.getD_some]
  dsimp only [commitInput]
  rw [findEvidence_insertBy hf, if_pos rfl]

theorem step_conserve (L c) :
    activeCents (step L c).input.payments + reversedCent (outcome L c) =
      activeCents L.input.payments + recordedCent (outcome L c) := by
  rcases step_kind L c with ⟨hs, hp, -⟩ | ⟨rc, w, post, res, -, ho, hp, -, -, -, -, -, -, hpay, -⟩ |
    ⟨vc, _, w, post, res, hcmd, ho, _⟩
  · rw [hp, hs.fields.2.2.2.1, hs.fields.2.2.2.2]
  · have e1 : reversedCent (outcome L c) = 0 := by rw [ho]; rfl
    have e2 : recordedCent (outcome L c) = (recordedPayment (L.request c).input rc).amountCents := by
      rw [ho]; simp [recordedCent, hp]
    rw [e1, e2, hpay, activeCents_eq, activeCents_eq, sum_insertBy]
    simp [recordedPayment] <;> omega
  · obtain ⟨p', -, -, hw', -, hact, -⟩ := reverse_exact (r := L.request c) hcmd ho
    have e1 : reversedCent (outcome L c) = p'.amountCents := by rw [ho]; simp [reversedCent, hw']
    have e2 : recordedCent (outcome L c) = 0 := by rw [ho]; rfl
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

theorem decideRecord_retry {r c p} (hz : c.amountCents ≠ 0) (hfor : r.foreign.paymentId = false)
    (hp : findPayment r.input.payments c.paymentId = some p) : decideRecord r c = recordRetry r c p := by
  simp [decideRecord, hz, hfor, hp]

theorem rec_duplicate {M : Ledger} {c rev} (now' : Nat) (h : Rec M c rev) :
    outcome M ⟨now', some rev, .record c⟩ = .duplicate (some c.paymentId) := by
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
    (h : outcome L c0 = .mutated .RECORDED w post res) : Rec (step L c0) c rev := by
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

theorem revDone_duplicate {M : Ledger} {c b} (exp' : Option Nat) (h : RevDone M c b) :
    outcome M ⟨b, exp', .reverse c⟩ = .duplicate none := by
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

theorem step_reversed {L c w post res} (h : outcome L c = .mutated .REVERSED w post res) :
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
    (h : outcome L c0 = .mutated .REVERSED w post res) : RevDone (step L c0) c b := by
  obtain ⟨vc, p, e, hcmd', hf, hw, he, hle, hform, hpay⟩ := step_reversed h
  obtain rfl : vc = c := Command.reverse.inj (hcmd'.symm.trans hcmd)
  subst he
  refine ⟨reversedImage p vc, _, ?_, rfl, step_mutated_evidence h hw, hle, hb, ?_, ?_, hform⟩
  · rw [hpay]; exact findPayment_reversed hf
  · intro t ht; simp [reversalRecord, ht]
  · exact (reversalRecord_congr (step_context L c0) rfl rfl vc _ _).trans
      (reversalRecord_congr (i := L.input) (j := (L.request c0).input) rfl rfl rfl vc _ _)

theorem evaluate_balance {i r} (h : evaluate i = some r) :
    ∃ la, evalLawfulSum i.claims = some la ∧
      r.shortfallCents + (activeCents i.payments + la) = r.overageCents + i.obligation.owedCents := by
  unfold evaluate at h
  split at h
  · unfold evaluateWellFormed evaluateTotals at h
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
            have hcash : cash = activeCents i.payments := ((evalPaymentSum_active _ _ hc).1).symm
            have ht' : t = cash + la := by
              unfold evalAdd at ht
              split at ht
              · exact (Option.some.inj ht).symm
              · cases ht
            refine ⟨la, rfl, ?_⟩
            show (if i.obligation.owedCents > t then i.obligation.owedCents - t else 0) +
              (activeCents i.payments + la) =
              (if t > i.obligation.owedCents then t - i.obligation.owedCents else 0) + i.obligation.owedCents
            rw [← hcash]
            split <;> split <;> omega
  · simp at h

theorem step_frame (L c) : (step L c).input.claims = L.input.claims ∧
    (step L c).input.obligation = L.input.obligation := by
  rcases step_cases L c with ⟨k, w, post, res, ho, he⟩ | ⟨pid, e, post, ho, he⟩ | ⟨-, -, he⟩ <;> rw [he]
  · dsimp only; rw [(paymentTransition_mutated_post ho).1]; exact ⟨rfl, rfl⟩
  · dsimp only; rw [(alias_shape ho).1]; exact ⟨rfl, rfl⟩
  · exact ⟨rfl, rfl⟩

theorem run_frame (L : Ledger) : ∀ calls, (run L calls).input.claims = L.input.claims ∧
    (run L calls).input.obligation = L.input.obligation
  | [] => ⟨rfl, rfl⟩
  | c :: cs => by
    obtain ⟨h1, h2⟩ := run_frame (step L c) cs
    obtain ⟨g1, g2⟩ := step_frame L c
    exact ⟨by rw [run_cons, h1, g1], by rw [run_cons, h2, g2]⟩

theorem trace_get : ∀ (calls : List Call) (L : Ledger) (n : Nat) (o : PaymentOutcome),
    (trace L calls)[n]? = some o → ∃ c, calls[n]? = some c ∧ o = outcome (run L (calls.take n)) c
  | [], L, n, o, h => by simp [trace] at h
  | c :: cs, L, 0, o, h => by
    simp only [trace, List.getElem?_cons_zero, Option.some.injEq] at h
    exact ⟨c, rfl, h.symm⟩
  | c :: cs, L, n + 1, o, h => by
    simp only [trace, List.getElem?_cons_succ] at h
    obtain ⟨c', hc', ho⟩ := trace_get cs (step L c) n o h
    exact ⟨c', by simpa using hc', by rw [List.take_succ_cons, run_cons]; exact ho⟩

end LedgerLayer

/-! ## 16.2-16.6, 16.9 Corrected and folded-in statements -/

open BlindLedger.Financial.CorrectionTransition

theorem wf_setCases {i : FinancialInput} {X : List CaseRecord} (h : financialInputWellFormed i = true)
    (hl : 1 ≤ X.length) (hl2 : X.length ≤ maxRows)
    (hid : X.map CaseRecord.caseId = i.cases.map CaseRecord.caseId)
    (hX : ∀ k ∈ X, caseWellFormed i k = true ∧ k.updatedAt ≤ i.evaluatedAt) :
    financialInputWellFormed { i with cases := X } = true := by
  simp only [financialInputWellFormed, Bool.and_assoc, Bool.and_eq_true, decide_eq_true_eq] at h ⊢
  obtain ⟨h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11,h12,h13,h14,h15,h16,h17,h18,h19,h20,h21,h22,h23,h24,h25,h26,h27,h28,h29,h30,h31,h32,h33,h34,h35,h36,h37,h38,h39,h40,h41,h42,h43,h44,h45,h46,h47,h48,h49,h50,h51,h52,h53,h54,h55⟩ := h
  repeat' apply And.intro
  all_goals first | assumption | skip
  · show canonicalIdList (X.map CaseRecord.caseId) = true
    rw [hid]; assumption
  · exact List.all_eq_true.2 fun k hk => (hX k hk).1
  · exact List.all_eq_true.2 fun k hk => decide_eq_true (hX k hk).2

theorem wf_commit {post : FinancialInput} (res : FinancialResult)
    (h : financialInputWellFormed post = true) (hR : post.beforeRevision + 1 < maxRevision) :
    financialInputWellFormed (commitInput post res) = true := by
  have hc := h
  simp only [financialInputWellFormed, Bool.and_assoc, Bool.and_eq_true, decide_eq_true_eq] at hc
  obtain ⟨h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11,h12,h13,h14,h15,h16,h17,h18,h19,h20,h21,h22,h23,h24,h25,h26,h27,h28,h29,h30,h31,h32,h33,h34,h35,h36,h37,h38,h39,h40,h41,h42,h43,h44,h45,h46,h47,h48,h49,h50,h51,h52,h53,h54,h55⟩ := hc
  have hcs : financialInputWellFormed { post with cases := post.cases.map fun k =>
      { k with status := res.caseStatus, updatedAt := post.evaluatedAt } } = true := by
    refine wf_setCases h ?_ ?_ ?_ ?_
    · simp only [List.length_map]; exact h22
    · simp only [List.length_map]; exact h23
    · simp [List.map_map, Function.comp_def]
    · intro k hk
      obtain ⟨k0, hk0, rfl⟩ := List.mem_map.1 hk
      refine ⟨?_, Nat.le_refl _⟩
      have hk1 := List.all_eq_true.1 h37 k0 hk0
      simp only [caseWellFormed, Bool.and_assoc, Bool.and_eq_true, decide_eq_true_eq] at hk1 ⊢
      obtain ⟨a, b, c, d, e, -⟩ := hk1
      exact ⟨a, b, c, d, e, h7⟩
  have e : commitInput post res = { ({ post with cases := post.cases.map fun k =>
      { k with status := res.caseStatus, updatedAt := post.evaluatedAt } } : FinancialInput) with
      beforeRevision := post.beforeRevision + 1 } := rfl
  rw [e]
  exact wf_setRevision hcs (by show post.beforeRevision ≤ post.beforeRevision + 1; omega) hR


theorem action_id_wf {i : FinancialInput} (h : financialInputWellFormed i = true) {x : ActionRecord}
    (hx : x ∈ i.actions) : idWellFormed x.actionId = true := by
  simp only [financialInputWellFormed, Bool.and_assoc, Bool.and_eq_true, decide_eq_true_eq] at h
  obtain ⟨h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11,h12,h13,h14,h15,h16,h17,h18,h19,h20,h21,h22,h23,h24,h25,h26,h27,h28,h29,h30,h31,h32,h33,h34,h35,h36,h37,h38,h39,h40,h41,h42,h43,h44,h45,h46,h47,h48,h49,h50,h51,h52,h53,h54,h55⟩ := h
  have := List.all_eq_true.1 h38 x hx
  simp only [actionWellFormed, Bool.and_assoc, Bool.and_eq_true] at this
  exact List.all_eq_true.1 this.1 x.actionId (by simp)

theorem step_wellFormed (L : Ledger) (hL : ledgerWellFormed L) (c : Call) (hc : clocksOk L [c])
    (hR : L.input.beforeRevision + 1 < maxRevision) : ledgerWellFormed (step L c) := by
  have hI := step_Inv c (Inv_of_wf hL)
  have hb : ∀ {k w post res}, outcome L c = .mutated k w post res →
      post.beforeRevision = L.input.beforeRevision :=
    fun {k w post res} ho => by rw [(paymentTransition_mutated_post ho).1]; rfl
  have hA : financialInputWellFormed (step L c).input = true := by
    rcases step_cases L c with ⟨k, w, post, res, ho, he⟩ | ⟨pid, e, post, ho, he⟩ | ⟨-, -, he⟩ <;> rw [he]
    · exact wf_commit res (paymentTransition_mutated_post ho).2.1 (by rw [hb ho]; exact hR)
    · exact (alias_shape ho).2.1
    · exact hL.1
  have hB : L.input.beforeRevision ≤ (step L c).input.beforeRevision := by
    rcases step_cases L c with ⟨k, w, post, res, ho, he⟩ | ⟨pid, e, post, ho, he⟩ | ⟨-, -, he⟩ <;> rw [he]
    · show L.input.beforeRevision ≤ post.beforeRevision + 1
      rw [hb ho]; omega
    · rw [(alias_shape ho).1]; exact Nat.le_refl _
    · exact Nat.le_refl _
  have hC : ∀ {w post res}, outcome L c = .mutated .RECORDED w post res →
      (step L c).input.beforeRevision = L.input.beforeRevision + 1 :=
    fun {w post res} ho => by
      rw [step_mutated ho]; show post.beforeRevision + 1 = _; rw [hb ho]
  have hrec : ∀ k ∈ L.receipts, k.recordedRevision < L.input.beforeRevision ∧
      k.paysActionId.all idWellFormed = true := by
    have := hL.2
    simp only [receiptsWellFormed, Bool.and_eq_true, beq_iff_eq, List.all_eq_true, decide_eq_true_eq] at this
    exact this.2
  refine ⟨hA, ?_⟩
  simp only [receiptsWellFormed, Bool.and_eq_true, beq_iff_eq, List.all_eq_true, decide_eq_true_eq]
  refine ⟨hI.2, ?_⟩
  have old : ∀ k ∈ L.receipts, k.recordedRevision < (step L c).input.beforeRevision ∧
      k.paysActionId.all idWellFormed = true :=
    fun k hk => ⟨Nat.lt_of_lt_of_le (hrec k hk).1 hB, (hrec k hk).2⟩
  rcases step_kind L c with ⟨-, -, hr⟩ | ⟨rc, w, post, res, hcmd, ho, -, -, -, -, -, -, -, -, hr⟩ |
    ⟨-, -, -, -, -, -, -, -, -, -, -, -, hr, -⟩
  · rw [hr]; exact old
  · rw [hr]; intro k hk
    rcases (mem_insertBy Receipt.paymentId _ k _).1 hk with rfl | hk
    · refine ⟨?_, ?_⟩
      · show L.input.beforeRevision < (step L c).input.beforeRevision
        rw [hC ho]; omega
      · show rc.paysActionId.all idWellFormed = true
        cases hpa : rc.paysActionId with
        | none => rfl
        | some a =>
          obtain ⟨x, hx, hxa, -⟩ := Payment.record_link_within_request (r := L.request c) hcmd hpa (trm ho)
          simp only [Option.all_some]
          rw [← hxa]; exact action_id_wf hL.1 hx
    · exact old k hk
  · rw [hr]; exact old



theorem evalAdd_comm (a b : Nat) : evalAdd a b = evalAdd b a := by
  unfold evalAdd
  simp only [Bool.and_eq_true, decide_eq_true_eq]
  by_cases h : (a ≤ maxCents ∧ b ≤ maxCents) ∧ a ≤ maxCents - b
  · have h' : (b ≤ maxCents ∧ a ≤ maxCents) ∧ b ≤ maxCents - a := by omega
    rw [if_pos h, if_pos h', Nat.add_comm]
  · have h' : ¬ ((b ≤ maxCents ∧ a ≤ maxCents) ∧ b ≤ maxCents - a) := by omega
    rw [if_neg h, if_neg h']

theorem evaluateState_summarize {i : FinancialInput} {rs b s} (hw : financialInputWellFormed i = true)
    (h : summarize i rs b = some s) : evaluateState (envOf i) s = evaluate i := by
  have hev : evaluate i = evaluateWellFormed i := by unfold evaluate; rw [hw]; rfl
  rw [hev]
  unfold summarize at h
  unfold evaluateWellFormed evaluateTotals
  unfold evaluateTotals at h
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
          have hcomp : evalCompletion i =
              (match evalCompletionLoop i.obligation.owedCents 0 (evalSortContributions (evalContributions i)) with
               | some x => some x
               | none => if t ≥ i.obligation.owedCents
                         then evalLatestContributionTime (evalSortContributions (evalContributions i)) else none) := by
            unfold evalCompletion
            dsimp only
            cases evalCompletionLoop i.obligation.owedCents 0 (evalSortContributions (evalContributions i)) with
            | some x => rfl
            | none => simp [hc, hl, evalAdd_comm la cash, ht]
          have hv : (if i.conflicts.length = 0 then
                (if (i.evidence.map EvidenceRecord.evidenceId).isEmpty then VerificationStatus.MISSING_EVIDENCE
                 else .SUPPORTED) else .CONFLICT_VISIBLE) = evalVerificationStatus i := by
            unfold evalVerificationStatus; cases i.conflicts <;> cases i.evidence <;> simp
          simp only [hc, hcl, hl, ht, Option.map_some]
          unfold evaluateState
          simp only [ht, Option.bind_some, Option.pure_def, bind, Option.bind]
          simp only [evaluateResult, envOf, hcomp, hv]
          cases hq : evalCompletionLoop i.obligation.owedCents 0 (evalSortContributions (evalContributions i))
          · simp [evalCaseStatus_eq]
            cases (if i.obligation.owedCents ≤ t then evalLatestContributionTime
              (evalSortContributions (evalContributions i)) else none) <;> rfl
          · simp [evalCaseStatus_eq]
            rfl

theorem state_requests_paid (L : Ledger) {s : ItemState} (h : summaryOf L.input L.receipts = some s)
    (a : RequestPaid) (ha : a ∈ s.requests) : a.paidCents = ledgerPaid L a.actionId := by
  unfold summaryOf summarize at h
  cases ht : evaluateTotals L.input with
  | none => simp [ht] at h
  | some t =>
    simp only [ht, Option.map_some, Option.some.injEq] at h
    subst h
    obtain ⟨x, -, rfl⟩ := List.mem_map.1 ha
    rfl

theorem rawEncode_evaluatedAt (i : FinancialInput) (t : Nat) :
    (rawEncodeFinancialInput { i with evaluatedAt := t }).length = (rawEncodeFinancialInput i).length := by
  simp only [rawEncodeFinancialInput, List.length_append, length_natBE]

theorem absorb_summarize (L : Ledger) (c : Call) {pid e post}
    (h : outcome L c = .alias pid e post) :
    (summaryOf L.input L.receipts).map (absorb · [e]) = summaryOf (step L c).input (step L c).receipts := by
  have hstep : step L c = { L with input := post } := by simp only [step, h]
  obtain ⟨hpost, -, hfresh⟩ := alias_shape h
  have hlen : (rawEncodeFinancialInput post).length =
      (rawEncodeFinancialInput L.input).length + (encodeEvidence e).length := by
    have := rawEncode_applyWrites_core (L.request c).input
      { evidence := some e, payment := none, conflict := none, receipt := none } (fun p hp => by cases hp)
    rw [← hpost] at this
    have h0 : (rawEncodeFinancialInput (L.request c).input).length = (rawEncodeFinancialInput L.input).length :=
      rawEncode_evaluatedAt L.input c.now
    simp only [oldPay, newPay, evBytes, cfBytes, Option.map_some, Option.getD_some, Option.map_none,
      Option.getD_none, Option.bind_none] at this
    omega
  rw [hstep]
  unfold summaryOf summarize
  have hT : evaluateTotals post = evaluateTotals L.input := by rw [hpost]; rfl
  show _ = (evaluateTotals post).map _
  rw [hT]
  cases evaluateTotals L.input with
  | none => rfl
  | some t =>
    simp only [Option.map_some, absorb, List.foldl_cons, List.foldl_nil, Option.some.injEq]
    have hE : post.evidence.map EvidenceRecord.evidenceId =
        insertBy (fun x => x) e.evidenceId (L.input.evidence.map EvidenceRecord.evidenceId) := by
      rw [hpost]
      exact map_insertBy EvidenceRecord.evidenceId EvidenceRecord.evidenceId id (fun _ => rfl) e _
    have hA : anchorItemLength post L.receipts = anchorItemLength L.input L.receipts + (encodeEvidence e).length := by
      unfold anchorItemLength; omega
    rw [hE, hA]
    subst hpost
    rfl


/-! ## Conflict retry (16.2 item 1) -/

theorem find_insertBy_ne {α} (key : α → String) (row : α) (P : α → Bool) (hP : P row = false) :
    ∀ l : List α, (insertBy key row l).find? P = l.find? P
  | [] => by simp [insertBy, hP]
  | y :: ys => by
    unfold insertBy
    split
    · simp [List.find?_cons, hP]
    · cases hy : P y <;> simp [List.find?_cons, hy, find_insertBy_ne key row P hP ys]

theorem find_map_same {α} (f : α → α) (P : α → Bool) :
    ∀ l : List α, (∀ x ∈ l, P (f x) = P x) → (l.map f).find? P = (l.find? P).map f
  | [], _ => rfl
  | x :: xs, h => by
    have hx := h x (by simp)
    have ih := find_map_same f P xs fun y hy => h y (by simp [hy])
    cases hpx : P x <;> simp [List.find?_cons, hx, hpx, ih]

theorem eq_of_nodup_key {α} (key : α → String) : ∀ {l : List α}, (l.map key).Nodup →
    ∀ {x y}, x ∈ l → y ∈ l → key x = key y → x = y
  | [], _, _, _, hx, _, _ => by cases hx
  | z :: zs, hn, x, y, hx, hy, hk => by
    simp only [List.map_cons, List.nodup_cons, List.mem_map] at hn
    rcases List.mem_cons.1 hx with rfl | hx' <;> rcases List.mem_cons.1 hy with rfl | hy'
    · rfl
    · exact absurd ⟨y, hy', hk.symm⟩ hn.1
    · exact absurd ⟨x, hx', hk⟩ hn.1
    · exact eq_of_nodup_key key hn.2 hx' hy' hk

theorem rev_map_same {l : List Payment} (hnd : (l.map Payment.paymentId).Nodup) {p : Payment}
    (hp : p ∈ l) (vc : ReverseCommand) : ∀ x ∈ l,
    (if x.paymentId = p.paymentId then reversedImage p vc else x).paymentId = x.paymentId ∧
    (if x.paymentId = p.paymentId then reversedImage p vc else x).commonOriginId = x.commonOriginId ∧
    (if x.paymentId = p.paymentId then reversedImage p vc else x).amountCents = x.amountCents := by
  intro x hx
  by_cases h : x.paymentId = p.paymentId
  · obtain rfl := eq_of_nodup_key _ hnd hx hp h
    simp [reversedImage]
  · simp [h]

theorem conflict_existing {r : PaymentRequest} {c w post res}
    (h : Payment.recordNew r c = .mutated .CONFLICT_RECORDED w post res) :
    ∃ p, r.input.payments.find? (·.commonOriginId = c.commonOriginId) = some p ∧
      p.amountCents ≠ c.amountCents := by
  unfold Payment.recordNew at h
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
      · obtain ⟨hk, -⟩ := mutate_eq h; cases hk
    | some p =>
      dsimp only at h
      split at h
      · split at h
        · simp at h
        · exact absurd h alias_or_dup_ne
      · rename_i hsm
        refine ⟨p, rfl, fun he => hsm ?_⟩
        simp [← hsame, he]

theorem recordRetry_conflict {r c p s} (hs : findEvidence r.input.evidence c.evidenceId = some s)
    (hfs : formRefusal s = none) (hle : c.eventAt ≤ s.receivedAt)
    (hc : confirmation r.input c s.receivedAt = s) (ho : p.commonOriginId ≠ c.commonOriginId) :
    recordRetry r c p = .refused .REQUEST_CONFLICT := by
  simp [recordRetry, hs, hfs, hc, Nat.not_lt.2 hle] <;> split <;> simp [ho]

theorem step_conflict (L c) {x} (h : x ∈ L.input.conflicts) : x ∈ (step L c).input.conflicts := by
  rcases step_cases L c with ⟨k, w, post, res, ho, he⟩ | ⟨pid, e, post, ho, he⟩ | ⟨-, -, he⟩ <;> rw [he]
  · dsimp only; rw [(paymentTransition_mutated_post ho).1]
    simp only [commitInput, applyWrites]
    cases w.conflict with
    | none => exact h
    | some X => simp only [Option.map_some, Option.getD_some]; exact (mem_insertBy _ _ _ _).2 (Or.inr h)
  · dsimp only; rw [(alias_shape ho).1]
    simp only [applyWrites, Option.map_none, Option.getD_none]; exact h
  · exact h

/-- The payment rows a conflict retry depends on. -/
def CRp (M : Ledger) (c : RecordCommand) : Prop :=
  (M.input.payments.map Payment.paymentId).Nodup ∧
  (∃ p0, M.input.payments.find? (·.commonOriginId = c.commonOriginId) = some p0 ∧
    p0.amountCents ≠ c.amountCents) ∧
  ∀ p ∈ M.input.payments, p.paymentId = c.paymentId → p.commonOriginId ≠ c.commonOriginId

def CR (M : Ledger) (c : RecordCommand) (cid : String) : Prop :=
  c.amountCents ≠ 0 ∧ CRp M c ∧
  (∃ s, findEvidence M.input.evidence c.evidenceId = some s ∧ c.eventAt ≤ s.receivedAt ∧
    confirmation M.input c s.receivedAt = s ∧ formRefusal s = none) ∧
  (∃ x ∈ M.input.conflicts, x.conflictId = cid) ∧ conflictIdOf M.input c = cid

theorem CRp_step {M c} (h : CRp M c) (c') : CRp (step M c') c := by
  obtain ⟨hnd, ⟨p0, hex, hsm⟩, hid⟩ := h
  rcases step_kind M c' with ⟨-, hp, -⟩ | ⟨rc, w, post, res, -, -, -, -, -, hor, -, -, hnd', hp, -⟩ |
    ⟨vc, p, w, post, res, -, -, hf, -, -, hnd', hp, -⟩
  · unfold CRp; rw [hp]; exact ⟨hnd, ⟨p0, hex, hsm⟩, hid⟩
  · have hp0 := List.mem_of_find?_eq_some hex
    have hpo : p0.commonOriginId = c.commonOriginId := by simpa using List.find?_some hex
    have hrow : (recordedPayment (M.request c').input rc).commonOriginId ≠ c.commonOriginId :=
      fun e => hor p0 hp0 (hpo.trans e.symm)
    refine ⟨hnd', ⟨p0, ?_, hsm⟩, fun q hq hqi => ?_⟩
    · rw [hp, find_insertBy_ne Payment.paymentId (recordedPayment (M.request c').input rc)
        (fun x => decide (x.commonOriginId = c.commonOriginId)) (decide_eq_false hrow)]
      exact hex
    · rw [hp, mem_insertBy] at hq
      rcases hq with rfl | hq
      · exact hrow
      · exact hid q hq hqi
  · have hmem : p ∈ M.input.payments := by
      rw [findPayment_eq] at hf; exact List.mem_of_find?_eq_some hf
    have hm := rev_map_same hnd hmem vc
    have hp0 := List.mem_of_find?_eq_some hex
    have hf2 := find_map_same (fun x : Payment => if x.paymentId = p.paymentId then reversedImage p vc else x)
      (fun x => decide (x.commonOriginId = c.commonOriginId)) M.input.payments
      (fun x hx => by simp only [(hm x hx).2.1])
    rw [hex, Option.map_some] at hf2
    refine ⟨hnd', ⟨_, by rw [hp]; exact hf2, fun e => hsm ((hm p0 hp0).2.2.symm.trans e)⟩, fun q hq hqi => ?_⟩
    rw [hp, List.mem_map] at hq
    obtain ⟨y, hy, rfl⟩ := hq
    exact fun e => hid y hy ((hm y hy).1.symm.trans hqi) ((hm y hy).2.1.symm.trans e)

theorem CR_step {M c cid} (h : CR M c cid) (c') : CR (step M c') c cid := by
  obtain ⟨hz, hp, ⟨s, hs, hle, hce, hfs⟩, ⟨x, hx, hxid⟩, hcid⟩ := h
  refine ⟨hz, CRp_step hp c', ⟨s, step_evidence M c' hs, hle, ?_, hfs⟩,
    ⟨x, step_conflict M c' hx, hxid⟩, ?_⟩
  · rw [confirmation_ctx (step_context M c') c s.receivedAt]; exact hce
  · unfold conflictIdOf at hcid ⊢; rw [step_context]; exact hcid

theorem run_CR {M c cid} (h : CR M c cid) : ∀ calls, CR (run M calls) c cid
  | [] => h
  | c' :: cs => run_CR (CR_step h c') cs

theorem CR_init {L : Ledger} {c : RecordCommand} {c0 : Call} {w post res}
    (hcmd : c0.command = .record c) (h : outcome L c0 = .mutated .CONFLICT_RECORDED w post res) :
    CR (step L c0) c (conflictIdOf L.input c) := by
  have ht : Payment.paymentTransition (L.request c0) = .mutated .CONFLICT_RECORDED w post res := trm h
  rcases Payment.paymentTransition_cases ht with ⟨c', hc', hd⟩ | ⟨c', hc', hd⟩
  · obtain rfl : c = c' := (Command.record.inj (hc'.symm.trans hcmd)).symm
    obtain ⟨hf, hn⟩ := Payment.decideRecord_mutated hd
    obtain ⟨p0, hex, hsm⟩ := conflict_existing hn
    obtain ⟨-, -, hew, ⟨hk, -⟩ | ⟨-, p, -, -, -, -, -, hwc⟩⟩ := Payment.recordNew_mutated hn
    · cases hk
    obtain ⟨hpost, hwf, -⟩ := paymentTransition_mutated_post h
    have hpay : (step L c0).input.payments = L.input.payments := by
      rw [step_payments_mutated h]; exact (conflict_changes_no_cash h).1
    refine ⟨fun h0 => ?_, ⟨?_, ⟨p0, ?_, hsm⟩, ?_⟩, ?_, ⟨conflictImage (L.request c0).input c p
      ("conflict:" ++ (L.request c0).input.context.itemId ++ ":" ++ c.commonOriginId ++ ":" ++ c.evidenceId), ?_, rfl⟩, ?_⟩
    · have h' : paymentTransition (L.request c0) = .mutated .CONFLICT_RECORDED w post res := h
      rw [record_amount_zero (r := L.request c0) hcmd h0] at h'
      cases h'
    · rw [step_payments_mutated h]; exact nodup_ids_of_wf hwf
    · rw [hpay]; exact hex
    · rw [hpay]
      intro q hq hqi
      exact absurd (decide_eq_true hqi) (List.find?_eq_none.1 ((findPayment_eq _ _).symm.trans hf) q hq)
    · obtain ⟨hform, hle, -, hcase⟩ := hew
      rcases hcase with ⟨hw, -⟩ | ⟨-, s, hs, hle', hce⟩
      · refine ⟨_, step_mutated_evidence h hw, hle, ?_, hform⟩
        exact (confirmation_ctx (step_context L c0) c _).trans
          (confirmation_ctx (i := L.input) (j := (L.request c0).input) rfl c _)
      · refine ⟨s, step_evidence L c0 hs, hle', ?_, formRefusal_of_conf hce hform⟩
        exact (confirmation_ctx (step_context L c0) c _).trans
          ((confirmation_ctx (i := L.input) (j := (L.request c0).input) rfl c _).trans hce)
    · rw [step_mutated h, hpost]
      simp only [commitInput, applyWrites, hwc, Option.map_some, Option.getD_some]
      exact (mem_insertBy _ _ _ _).2 (Or.inl rfl)
    · unfold conflictIdOf; rw [step_context]
  · obtain ⟨-, -, hk, -⟩ := Payment.decideReverse_mutated hd; cases hk

theorem CR_retry {M : Ledger} {c cid} (h : CR M c cid) (now' : Nat) (exp' : Option Nat) :
    outcome M ⟨now', exp', .record c⟩ =
      if (findPayment M.input.payments c.paymentId).isSome
      then .refused .REQUEST_CONFLICT else .conflictUnchanged cid := by
  obtain ⟨hz, ⟨-, ⟨p0, hex, hsm⟩, hid⟩, ⟨s, hs, hle, hce, hfs⟩, ⟨x, hx, hxid⟩, hcid⟩ := h
  show decideRecord (M.request ⟨now', exp', .record c⟩) c = _
  have hce' : confirmation (M.request ⟨now', exp', .record c⟩).input c s.receivedAt = s :=
    (confirmation_ctx (i := (M.request ⟨now', exp', .record c⟩).input) (j := M.input) rfl c _).trans hce
  cases hp : findPayment M.input.payments c.paymentId with
  | some p =>
    have hp' : findPayment (M.request ⟨now', exp', .record c⟩).input.payments c.paymentId = some p := hp
    have hmem : p ∈ M.input.payments := by
      rw [findPayment_eq] at hp; exact List.mem_of_find?_eq_some hp
    rw [decideRecord_retry (r := M.request ⟨now', exp', .record c⟩) hz rfl hp',
      recordRetry_conflict hs hfs hle hce' (hid p hmem (findPayment_id _ _ _ hp'))]
    simp
  | none =>
    have hp' : findPayment (M.request ⟨now', exp', .record c⟩).input.payments c.paymentId = none := hp
    have hd : decideRecord (M.request ⟨now', exp', .record c⟩) c =
        recordNew (M.request ⟨now', exp', .record c⟩) c := by
      have hfor : (M.request ⟨now', exp', .record c⟩).foreign.paymentId = false := rfl
      simp [decideRecord, hz, hp', hfor]
    have hslot : evidenceSlot (M.request ⟨now', exp', .record c⟩)
        (confirmation (M.request ⟨now', exp', .record c⟩).input c
          (M.request ⟨now', exp', .record c⟩).input.evaluatedAt) = .same s :=
      evidenceSlot_same rfl hs hle hce'
    have hany : (M.request ⟨now', exp', .record c⟩).input.conflicts.any
        (·.conflictId = conflictIdOf (M.request ⟨now', exp', .record c⟩).input c) = true :=
      List.any_eq_true.2 ⟨x, hx, decide_eq_true (hxid.trans hcid.symm)⟩
    have hex' : (M.request ⟨now', exp', .record c⟩).input.payments.find?
        (·.commonOriginId = c.commonOriginId) = some p0 := hex
    rw [hd]
    unfold recordNew
    dsimp only
    simp [hex', hsm, hany, hslot, Slot.isSame, hcid]
    exact hcid

theorem run_conflict_retry_unchanged (L : Ledger) (c : RecordCommand) (now : Nat)
    (exp exp' : Option Nat) (calls : List Call) (now' : Nat)
    (h : ∃ w post res, outcome L ⟨now, exp, .record c⟩ = .mutated .CONFLICT_RECORDED w post res) :
    outcome (run (step L ⟨now, exp, .record c⟩) calls) ⟨now', exp', .record c⟩ =
      if (findPayment (run (step L ⟨now, exp, .record c⟩) calls).input.payments c.paymentId).isSome
      then .refused .REQUEST_CONFLICT else .conflictUnchanged (conflictIdOf L.input c) := by
  obtain ⟨w, post, res, ho⟩ := h
  exact CR_retry (run_CR (CR_init (c0 := ⟨now, exp, .record c⟩) rfl ho) calls) now' exp'

/-! ## Anchor capacity (D3) -/

theorem advance_anchor {v s w s'} (h : advance v s w = some s') :
    s'.anchorBytes = s.anchorBytes + anchorGrowth v w := by
  unfold advance at h
  dsimp only at h
  repeat' split at h
  all_goals first | (obtain rfl := Option.some.inj h; rfl) | simp at h

theorem commitView_fits {v s k w k' w' s' r} (h : commitView v s k w = .mutated k' w' s' r) :
    s'.anchorBytes + maxCallTailBytes ≤ maxTotalEncodedBytes := by
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
      have := advance_anchor hadv
      show s2.anchorBytes + _ ≤ _
      omega

theorem anchorItem_fits {v : PaymentView} {k w s r} (h : stepView v = .mutated k w s r) :
    s.anchorBytes + maxCallTailBytes ≤ maxTotalEncodedBytes := sorry

theorem idWellFormed_len {s : String} (h : idWellFormed s = true) : s.toUTF8.toList.length ≤ 128 := by
  simp only [idWellFormed, Bool.and_eq_true, decide_eq_true_eq] at h
  exact h.1.2

theorem encodeString_len {s : String} (h : idWellFormed s = true) : (encodeString s).length ≤ 130 := by
  have := idWellFormed_len h
  simp only [encodeString, List.length_append, length_natBE]
  omega

theorem optId_len {o : Option String} (h : (nonEmpty o).all idWellFormed = true) :
    (encodeOptionString o).length ≤ 131 := by
  cases o with
  | none => simp [encodeOptionString]
  | some s =>
    by_cases hs : s = ""
    · subst hs; simp [encodeOptionString, encodeString, length_natBE]
    · have := encodeString_len (s := s) (by simpa [nonEmpty, hs] using h)
      simp only [encodeOptionString, List.length_cons]
      omega

theorem optAll_len {o : Option String} (h : o.all idWellFormed = true) :
    (encodeOptionString o).length ≤ 131 := by
  cases o with
  | none => simp [encodeOptionString]
  | some s =>
    have := encodeString_len (s := s) (by simpa using h)
    simp only [encodeOptionString, List.length_cons]
    omega

theorem anchorItem_length (r : PaymentRequest) (hc : commandWellFormed r.command = true) :
    (encodePaymentRequest r).length ≤ anchorItemLength r.input r.receipts + maxCallTailBytes := by
  have hcmd : (encodeCommand r.command).length ≤ 1000 := by
    cases hcm : r.command with
    | record c =>
      rw [hcm] at hc
      simp only [commandWellFormed, Bool.and_eq_true] at hc
      obtain ⟨⟨⟨⟨hids, hl⟩, hp⟩, -⟩, -⟩ := hc
      have h1 := encodeString_len (List.all_eq_true.1 hids c.paymentId (by simp))
      have h2 := encodeString_len (List.all_eq_true.1 hids c.evidenceId (by simp))
      have h3 := encodeString_len (List.all_eq_true.1 hids c.commonOriginId (by simp))
      have h4 := encodeString_len (List.all_eq_true.1 hids c.sourceId (by simp))
      have h5 := encodeString_len (List.all_eq_true.1 hids c.sourceVersion (by simp))
      have h6 := optId_len hl
      have h7 := optAll_len hp
      simp only [encodeCommand, List.length_cons, List.length_append, length_natBE]
      omega
    | reverse c =>
      rw [hcm] at hc
      simp only [commandWellFormed, Bool.and_eq_true] at hc
      obtain ⟨⟨⟨h1, h2⟩, h3⟩, -⟩ := hc
      have h1 := encodeString_len h1
      have h2 := encodeString_len h2
      have h3 := optId_len h3
      have h4 : (encodeOptionNat c.eventAt).length ≤ 9 := by
        cases c.eventAt <;> simp [encodeOptionNat, length_natBE]
      simp only [encodeCommand, List.length_cons, List.length_append]
      omega
  have ho : (encodeOptionNat r.expectedRevision).length ≤ 9 := by
    cases r.expectedRevision <;> simp [encodeOptionNat, length_natBE]
  have hf : (encodeForeign r.foreign).length = 1 := rfl
  simp only [encodePaymentRequest, anchorItemLength, anchorOverhead, maxCallTailBytes,
    List.length_append, length_natBE, List.length_singleton]
  omega

theorem rawEncode_commit_length (post : FinancialInput) (res : FinancialResult) :
    (rawEncodeFinancialInput (commitInput post res)).length = (rawEncodeFinancialInput post).length := by
  have hc : (encodeList encodeCase (post.cases.map fun k =>
      { k with status := res.caseStatus, updatedAt := post.evaluatedAt })).length =
      (encodeList encodeCase post.cases).length := by
    rw [length_encodeList, length_encodeList, List.map_map]
    congr 2
    exact List.map_congr_left fun k _ => by simp [Function.comp, encodeCase, length_natBE]
  simp only [rawEncodeFinancialInput, commitInput, List.length_append, length_natBE]
  omega

theorem post_len_le {r : PaymentRequest} {k w post res}
    (h : paymentTransition r = .mutated k w post res) :
    (rawEncodeFinancialInput post).length ≤ (rawEncodeFinancialInput r.input).length + addedBytes r.input w := by
  obtain ⟨hpost, hwf, -⟩ := paymentTransition_mutated_post h
  have hp : ∀ p, w.payment = some p → (findPayment r.input.payments p.paymentId).isSome = true →
      (r.input.payments.map Payment.paymentId).Nodup := fun p hw hs =>
    payments_nodup_of_replace (hpost ▸ hwf) hw hs
  have := rawEncode_applyWrites_core r.input w hp
  unfold addedBytes
  rw [hpost]
  omega

theorem alias_len {r : PaymentRequest} {pid e post} (h : paymentTransition r = .alias pid e post) :
    (rawEncodeFinancialInput post).length = (rawEncodeFinancialInput r.input).length + (encodeEvidence e).length := by
  rw [(alias_shape h).1]
  have := rawEncode_applyWrites_core r.input
    { evidence := some e, payment := none, conflict := none, receipt := none } (fun p hp => by cases hp)
  simpa [evBytes, newPay, oldPay, cfBytes] using this

theorem commitReceipts_len (rs : List Receipt) (w : Writes) :
    (encodeList encodeReceipt (commitReceipts rs w)).length = (encodeList encodeReceipt rs).length + receiptBytes w := by
  cases hw : w.receipt with
  | none => simp [commitReceipts, receiptBytes, hw]
  | some k => simp [commitReceipts, receiptBytes, hw, length_encodeList, sum_insertBy] <;> omega

theorem step_anchor_fits (L : Ledger) (hL : ledgerWellFormed L) (c : Call)
    (hfit : anchorItemLength L.input L.receipts + maxCallTailBytes ≤ maxTotalEncodedBytes) :
    anchorItemLength (step L c).input (step L c).receipts + maxCallTailBytes ≤ maxTotalEncodedBytes := by
  have e1 : (L.request c).inputBytes = (rawEncodeFinancialInput (L.request c).input).length := rfl
  rcases step_cases L c with ⟨k, w, post, res, ho, he⟩ | ⟨pid, e, post, ho, he⟩ | ⟨-, -, he⟩ <;> rw [he]
  · have hcap := transition_cap (r := L.request c) ho
    have hl := post_len_le (r := L.request c) ho
    simp only [withinCapacity, decide_eq_true_eq, e1] at hcap
    unfold anchorItemLength
    dsimp only
    have hcr := commitReceipts_len L.receipts w
    unfold commitReceipts at hcr
    rw [rawEncode_commit_length]
    have : (L.request c).receipts = L.receipts := rfl
    rw [this] at hcap
    omega
  · have hcap := transition_alias_cap (r := L.request c) ho
    have hl := alias_len (r := L.request c) ho
    simp only [withinCapacity, decide_eq_true_eq, e1] at hcap
    simp [addedBytes, evBytes, newPay, oldPay, cfBytes, receiptBytes] at hcap
    unfold anchorItemLength
    dsimp only
    rw [hl]
    have : (L.request c).receipts = L.receipts := rfl
    rw [this] at hcap
    omega
  · exact hfit

-- 16.2 item 1 (5.3): exact, hypothesis-free

-- 16.2 item 2 (5.6)

theorem find_requests (l : List ActionRecord) (a : String) (f : ActionRecord → RequestPaid)
    (hf : ∀ x, (f x).actionId = x.actionId) :
    ((l.filter (·.kind = "CORRECTION_PAYMENT_REQUEST")).map f).find? (·.actionId = a) =
      (l.find? fun x => x.actionId = a && x.kind = "CORRECTION_PAYMENT_REQUEST").map f := by
  induction l with
  | nil => rfl
  | cons x xs ih =>
    by_cases hk : x.kind = "CORRECTION_PAYMENT_REQUEST" <;> by_cases ha : x.actionId = a <;>
      simp [List.filter_cons, List.find?_cons, hk, ha, hf, ih]

/-- R1 over the state is R1 over the snapshot. -/
theorem linkRefusalView_eq {i : FinancialInput} {rs b S} (hw : financialInputWellFormed i = true)
    (hS : summarize i rs b = some S) (c : RecordCommand) :
    linkRefusalView (envOf i) S c = linkRefusal i rs c := by
  have hreq : S.requests = (i.actions.filter (·.kind = "CORRECTION_PAYMENT_REQUEST")).map fun a =>
      ⟨a.actionId, a.amountCents, linkedActivePaidCents i.payments (linksOf rs) a.actionId⟩ := by
    unfold summarize at hS
    cases hT : evaluateTotals i with
    | none => simp [hT] at hS
    | some t => simp only [hT, Option.map_some, Option.some.injEq] at hS; rw [← hS]
  have hev : evaluateState (envOf i) S = evaluate i := evaluateState_summarize hw hS
  cases hp : c.paysActionId with
  | none => simp [linkRefusalView, linkRefusal, hp]
  | some a =>
    simp only [linkRefusalView, linkRefusal, hp, Option.bind_some]
    rw [hev, hreq, find_requests _ _ _ (fun _ => rfl)]
    cases hfnd : i.actions.find? (fun x => x.actionId = a && x.kind = "CORRECTION_PAYMENT_REQUEST") with
    | none => simp
    | some q =>
      have hq := List.find?_some hfnd
      simp only [Bool.and_eq_true, decide_eq_true_eq] at hq
      simp [hq.1]

-- 16.2 item 3 (5.6): request-level; stepView_state is deleted (it is the `project` clause)
theorem stepView_eq {r : PaymentRequest} (hr : requestWellFormed r = true)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length) {v : PaymentView}
    (hv : Faithful r v) : some (stepView v) = project r (paymentTransition r) := sorry


theorem chain_fold_eq_full (L : Ledger) (hL : ledgerWellFormed L) (calls : List Call)
    (hc : clocksOk L calls) (hR : L.input.beforeRevision + calls.length ≤ maxRevision)
    (vs : List PaymentView) (hv : ChainFaithful L calls vs) :
    vs.map (some ∘ stepView) =
      ((ledgers L calls).zip calls).map fun M => project (M.1.request M.2) (outcome M.1 M.2) := sorry



-- 16.2 item 4 (5.1, D3)



-- 16.2 item 5 (5.1): both forms
theorem paymentRespond_decode_none {w : Bytes} (h : decodePaymentItem w = none) :
    paymentRespond w = [UInt8.ofNat 1] := by
  simp [paymentRespond, h]

theorem decodeStepOutcome_encode {o : StepOutcome} {b : Bytes} (h : encodeStepOutcome o = some b) :
    decodeStepOutcome b = some o := by
  dsimp only [encodeStepOutcome] at h
  split at h <;> simp_all

theorem decodePaymentItem_coherent {w : Bytes} {v : PaymentView} (h : decodePaymentItem w = some v) :
    coherent v = true := sorry

theorem decodePaymentItem_encode (v : PaymentView) (hw : viewWellFormed v = true)
    (hc : coherent v = true) : decodePaymentItem (encodeFormB v) = some v := sorry

-- 16.2 item 6 (5.3): placeholders removed, unused hypotheses dropped
theorem run_record_retry_duplicate (L : Ledger) (hL : ledgerWellFormed L) (c : RecordCommand)
    (now rev : Nat) (calls : List Call) (now' : Nat)
    (h : ∃ w post res, outcome L ⟨now, some rev, .record c⟩ = .mutated .RECORDED w post res) :
    outcome (run (step L ⟨now, some rev, .record c⟩) calls) ⟨now', some rev, .record c⟩ =
      .duplicate (some c.paymentId) := by
  obtain ⟨w, post, res, ho⟩ := h
  exact rec_duplicate now' (run_Rec (Rec_init (Inv_of_wf hL) rfl rfl ho) calls)

theorem run_reverse_retry_duplicate (L : Ledger) (c : ReverseCommand) (now : Nat)
    (exp exp' : Option Nat) (calls : List Call) (now' : Nat) (hnow : now ≤ now')
    (h : ∃ w post res, outcome L ⟨now, exp, .reverse c⟩ = .mutated .REVERSED w post res) :
    outcome (run (step L ⟨now, exp, .reverse c⟩) calls) ⟨now', exp', .reverse c⟩ = .duplicate none := by
  obtain ⟨w, post, res, ho⟩ := h
  exact revDone_duplicate exp' (run_RevDone (RevDone_init rfl hnow ho) calls)

-- 16.9 R1 (5.2) as signed
theorem record_link_within_shortfall {r : PaymentRequest} {c w post result a}
    (hc : r.command = .record c) (ha : c.paysActionId = some a)
    (h : paymentTransition r = .mutated .RECORDED w post result) :
    ∃ before, evaluate r.input = some before ∧ c.amountCents ≤ before.shortfallCents := by
  have h1 := paymentTransition_r1 hc h (fun f => nofun) w post result rfl a ha
  cases hE : evaluate r.input with
  | none => rw [hE] at h1; simp at h1
  | some b => rw [hE] at h1; exact ⟨b, rfl, by simpa using h1⟩

def linkedRecorded : PaymentOutcome → Nat
  | .mutated .RECORDED w _ _ =>
      if (w.receipt.bind (·.paysActionId)).isSome then (w.payment.map (·.amountCents)).getD 0 else 0
  | _ => 0

-- 16.9 R1-run (5.4), corrected: the balance is read from the request the n-th call saw
theorem run_linked_within_shortfall (L : Ledger) (calls : List Call) (n : Nat) (o : PaymentOutcome)
    (ho : (trace L calls)[n]? = some o) (hl : linkedRecorded o ≠ 0) :
    ∃ c before, calls[n]? = some c ∧
      evaluate ((run L (calls.take n)).request c).input = some before ∧
      linkedRecorded o ≤ before.shortfallCents := by
  obtain ⟨c, hc, rfl⟩ := trace_get calls L n o ho
  refine ⟨c, ?_⟩
  generalize run L (calls.take n) = M at hl ⊢
  cases hO : outcome M c with
  | mutated k w post res =>
    rw [hO] at hl
    cases k
    · obtain ⟨rc, hcmd, hpay, hrec, -⟩ := step_recorded hO
      have e : linkedRecorded (.mutated .RECORDED w post res) =
          if rc.paysActionId.isSome then rc.amountCents else 0 := by
        simp [linkedRecorded, hpay, hrec, recordedPayment, recordedReceipt]
      rw [e] at hl
      cases hpa : rc.paysActionId with
      | none => simp [hpa] at hl
      | some a =>
        obtain ⟨before, hev, hle⟩ := record_link_within_shortfall (r := M.request c) (c := rc) (a := a)
          hcmd hpa hO
        refine ⟨before, hc, hev, ?_⟩
        rw [e, hpa]
        simpa using hle
    all_goals simp [linkedRecorded] at hl
  | _ => rw [hO] at hl; simp [linkedRecorded] at hl

-- 16.9 E6 (5.4): hL, hc and hClaims dropped (claims and obligation are frame)
theorem run_balance_identity (L : Ledger) (calls : List Call) {r r' : FinancialResult}
    (h : evaluate L.input = some r) (h' : evaluate (run L calls).input = some r') :
    r'.shortfallCents + r.overageCents + recordedCents (trace L calls) =
      r.shortfallCents + r'.overageCents + reversedOutcomeCents (trace L calls) := by
  obtain ⟨la, hla, e1⟩ := evaluate_balance h
  obtain ⟨la', hla', e2⟩ := evaluate_balance h'
  obtain ⟨hcl, hob⟩ := run_frame L calls
  rw [hcl, hla] at hla'
  have hl := Option.some.inj hla'
  rw [hob] at e2
  have hc := conserve_gen calls L
  omega

-- 16.9 A2 (5.2), strengthened to aliases
theorem paymentTransition_shadow_refused (r : PaymentRequest)
    (hShadow : r.input.context.mode = .SHADOW) :
    (∀ k w post result, paymentTransition r ≠ .mutated k w post result) ∧
      ∀ pid e post, paymentTransition r ≠ .alias pid e post := by
  by_cases hn : ∃ f, paymentTransition r = .refused f
  · obtain ⟨f, hf⟩ := hn
    exact ⟨fun k w p res h => (by rw [hf] at h; cases h), fun pid e p h => (by rw [hf] at h; cases h)⟩
  · exact (paymentTransition_tr rfl fun f h => hn ⟨f, h⟩).2.1 hShadow

theorem refusals_complete (f : Refusal) : f ∈ refusals := by
  cases f <;> simp [refusals]

/-! ## 16.10 Known answers: the chain agrees with the reference on concrete calls, and the
    fixed bytes of each new layout (printed as hex into the build log) -/

private def hexDigit (n : Nat) : Char := Char.ofNat (if n < 10 then 48 + n else 87 + n)
private def hex (b : Bytes) : String :=
  String.ofList (b.flatMap fun x => [hexDigit (x.toNat / 16), hexDigit (x.toNat % 16)])

private def kNow : Nat := 1_774_922_400_000
private def kL0 : Ledger := ⟨katBase, []⟩
private def kRec : RecordCommand :=
  { paymentId := "payment:kat:1", evidenceId := "evidence:kat:1", commonOriginId := "origin:kat:1",
    sourceId := "source:kat", sourceVersion := "v1", localRef := none, amountCents := 700_000,
    eventAt := 1_774_900_000_000, paysActionId := none }
private def kRev : ReverseCommand :=
  { paymentId := "payment:kat:1", evidenceId := "evidence:kat:2", commonOriginId := none,
    eventAt := some 1_774_910_000_000 }
private def c1 : Call := ⟨kNow, some 0, .record kRec⟩
private def c2 : Call := ⟨kNow + 1_000, some 1, .reverse kRev⟩
private def cConflict : Call :=
  ⟨kNow + 1_000, none, .record { kRec with paymentId := "payment:kat:2", evidenceId := "evidence:kat:3", amountCents := 1 }⟩
private def cAlias : Call :=
  ⟨kNow + 1_000, none, .record { kRec with paymentId := "payment:kat:3", evidenceId := "evidence:kat:4" }⟩
private def kL1 : Ledger := step kL0 c1
private def kL2 : Ledger := step kL1 c2
private def kShadow : Ledger := ⟨{ katBase with context := { katBase.context with mode := .SHADOW } }, []⟩

private def agrees (L : Ledger) (c : Call) : Bool :=
  match viewOfAnchor (L.request c) with
  | none => false
  | some v => decide (some (stepView v) = project (L.request c) (outcome L c))

private def kind : PaymentOutcome → String
  | .mutated .RECORDED .. => "RECORDED"
  | .mutated .REVERSED .. => "REVERSED"
  | .mutated .CONFLICT_RECORDED .. => "CONFLICT_RECORDED"
  | .alias .. => "ALIAS"
  | .duplicate _ => "DUPLICATE"
  | .conflictUnchanged _ => "CONFLICT_UNCHANGED"
  | .refused _ => "REFUSED"

private def absorbs (L : Ledger) (c : Call) : Bool :=
  match outcome L c with
  | .alias _ e _ => decide ((summaryOf L.input L.receipts).map (absorb · [e]) =
      summaryOf (step L c).input (step L c).receipts)
  | _ => false

private def formBRoundTrips (L : Ledger) (c : Call) : Bool :=
  (viewOfAnchor (L.request c)).any fun v =>
    viewWellFormed v && coherent v && decide (decodePaymentItem (encodeFormB v) = some v)

private def answerRoundTrips (L : Ledger) (c : Call) : Bool :=
  (viewOfAnchor (L.request c)).any fun v => (encodeStepOutcome (stepView v)).isSome

#guard kind (outcome kL0 c1) == "RECORDED"
#guard agrees kL0 c1
#guard kind (outcome kL1 ⟨kNow + 1, some 0, .record kRec⟩) == "DUPLICATE"
#guard agrees kL1 ⟨kNow + 1, some 0, .record kRec⟩
#guard kind (outcome kL1 c2) == "REVERSED"
#guard agrees kL1 c2
#guard kind (outcome kL2 { c2 with now := kNow + 2_000, expectedRevision := none }) == "DUPLICATE"
#guard agrees kL2 { c2 with now := kNow + 2_000, expectedRevision := none }
#guard kind (outcome kL1 cConflict) == "CONFLICT_RECORDED"
#guard agrees kL1 cConflict
#guard kind (outcome (step kL1 cConflict) { cConflict with now := kNow + 5_000, expectedRevision := some 7 }) ==
  "CONFLICT_UNCHANGED"
#guard kind (outcome kL1 cAlias) == "ALIAS"
#guard agrees kL1 cAlias
#guard absorbs kL1 cAlias
#guard kind (outcome kShadow c1) == "REFUSED"
#guard agrees kShadow c1
#guard formBRoundTrips kL0 c1
#guard formBRoundTrips kL1 c2
#guard answerRoundTrips kL0 c1
#guard answerRoundTrips kL1 c2
#guard answerRoundTrips kL1 cAlias
#guard decodeStepOutcome (rawEncodeStepOutcome (.refused .CAPACITY)) == some (.refused .CAPACITY)
#guard refusals.length = 16 && anchorOverhead = 13

private def longId : String := String.ofList (List.replicate 128 'a')
private def worstRecord : Command := .record
  { paymentId := longId, evidenceId := longId, commonOriginId := longId, sourceId := longId,
    sourceVersion := longId, localRef := some longId, amountCents := 1, eventAt := 1, paysActionId := some longId }
#guard commandWellFormed worstRecord
#guard (encodeForeign ⟨true, true⟩ ++ encodeOptionNat (some 0) ++ encodeCommand worstRecord).length = 939

#eval (viewOfAnchor (kL0.request c1)).map fun v => hex (encodeFormB v)
#eval (viewOfAnchor (kL1.request c2)).map fun v => hex (encodeFormB v)
#eval (summaryOf kL1.input kL1.receipts).map fun s => hex (encodeItemState s)
#eval hex (rawEncodeStepOutcome (.refused .CAPACITY))
#eval (viewOfAnchor (kL0.request c1)).map fun v => ((encodeStepOutcome (stepView v)).map hex)

end BlindLedger.Financial.Payment.Rev12
