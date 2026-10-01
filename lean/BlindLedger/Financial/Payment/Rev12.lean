import BlindLedger.Financial.Payment.Bridge
import BlindLedger.Financial.Payment.Codec
import BlindLedger.Financial.Theorems.Vectors
import BlindLedger.Financial.CodecLaws.Records

/-! Design rev 1.2 (rrb/designs/lean-live-m3-v1.md section 16), type-checked, every theorem proved (no `sorry`).
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

/-- Section 2.6 coherence: the rows are the ones the command names, and agree with the state.
    An ACTIVE row's contribution is in the state (`advance` erases it). A REVERSED row is not
    checked: an authorized determination may carry the same (time, id, amount) contribution. -/
def coherent (v : PaymentView) : Bool :=
  let contributes (p : Payment) :=
    !decide (p.status = .ACTIVE) || v.state.contributions.contains ⟨p.eventAt, p.paymentId, p.amountCents⟩
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

private def Fits (o : StepOutcome) : Prop :=
  ∀ k w s r, o = .mutated k w s r → s.anchorBytes + maxCallTailBytes ≤ maxTotalEncodedBytes

private theorem fits_commit {v s k w} : Fits (commitView v s k w) :=
  fun _ _ _ _ h => commitView_fits h
private theorem fits_refused {x} : Fits (.refused x) := fun _ _ _ _ h => by cases h
private theorem fits_dup {x} : Fits (.duplicate x) := fun _ _ _ _ h => by cases h
private theorem fits_cu {x} : Fits (.conflictUnchanged x) := fun _ _ _ _ h => by cases h
private theorem fits_alias {x y} : Fits (.alias x y) := fun _ _ _ _ h => by cases h

private theorem fits_ite {c : Prop} [Decidable c] {a b : StepOutcome} (ha : Fits a) (hb : Fits b) :
    Fits (if c then a else b) := by
  by_cases h : c
  · rw [if_pos h]; exact ha
  · rw [if_neg h]; exact hb

private theorem fits_aliasView {v s p e} : Fits (aliasView v s p e) := by
  unfold aliasView
  refine fits_ite fits_refused (fits_ite fits_refused (fits_ite fits_alias fits_refused))

set_option maxHeartbeats 1000000 in
private theorem fits_reverse {v s c} : Fits (viewReverse v s c) := by
  unfold viewReverse; dsimp only; repeat' split
  all_goals first | exact fits_refused | exact fits_dup | exact fits_commit | skip

set_option maxHeartbeats 1000000 in
private theorem fits_retry {v c p k} : Fits (viewRecordRetry v c p k) := by
  unfold viewRecordRetry; dsimp only; repeat' split
  all_goals first | exact fits_refused | exact fits_dup | skip

set_option maxHeartbeats 1000000 in
private theorem fits_new {v s c} : Fits (viewRecordNew v s c) := by
  unfold viewRecordNew
  dsimp only
  refine fits_ite fits_refused (fits_ite fits_cu (fits_ite fits_refused (fits_ite fits_refused ?_)))
  split
  · exact fits_refused
  · refine fits_ite fits_refused ?_
    split
    · exact fits_refused
    · split
      · exact fits_ite (fits_ite fits_refused (fits_ite fits_aliasView fits_dup))
          (fits_ite fits_cu (fits_ite fits_refused fits_commit))
      · split
        · exact fits_refused
        · exact fits_commit

private theorem fits_step {v} : Fits (stepView v) := by
  unfold stepView
  dsimp only
  split
  · refine fits_ite fits_refused (fits_ite fits_refused ?_)
    split
    · exact fits_retry
    · exact fits_new
  · exact fits_reverse

theorem anchorItem_fits {v : PaymentView} {k w s r} (h : stepView v = .mutated k w s r) :
    s.anchorBytes + maxCallTailBytes ≤ maxTotalEncodedBytes := fits_step k w s r h

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

-- 16.2 item 5 (5.1): both forms
theorem paymentRespond_decode_none {w : Bytes} (h : decodePaymentItem w = none) :
    paymentRespond w = [UInt8.ofNat 1] := by
  simp [paymentRespond, h]

theorem decodeStepOutcome_encode {o : StepOutcome} {b : Bytes} (h : encodeStepOutcome o = some b) :
    decodeStepOutcome b = some o := by
  dsimp only [encodeStepOutcome] at h
  split at h <;> simp_all

theorem evalInsertContribution_perm (y : EvalContribution) :
    ∀ l, (evalInsertContribution y l).Perm (y :: l)
  | [] => .refl _
  | a :: l => by
    unfold evalInsertContribution
    split
    · exact .refl _
    · exact ((evalInsertContribution_perm y l).cons a).trans (.swap y a l)

theorem evalSortContributions_perm : ∀ l, (evalSortContributions l).Perm l
  | [] => .refl _
  | a :: l => (evalInsertContribution_perm a _).trans ((evalSortContributions_perm l).cons a)

theorem active_contribution {i : FinancialInput} {p : Payment} (hp : p ∈ i.payments)
    (ha : p.status = .ACTIVE) :
    (evalSortContributions (evalContributions i)).contains ⟨p.eventAt, p.paymentId, p.amountCents⟩ = true := by
  rw [List.contains_iff_mem, (evalSortContributions_perm _).mem_iff]
  simp only [evalContributions]
  apply List.mem_append_left
  generalize i.payments = ps at hp
  induction ps with
  | nil => cases hp
  | cons q qs ih =>
    rcases List.mem_cons.mp hp with rfl | h
    · simp [ha]
    · simp only [List.foldr_cons]; split <;> simp [ih h]

theorem findEvidence_id : ∀ {l : List EvidenceRecord} {id : String} {e : EvidenceRecord},
    findEvidence l id = some e → e.evidenceId = id
  | [], _, _, h => by simp [findEvidence] at h
  | x :: xs, id, e, h => by
      unfold findEvidence at h
      split at h
      · cases h; assumption
      · exact findEvidence_id h

theorem viewOfAnchor_coherent {r : PaymentRequest} {v : PaymentView} (h : viewOfAnchor r = some v) :
    coherent v = true := by
  obtain ⟨i, n, rs, fo, er, cmd⟩ := r
  unfold viewOfAnchor at h
  obtain ⟨S, hS, rfl⟩ := Option.map_eq_some_iff.mp h
  unfold summarize at hS
  obtain ⟨t, -, rfl⟩ := Option.map_eq_some_iff.mp hS
  have hc : ∀ p ∈ i.payments, (!decide (p.status = .ACTIVE) ||
      (evalSortContributions (evalContributions i)).contains ⟨p.eventAt, p.paymentId, p.amountCents⟩) = true := by
    intro p hp
    by_cases ha : p.status = .ACTIVE
    · rw [active_contribution hp ha, Bool.or_true]
    · simp [ha]
  have hid : ∀ x, ((findPayment i.payments (cmdPaymentId cmd)).bind fun p =>
      (receiptOf rs p.paymentId).map fun k => (p, k)) = some x →
      x.1.paymentId = cmdPaymentId cmd ∧ x.1 ∈ i.payments := by
    intro x hx
    obtain ⟨p, hp, hx⟩ := Option.bind_eq_some_iff.mp hx
    obtain ⟨k, -, rfl⟩ := Option.map_eq_some_iff.mp hx
    exact ⟨findPayment_id _ _ _ hp, findPayment_mem hp⟩
  cases cmd with
  | record c =>
    simp only [coherent, Bool.and_eq_true, Option.all_eq_true]
    refine ⟨⟨⟨⟨decide_eq_true rfl, fun x hx => ?_⟩, fun e he => decide_eq_true (findEvidence_id he)⟩, rfl⟩,
      fun x hx => ?_⟩
    · obtain ⟨hpid, hmem⟩ := hid x hx
      exact ⟨decide_eq_true hpid, hc _ hmem⟩
    · obtain ⟨p, hp, hx⟩ := Option.bind_eq_some_iff.mp hx
      obtain ⟨pk, hk, rfl⟩ := Option.map_eq_some_iff.mp hx
      obtain ⟨k, -, rfl⟩ := Option.map_eq_some_iff.mp hk
      have ho := List.find?_some hp
      simp only [decide_eq_true_eq] at ho
      refine ⟨⟨decide_eq_true ho, hc _ (List.mem_of_find?_eq_some hp)⟩,
        fun e he => decide_eq_true ?_⟩
      obtain ⟨id, hr, he⟩ := Option.bind_eq_some_iff.mp he
      show some e.evidenceId = p.reversalEvidenceId
      rw [hr, findEvidence_id he]
  | reverse c =>
    simp only [coherent, Bool.and_eq_true, Option.all_eq_true]
    refine ⟨⟨⟨⟨decide_eq_true rfl, fun x hx => ?_⟩, fun e he => decide_eq_true (findEvidence_id he)⟩, rfl⟩,
      rfl, rfl⟩
    obtain ⟨hpid, hmem⟩ := hid x hx
    exact ⟨decide_eq_true hpid, hc _ hmem⟩

theorem decodePaymentItem_cases {w : Bytes} {v : PaymentView} (h : decodePaymentItem w = some v) :
    (∃ r, decodePaymentRequest w = some r ∧ viewOfAnchor r = some v) ∨
      (viewWellFormed v = true ∧ coherent v = true) := by
  unfold decodePaymentItem at h
  split at h
  · split at h
    · exact .inl (Option.bind_eq_some_iff.mp h)
    · split at h
      · obtain ⟨-, hf⟩ := Option.filter_eq_some_iff.mp h
        simp only [Bool.and_eq_true] at hf
        exact .inr ⟨hf.1.1, hf.1.2⟩
      · cases h
  · cases h

/-- The worker steps only views whose command is well formed: the hypothesis `hw` of
    `chain_fold_eq_full`. Form A: `decodePaymentRequest`'s filter (Codec.lean:79, as
    CodecLaws.lean:371); form B: `viewWellFormed` (above). -/
theorem decodePaymentItem_command {w : Bytes} {v : PaymentView} (h : decodePaymentItem w = some v) :
    (commandWellFormed v.command && v.expectedRevision.all (· < 2 ^ 63)) = true := by
  rcases decodePaymentItem_cases h with ⟨r, hr, hv⟩ | ⟨hw, -⟩
  · unfold decodePaymentRequest at hr
    have hq := (Option.filter_eq_some_iff.mp hr).2
    simp only [Bool.and_eq_true] at hq
    have hq := hq.1.1
    simp only [requestWellFormed, Bool.and_eq_true] at hq
    unfold viewOfAnchor at hv
    obtain ⟨S, -, rfl⟩ := Option.map_eq_some_iff.mp hv
    simp [hq.1.2, hq.2]
  · simp only [viewWellFormed, Bool.and_eq_true] at hw
    simp [hw.1.2, hw.2]

theorem decodePaymentItem_coherent {w : Bytes} {v : PaymentView} (h : decodePaymentItem w = some v) :
    coherent v = true := by
  rcases decodePaymentItem_cases h with ⟨r, -, hv⟩ | ⟨-, hc⟩
  · exact viewOfAnchor_coherent hv
  · exact hc

/-! ## 16.2 items 3 and 4: the lockstep proofs (helpers are private) -/

/-! ## Contributions: the insertion sort is a sort -/

private def cb (x y : EvalContribution) : Bool :=
  contributionKeyBefore x.time x.amountCents x.identity y.time y.amountCents y.identity

private theorem cb_iff {x y : EvalContribution} : cb x y = true ↔
    x.time < y.time ∨ (x.time = y.time ∧ (x.amountCents < y.amountCents ∨
      (x.amountCents = y.amountCents ∧ x.identity < y.identity))) := by
  simp [cb, contributionKeyBefore]

private theorem cb_trans {x y z : EvalContribution} (h1 : cb x y = true) (h2 : cb y z = true) :
    cb x z = true := by
  rw [cb_iff] at *
  rcases h1 with h1 | ⟨e1, h1 | ⟨e1', h1⟩⟩ <;> rcases h2 with h2 | ⟨e2, h2 | ⟨e2', h2⟩⟩
  · exact .inl (by omega)
  · exact .inl (by omega)
  · exact .inl (by omega)
  · exact .inl (by omega)
  · exact .inr ⟨by omega, .inl (by omega)⟩
  · exact .inr ⟨by omega, .inl (by omega)⟩
  · exact .inl (by omega)
  · exact .inr ⟨by omega, .inl (by omega)⟩
  · exact .inr ⟨by omega, .inr ⟨by omega, String.lt_trans h1 h2⟩⟩

private theorem cb_asymm {x y : EvalContribution} (h : cb x y = true) : cb y x = false := by
  cases h' : cb y x
  · rfl
  · have := cb_trans h h'
    rw [cb_iff] at this
    rcases this with h | ⟨-, h | ⟨-, h⟩⟩
    · omega
    · omega
    · exact absurd h (String.lt_irrefl _)

private theorem cb_conn {x y : EvalContribution} (h1 : cb x y = false) (h2 : cb y x = false) : x = y := by
  rw [← Bool.not_eq_true, cb_iff] at h1 h2
  obtain ⟨t, i, a⟩ := x
  obtain ⟨t', i', a'⟩ := y
  simp only at h1 h2
  have ht : t = t' := by omega
  subst ht
  have ha : a = a' := by omega
  subst ha
  have hi : i = i' := String.le_antisymm (String.not_lt.1 (fun h => h2 (.inr ⟨rfl, .inr ⟨rfl, h⟩⟩)))
    (String.not_lt.1 (fun h => h1 (.inr ⟨rfl, .inr ⟨rfl, h⟩⟩)))
  rw [hi]

private theorem ins_cons (y a : EvalContribution) (l : List EvalContribution) :
    evalInsertContribution y (a :: l) = if cb y a = true then y :: a :: l else a :: evalInsertContribution y l := rfl

private def Sorted (l : List EvalContribution) : Prop := l.Pairwise fun a b => cb b a = false

private theorem insert_sorted (y : EvalContribution) :
    ∀ {l : List EvalContribution}, Sorted l → Sorted (evalInsertContribution y l)
  | [], _ => by simp [evalInsertContribution, Sorted]
  | a :: l, h => by
    rw [ins_cons]
    obtain ⟨ha, hl⟩ := List.pairwise_cons.1 h
    by_cases hc : cb y a = true
    · rw [if_pos hc]
      refine List.pairwise_cons.2 ⟨fun z hz => ?_, h⟩
      rcases List.mem_cons.1 hz with rfl | hz
      · exact cb_asymm hc
      · cases hzy : cb z y
        · rfl
        · exact absurd (cb_trans hzy hc) (by rw [ha z hz]; simp)
    · rw [if_neg hc]
      refine List.pairwise_cons.2 ⟨fun z hz => ?_, insert_sorted y hl⟩
      rcases (List.mem_cons.1 ((evalInsertContribution_perm y l).mem_iff.1 hz)) with rfl | hz
      · simpa using hc
      · exact ha z hz

private theorem sort_sorted : ∀ l, Sorted (evalSortContributions l)
  | [] => by simp [evalSortContributions, Sorted]
  | a :: l => insert_sorted a (sort_sorted l)

private theorem sorted_eq {l₁ l₂ : List EvalContribution} (h : l₁.Perm l₂) (s₁ : Sorted l₁) (s₂ : Sorted l₂) :
    l₁ = l₂ :=
  h.eq_of_pairwise (fun _ _ _ _ h1 h2 => cb_conn h2 h1) s₁ s₂

private theorem sort_congr {l₁ l₂ : List EvalContribution} (h : l₁.Perm l₂) :
    evalSortContributions l₁ = evalSortContributions l₂ :=
  sorted_eq ((evalSortContributions_perm _).trans (h.trans (evalSortContributions_perm _).symm))
    (sort_sorted _) (sort_sorted _)

private theorem sort_erase (x : EvalContribution) {l : List EvalContribution} (h : x ∈ l) :
    (evalSortContributions l).erase x = evalSortContributions (l.erase x) := by
  have p : l.Perm (x :: l.erase x) := List.perm_cons_erase h
  have e : evalSortContributions l = evalInsertContribution x (evalSortContributions (l.erase x)) := by
    rw [sort_congr p]; rfl
  rw [e]
  refine sorted_eq ?_ ?_ (sort_sorted _)
  · exact ((evalInsertContribution_perm x _).erase x).trans (by simp)
  · exact (insert_sorted x (sort_sorted _)).sublist List.erase_sublist

/-! ## Insertion, canonical lists -/

private theorem insertBy_perm {α} (key : α → String) (row : α) :
    ∀ l : List α, (insertBy key row l).Perm (row :: l)
  | [] => .refl _
  | x :: xs => by
    unfold insertBy
    split
    · exact .refl _
    · exact ((insertBy_perm key row xs).cons x).trans (.swap row x xs)

private theorem str_trich (a b : String) : a < b ∨ a = b ∨ b < a := by
  by_cases h1 : a < b
  · exact Or.inl h1
  · by_cases h2 : b < a
    · exact Or.inr (Or.inr h2)
    · exact Or.inr (Or.inl (String.le_antisymm (String.not_lt.1 h2) (String.not_lt.1 h1)))

private theorem sa_iff : ∀ l : List String, strictlyAscending l = true ↔ l.Pairwise (· < ·)
  | [] => by simp [strictlyAscending]
  | [a] => by simp [strictlyAscending]
  | a :: b :: rest => by
      rw [strictlyAscending, Bool.and_eq_true, decide_eq_true_eq, sa_iff (b :: rest)]
      constructor
      · rintro ⟨hab, h⟩
        refine List.pairwise_cons.2 ⟨?_, h⟩
        intro x hx
        rcases List.mem_cons.1 hx with rfl | hx
        · exact hab
        · exact String.lt_trans hab ((List.pairwise_cons.1 h).1 x hx)
      · intro h
        obtain ⟨h1, h2⟩ := List.pairwise_cons.1 h
        exact ⟨h1 b (List.mem_cons_self ..), h2⟩

private theorem pairwise_insert_str (s : String) :
    ∀ {l : List String}, l.Pairwise (· < ·) → s ∉ l → (insertBy (fun x => x) s l).Pairwise (· < ·)
  | [], _, _ => by simp [insertBy]
  | x :: xs, h, hn => by
    obtain ⟨h1, h2⟩ := List.pairwise_cons.1 h
    have e : insertBy (fun x : String => x) s (x :: xs) =
        if s < x then s :: x :: xs else x :: insertBy (fun x => x) s xs := rfl
    rw [e]
    by_cases hs : s < x
    · rw [if_pos hs]
      refine List.pairwise_cons.2 ⟨fun y hy => ?_, h⟩
      rcases List.mem_cons.1 hy with rfl | hy
      · exact hs
      · exact String.lt_trans hs (h1 y hy)
    · rw [if_neg hs]
      have hxs : s ∉ xs := fun m => hn (List.mem_cons_of_mem _ m)
      have hsx : s ≠ x := fun e => hn (e ▸ List.mem_cons_self ..)
      refine List.pairwise_cons.2 ⟨fun y hy => ?_, pairwise_insert_str s h2 hxs⟩
      rcases (mem_insertBy (fun x : String => x) s y xs).1 hy with rfl | hy
      · rcases str_trich x y with h' | h' | h'
        · exact h'
        · exact absurd h'.symm hsx
        · exact absurd h' hs
      · exact h1 y hy

private theorem canonical_insert {l : List String} (h : canonicalIdList l = true) {s : String}
    (hs : idWellFormed s = true) (hn : s ∉ l) (hlen : l.length < maxRows) :
    canonicalIdList (insertBy (fun x => x) s l) = true := by
  obtain ⟨-, hid, hp⟩ := canonical_facts h
  have hperm := insertBy_perm (fun x : String => x) s l
  simp only [canonicalIdList, Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true]
  refine ⟨⟨?_, fun x hx => ?_⟩, (sa_iff _).2 (pairwise_insert_str s hp hn)⟩
  · rw [hperm.length_eq]; simp only [List.length_cons]; omega
  · rcases List.mem_cons.1 (hperm.mem_iff.1 hx) with rfl | hx
    · exact hs
    · exact hid x hx

/-! ## Totals -/

private theorem evalAdd_eq' (a b : Nat) : evalAdd a b = if a + b ≤ maxCents then some (a + b) else none := by
  unfold evalAdd
  by_cases h : a + b ≤ maxCents
  · rw [if_pos h, if_pos]
    simp only [Bool.and_eq_true, decide_eq_true_eq]; omega
  · rw [if_neg h, if_neg]
    simp only [Bool.and_eq_true, decide_eq_true_eq]; omega

private theorem evalPaymentSum_eq : ∀ ps : List Payment,
    evalPaymentSum ps = if activeCents ps ≤ maxCents then some (activeCents ps) else none
  | [] => by simp [evalPaymentSum, activeCents, maxCents]
  | p :: ps => by
    have ih := evalPaymentSum_eq ps
    by_cases hs : p.status = .ACTIVE
    · have e : activeCents (p :: ps) = p.amountCents + activeCents ps := by
        simp [activeCents, hs]
      rw [e]
      by_cases h1 : activeCents ps ≤ maxCents
      · rw [if_pos h1] at ih
        simp only [evalPaymentSum, ih, hs, if_true]
        exact evalAdd_eq' _ _
      · rw [if_neg h1] at ih
        have : ¬ p.amountCents + activeCents ps ≤ maxCents := by omega
        simp only [evalPaymentSum, ih, if_neg this]; rfl
    · have e : activeCents (p :: ps) = activeCents ps := by
        simp [activeCents, hs]
      rw [e]
      by_cases h1 : activeCents ps ≤ maxCents
      · rw [if_pos h1] at ih
        simp [evalPaymentSum, ih, hs, h1]
      · rw [if_neg h1] at ih
        simp [evalPaymentSum, ih, hs, h1]

private theorem evaluateTotals_payments {i : FinancialInput} {t} (h : evaluateTotals i = some t)
    (P : List Payment) :
    evaluateTotals { i with payments := P } =
      if activeCents P + t.lawful ≤ maxCents then
        some { cash := activeCents P, claimed := t.claimed, lawful := t.lawful,
               total := activeCents P + t.lawful }
      else none := by
  unfold evaluateTotals at h ⊢
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
  | some tot =>
    simp only [hc, hcl, hl, ht, Option.some.injEq] at h
    subst h
    have hla : la ≤ maxCents := by
      rw [evalAdd_eq'] at ht
      by_cases hh : cash + la ≤ maxCents
      · omega
      · rw [if_neg hh] at ht; cases ht
    dsimp only
    rw [evalPaymentSum_eq]
    by_cases h1 : activeCents P ≤ maxCents
    · rw [if_pos h1]
      simp only [evalAdd_eq']
      by_cases h2 : activeCents P + la ≤ maxCents
      · rw [if_pos h2, if_pos h2]
      · rw [if_neg h2, if_neg h2]
    · rw [if_neg h1, if_neg (by omega)]

/-! ## Contribution multisets -/

private def pcOf (P : List Payment) : List EvalContribution :=
  P.foldr (fun payment rest =>
    if payment.status = .ACTIVE then
      { time := payment.eventAt, identity := payment.paymentId, amountCents := payment.amountCents } :: rest
    else rest) []

private def dcOf (D : List OffsetDetermination) : List EvalContribution :=
  D.foldr (fun determination rest =>
    if determination.decision = .OFFSET_AUTHORIZED then
      { time := determination.decidedAt, identity := determination.determinationId,
        amountCents := determination.amountCents } :: rest
    else rest) []

private theorem evalContributions_eq (i : FinancialInput) :
    evalContributions i = pcOf i.payments ++ dcOf i.determinations := rfl

private def cOf (p : Payment) : EvalContribution := ⟨p.eventAt, p.paymentId, p.amountCents⟩

private theorem pcOf_eq (P : List Payment) :
    pcOf P = (P.filter fun q => q.status = .ACTIVE).map cOf := by
  induction P with
  | nil => rfl
  | cons p ps ih =>
    by_cases hs : p.status = .ACTIVE <;> simp [pcOf, hs, cOf] at ih ⊢ <;> exact ih

private theorem pcOf_perm {P Q : List Payment} (h : P.Perm Q) : (pcOf P).Perm (pcOf Q) := by
  rw [pcOf_eq, pcOf_eq]; exact (h.filter _).map _

private theorem pcOf_active {p : Payment} (P : List Payment) (h : p.status = .ACTIVE) :
    pcOf (p :: P) = cOf p :: pcOf P := by
  simp [pcOf, List.foldr_cons, h, cOf]

private theorem pcOf_inactive {p : Payment} (P : List Payment) (h : p.status ≠ .ACTIVE) :
    pcOf (p :: P) = pcOf P := by
  simp [pcOf, List.foldr_cons, h]

private theorem contrib_insert (dc : List EvalContribution) (P : List Payment) (x : Payment)
    (hx : x.status = .ACTIVE) :
    evalSortContributions (pcOf (insertBy Payment.paymentId x P) ++ dc) =
      evalInsertContribution (cOf x) (evalSortContributions (pcOf P ++ dc)) := by
  have hp : (pcOf (insertBy Payment.paymentId x P) ++ dc).Perm (cOf x :: (pcOf P ++ dc)) := by
    have := (pcOf_perm (insertBy_perm Payment.paymentId x P)).append_right dc
    rwa [pcOf_active _ hx, List.cons_append] at this
  rw [sort_congr hp]; rfl

private theorem pcOf_replace (new : Payment) (hnew : new.status ≠ .ACTIVE) :
    ∀ (P : List Payment) (q : Payment), (P.map Payment.paymentId).Nodup →
      findPayment P new.paymentId = some q → q.status = .ACTIVE →
      (pcOf P).Perm (cOf q :: pcOf (P.map fun x => if x.paymentId = new.paymentId then new else x))
  | [], q, _, h, _ => by simp [findPayment] at h
  | x :: xs, q, hn, h, hq => by
    rw [List.map_cons, List.nodup_cons] at hn
    by_cases hx : x.paymentId = new.paymentId
    · simp only [findPayment, hx, ↓reduceIte, Option.some.injEq] at h
      subst h
      have hid : xs.map (fun y => if y.paymentId = new.paymentId then new else y) = xs := by
        refine (List.map_congr_left (g := id) fun y hy => ?_).trans (List.map_id _)
        have hy' : y.paymentId ≠ new.paymentId := fun e =>
          hn.1 (List.mem_map.2 ⟨y, hy, e.trans hx.symm⟩)
        simp [hy']
      simp only [List.map_cons, hx, ↓reduceIte, hid]
      rw [pcOf_active _ hq, pcOf_inactive _ hnew]
    · simp only [findPayment, hx, ↓reduceIte] at h
      have ih := pcOf_replace new hnew xs q hn.2 h hq
      simp only [List.map_cons, hx, ↓reduceIte]
      by_cases ha : x.status = .ACTIVE
      · rw [pcOf_active _ ha, pcOf_active _ ha]
        exact (ih.cons (cOf x)).trans (.swap _ _ _)
      · rw [pcOf_inactive _ ha, pcOf_inactive _ ha]
        exact ih

private theorem contrib_replace (dc : List EvalContribution) (P : List Payment) (new q : Payment)
    (hnew : new.status ≠ .ACTIVE) (hn : (P.map Payment.paymentId).Nodup)
    (hf : findPayment P new.paymentId = some q) (hq : q.status = .ACTIVE) :
    evalSortContributions (pcOf (P.map fun x => if x.paymentId = new.paymentId then new else x) ++ dc) =
      (evalSortContributions (pcOf P ++ dc)).erase (cOf q) := by
  have hp := (pcOf_replace new hnew P q hn hf hq).append_right dc
  rw [List.cons_append] at hp
  have hm : cOf q ∈ pcOf P ++ dc := hp.symm.mem_iff.1 (List.mem_cons_self ..)
  rw [sort_erase _ hm]
  refine sort_congr ?_
  have := hp.erase (cOf q)
  rw [List.erase_cons_head] at this
  exact this.symm

/-! ## Well-formedness of a post-state: the 19 conjuncts that read payments, evidence or conflicts -/

private def upd (i : FinancialInput) (P : List Payment) (E : List EvidenceRecord)
    (C : List FinancialConflict) : FinancialInput :=
  { i with payments := P, evidence := E, conflicts := C }

private theorem wf_of_parts {i : FinancialInput} (hi : financialInputWellFormed i = true)
    {P : List Payment} {E : List EvidenceRecord} {C : List FinancialConflict}
    (n17 : P.length ≤ maxRows) (n20 : E.length ≤ maxRows) (n21 : C.length ≤ maxRows)
    (n25 : canonicalIdList (P.map Payment.paymentId) = true)
    (n28 : canonicalIdList (E.map EvidenceRecord.evidenceId) = true)
    (n29 : canonicalIdList (C.map FinancialConflict.conflictId) = true)
    (n32 : P.all (paymentWellFormed i.context) = true)
    (n34 : E.all (evidenceWellFormed i.context) = true)
    (n36 : C.all (conflictWellFormed (upd i P E C)) = true)
    (n39 : P.all (paymentEvidenceWellFormed (upd i P E C)) = true)
    (n40 : P.all (reversalEvidenceWellFormed (upd i P E C)) = true)
    (n41 : i.claims.all (claimEvidenceWellFormed (upd i P E C)) = true)
    (n48 : E.all (fun evidence =>
      if evidence.kind = "PAYMENT_CONFIRMATION" then paymentConfirmationAccounted (upd i P E C) evidence
      else if evidence.kind = "PAYMENT_REVERSAL" then reversalEvidenceAccounted (upd i P E C) evidence
      else if evidence.kind = "OFFSET_CLAIM" then
        i.claims.any (fun claim => claim.evidenceId = evidence.evidenceId)
      else true) = true)
    (n49 : E.all (fun evidence => decide (evidence.receivedAt ≤ i.evaluatedAt)) = true)
    (n51 : allReferencesExist (E.map EvidenceRecord.evidenceId) (P.map Payment.evidenceId) = true)
    (n52 : allReferencesExist (E.map EvidenceRecord.evidenceId) (P.filterMap Payment.reversalEvidenceId) = true)
    (n53 : allReferencesExist (E.map EvidenceRecord.evidenceId) (i.claims.map Claim.evidenceId) = true)
    (n54 : i.determinations.all (fun determination =>
      allReferencesExist (E.map EvidenceRecord.evidenceId) determination.supportingEvidenceIds) = true)
    (n55 : noDuplicates (P.map Payment.commonOriginId) = true) :
    financialInputWellFormed (upd i P E C) = true := by
  simp only [financialInputWellFormed, Bool.and_assoc, Bool.and_eq_true, decide_eq_true_eq] at hi ⊢
  obtain ⟨h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11,h12,h13,h14,h15,h16,h17,h18,h19,h20,h21,h22,h23,h24,h25,h26,h27,h28,h29,h30,h31,h32,h33,h34,h35,h36,h37,h38,h39,h40,h41,h42,h43,h44,h45,h46,h47,h48,h49,h50,h51,h52,h53,h54,h55⟩ := hi
  exact ⟨h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11,h12,h13,h14,h15,h16,n17,h18,h19,n20,n21,h22,h23,h24,n25,h26,h27,n28,n29,h30,h31,n32,h33,n34,h35,n36,h37,h38,n39,n40,n41,h42,h43,h44,h45,h46,h47,n48,n49,h50,n51,n52,n53,n54,n55⟩

private theorem noDup_iff : ∀ l : List String, noDuplicates l = true ↔ l.Nodup
  | [] => by simp [noDuplicates]
  | a :: l => by
    rw [noDuplicates, List.nodup_cons, ← noDup_iff l]
    simp [List.contains_iff_mem]

private theorem payments_le_evidence {post : FinancialInput}
    (h39 : post.payments.all (paymentEvidenceWellFormed post) = true)
    (h51 : allReferencesExist (post.evidence.map EvidenceRecord.evidenceId) (post.payments.map Payment.evidenceId) = true)
    (h55 : noDuplicates (post.payments.map Payment.commonOriginId) = true) :
    post.payments.length ≤ post.evidence.length := by
  let g : String → String := fun id => ((findEvidence post.evidence id).map (·.commonOriginId)).getD ""
  have hg : post.payments.map Payment.commonOriginId = (post.payments.map Payment.evidenceId).map g := by
    rw [List.map_map]
    refine List.map_congr_left fun p hp => ?_
    have := List.all_eq_true.1 h39 p hp
    unfold paymentEvidenceWellFormed at this
    cases hf : findEvidence post.evidence p.evidenceId with
    | none => simp [hf] at this
    | some ev =>
      rw [hf] at this
      simp only [Bool.and_eq_true, decide_eq_true_eq] at this
      show _ = g p.evidenceId
      simp only [g, hf, Option.map_some, Option.getD_some]
      exact this.1.1.2.symm
  have hnd : (post.payments.map Payment.evidenceId).Nodup := by
    have := (noDup_iff _).1 h55
    rw [hg] at this
    exact List.Pairwise.of_map g (fun a b h e => h (by rw [e])) this
  have hsub : (post.payments.map Payment.evidenceId) ⊆ post.evidence.map EvidenceRecord.evidenceId := by
    intro x hx
    have := List.all_eq_true.1 h51 x hx
    simpa using this
  have := hnd.length_le_of_subset hsub
  simpa using this

private theorem evalLatestCase_const (st : CaseStatus) (t : Nat) :
    ∀ K : List CaseRecord, K ≠ [] →
      evalLatestCase (K.map fun k => { k with status := st, updatedAt := t }) = st
  | [], h => absurd rfl h
  | [_], _ => rfl
  | _ :: k2 :: ks, _ => by
    simp only [List.map_cons]
    exact evalLatestCase_const st t (k2 :: ks) (by simp)

private theorem summarize_some {i : FinancialInput} {rs b S} (h : summarize i rs b = some S) :
    ∃ t, evaluateTotals i = some t ∧
      S = { revision := i.beforeRevision, cash := t.cash, claimed := t.claimed, lawful := t.lawful,
            contributions := evalSortContributions (evalContributions i),
            latestCase := evalLatestCase i.cases, delivery := evalLatestDelivery i.actions,
            conflictCount := i.conflicts.length, evidenceIds := i.evidence.map (·.evidenceId),
            requests := (i.actions.filter (·.kind = "CORRECTION_PAYMENT_REQUEST")).map fun a =>
              ⟨a.actionId, a.amountCents, linkedActivePaidCents i.payments (linksOf rs) a.actionId⟩,
            anchorBytes := b } := by
  unfold summarize at h
  cases ht : evaluateTotals i with
  | none => simp [ht] at h
  | some t =>
    simp only [ht, Option.map_some, Option.some.injEq] at h
    exact ⟨t, rfl, h.symm⟩

private theorem evaluate_after {i : FinancialInput} {res} (h : evaluate i = some res) :
    res.afterRevision = i.beforeRevision + 1 := by
  unfold evaluate at h
  split at h
  · unfold evaluateWellFormed at h
    cases hT : evaluateTotals i with
    | none => simp [hT] at h
    | some t => simp only [hT, Option.map_some, Option.some.injEq] at h; subst h; rfl
  · simp at h

private theorem evaluate_none_of {i : FinancialInput}
    (h : financialInputWellFormed i = true → evaluateTotals i = none) : evaluate i = none := by
  unfold evaluate
  by_cases hw : financialInputWellFormed i = true
  · rw [if_pos hw]; unfold evaluateWellFormed; rw [h hw]; rfl
  · rw [if_neg hw]

private theorem summary_commit {post : FinancialInput} {res : FinancialResult} {rs : List Receipt} {s' : ItemState}
    (hcases : post.cases ≠ [])
    (hs : summarize post rs (anchorItemLength post rs) = some s')
    (hres : res.afterRevision = post.beforeRevision + 1) :
    summaryOf (commitInput post res) rs = some (settle s' res) := by
  have hA : anchorItemLength (commitInput post res) rs = anchorItemLength post rs := by
    unfold anchorItemLength; rw [rawEncode_commit_length]
  unfold summaryOf
  rw [hA]
  obtain ⟨t, ht, rfl⟩ := summarize_some hs
  unfold summarize
  have hT : evaluateTotals (commitInput post res) = some t := ht
  rw [hT]
  simp only [Option.map_some, Option.some.injEq, settle, commitInput, hres]
  rw [evalLatestCase_const _ _ _ hcases]
  rfl

/-- The commit step, for any write set whose `advance` is the summary of the written post-state. -/
private theorem commit_core {r : PaymentRequest} {V : PaymentView} {S : ItemState} {k : Mutation} {w : Writes}
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hS : summarize r.input r.receipts (anchorItemLength r.input r.receipts) = some S)
    (hVenv : V.env = envOf r.input)
    (hgrow : anchorGrowth V w = addedBytes r.input w + receiptBytes w)
    (hraw : (rawEncodeFinancialInput (applyWrites r.input w)).length =
      (rawEncodeFinancialInput r.input).length + addedBytes r.input w)
    (hcases : r.input.cases ≠ [])
    (hadv : ∀ s', advance V S w = some s' → financialInputWellFormed (applyWrites r.input w) = true)
    (hsum : financialInputWellFormed (applyWrites r.input w) = true →
      advance V S w = summarize (applyWrites r.input w) (commitReceipts r.receipts w)
        (S.anchorBytes + anchorGrowth V w)) :
    some (commitView V S k w) = project r (mutate r k w) := by
  have hSb : S.anchorBytes = anchorItemLength r.input r.receipts := by
    obtain ⟨t, -, rfl⟩ := summarize_some hS; rfl
  have hcr := commitReceipts_len r.receipts w
  have hcap : (S.anchorBytes + anchorGrowth V w + maxCallTailBytes > maxTotalEncodedBytes) ↔
      ¬ withinCapacity r w = true := by
    simp only [withinCapacity, anchorItemLength, decide_eq_true_eq] at hSb ⊢
    omega
  unfold commitView mutate
  rw [hVenv]
  by_cases hsh : r.input.context.mode = .SHADOW
  · simp [envOf, hsh, project]
  have hsh' : (envOf r.input).context.mode ≠ .SHADOW := hsh
  simp only [hsh', hsh, if_false]
  by_cases hcp : withinCapacity r w = true
  · have hc2 : ¬ (S.anchorBytes + anchorGrowth V w + maxCallTailBytes > maxTotalEncodedBytes) :=
      fun h => (hcap.1 h) hcp
    simp only [hc2, hcp, if_false, Bool.not_true, Bool.false_eq_true]
    cases hA : advance V S w with
    | none =>
      have hnone : evaluate (applyWrites r.input w) = none := by
        refine evaluate_none_of fun hw => ?_
        have := hsum hw
        rw [hA] at this
        unfold summarize at this
        cases ht : evaluateTotals (applyWrites r.input w) with
        | none => rfl
        | some t => simp [ht] at this
      simp [hnone, project]
    | some s' =>
      have hw := hadv s' hA
      have hs' := (hsum hw).symm.trans hA
      have hb' : S.anchorBytes + anchorGrowth V w =
          anchorItemLength (applyWrites r.input w) (commitReceipts r.receipts w) := by
        simp only [anchorItemLength, hraw, hSb, hgrow] at hcr ⊢
        omega
      rw [hb'] at hs'
      have hev : evaluateState (envOf r.input) s' = evaluate (applyWrites r.input w) :=
        evaluateState_summarize hw hs'
      dsimp only
      rw [hev]
      cases hE : evaluate (applyWrites r.input w) with
      | none => simp [project]
      | some res =>
        have hres := evaluate_after hE
        have hsc := summary_commit (post := applyWrites r.input w) hcases hs' hres
        simp [project, hsc]
  · have hc2 : S.anchorBytes + anchorGrowth V w + maxCallTailBytes > maxTotalEncodedBytes :=
      hcap.2 hcp
    simp [hc2, hcp, project]

/-! ## Lookup and list facts -/

private theorem findEvidence_mem {l : List EvidenceRecord} {id e} (h : findEvidence l id = some e) : e ∈ l := by
  rw [findEvidence_eq] at h; exact List.mem_of_find?_eq_some h

private theorem findEvidence_none_ne {l : List EvidenceRecord} {id} (h : findEvidence l id = none) :
    ∀ e ∈ l, e.evidenceId ≠ id := by
  rw [findEvidence_eq, List.find?_eq_none] at h
  intro e he eq; exact h e he (by simp [eq])

private theorem findPayment_none_ne {l : List Payment} {id} (h : findPayment l id = none) :
    ∀ p ∈ l, p.paymentId ≠ id := by
  rw [findPayment_eq, List.find?_eq_none] at h
  intro e he eq; exact h e he (by simp [eq])

private theorem length_insertBy {α} (key : α → String) (row : α) (l : List α) :
    (insertBy key row l).length = l.length + 1 := by
  rw [(insertBy_perm key row l).length_eq]; rfl

private theorem all_insertBy {α} (key : α → String) (row : α) (f : α → Bool) {l : List α}
    (hr : f row = true) (hl : l.all f = true) : (insertBy key row l).all f = true := by
  rw [List.all_eq_true] at hl ⊢
  intro x hx
  rcases (mem_insertBy key row x l).1 hx with rfl | h
  · exact hr
  · exact hl x h

private theorem mem_replace {P : List Payment} {new : Payment} {pid : String} {x : Payment}
    (hx : x ∈ P.map fun y => if y.paymentId = pid then new else y) : x = new ∨ x ∈ P := by
  obtain ⟨y, hy, rfl⟩ := List.mem_map.1 hx
  by_cases h : y.paymentId = pid
  · left; simp [h]
  · right; simpa [h] using hy

/-! ## Row predicates are monotone under growth of the evidence list -/

private theorem pew_mono {i j : FinancialInput}
    (h : ∀ id ev, findEvidence i.evidence id = some ev → findEvidence j.evidence id = some ev)
    {q : Payment} (hq : paymentEvidenceWellFormed i q = true) : paymentEvidenceWellFormed j q = true := by
  unfold paymentEvidenceWellFormed at hq ⊢
  cases hf : findEvidence i.evidence q.evidenceId with
  | none => simp [hf] at hq
  | some ev => rw [hf] at hq; rw [h _ _ hf]; exact hq

private theorem cew_mono {i j : FinancialInput}
    (h : ∀ id ev, findEvidence i.evidence id = some ev → findEvidence j.evidence id = some ev)
    {q : Claim} (hq : claimEvidenceWellFormed i q = true) : claimEvidenceWellFormed j q = true := by
  unfold claimEvidenceWellFormed at hq ⊢
  cases hf : findEvidence i.evidence q.evidenceId with
  | none => simp [hf] at hq
  | some ev => rw [hf] at hq; rw [h _ _ hf]; exact hq

private theorem rew_mono {i j : FinancialInput}
    (h : ∀ id ev, findEvidence i.evidence id = some ev → findEvidence j.evidence id = some ev)
    {q : Payment} (hq : reversalEvidenceWellFormed i q = true) : reversalEvidenceWellFormed j q = true := by
  unfold reversalEvidenceWellFormed at hq ⊢
  rcases hs : q.status with _ | _ <;> rcases hr : q.reversalEvidenceId with _ | e <;>
    simp only [hs, hr] at hq ⊢
  · exact absurd hq (by decide)
  · exact absurd hq (by decide)
  cases hf : findEvidence i.evidence e with
  | none => simp [hf] at hq
  | some ev => rw [hf] at hq; rw [h _ _ hf]; exact hq

private theorem confl_mono {i j : FinancialInput} (hc : j.context = i.context)
    (he : ∀ id ev, findEvidence i.evidence id = some ev → findEvidence j.evidence id = some ev)
    (hp : ∀ id q, findPayment i.payments id = some q → ∃ q', findPayment j.payments id = some q' ∧
      q'.commonOriginId = q.commonOriginId ∧ q'.amountCents = q.amountCents)
    {x : FinancialConflict} (hx : conflictWellFormed i x = true) : conflictWellFormed j x = true := by
  unfold conflictWellFormed at hx ⊢
  rw [hc]
  simp only [Bool.and_eq_true] at hx ⊢
  obtain ⟨hA, hB⟩ := hx
  refine ⟨hA, ?_⟩
  rcases hq : findPayment i.payments x.existingPaymentId with _ | q <;>
    rcases hq' : findEvidence i.evidence x.candidateEvidenceId with _ | ev <;> simp only [hq, hq'] at hB
  all_goals try exact absurd hB (by decide)
  obtain ⟨q', hq2, ho, ha⟩ := hp _ _ hq
  rw [hq2, he _ _ hq']
  simpa only [ho, ha] using hB

private theorem accConf_mono {i j : FinancialInput}
    (hp : ∀ q ∈ i.payments, ∃ q' ∈ j.payments, q'.evidenceId = q.evidenceId ∧
      q'.commonOriginId = q.commonOriginId ∧ q'.amountCents = q.amountCents)
    (hc : ∀ x ∈ i.conflicts, x ∈ j.conflicts) {ev : EvidenceRecord}
    (h : paymentConfirmationAccounted i ev = true) : paymentConfirmationAccounted j ev = true := by
  unfold paymentConfirmationAccounted at h ⊢
  simp only [Bool.or_eq_true, List.any_eq_true, decide_eq_true_eq] at h ⊢
  rcases h with (⟨q, hq, hqe⟩ | ⟨x, hx, hxe⟩) | h
  · obtain ⟨q', hq', he, -, -⟩ := hp q hq
    exact Or.inl (Or.inl ⟨q', hq', he.trans hqe⟩)
  · exact Or.inl (Or.inr ⟨x, hc x hx, hxe⟩)
  · right
    cases ha : ev.amountCents with
    | none => simp [ha] at h
    | some a =>
      simp only [ha, List.any_eq_true, Bool.and_eq_true, decide_eq_true_eq] at h ⊢
      obtain ⟨q, hq, ho, hm⟩ := h
      obtain ⟨q', hq', -, ho', hm'⟩ := hp q hq
      exact ⟨q', hq', by rw [ho', ho], by rw [hm', hm]⟩

private theorem accRev_mono {i j : FinancialInput}
    (hp : ∀ id q, findPayment i.payments id = some q → q.status = .REVERSED →
      findPayment j.payments id = some q)
    {ev : EvidenceRecord} (h : reversalEvidenceAccounted i ev = true) :
    reversalEvidenceAccounted j ev = true := by
  unfold reversalEvidenceAccounted at h ⊢
  cases hr : ev.reversalOf with
  | none => simp [hr] at h
  | some pid =>
    simp only [hr] at h ⊢
    cases hf : findPayment i.payments pid with
    | none => simp [hf] at h
    | some q =>
      simp only [hf] at h
      have hq : q.status = .REVERSED := by
        revert h; simp only [Bool.and_eq_true, decide_eq_true_eq]; intro h; exact h.1.1.1.1
      rw [hp pid q hf hq]
      exact h

/-- The evidence-accounted conjunct, as a function of the input (its `i.claims` is `j.claims`). -/
private def accLam (j : FinancialInput) (evidence : EvidenceRecord) : Bool :=
  if evidence.kind = "PAYMENT_CONFIRMATION" then paymentConfirmationAccounted j evidence
  else if evidence.kind = "PAYMENT_REVERSAL" then reversalEvidenceAccounted j evidence
  else if evidence.kind = "OFFSET_CLAIM" then
    j.claims.any (fun claim => claim.evidenceId = evidence.evidenceId)
  else true

private theorem wf_ctx {i : FinancialInput} (h : financialInputWellFormed i = true) :
    idWellFormed i.context.obligationId = true ∧ idWellFormed i.context.itemId = true ∧
      i.evaluatedAt ≤ maxTime := by
  simp only [financialInputWellFormed, Bool.and_assoc, Bool.and_eq_true, decide_eq_true_eq] at h
  obtain ⟨h1, -, -, -, -, -, h7, -⟩ := h
  have hc := h1
  unfold contextWellFormed at hc
  simp only [Bool.and_eq_true] at hc
  obtain ⟨⟨hall, -⟩, -⟩ := hc
  exact ⟨List.all_eq_true.1 hall _ (by simp), List.all_eq_true.1 hall _ (by simp), of_decide_eq_true h7⟩

private theorem accLam_mono {i j : FinancialInput} (hcl : j.claims = i.claims)
    (hp : ∀ q ∈ i.payments, ∃ q' ∈ j.payments, q'.evidenceId = q.evidenceId ∧
      q'.commonOriginId = q.commonOriginId ∧ q'.amountCents = q.amountCents)
    (hc : ∀ x ∈ i.conflicts, x ∈ j.conflicts)
    (hr : ∀ id q, findPayment i.payments id = some q → q.status = .REVERSED →
      findPayment j.payments id = some q)
    {x : EvidenceRecord} (h : accLam i x = true) : accLam j x = true := by
  unfold accLam at h ⊢
  by_cases h1 : x.kind = "PAYMENT_CONFIRMATION"
  · simp only [h1, ↓reduceIte] at h ⊢; exact accConf_mono hp hc h
  by_cases h2 : x.kind = "PAYMENT_REVERSAL"
  · simp only [h2, ↓reduceIte] at h ⊢; exact accRev_mono hr h
  by_cases h3 : x.kind = "OFFSET_CLAIM"
  · simp only [h3, ↓reduceIte] at h ⊢; rw [hcl]; exact h
  · simp only [h1, h2, h3, ↓reduceIte] at h ⊢

private theorem known_of_find {E : List EvidenceRecord} {id e} (h : findEvidence E id = some e) :
    (E.map EvidenceRecord.evidenceId).contains id = true :=
  List.contains_iff_mem.2 (List.mem_map.2 ⟨e, findEvidence_mem h, findEvidence_id h⟩)

private theorem find_of_known {E : List EvidenceRecord} {id}
    (h : (E.map EvidenceRecord.evidenceId).contains id = true) : ∃ e, findEvidence E id = some e := by
  cases hf : findEvidence E id with
  | some e => exact ⟨e, rfl⟩
  | none =>
    obtain ⟨e, he, rfl⟩ := List.mem_map.1 (List.contains_iff_mem.1 h)
    exact absurd rfl (findEvidence_none_ne hf e he)

private theorem wf_grow {i : FinancialInput} (hi : financialInputWellFormed i = true)
    {P : List Payment} {E : List EvidenceRecord} {C : List FinancialConflict}
    (hE : ∀ id ev, findEvidence i.evidence id = some ev → findEvidence E id = some ev)
    (hPf : ∀ id q, findPayment i.payments id = some q → ∃ q', findPayment P id = some q' ∧
      q'.commonOriginId = q.commonOriginId ∧ q'.amountCents = q.amountCents ∧ q'.evidenceId = q.evidenceId)
    (hPr : ∀ id q, findPayment i.payments id = some q → q.status = .REVERSED → findPayment P id = some q)
    (hCm : ∀ x ∈ i.conflicts, x ∈ C)
    (n20 : E.length ≤ maxRows) (n21 : C.length ≤ maxRows)
    (n25 : P.length ≤ maxRows → canonicalIdList (P.map Payment.paymentId) = true)
    (n28 : canonicalIdList (E.map EvidenceRecord.evidenceId) = true)
    (n29 : canonicalIdList (C.map FinancialConflict.conflictId) = true)
    (n55 : noDuplicates (P.map Payment.commonOriginId) = true)
    (hPnew : ∀ q ∈ P, q ∉ i.payments → paymentWellFormed i.context q = true ∧
      paymentEvidenceWellFormed (upd i P E C) q = true ∧ reversalEvidenceWellFormed (upd i P E C) q = true)
    (hEnew : ∀ x ∈ E, x ∉ i.evidence → evidenceWellFormed i.context x = true ∧
      x.receivedAt ≤ i.evaluatedAt ∧ accLam (upd i P E C) x = true)
    (hCnew : ∀ x ∈ C, x ∉ i.conflicts → conflictWellFormed (upd i P E C) x = true) :
    financialInputWellFormed (upd i P E C) = true := by
  have hi' := hi
  simp only [financialInputWellFormed, Bool.and_assoc, Bool.and_eq_true, decide_eq_true_eq] at hi'
  obtain ⟨h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11,h12,h13,h14,h15,h16,h17,h18,h19,h20,h21,h22,h23,h24,h25,h26,h27,h28,h29,h30,h31,h32,h33,h34,h35,h36,h37,h38,h39,h40,h41,h42,h43,h44,h45,h46,h47,h48,h49,h50,h51,h52,h53,h54,h55⟩ := hi'
  have hp : ∀ q ∈ i.payments, ∃ q' ∈ P, q'.evidenceId = q.evidenceId ∧
      q'.commonOriginId = q.commonOriginId ∧ q'.amountCents = q.amountCents := by
    intro q hq
    have hnd := nodup_ids_of_wf hi
    obtain ⟨q', hq', ho, ha, he⟩ := hPf q.paymentId q (findPayment_of_mem hnd hq)
    exact ⟨q', findPayment_mem hq', he, ho, ha⟩
  have hfp : ∀ id q, findPayment i.payments id = some q → ∃ q', findPayment (upd i P E C).payments id = some q' ∧
      q'.commonOriginId = q.commonOriginId ∧ q'.amountCents = q.amountCents := fun id q h =>
    let ⟨q', a, b, c, _⟩ := hPf id q h; ⟨q', a, b, c⟩
  have n39' : P.all (paymentEvidenceWellFormed (upd i P E C)) = true := by
    rw [List.all_eq_true] at h39 ⊢
    intro q hq
    by_cases hm : q ∈ i.payments
    · exact pew_mono (i := i) (j := upd i P E C) hE (h39 q hm)
    · exact (hPnew q hq hm).2.1
  have n40' : P.all (reversalEvidenceWellFormed (upd i P E C)) = true := by
    rw [List.all_eq_true] at h40 ⊢
    intro q hq
    by_cases hm : q ∈ i.payments
    · exact rew_mono (i := i) (j := upd i P E C) hE (h40 q hm)
    · exact (hPnew q hq hm).2.2
  have n41' : i.claims.all (claimEvidenceWellFormed (upd i P E C)) = true := by
    rw [List.all_eq_true] at h41 ⊢
    exact fun q hq => cew_mono (i := i) (j := upd i P E C) hE (h41 q hq)
  have n51' : allReferencesExist (E.map EvidenceRecord.evidenceId) (P.map Payment.evidenceId) = true := by
    unfold allReferencesExist
    rw [List.all_eq_true]
    intro id hid
    obtain ⟨q, hq, rfl⟩ := List.mem_map.1 hid
    have := List.all_eq_true.1 n39' q hq
    unfold paymentEvidenceWellFormed at this
    cases hf : findEvidence E q.evidenceId with
    | none => simp [upd, hf] at this
    | some e => exact known_of_find hf
  have n17 : P.length ≤ maxRows := Nat.le_trans (payments_le_evidence (post := upd i P E C) n39' n51' n55) n20
  refine wf_of_parts hi n17 n20 n21 (n25 n17) n28 n29 ?_ ?_ ?_ n39' n40' n41' ?_ ?_ n51' ?_ ?_ ?_ n55
  · rw [List.all_eq_true] at h32 ⊢
    intro q hq
    by_cases hm : q ∈ i.payments
    · exact h32 q hm
    · exact (hPnew q hq hm).1
  · rw [List.all_eq_true] at h34 ⊢
    intro x hx
    by_cases hm : x ∈ i.evidence
    · exact h34 x hm
    · exact (hEnew x hx hm).1
  · rw [List.all_eq_true] at h36 ⊢
    intro x hx
    by_cases hm : x ∈ i.conflicts
    · exact confl_mono (i := i) (j := upd i P E C) rfl hE hfp (h36 x hm)
    · exact hCnew x hx hm
  · rw [List.all_eq_true] at h48 ⊢
    intro x hx
    by_cases hm : x ∈ i.evidence
    · exact accLam_mono (i := i) (j := upd i P E C) rfl hp hCm hPr (h48 x hm)
    · exact (hEnew x hx hm).2.2
  · rw [List.all_eq_true] at h49 ⊢
    intro x hx
    by_cases hm : x ∈ i.evidence
    · exact h49 x hm
    · exact decide_eq_true (hEnew x hx hm).2.1
  · -- n52
    unfold allReferencesExist
    rw [List.all_eq_true]
    intro id hid
    obtain ⟨q, hq, hr⟩ := List.mem_filterMap.1 hid
    have := List.all_eq_true.1 n40' q hq
    unfold reversalEvidenceWellFormed at this
    rcases hs : q.status with _ | _ <;> rw [hs, hr] at this
    · simp at this
    · cases hf : findEvidence E id with
      | none => simp [upd, hf] at this
      | some e => exact known_of_find hf
  · -- n53
    unfold allReferencesExist
    rw [List.all_eq_true]
    intro id hid
    obtain ⟨q, hq, rfl⟩ := List.mem_map.1 hid
    have := List.all_eq_true.1 n41' q hq
    unfold claimEvidenceWellFormed at this
    cases hf : findEvidence E q.evidenceId with
    | none => simp [upd, hf] at this
    | some e => exact known_of_find hf
  · -- n54
    rw [List.all_eq_true] at h54 ⊢
    intro d hd
    have := h54 d hd
    unfold allReferencesExist at this ⊢
    rw [List.all_eq_true] at this ⊢
    intro id hid
    obtain ⟨e, he⟩ := find_of_known (this id hid)
    exact known_of_find (hE _ _ he)

/-! ## The fixed strings the row builders write are well formed -/

private theorem utf8_list (s : String) : s.toUTF8.toList = s.toList.flatMap String.utf8EncodeChar := by
  rw [byteArray_toList_eq, String.toUTF8_eq_toByteArray, ← String.utf8Encode_toList]
  unfold List.utf8Encode
  rw [List.toList_data_toByteArray]

private theorem tok_conf : tokenWellFormed "PAYMENT_CONFIRMATION" = true := by
  unfold tokenWellFormed; rw [utf8_list]; decide
private theorem tok_rev : tokenWellFormed "PAYMENT_REVERSAL" = true := by
  unfold tokenWellFormed; rw [utf8_list]; decide
private theorem id_src : idWellFormed "synthetic-payment-source" = true := by
  unfold idWellFormed; rw [utf8_list]; decide
private theorem id_ver : idWellFormed "fixture-v1" = true := by
  unfold idWellFormed; rw [utf8_list]; decide
private theorem id_reason : idWellFormed "CONFLICTING_COMMON_ORIGIN_AMOUNT" = true := by
  unfold idWellFormed; rw [utf8_list]; decide

private theorem maxTime_eq : maxTime = 2 ^ 63 - 1 := rfl

/-! ## What a well-formed command and a refusal-free row give -/

private theorem cmd_record {c : RecordCommand} (h : commandWellFormed (.record c) = true) :
    idWellFormed c.paymentId = true ∧ idWellFormed c.evidenceId = true ∧
      idWellFormed c.commonOriginId = true ∧ idWellFormed c.sourceId = true ∧
      idWellFormed c.sourceVersion = true ∧ c.amountCents ≤ maxCents ∧ c.eventAt ≤ maxTime := by
  have := maxTime_eq
  simp only [commandWellFormed, Bool.and_eq_true, decide_eq_true_eq, List.all_cons, List.all_nil,
    Bool.and_true] at h
  obtain ⟨⟨⟨⟨⟨h1, h2, h3, h4, h5⟩, -⟩, -⟩, h6⟩, h7⟩ := h
  exact ⟨h1, h2, h3, h4, h5, h6, by omega⟩

private theorem cmd_reverse {c : ReverseCommand} (h : commandWellFormed (.reverse c) = true) :
    idWellFormed c.paymentId = true ∧ idWellFormed c.evidenceId = true := by
  simp only [commandWellFormed, Bool.and_eq_true] at h
  exact ⟨h.1.1.1, h.1.1.2⟩

private theorem form_ids {e : EvidenceRecord} (h : formRefusal e = none) :
    idWellFormed e.commonOriginId = true ∧ idWellFormed e.localRef = true := by
  unfold formRefusal at h
  by_cases h1 : idWellFormed e.commonOriginId = true
  · by_cases h2 : idWellFormed e.localRef = true
    · exact ⟨h1, h2⟩
    · simp [h1, h2] at h
  · simp [h1] at h

private theorem confirmation_wf {i : FinancialInput}
    (hctx : idWellFormed i.context.obligationId = true ∧ idWellFormed i.context.itemId = true)
    {c : RecordCommand} (hc : commandWellFormed (.record c) = true) {t : Nat}
    (hform : formRefusal (confirmation i c t) = none) (hle : c.eventAt ≤ t) (ht : t ≤ maxTime) :
    evidenceWellFormed i.context (confirmation i c t) = true := by
  obtain ⟨h1, h2, h3, h4, h5, h6, h7⟩ := cmd_record hc
  obtain ⟨hf1, hf2⟩ := form_ids hform
  simp only [confirmation] at hf1 hf2
  simp [evidenceWellFormed, confirmation, timeWellFormed, amountWellFormed, optionalIdWellFormed,
    kindWellFormed, tok_conf, h2, h3, h4, h5, h6, h7, hf2, hctx.1, hctx.2, hle, ht]

private theorem reversalRecord_wf {i : FinancialInput}
    (hctx : idWellFormed i.context.obligationId = true ∧ idWellFormed i.context.itemId = true)
    (hnow : i.evaluatedAt ≤ maxTime) {c : ReverseCommand} (hc : commandWellFormed (.reverse c) = true)
    {p : Payment} (hp : paymentWellFormed i.context p = true) {time : Nat}
    (hform : formRefusal (reversalRecord i c p time) = none) (hle : time ≤ i.evaluatedAt) :
    evidenceWellFormed i.context (reversalRecord i c p time) = true := by
  obtain ⟨h1, h2⟩ := cmd_reverse hc
  obtain ⟨hf1, hf2⟩ := form_ids hform
  have ht : time ≤ maxTime := by omega
  simp only [reversalRecord] at hf1 hf2
  simp only [paymentWellFormed, Bool.and_eq_true, decide_eq_true_eq, List.all_cons, List.all_nil,
    Bool.and_true, positiveAmountWellFormed, amountWellFormed] at hp
  obtain ⟨⟨⟨⟨⟨⟨hp1, -, -, -, -⟩, -⟩, -⟩, ⟨-, hpa⟩⟩, -⟩, -⟩ := hp
  simp [evidenceWellFormed, reversalRecord, timeWellFormed, amountWellFormed, optionalIdWellFormed,
    kindWellFormed, tok_rev, id_src, id_ver, h2, hf1, hf2, hctx.1, hctx.2, hle, hnow, hp1, hpa, ht]

private theorem recordedPayment_wf {i : FinancialInput}
    (hctx : idWellFormed i.context.obligationId = true ∧ idWellFormed i.context.itemId = true)
    {c : RecordCommand} (hc : commandWellFormed (.record c) = true) (h0 : c.amountCents ≠ 0) :
    paymentWellFormed i.context (recordedPayment i c) = true := by
  obtain ⟨h1, h2, h3, h4, h5, h6, h7⟩ := cmd_record hc
  simp [paymentWellFormed, recordedPayment, timeWellFormed, positiveAmountWellFormed, amountWellFormed,
    optionalIdWellFormed, h1, h2, h3, h6, h7, hctx.1, hctx.2]
  omega

private theorem reversedImage_wf {i : FinancialInput} {p : Payment} (hp : paymentWellFormed i.context p = true)
    {c : ReverseCommand} (hc : commandWellFormed (.reverse c) = true) :
    paymentWellFormed i.context (reversedImage p c) = true := by
  obtain ⟨-, h2⟩ := cmd_reverse hc
  unfold paymentWellFormed at hp ⊢
  rw [Bool.and_eq_true] at hp ⊢
  exact ⟨hp.1, h2⟩

/-! ## Facts read off a well-formed input -/

private theorem wf_facts {i : FinancialInput} (h : financialInputWellFormed i = true) :
    i.payments.length ≤ maxRows ∧ i.evidence.length ≤ maxRows ∧ i.conflicts.length ≤ maxRows ∧
    (∀ q ∈ i.payments, paymentWellFormed i.context q = true) ∧
    (∀ q ∈ i.payments, paymentEvidenceWellFormed i q = true) ∧
    (∀ q ∈ i.payments, reversalEvidenceWellFormed i q = true) ∧
    noDuplicates (i.payments.map Payment.commonOriginId) = true ∧ i.cases ≠ [] := by
  simp only [financialInputWellFormed, Bool.and_assoc, Bool.and_eq_true, decide_eq_true_eq] at h
  obtain ⟨h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11,h12,h13,h14,h15,h16,h17,h18,h19,h20,h21,h22,h23,h24,h25,h26,h27,h28,h29,h30,h31,h32,h33,h34,h35,h36,h37,h38,h39,h40,h41,h42,h43,h44,h45,h46,h47,h48,h49,h50,h51,h52,h53,h54,h55⟩ := h
  refine ⟨h17, h20, h21, List.all_eq_true.1 h32, List.all_eq_true.1 h39, List.all_eq_true.1 h40, h55, ?_⟩
  intro e
  rw [e] at h22
  exact absurd h22 (by simp)

/-! ## Paid totals under insert and replace (the `step_bridge` sums, on bare lists) -/

private theorem paid_eq (i0 : FinancialInput) {P : List Payment} {R : List Receipt}
    (hn : (P.map Payment.paymentId).Nodup) (hR : R.map Receipt.paymentId = P.map Payment.paymentId)
    (a : String) : linkedActivePaidCents P (linksOf R) a = (P.map (paidOn R a)).sum :=
  ledgerPaid_eq (L := ⟨{ i0 with payments := P }, R⟩) ⟨hn, hR⟩ a

private theorem ids_insert {x : Payment} {P : List Payment} :
    (insertBy Payment.paymentId x P).map Payment.paymentId = insertBy (fun s => s) x.paymentId (P.map Payment.paymentId) :=
  map_insertBy Payment.paymentId Payment.paymentId (fun s => s) (fun _ => rfl) x P

private theorem ids_insert_nodup {x : Payment} {P : List Payment} (hn : (P.map Payment.paymentId).Nodup)
    (hf : findPayment P x.paymentId = none) :
    ((insertBy Payment.paymentId x P).map Payment.paymentId).Nodup := by
  have hp := (insertBy_perm Payment.paymentId x P).map Payment.paymentId
  rw [hp.nodup_iff, List.map_cons, List.nodup_cons]
  exact ⟨fun h => let ⟨q, hq, e⟩ := List.mem_map.1 h; findPayment_none_ne hf q hq e, hn⟩

private theorem paid_insert (i0 : FinancialInput) {P : List Payment} {R : List Receipt}
    (hn : (P.map Payment.paymentId).Nodup) (hR : R.map Receipt.paymentId = P.map Payment.paymentId)
    {x : Payment} {K : Receipt} (hx : x.status = .ACTIVE) (hid : K.paymentId = x.paymentId)
    (hf : findPayment P x.paymentId = none) (a : String) :
    linkedActivePaidCents (insertBy Payment.paymentId x P) (linksOf (insertBy Receipt.paymentId K R)) a =
      linkedActivePaidCents P (linksOf R) a + (if K.paysActionId = some a then x.amountCents else 0) := by
  have hrn : receiptOf R K.paymentId = none := by
    rw [hid]; exact receiptOf_none (L := ⟨{ i0 with payments := P }, R⟩) ⟨hn, hR⟩ hf
  have hR' : (insertBy Receipt.paymentId K R).map Receipt.paymentId =
      (insertBy Payment.paymentId x P).map Payment.paymentId := by
    rw [ids_insert, map_insertBy Receipt.paymentId Receipt.paymentId (fun s => s) (fun _ => rfl) K R, hR, hid]
  rw [paid_eq i0 (ids_insert_nodup hn hf) hR', paid_eq i0 hn hR, sum_insertBy]
  have hne : ∀ q ∈ P, q.paymentId ≠ x.paymentId := findPayment_none_ne hf
  have hcongr : P.map (paidOn (insertBy Receipt.paymentId K R) a) = P.map (paidOn R a) :=
    List.map_congr_left fun q hq => by
      simp only [paidOn, receiptOf_insertBy hrn, if_neg (fun e : K.paymentId = q.paymentId =>
        hne q hq (e.symm.trans hid))]
  have hP : paidOn (insertBy Receipt.paymentId K R) a x = if K.paysActionId = some a then x.amountCents else 0 := by
    simp only [paidOn, receiptOf_insertBy hrn, hid, if_true, hx]
    by_cases h : K.paysActionId = some a <;> simp [h]
  rw [hcongr, hP]; omega

private theorem paid_replace (i0 : FinancialInput) {P : List Payment} {R : List Receipt}
    (hn : (P.map Payment.paymentId).Nodup) (hR : R.map Receipt.paymentId = P.map Payment.paymentId)
    {q p0 : Payment} (hq : findPayment P p0.paymentId = some q) (hact : q.status = .ACTIVE)
    (hp0 : p0.status ≠ .ACTIVE) {k : Receipt} (hk : receiptOf R q.paymentId = some k) (a : String) :
    linkedActivePaidCents (P.map fun x => if x.paymentId = p0.paymentId then p0 else x) (linksOf R) a +
      (if k.paysActionId = some a then q.amountCents else 0) = linkedActivePaidCents P (linksOf R) a := by
  have hids : (P.map fun x => if x.paymentId = p0.paymentId then p0 else x).map Payment.paymentId =
      P.map Payment.paymentId := by
    rw [List.map_map]
    refine List.map_congr_left fun x _ => ?_
    simp only [Function.comp]
    by_cases h : x.paymentId = p0.paymentId <;> simp [h]
  rw [paid_eq i0 (hids ▸ hn) (hR.trans hids.symm), paid_eq i0 hn hR]
  have hs := sum_replace (paidOn R a) p0 P q hn hq
  have e1 : paidOn R a q = if k.paysActionId = some a then q.amountCents else 0 := by
    simp [paidOn, hk, hact]
  have e2 : paidOn R a p0 = 0 := by simp [paidOn, hp0]
  rw [e1, e2] at hs
  omega

/-! ## The summary of a grown input -/

private theorem cash_eq {i : FinancialInput} {rs b S} (h : summarize i rs b = some S) :
    S.cash = activeCents i.payments := by
  obtain ⟨t, ht, rfl⟩ := summarize_some h
  have := evaluateTotals_payments ht i.payments
  have e : ({ i with payments := i.payments } : FinancialInput) = i := rfl
  rw [e, ht] at this
  by_cases hc : activeCents i.payments + t.lawful ≤ maxCents
  · rw [if_pos hc] at this
    simp only [Option.some.injEq] at this
    have := congrArg EvaluatedTotals.cash this
    exact this
  · rw [if_neg hc] at this; cases this

private theorem summarize_upd {i : FinancialInput} {rs b0 S} (hS : summarize i rs b0 = some S)
    (P : List Payment) (E : List EvidenceRecord) (C : List FinancialConflict) (rs' : List Receipt) (b : Nat) :
    summarize (upd i P E C) rs' b =
      if activeCents P + S.lawful ≤ maxCents then
        some { S with
          cash := activeCents P,
          contributions := evalSortContributions (pcOf P ++ dcOf i.determinations),
          conflictCount := C.length, evidenceIds := E.map EvidenceRecord.evidenceId,
          requests := ((i.actions.filter (·.kind = "CORRECTION_PAYMENT_REQUEST")).map fun a =>
            ⟨a.actionId, a.amountCents, linkedActivePaidCents P (linksOf rs') a.actionId⟩),
          anchorBytes := b }
      else none := by
  obtain ⟨t, ht, rfl⟩ := summarize_some hS
  have e : evaluateTotals (upd i P E C) = evaluateTotals { i with payments := P } := rfl
  unfold summarize
  rw [e, evaluateTotals_payments ht P]
  by_cases hc : activeCents P + t.lawful ≤ maxCents
  · rw [if_pos hc, if_pos hc]; rfl
  · rw [if_neg hc, if_neg hc]; rfl

private theorem activeCents_insert {x : Payment} (hx : x.status = .ACTIVE) (P : List Payment) :
    activeCents (insertBy Payment.paymentId x P) = x.amountCents + activeCents P := by
  rw [activeCents_eq, activeCents_eq, sum_insertBy, if_pos hx]

private theorem activeCents_replace {P : List Payment} {q p0 : Payment} (hn : (P.map Payment.paymentId).Nodup)
    (hq : findPayment P p0.paymentId = some q) (hact : q.status = .ACTIVE) (hp0 : p0.status ≠ .ACTIVE) :
    activeCents (P.map fun x => if x.paymentId = p0.paymentId then p0 else x) + q.amountCents =
      activeCents P := by
  have := sum_replace (fun x : Payment => if x.status = .ACTIVE then x.amountCents else 0) p0 P q hn hq
  rw [activeCents_eq, activeCents_eq]
  simp only [if_pos hact, if_neg hp0] at this
  omega

/-! ## Facts read off a summary -/

private theorem S_facts {i : FinancialInput} {rs b S} (h : summarize i rs b = some S) :
    S.evidenceIds = i.evidence.map EvidenceRecord.evidenceId ∧ S.conflictCount = i.conflicts.length ∧
    S.cash = activeCents i.payments ∧ S.cash + S.lawful ≤ maxCents ∧
    S.contributions = evalSortContributions (pcOf i.payments ++ dcOf i.determinations) ∧
    S.requests = (i.actions.filter (·.kind = "CORRECTION_PAYMENT_REQUEST")).map (fun a =>
      (⟨a.actionId, a.amountCents, linkedActivePaidCents i.payments (linksOf rs) a.actionId⟩ : RequestPaid)) ∧
    S.anchorBytes = b := by
  have hc := cash_eq h
  obtain ⟨t, ht, rfl⟩ := summarize_some h
  have := evaluateTotals_payments ht i.payments
  have e : ({ i with payments := i.payments } : FinancialInput) = i := rfl
  rw [e, ht] at this
  refine ⟨rfl, rfl, hc, ?_, rfl, rfl, rfl⟩
  by_cases hq : activeCents i.payments + t.lawful ≤ maxCents
  · rw [hc]; exact hq
  · rw [if_neg hq] at this; cases this

/-! ## The evidence write of a record: a fresh confirmation, or a stored retry of it -/

private def EvCase (i : FinancialInput) (c : RecordCommand) (ev : Option EvidenceRecord) : Prop :=
  (ev = some (confirmation i c i.evaluatedAt) ∧ findEvidence i.evidence c.evidenceId = none ∧
    formRefusal (confirmation i c i.evaluatedAt) = none ∧ c.eventAt ≤ i.evaluatedAt) ∨
  (ev = none ∧ ∃ t, findEvidence i.evidence c.evidenceId = some (confirmation i c t))

private theorem evCase_of {r : PaymentRequest} {c ev} (h : EvidenceWrite r c ev) : EvCase r.input c ev := by
  obtain ⟨hf, hle, -, h | h⟩ := h
  · exact Or.inl ⟨h.1, h.2, hf, hle⟩
  · obtain ⟨hn, s, hs, -, hc⟩ := h
    exact Or.inr ⟨hn, s.receivedAt, by rw [hc]; exact hs⟩

private def evOf (i : FinancialInput) (ev : Option EvidenceRecord) : List EvidenceRecord :=
  (ev.map fun e => insertBy EvidenceRecord.evidenceId e i.evidence).getD i.evidence

private theorem evOf_ids (i : FinancialInput) (ev : Option EvidenceRecord) :
    (evOf i ev).map EvidenceRecord.evidenceId =
      (ev.map fun e => insertBy (fun x => x) e.evidenceId (i.evidence.map EvidenceRecord.evidenceId)).getD
        (i.evidence.map EvidenceRecord.evidenceId) := by
  cases ev with
  | none => rfl
  | some e =>
    simp only [evOf, Option.map_some, Option.getD_some]
    exact map_insertBy EvidenceRecord.evidenceId EvidenceRecord.evidenceId (fun s => s) (fun _ => rfl) e _

private theorem evOf_length (i : FinancialInput) (ev : Option EvidenceRecord) :
    (evOf i ev).length = i.evidence.length + (if ev.isSome then 1 else 0) := by
  cases ev with
  | none => rfl
  | some e => simp [evOf, length_insertBy]

private theorem wf_canon {i : FinancialInput} (h : financialInputWellFormed i = true) :
    canonicalIdList (i.payments.map Payment.paymentId) = true ∧
    canonicalIdList (i.evidence.map EvidenceRecord.evidenceId) = true ∧
    canonicalIdList (i.conflicts.map FinancialConflict.conflictId) = true := by
  simp only [financialInputWellFormed, Bool.and_assoc, Bool.and_eq_true, decide_eq_true_eq] at h
  obtain ⟨h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11,h12,h13,h14,h15,h16,h17,h18,h19,h20,h21,h22,h23,h24,h25,h26,h27,h28,h29,h30,h31,h32,h33,h34,h35,h36,h37,h38,h39,h40,h41,h42,h43,h44,h45,h46,h47,h48,h49,h50,h51,h52,h53,h54,h55⟩ := h
  exact ⟨h25, h28, h29⟩

private theorem ev_facts {i : FinancialInput} (hwf : financialInputWellFormed i = true) {c : RecordCommand}
    (hc : commandWellFormed (.record c) = true) {ev} (hev : EvCase i c ev) :
    (∀ id x, findEvidence i.evidence id = some x → findEvidence (evOf i ev) id = some x) ∧
    (∃ t, findEvidence (evOf i ev) c.evidenceId = some (confirmation i c t)) ∧
    (∀ x ∈ evOf i ev, x ∉ i.evidence → evidenceWellFormed i.context x = true ∧
      x.receivedAt ≤ i.evaluatedAt ∧ x.evidenceId = c.evidenceId ∧ x.kind = "PAYMENT_CONFIRMATION" ∧
      x.commonOriginId = c.commonOriginId ∧ x.amountCents = some c.amountCents) ∧
    (ev.isSome = true → (evOf i ev).length ≤ maxRows →
      canonicalIdList ((evOf i ev).map EvidenceRecord.evidenceId) = true) := by
  obtain ⟨hid1, hid2, hnow⟩ := wf_ctx hwf
  rcases hev with ⟨rfl, hf, hform, hle⟩ | ⟨rfl, t, ht⟩
  · have hf' : findEvidence i.evidence (confirmation i c i.evaluatedAt).evidenceId = none := hf
    have hfi : ∀ id, findEvidence (evOf i (some (confirmation i c i.evaluatedAt))) id =
        if c.evidenceId = id then some (confirmation i c i.evaluatedAt) else findEvidence i.evidence id :=
      fun id => findEvidence_insertBy hf'
    refine ⟨fun id x h => ?_, ⟨i.evaluatedAt, by rw [hfi]; simp⟩, fun x hx hn => ?_, fun _ hl => ?_⟩
    · rw [hfi]
      by_cases e : c.evidenceId = id
      · subst e; rw [hf] at h; cases h
      · rw [if_neg e]; exact h
    · have hx' : x ∈ insertBy EvidenceRecord.evidenceId (confirmation i c i.evaluatedAt) i.evidence := hx
      rcases (mem_insertBy _ _ x _).1 hx' with rfl | h
      · exact ⟨confirmation_wf ⟨hid1, hid2⟩ hc hform hle hnow, Nat.le_refl _, rfl, rfl, rfl, rfl⟩
      · exact absurd h hn
    · rw [evOf_ids]
      simp only [Option.map_some, Option.getD_some]
      refine canonical_insert (wf_canon hwf).2.1 (cmd_record hc).2.1 ?_ ?_
      · intro hm
        obtain ⟨x, hx⟩ := find_of_known (List.contains_iff_mem.2 hm)
        rw [hf'] at hx; cases hx
      · have := evOf_length i (some (confirmation i c i.evaluatedAt))
        simp only [Option.isSome_some, if_true] at this
        rw [List.length_map]; omega
  · exact ⟨fun id x h => h, ⟨t, ht⟩, fun x hx hn => absurd hx hn, fun h => by simp at h⟩

/-! ## `advance` on the three write shapes -/

private theorem adv_rec (V : PaymentView) (S : ItemState) (ev : Option EvidenceRecord) (p : Payment) (k : Receipt) :
    advance V S ⟨ev, some p, none, some k⟩ =
      if ((ev.map fun e => insertBy (fun x => x) e.evidenceId S.evidenceIds).getD S.evidenceIds).length > maxRows ||
          S.conflictCount > maxRows then none else
      if S.cash + p.amountCents + S.lawful > maxCents then none else
      some { S with
        evidenceIds := (ev.map fun e => insertBy (fun x => x) e.evidenceId S.evidenceIds).getD S.evidenceIds,
        anchorBytes := S.anchorBytes + anchorGrowth V ⟨ev, some p, none, some k⟩,
        cash := S.cash + p.amountCents,
        contributions := evalInsertContribution ⟨p.eventAt, p.paymentId, p.amountCents⟩ S.contributions,
        requests := S.requests.map fun q =>
          if k.paysActionId = some q.actionId then { q with paidCents := q.paidCents + p.amountCents } else q } := by
  unfold advance
  rfl

private theorem evOf_canon {i : FinancialInput} {ev : Option EvidenceRecord}
    (hcE : canonicalIdList (i.evidence.map EvidenceRecord.evidenceId) = true)
    (hEcan : ev.isSome = true → (evOf i ev).length ≤ maxRows →
      canonicalIdList ((evOf i ev).map EvidenceRecord.evidenceId) = true)
    (hl : (evOf i ev).length ≤ maxRows) :
    canonicalIdList ((evOf i ev).map EvidenceRecord.evidenceId) = true := by
  by_cases hs : ev.isSome = true
  · exact hEcan hs hl
  · have : ev = none := by cases ev with | none => rfl | some _ => exact absurd rfl hs
    subst this
    exact hcE

private theorem shape_recorded {r : PaymentRequest} {V : PaymentView} {S : ItemState}
    (hwf : financialInputWellFormed r.input = true)
    (hrec : r.receipts.map Receipt.paymentId = r.input.payments.map Payment.paymentId)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hS : summarize r.input r.receipts (anchorItemLength r.input r.receipts) = some S)
    (hVenv : V.env = envOf r.input) (hbyId : V.byId = none)
    {c : RecordCommand} (hc : commandWellFormed (.record c) = true) (h0 : c.amountCents ≠ 0)
    (hpid : findPayment r.input.payments c.paymentId = none)
    (hno : ∀ q ∈ r.input.payments, q.commonOriginId ≠ c.commonOriginId)
    {ev : Option EvidenceRecord} (hev : EvCase r.input c ev) :
    some (commitView V S .RECORDED ⟨ev, some (recordedPayment r.input c), none, some (recordedReceipt r.input c)⟩) =
      project r (mutate r .RECORDED ⟨ev, some (recordedPayment r.input c), none, some (recordedReceipt r.input c)⟩) := by
  obtain ⟨hSe, hSc, hScash, hSle, hSctr, hSreq, hSab⟩ := S_facts hS
  obtain ⟨hE, ⟨t, hEt⟩, hEnew, hEcan⟩ := ev_facts hwf hc hev
  obtain ⟨hP1, hE1, hC1, hPwf, hPew, hPrew, hNo, hcases⟩ := wf_facts hwf
  obtain ⟨hcP, hcE, hcC⟩ := wf_canon hwf
  obtain ⟨hid1, hid2, hnow⟩ := wf_ctx hwf
  have hnd := nodup_ids_of_wf hwf
  obtain ⟨hcid, -⟩ := cmd_record hc
  have hpost : applyWrites r.input ⟨ev, some (recordedPayment r.input c), none, some (recordedReceipt r.input c)⟩ =
      upd r.input (insertBy Payment.paymentId (recordedPayment r.input c) r.input.payments)
        (evOf r.input ev) r.input.conflicts := by
    unfold applyWrites upd evOf
    simp [recordedPayment, hpid]
  have hxact : (recordedPayment r.input c).status = .ACTIVE := rfl
  have hwfpost : (evOf r.input ev).length ≤ maxRows →
      financialInputWellFormed (upd r.input (insertBy Payment.paymentId (recordedPayment r.input c) r.input.payments)
        (evOf r.input ev) r.input.conflicts) = true := fun hl => by
    refine wf_grow hwf hE (fun id q h => ⟨q, ?_, rfl, rfl, rfl⟩) (fun id q h _ => ?_) (fun x hx => hx) hl hC1
      (fun hlen => ?_) ?_ hcC ?_ ?_ ?_ (fun q hq hn => absurd hq hn)
    · rw [findPayment_insertBy hpid]
      by_cases e : (recordedPayment r.input c).paymentId = id
      · exact absurd (e ▸ h) (by simp [recordedPayment, hpid])
      · rw [if_neg e]; exact h
    · rw [findPayment_insertBy hpid]
      by_cases e : (recordedPayment r.input c).paymentId = id
      · exact absurd (e ▸ h) (by simp [recordedPayment, hpid])
      · rw [if_neg e]; exact h
    · rw [ids_insert]
      refine canonical_insert hcP hcid ?_ ?_
      · intro hm
        obtain ⟨q, hq, e⟩ := List.mem_map.1 hm
        exact findPayment_none_ne hpid q hq e
      · rw [List.length_map]; rw [length_insertBy] at hlen; omega
    · exact evOf_canon hcE hEcan hl
    · rw [noDup_iff]
      refine ((insertBy_perm Payment.paymentId (recordedPayment r.input c) r.input.payments).map
        Payment.commonOriginId).nodup_iff.2 (List.nodup_cons.2 ⟨?_, (noDup_iff _).1 hNo⟩)
      intro hm
      obtain ⟨q, hq, e⟩ := List.mem_map.1 hm
      exact hno q hq e
    · intro q hq hn
      rcases (mem_insertBy _ _ q _).1 hq with rfl | h
      · refine ⟨recordedPayment_wf ⟨hid1, hid2⟩ hc h0, ?_, rfl⟩
        have hfe : findEvidence (evOf r.input ev) (recordedPayment r.input c).evidenceId =
            some (confirmation r.input c t) := hEt
        unfold paymentEvidenceWellFormed
        simp only [upd]
        rw [hfe]
        simp [confirmation, recordedPayment]
      · exact absurd h hn
    · intro x hx hn
      obtain ⟨a, b, d, e, -, -⟩ := hEnew x hx hn
      refine ⟨a, b, ?_⟩
      have hany : (upd r.input (insertBy Payment.paymentId (recordedPayment r.input c) r.input.payments)
          (evOf r.input ev) r.input.conflicts).payments.any (fun q => decide (q.evidenceId = x.evidenceId)) = true :=
        List.any_eq_true.2 ⟨recordedPayment r.input c, (mem_insertBy _ _ _ _).2 (Or.inl rfl),
          decide_eq_true (by rw [d]; rfl)⟩
      unfold accLam
      rw [if_pos e]
      unfold paymentConfirmationAccounted
      simp [hany]
  have hold : oldPay r.input ⟨ev, some (recordedPayment r.input c), none, some (recordedReceipt r.input c)⟩ = 0 := by
    simp [oldPay, recordedPayment, hpid]
  refine commit_core hb hS hVenv ?_ ?_ hcases ?_ ?_
  · unfold anchorGrowth addedBytes
    rw [hold, hbyId]
    simp
  · have := rawEncode_applyWrites_core r.input ⟨ev, some (recordedPayment r.input c), none, some (recordedReceipt r.input c)⟩
      (fun q hq hs => by simp [recordedPayment] at hq hs; subst hq; simp [hpid] at hs)
    unfold addedBytes
    rw [hold] at this ⊢
    omega
  · intro s' h
    rw [hpost]
    refine hwfpost ?_
    rw [adv_rec] at h
    by_cases h1 : ((ev.map fun e => insertBy (fun x => x) e.evidenceId S.evidenceIds).getD S.evidenceIds).length > maxRows ||
        S.conflictCount > maxRows
    · rw [if_pos h1] at h; cases h
    · rw [hSe, ← evOf_ids] at h1
      simp only [List.length_map, Bool.or_eq_true, decide_eq_true_eq, not_or, Nat.not_lt] at h1
      exact h1.1
  · intro hw
    rw [hpost] at hw ⊢
    have hl := (wf_facts hw).2.1
    simp only [upd] at hl
    rw [summarize_upd hS, adv_rec]
    have hids : (ev.map fun e => insertBy (fun x => x) e.evidenceId S.evidenceIds).getD S.evidenceIds =
        (evOf r.input ev).map EvidenceRecord.evidenceId := by rw [evOf_ids, hSe]
    have hcash := activeCents_insert hxact r.input.payments
    have h1 : ¬ (((ev.map fun e => insertBy (fun x => x) e.evidenceId S.evidenceIds).getD S.evidenceIds).length > maxRows ||
        S.conflictCount > maxRows) := by
      rw [hids, List.length_map, hSc]
      simp only [Bool.or_eq_true, decide_eq_true_eq, not_or, Nat.not_lt]
      exact ⟨hl, hC1⟩
    rw [if_neg h1]
    by_cases h2 : S.cash + (recordedPayment r.input c).amountCents + S.lawful > maxCents
    · rw [if_pos h2, if_neg]
      rw [hcash]; omega
    · rw [if_neg h2, if_pos]
      · have hcr : commitReceipts r.receipts ⟨ev, some (recordedPayment r.input c), none,
            some (recordedReceipt r.input c)⟩ = insertBy Receipt.paymentId (recordedReceipt r.input c) r.receipts := rfl
        rw [hcr]
        cases S with
        | mk rev cash claimed lawful contr lc dl cc eids reqs ab =>
          dsimp only at hScash hSe hSc hSctr hSreq hSab hcash hids
          subst hScash hSctr hSreq hSe hSc
          simp only [Option.some.injEq, ItemState.mk.injEq, true_and, and_true]
          refine ⟨?_, ?_, ?_, ?_⟩
          · rw [hcash]; omega
          · rw [contrib_insert _ _ _ hxact]; rfl
          · exact hids
          · rw [List.map_map]
            refine List.map_congr_left fun a _ => ?_
            have := paid_insert r.input (K := recordedReceipt r.input c) hnd hrec hxact rfl hpid a.actionId
            simp only [Function.comp]
            by_cases h : (recordedReceipt r.input c).paysActionId = some a.actionId <;> simp [h, this]
      · rw [hcash]; omega

private theorem adv_cf (V : PaymentView) (S : ItemState) (ev : Option EvidenceRecord) (x : FinancialConflict) :
    advance V S ⟨ev, none, some x, none⟩ =
      if ((ev.map fun e => insertBy (fun x => x) e.evidenceId S.evidenceIds).getD S.evidenceIds).length > maxRows ||
          S.conflictCount + 1 > maxRows then none else
      some { S with
        evidenceIds := (ev.map fun e => insertBy (fun x => x) e.evidenceId S.evidenceIds).getD S.evidenceIds,
        conflictCount := S.conflictCount + 1,
        anchorBytes := S.anchorBytes + anchorGrowth V ⟨ev, none, some x, none⟩ } := by
  unfold advance
  rfl

private theorem shape_conflict {r : PaymentRequest} {V : PaymentView} {S : ItemState}
    (hwf : financialInputWellFormed r.input = true)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hS : summarize r.input r.receipts (anchorItemLength r.input r.receipts) = some S)
    (hVenv : V.env = envOf r.input)
    {c : RecordCommand} (hc : commandWellFormed (.record c) = true) (h0 : c.amountCents ≠ 0)
    {p : Payment} (hp : findPayment r.input.payments p.paymentId = some p)
    (hporig : p.commonOriginId = c.commonOriginId) (hne : p.amountCents ≠ c.amountCents)
    (hcv : r.input.conflicts.any (·.conflictId = conflictIdOf r.input c) = false)
    (hcid : idWellFormed (conflictIdOf r.input c) = true)
    {ev : Option EvidenceRecord} (hev : EvCase r.input c ev) :
    some (commitView V S .CONFLICT_RECORDED ⟨ev, none, some (conflictImage r.input c p (conflictIdOf r.input c)), none⟩) =
      project r (mutate r .CONFLICT_RECORDED ⟨ev, none, some (conflictImage r.input c p (conflictIdOf r.input c)), none⟩) := by
  obtain ⟨hSe, hSc, hScash, hSle, hSctr, hSreq, hSab⟩ := S_facts hS
  obtain ⟨hE, ⟨t, hEt⟩, hEnew, hEcan⟩ := ev_facts hwf hc hev
  obtain ⟨hP1, hE1, hC1, hPwf, hPew, hPrew, hNo, hcases⟩ := wf_facts hwf
  obtain ⟨hcP, hcE, hcC⟩ := wf_canon hwf
  obtain ⟨hid1, hid2, hnow⟩ := wf_ctx hwf
  obtain ⟨hcid1, hcid2, hcid3, hcid4, hcid5, hcamt, hceve⟩ := cmd_record hc
  have hpm := findPayment_mem hp
  have hpwf := hPwf p hpm
  have hpwf' := hpwf
  simp only [paymentWellFormed, Bool.and_eq_true, decide_eq_true_eq, List.all_cons, List.all_nil,
    Bool.and_true, positiveAmountWellFormed, amountWellFormed] at hpwf'
  obtain ⟨⟨⟨⟨⟨⟨hp1, -, -, -, -⟩, -⟩, -⟩, ⟨hppos, hpamax⟩⟩, -⟩, -⟩ := hpwf'
  let x := conflictImage r.input c p (conflictIdOf r.input c)
  have hpost : applyWrites r.input ⟨ev, none, some x, none⟩ =
      upd r.input r.input.payments (evOf r.input ev) (insertBy FinancialConflict.conflictId x r.input.conflicts) :=
    rfl
  have hnc : conflictIdOf r.input c ∉ r.input.conflicts.map FinancialConflict.conflictId := by
    intro hm
    obtain ⟨y, hy, e⟩ := List.mem_map.1 hm
    have : r.input.conflicts.any (·.conflictId = conflictIdOf r.input c) = true :=
      List.any_eq_true.2 ⟨y, hy, decide_eq_true e⟩
    rw [hcv] at this; cases this
  have hwfpost : (evOf r.input ev).length ≤ maxRows → r.input.conflicts.length + 1 ≤ maxRows →
      financialInputWellFormed (upd r.input r.input.payments (evOf r.input ev)
        (insertBy FinancialConflict.conflictId x r.input.conflicts)) = true := fun hl hcl => by
    refine wf_grow hwf hE (fun id q h => ⟨q, h, rfl, rfl, rfl⟩) (fun id q h _ => h)
      (fun y hy => (mem_insertBy _ _ _ _).2 (Or.inr hy)) hl ?_ (fun _ => hcP) ?_ ?_ hNo
      (fun q hq hn => absurd hq hn) ?_ ?_
    · rw [length_insertBy]; exact hcl
    · exact evOf_canon hcE hEcan hl
    · have : (insertBy FinancialConflict.conflictId x r.input.conflicts).map FinancialConflict.conflictId =
          insertBy (fun s => s) x.conflictId (r.input.conflicts.map FinancialConflict.conflictId) :=
        map_insertBy _ _ (fun s => s) (fun _ => rfl) x _
      rw [this]
      refine canonical_insert hcC hcid hnc ?_
      rw [List.length_map]; omega
    · intro y hy hn
      obtain ⟨a, b, d, e, -, -⟩ := hEnew y hy hn
      refine ⟨a, b, ?_⟩
      have hany : (upd r.input r.input.payments (evOf r.input ev)
          (insertBy FinancialConflict.conflictId x r.input.conflicts)).conflicts.any
          (fun z => decide (z.candidateEvidenceId = y.evidenceId)) = true :=
        List.any_eq_true.2 ⟨x, (mem_insertBy _ _ _ _).2 (Or.inl rfl), decide_eq_true (by rw [d]; rfl)⟩
      unfold accLam
      rw [if_pos e]
      unfold paymentConfirmationAccounted
      simp [hany]
    · intro y hy hn
      rcases (mem_insertBy _ _ y _).1 hy with rfl | h
      · have hr : idWellFormed "CONFLICTING_COMMON_ORIGIN_AMOUNT" = true := id_reason
        have hpa : 0 < p.amountCents := hppos
        have hca : 0 < c.amountCents := Nat.pos_of_ne_zero h0
        simp [conflictWellFormed, x, conflictImage, confirmation, upd, positiveAmountWellFormed, amountWellFormed,
          timeWellFormed, hcid, hid1, hcid3, hp1, hcid2, hr, hp, hEt, hporig, hne, hpamax, hcamt, hnow, hpa, hca]
      · exact absurd h hn
  have hold : oldPay r.input ⟨ev, none, some x, none⟩ = 0 := by simp [oldPay]
  have hnew : newPay ⟨ev, none, some x, none⟩ = 0 := by simp [newPay]
  refine commit_core hb hS hVenv ?_ ?_ hcases ?_ ?_
  · unfold anchorGrowth addedBytes
    rw [hold, hnew]
    simp
  · have := rawEncode_applyWrites_core r.input ⟨ev, none, some x, none⟩ (fun q hq => by cases hq)
    unfold addedBytes
    simp only [x] at this
    rw [hold, hnew] at this ⊢
    omega
  · intro s' h
    rw [hpost]
    rw [adv_cf] at h
    by_cases h1 : ((ev.map fun e => insertBy (fun x => x) e.evidenceId S.evidenceIds).getD S.evidenceIds).length > maxRows ||
        S.conflictCount + 1 > maxRows
    · rw [if_pos h1] at h; cases h
    · rw [hSe, ← evOf_ids] at h1
      simp only [List.length_map, Bool.or_eq_true, decide_eq_true_eq, not_or, Nat.not_lt] at h1
      rw [hSc] at h1
      exact hwfpost h1.1 h1.2
  · intro hw
    rw [hpost] at hw ⊢
    obtain ⟨-, hl, hcl, -⟩ := wf_facts hw
    simp only [upd, length_insertBy] at hl hcl
    rw [summarize_upd hS, adv_cf]
    have hids : (ev.map fun e => insertBy (fun x => x) e.evidenceId S.evidenceIds).getD S.evidenceIds =
        (evOf r.input ev).map EvidenceRecord.evidenceId := by rw [evOf_ids, hSe]
    have h1 : ¬ (((ev.map fun e => insertBy (fun x => x) e.evidenceId S.evidenceIds).getD S.evidenceIds).length > maxRows ||
        S.conflictCount + 1 > maxRows) := by
      rw [hids, List.length_map, hSc]
      simp only [Bool.or_eq_true, decide_eq_true_eq, not_or, Nat.not_lt]
      exact ⟨hl, hcl⟩
    rw [if_neg h1, if_pos (by rw [← hScash]; exact hSle)]
    cases S with
    | mk rev cash claimed lawful contr lc dl cc eids reqs ab =>
      dsimp only at hScash hSe hSc hSctr hSreq hSab hids
      subst hScash hSctr hSreq hSe hSc
      simp only [Option.some.injEq, ItemState.mk.injEq, true_and, and_true]
      exact ⟨(length_insertBy _ _ _).symm, (evOf_ids _ _).symm, rfl⟩

private theorem adv_rev (V : PaymentView) (S : ItemState) (e : EvidenceRecord) (p' q : Payment) (k : Receipt)
    (hb : V.byId = some (q, k)) :
    advance V S ⟨some e, some p', none, none⟩ =
      if (insertBy (fun x => x) e.evidenceId S.evidenceIds).length > maxRows || S.conflictCount > maxRows
      then none else
      some { S with
        evidenceIds := insertBy (fun x => x) e.evidenceId S.evidenceIds,
        anchorBytes := S.anchorBytes + anchorGrowth V ⟨some e, some p', none, none⟩,
        cash := S.cash - q.amountCents,
        contributions := S.contributions.erase ⟨q.eventAt, q.paymentId, q.amountCents⟩,
        requests := S.requests.map fun x =>
          if k.paysActionId = some x.actionId then { x with paidCents := x.paidCents - q.amountCents } else x } := by
  unfold advance
  simp only [hb]
  rfl

private theorem enc_rev {p : Payment} (c : ReverseCommand) (h : p.reversalEvidenceId = none) :
    (encodePayment (reversedImage p c)).length = (encodePayment p).length + (encodeString c.evidenceId).length := by
  simp only [encodePayment, reversedImage, h, encodeOptionString, List.length_append, List.length_cons,
    List.length_nil]
  omega

private theorem rep_map {P : List Payment} {new p : Payment} (hnd : (P.map Payment.paymentId).Nodup)
    (hp : findPayment P new.paymentId = some p) {β : Type} (f : Payment → β) (hf : f new = f p) :
    (P.map fun x => if x.paymentId = new.paymentId then new else x).map f = P.map f := by
  rw [List.map_map]
  refine List.map_congr_left fun x hx => ?_
  simp only [Function.comp]
  by_cases h : x.paymentId = new.paymentId
  · rw [if_pos h]
    have h1 := findPayment_of_mem hnd hx
    rw [h, hp] at h1
    rw [hf, ← Option.some.inj h1]
  · rw [if_neg h]

private theorem rep_eq {P : List Payment} {new p q : Payment} (hnd : (P.map Payment.paymentId).Nodup)
    (hp : findPayment P new.paymentId = some p) (hq : q ∈ P) (h : q.paymentId = new.paymentId) : q = p := by
  have h1 := findPayment_of_mem hnd hq
  rw [h, hp] at h1
  exact (Option.some.inj h1).symm

private theorem shape_reversed {r : PaymentRequest} {V : PaymentView} {S : ItemState}
    (hwf : financialInputWellFormed r.input = true)
    (hrec : r.receipts.map Receipt.paymentId = r.input.payments.map Payment.paymentId)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hS : summarize r.input r.receipts (anchorItemLength r.input r.receipts) = some S)
    (hVenv : V.env = envOf r.input)
    {c : ReverseCommand} (hc : commandWellFormed (.reverse c) = true)
    {p : Payment} {k : Receipt} (hp : findPayment r.input.payments c.paymentId = some p)
    (hk : receiptOf r.receipts p.paymentId = some k) (hbyId : V.byId = some (p, k))
    (hact : p.status ≠ .REVERSED) {time : Nat}
    (hfe : findEvidence r.input.evidence c.evidenceId = none)
    (hform : formRefusal (reversalRecord r.input c p time) = none) (htime : time ≤ r.input.evaluatedAt) :
    some (commitView V S .REVERSED ⟨some (reversalRecord r.input c p time), some (reversedImage p c), none, none⟩) =
      project r (mutate r .REVERSED ⟨some (reversalRecord r.input c p time), some (reversedImage p c), none, none⟩) := by
  let e := reversalRecord r.input c p time
  let new := reversedImage p c
  obtain ⟨hSe, hSc, hScash, hSle, hSctr, hSreq, hSab⟩ := S_facts hS
  obtain ⟨hP1, hE1, hC1, hPwf, hPew, hPrew, hNo, hcases⟩ := wf_facts hwf
  obtain ⟨hcP, hcE, hcC⟩ := wf_canon hwf
  obtain ⟨hid1, hid2, hnow⟩ := wf_ctx hwf
  have hnd := nodup_ids_of_wf hwf
  obtain ⟨hcid, hceid⟩ := cmd_reverse hc
  have hpc : p.paymentId = c.paymentId := findPayment_id _ _ _ hp
  have hp' : findPayment r.input.payments p.paymentId = some p := by rw [hpc]; exact hp
  have hpm := findPayment_mem hp
  have hpwf := hPwf p hpm
  have hpact : p.status = .ACTIVE := by
    cases h : p.status with
    | ACTIVE => rfl
    | REVERSED => exact absurd h hact
  have hpnone : p.reversalEvidenceId = none := by
    have := hPrew p hpm
    unfold reversalEvidenceWellFormed at this
    rw [hpact] at this
    cases h : p.reversalEvidenceId with
    | none => rfl
    | some _ => rw [h] at this; simp at this
  have hpitem : p.itemId = r.input.context.itemId := by
    simp only [paymentWellFormed, Bool.and_eq_true, decide_eq_true_eq, List.all_cons, List.all_nil,
      Bool.and_true] at hpwf
    exact hpwf.1.1.1.2
  have hnew : findPayment r.input.payments new.paymentId = some p := hp'
  have hnewst : new.status ≠ .ACTIVE := by simp [new, reversedImage]
  have hpost : applyWrites r.input ⟨some e, some new, none, none⟩ =
      upd r.input (r.input.payments.map fun x => if x.paymentId = new.paymentId then new else x)
        (insertBy EvidenceRecord.evidenceId e r.input.evidence) r.input.conflicts := by
    unfold applyWrites upd
    simp [hnew]
  have hfe' : findEvidence r.input.evidence e.evidenceId = none := hfe
  have hfe2 : findEvidence (insertBy EvidenceRecord.evidenceId e r.input.evidence) c.evidenceId = some e :=
    (findEvidence_insertBy hfe').trans (if_pos rfl)
  have hE : ∀ id x, findEvidence r.input.evidence id = some x →
      findEvidence (insertBy EvidenceRecord.evidenceId e r.input.evidence) id = some x := fun id x h => by
    rw [findEvidence_insertBy hfe']
    by_cases ee : e.evidenceId = id
    · subst ee; rw [hfe'] at h; cases h
    · rw [if_neg ee]; exact h
  have hfind : ∀ id, findPayment (r.input.payments.map fun x => if x.paymentId = new.paymentId then new else x) id =
      (findPayment r.input.payments id).map fun x => if x.paymentId = new.paymentId then new else x :=
    fun id => findPayment_replace _ new new rfl id
  have hwfpost : (insertBy EvidenceRecord.evidenceId e r.input.evidence).length ≤ maxRows →
      financialInputWellFormed (upd r.input (r.input.payments.map fun x => if x.paymentId = new.paymentId then new else x)
        (insertBy EvidenceRecord.evidenceId e r.input.evidence) r.input.conflicts) = true := fun hl => by
    refine wf_grow hwf hE (fun id q h => ?_) (fun id q h hr => ?_) (fun x hx => hx) hl hC1
      (fun _ => ?_) ?_ hcC ?_ ?_ ?_ (fun q hq hn => absurd hq hn)
    · have hq := findPayment_mem h
      have hid := findPayment_id _ _ _ h
      refine ⟨if q.paymentId = new.paymentId then new else q, by rw [hfind, h]; rfl, ?_⟩
      by_cases ee : q.paymentId = new.paymentId
      · rw [if_pos ee, rep_eq hnd hnew hq ee]; exact ⟨rfl, rfl, rfl⟩
      · rw [if_neg ee]; exact ⟨rfl, rfl, rfl⟩
    · have hq := findPayment_mem h
      rw [hfind, h]
      by_cases ee : q.paymentId = new.paymentId
      · have := rep_eq hnd hnew hq ee
        rw [this] at hr; exact absurd hr hact
      · simp [ee]
    · rw [List.map_map]
      have : (r.input.payments.map ((Payment.paymentId) ∘ fun x => if x.paymentId = new.paymentId then new else x)) =
          r.input.payments.map Payment.paymentId := by
        have := rep_map hnd hnew Payment.paymentId rfl
        rwa [List.map_map] at this
      rw [this]; exact hcP
    · have : (insertBy EvidenceRecord.evidenceId e r.input.evidence).map EvidenceRecord.evidenceId =
          insertBy (fun s => s) e.evidenceId (r.input.evidence.map EvidenceRecord.evidenceId) :=
        map_insertBy _ _ (fun s => s) (fun _ => rfl) e _
      rw [this]
      refine canonical_insert hcE hceid ?_ ?_
      · intro hm
        obtain ⟨x, hx⟩ := find_of_known (List.contains_iff_mem.2 hm)
        rw [hfe'] at hx; cases hx
      · rw [List.length_map]; rw [length_insertBy] at hl; omega
    · rw [noDup_iff]
      have := rep_map hnd hnew Payment.commonOriginId rfl
      rw [this]; exact (noDup_iff _).1 hNo
    · intro q hq hn
      rcases mem_replace hq with rfl | h
      · refine ⟨reversedImage_wf hpwf hc, ?_, ?_⟩
        · exact pew_mono (i := r.input) (j := upd r.input _ _ _) hE (hPew p hpm)
        · unfold reversalEvidenceWellFormed
          simp only [upd, new, reversedImage]
          rw [hfe2]
          simp [e, reversalRecord, hpitem]
      · exact absurd h hn
    · intro x hx hn
      rcases (mem_insertBy _ _ x _).1 hx with rfl | h
      · refine ⟨reversalRecord_wf ⟨hid1, hid2⟩ hnow hc hpwf hform htime, Nat.le_refl _, ?_⟩
        unfold accLam
        rw [if_neg (by simp [e, reversalRecord]), if_pos (by simp [e, reversalRecord])]
        unfold reversalEvidenceAccounted
        simp only [e, reversalRecord, upd]
        rw [hfind, hp']
        simp [new, reversedImage, hpitem]
      · exact absurd h hn
  have hold : oldPay r.input ⟨some e, some new, none, none⟩ = (encodePayment p).length := by
    simp [oldPay, new, reversedImage, hp']
  have hnewp : newPay ⟨some e, some new, none, none⟩ = (encodePayment new).length := by simp [newPay]
  have hlenle : (encodePayment new).length = (encodePayment p).length + (encodeString c.evidenceId).length :=
    enc_rev c hpnone
  have hrep := activeCents_replace hnd hnew hpact hnewst
  refine commit_core hb hS hVenv ?_ ?_ hcases ?_ ?_
  · unfold anchorGrowth addedBytes
    rw [hold, hbyId]
    simp [receiptBytes]
  · have := rawEncode_applyWrites_core r.input ⟨some e, some new, none, none⟩ (fun q hq hs => hnd)
    unfold addedBytes
    rw [hold, hnewp] at this ⊢
    simp only [e, new] at this hlenle ⊢
    omega
  · intro s' h
    rw [hpost]
    rw [adv_rev V S e new p k hbyId] at h
    by_cases h1 : (insertBy (fun x => x) e.evidenceId S.evidenceIds).length > maxRows || S.conflictCount > maxRows
    · rw [if_pos h1] at h; cases h
    · rw [hSe] at h1
      simp only [length_insertBy, List.length_map, Bool.or_eq_true, decide_eq_true_eq, not_or, Nat.not_lt] at h1
      exact hwfpost (by rw [length_insertBy]; exact h1.1)
  · intro hw
    rw [hpost] at hw ⊢
    have hl := (wf_facts hw).2.1
    simp only [upd, length_insertBy] at hl
    rw [summarize_upd hS, adv_rev V S e new p k hbyId]
    have h1 : ¬ ((insertBy (fun x => x) e.evidenceId S.evidenceIds).length > maxRows || S.conflictCount > maxRows) := by
      rw [hSe, hSc]
      simp only [length_insertBy, List.length_map, Bool.or_eq_true, decide_eq_true_eq, not_or, Nat.not_lt]
      exact ⟨hl, hC1⟩
    have hcr : commitReceipts r.receipts ⟨some (reversalRecord r.input c p time), some (reversedImage p c), none, none⟩ = r.receipts := rfl
    rw [hcr, if_neg h1, if_pos (by omega)]
    cases S with
    | mk rev cash claimed lawful contr lc dl cc eids reqs ab =>
      dsimp only at hScash hSe hSc hSctr hSreq hSab hl
      subst hScash hSctr hSreq hSe hSc
      simp only [Option.some.injEq, ItemState.mk.injEq, true_and]
      refine ⟨?_, ?_, ?_, ?_, rfl⟩
      · omega
      · exact (contrib_replace _ _ new p hnewst hnd hnew hpact).symm
      · exact (map_insertBy _ _ (fun s => s) (fun _ => rfl) e _).symm
      · rw [List.map_map]
        refine List.map_congr_left fun a _ => ?_
        have := paid_replace r.input hnd hrec hnew hpact hnewst hk a.actionId
        simp only [Function.comp]
        by_cases h : k.paysActionId = some a.actionId
        · rw [if_pos h] at this
          simp only [if_pos h, RequestPaid.mk.injEq, eq_self, true_and]; omega
        · rw [if_neg h] at this
          simp only [if_neg h, RequestPaid.mk.injEq, eq_self, true_and]; omega

private theorem alias_wf {r : PaymentRequest} (hwf : financialInputWellFormed r.input = true)
    {c : RecordCommand} (hc : commandWellFormed (.record c) = true)
    {p : Payment} (hp : p ∈ r.input.payments) (hporig : p.commonOriginId = c.commonOriginId)
    (hamt : p.amountCents = c.amountCents)
    (hfe : findEvidence r.input.evidence c.evidenceId = none)
    (hform : formRefusal (confirmation r.input c r.input.evaluatedAt) = none)
    (hle : c.eventAt ≤ r.input.evaluatedAt) :
    financialInputWellFormed (applyWrites r.input
      ⟨some (confirmation r.input c r.input.evaluatedAt), none, none, none⟩) = true ↔
      r.input.evidence.length < maxRows := by
  have hev : EvCase r.input c (some (confirmation r.input c r.input.evaluatedAt)) :=
    Or.inl ⟨rfl, hfe, hform, hle⟩
  obtain ⟨hE, ⟨t, hEt⟩, hEnew, hEcan⟩ := ev_facts hwf hc hev
  obtain ⟨hP1, hE1, hC1, hPwf, hPew, hPrew, hNo, hcases⟩ := wf_facts hwf
  obtain ⟨hcP, hcE, hcC⟩ := wf_canon hwf
  have hpost : applyWrites r.input ⟨some (confirmation r.input c r.input.evaluatedAt), none, none, none⟩ =
      upd r.input r.input.payments (evOf r.input (some (confirmation r.input c r.input.evaluatedAt)))
        r.input.conflicts := rfl
  rw [hpost]
  constructor
  · intro hw
    have hl := (wf_facts hw).2.1
    simp only [upd, evOf, Option.map_some, Option.getD_some, length_insertBy] at hl
    omega
  · intro hl
    have hl' : (evOf r.input (some (confirmation r.input c r.input.evaluatedAt))).length ≤ maxRows := by
      simp only [evOf, Option.map_some, Option.getD_some, length_insertBy]; omega
    refine wf_grow hwf hE (fun id q h => ⟨q, h, rfl, rfl, rfl⟩) (fun id q h _ => h) (fun x hx => hx) hl' hC1
      (fun _ => hcP) (evOf_canon hcE hEcan hl') hcC hNo (fun q hq hn => absurd hq hn) ?_ (fun x hx hn => absurd hx hn)
    intro x hx hn
    obtain ⟨a, b, d, e, f, g⟩ := hEnew x hx hn
    refine ⟨a, b, ?_⟩
    unfold accLam
    rw [if_pos e]
    unfold paymentConfirmationAccounted
    simp only [g, f, upd, Bool.or_eq_true, List.any_eq_true, decide_eq_true_eq, Bool.and_eq_true]
    exact Or.inr ⟨p, hp, hporig, hamt⟩

private theorem alias_cap {r : PaymentRequest} {S : ItemState}
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hSab : S.anchorBytes = anchorItemLength r.input r.receipts) (e : EvidenceRecord) :
    withinCapacity r ⟨some e, none, none, none⟩ = true ↔
      ¬ (S.anchorBytes + (encodeEvidence e).length + maxCallTailBytes > maxTotalEncodedBytes) := by
  unfold withinCapacity
  rw [decide_eq_true_iff]
  unfold addedBytes
  simp only [evBytes, newPay, oldPay, cfBytes, receiptBytes, Option.map_some, Option.getD_some,
    Option.map_none, Option.getD_none, Option.bind_none]
  unfold anchorItemLength at hSab
  omega

private theorem shape_alias {r : PaymentRequest} {V : PaymentView} {S : ItemState}
    (hwf : financialInputWellFormed r.input = true)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hS : summarize r.input r.receipts (anchorItemLength r.input r.receipts) = some S)
    (hVenv : V.env = envOf r.input)
    {c : RecordCommand} (hc : commandWellFormed (.record c) = true)
    {p : Payment} (hp : p ∈ r.input.payments) (hporig : p.commonOriginId = c.commonOriginId)
    (hamt : p.amountCents = c.amountCents)
    (hfe : findEvidence r.input.evidence c.evidenceId = none)
    (hform : formRefusal (confirmation r.input c r.input.evaluatedAt) = none)
    (hle : c.eventAt ≤ r.input.evaluatedAt) (pid : String) :
    some (aliasView V S pid (confirmation r.input c r.input.evaluatedAt)) =
      project r (aliasOf r pid (confirmation r.input c r.input.evaluatedAt)) := by
  obtain ⟨hSe, hSc, hScash, hSle, hSctr, hSreq, hSab⟩ := S_facts hS
  have hwfiff := alias_wf hwf hc hp hporig hamt hfe hform hle
  have hcap := alias_cap hb hSab (confirmation r.input c r.input.evaluatedAt)
  have hmode : V.env.context.mode = r.input.context.mode := by rw [hVenv]; rfl
  unfold aliasView aliasOf
  dsimp only
  rw [hmode]
  by_cases hm : r.input.context.mode = .SHADOW
  · simp [hm, project]
  · rw [if_neg hm, if_neg hm]
    by_cases hcp : S.anchorBytes + (encodeEvidence (confirmation r.input c r.input.evaluatedAt)).length +
        maxCallTailBytes > maxTotalEncodedBytes
    · have : (!withinCapacity r ⟨some (confirmation r.input c r.input.evaluatedAt), none, none, none⟩) = true := by
        cases h : withinCapacity r ⟨some (confirmation r.input c r.input.evaluatedAt), none, none, none⟩
        · rfl
        · exact absurd hcp (hcap.1 h)
      rw [if_pos hcp, if_pos this]; rfl
    · have : ¬ ((!withinCapacity r ⟨some (confirmation r.input c r.input.evaluatedAt), none, none, none⟩) = true) := by
        simp only [Bool.not_eq_true', Bool.not_eq_false]
        exact hcap.2 hcp
      rw [if_neg hcp, if_neg this]
      rw [hSe, List.length_map]
      by_cases hlt : r.input.evidence.length < maxRows
      · rw [if_pos hlt, if_pos (hwfiff.2 hlt)]; rfl
      · rw [if_neg hlt, if_neg (fun h => hlt (hwfiff.1 h))]; rfl

private theorem faithful_unpack {r : PaymentRequest} {v : PaymentView}
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length) (hv : Faithful r v) :
    ∃ S, summarize r.input r.receipts (anchorItemLength r.input r.receipts) = some S ∧
      absorb v.state v.pending = S ∧ v.env = envOf r.input ∧
      v.byId = (findPayment r.input.payments (cmdPaymentId r.command)).bind
        (fun p => (receiptOf r.receipts p.paymentId).map fun k => (p, k)) ∧
      v.byOrigin = (match r.command with
        | .record c => (r.input.payments.find? (·.commonOriginId = c.commonOriginId)).bind fun p =>
            ((receiptOf r.receipts p.paymentId).map fun k => (p, k)).map fun (p, k) =>
              (p, k, p.reversalEvidenceId.bind (findEvidence r.input.evidence))
        | .reverse _ => none) ∧
      v.evidence = findEvidence r.input.evidence (cmdEvidenceId r.command) ∧
      v.conflictVisible = (match r.command with
        | .record c => r.input.conflicts.any (·.conflictId = conflictIdOf r.input c)
        | .reverse _ => false) ∧
      v.foreign = r.foreign ∧ v.expectedRevision = r.expectedRevision ∧ v.command = r.command := by
  have hbA : anchorOverhead + r.inputBytes + (encodeList encodeReceipt r.receipts).length =
      anchorItemLength r.input r.receipts := by unfold anchorItemLength; omega
  unfold Faithful viewOfAnchor at hv
  dsimp only at hv
  rw [hbA] at hv
  cases hsum : summarize r.input r.receipts (anchorItemLength r.input r.receipts) with
  | none => rw [hsum] at hv; cases hv
  | some S =>
    rw [hsum] at hv
    simp only [Option.map_some, Option.some.injEq] at hv
    exact ⟨S, rfl, (congrArg PaymentView.state hv).symm,
      (congrArg PaymentView.env hv).symm, (congrArg PaymentView.byId hv).symm,
      (congrArg PaymentView.byOrigin hv).symm, (congrArg PaymentView.evidence hv).symm,
      (congrArg PaymentView.conflictVisible hv).symm, (congrArg PaymentView.foreign hv).symm,
      (congrArg PaymentView.expectedRevision hv).symm, (congrArg PaymentView.command hv).symm⟩

private theorem head_conf (i : FinancialInput) (c : RecordCommand) (t : Nat) :
    confirmation (envOf i).head c t = confirmation i c t := rfl
private theorem head_rrec (i : FinancialInput) (c : ReverseCommand) (p : Payment) (t : Nat) :
    reversalRecord (envOf i).head c p t = reversalRecord i c p t := rfl
private theorem head_rpay (i : FinancialInput) (c : RecordCommand) :
    recordedPayment (envOf i).head c = recordedPayment i c := rfl
private theorem head_rrcp (i : FinancialInput) (c : RecordCommand) :
    recordedReceipt (envOf i).head c = recordedReceipt i c := rfl
private theorem head_cimg (i : FinancialInput) (c : RecordCommand) (p : Payment) (id : String) :
    conflictImage (envOf i).head c p id = conflictImage i c p id := rfl
private theorem head_cid (i : FinancialInput) (c : RecordCommand) :
    conflictIdOf (envOf i).head c = conflictIdOf i c := rfl

private theorem retry_lock {r : PaymentRequest} {V : PaymentView} {c : RecordCommand} {p : Payment} {k : Receipt}
    (henv : V.env = envOf r.input) (hev : V.evidence = findEvidence r.input.evidence c.evidenceId)
    (hexp : V.expectedRevision = r.expectedRevision) (hk : receiptOf r.receipts p.paymentId = some k) :
    some (viewRecordRetry V c p k) = project r (recordRetry r c p) := by
  unfold viewRecordRetry recordRetry
  rw [hev]
  cases hf : findEvidence r.input.evidence c.evidenceId with
  | none => simp only [hf]; rfl
  | some s =>
    simp only [hf, hk, henv, hexp, head_conf]
    cases hform : formRefusal (confirmation r.input c s.receivedAt) with
    | some f => simp only [hform]; rfl
    | none =>
      simp only [hform]
      by_cases hch : c.eventAt > s.receivedAt
      · simp only [hch, ↓reduceIte]; rfl
      · simp only [hch, ↓reduceIte]
        by_cases hq : r.expectedRevision = some k.recordedRevision ∧ k.paysActionId = c.paysActionId ∧
            p.evidenceId = c.evidenceId ∧ p.commonOriginId = c.commonOriginId ∧
            p.amountCents = c.amountCents ∧ p.eventAt = c.eventAt ∧ confirmation r.input c s.receivedAt = s
        · simp only [hq, and_self, ↓reduceIte]; rfl
        · simp only [hq, ↓reduceIte]; rfl

private theorem envOf_eval (i : FinancialInput) : (envOf i).evaluatedAt = i.evaluatedAt := rfl
private theorem envOf_before (i : FinancialInput) : (envOf i).beforeRevision = i.beforeRevision := rfl

private theorem rev_lock {r : PaymentRequest} {V : PaymentView} {S : ItemState}
    (hwf : financialInputWellFormed r.input = true)
    (hrec : r.receipts.map Receipt.paymentId = r.input.payments.map Payment.paymentId)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hS : summarize r.input r.receipts (anchorItemLength r.input r.receipts) = some S)
    (hVenv : V.env = envOf r.input) {c : ReverseCommand} (hc : commandWellFormed (.reverse c) = true)
    (hbyId : V.byId = (findPayment r.input.payments c.paymentId).bind
      (fun p => (receiptOf r.receipts p.paymentId).map fun k => (p, k)))
    (hev : V.evidence = findEvidence r.input.evidence c.evidenceId)
    (hfor : V.foreign = r.foreign) (hexp : V.expectedRevision = r.expectedRevision) :
    some (viewReverse V S c) = project r (decideReverse r c) := by
  have hnd := nodup_ids_of_wf hwf
  cases hfp : findPayment r.input.payments c.paymentId with
  | none =>
    rw [hfp] at hbyId
    simp only [viewReverse, decideReverse, hbyId, hfp, Option.bind_none]
    rfl
  | some p =>
    obtain ⟨k, hk⟩ := receipt_exists (L := ⟨r.input, r.receipts⟩) ⟨hnd, hrec⟩ hfp
    have hbyId' : V.byId = some (p, k) := by rw [hbyId, hfp]; simp [hk]
    unfold viewReverse decideReverse
    simp only [hbyId', hfp, hfor, hev, hVenv, head_rrec, envOf_eval, envOf_before, revisionOk, hexp]
    cases hfe : r.foreign.evidenceId with
    | true => simp only [hfe]; rfl
    | false =>
      simp only [Bool.false_eq_true, ↓reduceIte]
      generalize hT : c.eventAt.getD (((findEvidence r.input.evidence c.evidenceId).map (·.eventAt)).getD
        r.input.evaluatedAt) = time
      cases hform : formRefusal (reversalRecord r.input c p time) with
      | some f => simp only [hform]; rfl
      | none =>
        simp only [hform]
        by_cases hch : time > r.input.evaluatedAt
        · simp only [hch, ↓reduceIte]; rfl
        · simp only [hch, ↓reduceIte]
          have hs : slotOf false (findEvidence r.input.evidence c.evidenceId)
              (reversalRecord r.input c p time) = evidenceSlot r (reversalRecord r.input c p time) :=
            by rw [evidenceSlot_eq, hfe]; rfl
          rw [hs]
          cases hsl : evidenceSlot r (reversalRecord r.input c p time) with
          | clash => simp only [hsl]; rfl
          | same s => simp only [hsl]; rfl
          | fresh =>
            simp only [hsl]
            obtain ⟨-, hfs | ⟨s, hs', -⟩⟩ := slot_cases (r := r) (e := reversalRecord r.input c p time)
              (by rw [hsl]; intro h; cases h)
            · have hfe' : findEvidence r.input.evidence c.evidenceId = none := hfs.2
              by_cases hrv : (!r.expectedRevision.all fun x => decide (x = r.input.beforeRevision)) = true
              · simp only [hrv, ↓reduceIte]; rfl
              · simp only [hrv]
                by_cases hst : p.status = .REVERSED
                · simp only [hst, ↓reduceIte]; rfl
                · simp only [hst, ↓reduceIte]
                  exact shape_reversed hwf hrec hb hS hVenv hc hfp hk hbyId' hst hfe' hform
                    (Nat.not_lt.1 hch)
            · rw [hsl] at hs'; cases hs'

private theorem conf_evid (i : FinancialInput) (c : RecordCommand) (t : Nat) :
    (confirmation i c t).evidenceId = c.evidenceId := rfl

private theorem slot_facts {foreign : Bool} {stored : Option EvidenceRecord} {e : EvidenceRecord} {slot : Slot}
    (h : slotOf foreign stored e = slot) :
    (slot = .fresh → foreign = false ∧ stored = none) ∧
    (∀ s, slot = .same s → foreign = false ∧ stored = some s ∧ e.eventAt ≤ s.receivedAt ∧
      { e with receivedAt := s.receivedAt } = s) := by
  unfold slotOf at h
  cases foreign with
  | true =>
    simp only [↓reduceIte] at h
    subst h
    exact ⟨fun h => (nomatch h), fun s h => nomatch h⟩
  | false =>
    cases stored with
    | none =>
      simp only [Bool.false_eq_true, ↓reduceIte] at h
      subst h
      exact ⟨fun _ => ⟨rfl, rfl⟩, fun s h => nomatch h⟩
    | some s0 =>
      simp only [Bool.false_eq_true, ↓reduceIte] at h
      by_cases hc : e.eventAt ≤ s0.receivedAt ∧ { e with receivedAt := s0.receivedAt } = s0
      · rw [if_pos hc] at h
        subst h
        refine ⟨fun h => (nomatch h), fun s h => ?_⟩
        cases h
        exact ⟨rfl, rfl, hc.1, hc.2⟩
      · rw [if_neg hc] at h
        subst h
        exact ⟨fun h => (nomatch h), fun s h => nomatch h⟩

private theorem ev_leaf {i : FinancialInput} {c : RecordCommand} {R : Nat} {foreign : Bool} {slot : Slot}
    (hsl : slotOf foreign (findEvidence i.evidence c.evidenceId) (confirmation i c R) = slot)
    (hne : slot ≠ .clash) (hR : findEvidence i.evidence c.evidenceId = none → R = i.evaluatedAt)
    (hform : formRefusal (confirmation i c R) = none) (hle : c.eventAt ≤ R) :
    EvCase i c (if slot.isFresh = true then some (confirmation i c R) else none) := by
  obtain ⟨hf, hs⟩ := slot_facts hsl
  cases slot with
  | clash => exact absurd rfl hne
  | fresh =>
    obtain ⟨-, hst⟩ := hf rfl
    have := hR hst
    subst this
    exact Or.inl ⟨rfl, hst, hform, hle⟩
  | same s =>
    obtain ⟨-, hst, -, hs'⟩ := hs s rfl
    refine Or.inr ⟨rfl, s.receivedAt, ?_⟩
    rw [hst]
    exact congrArg some hs'.symm

private theorem new_none {r : PaymentRequest} {V : PaymentView} {S : ItemState}
    (hwf : financialInputWellFormed r.input = true)
    (hrec : r.receipts.map Receipt.paymentId = r.input.payments.map Payment.paymentId)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hS : summarize r.input r.receipts (anchorItemLength r.input r.receipts) = some S)
    (hVenv : V.env = envOf r.input) {c : RecordCommand} (hc : commandWellFormed (.record c) = true)
    (h0 : c.amountCents ≠ 0) (hpid : findPayment r.input.payments c.paymentId = none)
    (hbyId : V.byId = none) (hbo : V.byOrigin = none)
    (hev : V.evidence = findEvidence r.input.evidence c.evidenceId)
    (hcv : V.conflictVisible = r.input.conflicts.any (·.conflictId = conflictIdOf r.input c))
    (hfor : V.foreign = r.foreign) (hexp : V.expectedRevision = r.expectedRevision)
    (hex : r.input.payments.find? (·.commonOriginId = c.commonOriginId) = none) :
    some (viewRecordNew V S c) = project r (recordNew r c) := by
  have hlink := linkRefusalView_eq hwf hS c
  have hno : ∀ q ∈ r.input.payments, q.commonOriginId ≠ c.commonOriginId :=
    fun q hq h => (List.find?_eq_none.1 hex q hq) (decide_eq_true h)
  unfold viewRecordNew recordNew
  simp only [hbo, hev, hcv, hfor, hexp, hVenv, hex, hlink, head_conf, head_rpay, head_rrcp,
    envOf_eval, envOf_before, revisionOk, evidenceSlot_eq, conf_evid, Option.any_none, Option.isSome_none,
    Bool.false_and, Bool.and_false, Bool.not_false, Bool.true_and,
    Bool.false_eq_true, ↓reduceIte]
  by_cases hrv : (!Option.all (fun x => decide (x = r.input.beforeRevision)) r.expectedRevision) = true
  · simp only [hrv, ↓reduceIte]; rfl
  · simp only [hrv, Bool.false_eq_true, ↓reduceIte]
    cases hform : formRefusal (confirmation r.input c r.input.evaluatedAt) with
    | some f => simp only [hform]; rfl
    | none =>
      simp only [hform]
      by_cases hch : c.eventAt > r.input.evaluatedAt
      · simp only [hch, ↓reduceIte]; rfl
      · simp only [hch, ↓reduceIte]
        cases hsl : slotOf r.foreign.evidenceId (findEvidence r.input.evidence c.evidenceId)
            (confirmation r.input c r.input.evaluatedAt) with
        | clash => simp only [hsl]; rfl
        | same s =>
          simp only [hsl]
          cases hlr : linkRefusal r.input r.receipts c with
          | some f => simp only [hlr]; rfl
          | none =>
            simp only [hlr]
            exact shape_recorded hwf hrec hb hS hVenv hbyId hc h0 hpid hno
              (ev_leaf hsl (by simp) (fun _ => rfl) hform (Nat.not_lt.1 hch))
        | fresh =>
          simp only [hsl]
          cases hlr : linkRefusal r.input r.receipts c with
          | some f => simp only [hlr]; rfl
          | none =>
            simp only [hlr]
            exact shape_recorded hwf hrec hb hS hVenv hbyId hc h0 hpid hno
              (ev_leaf hsl (by simp) (fun _ => rfl) hform (Nat.not_lt.1 hch))

private theorem receipt_of_mem {r : PaymentRequest} (hwf : financialInputWellFormed r.input = true)
    (hrec : r.receipts.map Receipt.paymentId = r.input.payments.map Payment.paymentId)
    {p : Payment} (hp : p ∈ r.input.payments) : ∃ k, receiptOf r.receipts p.paymentId = some k := by
  have hn : (r.receipts.map Receipt.paymentId).Nodup := by rw [hrec]; exact nodup_ids_of_wf hwf
  have : p.paymentId ∈ r.receipts.map Receipt.paymentId := by
    rw [hrec]; exact List.mem_map.2 ⟨p, hp, rfl⟩
  obtain ⟨k, hk, hkp⟩ := List.mem_map.1 this
  exact ⟨k, by rw [← hkp]; exact find_of_mem Receipt.paymentId hn hk⟩

private theorem new_diff {r : PaymentRequest} {V : PaymentView} {S : ItemState}
    (hwf : financialInputWellFormed r.input = true)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hS : summarize r.input r.receipts (anchorItemLength r.input r.receipts) = some S)
    (hVenv : V.env = envOf r.input) {c : RecordCommand} (hc : commandWellFormed (.record c) = true)
    (h0 : c.amountCents ≠ 0)
    {p : Payment} {k : Receipt} (hex : r.input.payments.find? (·.commonOriginId = c.commonOriginId) = some p)
    (hne : p.amountCents ≠ c.amountCents)
    (hbo : V.byOrigin = some (p, k, p.reversalEvidenceId.bind (findEvidence r.input.evidence)))
    (hev : V.evidence = findEvidence r.input.evidence c.evidenceId)
    (hcv : V.conflictVisible = r.input.conflicts.any (·.conflictId = conflictIdOf r.input c))
    (hfor : V.foreign = r.foreign) (hexp : V.expectedRevision = r.expectedRevision) :
    some (viewRecordNew V S c) = project r (recordNew r c) := by
  have hp := List.mem_of_find?_eq_some hex
  have hporig : p.commonOriginId = c.commonOriginId := by
    have := List.find?_some hex
    simpa using this
  unfold viewRecordNew recordNew
  simp only [decide_eq_false hne, hbo, hev, hcv, hfor, hexp, hVenv, hex, head_conf, head_cid, head_cimg,
    envOf_eval, envOf_before, revisionOk, evidenceSlot_eq, conf_evid, Option.any_some, Option.isSome_some,
    Bool.false_and, Bool.not_false, Bool.true_and,
    Bool.false_eq_true, ↓reduceIte]
  have hfp := findPayment_of_mem (nodup_ids_of_wf hwf) hp
  repeat' split
  all_goals (try rfl)
  all_goals
    rename_i _ _ _ hform hch _ hnc hcvf hid hfr
    have hev' := ev_leaf (slot := slotOf r.foreign.evidenceId (findEvidence r.input.evidence c.evidenceId)
      (confirmation r.input c r.input.evaluatedAt)) rfl hnc (fun _ => rfl) hform (Nat.not_lt.1 hch)
  · rw [if_pos hfr] at hev'
    exact shape_conflict hwf hb hS hVenv hc h0 hfp hporig hne (by simpa using hcvf) (by simpa using hid) hev'
  · rw [if_neg hfr] at hev'
    exact shape_conflict hwf hb hS hVenv hc h0 hfp hporig hne (by simpa using hcvf) (by simpa using hid) hev'

private theorem new_same {r : PaymentRequest} {V : PaymentView} {S : ItemState}
    (hwf : financialInputWellFormed r.input = true)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hS : summarize r.input r.receipts (anchorItemLength r.input r.receipts) = some S)
    (hVenv : V.env = envOf r.input) {c : RecordCommand} (hc : commandWellFormed (.record c) = true)
    {p : Payment} {k : Receipt} (hex : r.input.payments.find? (·.commonOriginId = c.commonOriginId) = some p)
    (hs : p.amountCents = c.amountCents)
    (hk : receiptOf r.receipts p.paymentId = some k)
    (hbo : V.byOrigin = some (p, k, p.reversalEvidenceId.bind (findEvidence r.input.evidence)))
    (hev : V.evidence = findEvidence r.input.evidence c.evidenceId)
    (hcv : V.conflictVisible = r.input.conflicts.any (·.conflictId = conflictIdOf r.input c))
    (hfor : V.foreign = r.foreign) (hexp : V.expectedRevision = r.expectedRevision) :
    some (viewRecordNew V S c) = project r (recordNew r c) := by
  have hp := List.mem_of_find?_eq_some hex
  have hporig : p.commonOriginId = c.commonOriginId := by
    have := List.find?_some hex
    simpa using this
  unfold viewRecordNew recordNew
  simp only [decide_eq_true hs, hbo, hev, hcv, hfor, hexp, hVenv, hex, hk, head_conf, head_cid,
    envOf_eval, envOf_before, revisionOk, evidenceSlot_eq, conf_evid, Option.any_some, Option.isSome_some,
    Option.bind_some, Bool.true_and,
    ↓reduceIte]
  repeat' split
  all_goals (try rfl)
  · rename_i _ _ _ h4 _ _ h3 _ _ _ _ h
    have hf0 : r.foreign.evidenceId = false := by
      cases hf : r.foreign.evidenceId
      · rfl
      · exact absurd (by simp [hf]) h4
    have hsome : (findEvidence r.input.evidence c.evidenceId).isSome = true := by simpa [hf0] using h3
    cases hsl : slotOf r.foreign.evidenceId (findEvidence r.input.evidence c.evidenceId)
        (confirmation r.input c ((Option.map (fun x => x.receivedAt) (findEvidence r.input.evidence c.evidenceId)).getD
          r.input.evaluatedAt)) with
    | clash => simp [hsl, Slot.isFresh] at h
    | same s => simp [hsl, Slot.isFresh] at h
    | fresh =>
      obtain ⟨-, hst⟩ := (slot_facts hsl).1 rfl
      rw [hst] at hsome
      cases hsome
  · rename_i _ _ _ _ _ heq h3 hch _ _ _ _
    rw [if_neg h3] at heq
    have hfe : findEvidence r.input.evidence c.evidenceId = none := by
      cases hh : findEvidence r.input.evidence c.evidenceId
      · rfl
      · exact absurd (by simp [hh]) h3
    exact shape_alias hwf hb hS hVenv hc hp hporig hs hfe heq (Nat.not_lt.1 hch) p.paymentId

private theorem new_lock {r : PaymentRequest} {V : PaymentView} {S : ItemState}
    (hwf : financialInputWellFormed r.input = true)
    (hrec : r.receipts.map Receipt.paymentId = r.input.payments.map Payment.paymentId)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length)
    (hS : summarize r.input r.receipts (anchorItemLength r.input r.receipts) = some S)
    (hVenv : V.env = envOf r.input) {c : RecordCommand} (hc : commandWellFormed (.record c) = true)
    (h0 : c.amountCents ≠ 0) (hpid : findPayment r.input.payments c.paymentId = none)
    (hbyId : V.byId = none)
    (hbo : V.byOrigin = (r.input.payments.find? (·.commonOriginId = c.commonOriginId)).bind fun p =>
      ((receiptOf r.receipts p.paymentId).map fun k => (p, k)).map fun (p, k) =>
        (p, k, p.reversalEvidenceId.bind (findEvidence r.input.evidence)))
    (hev : V.evidence = findEvidence r.input.evidence c.evidenceId)
    (hcv : V.conflictVisible = r.input.conflicts.any (·.conflictId = conflictIdOf r.input c))
    (hfor : V.foreign = r.foreign) (hexp : V.expectedRevision = r.expectedRevision) :
    some (viewRecordNew V S c) = project r (recordNew r c) := by
  cases hex : r.input.payments.find? (·.commonOriginId = c.commonOriginId) with
  | none =>
    rw [hex] at hbo
    exact new_none hwf hrec hb hS hVenv hc h0 hpid hbyId hbo hev hcv hfor hexp hex
  | some p =>
    obtain ⟨k, hk⟩ := receipt_of_mem hwf hrec (List.mem_of_find?_eq_some hex)
    rw [hex] at hbo
    simp only [Option.bind_some, hk, Option.map_some] at hbo
    by_cases hs : p.amountCents = c.amountCents
    · exact new_same hwf hb hS hVenv hc hex hs hk hbo hev hcv hfor hexp
    · exact new_diff hwf hb hS hVenv hc h0 hex hs hbo hev hcv hfor hexp

-- 16.2 item 3 (5.6): request-level; stepView_state is deleted (it is the `project` clause)
theorem stepView_eq {r : PaymentRequest} (hr : requestWellFormed r = true)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length) {v : PaymentView}
    (hv : Faithful r v) : some (stepView v) = project r (paymentTransition r) := by
  obtain ⟨S, hS, habs, hVenv, hbyId, hbo, hev, hcv, hfor, hexp, hcmd⟩ := faithful_unpack hb hv
  simp only [requestWellFormed, Bool.and_eq_true] at hr
  obtain ⟨⟨⟨hwf, hrcp⟩, hcw⟩, -⟩ := hr
  have hrec : r.receipts.map Receipt.paymentId = r.input.payments.map Payment.paymentId := by
    simp only [receiptsWellFormed, Bool.and_eq_true, beq_iff_eq] at hrcp; exact hrcp.1
  unfold stepView paymentTransition
  dsimp only
  rw [habs, hcmd]
  cases hcm : r.command with
  | reverse c =>
    simp only [hcm, cmdPaymentId, cmdEvidenceId] at hbyId hev hcw
    exact rev_lock hwf hrec hb hS hVenv hcw hbyId hev hfor hexp
  | record c =>
    simp only [hcm, cmdPaymentId, cmdEvidenceId] at hbyId hev hbo hcv hcw
    dsimp only
    rw [hfor]
    unfold decideRecord
    by_cases h0 : c.amountCents = 0
    · simp only [h0, ↓reduceIte]; rfl
    · simp only [h0, ↓reduceIte]
      by_cases hf : r.foreign.paymentId = true
      · simp only [hf, ↓reduceIte]; rfl
      · simp only [hf]
        cases hfp : findPayment r.input.payments c.paymentId with
        | some p =>
          obtain ⟨k, hk⟩ := receipt_of_mem hwf hrec (findPayment_mem hfp)
          rw [hfp] at hbyId
          simp only [Option.bind_some, hk, Option.map_some] at hbyId
          rw [hbyId]
          exact retry_lock hVenv hev hexp hk
        | none =>
          rw [hfp] at hbyId
          simp only [Option.bind_none] at hbyId
          rw [hbyId]
          exact new_lock hwf hrec hb hS hVenv hcw h0 hfp hbyId hbo hev hcv hfor hexp

private theorem bind_now {i : FinancialInput} {t : Nat} {a : ActionRecord}
    (h : actionBindingWellFormed i a = true) (hle : i.evaluatedAt ≤ t) :
    actionBindingWellFormed { i with evaluatedAt := t } a = true := by
  unfold actionBindingWellFormed at h ⊢
  cases hd : a.determinationId with
  | none => rw [hd] at h; exact h
  | some id =>
    rw [hd] at h
    simp only at h ⊢
    cases hf : findDetermination i.determinations id with
    | none => rw [hf] at h; exact h
    | some x =>
      rw [hf] at h
      simp only [Bool.and_eq_true, decide_eq_true_eq] at h ⊢
      exact ⟨h.1, by have := h.2; omega⟩

private theorem actWF_now {i : FinancialInput} {t : Nat} {a : ActionRecord}
    (h : actionWellFormed i a = true) (hle : i.evaluatedAt ≤ t) :
    actionWellFormed { i with evaluatedAt := t } a = true := by
  unfold actionWellFormed at h ⊢
  rw [Bool.and_eq_true] at h ⊢
  exact ⟨h.1, bind_now h.2 hle⟩

private theorem detAct_now {i : FinancialInput} {t : Nat} {x : OffsetDetermination}
    (h : determinationActionWellFormed i x = true) (hle : i.evaluatedAt ≤ t) :
    determinationActionWellFormed { i with evaluatedAt := t } x = true := by
  simp only [determinationActionWellFormed, actionsForDetermination, Bool.and_eq_true,
    List.all_eq_true] at h ⊢
  exact ⟨h.1, fun a ha => bind_now (h.2 a ha) hle⟩

private theorem detWF_now {i : FinancialInput} {t : Nat} {x : OffsetDetermination}
    (h : determinationWellFormed i x = true) (hle : i.evaluatedAt ≤ t) :
    determinationWellFormed { i with evaluatedAt := t } x = true := by
  unfold determinationWellFormed at h ⊢
  rw [Bool.and_eq_true, Bool.and_eq_true] at h ⊢
  obtain ⟨⟨hP, hD⟩, hM⟩ := h
  refine ⟨⟨hP, ?_⟩, hM⟩
  simp only [decide_eq_true_eq] at hD ⊢
  omega

private theorem wf_now {i : FinancialInput} {t : Nat} (h : financialInputWellFormed i = true)
    (hle : i.evaluatedAt ≤ t) (ht : t ≤ maxTime) :
    financialInputWellFormed { i with evaluatedAt := t } = true := by
  unfold financialInputWellFormed at h ⊢
  simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, and_assoc] at h ⊢
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18, h19, h20, h21, h22, h23, h24, h25, h26, h27, h28, h29, h30, h31, h32, h33, h34, h35, h36, h37, h38, h39, h40, h41, h42, h43, h44, h45, h46, h47, h48, h49, h50, h51, h52, h53, h54, h55⟩ := h
  exact ⟨h1, h2, h3, h4, h5, h6, (by simp only [timeWellFormed, decide_eq_true_eq]; exact ht), h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18, h19, h20, h21, h22, h23, h24, h25, h26, h27, h28, h29, h30, h31, h32, h33, h34, fun x hx => detWF_now (h35 x hx) hle, h36, h37, fun x hx => actWF_now (h38 x hx) hle, h39, h40, h41, h42, h43, h44, fun x hx => detAct_now (h45 x hx) hle, h46, h47, h48, fun x hx => Nat.le_trans (h49 x hx) hle, fun x hx => Nat.le_trans (h50 x hx) hle, h51, h52, h53, h54, h55⟩

private theorem step_eval (L : Ledger) (c : Call) :
    (step L c).input.evaluatedAt = L.input.evaluatedAt ∨ (step L c).input.evaluatedAt = c.now := by
  rcases step_cases L c with ⟨k, w, post, res, ho, he⟩ | ⟨pid, e, post, ho, he⟩ | ⟨-, -, he⟩ <;> rw [he]
  · right; rw [(paymentTransition_mutated_post ho).1]; rfl
  · right; rw [(alias_shape ho).1]; rfl
  · left; rfl

private theorem step_before_le (L : Ledger) (c : Call) :
    (step L c).input.beforeRevision ≤ L.input.beforeRevision + 1 := by
  rcases step_cases L c with ⟨k, w, post, res, ho, he⟩ | ⟨pid, e, post, ho, he⟩ | ⟨-, -, he⟩ <;> rw [he]
  · have hb : post.beforeRevision = L.input.beforeRevision := by
      rw [(paymentTransition_mutated_post ho).1]; rfl
    show post.beforeRevision + 1 ≤ _
    rw [hb]
    exact Nat.le_refl _
  · rw [(alias_shape ho).1]; exact Nat.le_succ _
  · exact Nat.le_succ _

/-- `hw` is `decodePaymentItem_command` for each view: the worker steps only decoded views. -/
theorem chain_fold_eq_full (L : Ledger) (hL : ledgerWellFormed L) (calls : List Call)
    (hc : clocksOk L calls) (hR : L.input.beforeRevision + calls.length ≤ maxRevision)
    (vs : List PaymentView) (hv : ChainFaithful L calls vs)
    (hw : vs.all fun v => commandWellFormed v.command && v.expectedRevision.all (· < 2 ^ 63)) :
    vs.map (some ∘ stepView) =
      ((ledgers L calls).zip calls).map fun M => project (M.1.request M.2) (outcome M.1 M.2) := by
  induction calls generalizing L vs with
  | nil =>
    obtain ⟨hlen, -⟩ := hv
    have : vs = [] := List.length_eq_zero_iff.1 (by simpa using hlen)
    subst this; rfl
  | cons c cs ih =>
    obtain ⟨hlen, hv⟩ := hv
    cases vs with
    | nil => simp at hlen
    | cons v vs' =>
      have hFv : Faithful (L.request c) v := hv 0 L c v rfl rfl rfl
      simp only [List.all_cons, Bool.and_eq_true] at hw
      obtain ⟨⟨hcmd, hexp⟩, hw2⟩ := hw
      obtain ⟨-, -, -, -, -, -, -, -, -, hexp', hcmd'⟩ := faithful_unpack (r := L.request c) (v := v) rfl hFv
      have hpw := (List.pairwise_cons.1 hc.1).1 c.now (by simp)
      have hnow : c.now < 2 ^ 63 := by
        have := hc.2
        simp only [List.all_cons, Bool.and_eq_true, decide_eq_true_eq] at this
        exact this.1
      have hmax : c.now ≤ maxTime := by simp only [maxTime, maxCents]; omega
      have hrq : requestWellFormed (L.request c) = true := by
        simp only [requestWellFormed, Bool.and_eq_true]
        refine ⟨⟨⟨wf_now hL.1 hpw hmax, hL.2⟩, ?_⟩, ?_⟩
        · show commandWellFormed c.command = true
          have e : v.command = c.command := hcmd'
          rw [e] at hcmd; exact hcmd
        · show c.expectedRevision.all (· < 2 ^ 63) = true
          have e : v.expectedRevision = c.expectedRevision := hexp'
          rw [e] at hexp; exact hexp
      have head : some (stepView v) = project (L.request c) (outcome L c) :=
        stepView_eq hrq rfl hFv
      show some (stepView v) :: vs'.map (some ∘ stepView) =
        project (L.request c) (outcome L c) :: ((ledgers (step L c) cs).zip cs).map _
      rw [head]
      cases cs with
      | nil =>
        have : vs' = [] := List.length_eq_zero_iff.1 (by simpa using hlen)
        subst this; rfl
      | cons c' cs' =>
        congr 1
        have hRs : L.input.beforeRevision + 1 < maxRevision := by
          simp only [List.length_cons] at hR; omega
        have hclk : clocksOk L [c] := ⟨by simp [List.pairwise_cons, hpw], by simpa using hnow⟩
        refine ih (step L c) (step_wellFormed L hL c hclk hRs) ?_ ?_ vs' ?_ hw2
        · obtain ⟨hp1, hp2⟩ := hc
          simp only [List.all_cons, Bool.and_eq_true] at hp2
          refine ⟨?_, by simp only [List.all_cons, Bool.and_eq_true]; exact hp2.2⟩
          have h1 := List.pairwise_cons.1 hp1
          have h2 := List.pairwise_cons.1 h1.2
          refine List.pairwise_cons.2 ⟨fun b hb => ?_, h2.2⟩
          rcases step_eval L c with he | he <;> rw [he]
          · exact h1.1 b (List.mem_cons_of_mem _ hb)
          · exact h2.1 b hb
        · have := step_before_le L c
          simp only [List.length_cons] at hR ⊢; omega
        · refine ⟨by simpa using hlen, fun n M c'' v'' hM hc'' hv'' => hv (n + 1) M c'' v'' hM hc'' hv''⟩

section FormBRoundTrip

private theorem bind_step {α β : Type} {x : Option α} {a : α} {f : α → Option β} {y : Option β}
    (hx : x = some a) (hf : f a = y) : (x >>= f) = y := by
  subst hx; exact hf

local macro "step " h:term : tactic => `(tactic| (refine bind_step $h ?_; try dsimp only))

private theorem lenWire {v : String} (h : v.toUTF8.toList.length ≤ 512) : stringWireAdmissible v :=
  stringWireAdmissible_of_length v (Nat.lt_of_le_of_lt h (by decide))

private theorem idWire {v : String} (h : idWellFormed v = true) : stringWireAdmissible v := by
  unfold idWellFormed maxIdBytes at h
  simp only [Bool.and_eq_true, decide_eq_true_eq] at h
  exact lenWire (Nat.le_trans h.1.2 (by decide))

private theorem textWire {v : String} (h : textWellFormed v = true) : stringWireAdmissible v := by
  unfold textWellFormed maxTextBytes at h
  simp only [Bool.and_eq_true, decide_eq_true_eq] at h
  exact lenWire h.1.2

private theorem tokenWire {v : String} (h : tokenWellFormed v = true) : stringWireAdmissible v := by
  unfold tokenWellFormed at h
  simp only [Bool.and_eq_true, decide_eq_true_eq] at h
  exact lenWire (Nat.le_trans h.1.2 (by decide))

private theorem usdWire : stringWireAdmissible "USD" := by
  apply stringWireAdmissible_of_length
  have hBytes := string_utf8_length_le "USD"
  have hChars : "USD".toList.length = 3 := by decide
  omega

private theorem nat8Wire {v b : Nat} (h : v ≤ b) (hb : b < 256 ^ 8) : nat8WireAdmissible v :=
  Nat.lt_of_le_of_lt h hb

private theorem cents8 {v : Nat} (h : v ≤ maxCents) : nat8WireAdmissible v := nat8Wire h maxCents_fits_u64
private theorem time8 {v : Nat} (h : v ≤ maxTime) : nat8WireAdmissible v := nat8Wire h maxTime_fits_u64
private theorem rev8 {v : Nat} (h : v ≤ maxRevision) : nat8WireAdmissible v :=
  nat8Wire h maxRevision_fits_u64

private theorem listWire {α : Type} {vs : List α} {P : α → Prop} (h : vs.length ≤ maxRows)
    (hP : ∀ x ∈ vs, P x) : wireListAdmissible vs P :=
  ⟨⟨h, Nat.lt_of_le_of_lt h (by decide)⟩, hP⟩

private theorem optIdWire {o : Option String} (h : optionalIdWellFormed o = true) :
    optionStringWireAdmissible o := by
  cases o with
  | none => trivial
  | some v => exact idWire h

private theorem digestWire {d : Bytes} (h : digestWellFormed d = true) : digestWireAdmissible d := by
  simpa [digestWellFormed, digestWireAdmissible] using h

private theorem contextWire {c : FinancialContext} (h : contextWellFormed c = true) :
    contextWireAdmissible c := by
  unfold contextWellFormed at h
  simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, and_assoc] at h
  obtain ⟨hI, hCur, _⟩ := h
  exact ⟨idWire (hI _ (by simp)), idWire (hI _ (by simp)), idWire (hI _ (by simp)),
    idWire (hI _ (by simp)), idWire (hI _ (by simp)), idWire (hI _ (by simp)),
    idWire (hI _ (by simp)), idWire (hI _ (by simp)), hCur ▸ usdWire⟩

private theorem authorityWire {a : TrustedAuthority} (h : authorityWellFormed a = true) :
    authorityWireAdmissible a := by
  unfold authorityWellFormed at h
  simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, and_assoc] at h
  obtain ⟨hId, -, hEpoch, hDig, -, -, hLen, -, hActors⟩ := h
  refine ⟨idWire hId, nat8Wire hEpoch maxCents_fits_u64, digestWire hDig,
    listWire hLen fun actor ha => ?_⟩
  have hA := hActors actor ha
  unfold authorityActorWellFormed at hA
  simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, and_assoc] at hA
  obtain ⟨hAId, -, hRLen, hRoles, -⟩ := hA
  exact ⟨idWire hAId, listWire hRLen fun r hr => tokenWire (hRoles r hr)⟩

private theorem packWire {p : ControlPack} (h : controlPackWellFormed p = true) :
    controlPackWireAdmissible p := by
  unfold controlPackWellFormed at h
  simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, and_assoc] at h
  obtain ⟨hI, hCur, -, hV, hSrc, hS, hE, hR, hA, -, -, hRoles, hTLen, hTests, hDig, -⟩ := h
  unfold sourceRefsWellFormed boundedTextList at hSrc
  simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true] at hSrc
  unfold authorizedRolesWellFormed at hRoles
  simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, and_assoc] at hRoles
  unfold timeWellFormed at hS hE hR hA
  simp only [decide_eq_true_eq] at hS hE hR hA
  exact ⟨idWire (hI _ (by simp)), idWire (hI _ (by simp)), idWire (hI _ (by simp)),
    idWire (hI _ (by simp)), idWire (hI _ (by simp)), hCur ▸ usdWire, rev8 hV,
    listWire hSrc.2.1 fun s hs => textWire (hSrc.2.2 s hs), time8 hS, time8 hE, time8 hR, time8 hA,
    idWire (hI _ (by simp)), idWire (hI _ (by simp)),
    listWire hRoles.1 fun s hs => tokenWire (hRoles.2.1 s hs),
    listWire hTLen fun s hs => textWire (hTests s hs), digestWire hDig⟩

private theorem obligationWire {o : Obligation} (h : obligationWellFormed o = true) :
    obligationWireAdmissible o := by
  unfold obligationWellFormed positiveAmountWellFormed amountWellFormed timeWellFormed at h
  simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, and_assoc] at h
  obtain ⟨hI, -, hOwed, hDue, -, hRule⟩ := h
  exact ⟨idWire (hI _ (by simp)), idWire (hI _ (by simp)), idWire (hI _ (by simp)),
    cents8 hOwed, time8 hDue, rev8 hRule⟩

private theorem paymentWire {c : FinancialContext} {p : Payment}
    (h : paymentWellFormed c p = true) : paymentWireAdmissible p := by
  unfold paymentWellFormed positiveAmountWellFormed amountWellFormed timeWellFormed at h
  simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, and_assoc] at h
  obtain ⟨hI, -, -, -, hAmt, hTime, hRev⟩ := h
  exact ⟨idWire (hI _ (by simp)), idWire (hI _ (by simp)), idWire (hI _ (by simp)),
    idWire (hI _ (by simp)), idWire (hI _ (by simp)), cents8 hAmt, time8 hTime, optIdWire hRev⟩

private theorem evidenceWire {c : FinancialContext} {e : EvidenceRecord}
    (h : evidenceWellFormed c e = true) : evidenceWireAdmissible e := by
  unfold evidenceWellFormed timeWellFormed at h
  simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, and_assoc] at h
  obtain ⟨hI, hKind, -, -, hA, hE, hR, -, hM, hRev, hSup⟩ := h
  refine ⟨idWire (hI _ (by simp)), idWire (hI _ (by simp)), idWire (hI _ (by simp)),
    tokenWire hKind, idWire (hI _ (by simp)), idWire (hI _ (by simp)), idWire (hI _ (by simp)),
    idWire (hI _ (by simp)), time8 hA, time8 hE, time8 hR, ?_, optIdWire hRev, optIdWire hSup⟩
  cases hAm : e.amountCents with
  | none => trivial
  | some a => rw [hAm] at hM; exact cents8 (by simpa [amountWellFormed] using hM)

private theorem optAllWire {o : Option String} (h : o.all idWellFormed = true) :
    optionStringWireAdmissible o := by
  cases o with
  | none => trivial
  | some v => exact idWire h

private theorem optNonEmptyWire {o : Option String} (h : (nonEmpty o).all idWellFormed = true) :
    optionStringWireAdmissible o := by
  cases o with
  | none => trivial
  | some v =>
    by_cases hv : v = ""
    · subst hv
      apply stringWireAdmissible_of_length
      have := string_utf8_length_le ""
      have h0 : "".toList.length = 0 := rfl
      omega
    · exact idWire (by simpa [nonEmpty, hv] using h)

private theorem opt63Wire {o : Option Nat} (h : o.all (· < 2 ^ 63) = true) :
    optionNatWireAdmissible o := by
  cases o with
  | none => trivial
  | some v => exact Nat.lt_of_lt_of_le (of_decide_eq_true h) (by decide)

private theorem readReceipt_append (k : Receipt) (rest : Bytes)
    (h1 : stringWireAdmissible k.paymentId) (h2 : nat8WireAdmissible k.recordedRevision)
    (h3 : optionStringWireAdmissible k.paysActionId) :
    readReceipt (encodeReceipt k ++ rest) = some (k, rest) := by
  unfold readReceipt encodeReceipt
  simp only [List.append_assoc]
  step (readString_encodeString_append _ _ h1)
  step (readNat8_natBE_append _ _ h2)
  step (readOptionString_encodeOptionString_append _ _ h3)
  rfl

private theorem readForeign_append (f : Foreign) (rest : Bytes) :
    readForeign (encodeForeign f ++ rest) = some (f, rest) := by
  cases f with | mk a b => cases a <;> cases b <;> rfl

private theorem readCommand_append (c : Command) (rest : Bytes) (h : commandWellFormed c = true) :
    readCommand (encodeCommand c ++ rest) = some (c, rest) := by
  unfold commandWellFormed at h
  cases c with
  | record c =>
    simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true, and_assoc] at h
    obtain ⟨hI, hL, hP, hAmt, hTime⟩ := h
    unfold encodeCommand readCommand
    simp only [List.cons_append, List.append_assoc]
    step rfl
    rw [if_pos (by decide)]
    step (readString_encodeString_append _ _ (idWire (hI _ (by simp))))
    step (readString_encodeString_append _ _ (idWire (hI _ (by simp))))
    step (readString_encodeString_append _ _ (idWire (hI _ (by simp))))
    step (readString_encodeString_append _ _ (idWire (hI _ (by simp))))
    step (readString_encodeString_append _ _ (idWire (hI _ (by simp))))
    step (readOptionString_encodeOptionString_append _ _ (optNonEmptyWire hL))
    step (readNat8_natBE_append _ _ (cents8 hAmt))
    step (readNat8_natBE_append _ _ (Nat.lt_of_lt_of_le hTime (by decide)))
    step (readOptionString_encodeOptionString_append _ _ (optAllWire hP))
    rfl
  | reverse c =>
    simp only [Bool.and_eq_true, and_assoc] at h
    obtain ⟨hP, hE, hO, hT⟩ := h
    unfold encodeCommand readCommand
    simp only [List.cons_append, List.append_assoc]
    step rfl
    rw [if_neg (by decide), if_pos (by decide)]
    step (readString_encodeString_append _ _ (idWire hP))
    step (readString_encodeString_append _ _ (idWire hE))
    step (readOptionString_encodeOptionString_append _ _ (optNonEmptyWire hO))
    step (readOptionNat_encodeOptionNat_append _ _ (opt63Wire hT))
    rfl


private theorem drop_hdr {α : Type} (l : List α) (a : α) (b : List α) :
    (l ++ a :: b).drop (l.length + 1) = b := by
  have h := List.drop_left (l₁ := l ++ [a]) (l₂ := b)
  simpa [List.length_append] using h

private theorem readOpt_append {α : Type} {f : Bytes → Option (α × Bytes)} {g : α → Bytes}
    {o : Option α} (rest : Bytes) (h : ∀ a, o = some a → ∀ t, f (g a ++ t) = some (a, t)) :
    readOpt f (encodeOpt g o ++ rest) = some (o, rest) := by
  cases o with
  | none => simp [encodeOpt, readOpt, readByte]
  | some a => simp [encodeOpt, readOpt, readByte, h a rfl rest]

private theorem all_some {α : Type} {o : Option α} {p : α → Bool} (h : o.all p = true) {a : α}
    (ha : o = some a) : p a = true := by
  subst ha; exact h

private theorem encodeList_def {α : Type} (enc : α → Bytes) (vs : List α) :
    encodeList enc vs = natBE 2 vs.length ++ vs.flatMap enc := rfl

private theorem readContribution_append (x : EvalContribution) (t : Bytes)
    (h1 : nat8WireAdmissible x.time) (h2 : stringWireAdmissible x.identity)
    (h3 : nat8WireAdmissible x.amountCents) :
    readContribution (encodeContribution x ++ t) = some (x, t) := by
  unfold readContribution encodeContribution
  simp only [List.append_assoc]
  step (readNat8_natBE_append _ _ h1)
  step (readString_encodeString_append _ _ h2)
  step (readNat8_natBE_append _ _ h3)
  rfl

private theorem readRequestPaid_append (x : RequestPaid) (t : Bytes)
    (h1 : stringWireAdmissible x.actionId) (h2 : nat8WireAdmissible x.amountCents)
    (h3 : nat8WireAdmissible x.paidCents) :
    readRequestPaid (encodeRequestPaid x ++ t) = some (x, t) := by
  unfold readRequestPaid encodeRequestPaid
  simp only [List.append_assoc]
  step (readString_encodeString_append _ _ h1)
  step (readNat8_natBE_append _ _ h2)
  step (readNat8_natBE_append _ _ h3)
  rfl

private theorem readEnv_append (e : Env) (rest : Bytes) (h : envWellFormed e = true) :
    readEnv (encodeEnv e ++ rest) = some (e, rest) := by
  simp only [envWellFormed, Bool.and_eq_true, decide_eq_true_eq, and_assoc] at h
  obtain ⟨hC, hA, hP, hO, hB, -, hT, -⟩ := h
  unfold readEnv encodeEnv
  simp only [List.append_assoc]
  step (decodeContext_encodeContext_append _ _ (contextWire hC))
  step (decodeAuthority_encodeAuthority_append _ _ (authorityWire hA))
  step (decodeControlPack_encodeControlPack_append _ _ (packWire hP))
  step (decodeObligation_encodeObligation_append _ _ (obligationWire hO))
  step (readNat8_natBE_append _ _ (rev8 (Nat.le_of_lt hB)))
  step (readNat8_natBE_append _ _ (time8 (by simpa [timeWellFormed] using hT)))
  rfl

private theorem env_before_lt {e : Env} (h : envWellFormed e = true) :
    e.beforeRevision < maxRevision := by
  simp only [envWellFormed, Bool.and_eq_true, decide_eq_true_eq, and_assoc] at h
  obtain ⟨-, -, -, -, hB, -⟩ := h
  exact hB

private theorem readItemState_append (s : ItemState) (rest : Bytes) (h : stateWellFormed s = true) :
    readItemState (encodeItemState s ++ rest) = some (s, rest) := by
  simp only [stateWellFormed, Bool.and_eq_true, decide_eq_true_eq, and_assoc] at h
  obtain ⟨hRev, hCash, hCl, hLaw, hCN, hCon, hCC, hEL, hEC, hRL, hReq, hAB⟩ := h
  simp only [canonicalIdList, Bool.and_eq_true, decide_eq_true_eq] at hEC
  unfold readItemState encodeItemState
  rw [encodeList_def encodeContribution s.contributions]
  simp only [List.append_assoc, List.cons_append]
  step (readNat8_natBE_append _ _ (rev8 (Nat.le_of_lt hRev)))
  step (readNat8_natBE_append _ _ (cents8 hCash))
  step (readNat8_natBE_append _ _ (cents8 hCl))
  step (readNat8_natBE_append _ _ (cents8 hLaw))
  step (readNatBE_natBE_append 2 s.contributions.length _
    (Nat.lt_of_le_of_lt hCN (by unfold maxRows; decide)))
  rw [if_neg (by omega)]
  step (readMany_flatMap_append_of_mem encodeContribution readContribution s.contributions _
    (fun x hx t => by
      have hx2 := List.all_eq_true.mp hCon x hx
      simp only [Bool.and_eq_true, decide_eq_true_eq] at hx2
      exact readContribution_append x t (time8 (by simpa [timeWellFormed] using hx2.1.1))
        (idWire hx2.1.2) (cents8 hx2.2)))
  step rfl
  step (decodeCaseStatus_encodeCaseStatus _)
  step rfl
  step (decodeDeliveryStatus_encodeDeliveryStatus _)
  step (readNatBE_natBE_append 2 s.conflictCount _ (Nat.lt_of_le_of_lt hCC maxRows_fits_u16))
  step (readList_encodeString_append s.evidenceIds _ hEL
    (fun v hv => idWire (List.all_eq_true.mp hEC.1.2 v hv)))
  step (readList_encodeList_append_of_mem encodeRequestPaid readRequestPaid s.requests _ hRL
    (Nat.lt_of_le_of_lt hRL maxRows_fits_u16)
    (fun q hq t => by
      have hq2 := List.all_eq_true.mp hReq q hq
      simp only [Bool.and_eq_true, decide_eq_true_eq] at hq2
      exact readRequestPaid_append q t (idWire hq2.1.1) (cents8 hq2.1.2) (cents8 hq2.2)))
  step (readNatBE_natBE_append 4 s.anchorBytes _
    (Nat.lt_of_le_of_lt hAB (by unfold maxTotalEncodedBytes; decide)))
  rfl

private theorem parseFormB_encode (v : PaymentView) (hw : viewWellFormed v = true) :
    parseFormB (encodeFormB v) = some v := by
  simp only [viewWellFormed, Bool.and_eq_true, decide_eq_true_eq, and_assoc] at hw
  obtain ⟨hEnv, hSt, hPL, -, hPA, hId, hOr, hEv, hCmd, hEx⟩ := hw
  have hB := env_before_lt hEnv
  unfold parseFormB encodeFormB
  simp only [List.append_assoc, List.cons_append, List.nil_append]
  rw [drop_hdr]
  step (readEnv_append _ _ hEnv)
  step (readItemState_append _ _ hSt)
  step (readList_encodeList_append_of_mem encodeEvidence decodeEvidence v.pending _ hPL
    (Nat.lt_of_le_of_lt hPL maxRows_fits_u16)
    (fun e he t => decodeEvidence_encodeEvidence_append e t
      (evidenceWire (List.all_eq_true.mp hPA e he))))
  step (readOpt_append _ (fun a ha t => by
    have hr := all_some hId ha
    simp only [Bool.and_eq_true, decide_eq_true_eq, and_assoc] at hr
    obtain ⟨hp, hk, hlt, hpa⟩ := hr
    simp only [List.append_assoc]
    step (decodePayment_encodePayment_append _ _ (paymentWire hp))
    step (readReceipt_append _ _ (by rw [hk]; exact (paymentWire hp).1) (rev8 (by omega))
      (optAllWire hpa))
    rfl))
  step (readOpt_append _ (fun a ha t => by
    have hr := all_some hOr ha
    simp only [Bool.and_eq_true, decide_eq_true_eq, and_assoc] at hr
    obtain ⟨hp, hk, hlt, hpa, hev⟩ := hr
    simp only [List.append_assoc]
    step (decodePayment_encodePayment_append _ _ (paymentWire hp))
    step (readReceipt_append _ _ (by rw [hk]; exact (paymentWire hp).1) (rev8 (by omega))
      (optAllWire hpa))
    step (readOpt_append _ (fun e he t => decodeEvidence_encodeEvidence_append e t
      (evidenceWire (all_some hev he))))
    rfl))
  step (readOpt_append _ (fun e he t => decodeEvidence_encodeEvidence_append e t
    (evidenceWire (all_some hEv he))))
  step (readBool_encodeBool_append _ _)
  step (readForeign_append _ _)
  step (readOptionNat_encodeOptionNat_append _ _ (opt63Wire hEx))
  have hc := readCommand_append v.command [] hCmd
  rw [List.append_nil] at hc
  step hc
  rfl

end FormBRoundTrip

theorem decodePaymentItem_encode (v : PaymentView) (hw : viewWellFormed v = true)
    (hc : coherent v = true) : decodePaymentItem (encodeFormB v) = some v := by
  have hp := parseFormB_encode v hw
  have h1 : (encodeFormB v).drop paymentMagic.length =
      UInt8.ofNat 2 :: (encodeFormB v).drop (paymentMagic.length + 1) := by
    unfold encodeFormB
    simp only [List.append_assoc, List.cons_append, List.nil_append]
    rw [List.drop_left, drop_hdr]
  unfold decodePaymentItem
  rw [h1]
  simp [hp, hw, hc]

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

/-! ## Why `chain_fold_eq_full` has `hw`, and why `coherent` skips REVERSED rows

    `hw`: with only the other hypotheses, an ill-formed command (empty payment id) makes the
    reference refuse (POST_REJECTED) while the view mutates. No worker input carries one
    (`decodePaymentItem_command`). `coherent`: a payment may share its (time, id, amount)
    contribution with an authorized determination. The `y` chain reaches that state through the
    reference ledger; the view agrees at every step, and the reversed row decodes in both forms. -/

private def badCall : Call := ⟨kNow, some 0, .record { kRec with paymentId := "" }⟩
#guard financialInputWellFormed kL0.input && receiptsWellFormed kL0.input kL0.receipts
#guard decide (kL0.input.evaluatedAt ≤ kNow) && decide (kNow < 2 ^ 63)
#guard decide (kL0.input.beforeRevision + 1 ≤ maxRevision)
#guard commandWellFormed badCall.command == false
#guard match viewOfAnchor (kL0.request badCall) with
  | none => false
  | some v => decide (absorbed v = v) && !decide (some (stepView v) = project (kL0.request badCall) (outcome kL0 badCall))

private def xCmd : RecordCommand :=
  { paymentId := "determination:action:h:offset", evidenceId := "evidence:cash", commonOriginId := "origin:cash:h",
    sourceId := "fixture-payment-file", sourceVersion := "cash-v1", localRef := none, amountCents := 300_000,
    eventAt := 1_774_864_800_000, paysActionId := none }
private def yL0 : Ledger :=
  ⟨{ katAuthorized with beforeRevision := 2, payments := [], evidence := [katOffsetEvidence] }, []⟩
private def yRec : Call := ⟨1_774_922_400_000, none, .record xCmd⟩
private def yRev : Call := ⟨1_774_922_401_000, none, .reverse
  { paymentId := xCmd.paymentId, evidenceId := "evidence:reversal", commonOriginId := none, eventAt := some 1_774_900_000_000 }⟩
private def yL1 : Ledger := step yL0 yRec
private def yL2 : Ledger := step yL1 yRev
private def yRetry : Call := { yRec with now := 1_774_922_402_000 }

#guard financialInputWellFormed yL0.input && requestWellFormed (yL2.request yRetry)
#guard kind (outcome yL0 yRec) == "RECORDED" && agrees yL0 yRec
#guard kind (outcome yL1 yRev) == "REVERSED" && agrees yL1 yRev
#guard agrees yL2 yRetry && formBRoundTrips yL2 yRetry
#guard ((decodePaymentItem (encodePaymentRequest (yL2.request yRetry))).map coherent) == some true

/-- info: 'BlindLedger.Financial.Payment.Rev12.paymentRespond_decode_none' depends on axioms: [propext,
 Classical.choice,
 Quot.sound] -/
#guard_msgs in #print axioms paymentRespond_decode_none
/-- info: 'BlindLedger.Financial.Payment.Rev12.decodeStepOutcome_encode' depends on axioms: [propext,
 Classical.choice,
 Quot.sound] -/
#guard_msgs in #print axioms decodeStepOutcome_encode
/-- info: 'BlindLedger.Financial.Payment.Rev12.refusals_complete' depends on axioms: [propext] -/
#guard_msgs in #print axioms refusals_complete
/-- info: 'BlindLedger.Financial.Payment.Rev12.absorb_summarize' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms absorb_summarize
/-- info: 'BlindLedger.Financial.Payment.Rev12.evaluateState_summarize' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms evaluateState_summarize
/-- info: 'BlindLedger.Financial.Payment.Rev12.state_requests_paid' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms state_requests_paid
/-- info: 'BlindLedger.Financial.Payment.Rev12.anchorItem_fits' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms anchorItem_fits
/-- info: 'BlindLedger.Financial.Payment.Rev12.anchorItem_length' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms anchorItem_length
/-- info: 'BlindLedger.Financial.Payment.Rev12.step_anchor_fits' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms step_anchor_fits
/-- info: 'BlindLedger.Financial.Payment.Rev12.decodePaymentItem_encode' depends on axioms: [propext,
 Classical.choice,
 Quot.sound] -/
#guard_msgs in #print axioms decodePaymentItem_encode
/-- info: 'BlindLedger.Financial.Payment.Rev12.run_conflict_retry_unchanged' depends on axioms: [propext,
 Classical.choice,
 Quot.sound] -/
#guard_msgs in #print axioms run_conflict_retry_unchanged
/-- info: 'BlindLedger.Financial.Payment.Rev12.step_wellFormed' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms step_wellFormed
/-- info: 'BlindLedger.Financial.Payment.Rev12.record_link_within_shortfall' depends on axioms: [propext,
 Classical.choice,
 Quot.sound] -/
#guard_msgs in #print axioms record_link_within_shortfall
/-- info: 'BlindLedger.Financial.Payment.Rev12.run_linked_within_shortfall' depends on axioms: [propext,
 Classical.choice,
 Quot.sound] -/
#guard_msgs in #print axioms run_linked_within_shortfall
/-- info: 'BlindLedger.Financial.Payment.Rev12.run_balance_identity' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms run_balance_identity
/-- info: 'BlindLedger.Financial.Payment.Rev12.paymentTransition_shadow_refused' depends on axioms: [propext,
 Classical.choice,
 Quot.sound] -/
#guard_msgs in #print axioms paymentTransition_shadow_refused
/-- info: 'BlindLedger.Financial.Payment.Rev12.run_record_retry_duplicate' depends on axioms: [propext,
 Classical.choice,
 Quot.sound] -/
#guard_msgs in #print axioms run_record_retry_duplicate
/-- info: 'BlindLedger.Financial.Payment.Rev12.run_reverse_retry_duplicate' depends on axioms: [propext,
 Classical.choice,
 Quot.sound] -/
#guard_msgs in #print axioms run_reverse_retry_duplicate
/-- info: 'BlindLedger.Financial.Payment.Rev12.decodePaymentItem_command' depends on axioms: [propext,
 Classical.choice,
 Quot.sound] -/
#guard_msgs in #print axioms decodePaymentItem_command
/-- info: 'BlindLedger.Financial.Payment.Rev12.decodePaymentItem_coherent' depends on axioms: [propext,
 Classical.choice,
 Quot.sound] -/
#guard_msgs in #print axioms decodePaymentItem_coherent

/-- info: 'BlindLedger.Financial.Payment.Rev12.stepView_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms stepView_eq
/-- info: 'BlindLedger.Financial.Payment.Rev12.chain_fold_eq_full' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms chain_fold_eq_full

end BlindLedger.Financial.Payment.Rev12
