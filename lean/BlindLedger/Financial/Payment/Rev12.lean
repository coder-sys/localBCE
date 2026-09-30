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
      let linkOk : Option Refusal := c.paysActionId.bind fun a =>
        match i.actions.find? (fun x => x.actionId = a && x.kind = "CORRECTION_PAYMENT_REQUEST") with
        | none => some .LINK_UNKNOWN
        | some req =>
          -- R1: within the request and within the balance still owed
          if CorrectionTransition.linkedActivePaidCents i.payments (linksOf r.receipts) a + c.amountCents >
               req.amountCents || !(evaluate i).any (c.amountCents ≤ ·.shortfallCents)
          then some .LINK_EXCEEDS_UNPAID else none
      match linkOk with
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
      let linkOk : Option Refusal := c.paysActionId.bind fun a =>
        match s.requests.find? (·.actionId = a) with
        | none => some .LINK_UNKNOWN
        | some q =>
          if q.paidCents + c.amountCents > q.amountCents ||
             !(evaluateState v.env s).any (c.amountCents ≤ ·.shortfallCents)
          then some .LINK_EXCEEDS_UNPAID else none
      match linkOk with
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

/-! ## 16.2-16.6, 16.9 Corrected and folded-in statements -/

-- 16.2 item 1 (5.3): exact, hypothesis-free
theorem run_conflict_retry_unchanged (L : Ledger) (c : RecordCommand) (now : Nat)
    (exp exp' : Option Nat) (calls : List Call) (now' : Nat)
    (h : ∃ w post res, outcome L ⟨now, exp, .record c⟩ = .mutated .CONFLICT_RECORDED w post res) :
    outcome (run (step L ⟨now, exp, .record c⟩) calls) ⟨now', exp', .record c⟩ =
      if (findPayment (run (step L ⟨now, exp, .record c⟩) calls).input.payments c.paymentId).isSome
      then .refused .REQUEST_CONFLICT else .conflictUnchanged (conflictIdOf L.input c) := sorry

-- 16.2 item 2 (5.6)
theorem step_wellFormed (L : Ledger) (hL : ledgerWellFormed L) (c : Call) (hc : clocksOk L [c])
    (hR : L.input.beforeRevision + 1 < maxRevision) : ledgerWellFormed (step L c) := sorry

-- 16.2 item 3 (5.6): request-level; stepView_state is deleted (it is the `project` clause)
theorem stepView_eq {r : PaymentRequest} (hr : requestWellFormed r = true)
    (hb : r.inputBytes = (rawEncodeFinancialInput r.input).length) {v : PaymentView}
    (hv : Faithful r v) : some (stepView v) = project r (paymentTransition r) := sorry

theorem absorb_summarize (L : Ledger) (c : Call) {pid e post}
    (h : outcome L c = .alias pid e post) :
    (summaryOf L.input L.receipts).map (absorb · [e]) = summaryOf (step L c).input (step L c).receipts :=
  sorry

theorem chain_fold_eq_full (L : Ledger) (hL : ledgerWellFormed L) (calls : List Call)
    (hc : clocksOk L calls) (hR : L.input.beforeRevision + calls.length ≤ maxRevision)
    (vs : List PaymentView) (hv : ChainFaithful L calls vs) :
    vs.map (some ∘ stepView) =
      ((ledgers L calls).zip calls).map fun M => project (M.1.request M.2) (outcome M.1 M.2) := sorry

theorem evaluateState_summarize {i : FinancialInput} {rs b s} (hw : financialInputWellFormed i = true)
    (h : summarize i rs b = some s) : evaluateState (envOf i) s = evaluate i := sorry

theorem state_requests_paid (L : Ledger) {s : ItemState} (h : summaryOf L.input L.receipts = some s)
    (a : RequestPaid) (ha : a ∈ s.requests) : a.paidCents = ledgerPaid L a.actionId := sorry

-- 16.2 item 4 (5.1, D3)
theorem anchorItem_fits {v : PaymentView} {k w s r} (h : stepView v = .mutated k w s r) :
    s.anchorBytes + maxCallTailBytes ≤ maxTotalEncodedBytes := sorry

theorem anchorItem_length (r : PaymentRequest) (hc : commandWellFormed r.command = true) :
    (encodePaymentRequest r).length ≤ anchorItemLength r.input r.receipts + maxCallTailBytes := sorry

theorem step_anchor_fits (L : Ledger) (hL : ledgerWellFormed L) (c : Call)
    (hfit : anchorItemLength L.input L.receipts + maxCallTailBytes ≤ maxTotalEncodedBytes) :
    anchorItemLength (step L c).input (step L c).receipts + maxCallTailBytes ≤ maxTotalEncodedBytes :=
  sorry

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
      .duplicate (some c.paymentId) := sorry

theorem run_reverse_retry_duplicate (L : Ledger) (c : ReverseCommand) (now : Nat)
    (exp exp' : Option Nat) (calls : List Call) (now' : Nat) (hnow : now ≤ now')
    (h : ∃ w post res, outcome L ⟨now, exp, .reverse c⟩ = .mutated .REVERSED w post res) :
    outcome (run (step L ⟨now, exp, .reverse c⟩) calls) ⟨now', exp', .reverse c⟩ = .duplicate none :=
  sorry

-- 16.9 R1 (5.2) as signed
theorem record_link_within_shortfall {r : PaymentRequest} {c w post result a}
    (hc : r.command = .record c) (ha : c.paysActionId = some a)
    (h : paymentTransition r = .mutated .RECORDED w post result) :
    ∃ before, evaluate r.input = some before ∧ c.amountCents ≤ before.shortfallCents := sorry

def linkedRecorded : PaymentOutcome → Nat
  | .mutated .RECORDED w _ _ =>
      if (w.receipt.bind (·.paysActionId)).isSome then (w.payment.map (·.amountCents)).getD 0 else 0
  | _ => 0

-- 16.9 R1-run (5.4), corrected: the balance is read from the request the n-th call saw
theorem run_linked_within_shortfall (L : Ledger) (calls : List Call) (n : Nat) (o : PaymentOutcome)
    (ho : (trace L calls)[n]? = some o) (hl : linkedRecorded o ≠ 0) :
    ∃ c before, calls[n]? = some c ∧
      evaluate ((run L (calls.take n)).request c).input = some before ∧
      linkedRecorded o ≤ before.shortfallCents := sorry

-- 16.9 E6 (5.4): hL, hc and hClaims dropped (claims and obligation are frame)
theorem run_balance_identity (L : Ledger) (calls : List Call) {r r' : FinancialResult}
    (h : evaluate L.input = some r) (h' : evaluate (run L calls).input = some r') :
    r'.shortfallCents + r.overageCents + recordedCents (trace L calls) =
      r.shortfallCents + r'.overageCents + reversedOutcomeCents (trace L calls) := sorry

-- 16.9 A2 (5.2), strengthened to aliases
theorem paymentTransition_shadow_refused (r : PaymentRequest)
    (hShadow : r.input.context.mode = .SHADOW) :
    (∀ k w post result, paymentTransition r ≠ .mutated k w post result) ∧
      ∀ pid e post, paymentTransition r ≠ .alias pid e post := sorry

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
