import BlindLedger.Financial.Payment.Open

namespace BlindLedger.Financial.Payment

open BlindLedger.Financial BlindLedger.Financial.CorrectionTransition

/-- The row images written (named so the laws can state them). -/
def recordedPayment (i : FinancialInput) (c : RecordCommand) : Payment :=
  { paymentId := c.paymentId, obligationId := i.context.obligationId, itemId := i.context.itemId,
    evidenceId := c.evidenceId, commonOriginId := c.commonOriginId, amountCents := c.amountCents,
    eventAt := c.eventAt, reversalEvidenceId := none, status := .ACTIVE }

def recordedReceipt (i : FinancialInput) (c : RecordCommand) : Receipt :=
  { paymentId := c.paymentId, recordedRevision := i.beforeRevision, paysActionId := c.paysActionId }

def reversedImage (p : Payment) (c : ReverseCommand) : Payment :=
  { p with status := .REVERSED, reversalEvidenceId := some c.evidenceId }

def conflictImage (i : FinancialInput) (c : RecordCommand) (p : Payment)
    (conflictId : String) : FinancialConflict :=
  { conflictId := conflictId, obligationId := i.context.obligationId,
    commonOriginId := c.commonOriginId, existingPaymentId := p.paymentId,
    candidateEvidenceId := c.evidenceId, existingAmountCents := p.amountCents,
    candidateAmountCents := c.amountCents, reason := "CONFLICTING_COMMON_ORIGIN_AMOUNT",
    visibleAt := i.evaluatedAt }

/-- A record whose payment id is already stored: a retry (III.3), never a write. -/
def recordRetry (r : PaymentRequest) (c : RecordCommand) (p : Payment) : PaymentOutcome :=
  let i := r.input
  match findEvidence i.evidence c.evidenceId with
  | none => .refused .REQUEST_CONFLICT
  | some s =>
    let e := confirmation i c s.receivedAt
    match formRefusal e with
    | some f => .refused f
    | none =>
      if c.eventAt > s.receivedAt then .refused .CHRONOLOGY else
      match receiptOf r.receipts p.paymentId with
      | none => .refused .REQUEST_CONFLICT  -- unreachable after decode (receipts aligned)
      | some k =>
        if r.expectedRevision = some k.recordedRevision ∧ k.paysActionId = c.paysActionId ∧
           p.evidenceId = c.evidenceId ∧ p.commonOriginId = c.commonOriginId ∧
           p.amountCents = c.amountCents ∧ p.eventAt = c.eventAt ∧ e = s
        then .duplicate (some c.paymentId) else .refused .REQUEST_CONFLICT

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

end BlindLedger.Financial.Payment
