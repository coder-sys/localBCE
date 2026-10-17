import BlindLedger.Financial.Payment.Transition

namespace BlindLedger.Financial.Payment

open BlindLedger.Financial BlindLedger.Financial.CorrectionTransition

/-! Step 1's payment model, kept only as the proof-only reference that the live model is checked
    against (`Payment.Laws`: a non-refused live outcome is the `Base` outcome).  It is in no
    executable's import closure. -/

namespace Base

def withinCapacity (r : PaymentRequest) (w : Writes) : Bool :=
  r.inputBytes + addedBytes r.input w ≤ maxTotalEncodedBytes

/-- Every write that changes a value ends here: capacity, then Lean's own post-state
    must evaluate (evaluate re-checks well-formedness). Fail closed otherwise. -/
def mutate (r : PaymentRequest) (k : Mutation) (w : Writes) : PaymentOutcome :=
  if !withinCapacity r w then .refused .CAPACITY else
  let post := applyWrites r.input w
  match evaluate post with
  | none => .refused .POST_REJECTED
  | some result => .mutated k w post result

/-- An alias writes one evidence row and no evaluation (a repeat changes no value),
    but its post-state must still be well-formed, so the next snapshot decodes. -/
def aliasOf (r : PaymentRequest) (pid : String) (e : EvidenceRecord) : PaymentOutcome :=
  let w : Writes := { evidence := some e, payment := none, conflict := none, receipt := none }
  if !withinCapacity r w then .refused .CAPACITY else
  let post := applyWrites r.input w
  if financialInputWellFormed post then .alias pid e post else .refused .POST_REJECTED

/-- A record with a fresh payment id: duplicate origin, conflict, alias or a new payment. -/
def recordNew (r : PaymentRequest) (c : RecordCommand) : PaymentOutcome :=
  let i := r.input
  let now := i.evaluatedAt
  let existing := i.payments.find? (·.commonOriginId = c.commonOriginId)
  let same := existing.any (·.amountCents = c.amountCents)
  let stored := findEvidence i.evidence c.evidenceId
  let prior := same && (stored.isSome || r.foreign.evidenceId)
  let conflictId := "conflict:" ++ i.context.itemId ++ ":" ++ c.commonOriginId ++ ":" ++ c.evidenceId
  let reversedBefore := existing.any fun p => p.status = .REVERSED &&
    ((p.reversalEvidenceId.bind (findEvidence i.evidence)).any fun v => v.eventAt < c.eventAt)
  if same && !prior && reversedBefore then .refused .ORIGIN_REVERSED else
  -- D1: an exact retry of a visible conflict is CONFLICT at any revision (III.3)
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
          if linkedActivePaidCents i.payments (linksOf r.receipts) a + c.amountCents > req.amountCents
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
    | .same _ => .duplicate none                  -- retry ignores the revision (III.3)
    | .fresh =>
      if !revisionOk r then .refused .REVISION_CONFLICT else
      if p.status = .REVERSED then .refused .ALREADY_REVERSED else
      mutate r .REVERSED
        { evidence := some e, conflict := none, receipt := none, payment := some (reversedImage p c) }

def paymentTransition (r : PaymentRequest) : PaymentOutcome :=
  match r.command with
  | .record c => decideRecord r c
  | .reverse c => decideReverse r c

end Base

end BlindLedger.Financial.Payment
