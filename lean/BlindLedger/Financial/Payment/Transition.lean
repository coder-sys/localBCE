import BlindLedger.Financial.Payment.Types

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

end BlindLedger.Financial.Payment
