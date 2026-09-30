import BlindLedger.Financial.Evaluation
import BlindLedger.Financial.CorrectionTransition.PaidSum

namespace BlindLedger.Financial.Payment

open BlindLedger.Financial BlindLedger.Financial.CorrectionTransition

/-! Lean-live M3 (docs: rrb/designs/lean-live-m3-v1.md, sections 2.1, 2.2, 2.4): the payment
    commands' types and helpers.  Nothing here is called by the worker yet. -/

/-- A payment row's stored PAYMENT_RECEIVED event: the revision it was recorded at
    (the event's before_revision) and the correction request it pays, if any. -/
structure Receipt where
  paymentId : String
  recordedRevision : Nat
  paysActionId : Option String
deriving DecidableEq, Repr

structure RecordCommand where
  paymentId : String
  evidenceId : String
  commonOriginId : String
  sourceId : String
  sourceVersion : String
  localRef : Option String        -- none or "" means `payment:{paymentId}`
  amountCents : Nat
  eventAt : Nat
  paysActionId : Option String
deriving DecidableEq, Repr

structure ReverseCommand where
  paymentId : String
  evidenceId : String
  commonOriginId : Option String  -- none or "" means `reversal:{paymentId}`
  eventAt : Option Nat            -- none: the stored reversal evidence's time, else now
deriving DecidableEq, Repr

inductive Command where
  | record (c : RecordCommand)
  | reverse (c : ReverseCommand)
deriving DecidableEq, Repr

/-- Carried facts: the id is a row of another obligation (payments) or item (evidence). -/
structure Foreign where
  paymentId : Bool
  evidenceId : Bool
deriving DecidableEq, Repr

structure PaymentRequest where
  input : FinancialInput      -- the pre-state; now = input.evaluatedAt
  inputBytes : Nat            -- length of its BLFIN02 encoding (set by the decoder)
  receipts : List Receipt     -- one per input.payments row, same order
  foreign : Foreign
  expectedRevision : Option Nat
  command : Command
deriving Repr

inductive Refusal where
  | AMOUNT_ZERO | REQUEST_CONFLICT | ORIGIN_REVERSED | REVISION_CONFLICT
  | EVIDENCE_CONFLICT | CHRONOLOGY | LINK_UNKNOWN | LINK_EXCEEDS_UNPAID
  | PAYMENT_MISSING | ALREADY_REVERSED | ORIGIN_FORM | LOCAL_REF_FORM
  | CONFLICT_ID_FORM | CAPACITY | POST_REJECTED | SHADOW_READ_ONLY
deriving DecidableEq, Repr

inductive Mutation where
  | RECORDED | REVERSED | CONFLICT_RECORDED
deriving DecidableEq, Repr

/-- Row images the adapter writes; nothing else is written. -/
structure Writes where
  evidence : Option EvidenceRecord      -- inserted
  payment : Option Payment  -- inserted (RECORDED) or replaced (REVERSED)
  conflict : Option FinancialConflict   -- inserted
  receipt : Option Receipt              -- RECORDED only
deriving DecidableEq, Repr

inductive PaymentOutcome where
  | mutated (kind : Mutation) (writes : Writes) (post : FinancialInput) (result : FinancialResult)
  | alias (paymentId : String) (evidence : EvidenceRecord) (post : FinancialInput)
  | duplicate (paymentId : Option String)   -- none for a reversal retry
  | conflictUnchanged (conflictId : String)
  | refused (reason : Refusal)

/-! ## Helpers -/

def insertBy {α : Type} (key : α → String) (row : α) : List α → List α
  | [] => [row]
  | x :: xs => if key row < key x then row :: x :: xs else x :: insertBy key row xs

def activeCents (ps : List Payment) : Nat :=
  ((ps.filter (·.status = .ACTIVE)).map Payment.amountCents).sum
def reversedCents (ps : List Payment) : Nat :=
  ((ps.filter (·.status = .REVERSED)).map Payment.amountCents).sum

def linksOf (rs : List Receipt) : List PaymentLink :=
  rs.filterMap fun r => r.paysActionId.map fun a => { paymentId := r.paymentId, actionId := a }

def receiptOf (rs : List Receipt) (id : String) : Option Receipt := rs.find? (·.paymentId = id)

def revisionOk (r : PaymentRequest) : Bool :=
  r.expectedRevision.all (· = r.input.beforeRevision)

def nonEmpty (s : Option String) : Option String := s.filter (· ≠ "")

def confirmation (i : FinancialInput) (c : RecordCommand) (receivedAt : Nat) : EvidenceRecord :=
  { evidenceId := c.evidenceId, obligationId := i.context.obligationId, itemId := i.context.itemId,
    kind := "PAYMENT_CONFIRMATION", commonOriginId := c.commonOriginId,
    sourceId := c.sourceId, sourceVersion := c.sourceVersion,
    localRef := (nonEmpty c.localRef).getD ("payment:" ++ c.paymentId),
    applicableAt := c.eventAt, eventAt := c.eventAt, receivedAt,
    amountCents := some c.amountCents, reversalOf := none, supersedes := none }

def reversalRecord (i : FinancialInput) (c : ReverseCommand) (p : Payment)
    (time : Nat) : EvidenceRecord :=
  { evidenceId := c.evidenceId, obligationId := i.context.obligationId, itemId := i.context.itemId,
    kind := "PAYMENT_REVERSAL",
    commonOriginId := (nonEmpty c.commonOriginId).getD ("reversal:" ++ p.paymentId),
    sourceId := "synthetic-payment-source", sourceVersion := "fixture-v1",
    localRef := "reversal:" ++ p.paymentId, applicableAt := time, eventAt := time,
    receivedAt := i.evaluatedAt, amountCents := some p.amountCents,
    reversalOf := some p.paymentId, supersedes := none }

/-- The fields Lean builds itself, checked in Python's `EvidenceRecord` order. -/
def formRefusal (e : EvidenceRecord) : Option Refusal :=
  if !idWellFormed e.commonOriginId then some .ORIGIN_FORM
  else if !idWellFormed e.localRef then some .LOCAL_REF_FORM
  else none

inductive Slot where
  | fresh | same (stored : EvidenceRecord) | clash

def Slot.isFresh : Slot → Bool
  | .fresh => true
  | _ => false

def Slot.isSame : Slot → Bool
  | .same _ => true
  | _ => false

/-- `_insert_evidence`: a stored id is a retry iff the new record, given the stored
    received time, equals the stored record and its event is not after that time. -/
def evidenceSlot (r : PaymentRequest) (e : EvidenceRecord) : Slot :=
  if r.foreign.evidenceId then .clash else
  match findEvidence r.input.evidence e.evidenceId with
  | none => .fresh
  | some s => if e.eventAt ≤ s.receivedAt ∧ { e with receivedAt := s.receivedAt } = s
              then .same s else .clash

def applyWrites (i : FinancialInput) (w : Writes) : FinancialInput :=
  { i with
    evidence := (w.evidence.map fun e => insertBy EvidenceRecord.evidenceId e i.evidence).getD i.evidence
    payments := match w.payment with
      | none => i.payments
      | some p => if (findPayment i.payments p.paymentId).isSome
                  then i.payments.map fun q => if q.paymentId = p.paymentId then p else q
                  else insertBy Payment.paymentId p i.payments
    conflicts := (w.conflict.map fun x => insertBy FinancialConflict.conflictId x i.conflicts).getD i.conflicts }

/-- BLFIN02 growth of `applyWrites`. Lists carry fixed-width counts, so growth is additive
    (`rawEncode_applyWrites_core`). No O(n) re-encode on the live path. -/
def evBytes (w : Writes) : Nat := (w.evidence.map fun e => (encodeEvidence e).length).getD 0
def cfBytes (w : Writes) : Nat := (w.conflict.map fun x => (encodeConflict x).length).getD 0
def newPay (w : Writes) : Nat := (w.payment.map fun p => (encodePayment p).length).getD 0
def oldPay (i : FinancialInput) (w : Writes) : Nat :=
  ((w.payment.bind fun p => findPayment i.payments p.paymentId).map fun q =>
    (encodePayment q).length).getD 0

def addedBytes (i : FinancialInput) (w : Writes) : Nat :=
  evBytes w + (newPay w - oldPay i w) + cfBytes w

def withinCapacity (r : PaymentRequest) (w : Writes) : Bool :=
  r.inputBytes + addedBytes r.input w ≤ maxTotalEncodedBytes

/-! ## Request well-formedness, which the decoder enforces (section 2.4) -/

def commandWellFormed : Command → Bool
  | .record c => [c.paymentId, c.evidenceId, c.commonOriginId, c.sourceId, c.sourceVersion].all idWellFormed &&
      (nonEmpty c.localRef).all idWellFormed && c.paysActionId.all idWellFormed &&
      c.amountCents ≤ maxCents && c.eventAt < 2 ^ 63
  | .reverse c => idWellFormed c.paymentId && idWellFormed c.evidenceId &&
      (nonEmpty c.commonOriginId).all idWellFormed && c.eventAt.all (· < 2 ^ 63)

def receiptsWellFormed (i : FinancialInput) (rs : List Receipt) : Bool :=
  rs.map Receipt.paymentId == i.payments.map Payment.paymentId &&
  rs.all fun k => k.recordedRevision < i.beforeRevision && k.paysActionId.all idWellFormed

def requestWellFormed (r : PaymentRequest) : Bool :=
  financialInputWellFormed r.input && receiptsWellFormed r.input r.receipts &&
  commandWellFormed r.command && r.expectedRevision.all (· < 2 ^ 63)

end BlindLedger.Financial.Payment
