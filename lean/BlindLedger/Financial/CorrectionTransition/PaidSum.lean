import BlindLedger.Financial.Codec

/-! Paid-so-far from the snapshot (design: docs/CORE_REDESIGN.md, "Lean paid
    sum").  `BLFCMD03` replaces the caller's `correctionPaid` totals with the
    payment-to-action links; Lean sums the active linked payment rows itself.

    BUILDER: the laws in the marked section are statements with `sorry`
    bodies.  Fill every one before any module imports this file. -/

namespace BlindLedger.Financial.CorrectionTransition

open BlindLedger.Financial

/-- One PAYMENT_RECEIVED link: payment row `paymentId` pays correction action
    `actionId`.  Sent only for linked rows, ascending by `paymentId`. -/
structure PaymentLink where
  paymentId : String
  actionId : String
deriving DecidableEq, Repr

def encodePaymentLink (link : PaymentLink) : Bytes :=
  encodeString link.paymentId ++ encodeString link.actionId

def readPaymentLink (bytes : Bytes) : Option (PaymentLink × Bytes) := do
  let (paymentId, rest) ← readString bytes
  let (actionId, rest) ← readString rest
  pure ({ paymentId := paymentId, actionId := actionId }, rest)

/-- At most one link per payment row, in canonical payment-ID order. -/
def paymentLinksWellFormed (links : List PaymentLink) : Bool :=
  canonicalIdList (links.map PaymentLink.paymentId) &&
    links.all (fun link => idWellFormed link.actionId)

/-! ## Specification (not executed: quadratic by design, for statements only) -/

/-- Every link names a payment row of the snapshot and a correction payment
    request of the snapshot.  Anything else is `INVALID_INPUT`. -/
def paymentLinksAdmissible (payments : List Payment) (actions : List ActionRecord)
    (links : List PaymentLink) : Bool :=
  links.all fun link =>
    payments.any (fun payment => payment.paymentId = link.paymentId) &&
      actions.any (fun action => action.actionId = link.actionId &&
        action.kind = "CORRECTION_PAYMENT_REQUEST")

/-- Cents of the active payment rows the links attribute to `actionId`. -/
def linkedActivePaidCents (payments : List Payment) (links : List PaymentLink)
    (actionId : String) : Nat :=
  ((payments.filter fun payment => payment.status = .ACTIVE &&
      links.any fun link => link.paymentId = payment.paymentId && link.actionId = actionId).map
    Payment.amountCents).sum

/-- `outstandingCorrectionCents` with the paid term derived from the rows. -/
def linkedOutstandingCents (payments : List Payment) (links : List PaymentLink) :
    List ActionRecord → Nat
  | [] => 0
  | action :: rest =>
      (if action.kind = "CORRECTION_PAYMENT_REQUEST" ∧ action.status ≠ .CANCELLED then
        action.amountCents - linkedActivePaidCents payments links action.actionId else 0) +
        linkedOutstandingCents payments links rest

/-- Tamper vocabulary for the laws below. -/
def reversePaymentRow (paymentId : String) (payments : List Payment) : List Payment :=
  payments.map fun payment =>
    if payment.paymentId = paymentId then { payment with status := .REVERSED } else payment

def retargetPaymentLink (paymentId actionId : String) (links : List PaymentLink) :
    List PaymentLink :=
  links.map fun link =>
    if link.paymentId = paymentId then { link with actionId := actionId } else link

/-! ## BUILDER: statements to prove (sorry until filled) -/

/-- Reversing a linked active row lowers exactly its action's paid-so-far by
    exactly its amount; every other action is unchanged. -/
theorem linkedActivePaidCents_reverse (payments : List Payment) (links : List PaymentLink)
    (payment : Payment) (actionId other : String)
    (hRows : (payments.map Payment.paymentId).Nodup)
    (hLinks : (links.map PaymentLink.paymentId).Nodup)
    (hMember : payment ∈ payments) (hActive : payment.status = .ACTIVE)
    (hLinked : (⟨payment.paymentId, actionId⟩ : PaymentLink) ∈ links) :
    linkedActivePaidCents (reversePaymentRow payment.paymentId payments) links other +
        (if other = actionId then payment.amountCents else 0) =
      linkedActivePaidCents payments links other := by
  sorry

/-- Moving a link moves exactly the row's amount from the old action to the
    new one; every other action is unchanged. -/
theorem linkedActivePaidCents_retarget (payments : List Payment) (links : List PaymentLink)
    (payment : Payment) (fromId toId other : String)
    (hRows : (payments.map Payment.paymentId).Nodup)
    (hLinks : (links.map PaymentLink.paymentId).Nodup)
    (hMember : payment ∈ payments) (hActive : payment.status = .ACTIVE)
    (hLinked : (⟨payment.paymentId, fromId⟩ : PaymentLink) ∈ links) :
    linkedActivePaidCents payments (retargetPaymentLink payment.paymentId toId links) other +
        (if other = fromId then payment.amountCents else 0) =
      linkedActivePaidCents payments links other +
        (if other = toId then payment.amountCents else 0) := by
  sorry

/-- No cent is invented or counted twice: over distinct actions, paid-so-far
    never exceeds the active cash in the snapshot. -/
theorem linkedActivePaidCents_total_le_active (payments : List Payment)
    (links : List PaymentLink) (actionIds : List String)
    (hActions : actionIds.Nodup) (hLinks : (links.map PaymentLink.paymentId).Nodup) :
    (actionIds.map (linkedActivePaidCents payments links)).sum ≤
      ((payments.filter fun payment => payment.status = .ACTIVE).map Payment.amountCents).sum := by
  sorry

end BlindLedger.Financial.CorrectionTransition
