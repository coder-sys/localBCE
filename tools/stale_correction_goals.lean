import BlindLedger.Financial.Payment.Bridge

/-! Stale corrections: the theorem STATEMENTS of design
    C:\Users\neers\rrb\designs\stale-correction-v1.md §6.  Every proof is `sorry`.
    This file is outside `lean/`, so no executable, library target, TCB report or pin manifest sees it.
    Check: from `lean/`, `lake env lean ../tools/stale_correction_goals.lean` over a build of
    `BlindLedger.Financial.Payment.Bridge` (lean tree b8b824e3, trunk 5e2e552).
    The five R2 definitions are verbatim copies of `tools/r2_request_shrink_goals.lean` (a tools file
    cannot be imported).  M3 step 2 moves R2's definitions to `lean/BlindLedger/Financial/Payment/Open.lean`;
    that builder deletes the copies here and moves `stillAsks`, `deliveryMet`, `ackAction` and
    statements 1-6 beside them, unchanged, each with its proof and an axiom pin, then deletes this file. -/

namespace BlindLedger.Financial.Payment.Stale

open BlindLedger.Financial BlindLedger.Financial.CorrectionTransition

/-! ### R2 definitions (copies) -/

def countedRequest (x : ActionRecord) : Bool :=
  x.kind == "CORRECTION_PAYMENT_REQUEST" && x.status != .CANCELLED

def servedBefore (b a : ActionRecord) : Bool :=
  b.revision < a.revision || (b.revision == a.revision && decide (b.actionId < a.actionId))

def unpaidOf (ps : List Payment) (ls : List PaymentLink) (x : ActionRecord) : Nat :=
  x.amountCents - linkedActivePaidCents ps ls x.actionId

def unpaidBefore (ps : List Payment) (ls : List PaymentLink) (xs : List ActionRecord)
    (a : ActionRecord) : Nat :=
  ((xs.filter fun b => countedRequest b && servedBefore b a).map (unpaidOf ps ls)).sum

def openCents (s : Nat) (ps : List Payment) (ls : List PaymentLink) (xs : List ActionRecord)
    (a : ActionRecord) : Nat :=
  if countedRequest a then min (unpaidOf ps ls a) (s - unpaidBefore ps ls xs a) else 0

/-! ### Stale corrections: derived, never stored -/

/-- An action still asks the payer for something: a correction request while it has money open
    (R2), any other action (an offset authorization notice) until cancelled.  A request whose open
    amount is 0 is moot: it asks for nothing, and asks again if the balance returns. -/
def stillAsks (s : Nat) (ps : List Payment) (ls : List PaymentLink) (xs : List ActionRecord)
    (x : ActionRecord) : Bool :=
  x.status != .CANCELLED && (x.kind != "CORRECTION_PAYMENT_REQUEST" || 0 < openCents s ps ls xs x)

/-- The decision package's `delivery_acknowledged_or_not_required` for an obligation with at least
    one action: every action that still asks has been acknowledged.  Replaces the newest-action-only
    reading (owner `decision_package`, `delivery_support`). -/
def deliveryMet (s : Nat) (ps : List Payment) (ls : List PaymentLink) (xs : List ActionRecord) : Bool :=
  xs.all fun x => !stillAsks s ps ls xs x || x.status == .ACKNOWLEDGED

/-- The acknowledgment of action `id` (owner `acknowledge_action`): READY becomes ACKNOWLEDGED. -/
def ackAction (id : String) (y : ActionRecord) : ActionRecord :=
  if y.actionId = id then { y with status := .ACKNOWLEDGED } else y

/-! Known answers (executed by `lake env lean`). -/

private def kAct (id kind : String) (rev : Nat) (st : ActionStatus) : ActionRecord :=
  { actionId := id, obligationId := "o", determinationId := none, kind := kind, amountCents := 300000,
    currency := "USD", revision := rev, status := st, payloadDigest := [], createdAt := rev }
private def kReq (id : String) (rev : Nat) (st : ActionStatus) : ActionRecord :=
  kAct id "CORRECTION_PAYMENT_REQUEST" rev st

-- One READY request: it waits on delivery while 300,000 is owed, not once nothing is owed.
#guard !deliveryMet 300000 [] [] [kReq "a" 1 .READY]
#guard deliveryMet 0 [] [] [kReq "a" 1 .READY]
-- Older A READY and still open, newer B acknowledged: not delivered (the newest-only reading says it is).
#guard !deliveryMet 600000 [] [] [kReq "b" 2 .ACKNOWLEDGED, kReq "a" 1 .READY]
-- Older A acknowledged, newer B READY but cut to 0 by a 300,000 balance: delivered.
#guard deliveryMet 300000 [] [] [kReq "b" 2 .READY, kReq "a" 1 .ACKNOWLEDGED]
#guard !deliveryMet 300001 [] [] [kReq "b" 2 .READY, kReq "a" 1 .ACKNOWLEDGED]
-- An offset authorization notice waits on delivery whatever the balance.
#guard !deliveryMet 0 [] [] [kAct "n" "OFFSET_AUTHORIZATION" 1 .READY]
-- Acknowledging changes no open amount.
#guard [kReq "b" 2 .READY, kReq "a" 1 .READY].map (fun y =>
    openCents 400000 [] [] ([kReq "b" 2 .READY, kReq "a" 1 .READY].map (ackAction "a")) (ackAction "a" y)) ==
  [100000, 300000]

/-! ## Statements -/

/-- 1. What a request may ask (and what any future dispatcher may send for it) never exceeds the
    unpaid balance or the request's own unpaid part.  A stale payload amount is never the ask. -/
theorem openCents_le_balance_and_unpaid (s : Nat) (ps : List Payment) (ls : List PaymentLink)
    (xs : List ActionRecord) (a : ActionRecord) :
    openCents s ps ls xs a ≤ s ∧ openCents s ps ls xs a ≤ unpaidOf ps ls a := by
  sorry

/-- 2. Reduce, derived: a falling balance (unlinked payment, accepted offset) never raises what any
    request asks; a rising balance (reversal) never lowers it. -/
theorem openCents_mono_balance {s s' : Nat} (ps : List Payment) (ls : List PaymentLink)
    (xs : List ActionRecord) (a : ActionRecord) (h : s' ≤ s) :
    openCents s' ps ls xs a ≤ openCents s ps ls xs a := by
  sorry

/-- 3. The specification of the delivery requirement. -/
theorem deliveryMet_iff (s : Nat) (ps : List Payment) (ls : List PaymentLink) (xs : List ActionRecord) :
    deliveryMet s ps ls xs = true ↔
      ∀ x ∈ xs, stillAsks s ps ls xs x = true → x.status = .ACKNOWLEDGED := by
  sorry

/-- 4. A stale request never blocks: once delivery is met, a falling balance keeps it met. -/
theorem deliveryMet_of_balance_le {s s' : Nat} (ps : List Payment) (ls : List PaymentLink)
    (xs : List ActionRecord) (h : s' ≤ s) (hm : deliveryMet s ps ls xs = true) :
    deliveryMet s' ps ls xs = true := by
  sorry

/-- 5. Cancel, derived: when nothing is owed, delivery waits on no correction request, only on
    other actions still READY. -/
theorem deliveryMet_zero_balance (ps : List Payment) (ls : List PaymentLink) (xs : List ActionRecord) :
    deliveryMet 0 ps ls xs =
      xs.all fun x => x.kind == "CORRECTION_PAYMENT_REQUEST" || x.status != .READY := by
  sorry

/-- 6. Delivery is not cash: acknowledging a READY action changes no request's open amount. -/
theorem openCents_ack (s : Nat) (ps : List Payment) (ls : List PaymentLink) (xs : List ActionRecord)
    (id : String) (hr : ∀ y ∈ xs, y.actionId = id → y.status = .READY) :
    ∀ y ∈ xs, openCents s ps ls (xs.map (ackAction id)) (ackAction id y) = openCents s ps ls xs y := by
  sorry

end BlindLedger.Financial.Payment.Stale
