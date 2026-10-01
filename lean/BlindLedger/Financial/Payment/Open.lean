import BlindLedger.Financial.Payment.Types

namespace BlindLedger.Financial.Payment

open BlindLedger.Financial BlindLedger.Financial.CorrectionTransition

/-! R2 (design `r2-request-shrink-v1.md` section 7), the definitions: open correction requests
    shrink and regrow with the unpaid balance.  The laws are in `Payment.OpenLaws`. -/

/-- A request that still asks for money: exactly the filter of `linkedOutstandingCents`. -/
def countedRequest (x : ActionRecord) : Bool :=
  x.kind == "CORRECTION_PAYMENT_REQUEST" && x.status != .CANCELLED

/-- `b` is served before `a`: made at an earlier revision, then by action id. -/
def servedBefore (b a : ActionRecord) : Bool :=
  b.revision < a.revision || (b.revision == a.revision && decide (b.actionId < a.actionId))

/-- What request `x` asks for that active linked payments have not paid. -/
def unpaidOf (ps : List Payment) (ls : List PaymentLink) (x : ActionRecord) : Nat :=
  x.amountCents - linkedActivePaidCents ps ls x.actionId

/-- The unpaid parts of the counted requests served before `a`. -/
def unpaidBefore (ps : List Payment) (ls : List PaymentLink) (xs : List ActionRecord)
    (a : ActionRecord) : Nat :=
  ((xs.filter fun b => countedRequest b && servedBefore b a).map (unpaidOf ps ls)).sum

/-- R2: what request `a` may still collect when the unpaid balance is `s`.  Older requests keep
    their unpaid part first; the newest are reduced first. -/
def openCents (s : Nat) (ps : List Payment) (ls : List PaymentLink) (xs : List ActionRecord)
    (a : ActionRecord) : Nat :=
  if countedRequest a then min (unpaidOf ps ls a) (s - unpaidBefore ps ls xs a) else 0

def openTotal (s : Nat) (ps : List Payment) (ls : List PaymentLink) (xs : List ActionRecord) : Nat :=
  (xs.map (openCents s ps ls xs)).sum

end BlindLedger.Financial.Payment
