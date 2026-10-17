import BlindLedger.Financial.Codec
import BlindLedger.Financial.Evaluation

namespace BlindLedger.Financial.DecisionPackage
open BlindLedger.Financial

inductive Support where
  | SUPPORTED | NO_LINKED_EVIDENCE | CONFLICTED | UNKNOWN | NOT_SATISFIED
deriving DecidableEq, Repr

inductive Assessment where
  | NOT_RESOLVED | CONFLICTED | UNSUPPORTED | UNKNOWN | SUPPORTED
deriving DecidableEq, Repr

structure PkgPayment where
  amountCents : Nat
  active : Bool
deriving DecidableEq, Repr

structure PkgClaim where
  amountCents : Nat
  status : ClaimStatus
deriving DecidableEq, Repr

/-- `acknowledged`: the outbox holds an acknowledgment reference. -/
structure PkgAction where
  status : ActionStatus
  acknowledged : Bool
deriving DecidableEq, Repr

/-- Everything the conclusions depend on. No page window: every row of the obligation. -/
structure PackageFacts where
  owedCents : Nat
  receivedCashCents : Nat
  claimedAdjustmentCents : Nat
  lawfulAdjustmentCents : Nat
  amountSatisfied : Bool
  reportingComplete : Bool
  verification : VerificationStatus
  payments : List PkgPayment        -- every payments row, ORDER BY payment_id
  claims : List PkgClaim            -- every claimed_adjustments row, ORDER BY claim_id
  reportCount : Nat                 -- REPORT and REPORT_CORRECTION evidence rows
  conflictCount : Nat               -- financial_conflicts rows
  caseStatus : Option CaseStatus    -- latest case by case_id
  action : Option PkgAction         -- latest action by (revision, action_id)
deriving DecidableEq, Repr

def activePayments (f : PackageFacts) : List PkgPayment := f.payments.filter (·.active)
def authorizedClaims (f : PackageFacts) : List PkgClaim := f.claims.filter (·.status = .AUTHORIZED)
def adjustmentClaims (f : PackageFacts) : List PkgClaim :=
  f.claims.filter (fun c => c.status = .CLAIMED || c.status = .AUTHORIZED)

def activeSum (f : PackageFacts) : Nat := ((activePayments f).map (·.amountCents)).sum
def claimedSum (f : PackageFacts) : Nat := ((adjustmentClaims f).map (·.amountCents)).sum
def lawfulSum (f : PackageFacts) : Nat := ((authorizedClaims f).map (·.amountCents)).sum

def paymentSupport (f : PackageFacts) : Support :=
  if (activePayments f).length ≠ 0 ∧ activeSum f = f.receivedCashCents then .SUPPORTED
  else if (activePayments f).length = 0 ∧ f.receivedCashCents = 0 then .NO_LINKED_EVIDENCE
  else .CONFLICTED

/-- Python's `(authorized_claim_count or adjustment_rows)` is `adjustmentClaims f ≠ []`:
    AUTHORIZED claims are adjustment rows. -/
def adjustmentSupport (f : PackageFacts) : Support :=
  if adjustmentClaims f ≠ [] ∧ claimedSum f = f.claimedAdjustmentCents ∧ lawfulSum f = f.lawfulAdjustmentCents then .SUPPORTED
  else if adjustmentClaims f = [] ∧ f.claimedAdjustmentCents = 0 ∧ f.lawfulAdjustmentCents = 0 then .NO_LINKED_EVIDENCE
  else .CONFLICTED

def reportingSupport (f : PackageFacts) : Support :=
  if f.reportingComplete then (if f.reportCount ≠ 0 then .SUPPORTED else .UNKNOWN)
  else if f.reportCount ≠ 0 then .CONFLICTED else .NOT_SATISFIED

/-- The schema has no durable "acknowledgment not required" marker, so no action is UNKNOWN. -/
def deliverySupport (f : PackageFacts) : Support :=
  match f.action with
  | none => .UNKNOWN
  | some a => if a.status = .ACKNOWLEDGED ∧ a.acknowledged = true then .SUPPORTED else .NOT_SATISFIED

/-- Last branch: all rows, not the page (fixes section 1.3). -/
def amountSupport (f : PackageFacts) : Support :=
  if paymentSupport f = .CONFLICTED ∨ adjustmentSupport f = .CONFLICTED then .CONFLICTED
  else if f.amountSatisfied = true ∧ (activePayments f).length = 0 ∧ (authorizedClaims f).length = 0 then .UNKNOWN
  else if f.verification = .CONFLICT_VISIBLE then .CONFLICTED
  else if (activePayments f).length + (authorizedClaims f).length ≠ 0 then .SUPPORTED
  else .NO_LINKED_EVIDENCE

def requiredAmount (f : PackageFacts) : Support :=
  if amountSupport f = .CONFLICTED then .CONFLICTED
  else if f.amountSatisfied = true ∧ amountSupport f = .SUPPORTED then .SUPPORTED
  else if f.amountSatisfied = false then .NOT_SATISFIED
  else .UNKNOWN

/-- Key order is the sorted Python key order: amount_satisfied,
    delivery_acknowledged_or_not_required, reporting_complete. Bit i of the mask is key i. -/
def requirements (f : PackageFacts) : List Support := [requiredAmount f, deliverySupport f, reportingSupport f]

def missingMask (f : PackageFacts) : Nat :=
  (if requiredAmount f = .SUPPORTED then 0 else 1) + (if deliverySupport f = .SUPPORTED then 0 else 2) +
    (if reportingSupport f = .SUPPORTED then 0 else 4)

def assessment (f : PackageFacts) : Assessment :=
  if f.caseStatus ≠ some .RESOLVED then .NOT_RESOLVED
  else if f.conflictCount ≠ 0 ∨ amountSupport f = .CONFLICTED ∨ reportingSupport f = .CONFLICTED then .CONFLICTED
  else if Support.NOT_SATISFIED ∈ requirements f then .UNSUPPORTED
  else if missingMask f ≠ 0 then .UNKNOWN
  else .SUPPORTED

structure Conclusions where
  cash : Support
  amount : Support
  reporting : Support
  delivery : Support
  requiredAmount : Support
  missingMask : Nat
  assessment : Assessment
  missingCents : Nat
  activePaymentCount : Nat
  authorizedClaimCount : Nat
deriving DecidableEq, Repr

def conclude (f : PackageFacts) : Conclusions where
  cash := paymentSupport f
  amount := amountSupport f
  reporting := reportingSupport f
  delivery := deliverySupport f
  requiredAmount := requiredAmount f
  missingMask := missingMask f
  assessment := assessment f
  missingCents := f.owedCents - f.receivedCashCents
  activePaymentCount := (activePayments f).length
  authorizedClaimCount := (authorizedClaims f).length

end BlindLedger.Financial.DecisionPackage
