import BlindLedger.Financial.Types

namespace BlindLedger.Financial

/-! A declarative projection used only as a semantic specification.  It uses
    list filtering and an independently written ordered contribution fold;
    the executable evaluator in `Evaluation.lean` uses different recursive
    traversals and never calls this projection. -/

structure SpecContribution where
  time : Nat
  identity : String
  amountCents : Nat
deriving DecidableEq, Repr

structure SpecProjection where
  evidenceIds : List String
  completionAt : Option Nat
  owedCents : Nat
  claimedAdjustmentCents : Nat
  lawfulAdjustmentCents : Nat
  receivedCashCents : Nat
  shortfallCents : Nat
  overageCents : Nat
  cashSatisfied : Bool
  amountSatisfied : Bool
  timely : Bool
  reportingComplete : Bool
  verificationStatus : VerificationStatus
  caseStatus : CaseStatus
  deliveryStatus : DeliveryStatus
deriving DecidableEq, Repr

def specAdd (left right : Nat) : Option Nat :=
  if left ≤ maxCents && right ≤ maxCents && left ≤ maxCents - right then
    some (left + right)
  else none

def specSum : List Nat → Option Nat
  | [] => some 0
  | value :: rest => do
      let tail ← specSum rest
      specAdd value tail

def specPaymentAmounts : List Payment → List Nat
  | [] => []
  | payment :: rest =>
      (if payment.status = .ACTIVE then [payment.amountCents] else []) ++
        specPaymentAmounts rest

def specClaimedAmounts : List Claim → List Nat
  | [] => []
  | claim :: rest =>
      (if claim.status = .CLAIMED || claim.status = .AUTHORIZED
       then [claim.amountCents] else []) ++ specClaimedAmounts rest

def specLawfulAmounts : List Claim → List Nat
  | [] => []
  | claim :: rest =>
      (if claim.status = .AUTHORIZED then [claim.amountCents] else []) ++
        specLawfulAmounts rest

def specContributions (input : FinancialInput) : List SpecContribution :=
  let paymentContributions := input.payments.filterMap (fun payment =>
    if payment.status = .ACTIVE then
      some
        { time := payment.eventAt
          identity := payment.paymentId
          amountCents := payment.amountCents }
    else none)
  let determinationContributions := input.determinations.filterMap (fun determination =>
    if determination.decision = .OFFSET_AUTHORIZED then
      some
        { time := determination.decidedAt
          identity := determination.determinationId
          amountCents := determination.amountCents }
    else none)
  paymentContributions ++ determinationContributions

def specContributionBefore (left right : SpecContribution) : Bool :=
  left.time < right.time ||
    (left.time = right.time &&
      (left.amountCents < right.amountCents ||
        (left.amountCents = right.amountCents && decide (left.identity < right.identity))))

def specInsertContribution (value : SpecContribution) : List SpecContribution → List SpecContribution
  | [] => [value]
  | first :: rest =>
      if specContributionBefore value first then value :: first :: rest
      else first :: specInsertContribution value rest

def specSortContributions : List SpecContribution → List SpecContribution
  | [] => []
  | first :: rest => specInsertContribution first (specSortContributions rest)

def specCompletionLoop (owed total : Nat) : List SpecContribution → Option Nat
  | [] => none
  | contribution :: rest => do
      let next ← specAdd total contribution.amountCents
      if next ≥ owed then some contribution.time
      else specCompletionLoop owed next rest

def specLatestContributionTime : List SpecContribution → Option Nat
  | [] => none
  | contribution :: rest =>
      match specLatestContributionTime rest with
      | none => some contribution.time
      | some latest => some (max latest contribution.time)

def specCompletion (input : FinancialInput) (owed : Nat) : Option Nat :=
  let contributions := specSortContributions (specContributions input)
  match specCompletionLoop owed 0 contributions with
  | some completion => some completion
  | none => do
      let cash ← specSum (specPaymentAmounts input.payments)
      let lawful ← specSum (specLawfulAmounts input.claims)
      let total ← specAdd lawful cash
      if total ≥ owed then specLatestContributionTime contributions else none

def specLatestCase : List CaseRecord → CaseStatus
  | [] => .OPEN
  | [_] => .OPEN
  | _ :: rest => specLatestCase rest

def specLatestCaseValue : List CaseRecord → CaseStatus
  | [] => .OPEN
  | [caseRecord] => caseRecord.status
  | _ :: rest => specLatestCaseValue rest

def specActionIsLater (candidate current : ActionRecord) : Bool :=
  current.createdAt < candidate.createdAt ||
    (current.createdAt = candidate.createdAt && decide (current.actionId < candidate.actionId))

def specLatestActionRecord : List ActionRecord → Option ActionRecord
  | [] => none
  | action :: rest =>
      match specLatestActionRecord rest with
      | none => some action
      | some current => if specActionIsLater action current then some action else some current

def specLatestAction : List ActionRecord → DeliveryStatus
  | [] => .NONE
  | actions =>
      match specLatestActionRecord actions with
      | none => .NONE
      | some action =>
          match action.status with
           | .READY => .READY
           | .ACKNOWLEDGED => .ACKNOWLEDGED
           | .CANCELLED => .CANCELLED

def specCaseStatus (input : FinancialInput) (amountSatisfied : Bool) : CaseStatus :=
  let prior := specLatestCaseValue input.cases
  if amountSatisfied && input.obligation.reportingComplete then .RESOLVED
  else if amountSatisfied then .ACTIONED
  else if prior = .CORRECTION_REQUIRED then .CORRECTION_REQUIRED
  else if prior = .AUTHORIZED then .AUTHORIZED
  else .OPEN

def specVerificationStatus (input : FinancialInput) : VerificationStatus :=
  if input.conflicts.isEmpty then
    if input.evidence.isEmpty then .MISSING_EVIDENCE else .SUPPORTED
  else .CONFLICT_VISIBLE

def specification (input : FinancialInput) : Option SpecProjection := do
  if financialInputWellFormed input = false then none else pure ()
  let cash ← specSum (specPaymentAmounts input.payments)
  let claimed ← specSum (specClaimedAmounts input.claims)
  let lawful ← specSum (specLawfulAmounts input.claims)
  let total ← specAdd cash lawful
  let owed := input.obligation.owedCents
  let shortfall := if owed > total then owed - total else 0
  let overage := if total > owed then total - owed else 0
  let amountSatisfied := total ≥ owed
  let cashSatisfied := cash ≥ owed
  let completion := specCompletion input owed
  let timely := match completion with
    | none => false
    | some completionTime => completionTime ≤ input.obligation.dueAt
  pure {
    evidenceIds := input.evidence.map EvidenceRecord.evidenceId
    completionAt := completion
    owedCents := owed
    claimedAdjustmentCents := claimed
    lawfulAdjustmentCents := lawful
    receivedCashCents := cash
    shortfallCents := shortfall
    overageCents := overage
    cashSatisfied := cashSatisfied
    amountSatisfied := amountSatisfied
    timely := timely
    reportingComplete := input.obligation.reportingComplete
    verificationStatus := specVerificationStatus input
    caseStatus := specCaseStatus input amountSatisfied
    deliveryStatus := specLatestAction input.actions }

/-! This is a relation over the semantic fields, not an assertion that an
    evaluator call equals the specification call.  Binding fields are checked
    here as part of the correspondence boundary. -/
def satisfiesSpecification (input : FinancialInput) (result : FinancialResult) : Prop :=
  match specification input with
  | none => False
  | some expected =>
      result.context = input.context ∧
      result.authorityId = input.authority.authorityId ∧
      result.authorityEpoch = input.authority.epoch ∧
      result.authorityDigest = input.authority.digest ∧
      result.packId = input.pack.packId ∧
      result.packDigest = input.pack.digest ∧
      result.beforeRevision = input.beforeRevision ∧
      result.afterRevision = input.beforeRevision + 1 ∧
      result.evaluatedAt = input.evaluatedAt ∧
      result.ruleVersion = input.obligation.ruleVersion ∧
      result.evidenceIds = expected.evidenceIds ∧
      result.completionAt = expected.completionAt ∧
      result.owedCents = expected.owedCents ∧
      result.claimedAdjustmentCents = expected.claimedAdjustmentCents ∧
      result.lawfulAdjustmentCents = expected.lawfulAdjustmentCents ∧
      result.receivedCashCents = expected.receivedCashCents ∧
      result.shortfallCents = expected.shortfallCents ∧
      result.overageCents = expected.overageCents ∧
      result.cashSatisfied = expected.cashSatisfied ∧
      result.amountSatisfied = expected.amountSatisfied ∧
      result.timely = expected.timely ∧
      result.reportingComplete = expected.reportingComplete ∧
      result.verificationStatus = expected.verificationStatus ∧
      result.caseStatus = expected.caseStatus ∧
      result.deliveryStatus = expected.deliveryStatus

end BlindLedger.Financial
