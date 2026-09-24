import BlindLedger.Financial.Specification

namespace BlindLedger.Financial

/-! Executable evaluator.  The recursive traversals here are intentionally
    separate from the filtering/sorting definitions in `Specification.lean`.
    Every rejection is fail-closed; there is no `verified` Boolean and no
    caller-selected semantic winner. -/

def evalAdd (left right : Nat) : Option Nat :=
  if left ≤ maxCents && right ≤ maxCents && left ≤ maxCents - right then
    some (left + right)
  else none

def evalPaymentSum : List Payment → Option Nat
  | [] => some 0
  | payment :: rest => do
      let tail ← evalPaymentSum rest
      if payment.status = .ACTIVE then evalAdd payment.amountCents tail else pure tail

def evalClaimedSum : List Claim → Option Nat
  | [] => some 0
  | claim :: rest => do
      let tail ← evalClaimedSum rest
      if claim.status = .CLAIMED || claim.status = .AUTHORIZED then
        evalAdd claim.amountCents tail
      else pure tail

def evalLawfulSum : List Claim → Option Nat
  | [] => some 0
  | claim :: rest => do
      let tail ← evalLawfulSum rest
      if claim.status = .AUTHORIZED then evalAdd claim.amountCents tail else pure tail

structure EvalContribution where
  time : Nat
  identity : String
  amountCents : Nat
deriving DecidableEq, Repr

def evalInsertContribution (value : EvalContribution) : List EvalContribution → List EvalContribution
  | [] => [value]
  | first :: rest =>
      if contributionKeyBefore value.time value.amountCents value.identity
          first.time first.amountCents first.identity then
        value :: first :: rest
      else first :: evalInsertContribution value rest

def evalSortContributions : List EvalContribution → List EvalContribution
  | [] => []
  | first :: rest =>
      evalInsertContribution first (evalSortContributions rest)

def evalContributions (input : FinancialInput) : List EvalContribution :=
  let paymentContributions := input.payments.foldr
    (fun payment rest =>
      if payment.status = .ACTIVE then
        { time := payment.eventAt
          identity := payment.paymentId
          amountCents := payment.amountCents } :: rest
      else rest) []
  let determinationContributions := input.determinations.foldr
    (fun determination rest =>
      if determination.decision = .OFFSET_AUTHORIZED then
        { time := determination.decidedAt
          identity := determination.determinationId
          amountCents := determination.amountCents } :: rest
      else rest) []
  paymentContributions ++ determinationContributions

def evalCompletionLoop (owed total : Nat) : List EvalContribution → Option Nat
  | [] => none
  | contribution :: rest => do
      let next ← evalAdd total contribution.amountCents
      if next ≥ owed then some contribution.time
      else evalCompletionLoop owed next rest

def evalLatestContributionTime : List EvalContribution → Option Nat
  | [] => none
  | contribution :: rest =>
      match evalLatestContributionTime rest with
      | none => some contribution.time
      | some latest => some (max latest contribution.time)

def evalCompletion (input : FinancialInput) : Option Nat :=
  let contributions := evalSortContributions (evalContributions input)
  match evalCompletionLoop input.obligation.owedCents 0 contributions with
  | some completion => some completion
  | none => do
      let cash ← evalPaymentSum input.payments
      let lawful ← evalLawfulSum input.claims
      let total ← evalAdd lawful cash
      if total ≥ input.obligation.owedCents then
        evalLatestContributionTime contributions
      else none

def evalLatestCase : List CaseRecord → CaseStatus
  | [] => .OPEN
  | [caseRecord] => caseRecord.status
  | _ :: rest => evalLatestCase rest

def evalActionIsLater (candidate current : ActionRecord) : Bool :=
  current.createdAt < candidate.createdAt ||
    (current.createdAt = candidate.createdAt && decide (current.actionId < candidate.actionId))

def evalLatestAction : List ActionRecord → Option ActionRecord
  | [] => none
  | action :: rest =>
      match evalLatestAction rest with
      | none => some action
      | some current => if evalActionIsLater action current then some action else some current

def evalLatestDelivery : List ActionRecord → DeliveryStatus
  | [] => .NONE
  | actions =>
      match evalLatestAction actions with
      | none => .NONE
      | some action =>
          match action.status with
          | .READY => .READY
          | .ACKNOWLEDGED => .ACKNOWLEDGED
          | .CANCELLED => .CANCELLED

def evalCaseStatus (input : FinancialInput) (amountSatisfied : Bool) : CaseStatus :=
  let prior := evalLatestCase input.cases
  if amountSatisfied && input.obligation.reportingComplete then .RESOLVED
  else if amountSatisfied then .ACTIONED
  else if prior = .CORRECTION_REQUIRED then .CORRECTION_REQUIRED
  else if prior = .AUTHORIZED then .AUTHORIZED
  else .OPEN

def evalVerificationStatus (input : FinancialInput) : VerificationStatus :=
  if input.conflicts.isEmpty then
    if input.evidence.isEmpty then .MISSING_EVIDENCE else .SUPPORTED
  else .CONFLICT_VISIBLE

def evaluateResult (input : FinancialInput) (cash claimed lawful total : Nat) : FinancialResult :=
  let owed := input.obligation.owedCents
  let shortfall := if owed > total then owed - total else 0
  let overage := if total > owed then total - owed else 0
  let amountSatisfied := total ≥ owed
  let cashSatisfied := cash ≥ owed
  let completion := evalCompletion input
  let timely := match completion with
    | none => false
    | some completionTime => completionTime ≤ input.obligation.dueAt
  {
    context := input.context
    authorityId := input.authority.authorityId
    authorityEpoch := input.authority.epoch
    authorityDigest := input.authority.digest
    packId := input.pack.packId
    packDigest := input.pack.digest
    beforeRevision := input.beforeRevision
    afterRevision := input.beforeRevision + 1
    evaluatedAt := input.evaluatedAt
    ruleVersion := input.obligation.ruleVersion
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
    verificationStatus := evalVerificationStatus input
    caseStatus := evalCaseStatus input amountSatisfied
    deliveryStatus := evalLatestDelivery input.actions }

structure EvaluatedTotals where
  cash : Nat
  claimed : Nat
  lawful : Nat
  total : Nat
deriving DecidableEq, Repr

def evaluateTotals (input : FinancialInput) : Option EvaluatedTotals :=
  match evalPaymentSum input.payments with
  | none => none
  | some cash =>
      match evalClaimedSum input.claims with
      | none => none
      | some claimed =>
          match evalLawfulSum input.claims with
          | none => none
          | some lawful =>
              match evalAdd cash lawful with
              | none => none
              | some total => some { cash := cash, claimed := claimed, lawful := lawful, total := total }

def evaluateWellFormed (input : FinancialInput) : Option FinancialResult :=
  (evaluateTotals input).map (fun totals =>
    evaluateResult input totals.cash totals.claimed totals.lawful totals.total)

def evaluate (input : FinancialInput) : Option FinancialResult :=
  if financialInputWellFormed input then evaluateWellFormed input else none

end BlindLedger.Financial
