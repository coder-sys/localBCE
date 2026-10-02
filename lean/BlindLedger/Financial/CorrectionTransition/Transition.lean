import BlindLedger.Financial.DecisionPackage.Projection
import BlindLedger.Financial.Evaluation
import BlindLedger.Sha3
import BlindLedger.Financial.CorrectionTransition.Types

namespace BlindLedger.Financial.CorrectionTransition

open BlindLedger.Financial
open BlindLedger.Financial.DecisionPackage

private def correctionDecision : DeterminationDecision :=
  .OFFSET_REJECTED_CORRECTION_AUTHORIZED

private def actionKind : String := "CORRECTION_PAYMENT_REQUEST"

private def actionDomain : Bytes := "RR/FINANCIAL/ACTION/v1".toUTF8.toList ++ [UInt8.ofNat 0]

private def appendBytes (parts : List Bytes) : Bytes :=
  parts.foldl (fun output part => output ++ part) []

private def ownerFramedDigest (domain : Bytes) (parts : List Bytes) : Bytes :=
  (BlindLedger.Semantic.sha3_512
    ((domain ++ appendBytes (parts.map (fun part => natBE 8 part.length ++ part))).toByteArray)).toList

private def hexDigit (value : Nat) : Char :=
  Char.ofNat (if value < 10 then 48 + value else 55 + value)

def digestHex (value : Bytes) : String :=
  String.ofList (value.foldr (fun byte output =>
    hexDigit (byte.toNat / 16) :: hexDigit (byte.toNat % 16) :: output) [])

/-! Every string in this canonical JSON payload has already passed the
    Owner's ASCII identifier/role/kind grammar. That grammar excludes JSON
    quotation marks, backslashes, control bytes, and non-ASCII text. -/
private def jsonId (value : String) : String := "\"" ++ value ++ "\""

def evidenceDomain : Bytes := "RR/FINANCIAL/EVIDENCE/v1".toUTF8.toList ++ [UInt8.ofNat 0]

def rosterJson (a : TrustedAuthority) : String :=
  "{\"actors\":[" ++ ",".intercalate (a.actors.map fun x =>
      "{\"actor_id\":" ++ jsonId x.actorId ++ ",\"roles\":[" ++ ",".intercalate (x.roles.map jsonId) ++ "]}") ++
    "],\"authority_id\":" ++ jsonId a.authorityId ++ ",\"epoch\":" ++ toString a.epoch ++
    ",\"synthetic_only\":" ++ (if a.syntheticOnly then "true" else "false") ++ "}"

def authorityDigestOf (a : TrustedAuthority) : Bytes :=
  ownerFramedDigest evidenceDomain [(rosterJson a).toUTF8.toList]

inductive CorrectionActionDispatchMode where
  | SYNTHETIC_RECORD_ONLY
deriving DecidableEq, Repr

def CorrectionActionDispatchMode.wireValue : CorrectionActionDispatchMode → String
  | .SYNTHETIC_RECORD_ONLY => "SYNTHETIC_RECORD_ONLY"

structure CorrectionActionPayload where
  dispatchMode : CorrectionActionDispatchMode
  canonicalJson : String
deriving DecidableEq, Repr

def offsetActionPayload (kind : String) (request : CorrectionTransitionRequest)
    (determinationId : String) (resultingRevision amountCents : Nat) : CorrectionActionPayload :=
  let command := request.command
  let input := request.currentInput
  let dispatchMode := CorrectionActionDispatchMode.SYNTHETIC_RECORD_ONLY
  { dispatchMode := dispatchMode
    canonicalJson :=
      "{\"action_id\":" ++ jsonId command.actionId ++
        ",\"amount_cents\":" ++ toString amountCents ++
        ",\"claim_id\":" ++ jsonId command.claimId ++
        ",\"currency\":" ++ jsonId input.context.currency ++
        ",\"determination_id\":" ++ jsonId determinationId ++
        ",\"dispatch\":" ++ jsonId dispatchMode.wireValue ++
        ",\"input_evaluation_id\":" ++ jsonId command.evaluationId ++
        ",\"input_evaluation_result_digest\":" ++ jsonId (digestHex command.evaluationResultDigest) ++
        ",\"kind\":" ++ jsonId kind ++
        ",\"obligation_id\":" ++ jsonId input.context.obligationId ++
        ",\"revision\":" ++ toString resultingRevision ++ "}" }

def canonicalActionPayload (request : CorrectionTransitionRequest)
    (determinationId : String) (resultingRevision amountCents : Nat) : CorrectionActionPayload :=
  offsetActionPayload "CORRECTION_PAYMENT_REQUEST" request determinationId resultingRevision amountCents

/-- The Owner's storage digest of the action payload. The Owner recomputes it
    from the row it writes and refuses any difference (`correction_digest_binding`). -/
def correctionActionPayloadDigest (payload : CorrectionActionPayload) : Bytes :=
  ownerFramedDigest actionDomain [payload.canonicalJson.toUTF8.toList]

structure CorrectionMutationLinkFacts (request : CorrectionTransitionRequest)
    (mutation : CorrectionMutation) : Prop where
  transition : mutation.transition = .OFFSET_REJECTED_CORRECTION_AUTHORIZED
  effectSequence : mutation.orderedEffects = [ .DETERMINATION_RECORDED, .CLAIM_REJECTED,
    .CASE_UPSERTED, .ACTION_CREATED, .OUTBOX_CREATED, .PROJECTION_RECOMPUTED, .EVENT_APPENDED ]
  determinationIdentity : mutation.determination.determinationId =
    "determination:" ++ request.command.actionId
  acceptedActionIdentity : mutation.action.actionId = request.command.actionId
  actionDeterminationIdentity : mutation.action.determinationId =
    some mutation.determination.determinationId
  actionObligationIdentity : mutation.action.obligationId =
    request.currentInput.context.obligationId
  outboxActionIdentity : mutation.outbox.actionId = mutation.action.actionId
  followUpActionIdentity : mutation.followUps.actionId = mutation.action.actionId
  followUpOutboxIdentity : mutation.followUps.outboxActionId = mutation.outbox.actionId
  caseIdentity : mutation.caseDelta.record.caseId = mutation.followUps.caseId
  followUpCaseIdentity : mutation.followUps.caseId =
    "case:" ++ request.currentInput.context.obligationId
  caseObligationIdentity : mutation.caseDelta.record.obligationId =
    request.currentInput.context.obligationId
  eventAggregateIdentity : mutation.event.aggregateId = request.currentInput.context.obligationId
  eventKind : mutation.event.kind = "OFFSET_REJECTED_CORRECTION_AUTHORIZED"
  resultingEvaluationIdentity : mutation.followUps.resultingEvaluationId =
    "evaluation:" ++ request.currentInput.context.obligationId ++ ":r" ++
      toString (request.command.expectedRevision + 1)
  eventSequence : mutation.event.sequence = request.command.currentEventSequence + 1
  followUpEventSequence : mutation.followUps.eventSequence = mutation.event.sequence
  eventPreviousHead : mutation.event.previousHead = request.command.previousHistoryHead
  dependencyEventSequence : mutation.dependencies.currentEventSequence =
    request.command.currentEventSequence
  dependencyPreviousHead : mutation.dependencies.previousHistoryHead =
    request.command.previousHistoryHead
  eventBeforeRevision : mutation.event.beforeRevision = request.command.expectedRevision
  eventAfterRevision : mutation.event.afterRevision = request.command.expectedRevision + 1
  determinationBeforeRevision : mutation.determination.expectedRevision =
    request.command.expectedRevision
  determinationAfterRevision : mutation.determination.resultingRevision =
    request.command.expectedRevision + 1
  actionRevision : mutation.action.revision = request.command.expectedRevision + 1
  resultingInputBeforeRevision : mutation.resultingInput.beforeRevision =
    request.command.expectedRevision
  resultingResultAfterRevision : mutation.resultingResult.afterRevision =
    request.command.expectedRevision + 1
  dependencyEvaluationIdentity : mutation.dependencies.inputEvaluationId =
    request.command.evaluationId
  dependencyEvaluationDigest : mutation.dependencies.inputEvaluationResultDigest =
    request.command.evaluationResultDigest
  dependencyEvaluationRevision : mutation.dependencies.inputEvaluationRevision =
    request.command.expectedRevision
  dependencyEvaluationTime : mutation.dependencies.inputEvaluationEvaluatedAtMs =
    request.currentReceipt.result.evaluatedAtMs
  dependencyDecisionTime : mutation.dependencies.decisionAtMs = request.command.decisionAtMs
  dependencyOwnerTime : mutation.dependencies.ownerNowMs = request.command.ownerNowMs
  dependencyAuthorityIdentity : mutation.dependencies.authorityId =
    request.currentInput.authority.authorityId
  dependencyAuthorityEpoch : mutation.dependencies.authorityEpoch =
    request.currentInput.authority.epoch
  dependencyAuthorityDigest : mutation.dependencies.authorityDigest =
    request.currentInput.authority.digest
  dependencyControlPackIdentity : mutation.dependencies.controlPackId =
    request.currentInput.pack.packId
  dependencyControlPackVersion : mutation.dependencies.controlPackVersion =
    request.currentInput.pack.version
  dependencyControlPackDigest : mutation.dependencies.controlPackDigest =
    request.currentInput.pack.digest
  dependencyEvidence : mutation.dependencies.supportingEvidence =
    request.currentReceipt.evidenceBindings
  dependencyQueries : mutation.dependencies.queryObservations =
    request.command.queryObservations
  derivedPaid : derivedCorrectionPaid request.currentInput.payments request.currentInput.actions
    request.command.paymentLinks = some mutation.dependencies.correctionPaid
  readyAction : mutation.action.status = .READY
  readyOutbox : mutation.outbox.status = .READY
  outboxAttempt : mutation.outbox.attempt = 0
  noAcknowledgment : mutation.outbox.acknowledgmentReference = none
  outboxActionTime : mutation.outbox.updatedAtMs = mutation.action.createdAt
  actionPayloadDispatchMode : (canonicalActionPayload request
    mutation.determination.determinationId (request.command.expectedRevision + 1)
      mutation.action.amountCents).dispatchMode = .SYNTHETIC_RECORD_ONLY
  actionPayloadDigest : mutation.action.payloadDigest = correctionActionPayloadDigest
    (canonicalActionPayload request mutation.determination.determinationId
      (request.command.expectedRevision + 1) mutation.action.amountCents)
  correctionKind : mutation.action.kind = "CORRECTION_PAYMENT_REQUEST"
  claimAmount : mutation.determination.amountCents = mutation.dependencies.claimBefore.amountCents
  amountRule : mutation.action.amountCents =
    min mutation.determination.amountCents (mutation.dependencies.inputShortfallCents -
      outstandingCorrectionCents mutation.dependencies.correctionPaid request.currentInput.actions)
  inputShortfall : ∃ result, evaluate request.currentInput = some result ∧
    result.shortfallCents = mutation.dependencies.inputShortfallCents ∧
    outstandingCorrectionCents mutation.dependencies.correctionPaid request.currentInput.actions <
      result.shortfallCents
  resultingEvaluates : evaluate mutation.resultingInput = some mutation.resultingResult
  resultingFrame : mutation.resultingInput.context = request.currentInput.context ∧
    mutation.resultingInput.authority = request.currentInput.authority ∧
    mutation.resultingInput.pack = request.currentInput.pack ∧
    mutation.resultingInput.obligation = request.currentInput.obligation ∧
    mutation.resultingInput.payments = request.currentInput.payments ∧
    mutation.resultingInput.evidence = request.currentInput.evidence ∧
    mutation.resultingInput.conflicts = request.currentInput.conflicts
  resultingClaims : mutation.resultingInput.claims = request.currentInput.claims.map (fun claim =>
    if claim.claimId = request.command.claimId then
      { mutation.dependencies.claimBefore with status := .REJECTED } else claim)
  resultingActions : mutation.resultingInput.actions.Perm
    (mutation.action :: request.currentInput.actions)
  resultingDeterminations : mutation.resultingInput.determinations.Perm
    (mutation.determination :: request.currentInput.determinations)
  authorizedDeterminations : mutation.resultingInput.determinations.filter
      (fun d => d.decision = .OFFSET_AUTHORIZED) =
    request.currentInput.determinations.filter (fun d => d.decision = .OFFSET_AUTHORIZED)
  determinationDecision : mutation.determination.decision = .OFFSET_REJECTED_CORRECTION_AUTHORIZED ∧
    mutation.determination.claimId = request.command.claimId
  determinationActor : mutation.determination.actorId = request.command.actorId ∧
    mutation.determination.actorRole = request.command.actorRole ∧
    mutation.determination.authorityId = request.currentInput.authority.authorityId ∧
    mutation.determination.authorityEpoch = request.currentInput.authority.epoch ∧
    mutation.determination.authorityDigest = request.currentInput.authority.digest

def sameOwnerResult (result : FinancialResult) (receipt : EvaluationReceipt)
    (expectedEvaluationId : String) : Bool :=
  let owner := receipt.result
  owner.evaluationId = expectedEvaluationId &&
    owner.obligationId = result.context.obligationId &&
    owner.revision = result.afterRevision && owner.ruleVersion = result.ruleVersion &&
    owner.evidenceIds = result.evidenceIds && owner.authorityId = result.authorityId &&
    owner.evaluatedAtMs = result.evaluatedAt && owner.owedCents = result.owedCents &&
    owner.claimedAdjustmentCents = result.claimedAdjustmentCents &&
    owner.lawfulAdjustmentCents = result.lawfulAdjustmentCents &&
    owner.receivedCashCents = result.receivedCashCents &&
    owner.shortfallCents = result.shortfallCents && owner.overageCents = result.overageCents &&
    owner.cashSatisfied = result.cashSatisfied && owner.amountSatisfied = result.amountSatisfied &&
    owner.timely = result.timely && owner.reportingComplete = result.reportingComplete &&
    owner.verificationStatus = ownerVerificationStatus result.verificationStatus &&
    owner.caseStatus = ownerCaseStatus result.caseStatus &&
    owner.deliveryStatus = ownerDeliveryStatus result.deliveryStatus &&
    receipt.scope.stateId = result.context.stateId &&
    receipt.scope.deploymentId = result.context.deploymentId &&
    receipt.scope.programId = result.context.programId &&
    receipt.scope.periodId = result.context.periodId &&
    receipt.scope.currency = result.context.currency &&
    receipt.controlPack.packId = result.packId &&
    receipt.controlPack.version = result.ruleVersion &&
    receipt.controlPack.digest = result.packDigest &&
    receipt.authority.authorityEpoch = result.authorityEpoch &&
    receipt.authority.authorityDigest = result.authorityDigest &&
    receipt.resultDigest = receipt.evaluationResultDigest &&
    receipt.resultDigest.length = digestBytes && receipt.receiptDigest.length = digestBytes &&
    receipt.evidenceBindings.map EvidenceBinding.evidenceId = result.evidenceIds

private def currentReceiptBound (request : CorrectionTransitionRequest)
    (result : FinancialResult) : Bool :=
  let command := request.command
  let input := request.currentInput
  let receipt := request.currentReceipt
  let expectedEvaluationId := "evaluation:" ++ input.context.obligationId ++
    ":r" ++ toString command.expectedRevision
  input.context.itemId = command.itemId && input.beforeRevision + 1 = command.expectedRevision &&
    command.expectedRevision = result.afterRevision &&
    input.evaluatedAt = receipt.result.evaluatedAtMs &&
    command.evaluationId = expectedEvaluationId &&
    command.evaluationId = receipt.result.evaluationId &&
    command.evaluationResultDigest = receipt.resultDigest &&
    receipt.contractVersion = evaluationReceiptContractV1 &&
    evaluationReceiptWellFormed receipt &&
    (match receipt.inputSnapshotDigest with
      | some digest => digestWellFormed digest
      | none => false) && sameOwnerResult result receipt expectedEvaluationId

private def querySubjectsMatch (observations : CorrectionQueryObservations)
    (command : CorrectionCommand) : Bool :=
  observations.actionId.predicate = .ACTION_ID &&
    observations.actionId.subject = command.actionId &&
    observations.determinationId.predicate = .DETERMINATION_ID &&
    observations.determinationId.subject = "determination:" ++ command.actionId &&
    observations.evaluationConsumed.predicate = .EVALUATION_CONSUMED &&
    observations.evaluationConsumed.subject = command.evaluationId

private def querySetCompleteAtCommand (command : CorrectionCommand) : Bool :=
  let observations := command.queryObservations
  correctionQueryObservationsWellFormed observations &&
    observations.actionId.complete && observations.determinationId.complete &&
    observations.evaluationConsumed.complete &&
    querySubjectsMatch observations command &&
    correctionQueryObservationsAt observations command.currentEventSequence command.previousHistoryHead

private def querySetExactRetry (observations : CorrectionQueryObservations)
    (command : CorrectionCommand) : Bool :=
  observations.actionId.matchCount = 1 && observations.actionId.resultIdentity = some command.actionId &&
    observations.determinationId.matchCount = 1 &&
      observations.determinationId.resultIdentity = some ("determination:" ++ command.actionId) &&
    observations.evaluationConsumed.matchCount = 1 &&
      observations.evaluationConsumed.resultIdentity = some ("determination:" ++ command.actionId)

private def lookupAuthorityMatches (command : CorrectionCommand)
    (identity : ExistingCorrectionIdentity) : Bool :=
  identity.authorityId = command.currentAuthorityId &&
    identity.authorityEpoch = command.currentAuthorityEpoch &&
    identity.authorityDigest = command.currentAuthorityDigest

def decisionActionKind : DeterminationDecision → String
  | .OFFSET_AUTHORIZED => "OFFSET_AUTHORIZATION"
  | .OFFSET_REJECTED_CORRECTION_AUTHORIZED => "CORRECTION_PAYMENT_REQUEST"

def offsetIdentityMatches (decision : DeterminationDecision) (request : CorrectionTransitionRequest)
    (identity : ExistingCorrectionIdentity) : Bool :=
  let command := request.command
  identity.actionId = command.actionId &&
    identity.actionObligationId = request.currentInput.context.obligationId &&
    identity.determinationObligationId = request.currentInput.context.obligationId &&
    identity.determinationId = "determination:" ++ command.actionId &&
    identity.actionKind = decisionActionKind decision && identity.claimId = command.claimId &&
    identity.actorId = command.actorId && identity.actorRole = command.actorRole &&
    identity.decision = decision &&
    identity.inputEvaluationId = command.evaluationId &&
    identity.inputEvaluationResultDigest = command.evaluationResultDigest &&
    identity.expectedRevision = command.expectedRevision &&
    identity.decidedAtMs = command.decisionAtMs

private def existingIdentityMatches (request : CorrectionTransitionRequest)
    (identity : ExistingCorrectionIdentity) : Bool :=
  offsetIdentityMatches correctionDecision request identity

def reject (command : CorrectionCommand) (reason : TransitionRejectReason) : CorrectionTransitionResult :=
  let explanation : TransitionExplanation := {
    code := .REJECTED
    transition := none
    rejectReason := some (reason)
    unresolvedRequirement := some (requiredTransitionCondition reason)
    claimId := if idWellFormed command.claimId then some command.claimId else none
    actionId := if idWellFormed command.actionId then some command.actionId else none
    inputEvaluationId := if idWellFormed command.evaluationId then some command.evaluationId else none
    expectedRevision := if revisionWellFormed command.expectedRevision
      then some command.expectedRevision else none
    resultingRevision := none }
  { status := .REJECTED
    rejectReason := some (reason)
    explanation := explanation
    actionId := none
    determinationId := none
    mutation := none }

def duplicate (command : CorrectionCommand) : CorrectionTransitionResult :=
  let explanation : TransitionExplanation := {
    code := .EXACT_RETRY
    transition := some (.OFFSET_REJECTED_CORRECTION_AUTHORIZED)
    rejectReason := none
    unresolvedRequirement := none
    claimId := some (command.claimId)
    actionId := some (command.actionId)
    inputEvaluationId := some (command.evaluationId)
    expectedRevision := some (command.expectedRevision)
    resultingRevision := none }
  { status := .DUPLICATE
    rejectReason := none
    explanation := explanation
    actionId := some (command.actionId)
    determinationId := some ("determination:" ++ command.actionId)
    mutation := none }

private def findCase (cases : List CaseRecord) (caseId : String) : Option CaseRecord :=
  cases.find? (fun record => record.caseId = caseId)

private def insertCaseSorted (record : CaseRecord) : List CaseRecord → List CaseRecord
  | [] => [record]
  | first :: rest =>
      if record.caseId < first.caseId then record :: first :: rest
      else first :: insertCaseSorted record rest

private def insertDeterminationSorted (record : OffsetDetermination) :
    List OffsetDetermination → List OffsetDetermination
  | [] => [record]
  | first :: rest =>
      if record.determinationId < first.determinationId then record :: first :: rest
      else first :: insertDeterminationSorted record rest

private def insertActionSorted (record : ActionRecord) : List ActionRecord → List ActionRecord
  | [] => [record]
  | first :: rest =>
      if record.actionId < first.actionId then record :: first :: rest
      else first :: insertActionSorted record rest

private theorem insertActionSorted_perm (x : ActionRecord) :
    ∀ l, (insertActionSorted x l).Perm (x :: l)
  | [] => List.Perm.refl _
  | y :: ys => by
      unfold insertActionSorted
      split
      · exact List.Perm.refl _
      · exact ((insertActionSorted_perm x ys).cons y).trans (List.Perm.swap x y ys)

private theorem insertDeterminationSorted_perm (x : OffsetDetermination) :
    ∀ l, (insertDeterminationSorted x l).Perm (x :: l)
  | [] => List.Perm.refl _
  | y :: ys => by
      unfold insertDeterminationSorted
      split
      · exact List.Perm.refl _
      · exact ((insertDeterminationSorted_perm x ys).cons y).trans (List.Perm.swap x y ys)

private theorem insertDeterminationSorted_filter (x : OffsetDetermination)
    (p : OffsetDetermination → Bool) (hx : p x = false) :
    ∀ l, (insertDeterminationSorted x l).filter p = l.filter p
  | [] => by simp [insertDeterminationSorted, hx]
  | y :: ys => by
      unfold insertDeterminationSorted
      split
      · simp [List.filter_cons, hx]
      · simp only [List.filter_cons]
        rw [insertDeterminationSorted_filter x p hx ys]

private def updateAllCaseStatus (cases : List CaseRecord) (status : CaseStatus)
    (updatedAt : Nat) : List CaseRecord :=
  cases.map (fun record => { record with status := status, updatedAt := updatedAt })

private theorem evalLatestCase_updateAllCaseStatus (cases : List CaseRecord)
    (status : CaseStatus) (updatedAt : Nat) :
    evalLatestCase (updateAllCaseStatus cases status updatedAt) =
      match cases with
      | [] => .OPEN
      | _ :: _ => status := by
  induction cases with
  | nil => rfl
  | cons first rest ih =>
      cases rest with
      | nil => rfl
      | cons second tail =>
          simpa [updateAllCaseStatus, evalLatestCase] using ih

/-- Proof-only restatement of the body of `evalCaseStatus` as a function of the
    prior (latest) case status. It is not used by any executed definition. -/
private def caseStatusRule (amountSatisfied reportingComplete : Bool) (prior : CaseStatus) :
    CaseStatus :=
  if amountSatisfied && reportingComplete then .RESOLVED
  else if amountSatisfied then .ACTIONED
  else if prior = .CORRECTION_REQUIRED then .CORRECTION_REQUIRED
  else if prior = .AUTHORIZED then .AUTHORIZED
  else .OPEN

private theorem evalCaseStatus_eq_caseStatusRule (input : FinancialInput) (amountSatisfied : Bool) :
    evalCaseStatus input amountSatisfied =
      caseStatusRule amountSatisfied input.obligation.reportingComplete
        (evalLatestCase input.cases) :=
  rfl

private theorem caseStatusRule_idempotent (amountSatisfied reportingComplete : Bool)
    (prior : CaseStatus) :
    caseStatusRule amountSatisfied reportingComplete
        (caseStatusRule amountSatisfied reportingComplete prior) =
      caseStatusRule amountSatisfied reportingComplete prior := by
  cases amountSatisfied <;> cases reportingComplete <;> cases prior <;> rfl

private theorem evalCaseStatus_updateAllCaseStatus_fixedPoint (input : FinancialInput)
    (amountSatisfied : Bool) (updatedAt : Nat) :
    evalCaseStatus
      { input with cases := updateAllCaseStatus input.cases (evalCaseStatus input amountSatisfied) updatedAt }
      amountSatisfied = evalCaseStatus input amountSatisfied := by
  have hLatest := evalLatestCase_updateAllCaseStatus input.cases
    (evalCaseStatus input amountSatisfied) updatedAt
  have hUpdated :
      evalCaseStatus
        { input with cases := updateAllCaseStatus input.cases (evalCaseStatus input amountSatisfied) updatedAt }
        amountSatisfied =
      caseStatusRule amountSatisfied input.obligation.reportingComplete
        (evalLatestCase
          (updateAllCaseStatus input.cases (evalCaseStatus input amountSatisfied) updatedAt)) :=
    rfl
  rw [hUpdated, hLatest, evalCaseStatus_eq_caseStatusRule input amountSatisfied]
  cases input.cases with
  | nil => rfl
  | cons first rest =>
      exact caseStatusRule_idempotent amountSatisfied input.obligation.reportingComplete
        (evalLatestCase (first :: rest))

private theorem evaluate_some_implies_input_wellFormed (input : FinancialInput)
    (result : FinancialResult) (hEval : evaluate input = some result) :
    financialInputWellFormed input = true := by
  cases hWellFormed : financialInputWellFormed input <;>
    simp_all [evaluate]

/-- Updating every case to the case status produced by the first evaluation is
    a fixed point. `evalLatestCase` reads the last case status; on an empty list
    it remains `.OPEN`. The full evaluation theorem below also proves that the
    resulting input's unchanged financial totals yield the same result. -/
theorem evaluate_after_case_status_update_fixedPoint (input : FinancialInput)
    (result : FinancialResult) (updatedAt : Nat)
    (hEval : evaluate input = some result)
    (hUpdatedWellFormed : financialInputWellFormed
      { input with cases := updateAllCaseStatus input.cases result.caseStatus updatedAt } = true) :
    evaluate
      { input with cases := updateAllCaseStatus input.cases result.caseStatus updatedAt } =
      some result := by
  let updated : FinancialInput :=
    { input with cases := updateAllCaseStatus input.cases result.caseStatus updatedAt }
  have hInputWellFormed := evaluate_some_implies_input_wellFormed input result hEval
  have hUpdatedWellFormed' : financialInputWellFormed updated = true := by
    simpa [updated] using hUpdatedWellFormed
  have hTotalsUpdated : evaluateTotals updated = evaluateTotals input := by
    rfl
  cases hTotals : evaluateTotals input with
  | none =>
      have hImpossible : False := by
        have hEval' := hEval
        unfold evaluate at hEval'
        rw [hInputWellFormed] at hEval'
        unfold evaluateWellFormed at hEval'
        simp [hTotals] at hEval'
      exact False.elim hImpossible
  | some totals =>
      have hEvalResult : evaluateResult input totals.cash totals.claimed totals.lawful totals.total = result := by
        have hEval' := hEval
        unfold evaluate at hEval'
        rw [hInputWellFormed] at hEval'
        unfold evaluateWellFormed at hEval'
        simpa [hTotals] using hEval'
      have hResultCaseStatus : result.caseStatus =
          evalCaseStatus input (totals.total ≥ input.obligation.owedCents) := by
        rw [← hEvalResult]
        rfl
      have hCaseStatus :
          evalCaseStatus updated (totals.total ≥ input.obligation.owedCents) =
            evalCaseStatus input (totals.total ≥ input.obligation.owedCents) := by
        change evalCaseStatus
          { input with cases := updateAllCaseStatus input.cases result.caseStatus updatedAt }
            (totals.total ≥ input.obligation.owedCents) = _
        rw [hResultCaseStatus]
        exact evalCaseStatus_updateAllCaseStatus_fixedPoint input
          (totals.total ≥ input.obligation.owedCents) updatedAt
      have hUpdatedEvalResult :
          evaluateResult updated totals.cash totals.claimed totals.lawful totals.total = result := by
        -- `evaluateResult` reads `cases` only through `evalCaseStatus`; every
        -- other field is definitionally the same for `updated` and `input`.
        calc
          evaluateResult updated totals.cash totals.claimed totals.lawful totals.total =
              { evaluateResult input totals.cash totals.claimed totals.lawful totals.total with
                caseStatus := evalCaseStatus updated (totals.total ≥ input.obligation.owedCents) } :=
            rfl
          _ = { evaluateResult input totals.cash totals.claimed totals.lawful totals.total with
                caseStatus := evalCaseStatus input (totals.total ≥ input.obligation.owedCents) } := by
            rw [hCaseStatus]
          _ = evaluateResult input totals.cash totals.claimed totals.lawful totals.total := rfl
          _ = result := hEvalResult
      show evaluate updated = some result
      unfold evaluate
      split
      next =>
        unfold evaluateWellFormed
        rw [hTotalsUpdated, hTotals]
        exact congrArg some hUpdatedEvalResult
      next hNotWellFormed =>
        exact absurd hUpdatedWellFormed' hNotWellFormed

/-- Returns the same value as `value`, paired with the equation that produced it. -/
private def optionWithProof {α : Type} : (value : Option α) → Option { item : α // value = some item }
  | none => none
  | some item => some ⟨item, rfl⟩

private def evaluateWithProof (input : FinancialInput) :
    Option { result : FinancialResult // evaluate input = some result } :=
  optionWithProof (evaluate input)

private def requireFinancialInputWellFormed (input : FinancialInput) :
    Except TransitionRejectReason (PLift (financialInputWellFormed input = true)) :=
  if hWellFormed : financialInputWellFormed input = true then
    .ok ⟨hWellFormed⟩
  else
    .error .INVALID_INPUT

private theorem findCase_some {cases : List CaseRecord} {caseId : String} {record : CaseRecord}
    (hFound : findCase cases caseId = some record) : record ∈ cases ∧ record.caseId = caseId := by
  unfold findCase at hFound
  have hPredicate := List.find?_some hFound
  exact ⟨List.mem_of_find?_eq_some hFound, by simpa using hPredicate⟩

private theorem mem_updateAllCaseStatus {cases : List CaseRecord} {status : CaseStatus}
    {updatedAt : Nat} {record : CaseRecord}
    (hMem : record ∈ updateAllCaseStatus cases status updatedAt) :
    ∃ original, original ∈ cases ∧ record.caseId = original.caseId ∧
      record.obligationId = original.obligationId := by
  unfold updateAllCaseStatus at hMem
  obtain ⟨original, hOriginalMem, hEq⟩ := List.mem_map.1 hMem
  subst hEq
  exact ⟨original, hOriginalMem, rfl, rfl⟩

private theorem mem_insertCaseSorted {requested record : CaseRecord} {cases : List CaseRecord}
    (hMem : record ∈ insertCaseSorted requested cases) : record = requested ∨ record ∈ cases := by
  induction cases with
  | nil =>
      simp only [insertCaseSorted] at hMem
      exact Or.inl (List.mem_singleton.1 hMem)
  | cons first rest ih =>
      simp only [insertCaseSorted] at hMem
      split at hMem
      · exact List.mem_cons.1 hMem
      · rcases List.mem_cons.1 hMem with hFirst | hTail
        · exact Or.inr (List.mem_cons.2 (Or.inl hFirst))
        · rcases ih hTail with hRequested | hRest
          · exact Or.inl hRequested
          · exact Or.inr (List.mem_cons.2 (Or.inr hRest))

private def upsertCorrectionCase (cases : List CaseRecord) (record : CaseRecord) :
    List CaseRecord × Bool :=
  if cases.any (fun existing => existing.caseId = record.caseId) then
    (cases.map (fun existing => if existing.caseId = record.caseId then record else existing), false)
  else
    (insertCaseSorted record cases, true)

/-- After the correction upsert, every case carrying the requested case id is
    the requested case record itself. -/
private theorem upsertCorrectionCase_sameId {cases : List CaseRecord}
    {requested record : CaseRecord}
    (hMem : record ∈ (upsertCorrectionCase cases requested).1)
    (hId : record.caseId = requested.caseId) : record = requested := by
  unfold upsertCorrectionCase at hMem
  split at hMem
  next =>
    obtain ⟨original, _, hEq⟩ := List.mem_map.1 hMem
    split at hEq
    next => exact hEq.symm
    next hOriginal =>
      rw [← hEq] at hId
      exact absurd hId hOriginal
  next hAny =>
    rcases mem_insertCaseSorted hMem with hRequested | hExisting
    · exact hRequested
    · exact False.elim (hAny (List.any_eq_true.2 ⟨record, hExisting, decide_eq_true hId⟩))

/-- The case found after the upsert and the status update carries the requested
    case id and obligation id. -/
private theorem correctionCase_found_links {cases : List CaseRecord}
    {requested record : CaseRecord} {status : CaseStatus} {updatedAt : Nat}
    (hFound : findCase (updateAllCaseStatus (upsertCorrectionCase cases requested).1 status updatedAt)
      requested.caseId = some record) :
    record.caseId = requested.caseId ∧ record.obligationId = requested.obligationId := by
  obtain ⟨hMem, hId⟩ := findCase_some hFound
  obtain ⟨original, hOriginalMem, hCaseId, hObligationId⟩ := mem_updateAllCaseStatus hMem
  have hOriginal : original = requested :=
    upsertCorrectionCase_sameId hOriginalMem (hCaseId.symm.trans hId)
  exact ⟨hId, hObligationId.trans (congrArg CaseRecord.obligationId hOriginal)⟩

def buildAccepted (request : CorrectionTransitionRequest)
    (currentResult : FinancialResult) (claim : Claim)
    (hEvaluates : evaluate request.currentInput = some currentResult)
    (paid : List CorrectionPaid)
    (hDerived : derivedCorrectionPaid request.currentInput.payments request.currentInput.actions
      request.command.paymentLinks = some paid)
    (hRequestable : outstandingCorrectionCents paid request.currentInput.actions <
      currentResult.shortfallCents) :
    Except TransitionRejectReason { mutation : CorrectionMutation // CorrectionMutationLinkFacts request mutation } := do
  let command := request.command
  let input := request.currentInput
  let mutationTime := max command.decisionAtMs command.ownerNowMs
  let afterRevision := command.expectedRevision + 1
  let determinationId := "determination:" ++ command.actionId
  let supportingEvidenceIds := request.currentReceipt.evidenceBindings.map EvidenceBinding.evidenceId
  let some inputSnapshotDigest := request.currentReceipt.inputSnapshotDigest
    | throw .INPUT_SNAPSHOT_MISSING
  let determination := {
    determinationId := determinationId
    obligationId := input.context.obligationId
    claimId := command.claimId
    actorId := command.actorId
    actorRole := command.actorRole
    authorityId := input.authority.authorityId
    authorityEpoch := input.authority.epoch
    authorityDigest := input.authority.digest
    decision := correctionDecision
    amountCents := claim.amountCents
    supportingEvidenceIds := supportingEvidenceIds
    expectedRevision := command.expectedRevision
    resultingRevision := afterRevision
    decidedAt := command.decisionAtMs }
  -- The correction requests only what the rejected offset left unpaid and
  -- earlier correction requests, less what was paid against them, do not
  -- already ask for.
  let amountCents := min claim.amountCents
    (currentResult.shortfallCents - outstandingCorrectionCents paid input.actions)
  let action := {
    actionId := command.actionId
    obligationId := input.context.obligationId
    determinationId := some determinationId
    kind := actionKind
    amountCents := amountCents
    currency := input.context.currency
    revision := afterRevision
    status := .READY
    payloadDigest := correctionActionPayloadDigest
      (canonicalActionPayload request determinationId afterRevision amountCents)
    createdAt := mutationTime }
  let changedClaim := { claim with status := .REJECTED }
  let newClaims := input.claims.map (fun existing =>
    if existing.claimId = command.claimId then changedClaim else existing)
  let newDeterminations := insertDeterminationSorted determination input.determinations
  let newActions := insertActionSorted action input.actions
  let caseId := "case:" ++ input.context.obligationId
  let requestedCase : CaseRecord := {
    caseId := caseId
    obligationId := input.context.obligationId
    reason := "CORRECTION_REQUIRED"
    nextActionOwner := "CASE_OWNER"
    dueAt := claim.deadlineAt
    status := .CORRECTION_REQUIRED
    updatedAt := mutationTime }
  let upsertedCases := upsertCorrectionCase input.cases requestedCase
  let casesWithCorrection := upsertedCases.1
  let inserted := upsertedCases.2
  if newDeterminations.length > maxRows || newActions.length > maxRows ||
      casesWithCorrection.length > maxRows || afterRevision > maxRevision ||
      command.currentEventSequence ≥ maxRows then
    throw .CAPACITY
  let provisional : FinancialInput := {
    input with
    beforeRevision := command.expectedRevision
    evaluatedAt := mutationTime
    claims := newClaims
    determinations := newDeterminations
    cases := casesWithCorrection
    actions := newActions }
  if !financialInputWellFormed provisional then throw .INVALID_INPUT
  let some provisionalResultCertificate := evaluateWithProof provisional | throw .INVALID_INPUT
  let provisionalResult := provisionalResultCertificate.val
  let finalCases := updateAllCaseStatus provisional.cases provisionalResult.caseStatus mutationTime
  let resultingInput := { provisional with cases := finalCases }
  let hResultingWellFormed ← requireFinancialInputWellFormed resultingInput
  let resultingResultCertificate :
      { result : FinancialResult // evaluate resultingInput = some result } :=
    ⟨provisionalResult,
      evaluate_after_case_status_update_fixedPoint provisional provisionalResult mutationTime
        provisionalResultCertificate.property hResultingWellFormed.down⟩
  let resultingResult := resultingResultCertificate.val
  if hResultRevision : resultingResult.afterRevision = afterRevision then
    let some foundCase := optionWithProof (findCase finalCases caseId) | throw .INVALID_INPUT
    let updatedCase := foundCase.val
    have hCaseLinks : updatedCase.caseId = requestedCase.caseId ∧
        updatedCase.obligationId = requestedCase.obligationId :=
      correctionCase_found_links (cases := input.cases) (requested := requestedCase)
        (status := provisionalResult.caseStatus) (updatedAt := mutationTime)
        foundCase.property
    let caseDelta : CorrectionCaseDelta := {
      record := updatedCase
      contractualAccountability := "PROGRAM_ACCOUNTABILITY"
      completionConditionsAmountSatisfied := true
      completionConditionsReportingComplete := true
      completionConditionsDeliveryAcknowledgedOrNotRequired := true
      inserted := inserted }
    let nextEventSequence := command.currentEventSequence + 1
    let newEvaluationId := "evaluation:" ++ input.context.obligationId ++ ":r" ++ toString afterRevision
    let event : CorrectionEventIntent := {
      sequence := nextEventSequence
      previousHead := command.previousHistoryHead
      aggregateType := "OBLIGATION"
      aggregateId := input.context.obligationId
      kind := "OFFSET_REJECTED_CORRECTION_AUTHORIZED"
      beforeRevision := command.expectedRevision
      afterRevision := afterRevision
      committedAtMs := mutationTime }
    let mutation : CorrectionMutation := {
      transition := .OFFSET_REJECTED_CORRECTION_AUTHORIZED
      orderedEffects := [ .DETERMINATION_RECORDED, .CLAIM_REJECTED, .CASE_UPSERTED,
        .ACTION_CREATED, .OUTBOX_CREATED, .PROJECTION_RECOMPUTED, .EVENT_APPENDED ]
      dependencies := {
        artifactContract := correctionTransitionContract
        artifactVersion := 1
        authorityId := input.authority.authorityId
        authorityEpoch := input.authority.epoch
        authorityDigest := input.authority.digest
        controlPackId := input.pack.packId
        controlPackVersion := input.pack.version
        controlPackDigest := input.pack.digest
        inputEvaluationId := command.evaluationId
        inputEvaluationResultDigest := command.evaluationResultDigest
        inputEvaluationRevision := command.expectedRevision
        inputEvaluationEvaluatedAtMs := request.currentReceipt.result.evaluatedAtMs
        inputEvaluationSnapshotDigest := inputSnapshotDigest
        inputShortfallCents := currentResult.shortfallCents
        decisionAtMs := command.decisionAtMs
        ownerNowMs := command.ownerNowMs
        claimBefore := claim
        supportingEvidence := request.currentReceipt.evidenceBindings
        queryObservations := command.queryObservations
        currentEventSequence := command.currentEventSequence
        previousHistoryHead := command.previousHistoryHead
        correctionPaid := paid }
      followUps := {
        actionId := command.actionId
        outboxActionId := command.actionId
        caseId := caseId
        resultingEvaluationId := newEvaluationId
        eventSequence := nextEventSequence }
      resultingInput := resultingInput
      resultingResult := resultingResult
      determination := determination
      action := action
      caseDelta := caseDelta
      outbox := {
        actionId := command.actionId
        status := .READY
        attempt := 0
        acknowledgmentReference := none
        updatedAtMs := mutationTime }
      event := event }
    if currentResult.afterRevision ≠ command.expectedRevision then throw .REVISION_CONFLICT
    let linkFacts : CorrectionMutationLinkFacts request mutation := {
      transition := rfl
      effectSequence := rfl
      determinationIdentity := rfl
      acceptedActionIdentity := rfl
      actionDeterminationIdentity := rfl
      actionObligationIdentity := rfl
      outboxActionIdentity := rfl
      followUpActionIdentity := rfl
      followUpOutboxIdentity := rfl
      caseIdentity := hCaseLinks.1
      followUpCaseIdentity := rfl
      caseObligationIdentity := hCaseLinks.2
      eventAggregateIdentity := rfl
      eventKind := rfl
      resultingEvaluationIdentity := rfl
      eventSequence := rfl
      followUpEventSequence := rfl
      eventPreviousHead := rfl
      dependencyEventSequence := rfl
      dependencyPreviousHead := rfl
      eventBeforeRevision := rfl
      eventAfterRevision := rfl
      determinationBeforeRevision := rfl
      determinationAfterRevision := rfl
      actionRevision := rfl
      resultingInputBeforeRevision := rfl
      resultingResultAfterRevision := hResultRevision
      dependencyEvaluationIdentity := rfl
      dependencyEvaluationDigest := rfl
      dependencyEvaluationRevision := rfl
      dependencyEvaluationTime := rfl
      dependencyDecisionTime := rfl
      dependencyOwnerTime := rfl
      dependencyAuthorityIdentity := rfl
      dependencyAuthorityEpoch := rfl
      dependencyAuthorityDigest := rfl
      dependencyControlPackIdentity := rfl
      dependencyControlPackVersion := rfl
      dependencyControlPackDigest := rfl
      dependencyEvidence := rfl
      dependencyQueries := rfl
      derivedPaid := hDerived
      readyAction := rfl
      readyOutbox := rfl
      outboxAttempt := rfl
      noAcknowledgment := rfl
      outboxActionTime := rfl
      actionPayloadDispatchMode := rfl
      actionPayloadDigest := rfl
      correctionKind := rfl
      claimAmount := rfl
      amountRule := rfl
      inputShortfall := ⟨currentResult, hEvaluates, rfl, hRequestable⟩
      resultingEvaluates := resultingResultCertificate.property
      resultingFrame := ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩
      resultingClaims := rfl
      resultingActions := insertActionSorted_perm action input.actions
      resultingDeterminations := insertDeterminationSorted_perm determination input.determinations
      authorizedDeterminations := insertDeterminationSorted_filter determination
        (fun d => decide (d.decision = .OFFSET_AUTHORIZED)) rfl input.determinations
      determinationDecision := ⟨rfl, rfl⟩
      determinationActor := ⟨rfl, rfl, rfl, rfl, rfl⟩ }
    pure ⟨mutation, linkFacts⟩
  else
    throw .REVISION_CONFLICT

inductive CorrectionTransitionPreflight (request : CorrectionTransitionRequest) where
  | duplicate
  | ready (currentResult : FinancialResult) (claim : Claim)
      (inputRevisionMatches : request.currentInput.beforeRevision + 1 = request.command.expectedRevision)
      (evaluates : evaluate request.currentInput = some currentResult)
      (paid : List CorrectionPaid)
      (derived : derivedCorrectionPaid request.currentInput.payments request.currentInput.actions
        request.command.paymentLinks = some paid)
      (requestable : outstandingCorrectionCents paid request.currentInput.actions <
        currentResult.shortfallCents)

def preflightCorrectionTransitionV0 (request : CorrectionTransitionRequest) :
    Except TransitionRejectReason (CorrectionTransitionPreflight request) := do
  let command := request.command
  if command.currentAuthorityId.isEmpty || command.currentAuthorityEpoch < 1 ||
      command.currentAuthorityEpoch > maxAuthorityEpoch ||
      !idWellFormed command.currentAuthorityId || !digestWellFormed command.currentAuthorityDigest ||
      !idWellFormed command.itemId || !idWellFormed command.claimId ||
      !idWellFormed command.actionId || !idWellFormed command.actorId ||
      !roleWellFormed command.actorRole || !idWellFormed command.evaluationId ||
      !digestWellFormed command.evaluationResultDigest ||
      !revisionWellFormed command.expectedRevision || !timeWellFormed command.decisionAtMs ||
      !timeWellFormed command.ownerNowMs || !digestWellFormed command.previousHistoryHead ||
      !correctionQueryObservationsWellFormed command.queryObservations then
    throw .INVALID_REQUEST
  if !querySetCompleteAtCommand command then throw .QUERY_OBSERVATION_INVALID
  match command.actionLookup with
  | .conflicting => throw .ACTION_CONFLICT
  | .existing identity =>
      if querySetExactRetry command.queryObservations command &&
          request.currentInput.context.itemId = command.itemId &&
          existingIdentityMatches request identity then
        if lookupAuthorityMatches command identity then
          return .duplicate
        else
          throw .AUTHORITY_STALE
      else
        throw .ACTION_CONFLICT
  | .absent => pure ()
  if command.queryObservations.actionId.matchCount ≠ 0 ||
      command.queryObservations.actionId.resultIdentity.isSome then
    throw .ACTION_CONFLICT
  if command.queryObservations.determinationId.matchCount ≠ 0 ||
      command.queryObservations.determinationId.resultIdentity.isSome then
    throw .DETERMINATION_CONFLICT
  let input := request.currentInput
  if input.context.mode = .SHADOW then throw .SHADOW_READ_ONLY
  if !financialInputWellFormed input then throw .INVALID_INPUT
  -- Lean, not the caller, decides what each correction request has been paid.
  let some paid := optionWithProof (derivedCorrectionPaid input.payments input.actions
    command.paymentLinks) | throw .INVALID_INPUT
  if input.context.itemId ≠ command.itemId || input.context.obligationId ≠ request.currentReceipt.result.obligationId then
    throw .SCOPE_MISMATCH
  if !sameAuthority input.authority command.currentAuthorityId
      command.currentAuthorityEpoch command.currentAuthorityDigest then
    throw .AUTHORITY_STALE
  if !authorityActorBindingWellFormed input.authority command.actorId command.actorRole ||
      !input.pack.authorizedRoles.contains command.actorRole then
    throw .ACTOR_UNAUTHORIZED
  let some claim := findClaim input.claims command.claimId | throw .CLAIM_MISSING
  if claim.status ≠ .CLAIMED then throw .CLAIM_NOT_CLAIMED
  if command.expectedRevision = 0 then throw .REVISION_CONFLICT
  if hInputRevision : input.beforeRevision + 1 = command.expectedRevision then
    let some currentCertificate := evaluateWithProof input | throw .INVALID_INPUT
    let currentResult := currentCertificate.val
    if request.currentReceipt.inputSnapshotDigest.isNone then
      throw .INPUT_SNAPSHOT_MISSING
    if !currentReceiptBound request currentResult then
      throw .EVALUATION_CONFLICT
    if !request.currentReceipt.evidenceBindings.any (fun binding => binding.evidenceId = claim.evidenceId) then
      throw .EVIDENCE_COVERAGE
    if request.currentReceipt.result.evaluatedAtMs > command.decisionAtMs then
      throw .CHRONOLOGY
    if command.queryObservations.evaluationConsumed.matchCount ≠ 0 ||
        command.queryObservations.evaluationConsumed.resultIdentity.isSome then
      throw .EVALUATION_CONSUMED
    if command.currentEventSequence ≥ maxRows then throw .CAPACITY
    if command.actionId ∈ input.actions.map ActionRecord.actionId ||
        ("determination:" ++ command.actionId) ∈ input.determinations.map OffsetDetermination.determinationId then
      throw .ACTION_CONFLICT
    -- Nothing is short: rejecting the offset leaves no balance to request.
    if currentResult.shortfallCents = 0 then throw .NO_SHORTFALL
    -- Earlier correction requests, less what was paid against them, already
    -- ask for the whole unpaid balance.
    if hRequestable : outstandingCorrectionCents paid.val input.actions <
        currentResult.shortfallCents then
      pure (.ready currentResult claim hInputRevision currentCertificate.property paid.val
        paid.property hRequestable)
    else
      throw .NO_REQUESTABLE_BALANCE
  else
    throw .REVISION_CONFLICT

inductive OffsetDecisionPreflight (request : CorrectionTransitionRequest) where
  | duplicate
  | ready (currentResult : FinancialResult) (claim : Claim)
      (inputRevisionMatches : request.currentInput.beforeRevision + 1 = request.command.expectedRevision)
      (evaluates : evaluate request.currentInput = some currentResult)
      (paid : List CorrectionPaid)
      (derived : derivedCorrectionPaid request.currentInput.payments request.currentInput.actions
        request.command.paymentLinks = some paid)

def preflightOffsetDecision (decision : DeterminationDecision) (request : CorrectionTransitionRequest) :
    Except TransitionRejectReason (OffsetDecisionPreflight request) := do
  let command := request.command
  if command.currentAuthorityId.isEmpty || command.currentAuthorityEpoch < 1 ||
      command.currentAuthorityEpoch > maxAuthorityEpoch ||
      !idWellFormed command.currentAuthorityId || !digestWellFormed command.currentAuthorityDigest ||
      !idWellFormed command.itemId || !idWellFormed command.claimId ||
      !idWellFormed command.actionId || !idWellFormed command.actorId ||
      !roleWellFormed command.actorRole || !idWellFormed command.evaluationId ||
      !digestWellFormed command.evaluationResultDigest ||
      !revisionWellFormed command.expectedRevision || !timeWellFormed command.decisionAtMs ||
      !timeWellFormed command.ownerNowMs || !digestWellFormed command.previousHistoryHead ||
      !correctionQueryObservationsWellFormed command.queryObservations then
    throw .INVALID_REQUEST
  if !querySetCompleteAtCommand command then throw .QUERY_OBSERVATION_INVALID
  match command.actionLookup with
  | .conflicting => throw .ACTION_CONFLICT
  | .existing identity =>
      if querySetExactRetry command.queryObservations command &&
          request.currentInput.context.itemId = command.itemId &&
          offsetIdentityMatches decision request identity then
        if lookupAuthorityMatches command identity then
          return .duplicate
        else
          throw .AUTHORITY_STALE
      else
        throw .ACTION_CONFLICT
  | .absent => pure ()
  if command.queryObservations.actionId.matchCount ≠ 0 ||
      command.queryObservations.actionId.resultIdentity.isSome then
    throw .ACTION_CONFLICT
  if command.queryObservations.determinationId.matchCount ≠ 0 ||
      command.queryObservations.determinationId.resultIdentity.isSome then
    throw .DETERMINATION_CONFLICT
  let input := request.currentInput
  if input.context.mode = .SHADOW then throw .SHADOW_READ_ONLY
  if !financialInputWellFormed input then throw .INVALID_INPUT
  let some paid := optionWithProof (derivedCorrectionPaid input.payments input.actions
    command.paymentLinks) | throw .INVALID_INPUT
  if input.context.itemId ≠ command.itemId || input.context.obligationId ≠ request.currentReceipt.result.obligationId then
    throw .SCOPE_MISMATCH
  if !sameAuthority input.authority command.currentAuthorityId
      command.currentAuthorityEpoch command.currentAuthorityDigest then
    throw .AUTHORITY_STALE
  -- M4 (A1 closure): the digest is the digest of the roster the actor check below reads.
  if authorityDigestOf input.authority ≠ command.currentAuthorityDigest then throw .AUTHORITY_STALE
  if !authorityActorBindingWellFormed input.authority command.actorId command.actorRole ||
      !input.pack.authorizedRoles.contains command.actorRole then
    throw .ACTOR_UNAUTHORIZED
  -- M4: a decision is never dated before its control pack was approved.
  if command.decisionAtMs < input.pack.approvedAt then throw .CONTROL_PACK_REJECTED
  let some claim := findClaim input.claims command.claimId | throw .CLAIM_MISSING
  if claim.status ≠ .CLAIMED then throw .CLAIM_NOT_CLAIMED
  if command.expectedRevision = 0 then throw .REVISION_CONFLICT
  if hInputRevision : input.beforeRevision + 1 = command.expectedRevision then
    let some currentCertificate := evaluateWithProof input | throw .INVALID_INPUT
    let currentResult := currentCertificate.val
    if request.currentReceipt.inputSnapshotDigest.isNone then
      throw .INPUT_SNAPSHOT_MISSING
    if !currentReceiptBound request currentResult then
      throw .EVALUATION_CONFLICT
    if !request.currentReceipt.evidenceBindings.any (fun binding => binding.evidenceId = claim.evidenceId) then
      throw .EVIDENCE_COVERAGE
    if request.currentReceipt.result.evaluatedAtMs > command.decisionAtMs then
      throw .CHRONOLOGY
    -- M4: a decision is never dated after the owner's clock.
    if command.decisionAtMs > command.ownerNowMs then throw .CHRONOLOGY
    if command.queryObservations.evaluationConsumed.matchCount ≠ 0 ||
        command.queryObservations.evaluationConsumed.resultIdentity.isSome then
      throw .EVALUATION_CONSUMED
    if command.currentEventSequence ≥ maxRows then throw .CAPACITY
    if command.actionId ∈ input.actions.map ActionRecord.actionId ||
        ("determination:" ++ command.actionId) ∈ input.determinations.map OffsetDetermination.determinationId then
      throw .ACTION_CONFLICT
    pure (.ready currentResult claim hInputRevision currentCertificate.property paid.val paid.property)
  else
    throw .REVISION_CONFLICT

def preflightCorrectionTransition (request : CorrectionTransitionRequest) :
    Except TransitionRejectReason (CorrectionTransitionPreflight request) := do
  match ← preflightOffsetDecision .OFFSET_REJECTED_CORRECTION_AUTHORIZED request with
  | .duplicate => pure .duplicate
  | .ready currentResult claim hRevision hEvaluates paid hDerived =>
    if currentResult.shortfallCents = 0 then throw .NO_SHORTFALL
    if hRequestable : outstandingCorrectionCents paid request.currentInput.actions <
        currentResult.shortfallCents then
      pure (.ready currentResult claim hRevision hEvaluates paid hDerived hRequestable)
    else
      throw .NO_REQUESTABLE_BALANCE

def applyCorrectionTransition (request : CorrectionTransitionRequest) : CorrectionTransitionResult :=
  match preflightCorrectionTransition request with
  | .error reason => reject request.command reason
  | .ok .duplicate => duplicate request.command
  | .ok (.ready currentResult claim _ hEvaluates paid hDerived hRequestable) =>
      match buildAccepted request currentResult claim hEvaluates paid hDerived hRequestable with
      | .error reason => reject request.command reason
      | .ok certified =>
          let mutation := certified.val
          let explanation : TransitionExplanation := {
            code := .CORRECTION_AUTHORIZED
            transition := some (.OFFSET_REJECTED_CORRECTION_AUTHORIZED)
            rejectReason := none
            unresolvedRequirement := none
            claimId := some (request.command.claimId)
            actionId := some (request.command.actionId)
            inputEvaluationId := some (request.command.evaluationId)
            expectedRevision := some (request.command.expectedRevision)
            resultingRevision := some (mutation.resultingResult.afterRevision) }
          CorrectionTransitionResult.mk
            .ACCEPTED
            none
            explanation
            (some request.command.actionId)
            (some ("determination:" ++ request.command.actionId))
            (some mutation)

-- NEW. Python `_ensure_case`: an outstanding correction keeps its case; anything else is replaced or inserted.
def upsertOffsetCase (cases : List CaseRecord) (record : CaseRecord) : List CaseRecord × Bool :=
  match findCase cases record.caseId with
  | some existing => if existing.status = .CORRECTION_REQUIRED then (cases, false)
                     else upsertCorrectionCase cases record
  | none => upsertCorrectionCase cases record

-- NEW. The writes of today's Python `authorize_offset`, decided in Lean. Same frame as `buildAccepted`
-- (time, ids, capacity, provisional input, case-status fixed point); differences are marked.
def buildAuthorized (request : CorrectionTransitionRequest) (currentResult : FinancialResult)
    (claim : Claim) (paid : List CorrectionPaid) : Except TransitionRejectReason CorrectionMutation := do
  let command := request.command
  let input := request.currentInput
  let mutationTime := max command.decisionAtMs command.ownerNowMs
  let afterRevision := command.expectedRevision + 1
  let determinationId := "determination:" ++ command.actionId
  let some inputSnapshotDigest := request.currentReceipt.inputSnapshotDigest
    | throw .INPUT_SNAPSHOT_MISSING
  let determination : OffsetDetermination := {
    determinationId := determinationId
    obligationId := input.context.obligationId
    claimId := command.claimId
    actorId := command.actorId
    actorRole := command.actorRole
    authorityId := input.authority.authorityId
    authorityEpoch := input.authority.epoch
    authorityDigest := input.authority.digest
    decision := .OFFSET_AUTHORIZED                                     -- differs
    amountCents := claim.amountCents
    supportingEvidenceIds := request.currentReceipt.evidenceBindings.map EvidenceBinding.evidenceId
    expectedRevision := command.expectedRevision
    resultingRevision := afterRevision
    decidedAt := command.decisionAtMs }
  let action : ActionRecord := {
    actionId := command.actionId
    obligationId := input.context.obligationId
    determinationId := some determinationId
    kind := "OFFSET_AUTHORIZATION"                                     -- differs
    amountCents := claim.amountCents                                   -- differs: the whole claim
    currency := input.context.currency
    revision := afterRevision
    status := .READY
    payloadDigest := correctionActionPayloadDigest
      (offsetActionPayload "OFFSET_AUTHORIZATION" request determinationId afterRevision claim.amountCents)
    createdAt := mutationTime }
  let newClaims := input.claims.map (fun existing =>
    if existing.claimId = command.claimId then { claim with status := .AUTHORIZED } else existing)  -- differs
  let newDeterminations := insertDeterminationSorted determination input.determinations
  let newActions := insertActionSorted action input.actions
  let caseId := "case:" ++ input.context.obligationId
  let requestedCase : CaseRecord := {
    caseId := caseId
    obligationId := input.context.obligationId
    reason := "OFFSET_AUTHORIZED"                                      -- differs
    nextActionOwner := "CASE_OWNER"
    dueAt := claim.deadlineAt
    status := .AUTHORIZED                                              -- differs
    updatedAt := mutationTime }
  let (casesWithDecision, inserted) := upsertOffsetCase input.cases requestedCase  -- differs
  if newDeterminations.length > maxRows || newActions.length > maxRows ||
      casesWithDecision.length > maxRows || afterRevision > maxRevision ||
      command.currentEventSequence ≥ maxRows then
    throw .CAPACITY
  let provisional : FinancialInput := {
    input with
    beforeRevision := command.expectedRevision
    evaluatedAt := mutationTime
    claims := newClaims
    determinations := newDeterminations
    cases := casesWithDecision
    actions := newActions }
  if !financialInputWellFormed provisional then throw .INVALID_INPUT
  let some provisionalResult := evaluate provisional | throw .INVALID_INPUT
  let resultingInput := { provisional with
    cases := updateAllCaseStatus provisional.cases provisionalResult.caseStatus mutationTime }
  if !financialInputWellFormed resultingInput then throw .INVALID_INPUT
  -- `evaluate_after_case_status_update_fixedPoint`: re-evaluating `resultingInput` gives this result.
  if provisionalResult.afterRevision ≠ afterRevision then throw .REVISION_CONFLICT
  let some updatedCase := findCase resultingInput.cases caseId | throw .INVALID_INPUT
  if currentResult.afterRevision ≠ command.expectedRevision then throw .REVISION_CONFLICT
  let nextEventSequence := command.currentEventSequence + 1
  pure {
    transition := .OFFSET_AUTHORIZED
    orderedEffects := [ .DETERMINATION_RECORDED, .CLAIM_AUTHORIZED, .CASE_UPSERTED,
      .ACTION_CREATED, .OUTBOX_CREATED, .PROJECTION_RECOMPUTED, .EVENT_APPENDED ]
    dependencies := {
      artifactContract := correctionTransitionContract
      artifactVersion := 1
      authorityId := input.authority.authorityId
      authorityEpoch := input.authority.epoch
      authorityDigest := input.authority.digest
      controlPackId := input.pack.packId
      controlPackVersion := input.pack.version
      controlPackDigest := input.pack.digest
      inputEvaluationId := command.evaluationId
      inputEvaluationResultDigest := command.evaluationResultDigest
      inputEvaluationRevision := command.expectedRevision
      inputEvaluationEvaluatedAtMs := request.currentReceipt.result.evaluatedAtMs
      inputEvaluationSnapshotDigest := inputSnapshotDigest
      inputShortfallCents := currentResult.shortfallCents
      decisionAtMs := command.decisionAtMs
      ownerNowMs := command.ownerNowMs
      claimBefore := claim
      supportingEvidence := request.currentReceipt.evidenceBindings
      queryObservations := command.queryObservations
      currentEventSequence := command.currentEventSequence
      previousHistoryHead := command.previousHistoryHead
      correctionPaid := paid }
    followUps := {
      actionId := command.actionId
      outboxActionId := command.actionId
      caseId := caseId
      resultingEvaluationId := "evaluation:" ++ input.context.obligationId ++ ":r" ++ toString afterRevision
      eventSequence := nextEventSequence }
    resultingInput := resultingInput
    resultingResult := provisionalResult
    determination := determination
    action := action
    caseDelta := {
      record := updatedCase
      contractualAccountability := "PROGRAM_ACCOUNTABILITY"
      completionConditionsAmountSatisfied := true
      completionConditionsReportingComplete := true
      completionConditionsDeliveryAcknowledgedOrNotRequired := true
      inserted := inserted }
    outbox := {
      actionId := command.actionId
      status := .READY
      attempt := 0
      acknowledgmentReference := none
      updatedAtMs := mutationTime }
    event := {
      sequence := nextEventSequence
      previousHead := command.previousHistoryHead
      aggregateType := "OBLIGATION"
      aggregateId := input.context.obligationId
      kind := "OFFSET_AUTHORIZED"                                       -- differs
      beforeRevision := command.expectedRevision
      afterRevision := afterRevision
      committedAtMs := mutationTime } }

-- NEW. `duplicate` with the transition kind as a parameter.
def duplicateOf (kind : TransitionKind) (command : CorrectionCommand) : CorrectionTransitionResult :=
  { duplicate command with explanation := { (duplicate command).explanation with transition := some kind } }

-- NEW. Served for BLFOFA01 frames.
def applyOffsetAuthorization (request : CorrectionTransitionRequest) : CorrectionTransitionResult :=
  match preflightOffsetDecision .OFFSET_AUTHORIZED request with
  | .error reason => reject request.command reason
  | .ok .duplicate => duplicateOf .OFFSET_AUTHORIZED request.command
  | .ok (.ready currentResult claim _ _ paid _) =>
      match buildAuthorized request currentResult claim paid with
      | .error reason => reject request.command reason
      | .ok mutation =>
          { status := .ACCEPTED
            rejectReason := none
            explanation := {
              code := .OFFSET_AUTHORIZED
              transition := some .OFFSET_AUTHORIZED
              rejectReason := none
              unresolvedRequirement := none
              claimId := some request.command.claimId
              actionId := some request.command.actionId
              inputEvaluationId := some request.command.evaluationId
              expectedRevision := some request.command.expectedRevision
              resultingRevision := some mutation.resultingResult.afterRevision }
            actionId := some request.command.actionId
            determinationId := some ("determination:" ++ request.command.actionId)
            mutation := some mutation }

/-- The case found after the upsert and the status update is the requested case with the
    new status and time. -/
private theorem correctionCase_found_eq {cases : List CaseRecord}
    {requested record : CaseRecord} {status : CaseStatus} {updatedAt : Nat}
    (hFound : findCase (updateAllCaseStatus (upsertCorrectionCase cases requested).1 status updatedAt)
      requested.caseId = some record) :
    record = { requested with status := status, updatedAt := updatedAt } := by
  obtain ⟨hMem, hId⟩ := findCase_some hFound
  obtain ⟨original, hOriginalMem, rfl⟩ := List.mem_map.1 hMem
  rw [upsertCorrectionCase_sameId hOriginalMem hId]
theorem ite_error_ok {c : Prop} [Decidable c] {ε α} {e : ε} {X : Except ε α} {r : α}
    (h : (if c then Except.error e else X) = Except.ok r) : ¬ c ∧ X = Except.ok r := by
  split at h <;> simp_all

private theorem dite_error_ok {c : Prop} [Decidable c] {ε α} {e : ε} {X : c → Except ε α} {r : α}
    (h : (if hc : c then X hc else Except.error e) = Except.ok r) : ∃ hc : c, X hc = Except.ok r := by
  split at h
  · exact ⟨‹_›, h⟩
  · cases h

private theorem bind_ok {ε α β} {x : Except ε α} {f : α → Except ε β} {r : β}
    (h : (x >>= f) = Except.ok r) : ∃ a, x = Except.ok a ∧ f a = Except.ok r := by
  cases x with
  | error e => cases h
  | ok a => exact ⟨a, rfl, h⟩

private theorem ite_cases {c : Prop} [Decidable c] {α} {X Y r : α}
    (h : (if c then X else Y) = r) : (c ∧ X = r) ∨ (¬c ∧ Y = r) := by
  by_cases hc : c
  · rw [if_pos hc] at h; exact Or.inl ⟨hc, h⟩
  · rw [if_neg hc] at h; exact Or.inr ⟨hc, h⟩

private theorem dite_cases {c : Prop} [Decidable c] {α} {X : c → α} {Y r : α}
    (h : (if hc : c then X hc else Y) = r) : (∃ hc : c, X hc = r) ∨ (¬c ∧ Y = r) := by
  by_cases hc : c
  · rw [dif_pos hc] at h; exact Or.inl ⟨hc, h⟩
  · rw [dif_neg hc] at h; exact Or.inr ⟨hc, h⟩

-- The proofs below split on these calls; keeping them opaque stops `split` evaluating the input.
-- The sections keep the attribute off the executable's definitions.
section
attribute [local irreducible] evaluateWithProof requireFinancialInputWellFormed optionWithProof findCase

/-- What the accepted mutation records beyond the link facts: the claim it rejects, the times,
    the constants, and the case it writes. -/
theorem buildAccepted_facts {request : CorrectionTransitionRequest}
    {currentResult : FinancialResult} {claim : Claim} {hEvaluates paid hDerived hRequestable}
    {mutation : CorrectionMutation} {links : CorrectionMutationLinkFacts request mutation}
    (h : buildAccepted request currentResult claim hEvaluates paid hDerived hRequestable =
      .ok ⟨mutation, links⟩) :
    mutation.dependencies.claimBefore = claim ∧
      mutation.event.aggregateType = "OBLIGATION" ∧
      mutation.event.committedAtMs = max request.command.decisionAtMs request.command.ownerNowMs ∧
      mutation.action.createdAt = mutation.event.committedAtMs ∧
      mutation.determination.decidedAt = request.command.decisionAtMs ∧
      mutation.determination.supportingEvidenceIds =
        request.currentReceipt.evidenceBindings.map EvidenceBinding.evidenceId ∧
      mutation.dependencies.artifactContract = correctionTransitionContract ∧
      mutation.dependencies.artifactVersion = 1 ∧
      request.currentReceipt.inputSnapshotDigest =
        some mutation.dependencies.inputEvaluationSnapshotDigest ∧
      mutation.caseDelta.record.reason = "CORRECTION_REQUIRED" ∧
      mutation.caseDelta.record.nextActionOwner = "CASE_OWNER" ∧
      mutation.caseDelta.record.dueAt = claim.deadlineAt ∧
      mutation.caseDelta.record.status = mutation.resultingResult.caseStatus ∧
      mutation.caseDelta.record.updatedAt = mutation.event.committedAtMs ∧
      mutation.caseDelta.contractualAccountability = "PROGRAM_ACCOUNTABILITY" ∧
      mutation.caseDelta.completionConditionsAmountSatisfied = true ∧
      mutation.caseDelta.completionConditionsReportingComplete = true ∧
      mutation.caseDelta.completionConditionsDeliveryAcknowledgedOrNotRequired = true ∧
      financialInputWellFormed mutation.resultingInput = true ∧
      mutation.outbox.updatedAtMs = mutation.event.committedAtMs := by
  delta buildAccepted at h
  generalize hDigest : request.currentReceipt.inputSnapshotDigest = D at h
  cases D with
  | none => cases h
  | some digest =>
    obtain ⟨-, h⟩ := ite_error_ok h
    obtain ⟨-, h⟩ := ite_error_ok h
    generalize evaluateWithProof _ = A at h
    cases A with
    | none => cases h
    | some certificate =>
      obtain ⟨hRes0, -, h⟩ := bind_ok h
      obtain ⟨hRev, h⟩ := dite_error_ok h
      generalize optionWithProof _ = C at h
      cases C with
      | none => cases h
      | some foundCase =>
        have hCase := correctionCase_found_eq foundCase.property
        obtain ⟨-, h⟩ := ite_error_ok h
        cases Except.ok.inj h
        generalize foundCase.val = R at hCase ⊢
        subst hCase
        refine ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_,
          hRes0.down, rfl⟩
        all_goals rfl

end

section
attribute [local irreducible] evaluateWithProof requireFinancialInputWellFormed optionWithProof findCase

private theorem no_match_observed {n : Nat} {r : Option String}
    (h : ¬(decide (n ≠ 0) || r.isSome) = true) : n = 0 ∧ r = none := by
  cases r <;> simp_all

/-- A ready preflight has passed the live-mode, well-formedness, authority and actor checks, and
    found the claim still claimed and covered by receipt evidence, against an unconsumed evaluation
    whose id, action id and determination id nothing has used. -/
theorem preflightOffsetDecision_ready_facts {decision : DeterminationDecision}
    {request : CorrectionTransitionRequest} {currentResult : FinancialResult} {claim : Claim}
    {a b paid c}
    (h : preflightOffsetDecision decision request = .ok
      (.ready currentResult claim a b paid c)) :
    authorityDigestOf request.currentInput.authority = request.command.currentAuthorityDigest ∧
      request.currentInput.pack.approvedAt ≤ request.command.decisionAtMs ∧
      request.command.decisionAtMs ≤ request.command.ownerNowMs ∧
    request.currentInput.context.mode ≠ .SHADOW ∧
      financialInputWellFormed request.currentInput = true ∧
      sameAuthority request.currentInput.authority request.command.currentAuthorityId
        request.command.currentAuthorityEpoch request.command.currentAuthorityDigest = true ∧
      authorityActorBindingWellFormed request.currentInput.authority request.command.actorId
        request.command.actorRole = true ∧
      request.currentInput.pack.authorizedRoles.contains request.command.actorRole = true ∧
      findClaim request.currentInput.claims request.command.claimId = some claim ∧
      claim.status = .CLAIMED ∧
      request.command.evaluationId = "evaluation:" ++ request.currentInput.context.obligationId ++
        ":r" ++ toString request.command.expectedRevision ∧
      request.currentReceipt.evidenceBindings.any
        (fun binding => binding.evidenceId = claim.evidenceId) = true ∧
      request.currentReceipt.result.evaluatedAtMs ≤ request.command.decisionAtMs ∧
      (∀ x ∈ request.currentInput.actions, x.actionId ≠ request.command.actionId) ∧
      (request.command.queryObservations.actionId.predicate = .ACTION_ID ∧
        request.command.queryObservations.actionId.subject = request.command.actionId ∧
        request.command.queryObservations.actionId.complete = true ∧
        request.command.queryObservations.actionId.matchCount = 0 ∧
        request.command.queryObservations.actionId.resultIdentity = none) ∧
      (request.command.queryObservations.determinationId.predicate = .DETERMINATION_ID ∧
        request.command.queryObservations.determinationId.subject =
          "determination:" ++ request.command.actionId ∧
        request.command.queryObservations.determinationId.complete = true ∧
        request.command.queryObservations.determinationId.matchCount = 0 ∧
        request.command.queryObservations.determinationId.resultIdentity = none) ∧
      (request.command.queryObservations.evaluationConsumed.predicate = .EVALUATION_CONSUMED ∧
        request.command.queryObservations.evaluationConsumed.subject = request.command.evaluationId ∧
        request.command.queryObservations.evaluationConsumed.complete = true ∧
        request.command.queryObservations.evaluationConsumed.matchCount = 0 ∧
        request.command.queryObservations.evaluationConsumed.resultIdentity = none) ∧
      correctionQueryObservationsAt request.command.queryObservations
        request.command.currentEventSequence request.command.previousHistoryHead = true := by
  delta preflightOffsetDecision at h
  obtain ⟨-, h⟩ := ite_error_ok h
  obtain ⟨hQ, h⟩ := ite_error_ok h
  generalize request.command.actionLookup = L at h
  cases L
  · obtain ⟨hA, h⟩ := ite_error_ok h
    obtain ⟨hD, h⟩ := ite_error_ok h
    obtain ⟨hShadow, h⟩ := ite_error_ok h
    obtain ⟨hWf, h⟩ := ite_error_ok h
    generalize optionWithProof (derivedCorrectionPaid request.currentInput.payments
      request.currentInput.actions request.command.paymentLinks) = P at h
    cases P with
    | none => cases h
    | some paid' =>
      obtain ⟨-, h⟩ := ite_error_ok h
      obtain ⟨hAuth, h⟩ := ite_error_ok h
      obtain ⟨hDig, h⟩ := ite_error_ok h
      obtain ⟨hActor, h⟩ := ite_error_ok h
      obtain ⟨hPack, h⟩ := ite_error_ok h
      generalize hCl : findClaim request.currentInput.claims request.command.claimId = Cl at h
      cases Cl with
      | none => cases h
      | some claim' =>
        obtain ⟨hStatus, h⟩ := ite_error_ok h
        obtain ⟨-, h⟩ := ite_error_ok h
        rcases dite_cases h with ⟨hI, h⟩ | ⟨-, h⟩
        · generalize evaluateWithProof request.currentInput = E at h
          cases E with
          | none => cases h
          | some certificate =>
            obtain ⟨hNone, h⟩ := ite_error_ok h
            obtain ⟨hBound, h⟩ := ite_error_ok h
            obtain ⟨hCover, h⟩ := ite_error_ok h
            obtain ⟨hChron, h⟩ := ite_error_ok h
            obtain ⟨hNow, h⟩ := ite_error_ok h
            obtain ⟨hConsumed, h⟩ := ite_error_ok h
            obtain ⟨-, h⟩ := ite_error_ok h
            obtain ⟨hFresh, h⟩ := ite_error_ok h
            cases Except.ok.inj h
            have hQ' : querySetCompleteAtCommand request.command = true := by simpa using hQ
            unfold querySetCompleteAtCommand querySubjectsMatch at hQ'
            simp only [Bool.and_eq_true, decide_eq_true_eq] at hQ'
            obtain ⟨⟨⟨⟨⟨-, qa⟩, qd⟩, qc⟩, ⟨⟨⟨⟨⟨pa, sa⟩, pd⟩, sd⟩, pc⟩, sc⟩⟩, qat⟩ := hQ'
            have hB : currentReceiptBound request certificate.val = true := by simpa using hBound
            have hDg : request.currentReceipt.inputSnapshotDigest.isSome = true := by
              cases hD : request.currentReceipt.inputSnapshotDigest with
              | none => exact absurd (by rw [hD]; try rfl) hNone
              | some d => rfl
            obtain ⟨d, hDd⟩ := Option.isSome_iff_exists.1 hDg
            delta currentReceiptBound at hB
            dsimp only at hB
            rw [hDd] at hB
            simp only [Bool.and_eq_true, decide_eq_true_eq] at hB
            obtain ⟨⟨⟨⟨⟨⟨⟨⟨⟨-, -⟩, -⟩, hEv⟩, -⟩, -⟩, -⟩, -⟩, -⟩, -⟩ := hB
            have hAct : authorityActorBindingWellFormed request.currentInput.authority
                  request.command.actorId request.command.actorRole = true ∧
                request.currentInput.pack.authorizedRoles.contains request.command.actorRole = true := by
              simpa using hActor
            obtain ⟨hA0, hA1⟩ := no_match_observed hA
            obtain ⟨hD0, hD1⟩ := no_match_observed hD
            obtain ⟨hC0, hC1⟩ := no_match_observed hConsumed
            refine ⟨by simpa using hDig, by omega, by omega, hShadow, by simpa using hWf, by simpa using hAuth, hAct.1, hAct.2,
              by first | rfl | assumption, by simpa using hStatus, hEv, by simpa using hCover,
              by omega, ?_, ⟨pa, sa, qa, hA0, hA1⟩, ⟨pd, sd, qd, hD0, hD1⟩,
              ⟨pc, sc, qc, hC0, hC1⟩, qat⟩
            intro x hx hEq
            apply hFresh
            simp only [Bool.or_eq_true, decide_eq_true_eq]
            exact Or.inl (List.mem_map.2 ⟨x, hx, hEq⟩)
        · cases h
  · exfalso
    rcases ite_cases h with ⟨-, h⟩ | ⟨-, h⟩
    · rcases ite_cases h with ⟨-, h⟩ | ⟨-, h⟩ <;> cases h
    · cases h
  · cases h


theorem preflightCorrectionTransition_shared {request : CorrectionTransitionRequest}
    {currentResult : FinancialResult} {claim : Claim} {a b paid c d}
    (h : preflightCorrectionTransition request = .ok
      (.ready currentResult claim a b paid c d)) :
    preflightOffsetDecision .OFFSET_REJECTED_CORRECTION_AUTHORIZED request =
      .ok (.ready currentResult claim a b paid c) := by
  delta preflightCorrectionTransition at h
  obtain ⟨r, hr, h⟩ := bind_ok h
  cases r with
  | duplicate => cases h
  | ready cr cl a' b' p c' =>
    obtain ⟨-, h⟩ := ite_error_ok h
    dsimp only at h
    split at h
    · cases Except.ok.inj h
      exact hr
    · cases h

/-- A ready preflight has passed the live-mode, well-formedness, authority and actor checks, and
    found the claim still claimed and covered by receipt evidence, against an unconsumed evaluation
    whose id, action id and determination id nothing has used. -/
theorem preflightCorrectionTransition_ready_facts {request : CorrectionTransitionRequest}
    {currentResult : FinancialResult} {claim : Claim} {a b paid c d}
    (h : preflightCorrectionTransition request = .ok
      (.ready currentResult claim a b paid c d)) :
    request.currentInput.context.mode ≠ .SHADOW ∧
      financialInputWellFormed request.currentInput = true ∧
      sameAuthority request.currentInput.authority request.command.currentAuthorityId
        request.command.currentAuthorityEpoch request.command.currentAuthorityDigest = true ∧
      authorityActorBindingWellFormed request.currentInput.authority request.command.actorId
        request.command.actorRole = true ∧
      request.currentInput.pack.authorizedRoles.contains request.command.actorRole = true ∧
      findClaim request.currentInput.claims request.command.claimId = some claim ∧
      claim.status = .CLAIMED ∧
      request.command.evaluationId = "evaluation:" ++ request.currentInput.context.obligationId ++
        ":r" ++ toString request.command.expectedRevision ∧
      request.currentReceipt.evidenceBindings.any
        (fun binding => binding.evidenceId = claim.evidenceId) = true ∧
      request.currentReceipt.result.evaluatedAtMs ≤ request.command.decisionAtMs ∧
      (∀ x ∈ request.currentInput.actions, x.actionId ≠ request.command.actionId) ∧
      (request.command.queryObservations.actionId.predicate = .ACTION_ID ∧
        request.command.queryObservations.actionId.subject = request.command.actionId ∧
        request.command.queryObservations.actionId.complete = true ∧
        request.command.queryObservations.actionId.matchCount = 0 ∧
        request.command.queryObservations.actionId.resultIdentity = none) ∧
      (request.command.queryObservations.determinationId.predicate = .DETERMINATION_ID ∧
        request.command.queryObservations.determinationId.subject =
          "determination:" ++ request.command.actionId ∧
        request.command.queryObservations.determinationId.complete = true ∧
        request.command.queryObservations.determinationId.matchCount = 0 ∧
        request.command.queryObservations.determinationId.resultIdentity = none) ∧
      (request.command.queryObservations.evaluationConsumed.predicate = .EVALUATION_CONSUMED ∧
        request.command.queryObservations.evaluationConsumed.subject = request.command.evaluationId ∧
        request.command.queryObservations.evaluationConsumed.complete = true ∧
        request.command.queryObservations.evaluationConsumed.matchCount = 0 ∧
        request.command.queryObservations.evaluationConsumed.resultIdentity = none) ∧
      correctionQueryObservationsAt request.command.queryObservations
        request.command.currentEventSequence request.command.previousHistoryHead = true := by
  exact (preflightOffsetDecision_ready_facts (preflightCorrectionTransition_shared h)).2.2.2

end

section
attribute [local irreducible] findCase

/-- What `buildAuthorized` writes: the claim flips to AUTHORIZED, the determination and action carry
    the whole claim, and the money-bearing frame is unchanged. -/
theorem buildAuthorized_spec {request : CorrectionTransitionRequest}
    {currentResult : FinancialResult} {claim : Claim} {paid : List CorrectionPaid}
    {mutation : CorrectionMutation}
    (h : buildAuthorized request currentResult claim paid = .ok mutation) :
    mutation.dependencies.claimBefore = claim ∧
      mutation.determination.determinationId = "determination:" ++ request.command.actionId ∧
      mutation.determination.decision = .OFFSET_AUTHORIZED ∧
      mutation.determination.actorId = request.command.actorId ∧
      mutation.determination.actorRole = request.command.actorRole ∧
      mutation.determination.authorityId = request.currentInput.authority.authorityId ∧
      mutation.determination.authorityEpoch = request.currentInput.authority.epoch ∧
      mutation.determination.authorityDigest = request.currentInput.authority.digest ∧
      mutation.determination.decidedAt = request.command.decisionAtMs ∧
      mutation.determination.amountCents = claim.amountCents ∧
      mutation.action.kind = "OFFSET_AUTHORIZATION" ∧
      mutation.action.actionId = request.command.actionId ∧
      mutation.action.amountCents = claim.amountCents ∧
      mutation.action.revision = request.command.expectedRevision + 1 ∧
      mutation.action.payloadDigest = correctionActionPayloadDigest
        (offsetActionPayload "OFFSET_AUTHORIZATION" request mutation.determination.determinationId
          mutation.action.revision mutation.action.amountCents) ∧
      mutation.resultingInput.claims = request.currentInput.claims.map (fun existing =>
        if existing.claimId = request.command.claimId then { claim with status := .AUTHORIZED }
        else existing) ∧
      mutation.resultingInput.payments = request.currentInput.payments ∧
      mutation.resultingInput.obligation = request.currentInput.obligation ∧
      evaluate mutation.resultingInput = some mutation.resultingResult := by
  delta buildAuthorized at h
  generalize request.currentReceipt.inputSnapshotDigest = D at h
  cases D with
  | none => cases h
  | some digest =>
    dsimp only at h
    obtain ⟨-, h⟩ := ite_error_ok h
    obtain ⟨-, h⟩ := ite_error_ok h
    generalize hE : evaluate _ = E at h
    cases E with
    | none => cases h
    | some provisionalResult =>
      obtain ⟨hWf, h⟩ := ite_error_ok h
      obtain ⟨-, h⟩ := ite_error_ok h
      generalize findCase _ _ = C at h
      cases C with
      | none => cases h
      | some updatedCase =>
        obtain ⟨-, h⟩ := ite_error_ok h
        cases Except.ok.inj h
        have hF := evaluate_after_case_status_update_fixedPoint _ provisionalResult
          (max request.command.decisionAtMs request.command.ownerNowMs) hE (by simpa using hWf)
        exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, hF⟩

end

end BlindLedger.Financial.CorrectionTransition
