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

private def digestHex (value : Bytes) : String :=
  String.ofList (value.foldr (fun byte output =>
    hexDigit (byte.toNat / 16) :: hexDigit (byte.toNat % 16) :: output) [])

/-! Every string in this canonical JSON payload has already passed the
    Owner's ASCII identifier/role/kind grammar. That grammar excludes JSON
    quotation marks, backslashes, control bytes, and non-ASCII text. -/
private def jsonId (value : String) : String := "\"" ++ value ++ "\""

inductive CorrectionActionDispatchMode where
  | SYNTHETIC_RECORD_ONLY
deriving DecidableEq, Repr

def CorrectionActionDispatchMode.wireValue : CorrectionActionDispatchMode → String
  | .SYNTHETIC_RECORD_ONLY => "SYNTHETIC_RECORD_ONLY"

structure CorrectionActionPayload where
  dispatchMode : CorrectionActionDispatchMode
  canonicalJson : String
deriving DecidableEq, Repr

def canonicalActionPayload (request : CorrectionTransitionRequest)
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
        ",\"kind\":\"CORRECTION_PAYMENT_REQUEST\"" ++
        ",\"obligation_id\":" ++ jsonId input.context.obligationId ++
        ",\"revision\":" ++ toString resultingRevision ++ "}" }

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
      outstandingCorrectionCents request.currentInput.actions)
  inputShortfall : ∃ result, evaluate request.currentInput = some result ∧
    result.shortfallCents = mutation.dependencies.inputShortfallCents ∧
    outstandingCorrectionCents request.currentInput.actions < result.shortfallCents

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

private def existingIdentityMatches (request : CorrectionTransitionRequest)
    (identity : ExistingCorrectionIdentity) : Bool :=
  let command := request.command
  let expectedDeterminationId := "determination:" ++ command.actionId
  identity.actionId = command.actionId &&
    identity.actionObligationId = request.currentInput.context.obligationId &&
    identity.determinationObligationId = request.currentInput.context.obligationId &&
    identity.determinationId = expectedDeterminationId &&
    identity.actionKind = actionKind && identity.claimId = command.claimId &&
    identity.actorId = command.actorId && identity.actorRole = command.actorRole &&
    identity.decision = correctionDecision &&
    identity.inputEvaluationId = command.evaluationId &&
    identity.inputEvaluationResultDigest = command.evaluationResultDigest &&
    identity.expectedRevision = command.expectedRevision &&
    identity.decidedAtMs = command.decisionAtMs

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
    (hRequestable : outstandingCorrectionCents request.currentInput.actions <
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
  -- The correction requests only what the rejected offset left unpaid and no
  -- earlier correction request already asks for.
  let amountCents := min claim.amountCents
    (currentResult.shortfallCents - outstandingCorrectionCents input.actions)
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
        previousHistoryHead := command.previousHistoryHead }
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
      inputShortfall := ⟨currentResult, hEvaluates, rfl, hRequestable⟩ }
    pure ⟨mutation, linkFacts⟩
  else
    throw .REVISION_CONFLICT

inductive CorrectionTransitionPreflight (request : CorrectionTransitionRequest) where
  | duplicate
  | ready (currentResult : FinancialResult) (claim : Claim)
      (inputRevisionMatches : request.currentInput.beforeRevision + 1 = request.command.expectedRevision)
      (evaluates : evaluate request.currentInput = some currentResult)
      (requestable : outstandingCorrectionCents request.currentInput.actions <
        currentResult.shortfallCents)

def preflightCorrectionTransition (request : CorrectionTransitionRequest) :
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
  if input.context.itemId ≠ command.itemId || input.context.obligationId ≠ request.currentReceipt.result.obligationId then
    throw .SCOPE_MISMATCH
  if !sameAuthority input.authority command.currentAuthorityId
      command.currentAuthorityEpoch command.currentAuthorityDigest then
    throw .AUTHORITY_STALE
  if !authorityActorBindingWellFormed input.authority command.actorId command.actorRole ||
      !input.pack.authorizedRoles.contains command.actorRole then
    throw .ACTOR_UNAUTHORIZED
  if input.pack.status ≠ .APPROVED then throw .CONTROL_PACK_REJECTED
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
    -- Earlier correction requests already ask for the whole unpaid balance.
    if hRequestable : outstandingCorrectionCents input.actions < currentResult.shortfallCents then
      pure (.ready currentResult claim hInputRevision currentCertificate.property hRequestable)
    else
      throw .NO_REQUESTABLE_BALANCE
  else
    throw .REVISION_CONFLICT

def applyCorrectionTransition (request : CorrectionTransitionRequest) : CorrectionTransitionResult :=
  match preflightCorrectionTransition request with
  | .error reason => reject request.command reason
  | .ok .duplicate => duplicate request.command
  | .ok (.ready currentResult claim _ hEvaluates hRequestable) =>
      match buildAccepted request currentResult claim hEvaluates hRequestable with
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

end BlindLedger.Financial.CorrectionTransition
