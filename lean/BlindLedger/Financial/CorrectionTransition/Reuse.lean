import BlindLedger.Financial.CorrectionTransition.Transition

namespace BlindLedger.Financial.CorrectionTransition

open BlindLedger.Financial
open BlindLedger.Financial.DecisionPackage

private def queryObservationAt (observation : CorrectionQueryObservation)
    (predicate : CorrectionQueryPredicate) (subject : String)
    (sequence : Nat) (head : Bytes) : Bool :=
  correctionQueryObservationWellFormed observation && observation.complete &&
    observation.predicate = predicate && observation.subject = subject &&
    observation.versionSequence = sequence && observation.versionHead = head

private def queryObservationsAtSnapshot (observations : CorrectionQueryObservations)
    (sequence : Nat) (head : Bytes) : Bool :=
  correctionQueryObservationsWellFormed observations &&
    observations.actionId.complete && observations.determinationId.complete &&
    observations.evaluationConsumed.complete &&
    observations.actionId.versionSequence = sequence &&
    observations.actionId.versionHead = head &&
    observations.determinationId.versionSequence = sequence &&
    observations.determinationId.versionHead = head &&
    observations.evaluationConsumed.versionSequence = sequence &&
    observations.evaluationConsumed.versionHead = head

private def querySnapshotAt (observations : CorrectionQueryObservations)
    (mutation : CorrectionMutation) (sequence : Nat) (head : Bytes) : Bool :=
  sequence ≥ mutation.event.sequence && digestWellFormed head &&
    queryObservationsAtSnapshot observations sequence head &&
    queryObservationAt observations.actionId .ACTION_ID mutation.action.actionId sequence head &&
    observations.actionId.matchCount = 1 &&
    observations.actionId.resultIdentity = some mutation.action.actionId &&
    queryObservationAt observations.evaluationConsumed .EVALUATION_CONSUMED
      mutation.dependencies.inputEvaluationId sequence head &&
    observations.evaluationConsumed.matchCount = 1 &&
    observations.evaluationConsumed.resultIdentity = some mutation.determination.determinationId

private def withoutCorrectionDetermination (rows : List OffsetDetermination)
    (determinationId : String) : List OffsetDetermination :=
  rows.filter (fun row => row.determinationId ≠ determinationId)

private def casesWithoutUpdateTimes (rows : List CaseRecord) : List CaseRecord :=
  rows.map (fun row => { row with updatedAt := 0 })

/-! This comparison excludes only observation-time metadata and the one
    correction determination whose human approval is assessed on its own axis.
    Every other field that affects this obligation's calculation or projection
    remains part of the comparison. -/
private def calculationInputMatches (saved current : FinancialInput)
    (correctionDeterminationId : String) : Bool :=
  current.context = saved.context && current.authority = saved.authority &&
    current.pack = saved.pack && current.obligation = saved.obligation &&
    current.beforeRevision = saved.beforeRevision && current.payments = saved.payments &&
    current.claims = saved.claims &&
    withoutCorrectionDetermination current.determinations correctionDeterminationId =
      withoutCorrectionDetermination saved.determinations correctionDeterminationId &&
    current.evidence = saved.evidence && current.conflicts = saved.conflicts &&
    casesWithoutUpdateTimes current.cases = casesWithoutUpdateTimes saved.cases &&
    current.actions = saved.actions

private def resultMatchesPostState (saved current : FinancialResult) : Bool :=
  { current with evaluatedAt := saved.evaluatedAt } = saved

private def currentReceiptMatches (request : CorrectionReuseRequest)
    (mutation : CorrectionMutation) (currentResult : FinancialResult) : Bool :=
  let expectedEvaluationId := mutation.followUps.resultingEvaluationId
  request.currentInput.beforeRevision + 1 = mutation.resultingResult.afterRevision &&
    currentResult.afterRevision = mutation.resultingResult.afterRevision &&
    request.currentReceipt.contractVersion = evaluationReceiptContractV1 &&
    evaluationReceiptWellFormed request.currentReceipt &&
    (match request.currentReceipt.inputSnapshotDigest with
      | some digest => digestWellFormed digest
      | none => false) &&
    request.currentReceipt.result.evaluationId = expectedEvaluationId &&
    request.currentReceipt.evidenceBindings = mutation.dependencies.supportingEvidence &&
    sameOwnerResult currentResult request.currentReceipt expectedEvaluationId

def calculationReason (request : CorrectionReuseRequest)
    (mutation : CorrectionMutation) : Option CorrectionCalculationReason :=
  if !querySnapshotAt request.currentQueries mutation request.currentEventSequence
      request.currentHistoryHead then
    some .QUERY_OBSERVATION_INVALID
  else if !calculationInputMatches mutation.resultingInput request.currentInput
      mutation.determination.determinationId then
    some .RELEVANT_FINANCIAL_FACT_CHANGED
  else if request.currentReceipt.evidenceBindings ≠ mutation.dependencies.supportingEvidence then
    some .EVIDENCE_BINDING_CHANGED
  else
    match evaluate request.currentInput with
    | none => some .CURRENT_RESULT_CHANGED
    | some currentResult =>
        if !currentReceiptMatches request mutation currentResult then
          some .CURRENT_RECEIPT_INVALID
        else if !resultMatchesPostState mutation.resultingResult currentResult then
          some .CURRENT_RESULT_CHANGED
        else none

private def approvalQueryMatches (request : CorrectionReuseRequest)
    (mutation : CorrectionMutation) : Bool :=
  queryObservationAt request.currentQueries.determinationId .DETERMINATION_ID
    mutation.determination.determinationId request.currentEventSequence request.currentHistoryHead &&
    request.currentQueries.determinationId.matchCount = 1 &&
    request.currentQueries.determinationId.resultIdentity = some mutation.determination.determinationId

def approvalReason (request : CorrectionReuseRequest)
    (mutation : CorrectionMutation) : Option CorrectionApprovalReason :=
  if !approvalQueryMatches request mutation || request.currentDetermination.isNone then
    some .DETERMINATION_MISSING
  else if request.currentDetermination ≠ some mutation.determination then
    some .DETERMINATION_CHANGED
  else if request.currentDeterminationDigest ≠ some mutation.determinationDigest then
    some .DETERMINATION_DIGEST_CHANGED
  else none

private def currentAction (input : FinancialInput) (actionId : String) : Option ActionRecord :=
  input.actions.find? (fun action => action.actionId = actionId)

private def actionIdentityMatches (expected current : ActionRecord) : Bool :=
  current.actionId = expected.actionId && current.obligationId = expected.obligationId &&
    current.determinationId = expected.determinationId && current.kind = expected.kind &&
    current.amountCents = expected.amountCents && current.currency = expected.currency &&
    current.revision = expected.revision && current.payloadDigest = expected.payloadDigest &&
    current.createdAt = expected.createdAt

private def outboxIdentityMatches (expected current : CorrectionOutboxDelta) : Bool :=
  current.actionId = expected.actionId && current.attempt = expected.attempt &&
    current.payloadDigest = expected.payloadDigest && current.idempotencyKey = expected.idempotencyKey &&
    current.acknowledgmentReference = expected.acknowledgmentReference &&
    current.updatedAtMs = expected.updatedAtMs

def executionEnvironmentDenial (request : CorrectionReuseRequest)
    (mutation : CorrectionMutation) : Option CorrectionExecutionDenial := do
  if request.currentInput.context.mode = .SHADOW then
    return .SHADOW_MODE
  if !sameAuthority request.currentInput.authority mutation.dependencies.authorityId
      mutation.dependencies.authorityEpoch mutation.dependencies.authorityDigest then
    return .AUTHORITY_STALE
  if !authorityActorBindingWellFormed request.currentInput.authority
      mutation.determination.actorId mutation.determination.actorRole ||
      !request.currentInput.pack.authorizedRoles.contains mutation.determination.actorRole then
    return .ACTOR_NOT_AUTHORIZED
  if request.currentInput.pack.status ≠ .APPROVED then
    return .CONTROL_PACK_NOT_APPROVED
  let some action := currentAction request.currentInput mutation.action.actionId
    | return .ACTION_MISSING
  if !actionIdentityMatches mutation.action action then return .ACTION_CHANGED
  if action.status ≠ .READY then return .ACTION_NOT_READY
  let some outbox := request.currentOutbox | return .OUTBOX_MISSING
  if !outboxIdentityMatches mutation.outbox outbox then return .OUTBOX_CHANGED
  if outbox.status ≠ .READY || outbox.acknowledgmentReference.isSome then
    return .OUTBOX_NOT_READY
  none

def correctionExecutionAxisDenial (calculationValidity : CorrectionCalculationValidity)
    (humanApprovalValidity : CorrectionApprovalValidity) : Option CorrectionExecutionDenial :=
  if calculationValidity = .INVALID then some .CALCULATION_INVALID
  else if humanApprovalValidity = .INVALID then some .HUMAN_APPROVAL_INVALID
  else none

def executionDenial (request : CorrectionReuseRequest) (mutation : CorrectionMutation)
    (calculationValidity : CorrectionCalculationValidity)
    (humanApprovalValidity : CorrectionApprovalValidity) : Option CorrectionExecutionDenial :=
  match executionEnvironmentDenial request mutation with
  | some denial => some denial
  | none => correctionExecutionAxisDenial calculationValidity humanApprovalValidity

def calculationValidityOfReason (reason : Option CorrectionCalculationReason) :
    CorrectionCalculationValidity :=
  if reason.isNone then .VALID else .INVALID

def approvalValidityOfReason (reason : Option CorrectionApprovalReason) :
    CorrectionApprovalValidity :=
  if reason.isNone then .VALID else .INVALID

def executionPermissionOfDenial (denial : Option CorrectionExecutionDenial) :
    CorrectionExecutionPermission :=
  match denial with
  | none => .ALLOWED
  | some _ => .DENIED

def assessAcceptedCorrectionReuse (request : CorrectionReuseRequest)
    (mutation : CorrectionMutation) : CorrectionReuseAssessment :=
  let calcReason := calculationReason request mutation
  let approvalInvalidReason := approvalReason request mutation
  let calculationValidity := calculationValidityOfReason calcReason
  let humanApprovalValidity := approvalValidityOfReason approvalInvalidReason
  let executionInvalidReason := executionDenial request mutation calculationValidity
    humanApprovalValidity
  let deadlineStatus := some (if request.currentOwnerNowMs < mutation.dependencies.claimBefore.deadlineAt
    then .BEFORE_DEADLINE else .DEADLINE_REACHED)
  { calculationValidity := calculationValidity
    calculationReason := calcReason
    humanApprovalValidity := humanApprovalValidity
    humanApprovalReason := approvalInvalidReason
    localExecutionPermission := executionPermissionOfDenial executionInvalidReason
    executionDenial := executionInvalidReason
    deadlineStatus := deadlineStatus
    unrelatedWatermarkAdvanced := request.currentEventSequence > mutation.event.sequence &&
      calculationValidity = .VALID && humanApprovalValidity = .VALID &&
      executionInvalidReason.isNone
    externalDispatchPermitted := false }

def assessCorrectionReuse (request : CorrectionReuseRequest) : CorrectionReuseAssessment :=
  match request.acceptedResult.status, request.acceptedResult.mutation with
  | .ACCEPTED, some mutation =>
      assessAcceptedCorrectionReuse request mutation
  | _, _ =>
      { calculationValidity := .INVALID
        calculationReason := some .ACCEPTED_TRANSITION_REQUIRED
        humanApprovalValidity := .INVALID
        humanApprovalReason := some .ACCEPTED_TRANSITION_REQUIRED
        localExecutionPermission := .DENIED
        executionDenial := some .CALCULATION_INVALID
        deadlineStatus := none
        unrelatedWatermarkAdvanced := false
        externalDispatchPermitted := false }

end BlindLedger.Financial.CorrectionTransition
