import BlindLedger.Financial.CorrectionTransition.Codec
import BlindLedger.Financial.CorrectionTransition.ReuseCodec
import BlindLedger.Financial.Theorems.Vectors

namespace BlindLedger.Financial.CorrectionTransition

open BlindLedger.Financial
open BlindLedger.Financial.DecisionPackage

private def katEvalAt : Nat := 1_774_922_400_000
private def katDecisionAt : Nat := 1_774_922_400_010
private def katOwnerNow : Nat := 1_774_922_400_020
private def katCorrectionClaimId : String := "claim:h:offset"
private def katCorrectionActionId : String := "action:correction:h:v1"
private def katCorrectionEvaluationId : String :=
  "evaluation:obligation:item-h:period-01:r4"

private def correctionKatDigest (byte : Nat) : Bytes :=
  List.replicate digestBytes (UInt8.ofNat byte)

private def correctionKatQuery (predicate : CorrectionQueryPredicate) (subject : String)
    (sequence head : Nat) (resultIdentity : Option String := none) : CorrectionQueryObservation := {
  predicate := predicate
  subject := subject
  complete := true
  matchCount := if resultIdentity.isSome then 1 else 0
  resultIdentity := resultIdentity
  versionSequence := sequence
  versionHead := correctionKatDigest head }

private def correctionKatAbsentQueries (sequence head : Nat) : CorrectionQueryObservations := {
  actionId := correctionKatQuery .ACTION_ID katCorrectionActionId sequence head
  determinationId := correctionKatQuery .DETERMINATION_ID
    ("determination:" ++ katCorrectionActionId) sequence head
  evaluationConsumed := correctionKatQuery .EVALUATION_CONSUMED
    katCorrectionEvaluationId sequence head }

private def correctionKatRetryQueries (sequence head : Nat) : CorrectionQueryObservations := {
  actionId := correctionKatQuery .ACTION_ID katCorrectionActionId sequence head
    (some katCorrectionActionId)
  determinationId := correctionKatQuery .DETERMINATION_ID
    ("determination:" ++ katCorrectionActionId) sequence head
    (some ("determination:" ++ katCorrectionActionId))
  evaluationConsumed := correctionKatQuery .EVALUATION_CONSUMED
    katCorrectionEvaluationId sequence head
    (some ("determination:" ++ katCorrectionActionId)) }

def correctionKatInput : FinancialInput := {
  katBase with
  beforeRevision := 3
  evaluatedAt := katEvalAt
  payments := [katPayment]
  claims := [katClaim .CLAIMED]
  evidence := [katCashEvidence, katOffsetEvidence]
  cases := [{
    caseId := "case:h:base"
    obligationId := katContext.obligationId
    reason := "OPEN"
    nextActionOwner := "CASE_OWNER"
    dueAt := katObligation.dueAt
    status := .OPEN
    updatedAt := 1_774_864_800_000 }]
  actions := [] }

def correctionKatCurrentReceipt : EvaluationReceipt := {
  contractVersion := evaluationReceiptContractV1
  scope := {
    stateId := katContext.stateId
    deploymentId := katContext.deploymentId
    programId := katContext.programId
    periodId := katContext.periodId
    currency := katContext.currency }
  controlPack := {
    packId := katPack.packId
    version := katPack.version
    digest := katPack.digest }
  evidenceBindings := [
    { evidenceId := "evidence:cash", recordDigest := correctionKatDigest 68 },
    { evidenceId := "evidence:offset", recordDigest := correctionKatDigest 68 }]
  inputSnapshotDigest := some (correctionKatDigest 91)
  authority := {
    authorityEpoch := katAuthority.epoch
    authorityDigest := katAuthority.digest }
  result := {
    evaluationId := katCorrectionEvaluationId
    obligationId := katContext.obligationId
    revision := 4
    ruleVersion := katPack.version
    evidenceIds := ["evidence:cash", "evidence:offset"]
    authorityId := katAuthority.authorityId
    evaluatedAtMs := katEvalAt
    owedCents := 10_000_000
    claimedAdjustmentCents := 300_000
    lawfulAdjustmentCents := 0
    receivedCashCents := 9_700_000
    shortfallCents := 300_000
    overageCents := 0
    cashSatisfied := false
    amountSatisfied := false
    timely := false
    reportingComplete := false
    verificationStatus := "SUPPORTED"
    caseStatus := "OPEN"
    deliveryStatus := "NONE" }
  resultDigest := correctionKatDigest 165
  receiptDigest := correctionKatDigest 90
  evaluationResultDigest := correctionKatDigest 165 }

def correctionKatCommand : CorrectionCommand := {
  itemId := katContext.itemId
  claimId := katCorrectionClaimId
  actionId := katCorrectionActionId
  actorId := "synthetic-official"
  actorRole := "FINANCE_DECISION"
  currentAuthorityId := katAuthority.authorityId
  currentAuthorityEpoch := katAuthority.epoch
  currentAuthorityDigest := katAuthority.digest
  expectedRevision := 4
  evaluationId := katCorrectionEvaluationId
  evaluationResultDigest := correctionKatDigest 165
  decisionAtMs := katDecisionAt
  ownerNowMs := katOwnerNow
  actionLookup := .absent
  queryObservations := correctionKatAbsentQueries 10 42
  currentEventSequence := 10
  previousHistoryHead := correctionKatDigest 42 }

def correctionKatRequest : CorrectionTransitionRequest := {
  command := correctionKatCommand
  currentInput := correctionKatInput
  currentReceipt := correctionKatCurrentReceipt }

def correctionKatAccepted : CorrectionTransitionResult :=
  applyCorrectionTransition correctionKatRequest

def correctionKatStoredIdentity : ExistingCorrectionIdentity := {
  actionId := katCorrectionActionId
  actionObligationId := katContext.obligationId
  determinationId := "determination:action:correction:h:v1"
  determinationObligationId := katContext.obligationId
  actionKind := "CORRECTION_PAYMENT_REQUEST"
  claimId := katCorrectionClaimId
  actorId := "synthetic-official"
  actorRole := "FINANCE_DECISION"
  authorityId := katAuthority.authorityId
  authorityEpoch := katAuthority.epoch
  authorityDigest := katAuthority.digest
  decision := .OFFSET_REJECTED_CORRECTION_AUTHORIZED
  inputEvaluationId := katCorrectionEvaluationId
  inputEvaluationResultDigest := correctionKatDigest 165
  expectedRevision := 4
  decidedAtMs := katDecisionAt }

def correctionKatPostInput : FinancialInput :=
  match correctionKatAccepted.mutation with
  | some mutation => mutation.resultingInput
  | none => correctionKatInput

def correctionKatRetryRequest : CorrectionTransitionRequest := {
  correctionKatRequest with
  command := {
    correctionKatCommand with
    actionLookup := .existing correctionKatStoredIdentity
    queryObservations := correctionKatRetryQueries 11 43
    currentEventSequence := 11
    previousHistoryHead := correctionKatDigest 43 }
  currentInput := {
    correctionKatPostInput with
    beforeRevision := 5
    evaluatedAt := katOwnerNow + 2
    actions := correctionKatPostInput.actions.map (fun action =>
      { action with status := .ACKNOWLEDGED }) }
  currentReceipt := correctionKatCurrentReceipt }

private def resultHasReason (result : CorrectionTransitionResult)
    (reason : TransitionRejectReason) : Bool :=
  result.status = .REJECTED && result.rejectReason = some reason &&
    result.explanation.unresolvedRequirement = some (requiredTransitionCondition reason) &&
    result.mutation.isNone

def gateCorrectionAcceptedTransition : Bool :=
  match correctionKatAccepted.mutation with
  | none => false
  | some mutation =>
      correctionKatAccepted.status = .ACCEPTED && correctionKatAccepted.rejectReason.isNone &&
      mutation.resultingInput.claims = [{ katClaim .CLAIMED with status := .REJECTED }] &&
      mutation.resultingInput.payments = correctionKatInput.payments &&
      mutation.resultingResult.afterRevision = 5 &&
      mutation.resultingResult.claimedAdjustmentCents = 0 &&
      mutation.resultingResult.receivedCashCents = 9_700_000 &&
      mutation.dependencies.inputShortfallCents = 300_000 &&
      mutation.determination.amountCents = 300_000 && mutation.action.amountCents = 300_000 &&
      mutation.action.payloadDigest = pendingPayloadDigest &&
      mutation.determination.decision = .OFFSET_REJECTED_CORRECTION_AUTHORIZED &&
      mutation.determination.expectedRevision = 4 && mutation.determination.resultingRevision = 5 &&
      mutation.action.kind = "CORRECTION_PAYMENT_REQUEST" && mutation.action.status = .READY &&
      mutation.action.revision = 5 && mutation.outbox.status = .READY &&
      mutation.outbox.attempt = 0 && mutation.outbox.acknowledgmentReference.isNone &&
      mutation.caseDelta.record.reason = "CORRECTION_REQUIRED" &&
      mutation.caseDelta.record.nextActionOwner = "CASE_OWNER" &&
      mutation.event.kind = "OFFSET_REJECTED_CORRECTION_AUTHORIZED" &&
      mutation.event.sequence = 11 && mutation.followUps.resultingEvaluationId =
        "evaluation:obligation:item-h:period-01:r5" &&
      mutation.orderedEffects = [ .DETERMINATION_RECORDED, .CLAIM_REJECTED, .CASE_UPSERTED,
        .ACTION_CREATED, .OUTBOX_CREATED, .PROJECTION_RECOMPUTED, .EVENT_APPENDED ]

def gateCorrectionInputReceiptBound : Bool :=
  match evaluate correctionKatInput with
  | none => false
  | some result =>
      result.afterRevision = 4 && result.receivedCashCents = correctionKatCurrentReceipt.result.receivedCashCents &&
      sameOwnerResult result correctionKatCurrentReceipt katCorrectionEvaluationId

def gateCorrectionExactRetryNoEffects : Bool :=
  let retryInput := correctionKatRetryRequest.currentInput
  let acknowledged := { retryInput with
    actions := retryInput.actions.map (fun action =>
      { action with status := .ACKNOWLEDGED }) }
  let request := { correctionKatRetryRequest with currentInput := acknowledged }
  let result := applyCorrectionTransition request
  result.status = .DUPLICATE && result.mutation.isNone && result.rejectReason.isNone &&
    result.actionId = some katCorrectionActionId &&
    result.determinationId = some "determination:action:correction:h:v1" &&
    result.explanation.code = .EXACT_RETRY

def gateCorrectionRetryChangedIdentityRejected : Bool :=
  let request := { correctionKatRetryRequest with command :=
    { correctionKatRetryRequest.command with decisionAtMs := katDecisionAt + 1 } }
  resultHasReason (applyCorrectionTransition request) .ACTION_CONFLICT

def gateCorrectionRevisionRejected : Bool :=
  let request := { correctionKatRequest with command :=
    { correctionKatCommand with expectedRevision := 3 } }
  resultHasReason (applyCorrectionTransition request) .REVISION_CONFLICT

def gateCorrectionEvaluationRejected : Bool :=
  let request := { correctionKatRequest with command :=
    { correctionKatCommand with evaluationResultDigest := correctionKatDigest 166 } }
  resultHasReason (applyCorrectionTransition request) .EVALUATION_CONFLICT

def gateCorrectionActorRejected : Bool :=
  let request := { correctionKatRequest with command :=
    { correctionKatCommand with actorRole := "RECEIVER" } }
  resultHasReason (applyCorrectionTransition request) .ACTOR_UNAUTHORIZED

def gateCorrectionMissingClaimRejected : Bool :=
  let request := { correctionKatRequest with command :=
    { correctionKatCommand with claimId := "claim:missing" } }
  resultHasReason (applyCorrectionTransition request) .CLAIM_MISSING

def gateCorrectionClaimNotClaimedRejected : Bool :=
  let determination := { katDetermination .OFFSET_AUTHORIZED with
    expectedRevision := 3
    resultingRevision := 4 }
  let action := { katAuthorizedAction with revision := 4 }
  let input := { correctionKatInput with
    claims := [katClaim .AUTHORIZED]
    determinations := [determination]
    actions := [action] }
  let request := { correctionKatRequest with currentInput := input }
  resultHasReason (applyCorrectionTransition request) .CLAIM_NOT_CLAIMED

def gateCorrectionChronologyRejected : Bool :=
  let request := { correctionKatRequest with command :=
    { correctionKatCommand with decisionAtMs := katEvalAt - 1 } }
  resultHasReason (applyCorrectionTransition request) .CHRONOLOGY

def gateCorrectionShadowRejected : Bool :=
  let input := { correctionKatInput with context := { correctionKatInput.context with mode := .SHADOW } }
  let request := { correctionKatRequest with currentInput := input }
  resultHasReason (applyCorrectionTransition request) .SHADOW_READ_ONLY

def gateCorrectionDeterminationCollisionRejected : Bool :=
  let observations := { correctionKatCommand.queryObservations with
    determinationId := correctionKatQuery .DETERMINATION_ID
      ("determination:" ++ katCorrectionActionId) 10 42
      (some ("determination:" ++ katCorrectionActionId)) }
  let request := { correctionKatRequest with command :=
    { correctionKatCommand with queryObservations := observations } }
  resultHasReason (applyCorrectionTransition request) .DETERMINATION_CONFLICT

def gateCorrectionConsumedEvaluationRejected : Bool :=
  let observations := { correctionKatCommand.queryObservations with
    evaluationConsumed := correctionKatQuery .EVALUATION_CONSUMED
      katCorrectionEvaluationId 10 42 (some "determination:other") }
  let request := { correctionKatRequest with command :=
    { correctionKatCommand with queryObservations := observations } }
  resultHasReason (applyCorrectionTransition request) .EVALUATION_CONSUMED

def gateCorrectionIncompleteQueryRejected : Bool :=
  let observations := { correctionKatCommand.queryObservations with
    actionId := { correctionKatCommand.queryObservations.actionId with complete := false } }
  let request := { correctionKatRequest with command :=
    { correctionKatCommand with queryObservations := observations } }
  resultHasReason (applyCorrectionTransition request) .QUERY_OBSERVATION_INVALID

def gateCorrectionStaleQueryVersionRejected : Bool :=
  let observations := { correctionKatCommand.queryObservations with
    determinationId := { correctionKatCommand.queryObservations.determinationId with
      versionSequence := 9 } }
  let request := { correctionKatRequest with command :=
    { correctionKatCommand with queryObservations := observations } }
  resultHasReason (applyCorrectionTransition request) .QUERY_OBSERVATION_INVALID

def gateCorrectionMissingSnapshotDigestRejected : Bool :=
  let request := { correctionKatRequest with currentReceipt :=
    { correctionKatCurrentReceipt with inputSnapshotDigest := none } }
  resultHasReason (applyCorrectionTransition request) .INPUT_SNAPSHOT_MISSING

def gateCorrectionRequestCodecRoundtrip : Bool :=
  match encodeCorrectionTransitionRequest correctionKatRequest with
  | none => false
  | some wire => decodeCorrectionTransitionRequest wire = some correctionKatRequest

def gateCorrectionResultCodecRoundtrip : Bool :=
  match encodeCorrectionTransitionResult correctionKatAccepted with
  | none => false
  | some wire => decodeCorrectionTransitionResult wire = some correctionKatAccepted

def gateCorrectionTrailingBytesRejected : Bool :=
  let requestRejected := match encodeCorrectionTransitionRequest correctionKatRequest with
    | none => false
    | some wire => (decodeCorrectionTransitionRequest (wire ++ [UInt8.ofNat 0])).isNone
  let resultRejected := match encodeCorrectionTransitionResult correctionKatAccepted with
    | none => false
    | some wire => (decodeCorrectionTransitionResult (wire ++ [UInt8.ofNat 0])).isNone
  requestRejected && resultRejected

/-- A receipt shaped like `base` whose owner result is Lean's projection `result`. -/
private def correctionKatReceiptFor (base : EvaluationReceipt) (evaluationId : String)
    (result : FinancialResult) : EvaluationReceipt :=
  { base with result := { base.result with
      evaluationId := evaluationId
      obligationId := result.context.obligationId
      revision := result.afterRevision
      ruleVersion := result.ruleVersion
      evidenceIds := result.evidenceIds
      authorityId := result.authorityId
      evaluatedAtMs := result.evaluatedAt
      owedCents := result.owedCents
      claimedAdjustmentCents := result.claimedAdjustmentCents
      lawfulAdjustmentCents := result.lawfulAdjustmentCents
      receivedCashCents := result.receivedCashCents
      shortfallCents := result.shortfallCents
      overageCents := result.overageCents
      cashSatisfied := result.cashSatisfied
      amountSatisfied := result.amountSatisfied
      timely := result.timely
      reportingComplete := result.reportingComplete
      verificationStatus := ownerVerificationStatus result.verificationStatus
      caseStatus := ownerCaseStatus result.caseStatus
      deliveryStatus := ownerDeliveryStatus result.deliveryStatus } }

/-- The KAT request with the obligation owed `owedCents` against the same 9,700,000
    cash and 300,000 claim; the receipt carries Lean's projection of that input. -/
private def correctionKatOwedRequest (owedCents : Nat) : CorrectionTransitionRequest :=
  let input := { correctionKatInput with
    obligation := { correctionKatInput.obligation with owedCents := owedCents } }
  match evaluate input with
  | some result => { correctionKatRequest with
      currentInput := input
      currentReceipt := correctionKatReceiptFor correctionKatCurrentReceipt
        katCorrectionEvaluationId result }
  | none => { correctionKatRequest with currentInput := input }

private def correctionKatOwedAction (owedCents : Nat) : Option (Nat × Nat × Nat) :=
  (applyCorrectionTransition (correctionKatOwedRequest owedCents)).mutation.map (fun mutation =>
    (mutation.dependencies.inputShortfallCents, mutation.determination.amountCents,
      mutation.action.amountCents))

/-- Paid in full: rejecting the offset leaves nothing to request. -/
def gateCorrectionZeroShortfallRejected : Bool :=
  let request := correctionKatOwedRequest 9_700_000
  (evaluate request.currentInput).map FinancialResult.shortfallCents = some 0 &&
    resultHasReason (applyCorrectionTransition request) .NO_SHORTFALL

/-- 100,000 unpaid against a 300,000 offset: the request is 100,000. -/
def gateCorrectionPartialShortfallAmount : Bool :=
  correctionKatOwedAction 9_800_000 = some (100_000, 300_000, 100_000)

/-- 300,000 unpaid against a 300,000 offset: the request is the whole claim. -/
def gateCorrectionFullShortfallAmount : Bool :=
  correctionKatOwedAction 10_000_000 = some (300_000, 300_000, 300_000)

/-- 800,000 unpaid against a 300,000 offset: the request is capped at the claim. -/
def gateCorrectionShortfallAboveClaimAmount : Bool :=
  correctionKatOwedAction 10_500_000 = some (800_000, 300_000, 300_000)

private def correctionKatReuseReceipt (mutation : CorrectionMutation) : EvaluationReceipt :=
  { correctionKatReceiptFor correctionKatCurrentReceipt mutation.followUps.resultingEvaluationId
      mutation.resultingResult with
    evidenceBindings := mutation.dependencies.supportingEvidence
    inputSnapshotDigest := some (correctionKatDigest 92)
    resultDigest := correctionKatDigest 101
    receiptDigest := correctionKatDigest 102
    evaluationResultDigest := correctionKatDigest 101 }

/-- The Owner's read right after `accepted` committed, handed back for reuse. -/
private def correctionKatReuseRequestFor (accepted : CorrectionTransitionResult) :
    CorrectionReuseRequest :=
  match accepted.mutation with
  | some mutation => {
      acceptedResult := accepted
      currentInput := mutation.resultingInput
      currentReceipt := correctionKatReuseReceipt mutation
      currentDetermination := some mutation.determination
      currentOutbox := some mutation.outbox
      currentQueries := correctionKatRetryQueries 11 43
      currentEventSequence := 11
      currentHistoryHead := correctionKatDigest 43
      currentOwnerNowMs := katOwnerNow + 1 }
  | none => {
      acceptedResult := accepted
      currentInput := correctionKatInput
      currentReceipt := correctionKatCurrentReceipt
      currentDetermination := none
      currentOutbox := none
      currentQueries := correctionKatAbsentQueries 10 42
      currentEventSequence := 10
      currentHistoryHead := correctionKatDigest 42
      currentOwnerNowMs := katOwnerNow }

def correctionKatReuseRequest : CorrectionReuseRequest :=
  correctionKatReuseRequestFor correctionKatAccepted

def gateCorrectionReuseBaselineValid : Bool :=
  let assessment := assessCorrectionReuse correctionKatReuseRequest
  assessment.calculationValidity = .VALID && assessment.calculationReason.isNone &&
    assessment.humanApprovalValidity = .VALID && assessment.humanApprovalReason.isNone &&
    assessment.localExecutionPermission = .ALLOWED && assessment.executionDenial.isNone &&
    assessment.deadlineStatus = some .DEADLINE_REACHED &&
    !assessment.unrelatedWatermarkAdvanced && !assessment.externalDispatchPermitted

def gateCorrectionReuseIgnoresUnrelatedWatermark : Bool :=
  let request := { correctionKatReuseRequest with
    currentQueries := correctionKatRetryQueries 100 44
    currentEventSequence := 100
    currentHistoryHead := correctionKatDigest 44 }
  let assessment := assessCorrectionReuse request
  assessment.calculationValidity = .VALID && assessment.humanApprovalValidity = .VALID &&
    assessment.localExecutionPermission = .ALLOWED && assessment.unrelatedWatermarkAdvanced

def gateCorrectionReuseClaimChangeInvalidates : Bool :=
  let changedInput := { correctionKatReuseRequest.currentInput with
    claims := correctionKatReuseRequest.currentInput.claims.map (fun claim =>
      if claim.claimId = katCorrectionClaimId then { claim with amountCents := claim.amountCents + 1 }
      else claim) }
  let assessment := assessCorrectionReuse { correctionKatReuseRequest with currentInput := changedInput }
  assessment.calculationValidity = .INVALID &&
    assessment.calculationReason = some .RELEVANT_FINANCIAL_FACT_CHANGED

def gateCorrectionReuseEvidenceChangeInvalidates : Bool :=
  let changedBindings := match correctionKatReuseRequest.currentReceipt.evidenceBindings with
    | [] => []
    | binding :: rest => { binding with recordDigest := correctionKatDigest 69 } :: rest
  let changedReceipt := { correctionKatReuseRequest.currentReceipt with
    evidenceBindings := changedBindings }
  let assessment := assessCorrectionReuse { correctionKatReuseRequest with currentReceipt := changedReceipt }
  assessment.calculationValidity = .INVALID &&
    assessment.calculationReason = some .EVIDENCE_BINDING_CHANGED

def gateCorrectionReusePackChangeInvalidates : Bool :=
  let changedInput := { correctionKatReuseRequest.currentInput with
    pack := { correctionKatReuseRequest.currentInput.pack with digest := correctionKatDigest 70 } }
  let assessment := assessCorrectionReuse { correctionKatReuseRequest with currentInput := changedInput }
  assessment.calculationValidity = .INVALID &&
    assessment.calculationReason = some .RELEVANT_FINANCIAL_FACT_CHANGED

def gateCorrectionReuseQueryInsertionInvalidates : Bool :=
  let changedQueries := { correctionKatReuseRequest.currentQueries with
    evaluationConsumed := { correctionKatReuseRequest.currentQueries.evaluationConsumed with
      resultIdentity := some "determination:other" } }
  let assessment := assessCorrectionReuse { correctionKatReuseRequest with currentQueries := changedQueries }
  assessment.calculationValidity = .INVALID &&
    assessment.calculationReason = some .QUERY_OBSERVATION_INVALID

def gateCorrectionReuseApprovalQueryStaleIsSeparate : Bool :=
  let changedQueries := { correctionKatReuseRequest.currentQueries with
    determinationId := { correctionKatReuseRequest.currentQueries.determinationId with
      resultIdentity := some "determination:other" } }
  let assessment := assessCorrectionReuse { correctionKatReuseRequest with currentQueries := changedQueries }
  assessment.calculationValidity = .VALID &&
    assessment.humanApprovalValidity = .INVALID &&
    assessment.humanApprovalReason = some .DETERMINATION_MISSING &&
    assessment.localExecutionPermission = .DENIED &&
    assessment.executionDenial = some .HUMAN_APPROVAL_INVALID &&
    !assessment.unrelatedWatermarkAdvanced

def gateCorrectionReuseApprovalStaleIsSeparate : Bool :=
  match correctionKatAccepted.mutation with
  | none => false
  | some mutation =>
      let staleApproval := { mutation.determination with actorRole := "RECEIVER" }
      let assessment := assessCorrectionReuse { correctionKatReuseRequest with
        currentDetermination := some staleApproval }
  assessment.calculationValidity = .VALID &&
    assessment.humanApprovalValidity = .INVALID &&
    assessment.humanApprovalReason = some .DETERMINATION_CHANGED &&
    assessment.localExecutionPermission = .DENIED &&
    assessment.executionDenial = some .HUMAN_APPROVAL_INVALID &&
    !assessment.unrelatedWatermarkAdvanced

def gateCorrectionReuseAckDeniesExecution : Bool :=
  match correctionKatReuseRequest.currentOutbox with
  | none => false
  | some oldOutbox =>
      let changedInput := { correctionKatReuseRequest.currentInput with
        actions := correctionKatReuseRequest.currentInput.actions.map (fun action =>
          { action with status := .ACKNOWLEDGED }) }
      let changedOutbox := { oldOutbox with
        status := .ACKNOWLEDGED
        attempt := 1
        acknowledgmentReference := some "ack:correction:h:v1"
        updatedAtMs := katOwnerNow + 3 }
      let assessment := assessCorrectionReuse { correctionKatReuseRequest with
        currentInput := changedInput
        currentOutbox := some changedOutbox }
      assessment.localExecutionPermission = .DENIED &&
        assessment.executionDenial = some .ACTION_NOT_READY

def gateCorrectionReuseCancelDeniesExecution : Bool :=
  match correctionKatReuseRequest.currentOutbox with
  | none => false
  | some oldOutbox =>
      let changedInput := { correctionKatReuseRequest.currentInput with
        actions := correctionKatReuseRequest.currentInput.actions.map (fun action =>
          { action with status := .CANCELLED }) }
      let changedOutbox := { oldOutbox with status := .CANCELLED }
      let assessment := assessCorrectionReuse { correctionKatReuseRequest with
        currentInput := changedInput
        currentOutbox := some changedOutbox }
      assessment.localExecutionPermission = .DENIED &&
        assessment.executionDenial = some .ACTION_NOT_READY

def gateCorrectionReuseStaleAuthorityDeniesExecution : Bool :=
  let changedInput := { correctionKatReuseRequest.currentInput with
    authority := { correctionKatReuseRequest.currentInput.authority with epoch :=
      correctionKatReuseRequest.currentInput.authority.epoch + 1 } }
  let assessment := assessCorrectionReuse { correctionKatReuseRequest with currentInput := changedInput }
  assessment.localExecutionPermission = .DENIED &&
    assessment.executionDenial = some .AUTHORITY_STALE

/-- Reuse of the partial correction (B2 amount 100,000) with the stored action's
    amount set to `amountCents`. -/
private def correctionKatPartialReuse (amountCents : Nat) : CorrectionReuseAssessment :=
  let request := correctionKatReuseRequestFor
    (applyCorrectionTransition (correctionKatOwedRequest 9_800_000))
  assessCorrectionReuse { request with currentInput := { request.currentInput with
    actions := request.currentInput.actions.map (fun action =>
      if action.actionId = katCorrectionActionId then { action with amountCents := amountCents }
      else action) } }

private def correctionKatReuseDeniesChangedAction (amountCents : Nat) : Bool :=
  (correctionKatPartialReuse 100_000).localExecutionPermission = .ALLOWED &&
    (correctionKatPartialReuse amountCents).localExecutionPermission = .DENIED &&
    (correctionKatPartialReuse amountCents).executionDenial = some .ACTION_CHANGED

/-- A stored correction one cent below the B2 amount is never executed. -/
def gateCorrectionReuseRejectsAmountBelowB2 : Bool :=
  correctionKatReuseDeniesChangedAction 99_999

/-- A stored correction one cent above the B2 amount is never executed. -/
def gateCorrectionReuseRejectsAmountAboveB2 : Bool :=
  correctionKatReuseDeniesChangedAction 100_001

def gateCorrectionReuseCodecRoundtrip : Bool :=
  match encodeCorrectionReuseRequest correctionKatReuseRequest with
  | none => false
  | some requestWire =>
      decodeCorrectionReuseRequest requestWire = some correctionKatReuseRequest &&
      match encodeCorrectionReuseAssessment
          (assessCorrectionReuse correctionKatReuseRequest) with
      | none => false
      | some resultWire => decodeCorrectionReuseAssessment resultWire =
          some (assessCorrectionReuse correctionKatReuseRequest)

def correctionTransitionKatLines : List (String × Bool) := [
  ("accepted_transition_effects_and_cash_separation", gateCorrectionAcceptedTransition),
  ("zero_shortfall_rejected_without_mutation", gateCorrectionZeroShortfallRejected),
  ("partial_shortfall_requests_unpaid_balance", gateCorrectionPartialShortfallAmount),
  ("full_shortfall_requests_claim_amount", gateCorrectionFullShortfallAmount),
  ("shortfall_above_claim_requests_claim_amount", gateCorrectionShortfallAboveClaimAmount),
  ("current_owner_evaluation_receipt_binding", gateCorrectionInputReceiptBound),
  ("exact_retry_after_ack_is_noop", gateCorrectionExactRetryNoEffects),
  ("changed_retry_identity_rejected", gateCorrectionRetryChangedIdentityRejected),
  ("stale_revision_rejected", gateCorrectionRevisionRejected),
  ("stale_evaluation_digest_rejected", gateCorrectionEvaluationRejected),
  ("unauthorized_actor_role_rejected", gateCorrectionActorRejected),
  ("missing_claim_rejected", gateCorrectionMissingClaimRejected),
  ("non_claimed_claim_rejected", gateCorrectionClaimNotClaimedRejected),
  ("consumed_evaluation_query_collision_rejected", gateCorrectionConsumedEvaluationRejected),
  ("evaluation_chronology_rejected", gateCorrectionChronologyRejected),
  ("shadow_mode_rejected", gateCorrectionShadowRejected),
  ("determination_identity_collision_rejected", gateCorrectionDeterminationCollisionRejected),
  ("incomplete_bounded_query_rejected", gateCorrectionIncompleteQueryRejected),
  ("stale_bounded_query_version_rejected", gateCorrectionStaleQueryVersionRejected),
  ("missing_input_snapshot_digest_rejected", gateCorrectionMissingSnapshotDigestRejected),
  ("reuse_valid_baseline", gateCorrectionReuseBaselineValid),
  ("reuse_ignores_unrelated_watermark_advance", gateCorrectionReuseIgnoresUnrelatedWatermark),
  ("reuse_claim_change_invalidates_calculation", gateCorrectionReuseClaimChangeInvalidates),
  ("reuse_evidence_binding_change_invalidates_calculation", gateCorrectionReuseEvidenceChangeInvalidates),
  ("reuse_control_pack_change_invalidates_calculation", gateCorrectionReusePackChangeInvalidates),
  ("reuse_relevant_query_insertion_invalidates_calculation", gateCorrectionReuseQueryInsertionInvalidates),
  ("reuse_approval_query_staleness_is_separate", gateCorrectionReuseApprovalQueryStaleIsSeparate),
  ("reuse_human_approval_staleness_is_separate", gateCorrectionReuseApprovalStaleIsSeparate),
  ("reuse_acknowledgment_denies_local_execution", gateCorrectionReuseAckDeniesExecution),
  ("reuse_cancellation_denies_local_execution", gateCorrectionReuseCancelDeniesExecution),
  ("reuse_stale_authority_denies_local_execution", gateCorrectionReuseStaleAuthorityDeniesExecution),
  ("reuse_rejects_amount_below_b2", gateCorrectionReuseRejectsAmountBelowB2),
  ("reuse_rejects_amount_above_b2", gateCorrectionReuseRejectsAmountAboveB2),
  ("reuse_protocol_roundtrip", gateCorrectionReuseCodecRoundtrip),
  ("request_codec_roundtrip", gateCorrectionRequestCodecRoundtrip),
  ("result_codec_roundtrip", gateCorrectionResultCodecRoundtrip),
  ("strict_trailing_byte_rejection", gateCorrectionTrailingBytesRejected) ]

def correctionTransitionKatCount : Nat := correctionTransitionKatLines.length

def correctionTransitionKatsPass : Bool :=
  correctionTransitionKatLines.all (fun entry => entry.2)

end BlindLedger.Financial.CorrectionTransition
