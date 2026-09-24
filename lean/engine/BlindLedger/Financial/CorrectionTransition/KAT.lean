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

def gateCorrectionOwnerDigestVectors : Bool :=
  match correctionKatAccepted.mutation with
  | none => false
  | some mutation =>
      mutation.determinationDigest = [
        0x1a, 0xb8, 0x2b, 0x82, 0xd1, 0x17, 0xfb, 0x08, 0x18, 0x0f, 0x9e, 0xf0, 0x8c, 0x04, 0x24, 0x9d,
        0x9d, 0x69, 0x11, 0xad, 0xe6, 0x94, 0xa5, 0xe1, 0x74, 0x60, 0x0b, 0x8e, 0x06, 0x08, 0xb0, 0x1f,
        0x40, 0x40, 0x43, 0xd8, 0x9d, 0x9e, 0x65, 0xe0, 0x8e, 0xfa, 0xd8, 0xd3, 0x3e, 0x8d, 0xd0, 0x83,
        0xbe, 0x81, 0x65, 0xb4, 0xd0, 0xb0, 0x1a, 0x03, 0x4d, 0x79, 0xde, 0xa2, 0xc2, 0xd4, 0x9a, 0xfb ] &&
      mutation.actionPayloadDigest = [
        0xcf, 0xe3, 0x09, 0x53, 0xf5, 0x92, 0xf0, 0x86, 0x03, 0x69, 0x82, 0x12, 0x9e, 0x5c, 0x1c, 0x66,
        0x84, 0x97, 0x09, 0xa5, 0x88, 0x17, 0x47, 0xcf, 0xd9, 0x07, 0x5d, 0x49, 0xdb, 0x56, 0xdc, 0x12,
        0x89, 0x0c, 0x82, 0xe3, 0x7c, 0xa9, 0x49, 0x31, 0x82, 0x4b, 0xd2, 0x8a, 0x79, 0xcb, 0x22, 0x35,
        0x0c, 0xd7, 0x7e, 0xd9, 0xb6, 0x08, 0xe0, 0x02, 0x3c, 0xf2, 0x4a, 0x8c, 0x36, 0xb8, 0x20, 0xc2 ] &&
      mutation.actionIdempotencyKey = [
        0xe0, 0xb7, 0x0f, 0xc0, 0xa8, 0xe5, 0xc4, 0x37, 0x56, 0xf7, 0x1d, 0x9f, 0x0f, 0xed, 0x93, 0x62,
        0x0b, 0xf7, 0x72, 0xe5, 0xcd, 0x24, 0x86, 0xd6, 0xc8, 0x9b, 0x7c, 0x8e, 0xf2, 0xd3, 0xb9, 0x27,
        0xe6, 0x2a, 0x28, 0x85, 0x02, 0x7d, 0x7b, 0xfd, 0x78, 0xa6, 0xa5, 0xaf, 0xcc, 0x77, 0x0f, 0x47,
        0xa3, 0xdf, 0xe3, 0x0b, 0x67, 0x60, 0x0f, 0x8f, 0xe5, 0x5e, 0x27, 0xcb, 0x75, 0x4b, 0x91, 0x8c ]

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

private def correctionKatReuseReceipt (mutation : CorrectionMutation) : EvaluationReceipt :=
  let result := mutation.resultingResult
  { correctionKatCurrentReceipt with
    evidenceBindings := mutation.dependencies.supportingEvidence
    inputSnapshotDigest := some (correctionKatDigest 92)
    result := { correctionKatCurrentReceipt.result with
      evaluationId := mutation.followUps.resultingEvaluationId
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
      deliveryStatus := ownerDeliveryStatus result.deliveryStatus }
    resultDigest := correctionKatDigest 101
    receiptDigest := correctionKatDigest 102
    evaluationResultDigest := correctionKatDigest 101 }

def correctionKatReuseRequest : CorrectionReuseRequest :=
  match correctionKatAccepted.mutation with
  | some mutation => {
      acceptedResult := correctionKatAccepted
      currentInput := mutation.resultingInput
      currentReceipt := correctionKatReuseReceipt mutation
      currentDetermination := some mutation.determination
      currentDeterminationDigest := some mutation.determinationDigest
      currentOutbox := some mutation.outbox
      currentQueries := correctionKatRetryQueries 11 43
      currentEventSequence := 11
      currentHistoryHead := correctionKatDigest 43
      currentOwnerNowMs := katOwnerNow + 1 }
  | none => {
      acceptedResult := correctionKatAccepted
      currentInput := correctionKatInput
      currentReceipt := correctionKatCurrentReceipt
      currentDetermination := none
      currentDeterminationDigest := none
      currentOutbox := none
      currentQueries := correctionKatAbsentQueries 10 42
      currentEventSequence := 10
      currentHistoryHead := correctionKatDigest 42
      currentOwnerNowMs := katOwnerNow }

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
  ("owner_domain_digest_vectors", gateCorrectionOwnerDigestVectors),
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
  ("reuse_protocol_roundtrip", gateCorrectionReuseCodecRoundtrip),
  ("request_codec_roundtrip", gateCorrectionRequestCodecRoundtrip),
  ("result_codec_roundtrip", gateCorrectionResultCodecRoundtrip),
  ("strict_trailing_byte_rejection", gateCorrectionTrailingBytesRejected) ]

def correctionTransitionKatCount : Nat := correctionTransitionKatLines.length

def correctionTransitionKatsPass : Bool :=
  correctionTransitionKatLines.all (fun entry => entry.2)

end BlindLedger.Financial.CorrectionTransition
