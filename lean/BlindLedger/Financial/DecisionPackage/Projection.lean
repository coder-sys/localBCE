import BlindLedger.Financial.Codec
import BlindLedger.Financial.DecisionPackage.Types

namespace BlindLedger.Financial.DecisionPackage

open BlindLedger.Financial

def ownerCaseStatus (value : CaseStatus) : String :=
  match value with
  | .OPEN => "OPEN"
  | .AUTHORIZED => "AUTHORIZED"
  | .CORRECTION_REQUIRED => "CORRECTION_REQUIRED"
  | .ACTIONED => "ACTIONED"
  | .RESOLVED => "RESOLVED"

def ownerVerificationStatus (value : VerificationStatus) : String :=
  match value with
  | .MISSING_EVIDENCE => "MISSING_EVIDENCE"
  | .SUPPORTED => "SUPPORTED"
  | .CONFLICT_VISIBLE => "CONFLICT_VISIBLE"

def ownerDeliveryStatus (value : DeliveryStatus) : String :=
  match value with
  | .NONE => "NONE"
  | .READY => "READY"
  | .ACKNOWLEDGED => "ACKNOWLEDGED"
  | .CANCELLED => "CANCELLED"

def boundedPackageId (value : String) : Bool := idWellFormed value
def boundedPackageText (value : String) : Bool := textWellFormed value
def packageDigestWellFormed (value : Bytes) : Bool := value.length = digestBytes

def optionalPackageIdWellFormed : Option String → Bool
  | none => true
  | some value => boundedPackageId value

def optionalPackageDigestWellFormed : Option Bytes → Bool
  | none => true
  | some value => packageDigestWellFormed value

def packageKnowledgeIdWellFormed (value : Knowledge String) : Bool :=
  match value with
  | .unknown => true
  | .known text => boundedPackageId text

def packageKnowledgeTextWellFormed (value : Knowledge String) : Bool :=
  match value with
  | .unknown => true
  | .known text => boundedPackageText text

def packageKnowledgeNatWellFormed (ceiling : Nat) (value : Knowledge Nat) : Bool :=
  match value with
  | .unknown => true
  | .known number => number ≤ ceiling

def packageKnowledgeDigestWellFormed (value : Knowledge Bytes) : Bool :=
  match value with
  | .unknown => true
  | .known digest => packageDigestWellFormed digest

def packageKnowledgeStringMatches (expected : String) (value : Knowledge String) : Bool :=
  match value with
  | .unknown => true
  | .known actual => actual = expected

def packageScopeWellFormed (scope : PackageScope) : Bool :=
  boundedPackageId scope.stateId && boundedPackageId scope.deploymentId &&
    boundedPackageId scope.programId && boundedPackageId scope.periodId &&
    boundedPackageId scope.currency

def packageObligationWellFormed (obligation : PackageObligation) : Bool :=
  boundedPackageId obligation.obligationId && boundedPackageId obligation.itemId &&
    packageKnowledgeIdWellFormed obligation.populationId &&
    boundedPackageId obligation.periodId &&
    boundedPackageId obligation.currency && obligation.revision ≤ maxRevision &&
    obligation.owedCents ≤ maxCents && obligation.claimedAdjustmentCents ≤ maxCents &&
    obligation.lawfulAdjustmentCents ≤ maxCents && obligation.receivedCashCents ≤ maxCents &&
    obligation.shortfallCents ≤ maxCents && obligation.overageCents ≤ maxCents &&
    boundedPackageText obligation.verificationStatus &&
    boundedPackageText obligation.caseStatus && boundedPackageText obligation.deliveryStatus &&
    optionalPackageIdWellFormed obligation.currentEvaluationId &&
    obligation.dueAtMs ≤ maxTime

def ownerPopulationBindingWellFormed (binding : OwnerPopulationBinding) : Bool :=
  packageKnowledgeIdWellFormed binding.populationId && boundedPackageText binding.status &&
    boundedPackageText binding.completeness && packageKnowledgeIdWellFormed binding.manifestId &&
    binding.manifestVersion ≥ 1 && binding.manifestVersion ≤ maxRevision &&
    packageKnowledgeDigestWellFormed binding.manifestDigest &&
    packageKnowledgeIdWellFormed binding.memberId && binding.memberCount ≤ maxRows &&
    packageKnowledgeDigestWellFormed binding.memberDigest

def packageControlPackWellFormed (pack : PackageControlPack) : Bool :=
  boundedPackageId pack.packId && pack.version ≥ 1 && pack.version ≤ maxRevision &&
    packageDigestWellFormed pack.digest && boundedPackageId pack.calculationRuleId &&
    boundedPackageId pack.adjustmentRuleId && !pack.sourceRefs.isEmpty &&
    pack.sourceRefs.length ≤ maxRows && pack.sourceRefs.all boundedPackageText &&
    !pack.authorizedRoles.isEmpty && pack.authorizedRoles.length ≤ maxRows &&
    pack.authorizedRoles.all boundedPackageId &&
    pack.effectiveStartMs ≤ maxTime && pack.effectiveEndMs ≤ maxTime &&
    pack.recordedAtMs ≤ maxTime && pack.approvedAtMs ≤ maxTime

def ownerEvaluationResultWellFormed (result : OwnerEvaluationResult) : Bool :=
  boundedPackageId result.evaluationId && boundedPackageId result.obligationId &&
    result.revision ≤ maxRevision && result.ruleVersion ≥ 1 && result.ruleVersion ≤ maxRevision &&
    result.evidenceIds.length ≤ maxRows && result.evidenceIds.all boundedPackageId &&
    boundedPackageId result.authorityId && result.evaluatedAtMs ≤ maxTime &&
    result.owedCents ≤ maxCents && result.claimedAdjustmentCents ≤ maxCents &&
    result.lawfulAdjustmentCents ≤ maxCents && result.receivedCashCents ≤ maxCents &&
    result.shortfallCents ≤ maxCents && result.overageCents ≤ maxCents &&
    boundedPackageText result.verificationStatus && boundedPackageText result.caseStatus &&
    boundedPackageText result.deliveryStatus

def evaluationReceiptWellFormed (receipt : EvaluationReceipt) : Bool :=
  receipt.contractVersion = evaluationReceiptContractV1 &&
    packageScopeWellFormed receipt.scope && boundedPackageId receipt.controlPack.packId &&
    receipt.controlPack.version ≥ 1 && receipt.controlPack.version ≤ maxRevision &&
    packageDigestWellFormed receipt.controlPack.digest &&
    receipt.evidenceBindings.length ≤ maxRows &&
    receipt.evidenceBindings.all (fun binding =>
      boundedPackageId binding.evidenceId && packageDigestWellFormed binding.recordDigest) &&
    optionalPackageDigestWellFormed receipt.inputSnapshotDigest &&
    receipt.authority.authorityEpoch ≥ 1 &&
    receipt.authority.authorityEpoch ≤ maxAuthorityEpoch &&
    packageDigestWellFormed receipt.authority.authorityDigest &&
    ownerEvaluationResultWellFormed receipt.result &&
    packageDigestWellFormed receipt.resultDigest &&
    packageDigestWellFormed receipt.receiptDigest &&
    packageDigestWellFormed receipt.evaluationResultDigest &&
    receipt.evaluationResultDigest = receipt.resultDigest &&
    receipt.evidenceBindings.map EvidenceBinding.evidenceId = receipt.result.evidenceIds

def ownerCaseWellFormed (caseRecord : OwnerCase) : Bool :=
  boundedPackageId caseRecord.caseId && boundedPackageId caseRecord.obligationId &&
    boundedPackageText caseRecord.reason &&
    boundedPackageText caseRecord.contractualAccountability &&
    boundedPackageId caseRecord.nextActionOwner && caseRecord.dueAtMs ≤ maxTime &&
    boundedPackageText caseRecord.status && caseRecord.updatedAtMs ≤ maxTime

def ownerDeterminationWellFormed (determination : OwnerDetermination) : Bool :=
  boundedPackageId determination.determinationId &&
    boundedPackageId determination.obligationId &&
    optionalPackageIdWellFormed determination.claimId &&
    boundedPackageId determination.actorId && boundedPackageId determination.actorRole &&
    boundedPackageId determination.authorityId && determination.authorityEpoch ≥ 1 &&
    determination.authorityEpoch ≤ maxAuthorityEpoch &&
    packageDigestWellFormed determination.authorityDigest &&
    boundedPackageText determination.decision && determination.amountCents ≤ maxCents &&
    determination.supportingEvidence.length ≤ maxRows &&
    determination.supportingEvidence.all (fun binding =>
      boundedPackageId binding.evidenceId && packageDigestWellFormed binding.recordDigest) &&
    determination.expectedRevision < determination.resultingRevision &&
    determination.resultingRevision ≤ maxRevision && determination.decidedAtMs ≤ maxTime &&
    packageDigestWellFormed determination.determinationDigest &&
    boundedPackageId determination.inputEvaluationId &&
    packageDigestWellFormed determination.inputEvaluationResultDigest

def ownerActionWellFormed (action : OwnerAction) : Bool :=
  boundedPackageId action.actionId && boundedPackageId action.obligationId &&
    boundedPackageId action.determinationId && boundedPackageText action.kind &&
    boundedPackageText action.status && action.revision ≤ maxRevision &&
    packageDigestWellFormed action.payloadDigest && action.createdAtMs ≤ maxTime &&
    boundedPackageText action.acknowledgmentStatus &&
    optionalPackageIdWellFormed action.acknowledgmentReference &&
    action.acknowledgmentAttempt ≤ maxRevision &&
    action.acknowledgmentUpdatedAtMs ≤ maxTime &&
    action.acknowledgmentCashEffectCents = 0

def packageResultMatchesOwner (input : DecisionPackageInput) : Bool :=
  let owner := input.currentReceipt.result
  let result := input.engineResult
  owner.evaluationId = input.expectedCurrent.evaluationId &&
    owner.evaluationId = input.obligation.currentEvaluationId.getD "" &&
    input.expectedCurrent.resultDigest = input.currentReceipt.resultDigest &&
    owner.obligationId = input.obligation.obligationId &&
    owner.obligationId = result.context.obligationId &&
    owner.revision = input.obligation.revision && owner.revision = result.afterRevision &&
    owner.ruleVersion = input.controlPack.version && owner.ruleVersion = result.ruleVersion &&
    owner.evidenceIds = result.evidenceIds &&
    owner.authorityId = result.authorityId &&
    input.currentReceipt.authority.authorityEpoch = result.authorityEpoch &&
    input.currentReceipt.authority.authorityDigest = result.authorityDigest &&
    owner.evaluatedAtMs = result.evaluatedAt &&
    owner.owedCents = input.obligation.owedCents && owner.owedCents = result.owedCents &&
    owner.claimedAdjustmentCents = input.obligation.claimedAdjustmentCents &&
    owner.claimedAdjustmentCents = result.claimedAdjustmentCents &&
    owner.lawfulAdjustmentCents = input.obligation.lawfulAdjustmentCents &&
    owner.lawfulAdjustmentCents = result.lawfulAdjustmentCents &&
    owner.receivedCashCents = input.obligation.receivedCashCents &&
    owner.receivedCashCents = result.receivedCashCents &&
    owner.shortfallCents = input.obligation.shortfallCents &&
    owner.shortfallCents = result.shortfallCents &&
    owner.overageCents = input.obligation.overageCents &&
    owner.overageCents = result.overageCents &&
    owner.cashSatisfied = input.obligation.cashSatisfied &&
    owner.cashSatisfied = result.cashSatisfied &&
    owner.amountSatisfied = input.obligation.amountSatisfied &&
    owner.amountSatisfied = result.amountSatisfied && owner.timely = input.obligation.timely &&
    owner.timely = result.timely && owner.reportingComplete = input.obligation.reportingComplete &&
    owner.reportingComplete = result.reportingComplete &&
    owner.verificationStatus = input.obligation.verificationStatus &&
    owner.verificationStatus = ownerVerificationStatus result.verificationStatus &&
    owner.caseStatus = input.obligation.caseStatus &&
    owner.caseStatus = ownerCaseStatus result.caseStatus &&
    owner.deliveryStatus = input.obligation.deliveryStatus &&
    owner.deliveryStatus = ownerDeliveryStatus result.deliveryStatus &&
    input.scope.stateId = result.context.stateId &&
    input.scope.deploymentId = result.context.deploymentId &&
    input.scope.programId = result.context.programId &&
    input.scope.periodId = result.context.periodId &&
    input.scope.currency = result.context.currency &&
    input.obligation.itemId = result.context.itemId &&
    packageKnowledgeStringMatches result.context.populationId input.obligation.populationId &&
    input.obligation.periodId = input.scope.periodId &&
    input.obligation.currency = input.scope.currency &&
    input.currentReceipt.scope = input.scope &&
    input.currentReceipt.controlPack.packId = input.controlPack.packId &&
    input.currentReceipt.controlPack.version = input.controlPack.version &&
    input.currentReceipt.controlPack.digest = input.controlPack.digest &&
    result.packId = input.controlPack.packId && result.packDigest = input.controlPack.digest &&
    input.currentReceipt.resultDigest = input.currentReceipt.evaluationResultDigest &&
    input.obligation.currentEvaluationId = some owner.evaluationId &&
    input.cash.recordedReceivedCashCents = owner.receivedCashCents &&
    input.cash.cashSatisfied = owner.cashSatisfied &&
    input.cash.claimedAdjustmentCents = owner.claimedAdjustmentCents &&
    input.cash.lawfulAdjustmentCents = owner.lawfulAdjustmentCents &&
    input.cash.amountSatisfied = owner.amountSatisfied &&
    input.cash.shortfallCents = owner.shortfallCents && input.cash.overageCents = owner.overageCents &&
    input.reporting.complete = owner.reportingComplete &&
    input.cash.activePaymentCount ≤ maxRows && input.cash.authorizedAdjustmentCount ≤ maxRows &&
    input.reporting.evidenceCount ≤ maxRows

def packageOptionalRecordsMatch (input : DecisionPackageInput) : Bool :=
  let caseValid := match input.currentCase with
    | none => true
    | some caseRecord =>
        ownerCaseWellFormed caseRecord &&
          caseRecord.obligationId = input.obligation.obligationId &&
          caseRecord.status = input.obligation.caseStatus
  let determinationValid := match input.currentDetermination with
    | none => input.priorReceipt.isNone && input.currentAction.isNone
    | some determination =>
          ownerDeterminationWellFormed determination &&
          determination.obligationId = input.obligation.obligationId &&
          determination.resultingRevision ≤ input.obligation.revision &&
          (match input.priorReceipt with
          | none => input.currentAction.isNone ||
              (match input.currentAction with
              | none => true
              | some action => action.determinationId = determination.determinationId)
          | some prior =>
              evaluationReceiptWellFormed prior && prior.scope = input.scope &&
                prior.result.obligationId = determination.obligationId &&
                prior.result.evaluationId = determination.inputEvaluationId &&
              prior.result.revision = determination.expectedRevision &&
                prior.resultDigest = determination.inputEvaluationResultDigest &&
                prior.controlPack = input.currentReceipt.controlPack &&
                prior.result.authorityId = determination.authorityId &&
                prior.authority.authorityEpoch = determination.authorityEpoch &&
                prior.authority.authorityDigest = determination.authorityDigest)
  let actionValid := match input.currentAction with
    | none => true
    | some action =>
        ownerActionWellFormed action && action.obligationId = input.obligation.obligationId &&
          (match input.currentDetermination with
          | none => false
          | some determination => action.determinationId = determination.determinationId)
  let originsValid := input.observedOriginRefs.length ≤ maxRows &&
    input.observedOriginRefs.all boundedPackageId
  caseValid && determinationValid && actionValid && originsValid

def decisionPackageInputWellFormed (input : DecisionPackageInput) : Bool :=
  (input.contract = decisionPackageContractV1 || input.contract = decisionPackageContractV2) &&
    (input.mirrorSchema.isNone || input.mirrorSchema = some mirrorSchemaV1) &&
    (input.resource.isNone || input.resource = some decisionPackageResource) &&
    (input.mirrorSchema.isSome = input.resource.isSome) &&
    packageScopeWellFormed input.scope && packageObligationWellFormed input.obligation &&
    (match input.populationBinding with
    | none => input.contract = decisionPackageContractV1 ||
        input.contract = decisionPackageContractV2
    | some binding => input.contract = decisionPackageContractV2 &&
        ownerPopulationBindingWellFormed binding &&
        packageKnowledgeStringMatches input.engineResult.context.populationId
          binding.populationId &&
        (match binding.populationId with
        | .unknown => true
        | .known populationId =>
            packageKnowledgeStringMatches populationId input.obligation.populationId) &&
        packageKnowledgeStringMatches input.obligation.itemId binding.memberId) &&
    packageControlPackWellFormed input.controlPack &&
    boundedPackageId input.expectedCurrent.evaluationId &&
    packageDigestWellFormed input.expectedCurrent.resultDigest &&
    evaluationReceiptWellFormed input.currentReceipt && packageResultMatchesOwner input &&
    packageOptionalRecordsMatch input && input.observedOriginRefs.length ≤ maxRows &&
    input.observedOriginRefs.all boundedPackageId &&
    (match encodeFinancialResult input.engineResult with
    | none => false
    | some bytes => bytes.length ≤ maxTotalEncodedBytes)

def priorDecisionSupport (input : DecisionPackageInput) : DecisionSupport :=
  match input.currentDetermination, input.priorReceipt with
  | some _, some receipt =>
      if receipt.result.verificationStatus = "SUPPORTED" then .SUPPORTED
      else if receipt.result.verificationStatus = "MISSING_EVIDENCE" ||
          receipt.result.verificationStatus = "CONFLICT_VISIBLE" then .UNSUPPORTED
      else .UNKNOWN
  | _, _ => .UNKNOWN

def projectDecisionPackage (input : DecisionPackageInput) : Option DecisionPackageProjection :=
  if !decisionPackageInputWellFormed input then none
  else
    let caseId := input.currentCase.map (fun value => value.caseId)
    let caseReason := input.currentCase.map (fun value => value.reason)
    let accountability := input.currentCase.map (fun value => value.contractualAccountability)
    let nextActionOwner := input.currentCase.map (fun value => value.nextActionOwner)
    let nextActionDeadline := input.currentCase.map (fun value => value.dueAtMs)
    let determinationId := input.currentDetermination.map (fun value => value.determinationId)
    let claimId := (input.currentDetermination.bind (fun value => value.claimId))
    let decisionActorId := input.currentDetermination.map (fun value => value.actorId)
    let decisionActorRole := input.currentDetermination.map (fun value => value.actorRole)
    let decisionAuthorityId := input.currentDetermination.map (fun value => value.authorityId)
    let decisionAuthorityEpoch := input.currentDetermination.map
      (fun value => value.authorityEpoch)
    let decisionAuthorityDigest := input.currentDetermination.map
      (fun value => value.authorityDigest)
    let decision := input.currentDetermination.map (fun value => value.decision)
    let decisionAmount := input.currentDetermination.map (fun value => value.amountCents)
    let decisionSupportingEvidence := input.currentDetermination.map
      (fun value => value.supportingEvidence)
    let determinationDigest := input.currentDetermination.map
      (fun value => value.determinationDigest)
    let inputEvaluationId := input.currentDetermination.map
      (fun value => value.inputEvaluationId)
    let inputEvaluationResultDigest := input.currentDetermination.map
      (fun value => value.inputEvaluationResultDigest)
    let decisionExpectedRevision := input.currentDetermination.map
      (fun value => value.expectedRevision)
    let decisionResultingRevision := input.currentDetermination.map
      (fun value => value.resultingRevision)
    let decisionAtMs := input.currentDetermination.map (fun value => value.decidedAtMs)
    let actionId := input.currentAction.map (fun value => value.actionId)
    let actionKind := input.currentAction.map (fun value => value.kind)
    let actionStatus := input.currentAction.map (fun value => value.status)
    let acknowledgmentStatus := input.currentAction.map (fun value => value.acknowledgmentStatus)
    let acknowledgmentReference :=
      input.currentAction.bind (fun value => value.acknowledgmentReference)
    let acknowledgmentCashEffect := input.currentAction.map
      (fun value => value.acknowledgmentCashEffectCents)
    some {
      contract := input.contract
      scope := input.scope
      populationBinding := match input.populationBinding with
        | none => .unknown
        | some value => .known value
      obligationId := input.obligation.obligationId
      obligationRevision := input.obligation.revision
      controlPackId := input.controlPack.packId
      controlPackVersion := input.controlPack.version
      controlPackDigest := input.controlPack.digest
      sourceRefs := input.controlPack.sourceRefs
      evaluationId := input.currentReceipt.result.evaluationId
      evaluationResultDigest := input.currentReceipt.evaluationResultDigest
      resultDigest := input.currentReceipt.resultDigest
      receiptDigest := input.currentReceipt.receiptDigest
      currentReceipt := input.currentReceipt
      inputSnapshotDigest := match input.currentReceipt.inputSnapshotDigest with
        | none => .unknown
        | some digest => .known digest
      caseId := match caseId with | none => .unknown | some value => .known value
      caseReason := match caseReason with | none => .unknown | some value => .known value
      contractualAccountability := match accountability with
        | none => .unknown | some value => .known value
      caseStatus := .known input.obligation.caseStatus
      nextActionOwner := match nextActionOwner with
        | none => .unknown | some value => .known value
      nextActionDeadlineMs := match nextActionDeadline with
        | none => .unknown | some value => .known value
      nextActionCommand := .unknown
      determinationId := match determinationId with
        | none => .unknown | some value => .known value
      claimId := match claimId with | none => .unknown | some value => .known value
      decisionActorId := match decisionActorId with
        | none => .unknown | some value => .known value
      decisionActorRole := match decisionActorRole with
        | none => .unknown | some value => .known value
      decisionAuthorityId := match decisionAuthorityId with
        | none => .unknown | some value => .known value
      decisionAuthorityEpoch := match decisionAuthorityEpoch with
        | none => .unknown | some value => .known value
      decisionAuthorityDigest := match decisionAuthorityDigest with
        | none => .unknown | some value => .known value
      decision := match decision with | none => .unknown | some value => .known value
      decisionAmountCents := match decisionAmount with
        | none => .unknown | some value => .known value
      decisionSupportingEvidence := match decisionSupportingEvidence with
        | none => .unknown | some value => .known value
      determinationDigest := match determinationDigest with
        | none => .unknown | some value => .known value
      inputEvaluationId := match inputEvaluationId with
        | none => .unknown | some value => .known value
      inputEvaluationResultDigest := match inputEvaluationResultDigest with
        | none => .unknown | some value => .known value
      decisionExpectedRevision := match decisionExpectedRevision with
        | none => .unknown | some value => .known value
      decisionResultingRevision := match decisionResultingRevision with
        | none => .unknown | some value => .known value
      decisionAtMs := match decisionAtMs with
        | none => .unknown | some value => .known value
      decisionSupport := priorDecisionSupport input
      actionId := match actionId with | none => .unknown | some value => .known value
      actionKind := match actionKind with | none => .unknown | some value => .known value
      actionKindMapping := .unknown
      actionStatus := match actionStatus with | none => .unknown | some value => .known value
      acknowledgmentStatus := match acknowledgmentStatus with
        | none => .unknown | some value => .known value
      acknowledgmentReference := match acknowledgmentReference with
        | none => .unknown | some value => .known value
      acknowledgmentCashEffectCents := match acknowledgmentCashEffect with
        | none => .unknown | some value => .known value
      balance := {
        owedCents := input.obligation.owedCents
        receivedCashCents := input.cash.recordedReceivedCashCents
        claimedAdjustmentCents := input.cash.claimedAdjustmentCents
        lawfulAdjustmentCents := input.cash.lawfulAdjustmentCents
        shortfallCents := input.cash.shortfallCents
        overageCents := input.cash.overageCents
        cashSatisfied := input.cash.cashSatisfied
        amountSatisfied := input.cash.amountSatisfied
      }
      reportingComplete := input.reporting.complete
      reportingEvidenceCount := input.reporting.evidenceCount
      observedOriginRefs := input.observedOriginRefs
      commonCause := .unknown
    }

end BlindLedger.Financial.DecisionPackage
