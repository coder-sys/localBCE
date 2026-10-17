import BlindLedger.Financial.Codec
import BlindLedger.Financial.DecisionPackage.Projection

namespace BlindLedger.Financial.DecisionPackage

open BlindLedger.Financial

def encodeOptional {α : Type} (encode : α → Bytes) : Option α → Bytes
  | none => [UInt8.ofNat 0]
  | some value => UInt8.ofNat 1 :: encode value

def readOptional {α : Type} (parse : Bytes → Option (α × Bytes)) :
    Bytes → Option (Option α × Bytes)
  | [] => none
  | tag :: rest =>
      if tag.toNat = 0 then some (none, rest)
      else if tag.toNat = 1 then do
        let (value, tail) ← parse rest
        pure (some value, tail)
      else none

def encodePackageScope (scope : PackageScope) : Bytes :=
  encodeString scope.stateId ++ encodeString scope.deploymentId ++
    encodeString scope.programId ++ encodeString scope.periodId ++
    encodeString scope.currency

def readPackageScope (bytes : Bytes) : Option (PackageScope × Bytes) := do
  let (stateId, rest) ← readString bytes
  let (deploymentId, rest) ← readString rest
  let (programId, rest) ← readString rest
  let (periodId, rest) ← readString rest
  let (currency, rest) ← readString rest
  pure ({
    stateId := stateId
    deploymentId := deploymentId
    programId := programId
    periodId := periodId
    currency := currency }, rest)

def encodeKnowledge {α : Type} (encode : α → Bytes) : Knowledge α → Bytes
  | .unknown => [UInt8.ofNat 0]
  | .known value => UInt8.ofNat 1 :: encode value

def readKnowledge {α : Type} (parse : Bytes → Option (α × Bytes)) :
    Bytes → Option (Knowledge α × Bytes)
  | [] => none
  | tag :: rest =>
      if tag.toNat = 0 then some (.unknown, rest)
      else if tag.toNat = 1 then do
        let (value, tail) ← parse rest
        pure (.known value, tail)
      else none

def encodePackageObligation (value : PackageObligation) : Bytes :=
  encodeString value.obligationId ++ encodeString value.itemId ++
    encodeKnowledge encodeString value.populationId ++ encodeString value.periodId ++
    encodeString value.currency ++ natBE 8 value.revision ++ natBE 8 value.owedCents ++
    natBE 8 value.claimedAdjustmentCents ++ natBE 8 value.lawfulAdjustmentCents ++
    natBE 8 value.receivedCashCents ++ natBE 8 value.shortfallCents ++
    natBE 8 value.overageCents ++ encodeBool value.cashSatisfied ++
    encodeBool value.amountSatisfied ++ encodeBool value.timely ++
    encodeBool value.reportingComplete ++ encodeString value.verificationStatus ++
    encodeString value.caseStatus ++ encodeString value.deliveryStatus ++
    encodeOptionString value.currentEvaluationId ++ natBE 8 value.dueAtMs

def readPackageObligation (bytes : Bytes) : Option (PackageObligation × Bytes) := do
  let (obligationId, rest) ← readString bytes
  let (itemId, rest) ← readString rest
  let (populationId, rest) ← readKnowledge readString rest
  let (periodId, rest) ← readString rest
  let (currency, rest) ← readString rest
  let (revision, rest) ← readNatBE 8 rest
  let (owedCents, rest) ← readNatBE 8 rest
  let (claimedAdjustmentCents, rest) ← readNatBE 8 rest
  let (lawfulAdjustmentCents, rest) ← readNatBE 8 rest
  let (receivedCashCents, rest) ← readNatBE 8 rest
  let (shortfallCents, rest) ← readNatBE 8 rest
  let (overageCents, rest) ← readNatBE 8 rest
  let (cashSatisfied, rest) ← readBool rest
  let (amountSatisfied, rest) ← readBool rest
  let (timely, rest) ← readBool rest
  let (reportingComplete, rest) ← readBool rest
  let (verificationStatus, rest) ← readString rest
  let (caseStatus, rest) ← readString rest
  let (deliveryStatus, rest) ← readString rest
  let (currentEvaluationId, rest) ← readOptionString rest
  let (dueAtMs, rest) ← readNatBE 8 rest
  pure ({
    obligationId := obligationId
    itemId := itemId
    populationId := populationId
    periodId := periodId
    currency := currency
    revision := revision
    owedCents := owedCents
    claimedAdjustmentCents := claimedAdjustmentCents
    lawfulAdjustmentCents := lawfulAdjustmentCents
    receivedCashCents := receivedCashCents
    shortfallCents := shortfallCents
    overageCents := overageCents
    cashSatisfied := cashSatisfied
    amountSatisfied := amountSatisfied
    timely := timely
    reportingComplete := reportingComplete
    verificationStatus := verificationStatus
    caseStatus := caseStatus
    deliveryStatus := deliveryStatus
    currentEvaluationId := currentEvaluationId
    dueAtMs := dueAtMs }, rest)

def encodeOwnerPopulationBinding (value : OwnerPopulationBinding) : Bytes :=
  encodeKnowledge encodeString value.populationId ++ encodeString value.status ++
    encodeString value.completeness ++ encodeBool value.sourceComplete ++
    encodeKnowledge encodeString value.manifestId ++ natBE 8 value.manifestVersion ++
    encodeKnowledge encodeDigest value.manifestDigest ++
    encodeKnowledge encodeString value.memberId ++ natBE 8 value.memberCount ++
    encodeKnowledge encodeDigest value.memberDigest

def readOwnerPopulationBinding (bytes : Bytes) :
    Option (OwnerPopulationBinding × Bytes) := do
  let (populationId, rest) ← readKnowledge readString bytes
  let (status, rest) ← readString rest
  let (completeness, rest) ← readString rest
  let (sourceComplete, rest) ← readBool rest
  let (manifestId, rest) ← readKnowledge readString rest
  let (manifestVersion, rest) ← readNatBE 8 rest
  let (manifestDigest, rest) ← readKnowledge readDigest rest
  let (memberId, rest) ← readKnowledge readString rest
  let (memberCount, rest) ← readNatBE 8 rest
  let (memberDigest, rest) ← readKnowledge readDigest rest
  pure ({
    populationId := populationId
    status := status
    completeness := completeness
    sourceComplete := sourceComplete
    manifestId := manifestId
    manifestVersion := manifestVersion
    manifestDigest := manifestDigest
    memberId := memberId
    memberCount := memberCount
    memberDigest := memberDigest }, rest)

def encodePackageControlPack (value : PackageControlPack) : Bytes :=
  encodeString value.packId ++ natBE 8 value.version ++ encodeDigest value.digest ++
    encodeString value.calculationRuleId ++ encodeString value.adjustmentRuleId ++
    encodeList encodeString value.sourceRefs ++ encodeList encodeString value.authorizedRoles ++
    natBE 8 value.effectiveStartMs ++ natBE 8 value.effectiveEndMs ++
    natBE 8 value.recordedAtMs ++ natBE 8 value.approvedAtMs

def readPackageControlPack (bytes : Bytes) : Option (PackageControlPack × Bytes) := do
  let (packId, rest) ← readString bytes
  let (version, rest) ← readNatBE 8 rest
  let (digest, rest) ← readDigest rest
  let (calculationRuleId, rest) ← readString rest
  let (adjustmentRuleId, rest) ← readString rest
  let (sourceRefs, rest) ← readList readString rest
  let (authorizedRoles, rest) ← readList readString rest
  let (effectiveStartMs, rest) ← readNatBE 8 rest
  let (effectiveEndMs, rest) ← readNatBE 8 rest
  let (recordedAtMs, rest) ← readNatBE 8 rest
  let (approvedAtMs, rest) ← readNatBE 8 rest
  pure ({
    packId := packId
    version := version
    digest := digest
    calculationRuleId := calculationRuleId
    adjustmentRuleId := adjustmentRuleId
    sourceRefs := sourceRefs
    authorizedRoles := authorizedRoles
    effectiveStartMs := effectiveStartMs
    effectiveEndMs := effectiveEndMs
    recordedAtMs := recordedAtMs
    approvedAtMs := approvedAtMs }, rest)

def encodeReceiptControlPack (value : ReceiptControlPack) : Bytes :=
  encodeString value.packId ++ natBE 8 value.version ++ encodeDigest value.digest

def readReceiptControlPack (bytes : Bytes) : Option (ReceiptControlPack × Bytes) := do
  let (packId, rest) ← readString bytes
  let (version, rest) ← readNatBE 8 rest
  let (digest, rest) ← readDigest rest
  pure ({
    packId := packId
    version := version
    digest := digest }, rest)

def encodeReceiptAuthority (value : ReceiptAuthority) : Bytes :=
  natBE 8 value.authorityEpoch ++ encodeDigest value.authorityDigest

def readReceiptAuthority (bytes : Bytes) : Option (ReceiptAuthority × Bytes) := do
  let (authorityEpoch, rest) ← readNatBE 8 bytes
  let (authorityDigest, rest) ← readDigest rest
  pure ({
    authorityEpoch := authorityEpoch
    authorityDigest := authorityDigest }, rest)

def encodeEvidenceBinding (value : EvidenceBinding) : Bytes :=
  encodeString value.evidenceId ++ encodeDigest value.recordDigest

def readEvidenceBinding (bytes : Bytes) : Option (EvidenceBinding × Bytes) := do
  let (evidenceId, rest) ← readString bytes
  let (recordDigest, rest) ← readDigest rest
  pure ({
    evidenceId := evidenceId
    recordDigest := recordDigest }, rest)

def encodeOwnerEvaluationResult (value : OwnerEvaluationResult) : Bytes :=
  encodeString value.evaluationId ++ encodeString value.obligationId ++
    natBE 8 value.revision ++ natBE 8 value.ruleVersion ++
    encodeList encodeString value.evidenceIds ++ encodeString value.authorityId ++
    natBE 8 value.evaluatedAtMs ++ natBE 8 value.owedCents ++
    natBE 8 value.claimedAdjustmentCents ++ natBE 8 value.lawfulAdjustmentCents ++
    natBE 8 value.receivedCashCents ++ natBE 8 value.shortfallCents ++
    natBE 8 value.overageCents ++ encodeBool value.cashSatisfied ++
    encodeBool value.amountSatisfied ++ encodeBool value.timely ++
    encodeBool value.reportingComplete ++ encodeString value.verificationStatus ++
    encodeString value.caseStatus ++ encodeString value.deliveryStatus

def readOwnerEvaluationResult (bytes : Bytes) : Option (OwnerEvaluationResult × Bytes) := do
  let (evaluationId, rest) ← readString bytes
  let (obligationId, rest) ← readString rest
  let (revision, rest) ← readNatBE 8 rest
  let (ruleVersion, rest) ← readNatBE 8 rest
  let (evidenceIds, rest) ← readList readString rest
  let (authorityId, rest) ← readString rest
  let (evaluatedAtMs, rest) ← readNatBE 8 rest
  let (owedCents, rest) ← readNatBE 8 rest
  let (claimedAdjustmentCents, rest) ← readNatBE 8 rest
  let (lawfulAdjustmentCents, rest) ← readNatBE 8 rest
  let (receivedCashCents, rest) ← readNatBE 8 rest
  let (shortfallCents, rest) ← readNatBE 8 rest
  let (overageCents, rest) ← readNatBE 8 rest
  let (cashSatisfied, rest) ← readBool rest
  let (amountSatisfied, rest) ← readBool rest
  let (timely, rest) ← readBool rest
  let (reportingComplete, rest) ← readBool rest
  let (verificationStatus, rest) ← readString rest
  let (caseStatus, rest) ← readString rest
  let (deliveryStatus, rest) ← readString rest
  pure ({
    evaluationId := evaluationId
    obligationId := obligationId
    revision := revision
    ruleVersion := ruleVersion
    evidenceIds := evidenceIds
    authorityId := authorityId
    evaluatedAtMs := evaluatedAtMs
    owedCents := owedCents
    claimedAdjustmentCents := claimedAdjustmentCents
    lawfulAdjustmentCents := lawfulAdjustmentCents
    receivedCashCents := receivedCashCents
    shortfallCents := shortfallCents
    overageCents := overageCents
    cashSatisfied := cashSatisfied
    amountSatisfied := amountSatisfied
    timely := timely
    reportingComplete := reportingComplete
    verificationStatus := verificationStatus
    caseStatus := caseStatus
    deliveryStatus := deliveryStatus }, rest)

def encodeEvaluationReceipt (value : EvaluationReceipt) : Bytes :=
  encodeString value.contractVersion ++ encodePackageScope value.scope ++
    encodeReceiptControlPack value.controlPack ++
    encodeList encodeEvidenceBinding value.evidenceBindings ++
    encodeOptional encodeDigest value.inputSnapshotDigest ++
    encodeReceiptAuthority value.authority ++ encodeOwnerEvaluationResult value.result ++
    encodeDigest value.resultDigest ++ encodeDigest value.receiptDigest ++
    encodeDigest value.evaluationResultDigest

def readEvaluationReceipt (bytes : Bytes) : Option (EvaluationReceipt × Bytes) := do
  let (contractVersion, rest) ← readString bytes
  let (scope, rest) ← readPackageScope rest
  let (controlPack, rest) ← readReceiptControlPack rest
  let (evidenceBindings, rest) ← readList readEvidenceBinding rest
  let (inputSnapshotDigest, rest) ← readOptional readDigest rest
  let (authority, rest) ← readReceiptAuthority rest
  let (result, rest) ← readOwnerEvaluationResult rest
  let (resultDigest, rest) ← readDigest rest
  let (receiptDigest, rest) ← readDigest rest
  let (evaluationResultDigest, rest) ← readDigest rest
  pure ({
    contractVersion := contractVersion
    scope := scope
    controlPack := controlPack
    evidenceBindings := evidenceBindings
    inputSnapshotDigest := inputSnapshotDigest
    authority := authority
    result := result
    resultDigest := resultDigest
    receiptDigest := receiptDigest
    evaluationResultDigest := evaluationResultDigest }, rest)

def encodeCurrentExpectation (value : CurrentEvaluationExpectation) : Bytes :=
  encodeString value.evaluationId ++ encodeDigest value.resultDigest

def readCurrentExpectation (bytes : Bytes) :
    Option (CurrentEvaluationExpectation × Bytes) := do
  let (evaluationId, rest) ← readString bytes
  let (resultDigest, rest) ← readDigest rest
  pure ({
    evaluationId := evaluationId
    resultDigest := resultDigest }, rest)

def encodeOwnerCase (value : OwnerCase) : Bytes :=
  encodeString value.caseId ++ encodeString value.obligationId ++
    encodeString value.reason ++ encodeString value.contractualAccountability ++
    encodeString value.nextActionOwner ++ natBE 8 value.dueAtMs ++
    encodeString value.status ++ natBE 8 value.updatedAtMs

def readOwnerCase (bytes : Bytes) : Option (OwnerCase × Bytes) := do
  let (caseId, rest) ← readString bytes
  let (obligationId, rest) ← readString rest
  let (reason, rest) ← readString rest
  let (contractualAccountability, rest) ← readString rest
  let (nextActionOwner, rest) ← readString rest
  let (dueAtMs, rest) ← readNatBE 8 rest
  let (status, rest) ← readString rest
  let (updatedAtMs, rest) ← readNatBE 8 rest
  pure ({
    caseId := caseId
    obligationId := obligationId
    reason := reason
    contractualAccountability := contractualAccountability
    nextActionOwner := nextActionOwner
    dueAtMs := dueAtMs
    status := status
    updatedAtMs := updatedAtMs }, rest)

def encodeOwnerDetermination (value : OwnerDetermination) : Bytes :=
  encodeString value.determinationId ++ encodeString value.obligationId ++
    encodeOptionString value.claimId ++ encodeString value.actorId ++
    encodeString value.actorRole ++ encodeString value.authorityId ++
    natBE 8 value.authorityEpoch ++ encodeDigest value.authorityDigest ++
    encodeString value.decision ++ natBE 8 value.amountCents ++
    encodeList encodeEvidenceBinding value.supportingEvidence ++
    natBE 8 value.expectedRevision ++
    natBE 8 value.resultingRevision ++ natBE 8 value.decidedAtMs ++
    encodeDigest value.determinationDigest ++ encodeString value.inputEvaluationId ++
    encodeDigest value.inputEvaluationResultDigest

def readOwnerDetermination (bytes : Bytes) : Option (OwnerDetermination × Bytes) := do
  let (determinationId, rest) ← readString bytes
  let (obligationId, rest) ← readString rest
  let (claimId, rest) ← readOptionString rest
  let (actorId, rest) ← readString rest
  let (actorRole, rest) ← readString rest
  let (authorityId, rest) ← readString rest
  let (authorityEpoch, rest) ← readNatBE 8 rest
  let (authorityDigest, rest) ← readDigest rest
  let (decision, rest) ← readString rest
  let (amountCents, rest) ← readNatBE 8 rest
  let (supportingEvidence, rest) ← readList readEvidenceBinding rest
  let (expectedRevision, rest) ← readNatBE 8 rest
  let (resultingRevision, rest) ← readNatBE 8 rest
  let (decidedAtMs, rest) ← readNatBE 8 rest
  let (determinationDigest, rest) ← readDigest rest
  let (inputEvaluationId, rest) ← readString rest
  let (inputEvaluationResultDigest, rest) ← readDigest rest
  pure ({
    determinationId := determinationId
    obligationId := obligationId
    claimId := claimId
    actorId := actorId
    actorRole := actorRole
    authorityId := authorityId
    authorityEpoch := authorityEpoch
    authorityDigest := authorityDigest
    decision := decision
    amountCents := amountCents
    supportingEvidence := supportingEvidence
    expectedRevision := expectedRevision
    resultingRevision := resultingRevision
    decidedAtMs := decidedAtMs
    determinationDigest := determinationDigest
    inputEvaluationId := inputEvaluationId
    inputEvaluationResultDigest := inputEvaluationResultDigest }, rest)

def encodeOwnerAction (value : OwnerAction) : Bytes :=
  encodeString value.actionId ++ encodeString value.obligationId ++
    encodeString value.determinationId ++ encodeString value.kind ++
    encodeString value.status ++ natBE 8 value.revision ++
    encodeDigest value.payloadDigest ++ natBE 8 value.createdAtMs ++
    encodeString value.acknowledgmentStatus ++
    encodeOptionString value.acknowledgmentReference ++
    natBE 8 value.acknowledgmentAttempt ++
    natBE 8 value.acknowledgmentUpdatedAtMs ++
    natBE 8 value.acknowledgmentCashEffectCents

def readOwnerAction (bytes : Bytes) : Option (OwnerAction × Bytes) := do
  let (actionId, rest) ← readString bytes
  let (obligationId, rest) ← readString rest
  let (determinationId, rest) ← readString rest
  let (kind, rest) ← readString rest
  let (status, rest) ← readString rest
  let (revision, rest) ← readNatBE 8 rest
  let (payloadDigest, rest) ← readDigest rest
  let (createdAtMs, rest) ← readNatBE 8 rest
  let (acknowledgmentStatus, rest) ← readString rest
  let (acknowledgmentReference, rest) ← readOptionString rest
  let (acknowledgmentAttempt, rest) ← readNatBE 8 rest
  let (acknowledgmentUpdatedAtMs, rest) ← readNatBE 8 rest
  let (acknowledgmentCashEffectCents, rest) ← readNatBE 8 rest
  pure ({
    actionId := actionId
    obligationId := obligationId
    determinationId := determinationId
    kind := kind
    status := status
    revision := revision
    payloadDigest := payloadDigest
    createdAtMs := createdAtMs
    acknowledgmentStatus := acknowledgmentStatus
    acknowledgmentReference := acknowledgmentReference
    acknowledgmentAttempt := acknowledgmentAttempt
    acknowledgmentUpdatedAtMs := acknowledgmentUpdatedAtMs
    acknowledgmentCashEffectCents := acknowledgmentCashEffectCents }, rest)

def encodePackageCash (value : PackageCash) : Bytes :=
  natBE 8 value.recordedReceivedCashCents ++ encodeBool value.cashSatisfied ++
    natBE 8 value.claimedAdjustmentCents ++ natBE 8 value.lawfulAdjustmentCents ++
    encodeBool value.amountSatisfied ++ natBE 8 value.shortfallCents ++
    natBE 8 value.overageCents ++ natBE 8 value.activePaymentCount ++
    natBE 8 value.authorizedAdjustmentCount

def readPackageCash (bytes : Bytes) : Option (PackageCash × Bytes) := do
  let (recordedReceivedCashCents, rest) ← readNatBE 8 bytes
  let (cashSatisfied, rest) ← readBool rest
  let (claimedAdjustmentCents, rest) ← readNatBE 8 rest
  let (lawfulAdjustmentCents, rest) ← readNatBE 8 rest
  let (amountSatisfied, rest) ← readBool rest
  let (shortfallCents, rest) ← readNatBE 8 rest
  let (overageCents, rest) ← readNatBE 8 rest
  let (activePaymentCount, rest) ← readNatBE 8 rest
  let (authorizedAdjustmentCount, rest) ← readNatBE 8 rest
  pure ({
    recordedReceivedCashCents := recordedReceivedCashCents
    cashSatisfied := cashSatisfied
    claimedAdjustmentCents := claimedAdjustmentCents
    lawfulAdjustmentCents := lawfulAdjustmentCents
    amountSatisfied := amountSatisfied
    shortfallCents := shortfallCents
    overageCents := overageCents
    activePaymentCount := activePaymentCount
    authorizedAdjustmentCount := authorizedAdjustmentCount }, rest)

def encodePackageReporting (value : PackageReporting) : Bytes :=
  encodeBool value.complete ++ natBE 8 value.evidenceCount

def readPackageReporting (bytes : Bytes) : Option (PackageReporting × Bytes) := do
  let (complete, rest) ← readBool bytes
  let (evidenceCount, rest) ← readNatBE 8 rest
  pure ({
    complete := complete
    evidenceCount := evidenceCount }, rest)

def encodeDecisionPackageBody (value : DecisionPackageInput) : Option Bytes := do
  let engineResult ← encodeFinancialResult value.engineResult
  let bytes := decisionPackageInputMagic ++ encodeString value.contract ++
    encodeOptional encodeString value.mirrorSchema ++
    encodeOptional encodeString value.resource ++ encodePackageScope value.scope ++
    encodePackageObligation value.obligation ++
    encodeOptional encodeOwnerPopulationBinding value.populationBinding ++
    encodePackageControlPack value.controlPack ++
    encodeCurrentExpectation value.expectedCurrent ++
    encodeEvaluationReceipt value.currentReceipt ++
    encodeOptional encodeEvaluationReceipt value.priorReceipt ++
    encodeOptional encodeOwnerCase value.currentCase ++
    encodeOptional encodeOwnerDetermination value.currentDetermination ++
    encodeOptional encodeOwnerAction value.currentAction ++ encodePackageCash value.cash ++
    encodePackageReporting value.reporting ++ encodeList encodeString value.observedOriginRefs ++
    natBE 4 engineResult.length ++ engineResult
  if bytes.length ≤ maxDecisionPackageBytes then some bytes else none

def encodeDecisionPackageInput (value : DecisionPackageInput) : Option Bytes :=
  if decisionPackageInputWellFormed value then encodeDecisionPackageBody value else none

def decodeDecisionPackageInput (bytes : Bytes) : Option DecisionPackageInput := do
  if bytes.length > maxDecisionPackageBytes ||
      bytes.take decisionPackageInputMagic.length != decisionPackageInputMagic then none else
    let body := bytes.drop decisionPackageInputMagic.length
    let (contract, rest) ← readString body
    let (mirrorSchema, rest) ← readOptional readString rest
    let (resource, rest) ← readOptional readString rest
    let (scope, rest) ← readPackageScope rest
    let (obligation, rest) ← readPackageObligation rest
    let (populationBinding, rest) ← readOptional readOwnerPopulationBinding rest
    let (controlPack, rest) ← readPackageControlPack rest
    let (expectedCurrent, rest) ← readCurrentExpectation rest
    let (currentReceipt, rest) ← readEvaluationReceipt rest
    let (priorReceipt, rest) ← readOptional readEvaluationReceipt rest
    let (currentCase, rest) ← readOptional readOwnerCase rest
    let (currentDetermination, rest) ← readOptional readOwnerDetermination rest
    let (currentAction, rest) ← readOptional readOwnerAction rest
    let (cash, rest) ← readPackageCash rest
    let (reporting, rest) ← readPackageReporting rest
    let (observedOriginRefs, rest) ← readList readString rest
    let (engineResultLength, rest) ← readNatBE 4 rest
    if engineResultLength > maxTotalEncodedBytes || rest.length < engineResultLength then none else
      let engineResultBytes := rest.take engineResultLength
      let tail := rest.drop engineResultLength
      if !tail.isEmpty then none else do
        let engineResult ← decodeFinancialResult engineResultBytes
        let value : DecisionPackageInput := {
          contract := contract
          mirrorSchema := mirrorSchema
          resource := resource
          scope := scope
          obligation := obligation
          populationBinding := populationBinding
          controlPack := controlPack
          expectedCurrent := expectedCurrent
          currentReceipt := currentReceipt
          priorReceipt := priorReceipt
          currentCase := currentCase
          currentDetermination := currentDetermination
          currentAction := currentAction
          cash := cash
          reporting := reporting
          observedOriginRefs := observedOriginRefs
          engineResult := engineResult }
        if !decisionPackageInputWellFormed value then none else
          match encodeDecisionPackageBody value with
          | some canonical => if canonical = bytes then some value else none
          | none => none

def encodeDecisionSupport : DecisionSupport → Bytes
  | .UNKNOWN => [UInt8.ofNat 0]
  | .SUPPORTED => [UInt8.ofNat 1]
  | .UNSUPPORTED => [UInt8.ofNat 2]

def readDecisionSupport (bytes : Bytes) : Option (DecisionSupport × Bytes) := do
  let (tag, rest) ← readByte bytes
  match tag.toNat with
  | 0 => pure (.UNKNOWN, rest)
  | 1 => pure (.SUPPORTED, rest)
  | 2 => pure (.UNSUPPORTED, rest)
  | _ => none

def encodePackageBalance (value : PackageBalance) : Bytes :=
  natBE 8 value.owedCents ++ natBE 8 value.receivedCashCents ++
    natBE 8 value.claimedAdjustmentCents ++ natBE 8 value.lawfulAdjustmentCents ++
    natBE 8 value.shortfallCents ++ natBE 8 value.overageCents ++
    encodeBool value.cashSatisfied ++ encodeBool value.amountSatisfied

def readPackageBalance (bytes : Bytes) : Option (PackageBalance × Bytes) := do
  let (owedCents, rest) ← readNatBE 8 bytes
  let (receivedCashCents, rest) ← readNatBE 8 rest
  let (claimedAdjustmentCents, rest) ← readNatBE 8 rest
  let (lawfulAdjustmentCents, rest) ← readNatBE 8 rest
  let (shortfallCents, rest) ← readNatBE 8 rest
  let (overageCents, rest) ← readNatBE 8 rest
  let (cashSatisfied, rest) ← readBool rest
  let (amountSatisfied, rest) ← readBool rest
  pure ({
    owedCents := owedCents
    receivedCashCents := receivedCashCents
    claimedAdjustmentCents := claimedAdjustmentCents
    lawfulAdjustmentCents := lawfulAdjustmentCents
    shortfallCents := shortfallCents
    overageCents := overageCents
    cashSatisfied := cashSatisfied
    amountSatisfied := amountSatisfied }, rest)

def encodeKnowledgePopulationBinding : Knowledge OwnerPopulationBinding → Bytes :=
  encodeKnowledge encodeOwnerPopulationBinding

def readKnowledgePopulationBinding (bytes : Bytes) :
    Option (Knowledge OwnerPopulationBinding × Bytes) :=
  readKnowledge readOwnerPopulationBinding bytes

def encodeDecisionPackageProjectionBody (value : DecisionPackageProjection) : Bytes :=
  decisionPackageProjectionMagic ++ encodeString value.contract ++
    encodePackageScope value.scope ++ encodeKnowledgePopulationBinding value.populationBinding ++
    encodeString value.obligationId ++
    natBE 8 value.obligationRevision ++ encodeString value.controlPackId ++
    natBE 8 value.controlPackVersion ++ encodeDigest value.controlPackDigest ++
    encodeList encodeString value.sourceRefs ++ encodeString value.evaluationId ++
    encodeDigest value.evaluationResultDigest ++ encodeDigest value.resultDigest ++
    encodeDigest value.receiptDigest ++ encodeEvaluationReceipt value.currentReceipt ++
    encodeKnowledge encodeDigest value.inputSnapshotDigest ++
    encodeKnowledge encodeString value.caseId ++ encodeKnowledge encodeString value.caseReason ++
    encodeKnowledge encodeString value.contractualAccountability ++
    encodeKnowledge encodeString value.caseStatus ++
    encodeKnowledge encodeString value.nextActionOwner ++
    encodeKnowledge (natBE 8) value.nextActionDeadlineMs ++
    encodeKnowledge encodeString value.nextActionCommand ++
    encodeKnowledge encodeString value.determinationId ++
    encodeKnowledge encodeString value.claimId ++ encodeKnowledge encodeString value.decision ++
    encodeKnowledge encodeString value.decisionActorId ++
    encodeKnowledge encodeString value.decisionActorRole ++
    encodeKnowledge encodeString value.decisionAuthorityId ++
    encodeKnowledge (natBE 8) value.decisionAuthorityEpoch ++
    encodeKnowledge encodeDigest value.decisionAuthorityDigest ++
    encodeKnowledge (natBE 8) value.decisionAmountCents ++
    encodeKnowledge (encodeList encodeEvidenceBinding) value.decisionSupportingEvidence ++
    encodeKnowledge encodeDigest value.determinationDigest ++
    encodeKnowledge encodeString value.inputEvaluationId ++
    encodeKnowledge encodeDigest value.inputEvaluationResultDigest ++
    encodeKnowledge (natBE 8) value.decisionExpectedRevision ++
    encodeKnowledge (natBE 8) value.decisionResultingRevision ++
    encodeKnowledge (natBE 8) value.decisionAtMs ++
    encodeDecisionSupport value.decisionSupport ++ encodeKnowledge encodeString value.actionId ++
    encodeKnowledge encodeString value.actionKind ++
    encodeKnowledge encodeString value.actionKindMapping ++
    encodeKnowledge encodeString value.actionStatus ++
    encodeKnowledge encodeString value.acknowledgmentStatus ++
    encodeKnowledge encodeString value.acknowledgmentReference ++
    encodeKnowledge (natBE 8) value.acknowledgmentCashEffectCents ++
    encodePackageBalance value.balance ++ encodeBool value.reportingComplete ++
    natBE 8 value.reportingEvidenceCount ++ encodeList encodeString value.observedOriginRefs ++
    encodeKnowledge encodeString value.commonCause

def decisionPackageProjectionWellFormed (value : DecisionPackageProjection) : Bool :=
  (value.contract = decisionPackageContractV1 || value.contract = decisionPackageContractV2) &&
    packageScopeWellFormed value.scope && boundedPackageId value.obligationId &&
    (match value.contract, value.populationBinding with
      | contract, .known binding => contract = decisionPackageContractV2 &&
          ownerPopulationBindingWellFormed binding
      | _, .unknown => true) &&
    (match value.populationBinding with
      | .unknown => true
      | .known binding => ownerPopulationBindingWellFormed binding) &&
    value.obligationRevision ≤ maxRevision && boundedPackageId value.controlPackId &&
    value.controlPackVersion ≥ 1 && value.controlPackVersion ≤ maxRevision &&
    packageDigestWellFormed value.controlPackDigest && value.sourceRefs.length ≤ maxRows &&
    value.sourceRefs.all boundedPackageText && boundedPackageId value.evaluationId &&
    packageDigestWellFormed value.evaluationResultDigest &&
    packageDigestWellFormed value.resultDigest && packageDigestWellFormed value.receiptDigest &&
    evaluationReceiptWellFormed value.currentReceipt &&
    value.currentReceipt.scope = value.scope &&
    value.currentReceipt.controlPack.packId = value.controlPackId &&
    value.currentReceipt.controlPack.version = value.controlPackVersion &&
    value.currentReceipt.controlPack.digest = value.controlPackDigest &&
    value.currentReceipt.result.evaluationId = value.evaluationId &&
    value.currentReceipt.result.obligationId = value.obligationId &&
    value.currentReceipt.result.revision = value.obligationRevision &&
    value.currentReceipt.evaluationResultDigest = value.evaluationResultDigest &&
    value.currentReceipt.resultDigest = value.resultDigest &&
    value.currentReceipt.receiptDigest = value.receiptDigest &&
    (match value.currentReceipt.inputSnapshotDigest with
      | none => value.inputSnapshotDigest = .unknown
      | some digest => value.inputSnapshotDigest = .known digest) &&
    packageKnowledgeDigestWellFormed value.inputSnapshotDigest &&
    packageKnowledgeIdWellFormed value.caseId &&
    packageKnowledgeTextWellFormed value.caseReason &&
    packageKnowledgeTextWellFormed value.contractualAccountability &&
    packageKnowledgeTextWellFormed value.caseStatus &&
    packageKnowledgeIdWellFormed value.nextActionOwner &&
    packageKnowledgeNatWellFormed maxTime value.nextActionDeadlineMs &&
    packageKnowledgeTextWellFormed value.nextActionCommand &&
    packageKnowledgeIdWellFormed value.determinationId &&
    packageKnowledgeIdWellFormed value.claimId &&
    packageKnowledgeIdWellFormed value.decisionActorId &&
    packageKnowledgeIdWellFormed value.decisionActorRole &&
    packageKnowledgeIdWellFormed value.decisionAuthorityId &&
    packageKnowledgeNatWellFormed maxAuthorityEpoch value.decisionAuthorityEpoch &&
    packageKnowledgeDigestWellFormed value.decisionAuthorityDigest &&
    packageKnowledgeTextWellFormed value.decision &&
    packageKnowledgeNatWellFormed maxCents value.decisionAmountCents &&
    (match value.decisionSupportingEvidence with
      | .unknown => true
      | .known bindings => bindings.length ≤ maxRows && bindings.all (fun binding =>
          boundedPackageId binding.evidenceId && packageDigestWellFormed binding.recordDigest)) &&
    packageKnowledgeDigestWellFormed value.determinationDigest &&
    packageKnowledgeIdWellFormed value.inputEvaluationId &&
    packageKnowledgeDigestWellFormed value.inputEvaluationResultDigest &&
    packageKnowledgeNatWellFormed maxRevision value.decisionExpectedRevision &&
    packageKnowledgeNatWellFormed maxRevision value.decisionResultingRevision &&
    packageKnowledgeNatWellFormed maxTime value.decisionAtMs &&
    packageKnowledgeIdWellFormed value.actionId &&
    packageKnowledgeTextWellFormed value.actionKind &&
    packageKnowledgeTextWellFormed value.actionKindMapping &&
    packageKnowledgeTextWellFormed value.actionStatus &&
    packageKnowledgeTextWellFormed value.acknowledgmentStatus &&
    packageKnowledgeIdWellFormed value.acknowledgmentReference &&
    packageKnowledgeNatWellFormed maxCents value.acknowledgmentCashEffectCents &&
    (value.acknowledgmentCashEffectCents = .unknown ||
      value.acknowledgmentCashEffectCents = .known 0) &&
    packageKnowledgeTextWellFormed value.commonCause &&
    value.commonCause = .unknown && value.nextActionCommand = .unknown &&
    value.actionKindMapping = .unknown &&
    value.evaluationResultDigest = value.resultDigest &&
    value.balance.owedCents ≤ maxCents && value.balance.receivedCashCents ≤ maxCents &&
    value.balance.claimedAdjustmentCents ≤ maxCents &&
    value.balance.lawfulAdjustmentCents ≤ maxCents &&
    value.balance.shortfallCents ≤ maxCents && value.balance.overageCents ≤ maxCents &&
    value.currentReceipt.result.owedCents = value.balance.owedCents &&
    value.currentReceipt.result.receivedCashCents = value.balance.receivedCashCents &&
    value.currentReceipt.result.claimedAdjustmentCents = value.balance.claimedAdjustmentCents &&
    value.currentReceipt.result.lawfulAdjustmentCents = value.balance.lawfulAdjustmentCents &&
    value.currentReceipt.result.shortfallCents = value.balance.shortfallCents &&
    value.currentReceipt.result.overageCents = value.balance.overageCents &&
    value.currentReceipt.result.cashSatisfied = value.balance.cashSatisfied &&
    value.currentReceipt.result.amountSatisfied = value.balance.amountSatisfied &&
    value.currentReceipt.result.reportingComplete = value.reportingComplete &&
    value.caseStatus = .known value.currentReceipt.result.caseStatus &&
    value.reportingEvidenceCount ≤ maxRows && value.observedOriginRefs.length ≤ maxRows &&
    value.observedOriginRefs.all boundedPackageId

def encodeDecisionPackageProjection (value : DecisionPackageProjection) : Option Bytes :=
  if !decisionPackageProjectionWellFormed value then none else
    let bytes := encodeDecisionPackageProjectionBody value
    if bytes.length ≤ maxDecisionPackageBytes then some bytes else none

def decodeDecisionPackageProjection (bytes : Bytes) : Option DecisionPackageProjection := do
  if bytes.length > maxDecisionPackageBytes ||
      bytes.take decisionPackageProjectionMagic.length != decisionPackageProjectionMagic then none else
    let body := bytes.drop decisionPackageProjectionMagic.length
    let (contract, rest) ← readString body
    let (scope, rest) ← readPackageScope rest
    let (populationBinding, rest) ← readKnowledgePopulationBinding rest
    let (obligationId, rest) ← readString rest
    let (obligationRevision, rest) ← readNatBE 8 rest
    let (controlPackId, rest) ← readString rest
    let (controlPackVersion, rest) ← readNatBE 8 rest
    let (controlPackDigest, rest) ← readDigest rest
    let (sourceRefs, rest) ← readList readString rest
    let (evaluationId, rest) ← readString rest
    let (evaluationResultDigest, rest) ← readDigest rest
    let (resultDigest, rest) ← readDigest rest
    let (receiptDigest, rest) ← readDigest rest
    let (currentReceipt, rest) ← readEvaluationReceipt rest
    let (inputSnapshotDigest, rest) ← readKnowledge readDigest rest
    let (caseId, rest) ← readKnowledge readString rest
    let (caseReason, rest) ← readKnowledge readString rest
    let (contractualAccountability, rest) ← readKnowledge readString rest
    let (caseStatus, rest) ← readKnowledge readString rest
    let (nextActionOwner, rest) ← readKnowledge readString rest
    let (nextActionDeadlineMs, rest) ← readKnowledge (readNatBE 8) rest
    let (nextActionCommand, rest) ← readKnowledge readString rest
    let (determinationId, rest) ← readKnowledge readString rest
    let (claimId, rest) ← readKnowledge readString rest
    let (decision, rest) ← readKnowledge readString rest
    let (decisionActorId, rest) ← readKnowledge readString rest
    let (decisionActorRole, rest) ← readKnowledge readString rest
    let (decisionAuthorityId, rest) ← readKnowledge readString rest
    let (decisionAuthorityEpoch, rest) ← readKnowledge (readNatBE 8) rest
    let (decisionAuthorityDigest, rest) ← readKnowledge readDigest rest
    let (decisionAmountCents, rest) ← readKnowledge (readNatBE 8) rest
    let (decisionSupportingEvidence, rest) ← readKnowledge
      (fun bytes => readList readEvidenceBinding bytes) rest
    let (determinationDigest, rest) ← readKnowledge readDigest rest
    let (inputEvaluationId, rest) ← readKnowledge readString rest
    let (inputEvaluationResultDigest, rest) ← readKnowledge readDigest rest
    let (decisionExpectedRevision, rest) ← readKnowledge (readNatBE 8) rest
    let (decisionResultingRevision, rest) ← readKnowledge (readNatBE 8) rest
    let (decisionAtMs, rest) ← readKnowledge (readNatBE 8) rest
    let (decisionSupport, rest) ← readDecisionSupport rest
    let (actionId, rest) ← readKnowledge readString rest
    let (actionKind, rest) ← readKnowledge readString rest
    let (actionKindMapping, rest) ← readKnowledge readString rest
    let (actionStatus, rest) ← readKnowledge readString rest
    let (acknowledgmentStatus, rest) ← readKnowledge readString rest
    let (acknowledgmentReference, rest) ← readKnowledge readString rest
    let (acknowledgmentCashEffectCents, rest) ← readKnowledge (readNatBE 8) rest
    let (balance, rest) ← readPackageBalance rest
    let (reportingComplete, rest) ← readBool rest
    let (reportingEvidenceCount, rest) ← readNatBE 8 rest
    let (observedOriginRefs, rest) ← readList readString rest
    let (commonCause, rest) ← readKnowledge readString rest
    if !rest.isEmpty then none else
      let value : DecisionPackageProjection := {
        contract := contract
        scope := scope
        populationBinding := populationBinding
        obligationId := obligationId
        obligationRevision := obligationRevision
        controlPackId := controlPackId
        controlPackVersion := controlPackVersion
        controlPackDigest := controlPackDigest
        sourceRefs := sourceRefs
        evaluationId := evaluationId
        evaluationResultDigest := evaluationResultDigest
        resultDigest := resultDigest
        receiptDigest := receiptDigest
        currentReceipt := currentReceipt
        inputSnapshotDigest := inputSnapshotDigest
        caseId := caseId
        caseReason := caseReason
        contractualAccountability := contractualAccountability
        caseStatus := caseStatus
        nextActionOwner := nextActionOwner
        nextActionDeadlineMs := nextActionDeadlineMs
        nextActionCommand := nextActionCommand
        determinationId := determinationId
        claimId := claimId
        decisionActorId := decisionActorId
        decisionActorRole := decisionActorRole
        decisionAuthorityId := decisionAuthorityId
        decisionAuthorityEpoch := decisionAuthorityEpoch
        decisionAuthorityDigest := decisionAuthorityDigest
        decision := decision
        decisionAmountCents := decisionAmountCents
        decisionSupportingEvidence := decisionSupportingEvidence
        determinationDigest := determinationDigest
        inputEvaluationId := inputEvaluationId
        inputEvaluationResultDigest := inputEvaluationResultDigest
        decisionExpectedRevision := decisionExpectedRevision
        decisionResultingRevision := decisionResultingRevision
        decisionAtMs := decisionAtMs
        decisionSupport := decisionSupport
        actionId := actionId
        actionKind := actionKind
        actionKindMapping := actionKindMapping
        actionStatus := actionStatus
        acknowledgmentStatus := acknowledgmentStatus
        acknowledgmentReference := acknowledgmentReference
        acknowledgmentCashEffectCents := acknowledgmentCashEffectCents
        balance := balance
        reportingComplete := reportingComplete
        reportingEvidenceCount := reportingEvidenceCount
        observedOriginRefs := observedOriginRefs
        commonCause := commonCause }
      if !decisionPackageProjectionWellFormed value then none else
        match encodeDecisionPackageProjectionBody value with
        | canonical => if canonical = bytes then some value else none

end BlindLedger.Financial.DecisionPackage
