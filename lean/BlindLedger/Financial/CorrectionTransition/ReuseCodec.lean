import BlindLedger.Financial.CorrectionTransition.Codec
import BlindLedger.Financial.CorrectionTransition.Reuse

namespace BlindLedger.Financial.CorrectionTransition

open BlindLedger.Financial
open BlindLedger.Financial.DecisionPackage

def correctionReuseContract : String := "RR/FINANCIAL/CORRECTION-REUSE/v1"
def correctionReuseInputMagic : Bytes := "BLFCRU02".toUTF8.toList
def correctionReuseResultMagic : Bytes := "BLFCRV01".toUTF8.toList
def maxCorrectionReuseBytes : Nat := maxCorrectionTransitionBytes * 3

private def reuseSizedBytes (value : Bytes) : Bytes := natBE 4 value.length ++ value

private def readReuseSizedBytes (maximum : Nat) (bytes : Bytes) : Option (Bytes × Bytes) := do
  let (length, rest) ← readNatBE 4 bytes
  if length > maximum || length > rest.length then none
  else some (rest.take length, rest.drop length)

private def encodeOptionDetermination : Option OffsetDetermination → Bytes
  | none => [UInt8.ofNat 0]
  | some determination => UInt8.ofNat 1 :: encodeDetermination determination

private def readOptionDetermination (bytes : Bytes) : Option (Option OffsetDetermination × Bytes) := do
  let (tag, rest) ← readByte bytes
  if tag.toNat = 0 then some (none, rest)
  else if tag.toNat = 1 then do
    let (determination, tail) ← decodeDetermination rest
    pure (some determination, tail)
  else none

private def encodeOptionalStringReuse : Option String → Bytes
  | none => [UInt8.ofNat 0]
  | some value => UInt8.ofNat 1 :: encodeString value

private def readOptionalStringReuse (bytes : Bytes) : Option (Option String × Bytes) := do
  let (tag, rest) ← readByte bytes
  if tag.toNat = 0 then some (none, rest)
  else if tag.toNat = 1 then do
    let (value, tail) ← readString rest
    pure (some value, tail)
  else none

private def encodeOptionOutbox : Option CorrectionOutboxDelta → Bytes
  | none => [UInt8.ofNat 0]
  | some outbox =>
      [UInt8.ofNat 1] ++ encodeString outbox.actionId ++
        [encodeActionStatus outbox.status] ++ natBE 8 outbox.attempt ++
        encodeOptionalStringReuse outbox.acknowledgmentReference ++ natBE 8 outbox.updatedAtMs

private def readOptionOutbox (bytes : Bytes) : Option (Option CorrectionOutboxDelta × Bytes) := do
  let (tag, rest) ← readByte bytes
  if tag.toNat = 0 then some (none, rest)
  else if tag.toNat = 1 then do
    let (actionId, rest) ← readString rest
    let (statusByte, rest) ← readByte rest
    let status ← decodeActionStatus statusByte
    let (attempt, rest) ← readNatBE 8 rest
    let (acknowledgmentReference, rest) ← readOptionalStringReuse rest
    let (updatedAtMs, rest) ← readNatBE 8 rest
    let outbox : CorrectionOutboxDelta := {
      actionId := actionId
      status := status
      attempt := attempt
      acknowledgmentReference := acknowledgmentReference
      updatedAtMs := updatedAtMs }
    pure (some outbox, rest)
  else none

private def reuseRequestWellFormed (request : CorrectionReuseRequest) : Bool :=
  financialInputWellFormed request.currentInput &&
  evaluationReceiptWellFormed request.currentReceipt &&
  correctionQueryObservationsWellFormed request.currentQueries &&
  request.currentEventSequence ≤ maxRows && timeWellFormed request.currentOwnerNowMs &&
  digestWellFormed request.currentHistoryHead &&
  (match request.currentDetermination with
    | none => true
    | some determination =>
        idWellFormed determination.determinationId && idWellFormed determination.obligationId &&
        idWellFormed determination.claimId && idWellFormed determination.actorId &&
        roleWellFormed determination.actorRole && digestWellFormed determination.authorityDigest) &&
  (match request.currentOutbox with
    | none => true
    | some outbox => idWellFormed outbox.actionId && outbox.attempt ≤ maxRows &&
        timeWellFormed outbox.updatedAtMs)

def encodeCorrectionReuseRequest (request : CorrectionReuseRequest) : Option Bytes := do
  if !reuseRequestWellFormed request then none
  let acceptedBytes ← encodeCorrectionTransitionResult request.acceptedResult
  let inputBytes ← encodeFinancialInput request.currentInput
  let receiptBytes := encodeEvaluationReceipt request.currentReceipt
  let body := correctionReuseInputMagic ++ natBE 2 1 ++ encodeString correctionReuseContract ++
    reuseSizedBytes acceptedBytes ++ reuseSizedBytes inputBytes ++ reuseSizedBytes receiptBytes ++
    encodeOptionDetermination request.currentDetermination ++
    encodeOptionOutbox request.currentOutbox ++
    encodeCorrectionQueryObservations request.currentQueries ++
    natBE 8 request.currentEventSequence ++ encodeDigest request.currentHistoryHead ++
    natBE 8 request.currentOwnerNowMs
  if body.length ≤ maxCorrectionReuseBytes then some body else none

def decodeCorrectionReuseRequest (bytes : Bytes) : Option CorrectionReuseRequest := do
  if bytes.length > maxCorrectionReuseBytes || !correctionReuseInputMagic.isPrefixOf bytes then none
  let rest := bytes.drop correctionReuseInputMagic.length
  let (version, rest) ← readNatBE 2 rest
  if version ≠ 1 then none
  let (contract, rest) ← readString rest
  if contract ≠ correctionReuseContract then none
  let (acceptedBytes, rest) ← readReuseSizedBytes maxCorrectionTransitionBytes rest
  let acceptedResult ← decodeCorrectionTransitionResult acceptedBytes
  let (inputBytes, rest) ← readReuseSizedBytes maxCorrectionTransitionBytes rest
  let currentInput ← decodeFinancialInput inputBytes
  let (receiptBytes, rest) ← readReuseSizedBytes maxCorrectionTransitionBytes rest
  let (currentReceipt, receiptRest) ← readEvaluationReceipt receiptBytes
  if !receiptRest.isEmpty then none
  let (currentDetermination, rest) ← readOptionDetermination rest
  let (currentOutbox, rest) ← readOptionOutbox rest
  let (currentQueries, rest) ← readCorrectionQueryObservations rest
  let (currentEventSequence, rest) ← readNatBE 8 rest
  let (currentHistoryHead, rest) ← readDigest rest
  let (currentOwnerNowMs, rest) ← readNatBE 8 rest
  if !rest.isEmpty then none
  let request : CorrectionReuseRequest := {
    acceptedResult := acceptedResult
    currentInput := currentInput
    currentReceipt := currentReceipt
    currentDetermination := currentDetermination
    currentOutbox := currentOutbox
    currentQueries := currentQueries
    currentEventSequence := currentEventSequence
    currentHistoryHead := currentHistoryHead
    currentOwnerNowMs := currentOwnerNowMs }
  if !reuseRequestWellFormed request then none
  match encodeCorrectionReuseRequest request with
  | some canonical => if canonical = bytes then some request else none
  | none => none

private def encodeCalculationValidity : CorrectionCalculationValidity → UInt8
  | .VALID => UInt8.ofNat 1
  | .INVALID => UInt8.ofNat 2

private def readCalculationValidity (bytes : Bytes) : Option (CorrectionCalculationValidity × Bytes) := do
  let (tag, rest) ← readByte bytes
  let value ← match tag.toNat with
    | 1 => some .VALID
    | 2 => some .INVALID
    | _ => none
  pure (value, rest)

private def encodeCalculationReason : CorrectionCalculationReason → UInt8
  | .ACCEPTED_TRANSITION_REQUIRED => UInt8.ofNat 1
  | .QUERY_OBSERVATION_INVALID => UInt8.ofNat 2
  | .RELEVANT_FINANCIAL_FACT_CHANGED => UInt8.ofNat 3
  | .EVIDENCE_BINDING_CHANGED => UInt8.ofNat 4
  | .CURRENT_RECEIPT_INVALID => UInt8.ofNat 5
  | .CURRENT_RESULT_CHANGED => UInt8.ofNat 6

private def readCalculationReason (bytes : Bytes) : Option (CorrectionCalculationReason × Bytes) := do
  let (tag, rest) ← readByte bytes
  let value ← match tag.toNat with
    | 1 => some .ACCEPTED_TRANSITION_REQUIRED
    | 2 => some .QUERY_OBSERVATION_INVALID
    | 3 => some .RELEVANT_FINANCIAL_FACT_CHANGED
    | 4 => some .EVIDENCE_BINDING_CHANGED
    | 5 => some .CURRENT_RECEIPT_INVALID
    | 6 => some .CURRENT_RESULT_CHANGED
    | _ => none
  pure (value, rest)

private def encodeHumanApprovalValidity : CorrectionApprovalValidity → UInt8
  | .VALID => UInt8.ofNat 1
  | .INVALID => UInt8.ofNat 2

private def readHumanApprovalValidity (bytes : Bytes) : Option (CorrectionApprovalValidity × Bytes) := do
  let (tag, rest) ← readByte bytes
  let value ← match tag.toNat with
    | 1 => some .VALID
    | 2 => some .INVALID
    | _ => none
  pure (value, rest)

private def encodeApprovalReason : CorrectionApprovalReason → UInt8
  | .ACCEPTED_TRANSITION_REQUIRED => UInt8.ofNat 1
  | .DETERMINATION_MISSING => UInt8.ofNat 2
  | .DETERMINATION_CHANGED => UInt8.ofNat 3

private def readApprovalReason (bytes : Bytes) : Option (CorrectionApprovalReason × Bytes) := do
  let (tag, rest) ← readByte bytes
  let value ← match tag.toNat with
    | 1 => some .ACCEPTED_TRANSITION_REQUIRED
    | 2 => some .DETERMINATION_MISSING
    | 3 => some .DETERMINATION_CHANGED
    | _ => none
  pure (value, rest)

private def encodeExecutionPermission : CorrectionExecutionPermission → UInt8
  | .ALLOWED => UInt8.ofNat 1
  | .DENIED => UInt8.ofNat 2

private def readExecutionPermission (bytes : Bytes) : Option (CorrectionExecutionPermission × Bytes) := do
  let (tag, rest) ← readByte bytes
  let value ← match tag.toNat with
    | 1 => some .ALLOWED
    | 2 => some .DENIED
    | _ => none
  pure (value, rest)

private def encodeExecutionDenial : CorrectionExecutionDenial → UInt8
  | .CALCULATION_INVALID => UInt8.ofNat 1
  | .HUMAN_APPROVAL_INVALID => UInt8.ofNat 2
  | .SHADOW_MODE => UInt8.ofNat 3
  | .AUTHORITY_STALE => UInt8.ofNat 4
  | .ACTOR_NOT_AUTHORIZED => UInt8.ofNat 5
  | .CONTROL_PACK_NOT_APPROVED => UInt8.ofNat 6
  | .ACTION_MISSING => UInt8.ofNat 7
  | .ACTION_CHANGED => UInt8.ofNat 8
  | .ACTION_NOT_READY => UInt8.ofNat 9
  | .OUTBOX_MISSING => UInt8.ofNat 10
  | .OUTBOX_CHANGED => UInt8.ofNat 11
  | .OUTBOX_NOT_READY => UInt8.ofNat 12

private def readExecutionDenial (bytes : Bytes) : Option (CorrectionExecutionDenial × Bytes) := do
  let (tag, rest) ← readByte bytes
  let value ← match tag.toNat with
    | 1 => some .CALCULATION_INVALID
    | 2 => some .HUMAN_APPROVAL_INVALID
    | 3 => some .SHADOW_MODE
    | 4 => some .AUTHORITY_STALE
    | 5 => some .ACTOR_NOT_AUTHORIZED
    | 6 => some .CONTROL_PACK_NOT_APPROVED
    | 7 => some .ACTION_MISSING
    | 8 => some .ACTION_CHANGED
    | 9 => some .ACTION_NOT_READY
    | 10 => some .OUTBOX_MISSING
    | 11 => some .OUTBOX_CHANGED
    | 12 => some .OUTBOX_NOT_READY
    | _ => none
  pure (value, rest)

private def encodeDeadlineStatus : Option CorrectionDeadlineStatus → Bytes
  | none => [UInt8.ofNat 0]
  | some .BEFORE_DEADLINE => [UInt8.ofNat 1]
  | some .DEADLINE_REACHED => [UInt8.ofNat 2]

private def readDeadlineStatus (bytes : Bytes) : Option (Option CorrectionDeadlineStatus × Bytes) := do
  let (tag, rest) ← readByte bytes
  let value ← match tag.toNat with
    | 0 => some none
    | 1 => some (some .BEFORE_DEADLINE)
    | 2 => some (some .DEADLINE_REACHED)
    | _ => none
  pure (value, rest)

private def encodeOptionCalculationReason : Option CorrectionCalculationReason → Bytes
  | none => [UInt8.ofNat 0]
  | some reason => [UInt8.ofNat 1, encodeCalculationReason reason]

private def readOptionCalculationReason
    (bytes : Bytes) : Option (Option CorrectionCalculationReason × Bytes) := do
  let (tag, rest) ← readByte bytes
  if tag.toNat = 0 then some (none, rest)
  else if tag.toNat = 1 then do
    let (reason, tail) ← readCalculationReason rest
    pure (some reason, tail)
  else none

private def encodeOptionApprovalReason : Option CorrectionApprovalReason → Bytes
  | none => [UInt8.ofNat 0]
  | some reason => [UInt8.ofNat 1, encodeApprovalReason reason]

private def readOptionApprovalReason
    (bytes : Bytes) : Option (Option CorrectionApprovalReason × Bytes) := do
  let (tag, rest) ← readByte bytes
  if tag.toNat = 0 then some (none, rest)
  else if tag.toNat = 1 then do
    let (reason, tail) ← readApprovalReason rest
    pure (some reason, tail)
  else none

private def encodeOptionExecutionDenial : Option CorrectionExecutionDenial → Bytes
  | none => [UInt8.ofNat 0]
  | some reason => [UInt8.ofNat 1, encodeExecutionDenial reason]

private def readOptionExecutionDenial
    (bytes : Bytes) : Option (Option CorrectionExecutionDenial × Bytes) := do
  let (tag, rest) ← readByte bytes
  if tag.toNat = 0 then some (none, rest)
  else if tag.toNat = 1 then do
    let (reason, tail) ← readExecutionDenial rest
    pure (some reason, tail)
  else none

private def assessmentWellFormed (assessment : CorrectionReuseAssessment) : Bool :=
  (match assessment.calculationValidity, assessment.calculationReason with
    | .VALID, none | .INVALID, some _ => true
    | _, _ => false) &&
  (match assessment.humanApprovalValidity, assessment.humanApprovalReason with
    | .VALID, none | .INVALID, some _ => true
    | _, _ => false) &&
  (match assessment.localExecutionPermission, assessment.executionDenial with
    | .ALLOWED, none | .DENIED, some _ => true
    | _, _ => false) &&
  (assessment.localExecutionPermission = .DENIED ||
    (assessment.calculationValidity = .VALID &&
      assessment.humanApprovalValidity = .VALID)) &&
  (!assessment.unrelatedWatermarkAdvanced ||
    (assessment.calculationValidity = .VALID &&
      assessment.humanApprovalValidity = .VALID &&
      assessment.localExecutionPermission = .ALLOWED)) &&
  !assessment.externalDispatchPermitted

def encodeCorrectionReuseAssessment (assessment : CorrectionReuseAssessment) : Option Bytes := do
  if !assessmentWellFormed assessment then none
  let body := correctionReuseResultMagic ++ natBE 2 1 ++ encodeString correctionReuseContract ++
    [encodeCalculationValidity assessment.calculationValidity] ++
    encodeOptionCalculationReason assessment.calculationReason ++
    [encodeHumanApprovalValidity assessment.humanApprovalValidity] ++
    encodeOptionApprovalReason assessment.humanApprovalReason ++
    [encodeExecutionPermission assessment.localExecutionPermission] ++
    encodeOptionExecutionDenial assessment.executionDenial ++
    encodeDeadlineStatus assessment.deadlineStatus ++
    encodeBool assessment.unrelatedWatermarkAdvanced ++
    encodeBool assessment.externalDispatchPermitted
  if body.length ≤ maxCorrectionReuseBytes then some body else none

def decodeCorrectionReuseAssessment (bytes : Bytes) : Option CorrectionReuseAssessment := do
  if bytes.length > maxCorrectionReuseBytes || !correctionReuseResultMagic.isPrefixOf bytes then none
  let rest := bytes.drop correctionReuseResultMagic.length
  let (version, rest) ← readNatBE 2 rest
  if version ≠ 1 then none
  let (contract, rest) ← readString rest
  if contract ≠ correctionReuseContract then none
  let (calculationValidity, rest) ← readCalculationValidity rest
  let (calculationReason, rest) ← readOptionCalculationReason rest
  let (humanApprovalValidity, rest) ← readHumanApprovalValidity rest
  let (humanApprovalReason, rest) ← readOptionApprovalReason rest
  let (localExecutionPermission, rest) ← readExecutionPermission rest
  let (executionDenial, rest) ← readOptionExecutionDenial rest
  let (deadlineStatus, rest) ← readDeadlineStatus rest
  let (unrelatedWatermarkAdvanced, rest) ← readBool rest
  let (externalDispatchPermitted, rest) ← readBool rest
  if !rest.isEmpty then none
  let assessment : CorrectionReuseAssessment := {
    calculationValidity := calculationValidity
    calculationReason := calculationReason
    humanApprovalValidity := humanApprovalValidity
    humanApprovalReason := humanApprovalReason
    localExecutionPermission := localExecutionPermission
    executionDenial := executionDenial
    deadlineStatus := deadlineStatus
    unrelatedWatermarkAdvanced := unrelatedWatermarkAdvanced
    externalDispatchPermitted := externalDispatchPermitted }
  if !assessmentWellFormed assessment then none
  match encodeCorrectionReuseAssessment assessment with
  | some canonical =>
      if canonical = bytes then some assessment else none
  | none => none

end BlindLedger.Financial.CorrectionTransition
