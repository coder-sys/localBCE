import BlindLedger.Financial.Codec
import BlindLedger.Financial.DecisionPackage.Codec
import BlindLedger.Financial.CorrectionTransition.Types

namespace BlindLedger.Financial.CorrectionTransition

open BlindLedger.Financial
open BlindLedger.Financial.DecisionPackage

def encodeSizedBytes (value : Bytes) : Bytes := natBE 4 value.length ++ value

def readSizedBytes (maximum : Nat) (bytes : Bytes) : Option (Bytes × Bytes) := do
  let (length, rest) ← readNatBE 4 bytes
  if length > maximum || length > rest.length then none
  else some (rest.take length, rest.drop length)

def encodeActionLookup : ActionIdentityLookup → Bytes
  | .absent => [UInt8.ofNat 1]
  | .existing identity =>
      [UInt8.ofNat 2] ++ encodeString identity.actionId ++
        encodeString identity.actionObligationId ++ encodeString identity.determinationId ++
        encodeString identity.determinationObligationId ++ encodeString identity.actionKind ++
        encodeString identity.claimId ++ encodeString identity.actorId ++
        encodeString identity.actorRole ++ encodeString identity.authorityId ++
        natBE 8 identity.authorityEpoch ++ encodeDigest identity.authorityDigest ++
        [encodeDecision identity.decision] ++ encodeString identity.inputEvaluationId ++
        encodeDigest identity.inputEvaluationResultDigest ++ natBE 8 identity.expectedRevision ++
        natBE 8 identity.decidedAtMs
  | .conflicting => [UInt8.ofNat 3]

def readActionLookup (bytes : Bytes) : Option (ActionIdentityLookup × Bytes) := do
  let (tag, rest) ← readByte bytes
  if tag.toNat = 1 then some (.absent, rest)
  else if tag.toNat = 3 then some (.conflicting, rest)
  else if tag.toNat = 2 then do
    let (actionId, rest) ← readString rest
    let (actionObligationId, rest) ← readString rest
    let (determinationId, rest) ← readString rest
    let (determinationObligationId, rest) ← readString rest
    let (actionKind, rest) ← readString rest
    let (claimId, rest) ← readString rest
    let (actorId, rest) ← readString rest
    let (actorRole, rest) ← readString rest
    let (authorityId, rest) ← readString rest
    let (authorityEpoch, rest) ← readNatBE 8 rest
    let (authorityDigest, rest) ← readDigest rest
    let (decisionByte, rest) ← readByte rest
    let decision ← decodeDecision decisionByte
    let (inputEvaluationId, rest) ← readString rest
    let (inputEvaluationResultDigest, rest) ← readDigest rest
    let (expectedRevision, rest) ← readNatBE 8 rest
    let (decidedAtMs, rest) ← readNatBE 8 rest
    let identity : ExistingCorrectionIdentity := {
      actionId := actionId
      actionObligationId := actionObligationId
      determinationId := determinationId
      determinationObligationId := determinationObligationId
      actionKind := actionKind
      claimId := claimId
      actorId := actorId
      actorRole := actorRole
      authorityId := authorityId
      authorityEpoch := authorityEpoch
      authorityDigest := authorityDigest
      decision := decision
      inputEvaluationId := inputEvaluationId
      inputEvaluationResultDigest := inputEvaluationResultDigest
      expectedRevision := expectedRevision
      decidedAtMs := decidedAtMs }
    pure (.existing identity, rest)
  else none

def actionLookupWellFormed : ActionIdentityLookup → Bool
  | .absent | .conflicting => true
  | .existing identity =>
      [identity.actionId, identity.actionObligationId, identity.determinationId,
        identity.determinationObligationId, identity.actionKind, identity.claimId,
        identity.actorId, identity.authorityId, identity.inputEvaluationId].all idWellFormed &&
      roleWellFormed identity.actorRole && identity.authorityEpoch ≥ 1 &&
      identity.authorityEpoch ≤ maxAuthorityEpoch && digestWellFormed identity.authorityDigest &&
      digestWellFormed identity.inputEvaluationResultDigest &&
      revisionWellFormed identity.expectedRevision && timeWellFormed identity.decidedAtMs

def encodeQueryPredicate : CorrectionQueryPredicate → UInt8
  | .ACTION_ID => UInt8.ofNat 1
  | .DETERMINATION_ID => UInt8.ofNat 2
  | .EVALUATION_CONSUMED => UInt8.ofNat 3

def readQueryPredicate (bytes : Bytes) : Option (CorrectionQueryPredicate × Bytes) := do
  let (tag, rest) ← readByte bytes
  let predicate ← match tag.toNat with
    | 1 => some .ACTION_ID
    | 2 => some .DETERMINATION_ID
    | 3 => some .EVALUATION_CONSUMED
    | _ => none
  pure (predicate, rest)

def encodeQueryObservation (observation : CorrectionQueryObservation) : Bytes :=
  [encodeQueryPredicate observation.predicate] ++ encodeString observation.subject ++
    encodeBool observation.complete ++ natBE 8 observation.matchCount ++
    encodeOptionString observation.resultIdentity ++ natBE 8 observation.versionSequence ++
    encodeDigest observation.versionHead

def readQueryObservation (bytes : Bytes) : Option (CorrectionQueryObservation × Bytes) := do
  let (predicate, rest) ← readQueryPredicate bytes
  let (subject, rest) ← readString rest
  let (complete, rest) ← readBool rest
  let (matchCount, rest) ← readNatBE 8 rest
  let (resultIdentity, rest) ← readOptionString rest
  let (versionSequence, rest) ← readNatBE 8 rest
  let (versionHead, rest) ← readDigest rest
  let observation : CorrectionQueryObservation := {
    predicate := predicate
    subject := subject
    complete := complete
    matchCount := matchCount
    resultIdentity := resultIdentity
    versionSequence := versionSequence
    versionHead := versionHead }
  if !correctionQueryObservationWellFormed observation then none
  else some (observation, rest)

def encodeQueryObservations (observations : CorrectionQueryObservations) : Bytes :=
  encodeQueryObservation observations.actionId ++
    encodeQueryObservation observations.determinationId ++
    encodeQueryObservation observations.evaluationConsumed

def readQueryObservations (bytes : Bytes) : Option (CorrectionQueryObservations × Bytes) := do
  let (actionId, rest) ← readQueryObservation bytes
  let (determinationId, rest) ← readQueryObservation rest
  let (evaluationConsumed, rest) ← readQueryObservation rest
  pure ({
    actionId := actionId
    determinationId := determinationId
    evaluationConsumed := evaluationConsumed }, rest)

def encodeCorrectionQueryObservations (observations : CorrectionQueryObservations) : Bytes :=
  encodeQueryObservations observations

def readCorrectionQueryObservations
    (bytes : Bytes) : Option (CorrectionQueryObservations × Bytes) :=
  readQueryObservations bytes

def decodeCorrectionQueryObservations (bytes : Bytes) : Option CorrectionQueryObservations := do
  let (observations, rest) ← readQueryObservations bytes
  if rest.isEmpty && correctionQueryObservationsWellFormed observations
    then some observations else none

def encodeCorrectionPaid (entry : CorrectionPaid) : Bytes :=
  encodeString entry.actionId ++ natBE 8 entry.paidCents

def readCorrectionPaid (bytes : Bytes) : Option (CorrectionPaid × Bytes) := do
  let (actionId, rest) ← readString bytes
  let (paidCents, rest) ← readNatBE 8 rest
  pure ({ actionId := actionId, paidCents := paidCents }, rest)

def commandWellFormed (command : CorrectionCommand) : Bool :=
  [command.itemId, command.claimId, command.actionId, command.actorId,
    command.currentAuthorityId, command.evaluationId].all idWellFormed &&
  roleWellFormed command.actorRole &&
  command.currentAuthorityEpoch ≥ 1 && command.currentAuthorityEpoch ≤ maxAuthorityEpoch &&
  digestWellFormed command.currentAuthorityDigest && revisionWellFormed command.expectedRevision &&
  digestWellFormed command.evaluationResultDigest && timeWellFormed command.decisionAtMs &&
  timeWellFormed command.ownerNowMs && actionLookupWellFormed command.actionLookup &&
  correctionQueryObservationsWellFormed command.queryObservations &&
  command.currentEventSequence ≤ maxRows && digestWellFormed command.previousHistoryHead &&
  paymentLinksWellFormed command.paymentLinks

def encodeInputBody (request : CorrectionTransitionRequest) : Option Bytes := do
  if !commandWellFormed request.command ||
      !financialInputWellFormed request.currentInput ||
      !evaluationReceiptWellFormed request.currentReceipt then
    none
  let inputBytes ← encodeFinancialInput request.currentInput
  let receiptBytes := encodeEvaluationReceipt request.currentReceipt
  pure (correctionTransitionInputMagic ++ natBE 2 3 ++
    encodeString correctionTransitionContract ++
    encodeString request.command.itemId ++ encodeString request.command.claimId ++
    encodeString request.command.actionId ++ encodeString request.command.actorId ++
    encodeString request.command.actorRole ++ encodeString request.command.currentAuthorityId ++
    natBE 8 request.command.currentAuthorityEpoch ++ encodeDigest request.command.currentAuthorityDigest ++
    natBE 8 request.command.expectedRevision ++ encodeString request.command.evaluationId ++
    encodeDigest request.command.evaluationResultDigest ++ natBE 8 request.command.decisionAtMs ++
    natBE 8 request.command.ownerNowMs ++ encodeActionLookup request.command.actionLookup ++
    encodeQueryObservations request.command.queryObservations ++
    natBE 8 request.command.currentEventSequence ++
    encodeDigest request.command.previousHistoryHead ++
    encodeList encodePaymentLink request.command.paymentLinks ++ encodeSizedBytes inputBytes ++
    encodeSizedBytes receiptBytes)

def encodeCorrectionTransitionRequest (request : CorrectionTransitionRequest) : Option Bytes := do
  let body ← encodeInputBody request
  if body.length > maxCorrectionTransitionBytes then none else pure body

/-- Reads one BLFCMD03 request and returns the unread bytes.  The decoder below
    accepts only an empty remainder and the canonical re-encoding. -/
def parseCorrectionTransitionRequest (bytes : Bytes) :
    Option (CorrectionTransitionRequest × Bytes) := do
  if !correctionTransitionInputMagic.isPrefixOf bytes then none
  let rest := bytes.drop correctionTransitionInputMagic.length
  let (version, rest) ← readNatBE 2 rest
  if version ≠ 3 then none
  let (contract, rest) ← readString rest
  if contract ≠ correctionTransitionContract then none
  let (itemId, rest) ← readString rest
  let (claimId, rest) ← readString rest
  let (actionId, rest) ← readString rest
  let (actorId, rest) ← readString rest
  let (actorRole, rest) ← readString rest
  let (currentAuthorityId, rest) ← readString rest
  let (currentAuthorityEpoch, rest) ← readNatBE 8 rest
  let (currentAuthorityDigest, rest) ← readDigest rest
  let (expectedRevision, rest) ← readNatBE 8 rest
  let (evaluationId, rest) ← readString rest
  let (evaluationResultDigest, rest) ← readDigest rest
  let (decisionAtMs, rest) ← readNatBE 8 rest
  let (ownerNowMs, rest) ← readNatBE 8 rest
  let (actionLookup, rest) ← readActionLookup rest
  let (queryObservations, rest) ← readQueryObservations rest
  let (currentEventSequence, rest) ← readNatBE 8 rest
  let (previousHistoryHead, rest) ← readDigest rest
  let (paymentLinks, rest) ← readList readPaymentLink rest
  let (inputBytes, rest) ← readSizedBytes maxCorrectionTransitionBytes rest
  let (receiptBytes, rest) ← readSizedBytes maxCorrectionTransitionBytes rest
  let currentInput ← decodeFinancialInput inputBytes
  let (currentReceipt, receiptRest) ← readEvaluationReceipt receiptBytes
  if !receiptRest.isEmpty then none
  let request : CorrectionTransitionRequest := {
    command := {
      itemId := itemId
      claimId := claimId
      actionId := actionId
      actorId := actorId
      actorRole := actorRole
      currentAuthorityId := currentAuthorityId
      currentAuthorityEpoch := currentAuthorityEpoch
      currentAuthorityDigest := currentAuthorityDigest
      expectedRevision := expectedRevision
      evaluationId := evaluationId
      evaluationResultDigest := evaluationResultDigest
      decisionAtMs := decisionAtMs
      ownerNowMs := ownerNowMs
      actionLookup := actionLookup
      queryObservations := queryObservations
      currentEventSequence := currentEventSequence
      previousHistoryHead := previousHistoryHead
      paymentLinks := paymentLinks }
    currentInput := currentInput
    currentReceipt := currentReceipt }
  pure (request, rest)

/-- Well-formedness is enforced by the canonical re-encoding: the encoder
    refuses every request the transition would treat as malformed. -/
def decodeCorrectionTransitionRequest (bytes : Bytes) : Option CorrectionTransitionRequest :=
  if bytes.length > maxCorrectionTransitionBytes then none else
  match parseCorrectionTransitionRequest bytes with
  | some (request, []) =>
      if encodeCorrectionTransitionRequest request = some bytes then some request else none
  | _ => none

def encodeRejectReason : TransitionRejectReason → UInt8
  | .INVALID_REQUEST => UInt8.ofNat 1
  | .INVALID_INPUT => UInt8.ofNat 2
  | .SHADOW_READ_ONLY => UInt8.ofNat 3
  | .SCOPE_MISMATCH => UInt8.ofNat 4
  | .AUTHORITY_STALE => UInt8.ofNat 5
  | .ACTOR_UNAUTHORIZED => UInt8.ofNat 6
  | .CONTROL_PACK_REJECTED => UInt8.ofNat 7
  | .REVISION_CONFLICT => UInt8.ofNat 8
  | .EVALUATION_CONFLICT => UInt8.ofNat 9
  | .EVALUATION_CONSUMED => UInt8.ofNat 10
  | .EVIDENCE_COVERAGE => UInt8.ofNat 11
  | .CLAIM_MISSING => UInt8.ofNat 12
  | .CLAIM_NOT_CLAIMED => UInt8.ofNat 13
  | .ACTION_CONFLICT => UInt8.ofNat 14
  | .DETERMINATION_CONFLICT => UInt8.ofNat 15
  | .CHRONOLOGY => UInt8.ofNat 16
  | .CAPACITY => UInt8.ofNat 17
  | .QUERY_OBSERVATION_INVALID => UInt8.ofNat 18
  | .INPUT_SNAPSHOT_MISSING => UInt8.ofNat 19
  | .NO_SHORTFALL => UInt8.ofNat 20
  | .NO_REQUESTABLE_BALANCE => UInt8.ofNat 21
  | .DECISION_BACKDATED_PAST_DUE => UInt8.ofNat 22

def decodeRejectReason (byte : UInt8) : Option TransitionRejectReason :=
  match byte.toNat with
  | 1 => some .INVALID_REQUEST
  | 2 => some .INVALID_INPUT
  | 3 => some .SHADOW_READ_ONLY
  | 4 => some .SCOPE_MISMATCH
  | 5 => some .AUTHORITY_STALE
  | 6 => some .ACTOR_UNAUTHORIZED
  | 7 => some .CONTROL_PACK_REJECTED
  | 8 => some .REVISION_CONFLICT
  | 9 => some .EVALUATION_CONFLICT
  | 10 => some .EVALUATION_CONSUMED
  | 11 => some .EVIDENCE_COVERAGE
  | 12 => some .CLAIM_MISSING
  | 13 => some .CLAIM_NOT_CLAIMED
  | 14 => some .ACTION_CONFLICT
  | 15 => some .DETERMINATION_CONFLICT
  | 16 => some .CHRONOLOGY
  | 17 => some .CAPACITY
  | 18 => some .QUERY_OBSERVATION_INVALID
  | 19 => some .INPUT_SNAPSHOT_MISSING
  | 20 => some .NO_SHORTFALL
  | 21 => some .NO_REQUESTABLE_BALANCE
  | 22 => some .DECISION_BACKDATED_PAST_DUE
  | _ => none

def encodeOptionalRejectReason : Option TransitionRejectReason → Bytes
  | none => [UInt8.ofNat 0]
  | some reason => [UInt8.ofNat 1, encodeRejectReason reason]

def readOptionalRejectReason (bytes : Bytes) : Option (Option TransitionRejectReason × Bytes) := do
  let (tag, rest) ← readByte bytes
  if tag.toNat = 0 then some (none, rest)
  else if tag.toNat = 1 then do
    let (reasonByte, tail) ← readByte rest
    let reason ← decodeRejectReason reasonByte
    pure (some reason, tail)
  else none

def encodeTransitionKind : TransitionKind → UInt8
  | .OFFSET_REJECTED_CORRECTION_AUTHORIZED => UInt8.ofNat 1
  | .OFFSET_AUTHORIZED => UInt8.ofNat 2

def readTransitionKind (bytes : Bytes) : Option (TransitionKind × Bytes) := do
  let (tag, rest) ← readByte bytes
  match tag.toNat with
  | 1 => some (.OFFSET_REJECTED_CORRECTION_AUTHORIZED, rest)
  | 2 => some (.OFFSET_AUTHORIZED, rest)
  | _ => none

def encodeExplanationCode : ExplanationCode → UInt8
  | .CORRECTION_AUTHORIZED => UInt8.ofNat 1
  | .EXACT_RETRY => UInt8.ofNat 2
  | .REJECTED => UInt8.ofNat 3
  | .OFFSET_AUTHORIZED => UInt8.ofNat 4

def readExplanationCode (bytes : Bytes) : Option (ExplanationCode × Bytes) := do
  let (tag, rest) ← readByte bytes
  match tag.toNat with
  | 1 => some (.CORRECTION_AUTHORIZED, rest)
  | 2 => some (.EXACT_RETRY, rest)
  | 3 => some (.REJECTED, rest)
  | 4 => some (.OFFSET_AUTHORIZED, rest)
  | _ => none

def encodeCorrectionEffect : CorrectionEffect → UInt8
  | .DETERMINATION_RECORDED => UInt8.ofNat 1
  | .CLAIM_REJECTED => UInt8.ofNat 2
  | .CASE_UPSERTED => UInt8.ofNat 3
  | .ACTION_CREATED => UInt8.ofNat 4
  | .OUTBOX_CREATED => UInt8.ofNat 5
  | .PROJECTION_RECOMPUTED => UInt8.ofNat 6
  | .EVENT_APPENDED => UInt8.ofNat 7
  | .CLAIM_AUTHORIZED => UInt8.ofNat 8

def readCorrectionEffect (bytes : Bytes) : Option (CorrectionEffect × Bytes) := do
  let (tag, rest) ← readByte bytes
  let effect ← match tag.toNat with
    | 1 => some .DETERMINATION_RECORDED
    | 2 => some .CLAIM_REJECTED
    | 3 => some .CASE_UPSERTED
    | 4 => some .ACTION_CREATED
    | 5 => some .OUTBOX_CREATED
    | 6 => some .PROJECTION_RECOMPUTED
    | 7 => some .EVENT_APPENDED
    | 8 => some .CLAIM_AUTHORIZED
    | _ => none
  pure (effect, rest)

def encodeTransitionRequirement : TransitionRequirement → UInt8
  | .VALID_COMMAND => UInt8.ofNat 1
  | .WELL_FORMED_FINANCIAL_SNAPSHOT => UInt8.ofNat 2
  | .ACTIONABLE_OWNER_MODE => UInt8.ofNat 3
  | .REQUEST_SCOPE_MATCH => UInt8.ofNat 4
  | .CURRENT_AUTHORITY_MATCH => UInt8.ofNat 5
  | .AUTHORIZED_ACTOR_ROLE => UInt8.ofNat 6
  | .APPROVED_CONTROL_PACK => UInt8.ofNat 7
  | .CURRENT_REVISION_MATCH => UInt8.ofNat 8
  | .CURRENT_EVALUATION_BINDING => UInt8.ofNat 9
  | .UNIQUE_EVALUATION_USE => UInt8.ofNat 10
  | .CLAIM_EVIDENCE_COVERAGE => UInt8.ofNat 11
  | .CLAIM_EXISTS_IN_SCOPE => UInt8.ofNat 12
  | .CLAIM_IS_CLAIMED => UInt8.ofNat 13
  | .ACTION_IDENTITY_MATCH => UInt8.ofNat 14
  | .DETERMINATION_ID_AVAILABLE => UInt8.ofNat 15
  | .RECEIPT_PRECEDES_DECISION => UInt8.ofNat 16
  | .HISTORY_CAPACITY_AVAILABLE => UInt8.ofNat 17
  | .COMPLETE_QUERY_OBSERVATIONS => UInt8.ofNat 18
  | .INPUT_SNAPSHOT_DIGEST_AVAILABLE => UInt8.ofNat 19
  | .POSITIVE_SHORTFALL => UInt8.ofNat 20
  | .UNREQUESTED_SHORTFALL => UInt8.ofNat 21
  | .DECISION_NOT_BACKDATED_PAST_DUE => UInt8.ofNat 22

def readTransitionRequirement (bytes : Bytes) : Option (TransitionRequirement × Bytes) := do
  let (tag, rest) ← readByte bytes
  let requirement ← match tag.toNat with
    | 1 => some .VALID_COMMAND
    | 2 => some .WELL_FORMED_FINANCIAL_SNAPSHOT
    | 3 => some .ACTIONABLE_OWNER_MODE
    | 4 => some .REQUEST_SCOPE_MATCH
    | 5 => some .CURRENT_AUTHORITY_MATCH
    | 6 => some .AUTHORIZED_ACTOR_ROLE
    | 7 => some .APPROVED_CONTROL_PACK
    | 8 => some .CURRENT_REVISION_MATCH
    | 9 => some .CURRENT_EVALUATION_BINDING
    | 10 => some .UNIQUE_EVALUATION_USE
    | 11 => some .CLAIM_EVIDENCE_COVERAGE
    | 12 => some .CLAIM_EXISTS_IN_SCOPE
    | 13 => some .CLAIM_IS_CLAIMED
    | 14 => some .ACTION_IDENTITY_MATCH
    | 15 => some .DETERMINATION_ID_AVAILABLE
    | 16 => some .RECEIPT_PRECEDES_DECISION
    | 17 => some .HISTORY_CAPACITY_AVAILABLE
    | 18 => some .COMPLETE_QUERY_OBSERVATIONS
    | 19 => some .INPUT_SNAPSHOT_DIGEST_AVAILABLE
    | 20 => some .POSITIVE_SHORTFALL
    | 21 => some .UNREQUESTED_SHORTFALL
    | 22 => some .DECISION_NOT_BACKDATED_PAST_DUE
    | _ => none
  pure (requirement, rest)

def encodeOptionalRequirement : Option TransitionRequirement → Bytes
  | none => [UInt8.ofNat 0]
  | some requirement => [UInt8.ofNat 1, encodeTransitionRequirement requirement]

def readOptionalRequirement (bytes : Bytes) : Option (Option TransitionRequirement × Bytes) := do
  let (tag, rest) ← readByte bytes
  if tag.toNat = 0 then some (none, rest)
  else if tag.toNat = 1 then do
    let (requirement, tail) ← readTransitionRequirement rest
    pure (some requirement, tail)
  else none

def encodeDependencyFacts (facts : CorrectionDependencyFacts) : Bytes :=
  encodeString facts.artifactContract ++ natBE 8 facts.artifactVersion ++
    encodeString facts.authorityId ++ natBE 8 facts.authorityEpoch ++
    encodeDigest facts.authorityDigest ++ encodeString facts.controlPackId ++
    natBE 8 facts.controlPackVersion ++ encodeDigest facts.controlPackDigest ++
    encodeString facts.inputEvaluationId ++ encodeDigest facts.inputEvaluationResultDigest ++
    natBE 8 facts.inputEvaluationRevision ++ natBE 8 facts.inputEvaluationEvaluatedAtMs ++
    encodeDigest facts.inputEvaluationSnapshotDigest ++ natBE 8 facts.inputShortfallCents ++
    natBE 8 facts.decisionAtMs ++
    natBE 8 facts.ownerNowMs ++ encodeClaim facts.claimBefore ++
    encodeList encodeEvidenceBinding facts.supportingEvidence ++
    encodeQueryObservations facts.queryObservations ++
    natBE 8 facts.currentEventSequence ++
    encodeDigest facts.previousHistoryHead ++ encodeList encodeCorrectionPaid facts.correctionPaid

def readDependencyFacts (bytes : Bytes) : Option (CorrectionDependencyFacts × Bytes) := do
  let (artifactContract, rest) ← readString bytes
  let (artifactVersion, rest) ← readNatBE 8 rest
  let (authorityId, rest) ← readString rest
  let (authorityEpoch, rest) ← readNatBE 8 rest
  let (authorityDigest, rest) ← readDigest rest
  let (controlPackId, rest) ← readString rest
  let (controlPackVersion, rest) ← readNatBE 8 rest
  let (controlPackDigest, rest) ← readDigest rest
  let (inputEvaluationId, rest) ← readString rest
  let (inputEvaluationResultDigest, rest) ← readDigest rest
  let (inputEvaluationRevision, rest) ← readNatBE 8 rest
  let (inputEvaluationEvaluatedAtMs, rest) ← readNatBE 8 rest
  let (inputEvaluationSnapshotDigest, rest) ← readDigest rest
  let (inputShortfallCents, rest) ← readNatBE 8 rest
  let (decisionAtMs, rest) ← readNatBE 8 rest
  let (ownerNowMs, rest) ← readNatBE 8 rest
  let (claimBefore, rest) ← decodeClaim rest
  let (supportingEvidence, rest) ← readList readEvidenceBinding rest
  let (queryObservations, rest) ← readQueryObservations rest
  let (currentEventSequence, rest) ← readNatBE 8 rest
  let (previousHistoryHead, rest) ← readDigest rest
  let (correctionPaid, rest) ← readList readCorrectionPaid rest
  pure ({
    artifactContract := artifactContract
    artifactVersion := artifactVersion
    authorityId := authorityId
    authorityEpoch := authorityEpoch
    authorityDigest := authorityDigest
    controlPackId := controlPackId
    controlPackVersion := controlPackVersion
    controlPackDigest := controlPackDigest
    inputEvaluationId := inputEvaluationId
    inputEvaluationResultDigest := inputEvaluationResultDigest
    inputEvaluationRevision := inputEvaluationRevision
    inputEvaluationEvaluatedAtMs := inputEvaluationEvaluatedAtMs
    inputEvaluationSnapshotDigest := inputEvaluationSnapshotDigest
    inputShortfallCents := inputShortfallCents
    decisionAtMs := decisionAtMs
    ownerNowMs := ownerNowMs
    claimBefore := claimBefore
    supportingEvidence := supportingEvidence
    queryObservations := queryObservations
    currentEventSequence := currentEventSequence
    previousHistoryHead := previousHistoryHead
    correctionPaid := correctionPaid }, rest)

def encodeFollowUps (followUps : CorrectionFollowUps) : Bytes :=
  encodeString followUps.actionId ++ encodeString followUps.outboxActionId ++
    encodeString followUps.caseId ++ encodeString followUps.resultingEvaluationId ++
    natBE 8 followUps.eventSequence

def readFollowUps (bytes : Bytes) : Option (CorrectionFollowUps × Bytes) := do
  let (actionId, rest) ← readString bytes
  let (outboxActionId, rest) ← readString rest
  let (caseId, rest) ← readString rest
  let (resultingEvaluationId, rest) ← readString rest
  let (eventSequence, rest) ← readNatBE 8 rest
  pure ({
    actionId := actionId
    outboxActionId := outboxActionId
    caseId := caseId
    resultingEvaluationId := resultingEvaluationId
    eventSequence := eventSequence }, rest)

def encodeExplanation (explanation : TransitionExplanation) : Bytes :=
  let transitionBytes := match explanation.transition with
    | none => [UInt8.ofNat 0]
    | some kind => [UInt8.ofNat 1, encodeTransitionKind kind]
  [encodeExplanationCode explanation.code] ++ transitionBytes ++
    encodeOptionalRejectReason explanation.rejectReason ++
    encodeOptionalRequirement explanation.unresolvedRequirement ++
    encodeOptionString explanation.claimId ++ encodeOptionString explanation.actionId ++
    encodeOptionString explanation.inputEvaluationId ++
    encodeOptionNat explanation.expectedRevision ++ encodeOptionNat explanation.resultingRevision

def readExplanation (bytes : Bytes) : Option (TransitionExplanation × Bytes) := do
  let (code, rest) ← readExplanationCode bytes
  let (transitionTag, rest) ← readByte rest
  let (transition, rest) ← if transitionTag.toNat = 0 then
      some (none, rest)
    else if transitionTag.toNat = 1 then do
      let (kind, tail) ← readTransitionKind rest
      some (some kind, tail)
    else none
  let (rejectReason, rest) ← readOptionalRejectReason rest
  let (unresolvedRequirement, rest) ← readOptionalRequirement rest
  let (claimId, rest) ← readOptionString rest
  let (actionId, rest) ← readOptionString rest
  let (inputEvaluationId, rest) ← readOptionString rest
  let (expectedRevision, rest) ← readOptionNat rest
  let (resultingRevision, rest) ← readOptionNat rest
  pure ({
    code := code
    transition := transition
    rejectReason := rejectReason
    unresolvedRequirement := unresolvedRequirement
    claimId := claimId
    actionId := actionId
    inputEvaluationId := inputEvaluationId
    expectedRevision := expectedRevision
    resultingRevision := resultingRevision }, rest)

def encodeOptionalMutation : Option CorrectionMutation → Option Bytes
  | none => some [UInt8.ofNat 0]
  | some mutation => do
      let inputBytes ← encodeFinancialInput mutation.resultingInput
      let resultBytes ← encodeFinancialResult mutation.resultingResult
      pure ([UInt8.ofNat 1, encodeTransitionKind mutation.transition] ++
        encodeList (fun effect => [encodeCorrectionEffect effect]) mutation.orderedEffects ++
        encodeDependencyFacts mutation.dependencies ++ encodeFollowUps mutation.followUps ++
        encodeSizedBytes inputBytes ++ encodeSizedBytes resultBytes ++
        encodeDetermination mutation.determination ++
        encodeAction mutation.action ++ encodeCase mutation.caseDelta.record ++
        encodeString mutation.caseDelta.contractualAccountability ++
        encodeBool mutation.caseDelta.completionConditionsAmountSatisfied ++
        encodeBool mutation.caseDelta.completionConditionsReportingComplete ++
        encodeBool mutation.caseDelta.completionConditionsDeliveryAcknowledgedOrNotRequired ++
        encodeBool mutation.caseDelta.inserted ++ encodeString mutation.outbox.actionId ++
        [encodeActionStatus mutation.outbox.status] ++ natBE 8 mutation.outbox.attempt ++
        encodeOptionString mutation.outbox.acknowledgmentReference ++
        natBE 8 mutation.outbox.updatedAtMs ++ natBE 8 mutation.event.sequence ++
        encodeDigest mutation.event.previousHead ++ encodeString mutation.event.aggregateType ++
        encodeString mutation.event.aggregateId ++ encodeString mutation.event.kind ++
        natBE 8 mutation.event.beforeRevision ++ natBE 8 mutation.event.afterRevision ++
        natBE 8 mutation.event.committedAtMs)

def readOptionalMutation (bytes : Bytes) : Option (Option CorrectionMutation × Bytes) := do
  let (tag, rest) ← readByte bytes
  if tag.toNat = 0 then some (none, rest)
  else if tag.toNat ≠ 1 then none
  else do
    let (transition, rest) ← readTransitionKind rest
    let (orderedEffects, rest) ← readList readCorrectionEffect rest
    let (dependencies, rest) ← readDependencyFacts rest
    let (followUps, rest) ← readFollowUps rest
    let (inputBytes, rest) ← readSizedBytes maxCorrectionTransitionBytes rest
    let (resultBytes, rest) ← readSizedBytes maxCorrectionTransitionBytes rest
    let resultingInput ← decodeFinancialInput inputBytes
    let resultingResult ← decodeFinancialResult resultBytes
    let (determination, rest) ← decodeDetermination rest
    let (action, rest) ← decodeAction rest
    let (caseRecord, rest) ← decodeCase rest
    let (contractualAccountability, rest) ← readString rest
    let (completionConditionsAmountSatisfied, rest) ← readBool rest
    let (completionConditionsReportingComplete, rest) ← readBool rest
    let (completionConditionsDeliveryAcknowledgedOrNotRequired, rest) ← readBool rest
    let (inserted, rest) ← readBool rest
    let (outboxActionId, rest) ← readString rest
    let (outboxStatusByte, rest) ← readByte rest
    let outboxStatus ← decodeActionStatus outboxStatusByte
    let (attempt, rest) ← readNatBE 8 rest
    let (acknowledgmentReference, rest) ← readOptionString rest
    let (updatedAtMs, rest) ← readNatBE 8 rest
    let (sequence, rest) ← readNatBE 8 rest
    let (previousHead, rest) ← readDigest rest
    let (aggregateType, rest) ← readString rest
    let (aggregateId, rest) ← readString rest
    let (kind, rest) ← readString rest
    let (beforeRevision, rest) ← readNatBE 8 rest
    let (afterRevision, rest) ← readNatBE 8 rest
    let (committedAtMs, rest) ← readNatBE 8 rest
    let mutation : CorrectionMutation := {
      transition := transition
      orderedEffects := orderedEffects
      dependencies := dependencies
      followUps := followUps
      resultingInput := resultingInput
      resultingResult := resultingResult
      determination := determination
      action := action
      caseDelta := {
        record := caseRecord
        contractualAccountability := contractualAccountability
        completionConditionsAmountSatisfied := completionConditionsAmountSatisfied
        completionConditionsReportingComplete := completionConditionsReportingComplete
        completionConditionsDeliveryAcknowledgedOrNotRequired := completionConditionsDeliveryAcknowledgedOrNotRequired
        inserted := inserted }
      outbox := {
        actionId := outboxActionId
        status := outboxStatus
        attempt := attempt
        acknowledgmentReference := acknowledgmentReference
        updatedAtMs := updatedAtMs }
      event := {
        sequence := sequence
        previousHead := previousHead
        aggregateType := aggregateType
        aggregateId := aggregateId
        kind := kind
        beforeRevision := beforeRevision
        afterRevision := afterRevision
        committedAtMs := committedAtMs } }
    pure (some mutation, rest)

def optionalIdWellFormed : Option String → Bool
  | none => true
  | some value => idWellFormed value

def optionalRevisionWellFormed : Option Nat → Bool
  | none => true
  | some value => revisionWellFormed value

def resultWellFormed (result : CorrectionTransitionResult) : Bool :=
  match result.status, result.rejectReason, result.explanation.code,
      result.explanation.transition, result.explanation.rejectReason,
      result.explanation.unresolvedRequirement, result.actionId,
      result.determinationId, result.mutation with
  -- One arm for both accepted kinds; the authorize differences (design 3.3) test `kind`.
  | .ACCEPTED, none, code, some kind, none, none, some actionId, some determinationId, some mutation =>
      idWellFormed actionId && idWellFormed determinationId &&
      result.explanation.claimId = some mutation.determination.claimId &&
      result.explanation.actionId = some actionId &&
      result.explanation.inputEvaluationId = some mutation.dependencies.inputEvaluationId &&
      result.explanation.expectedRevision = some mutation.determination.expectedRevision &&
      result.explanation.resultingRevision = some mutation.resultingResult.afterRevision &&
      financialInputWellFormed mutation.resultingInput &&
      financialResultWellFormed mutation.resultingResult &&
      mutation.resultingResult.context = mutation.resultingInput.context &&
      mutation.resultingResult.authorityId = mutation.resultingInput.authority.authorityId &&
      mutation.resultingResult.authorityEpoch = mutation.resultingInput.authority.epoch &&
      mutation.resultingResult.authorityDigest = mutation.resultingInput.authority.digest &&
      mutation.resultingResult.packId = mutation.resultingInput.pack.packId &&
      mutation.resultingResult.packDigest = mutation.resultingInput.pack.digest &&
      mutation.resultingResult.afterRevision = mutation.resultingInput.beforeRevision + 1 &&
      mutation.transition = kind &&
      mutation.orderedEffects = [ .DETERMINATION_RECORDED,
        if kind = .OFFSET_AUTHORIZED then .CLAIM_AUTHORIZED else .CLAIM_REJECTED, .CASE_UPSERTED,
        .ACTION_CREATED, .OUTBOX_CREATED, .PROJECTION_RECOMPUTED, .EVENT_APPENDED ] &&
      mutation.determination.determinationId = determinationId &&
      idWellFormed mutation.determination.determinationId &&
      idWellFormed mutation.determination.obligationId &&
      idWellFormed mutation.determination.claimId &&
      idWellFormed mutation.determination.actorId &&
      roleWellFormed mutation.determination.actorRole &&
      idWellFormed mutation.determination.authorityId &&
      mutation.determination.decision = (if kind = .OFFSET_AUTHORIZED then .OFFSET_AUTHORIZED
        else .OFFSET_REJECTED_CORRECTION_AUTHORIZED) &&
      mutation.determination.amountCents > 0 && mutation.determination.amountCents ≤ maxCents &&
      revisionWellFormed mutation.determination.expectedRevision &&
      revisionWellFormed mutation.determination.resultingRevision &&
      mutation.determination.resultingRevision = mutation.determination.expectedRevision + 1 &&
      timeWellFormed mutation.determination.decidedAt &&
      mutation.determination.obligationId = mutation.resultingInput.context.obligationId &&
      mutation.action.actionId = actionId && digestWellFormed mutation.action.payloadDigest &&
      mutation.action.obligationId = mutation.determination.obligationId &&
      mutation.action.determinationId = some determinationId &&
      mutation.action.kind = (if kind = .OFFSET_AUTHORIZED then "OFFSET_AUTHORIZATION"
        else "CORRECTION_PAYMENT_REQUEST") &&
      (kind = .OFFSET_AUTHORIZED || mutation.dependencies.inputShortfallCents > 0) &&
      mutation.dependencies.inputShortfallCents ≤ maxCents &&
      -- An authorization covers the whole claim. A correction asks only for the balance that
      -- earlier correction requests, less what was paid against them, do not already ask for.
      correctionPaidWellFormed mutation.dependencies.correctionPaid &&
      mutation.action.amountCents = (if kind = .OFFSET_AUTHORIZED
        then mutation.determination.amountCents
        else min mutation.determination.amountCents (mutation.dependencies.inputShortfallCents -
          outstandingCorrectionCents mutation.dependencies.correctionPaid
            (mutation.resultingInput.actions.filter (fun action => action.actionId ≠ actionId)))) &&
      mutation.action.currency = mutation.resultingInput.context.currency &&
      mutation.action.revision = mutation.determination.resultingRevision &&
      mutation.action.status = .READY &&
      mutation.action.createdAt = mutation.event.committedAtMs &&
      mutation.outbox.actionId = actionId && mutation.outbox.attempt = 0 &&
      mutation.outbox.status = .READY &&
      mutation.event.beforeRevision = mutation.resultingResult.beforeRevision &&
      mutation.event.afterRevision = mutation.resultingResult.afterRevision &&
      mutation.event.beforeRevision = mutation.determination.expectedRevision &&
      mutation.event.afterRevision = mutation.determination.resultingRevision &&
      mutation.event.sequence = mutation.dependencies.currentEventSequence + 1 &&
      mutation.event.aggregateType = "OBLIGATION" &&
      mutation.event.aggregateId = mutation.resultingInput.context.obligationId &&
      mutation.event.kind = (if kind = .OFFSET_AUTHORIZED then "OFFSET_AUTHORIZED"
        else "OFFSET_REJECTED_CORRECTION_AUTHORIZED") &&
      mutation.event.committedAtMs = mutation.outbox.updatedAtMs &&
      mutation.event.previousHead = mutation.dependencies.previousHistoryHead &&
      mutation.event.previousHead.length = digestBytes &&
      mutation.followUps.actionId = actionId && mutation.followUps.outboxActionId = actionId &&
      mutation.followUps.caseId = mutation.caseDelta.record.caseId &&
      mutation.caseDelta.record.caseId = "case:" ++ mutation.resultingInput.context.obligationId &&
      mutation.caseDelta.record.obligationId = mutation.resultingInput.context.obligationId &&
      -- An authorization keeps an outstanding correction case (reason CORRECTION_REQUIRED, not
      -- inserted) with its owner and due date; an inserted or replaced case is checked in full.
      (mutation.caseDelta.record.reason =
          (if kind = .OFFSET_AUTHORIZED then "OFFSET_AUTHORIZED" else "CORRECTION_REQUIRED") ||
        kind = .OFFSET_AUTHORIZED && !mutation.caseDelta.inserted &&
          mutation.caseDelta.record.reason = "CORRECTION_REQUIRED") &&
      (mutation.caseDelta.record.nextActionOwner = "CASE_OWNER" ||
        kind = .OFFSET_AUTHORIZED && !mutation.caseDelta.inserted &&
          mutation.caseDelta.record.reason = "CORRECTION_REQUIRED" &&
          roleWellFormed mutation.caseDelta.record.nextActionOwner) &&
      (mutation.caseDelta.record.dueAt = mutation.dependencies.claimBefore.deadlineAt ||
        kind = .OFFSET_AUTHORIZED && !mutation.caseDelta.inserted &&
          mutation.caseDelta.record.reason = "CORRECTION_REQUIRED" &&
          timeWellFormed mutation.caseDelta.record.dueAt) &&
      mutation.caseDelta.record.status = mutation.resultingResult.caseStatus &&
      mutation.caseDelta.record.updatedAt = mutation.event.committedAtMs &&
      mutation.caseDelta.contractualAccountability = "PROGRAM_ACCOUNTABILITY" &&
      mutation.caseDelta.completionConditionsAmountSatisfied &&
      mutation.caseDelta.completionConditionsReportingComplete &&
      mutation.caseDelta.completionConditionsDeliveryAcknowledgedOrNotRequired &&
      mutation.outbox.status = .READY && mutation.outbox.acknowledgmentReference.isNone &&
      mutation.outbox.updatedAtMs = mutation.event.committedAtMs &&
      mutation.followUps.resultingEvaluationId = "evaluation:" ++ mutation.resultingInput.context.obligationId ++
        ":r" ++ toString mutation.resultingResult.afterRevision &&
      mutation.followUps.eventSequence = mutation.event.sequence &&
      mutation.dependencies.artifactContract = correctionTransitionContract &&
      mutation.dependencies.artifactVersion = 1 &&
      mutation.dependencies.authorityId = mutation.resultingInput.authority.authorityId &&
      mutation.dependencies.authorityEpoch = mutation.resultingInput.authority.epoch &&
      mutation.dependencies.authorityDigest = mutation.resultingInput.authority.digest &&
      mutation.dependencies.controlPackId = mutation.resultingInput.pack.packId &&
      mutation.dependencies.controlPackVersion = mutation.resultingInput.pack.version &&
      mutation.dependencies.controlPackDigest = mutation.resultingInput.pack.digest &&
      mutation.dependencies.inputEvaluationRevision = mutation.determination.expectedRevision &&
      mutation.dependencies.inputEvaluationId = "evaluation:" ++ mutation.resultingInput.context.obligationId ++
        ":r" ++ toString mutation.dependencies.inputEvaluationRevision &&
      mutation.dependencies.inputEvaluationEvaluatedAtMs ≤ mutation.dependencies.decisionAtMs &&
      timeWellFormed mutation.dependencies.inputEvaluationEvaluatedAtMs &&
      timeWellFormed mutation.dependencies.decisionAtMs &&
      timeWellFormed mutation.dependencies.ownerNowMs &&
      mutation.dependencies.decisionAtMs = mutation.determination.decidedAt &&
      mutation.event.committedAtMs = max mutation.dependencies.decisionAtMs
        mutation.dependencies.ownerNowMs &&
      mutation.dependencies.claimBefore.claimId = mutation.determination.claimId &&
      mutation.dependencies.claimBefore.status = .CLAIMED &&
      mutation.dependencies.claimBefore.obligationId = mutation.determination.obligationId &&
      mutation.dependencies.claimBefore.amountCents = mutation.determination.amountCents &&
      mutation.dependencies.supportingEvidence.any (fun binding =>
        binding.evidenceId = mutation.dependencies.claimBefore.evidenceId) &&
      idWellFormed mutation.dependencies.claimBefore.claimId &&
      idWellFormed mutation.dependencies.claimBefore.evidenceId &&
      roleWellFormed mutation.dependencies.claimBefore.ownerRole &&
      timeWellFormed mutation.dependencies.claimBefore.deadlineAt &&
      mutation.dependencies.supportingEvidence.all (fun binding =>
        idWellFormed binding.evidenceId && digestWellFormed binding.recordDigest) &&
      mutation.resultingInput.claims.any (fun claim =>
        claim = { mutation.dependencies.claimBefore with
          status := if kind = .OFFSET_AUTHORIZED then .AUTHORIZED else .REJECTED }) &&
      mutation.dependencies.supportingEvidence.map EvidenceBinding.evidenceId =
        mutation.determination.supportingEvidenceIds &&
      mutation.dependencies.inputEvaluationSnapshotDigest.length = digestBytes &&
      mutation.dependencies.inputEvaluationResultDigest.length = digestBytes &&
      mutation.dependencies.previousHistoryHead.length = digestBytes &&
      mutation.dependencies.queryObservations.actionId.predicate = .ACTION_ID &&
      mutation.dependencies.queryObservations.actionId.subject = actionId &&
      mutation.dependencies.queryObservations.actionId.complete &&
      mutation.dependencies.queryObservations.actionId.matchCount = 0 &&
      mutation.dependencies.queryObservations.actionId.resultIdentity.isNone &&
      mutation.dependencies.queryObservations.determinationId.predicate = .DETERMINATION_ID &&
      mutation.dependencies.queryObservations.determinationId.subject = determinationId &&
      mutation.dependencies.queryObservations.determinationId.complete &&
      mutation.dependencies.queryObservations.determinationId.matchCount = 0 &&
      mutation.dependencies.queryObservations.determinationId.resultIdentity.isNone &&
      mutation.dependencies.queryObservations.evaluationConsumed.predicate = .EVALUATION_CONSUMED &&
      mutation.dependencies.queryObservations.evaluationConsumed.subject =
        mutation.dependencies.inputEvaluationId &&
      mutation.dependencies.queryObservations.evaluationConsumed.complete &&
      mutation.dependencies.queryObservations.evaluationConsumed.matchCount = 0 &&
      mutation.dependencies.queryObservations.evaluationConsumed.resultIdentity.isNone &&
      correctionQueryObservationsAt mutation.dependencies.queryObservations
        mutation.dependencies.currentEventSequence mutation.dependencies.previousHistoryHead &&
      correctionQueryObservationsWellFormed mutation.dependencies.queryObservations &&
      code = if kind = .OFFSET_AUTHORIZED then .OFFSET_AUTHORIZED else .CORRECTION_AUTHORIZED
  | .DUPLICATE, none, .EXACT_RETRY, some _,
      none, none, some actionId, some determinationId, none =>
      idWellFormed actionId && determinationId = "determination:" ++ actionId &&
      result.explanation.claimId.isSome &&
      result.explanation.actionId = some actionId &&
      result.explanation.inputEvaluationId.isSome &&
      optionalIdWellFormed result.explanation.claimId &&
      optionalIdWellFormed result.explanation.inputEvaluationId &&
      optionalRevisionWellFormed result.explanation.expectedRevision &&
      result.explanation.expectedRevision.isSome &&
      result.explanation.resultingRevision.isNone
  | .REJECTED, some reason, .REJECTED, none, some explainedReason,
      some requirement, _, _, none =>
      reason = explainedReason && requirement = requiredTransitionCondition reason &&
      result.explanation.transition.isNone && result.actionId.isNone &&
      result.determinationId.isNone && result.explanation.resultingRevision.isNone &&
      optionalIdWellFormed result.explanation.claimId &&
      optionalIdWellFormed result.explanation.actionId &&
      optionalIdWellFormed result.explanation.inputEvaluationId &&
      optionalRevisionWellFormed result.explanation.expectedRevision
  | _, _, _, _, _, _, _, _, _ => false

def encodeCorrectionTransitionResult (result : CorrectionTransitionResult) : Option Bytes := do
  if !resultWellFormed result then none
  let status := match result.status with
    | .ACCEPTED => UInt8.ofNat 1
    | .DUPLICATE => UInt8.ofNat 2
    | .REJECTED => UInt8.ofNat 3
  let mutationBytes ← encodeOptionalMutation result.mutation
  let wire := correctionTransitionResultMagic ++ natBE 2 3 ++ [status] ++
    encodeString correctionTransitionContract ++
    encodeOptionalRejectReason result.rejectReason ++ encodeExplanation result.explanation ++
    encodeOptionString result.actionId ++
    encodeOptionString result.determinationId ++ mutationBytes
  if wire.length ≤ maxCorrectionTransitionBytes then some wire else none

/-- Reads one BLFCRES3 result and returns the unread bytes. -/
def parseCorrectionTransitionResult (bytes : Bytes) :
    Option (CorrectionTransitionResult × Bytes) := do
  if !correctionTransitionResultMagic.isPrefixOf bytes then none
  let rest := bytes.drop correctionTransitionResultMagic.length
  let (version, rest) ← readNatBE 2 rest
  if version ≠ 3 then none
  let (statusByte, rest) ← readByte rest
  let status ← match statusByte.toNat with
    | 1 => some TransitionStatus.ACCEPTED
    | 2 => some TransitionStatus.DUPLICATE
    | 3 => some TransitionStatus.REJECTED
    | _ => none
  let (contract, rest) ← readString rest
  if contract ≠ correctionTransitionContract then none
  let (rejectReason, rest) ← readOptionalRejectReason rest
  let (explanation, rest) ← readExplanation rest
  let (actionId, rest) ← readOptionString rest
  let (determinationId, rest) ← readOptionString rest
  let (mutation, rest) ← readOptionalMutation rest
  let result : CorrectionTransitionResult := {
    status := status
    rejectReason := rejectReason
    explanation := explanation
    actionId := actionId
    determinationId := determinationId
    mutation := mutation }
  pure (result, rest)

def decodeCorrectionTransitionResult (bytes : Bytes) : Option CorrectionTransitionResult :=
  if bytes.length > maxCorrectionTransitionBytes then none else
  match parseCorrectionTransitionResult bytes with
  | some (result, []) =>
      if encodeCorrectionTransitionResult result = some bytes then some result else none
  | _ => none

end BlindLedger.Financial.CorrectionTransition
