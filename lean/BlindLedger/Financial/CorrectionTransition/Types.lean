import BlindLedger.Financial.DecisionPackage.Types

namespace BlindLedger.Financial.CorrectionTransition

open BlindLedger.Financial
open BlindLedger.Financial.DecisionPackage

def correctionTransitionContract : String := "RR/FINANCIAL/CORRECTION-TRANSITION/v1"
def correctionTransitionInputMagic : Bytes := "BLFCMD02".toUTF8.toList
def correctionTransitionResultMagic : Bytes := "BLFCRES3".toUTF8.toList
def maxCorrectionTransitionBytes : Nat := maxTotalEncodedBytes

inductive TransitionStatus where
  | ACCEPTED
  | DUPLICATE
  | REJECTED
deriving DecidableEq, Repr

inductive TransitionKind where
  | OFFSET_REJECTED_CORRECTION_AUTHORIZED
deriving DecidableEq, Repr

inductive ExplanationCode where
  | CORRECTION_AUTHORIZED
  | EXACT_RETRY
  | REJECTED
deriving DecidableEq, Repr

inductive CorrectionEffect where
  | DETERMINATION_RECORDED
  | CLAIM_REJECTED
  | CASE_UPSERTED
  | ACTION_CREATED
  | OUTBOX_CREATED
  | PROJECTION_RECOMPUTED
  | EVENT_APPENDED
deriving DecidableEq, Repr

inductive TransitionRejectReason where
  | INVALID_REQUEST
  | INVALID_INPUT
  | SHADOW_READ_ONLY
  | SCOPE_MISMATCH
  | AUTHORITY_STALE
  | ACTOR_UNAUTHORIZED
  | CONTROL_PACK_REJECTED
  | REVISION_CONFLICT
  | EVALUATION_CONFLICT
  | EVALUATION_CONSUMED
  | EVIDENCE_COVERAGE
  | CLAIM_MISSING
  | CLAIM_NOT_CLAIMED
  | ACTION_CONFLICT
  | DETERMINATION_CONFLICT
  | CHRONOLOGY
  | QUERY_OBSERVATION_INVALID
  | INPUT_SNAPSHOT_MISSING
  | CAPACITY
  | NO_SHORTFALL
  | NO_REQUESTABLE_BALANCE
deriving DecidableEq, Repr

inductive TransitionRequirement where
  | VALID_COMMAND
  | WELL_FORMED_FINANCIAL_SNAPSHOT
  | ACTIONABLE_OWNER_MODE
  | REQUEST_SCOPE_MATCH
  | CURRENT_AUTHORITY_MATCH
  | AUTHORIZED_ACTOR_ROLE
  | APPROVED_CONTROL_PACK
  | CURRENT_REVISION_MATCH
  | CURRENT_EVALUATION_BINDING
  | UNIQUE_EVALUATION_USE
  | CLAIM_EVIDENCE_COVERAGE
  | CLAIM_EXISTS_IN_SCOPE
  | CLAIM_IS_CLAIMED
  | ACTION_IDENTITY_MATCH
  | DETERMINATION_ID_AVAILABLE
  | RECEIPT_PRECEDES_DECISION
  | COMPLETE_QUERY_OBSERVATIONS
  | INPUT_SNAPSHOT_DIGEST_AVAILABLE
  | HISTORY_CAPACITY_AVAILABLE
  | POSITIVE_SHORTFALL
  | UNREQUESTED_SHORTFALL
deriving DecidableEq, Repr

def requiredTransitionCondition : TransitionRejectReason → TransitionRequirement
  | .INVALID_REQUEST => .VALID_COMMAND
  | .INVALID_INPUT => .WELL_FORMED_FINANCIAL_SNAPSHOT
  | .SHADOW_READ_ONLY => .ACTIONABLE_OWNER_MODE
  | .SCOPE_MISMATCH => .REQUEST_SCOPE_MATCH
  | .AUTHORITY_STALE => .CURRENT_AUTHORITY_MATCH
  | .ACTOR_UNAUTHORIZED => .AUTHORIZED_ACTOR_ROLE
  | .CONTROL_PACK_REJECTED => .APPROVED_CONTROL_PACK
  | .REVISION_CONFLICT => .CURRENT_REVISION_MATCH
  | .EVALUATION_CONFLICT => .CURRENT_EVALUATION_BINDING
  | .EVALUATION_CONSUMED => .UNIQUE_EVALUATION_USE
  | .EVIDENCE_COVERAGE => .CLAIM_EVIDENCE_COVERAGE
  | .CLAIM_MISSING => .CLAIM_EXISTS_IN_SCOPE
  | .CLAIM_NOT_CLAIMED => .CLAIM_IS_CLAIMED
  | .ACTION_CONFLICT => .ACTION_IDENTITY_MATCH
  | .DETERMINATION_CONFLICT => .DETERMINATION_ID_AVAILABLE
  | .CHRONOLOGY => .RECEIPT_PRECEDES_DECISION
  | .QUERY_OBSERVATION_INVALID => .COMPLETE_QUERY_OBSERVATIONS
  | .INPUT_SNAPSHOT_MISSING => .INPUT_SNAPSHOT_DIGEST_AVAILABLE
  | .CAPACITY => .HISTORY_CAPACITY_AVAILABLE
  | .NO_SHORTFALL => .POSITIVE_SHORTFALL
  | .NO_REQUESTABLE_BALANCE => .UNREQUESTED_SHORTFALL

/-- What the payments linked to one correction request have paid against it. -/
structure CorrectionPaid where
  actionId : String
  paidCents : Nat
deriving DecidableEq, Repr

def correctionPaidCents (paid : List CorrectionPaid) (actionId : String) : Nat :=
  paid.foldr (fun entry total =>
    (if entry.actionId = actionId then entry.paidCents else 0) + total) 0

/-- What correction requests still ask for: every READY or ACKNOWLEDGED
    CORRECTION_PAYMENT_REQUEST less what has been paid against it (a CANCELLED
    one asks for nothing). -/
def outstandingCorrectionCents (paid : List CorrectionPaid) : List ActionRecord → Nat
  | [] => 0
  | action :: rest =>
      (if action.kind = "CORRECTION_PAYMENT_REQUEST" ∧ action.status ≠ .CANCELLED then
        action.amountCents - correctionPaidCents paid action.actionId else 0) +
        outstandingCorrectionCents paid rest

inductive CorrectionQueryPredicate where
  | ACTION_ID
  | DETERMINATION_ID
  | EVALUATION_CONSUMED
deriving DecidableEq, Repr

/-! These three bounded lookups are the complete absence/identity queries used
    by this correction operation. `versionSequence`/`versionHead` identify the
    same Owner history snapshot as the command; `complete` is a State adapter
    assertion that the unique-key lookup completed in that snapshot. -/
structure CorrectionQueryObservation where
  predicate : CorrectionQueryPredicate
  subject : String
  complete : Bool
  matchCount : Nat
  resultIdentity : Option String
  versionSequence : Nat
  versionHead : Bytes
deriving DecidableEq, Repr

structure CorrectionQueryObservations where
  actionId : CorrectionQueryObservation
  determinationId : CorrectionQueryObservation
  evaluationConsumed : CorrectionQueryObservation
deriving DecidableEq, Repr

def correctionQueryObservationWellFormed (observation : CorrectionQueryObservation) : Bool :=
  idWellFormed observation.subject && observation.matchCount ≤ 1 &&
    observation.versionSequence ≤ maxRows && digestWellFormed observation.versionHead &&
    (match observation.resultIdentity with
      | none => observation.matchCount = 0
      | some identity => observation.matchCount = 1 && idWellFormed identity)

def correctionQueryObservationsWellFormed (observations : CorrectionQueryObservations) : Bool :=
  correctionQueryObservationWellFormed observations.actionId &&
    correctionQueryObservationWellFormed observations.determinationId &&
    correctionQueryObservationWellFormed observations.evaluationConsumed

def correctionQueryObservationsAt (observations : CorrectionQueryObservations)
    (sequence : Nat) (head : Bytes) : Bool :=
  observations.actionId.versionSequence = sequence && observations.actionId.versionHead = head &&
    observations.determinationId.versionSequence = sequence &&
    observations.determinationId.versionHead = head &&
    observations.evaluationConsumed.versionSequence = sequence &&
    observations.evaluationConsumed.versionHead = head

/-! State supplies this lookup from the same write transaction that will apply
    an accepted delta. The present case contains only the identity fields that
    Owner's exact-retry helper compares; an unrelated/corrupt row is a conflict. -/
structure ExistingCorrectionIdentity where
  actionId : String
  actionObligationId : String
  determinationId : String
  determinationObligationId : String
  actionKind : String
  claimId : String
  actorId : String
  actorRole : String
  authorityId : String
  authorityEpoch : Nat
  authorityDigest : Bytes
  decision : DeterminationDecision
  inputEvaluationId : String
  inputEvaluationResultDigest : Bytes
  expectedRevision : Nat
  decidedAtMs : Nat
deriving DecidableEq, Repr

inductive ActionIdentityLookup where
  | absent
  | existing (identity : ExistingCorrectionIdentity)
  | conflicting
deriving DecidableEq, Repr

/-! The command's evaluation ID/digest/revision/time are mandatory even on a
    retry. This closes the Owner API's optional retry fields into one exact
    command identity. The current authority, global lookup facts and the
    payments linked to earlier correction requests are read by State, not
    caller-authenticated values. -/
structure CorrectionCommand where
  itemId : String
  claimId : String
  actionId : String
  actorId : String
  actorRole : String
  currentAuthorityId : String
  currentAuthorityEpoch : Nat
  currentAuthorityDigest : Bytes
  expectedRevision : Nat
  evaluationId : String
  evaluationResultDigest : Bytes
  decisionAtMs : Nat
  ownerNowMs : Nat
  actionLookup : ActionIdentityLookup
  queryObservations : CorrectionQueryObservations
  currentEventSequence : Nat
  previousHistoryHead : Bytes
  correctionPaid : List CorrectionPaid := []
deriving DecidableEq, Repr

structure CorrectionTransitionRequest where
  command : CorrectionCommand
  currentInput : FinancialInput
  currentReceipt : EvaluationReceipt
deriving DecidableEq, Repr

structure CorrectionCaseDelta where
  record : CaseRecord
  contractualAccountability : String
  completionConditionsAmountSatisfied : Bool
  completionConditionsReportingComplete : Bool
  completionConditionsDeliveryAcknowledgedOrNotRequired : Bool
  inserted : Bool
deriving DecidableEq, Repr

structure CorrectionOutboxDelta where
  actionId : String
  status : ActionStatus
  attempt : Nat
  acknowledgmentReference : Option String
  updatedAtMs : Nat
deriving DecidableEq, Repr

structure CorrectionEventIntent where
  sequence : Nat
  previousHead : Bytes
  aggregateType : String
  aggregateId : String
  kind : String
  beforeRevision : Nat
  afterRevision : Nat
  committedAtMs : Nat
deriving DecidableEq, Repr

structure CorrectionDependencyFacts where
  artifactContract : String
  artifactVersion : Nat
  authorityId : String
  authorityEpoch : Nat
  authorityDigest : Bytes
  controlPackId : String
  controlPackVersion : Nat
  controlPackDigest : Bytes
  inputEvaluationId : String
  inputEvaluationResultDigest : Bytes
  inputEvaluationRevision : Nat
  inputEvaluationEvaluatedAtMs : Nat
  inputEvaluationSnapshotDigest : Bytes
  inputShortfallCents : Nat
  decisionAtMs : Nat
  ownerNowMs : Nat
  claimBefore : Claim
  supportingEvidence : List EvidenceBinding
  queryObservations : CorrectionQueryObservations
  currentEventSequence : Nat
  previousHistoryHead : Bytes
  correctionPaid : List CorrectionPaid
deriving DecidableEq, Repr

inductive CorrectionCalculationValidity where
  | VALID
  | INVALID
deriving DecidableEq, Repr

inductive CorrectionCalculationReason where
  | ACCEPTED_TRANSITION_REQUIRED
  | QUERY_OBSERVATION_INVALID
  | RELEVANT_FINANCIAL_FACT_CHANGED
  | EVIDENCE_BINDING_CHANGED
  | CURRENT_RECEIPT_INVALID
  | CURRENT_RESULT_CHANGED
deriving DecidableEq, Repr

inductive CorrectionApprovalValidity where
  | VALID
  | INVALID
deriving DecidableEq, Repr

inductive CorrectionApprovalReason where
  | ACCEPTED_TRANSITION_REQUIRED
  | DETERMINATION_MISSING
  | DETERMINATION_CHANGED
deriving DecidableEq, Repr

inductive CorrectionExecutionPermission where
  | ALLOWED
  | DENIED
deriving DecidableEq, Repr

inductive CorrectionExecutionDenial where
  | CALCULATION_INVALID
  | HUMAN_APPROVAL_INVALID
  | SHADOW_MODE
  | AUTHORITY_STALE
  | ACTOR_NOT_AUTHORIZED
  | CONTROL_PACK_NOT_APPROVED
  | ACTION_MISSING
  | ACTION_CHANGED
  | ACTION_NOT_READY
  | OUTBOX_MISSING
  | OUTBOX_CHANGED
  | OUTBOX_NOT_READY
deriving DecidableEq, Repr

inductive CorrectionDeadlineStatus where
  | BEFORE_DEADLINE
  | DEADLINE_REACHED
deriving DecidableEq, Repr

structure CorrectionFollowUps where
  actionId : String
  outboxActionId : String
  caseId : String
  resultingEvaluationId : String
  eventSequence : Nat
deriving DecidableEq, Repr

structure TransitionExplanation where
  code : ExplanationCode
  transition : Option TransitionKind
  rejectReason : Option TransitionRejectReason
  unresolvedRequirement : Option TransitionRequirement
  claimId : Option String
  actionId : Option String
  inputEvaluationId : Option String
  expectedRevision : Option Nat
  resultingRevision : Option Nat
deriving DecidableEq, Repr

structure CorrectionMutation where
  transition : TransitionKind
  orderedEffects : List CorrectionEffect
  dependencies : CorrectionDependencyFacts
  followUps : CorrectionFollowUps
  resultingInput : FinancialInput
  resultingResult : FinancialResult
  determination : OffsetDetermination
  action : ActionRecord
  caseDelta : CorrectionCaseDelta
  outbox : CorrectionOutboxDelta
  event : CorrectionEventIntent
deriving DecidableEq, Repr

structure CorrectionTransitionResult where
  status : TransitionStatus
  rejectReason : Option TransitionRejectReason
  explanation : TransitionExplanation
  actionId : Option String
  determinationId : Option String
  mutation : Option CorrectionMutation
deriving DecidableEq, Repr

/-! Reuse checks one prior correction result against one current Owner read.
    The persisted result is passed back in full; current authority, approval,
    action, outbox, and the three bounded queries are separately observed. -/
structure CorrectionReuseRequest where
  acceptedResult : CorrectionTransitionResult
  currentInput : FinancialInput
  currentReceipt : EvaluationReceipt
  currentDetermination : Option OffsetDetermination
  currentOutbox : Option CorrectionOutboxDelta
  currentQueries : CorrectionQueryObservations
  currentEventSequence : Nat
  currentHistoryHead : Bytes
  currentOwnerNowMs : Nat
deriving DecidableEq, Repr

structure CorrectionReuseAssessment where
  calculationValidity : CorrectionCalculationValidity
  calculationReason : Option CorrectionCalculationReason
  humanApprovalValidity : CorrectionApprovalValidity
  humanApprovalReason : Option CorrectionApprovalReason
  localExecutionPermission : CorrectionExecutionPermission
  executionDenial : Option CorrectionExecutionDenial
  deadlineStatus : Option CorrectionDeadlineStatus
  unrelatedWatermarkAdvanced : Bool
  externalDispatchPermitted : Bool
deriving DecidableEq, Repr

end BlindLedger.Financial.CorrectionTransition
