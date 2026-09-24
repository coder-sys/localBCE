import BlindLedger.Financial.Types

namespace BlindLedger.Financial.DecisionPackage

open BlindLedger.Financial

/-! Engine-owned, read-only projection types for the versioned Owner/Mirror
    decision package. They do not model a command, a payment, or a state write. -/

def decisionPackageContractV1 : String := "RR/FINANCIAL/DECISION-PACKAGE/v1"
def decisionPackageContractV2 : String := "RR/FINANCIAL/DECISION-PACKAGE/v2"
def evaluationReceiptContractV1 : String := "RR/FINANCIAL/EVALUATION-RECEIPT/v1"
def mirrorSchemaV1 : String := "RR/FINANCIAL/MIRROR/v1"
def decisionPackageResource : String := "decision_package"

def decisionPackageInputMagic : Bytes := "BLFDCP01".toUTF8.toList
def decisionPackageProjectionMagic : Bytes := "BLFDPR01".toUTF8.toList
def maxDecisionPackageBytes : Nat := maxTotalEncodedBytes

inductive Knowledge (α : Type) where
  | known (value : α)
  | unknown
deriving DecidableEq, Repr

inductive DecisionSupport where
  | SUPPORTED
  | UNSUPPORTED
  | UNKNOWN
deriving DecidableEq, Repr

structure PackageScope where
  stateId : String
  deploymentId : String
  programId : String
  periodId : String
  currency : String
deriving DecidableEq, Repr

structure PackageObligation where
  obligationId : String
  itemId : String
  populationId : Knowledge String
  periodId : String
  currency : String
  revision : Nat
  owedCents : Nat
  claimedAdjustmentCents : Nat
  lawfulAdjustmentCents : Nat
  receivedCashCents : Nat
  shortfallCents : Nat
  overageCents : Nat
  cashSatisfied : Bool
  amountSatisfied : Bool
  timely : Bool
  reportingComplete : Bool
  verificationStatus : String
  caseStatus : String
  deliveryStatus : String
  currentEvaluationId : Option String
  dueAtMs : Nat
deriving DecidableEq, Repr

structure OwnerPopulationBinding where
  populationId : Knowledge String
  status : String
  completeness : String
  sourceComplete : Bool
  manifestId : Knowledge String
  manifestVersion : Nat
  manifestDigest : Knowledge Bytes
  memberId : Knowledge String
  memberCount : Nat
  memberDigest : Knowledge Bytes
deriving DecidableEq, Repr

structure PackageControlPack where
  packId : String
  version : Nat
  digest : Bytes
  calculationRuleId : String
  adjustmentRuleId : String
  sourceRefs : List String
  authorizedRoles : List String
  effectiveStartMs : Nat
  effectiveEndMs : Nat
  recordedAtMs : Nat
  approvedAtMs : Nat
deriving DecidableEq, Repr

structure ReceiptControlPack where
  packId : String
  version : Nat
  digest : Bytes
deriving DecidableEq, Repr

structure ReceiptAuthority where
  authorityEpoch : Nat
  authorityDigest : Bytes
deriving DecidableEq, Repr

structure EvidenceBinding where
  evidenceId : String
  recordDigest : Bytes
deriving DecidableEq, Repr

/-! This mirrors the Owner receipt's `_EVALUATION_RESULT_FIELDS`, including its
    stored evidence-id order. Digests remain opaque bytes; this projection does
    not claim to recompute the Owner's canonical-JSON domain hashes. -/
structure OwnerEvaluationResult where
  evaluationId : String
  obligationId : String
  revision : Nat
  ruleVersion : Nat
  evidenceIds : List String
  authorityId : String
  evaluatedAtMs : Nat
  owedCents : Nat
  claimedAdjustmentCents : Nat
  lawfulAdjustmentCents : Nat
  receivedCashCents : Nat
  shortfallCents : Nat
  overageCents : Nat
  cashSatisfied : Bool
  amountSatisfied : Bool
  timely : Bool
  reportingComplete : Bool
  verificationStatus : String
  caseStatus : String
  deliveryStatus : String
deriving DecidableEq, Repr

structure EvaluationReceipt where
  contractVersion : String
  scope : PackageScope
  controlPack : ReceiptControlPack
  evidenceBindings : List EvidenceBinding
  inputSnapshotDigest : Option Bytes
  authority : ReceiptAuthority
  result : OwnerEvaluationResult
  resultDigest : Bytes
  receiptDigest : Bytes
  evaluationResultDigest : Bytes
deriving DecidableEq, Repr

structure CurrentEvaluationExpectation where
  evaluationId : String
  resultDigest : Bytes
deriving DecidableEq, Repr

structure OwnerCase where
  caseId : String
  obligationId : String
  reason : String
  contractualAccountability : String
  nextActionOwner : String
  dueAtMs : Nat
  status : String
  updatedAtMs : Nat
deriving DecidableEq, Repr

structure OwnerDetermination where
  determinationId : String
  obligationId : String
  claimId : Option String
  actorId : String
  actorRole : String
  authorityId : String
  authorityEpoch : Nat
  authorityDigest : Bytes
  decision : String
  amountCents : Nat
  supportingEvidence : List EvidenceBinding
  expectedRevision : Nat
  resultingRevision : Nat
  decidedAtMs : Nat
  determinationDigest : Bytes
  inputEvaluationId : String
  inputEvaluationResultDigest : Bytes
deriving DecidableEq, Repr

structure OwnerAction where
  actionId : String
  obligationId : String
  determinationId : String
  kind : String
  status : String
  revision : Nat
  payloadDigest : Bytes
  createdAtMs : Nat
  acknowledgmentStatus : String
  acknowledgmentReference : Option String
  acknowledgmentAttempt : Nat
  acknowledgmentUpdatedAtMs : Nat
  acknowledgmentCashEffectCents : Nat
deriving DecidableEq, Repr

structure PackageCash where
  recordedReceivedCashCents : Nat
  cashSatisfied : Bool
  claimedAdjustmentCents : Nat
  lawfulAdjustmentCents : Nat
  amountSatisfied : Bool
  shortfallCents : Nat
  overageCents : Nat
  activePaymentCount : Nat
  authorizedAdjustmentCount : Nat
deriving DecidableEq, Repr

structure PackageReporting where
  complete : Bool
  evidenceCount : Nat
deriving DecidableEq, Repr

/-! `expectedCurrent` is the exact reference supplied with the Mirror request.
    An adapter must source it independently of the package bytes. The optional
    previous receipt is not present in the Owner package and is needed only to
    classify the determination's prior-evaluation support. -/
structure DecisionPackageInput where
  contract : String
  mirrorSchema : Option String
  resource : Option String
  scope : PackageScope
  obligation : PackageObligation
  populationBinding : Option OwnerPopulationBinding
  controlPack : PackageControlPack
  expectedCurrent : CurrentEvaluationExpectation
  currentReceipt : EvaluationReceipt
  priorReceipt : Option EvaluationReceipt
  currentCase : Option OwnerCase
  currentDetermination : Option OwnerDetermination
  currentAction : Option OwnerAction
  cash : PackageCash
  reporting : PackageReporting
  observedOriginRefs : List String
  engineResult : FinancialResult
deriving DecidableEq, Repr

structure PackageBalance where
  owedCents : Nat
  receivedCashCents : Nat
  claimedAdjustmentCents : Nat
  lawfulAdjustmentCents : Nat
  shortfallCents : Nat
  overageCents : Nat
  cashSatisfied : Bool
  amountSatisfied : Bool
deriving DecidableEq, Repr

structure DecisionPackageProjection where
  contract : String
  scope : PackageScope
  populationBinding : Knowledge OwnerPopulationBinding
  obligationId : String
  obligationRevision : Nat
  controlPackId : String
  controlPackVersion : Nat
  controlPackDigest : Bytes
  sourceRefs : List String
  evaluationId : String
  evaluationResultDigest : Bytes
  resultDigest : Bytes
  receiptDigest : Bytes
  currentReceipt : EvaluationReceipt
  inputSnapshotDigest : Knowledge Bytes
  caseId : Knowledge String
  caseReason : Knowledge String
  contractualAccountability : Knowledge String
  caseStatus : Knowledge String
  nextActionOwner : Knowledge String
  nextActionDeadlineMs : Knowledge Nat
  nextActionCommand : Knowledge String
  determinationId : Knowledge String
  claimId : Knowledge String
  decisionActorId : Knowledge String
  decisionActorRole : Knowledge String
  decisionAuthorityId : Knowledge String
  decisionAuthorityEpoch : Knowledge Nat
  decisionAuthorityDigest : Knowledge Bytes
  decision : Knowledge String
  decisionAmountCents : Knowledge Nat
  decisionSupportingEvidence : Knowledge (List EvidenceBinding)
  determinationDigest : Knowledge Bytes
  inputEvaluationId : Knowledge String
  inputEvaluationResultDigest : Knowledge Bytes
  decisionExpectedRevision : Knowledge Nat
  decisionResultingRevision : Knowledge Nat
  decisionAtMs : Knowledge Nat
  decisionSupport : DecisionSupport
  actionId : Knowledge String
  actionKind : Knowledge String
  actionKindMapping : Knowledge String
  actionStatus : Knowledge String
  acknowledgmentStatus : Knowledge String
  acknowledgmentReference : Knowledge String
  acknowledgmentCashEffectCents : Knowledge Nat
  balance : PackageBalance
  reportingComplete : Bool
  reportingEvidenceCount : Nat
  observedOriginRefs : List String
  commonCause : Knowledge String
deriving DecidableEq, Repr

end BlindLedger.Financial.DecisionPackage
