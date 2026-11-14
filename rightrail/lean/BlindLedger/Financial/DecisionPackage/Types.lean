import BlindLedger.Financial.Types

namespace BlindLedger.Financial.DecisionPackage

open BlindLedger.Financial

/-! Engine-owned, read-only types for the Owner evaluation receipt that the
    correction transition reads and writes. -/

def evaluationReceiptContractV1 : String := "RR/FINANCIAL/EVALUATION-RECEIPT/v1"
structure PackageScope where
  stateId : String
  deploymentId : String
  programId : String
  periodId : String
  currency : String
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
