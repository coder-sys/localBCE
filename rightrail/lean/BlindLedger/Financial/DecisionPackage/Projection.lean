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

def optionalPackageDigestWellFormed : Option Bytes → Bool
  | none => true
  | some value => packageDigestWellFormed value

def packageScopeWellFormed (scope : PackageScope) : Bool :=
  boundedPackageId scope.stateId && boundedPackageId scope.deploymentId &&
    boundedPackageId scope.programId && boundedPackageId scope.periodId &&
    boundedPackageId scope.currency

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

end BlindLedger.Financial.DecisionPackage
