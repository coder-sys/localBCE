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

end BlindLedger.Financial.DecisionPackage
