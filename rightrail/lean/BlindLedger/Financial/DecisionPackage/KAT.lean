import BlindLedger.Financial.DecisionPackage.Codec

namespace BlindLedger.Financial.DecisionPackage

open BlindLedger.Financial

def katDigest (byte : Nat) : Bytes := List.replicate digestBytes (UInt8.ofNat byte)

def katHScope : PackageScope := {
  stateId := "fixture-state"
  deploymentId := "fixture-rightrail"
  programId := "fixture-provider-payment"
  periodId := "fixture-2026-period-01"
  currency := "USD"
}

def katHContext : FinancialContext := {
  ownerId := "synthetic-owner"
  mode := .TEST
  provenance := .ROOT
  stateId := katHScope.stateId
  deploymentId := katHScope.deploymentId
  programId := katHScope.programId
  periodId := katHScope.periodId
  populationId := "population:fixture-2026-01"
  itemId := "item-h"
  obligationId := "obligation:item-h:period-01"
  currency := "USD"
}

def katHEvidenceIds : List String :=
  [ "evidence:action-h:ack"
    , "evidence:cash-h:9700000"
    , "evidence:correction-h:authorization" ]

def katHEngineResult : FinancialResult := {
  context := katHContext
  authorityId := "synthetic-authority-v1"
  authorityEpoch := 1
  authorityDigest := katDigest 17
  packId := "control-pack:fixture-2026-01:v1"
  packDigest := katDigest 51
  beforeRevision := 3
  afterRevision := 4
  evaluatedAt := 1_774_926_000_000
  ruleVersion := 1
  evidenceIds := katHEvidenceIds
  completionAt := none
  owedCents := 10_000_000
  claimedAdjustmentCents := 0
  lawfulAdjustmentCents := 0
  receivedCashCents := 9_700_000
  shortfallCents := 300_000
  overageCents := 0
  cashSatisfied := false
  amountSatisfied := false
  timely := false
  reportingComplete := false
  verificationStatus := .SUPPORTED
  caseStatus := .CORRECTION_REQUIRED
  deliveryStatus := .ACKNOWLEDGED
}

def katHOwnerResult : OwnerEvaluationResult := {
  evaluationId := "evaluation:obligation:item-h:period-01:r4"
  obligationId := "obligation:item-h:period-01"
  revision := 4
  ruleVersion := 1
  evidenceIds := katHEvidenceIds
  authorityId := "synthetic-authority-v1"
  evaluatedAtMs := 1_774_926_000_000
  owedCents := 10_000_000
  claimedAdjustmentCents := 0
  lawfulAdjustmentCents := 0
  receivedCashCents := 9_700_000
  shortfallCents := 300_000
  overageCents := 0
  cashSatisfied := false
  amountSatisfied := false
  timely := false
  reportingComplete := false
  verificationStatus := "SUPPORTED"
  caseStatus := "CORRECTION_REQUIRED"
  deliveryStatus := "ACKNOWLEDGED"
}

def katHReceipt : EvaluationReceipt := {
  contractVersion := evaluationReceiptContractV1
  scope := katHScope
  controlPack := {
    packId := "control-pack:fixture-2026-01:v1"
    version := 1
    digest := katDigest 51
  }
  evidenceBindings := katHEvidenceIds.map (fun evidenceId => {
    evidenceId := evidenceId
    recordDigest := katDigest 68
  })
  inputSnapshotDigest := none
  authority := {
    authorityEpoch := 1
    authorityDigest := katDigest 17
  }
  result := katHOwnerResult
  resultDigest := katDigest 165
  receiptDigest := katDigest 90
  evaluationResultDigest := katDigest 165
}

def katHInput : DecisionPackageInput := {
  contract := decisionPackageContractV1
  mirrorSchema := some mirrorSchemaV1
  resource := some decisionPackageResource
  scope := katHScope
  obligation := {
    obligationId := "obligation:item-h:period-01"
    itemId := "item-h"
    populationId := .unknown
    periodId := katHScope.periodId
    currency := katHScope.currency
    revision := 4
    owedCents := 10_000_000
    claimedAdjustmentCents := 0
    lawfulAdjustmentCents := 0
    receivedCashCents := 9_700_000
    shortfallCents := 300_000
    overageCents := 0
    cashSatisfied := false
    amountSatisfied := false
    timely := false
    reportingComplete := false
    verificationStatus := "SUPPORTED"
    caseStatus := "CORRECTION_REQUIRED"
    deliveryStatus := "ACKNOWLEDGED"
    currentEvaluationId := some katHOwnerResult.evaluationId
    dueAtMs := 1_774_915_200_000
  }
  populationBinding := none
  controlPack := {
    packId := "control-pack:fixture-2026-01:v1"
    version := 1
    digest := katDigest 51
    calculationRuleId := "calculation:per-recipient:v1"
    adjustmentRuleId := "adjustment:offset:v1"
    sourceRefs := ["fixture-source:approved-schedule:v1"]
    authorizedRoles := ["FINANCE_DECISION", "CASE_OWNER", "REPORTING_EDITOR", "RECEIVER"]
    effectiveStartMs := 1_767_225_600_000
    effectiveEndMs := 1_775_001_600_000
    recordedAtMs := 1_767_139_200_000
    approvedAtMs := 1_767_182_400_000
  }
  expectedCurrent := {
    evaluationId := katHOwnerResult.evaluationId
    resultDigest := katDigest 165
  }
  currentReceipt := katHReceipt
  priorReceipt := none
  currentCase := some {
    caseId := "case:obligation:item-h:period-01"
    obligationId := "obligation:item-h:period-01"
    reason := "CORRECTION_REQUIRED"
    contractualAccountability := "PROGRAM_ACCOUNTABILITY"
    nextActionOwner := "CASE_OWNER"
    dueAtMs := 1_774_915_200_000
    status := "CORRECTION_REQUIRED"
    updatedAtMs := 1_774_922_400_000
  }
  currentDetermination := some {
    determinationId := "determination:fixture-h:correction-v1"
    obligationId := "obligation:item-h:period-01"
    claimId := some "claim:obligation-item-h:offset-v1"
    actorId := "actor:fixture-finance"
    actorRole := "FINANCE_DECISION"
    authorityId := "synthetic-authority-v1"
    authorityEpoch := 1
    authorityDigest := katDigest 17
    decision := "OFFSET_REJECTED_CORRECTION_AUTHORIZED"
    amountCents := 300_000
    supportingEvidence := [
      { evidenceId := "evidence:correction-h:authorization", recordDigest := katDigest 68 },
      { evidenceId := "evidence:offset-h:claim", recordDigest := katDigest 68 }
    ]
    expectedRevision := 2
    resultingRevision := 3
    decidedAtMs := 1_774_922_400_000
    determinationDigest := katDigest 72
    inputEvaluationId := "evaluation:obligation:item-h:period-01:r2"
    inputEvaluationResultDigest := katDigest 166
  }
  currentAction := some {
    actionId := "action:obligation-item-h:correction-v1"
    obligationId := "obligation:item-h:period-01"
    determinationId := "determination:fixture-h:correction-v1"
    kind := "CORRECTION_REQUEST"
    status := "ACKNOWLEDGED"
    revision := 2
    payloadDigest := katDigest 69
    createdAtMs := 1_774_922_400_000
    acknowledgmentStatus := "ACKNOWLEDGED"
    acknowledgmentReference := some "ack:correction:h:v1"
    acknowledgmentAttempt := 1
    acknowledgmentUpdatedAtMs := 1_774_926_000_000
    acknowledgmentCashEffectCents := 0
  }
  cash := {
    recordedReceivedCashCents := 9_700_000
    cashSatisfied := false
    claimedAdjustmentCents := 0
    lawfulAdjustmentCents := 0
    amountSatisfied := false
    shortfallCents := 300_000
    overageCents := 0
    activePaymentCount := 1
    authorizedAdjustmentCount := 0
  }
  reporting := { complete := false, evidenceCount := 0 }
  observedOriginRefs := [
    "origin:action:h:ack:v1",
    "origin:cash:h:v1",
    "origin:correction:h:v1"
  ]
  engineResult := katHEngineResult
}

def gateOwnerHAcknowledgment : Bool :=
  match projectDecisionPackage katHInput with
  | none => false
  | some value =>
      value.contract = decisionPackageContractV1 &&
        value.obligationId = "obligation:item-h:period-01" &&
        value.obligationRevision = 4 && value.balance.owedCents = 10_000_000 &&
        value.balance.receivedCashCents = 9_700_000 &&
        value.balance.shortfallCents = 300_000 &&
        value.balance.cashSatisfied = false && value.balance.amountSatisfied = false &&
        value.caseStatus = .known "CORRECTION_REQUIRED" &&
        value.nextActionOwner = .known "CASE_OWNER" &&
        value.nextActionDeadlineMs = .known 1_774_915_200_000 &&
        value.decision = .known "OFFSET_REJECTED_CORRECTION_AUTHORIZED" &&
        value.decisionAmountCents = .known 300_000 &&
        value.acknowledgmentStatus = .known "ACKNOWLEDGED" &&
        value.acknowledgmentReference = .known "ack:correction:h:v1" &&
        value.acknowledgmentCashEffectCents = .known 0 &&
        value.reportingComplete = false && value.reportingEvidenceCount = 0

def gateOwnerHUnknowns : Bool :=
  match projectDecisionPackage katHInput with
  | none => false
  | some value => value.decisionSupport = .UNKNOWN &&
      value.inputSnapshotDigest = .unknown && value.nextActionCommand = .unknown &&
      value.commonCause = .unknown && value.actionKindMapping = .unknown

def gateOwnerActionKindPreserved : Bool :=
  match projectDecisionPackage katHInput with
  | none => false
  | some value => value.actionKind = .known "CORRECTION_REQUEST" &&
      value.actionKindMapping = .unknown

def gateSourceRefsPreserved : Bool :=
  let repeated := { katHInput with controlPack :=
    { katHInput.controlPack with sourceRefs :=
      ["source:rule-a", "source:rule-a", "source:rule-b"] } }
  match projectDecisionPackage repeated, encodeDecisionPackageInput repeated with
  | some value, some wire =>
      value.sourceRefs = ["source:rule-a", "source:rule-a", "source:rule-b"] &&
        decodeDecisionPackageInput wire = some repeated &&
        (match decodeDecisionPackageInput wire with
        | none => false
        | some decoded => decoded.controlPack.sourceRefs =
            ["source:rule-a", "source:rule-a", "source:rule-b"])
  | _, _ => false

def gateCurrentReceiptBinding : Bool :=
  decisionPackageInputWellFormed katHInput &&
    (projectDecisionPackage katHInput).isSome

def gateCurrentReceiptPreserved : Bool :=
  match projectDecisionPackage katHInput with
  | none => false
  | some projection => projection.currentReceipt = katHReceipt &&
      projection.currentReceipt.evidenceBindings.map EvidenceBinding.evidenceId =
        katHEvidenceIds

def gateStaleObligationRevision : Bool :=
  let stale := { katHInput with obligation :=
    { katHInput.obligation with revision := katHInput.obligation.revision + 1 } }
  projectDecisionPackage stale = none

def gateStaleCurrentReceiptId : Bool :=
  let stale := { katHInput with expectedCurrent :=
    { katHInput.expectedCurrent with evaluationId := "evaluation:stale" } }
  projectDecisionPackage stale = none

def gateStaleCurrentReceiptDigest : Bool :=
  let stale := { katHInput with expectedCurrent :=
    { katHInput.expectedCurrent with resultDigest := katDigest 1 } }
  projectDecisionPackage stale = none

def gateNonzeroAcknowledgmentCashRejected : Bool :=
  let stale := { katHInput with
    currentAction := (katHInput.currentAction.map
      (fun action => { action with acknowledgmentCashEffectCents := 1 })) }
  projectDecisionPackage stale = none

def katHMirrorPopulationBinding : OwnerPopulationBinding := {
  populationId := .unknown
  status := "PUBLISHED"
  completeness := "EXACT"
  sourceComplete := true
  manifestId := .unknown
  manifestVersion := 1
  manifestDigest := .unknown
  memberId := .unknown
  memberCount := 20
  memberDigest := .unknown
}

def gateV2PopulationUnknown : Bool :=
  let value := { katHInput with
    contract := decisionPackageContractV2
    populationBinding := some katHMirrorPopulationBinding }
  match projectDecisionPackage value with
  | none => false
  | some projection =>
      match projection.populationBinding with
      | .unknown => false
      | .known binding => binding.populationId = .unknown &&
          binding.manifestId = .unknown && binding.manifestDigest = .unknown &&
          binding.memberId = .unknown && binding.memberDigest = .unknown &&
          binding.status = "PUBLISHED" && binding.completeness = "EXACT" &&
          binding.sourceComplete && binding.manifestVersion = 1 && binding.memberCount = 20

def katHPopulationBinding : OwnerPopulationBinding := {
  populationId := .known "population:fixture-2026-01"
  status := "PUBLISHED"
  completeness := "EXACT"
  sourceComplete := true
  manifestId := .known "population-manifest:fixture-2026-01:v1"
  manifestVersion := 1
  manifestDigest := .known (katDigest 70)
  memberId := .known "item-h"
  memberCount := 20
  memberDigest := .known (katDigest 71)
}

def gateV2PopulationBindingPreserved : Bool :=
  let value := { katHInput with
    contract := decisionPackageContractV2
    mirrorSchema := none
    resource := none
    populationBinding := some katHPopulationBinding }
  match projectDecisionPackage value, encodeDecisionPackageInput value with
  | some projection, some wire =>
      projection.populationBinding = .known katHPopulationBinding &&
        decodeDecisionPackageInput wire = some value
  | _, _ => false

def katHPriorReceipt : EvaluationReceipt := {
  katHReceipt with
  result := { katHOwnerResult with
    evaluationId := "evaluation:obligation:item-h:period-01:r2"
    revision := 2
  }
  resultDigest := katDigest 166
  receiptDigest := katDigest 91
  evaluationResultDigest := katDigest 166
}

def gatePriorReceiptSupportsDecision : Bool :=
  let value := { katHInput with priorReceipt := some katHPriorReceipt }
  match projectDecisionPackage value with
  | none => false
  | some projection => projection.decisionSupport = .SUPPORTED

def gateStalePriorReceiptRejected : Bool :=
  let staleReceipt := { katHPriorReceipt with
    resultDigest := katDigest 5
    evaluationResultDigest := katDigest 5
  }
  let value := { katHInput with priorReceipt := some staleReceipt }
  projectDecisionPackage value = none

def gateInputCodecRoundtrip : Bool :=
  match encodeDecisionPackageInput katHInput with
  | none => false
  | some wire => decisionPackageInputMagic.isPrefixOf wire &&
      decodeDecisionPackageInput wire = some katHInput

def gateProjectionCodecRoundtrip : Bool :=
  match projectDecisionPackage katHInput with
  | none => false
  | some projection =>
      match encodeDecisionPackageProjection projection with
      | none => false
      | some wire => decisionPackageProjectionMagic.isPrefixOf wire &&
          decodeDecisionPackageProjection wire = some projection

def gateInputTrailingBytesRejected : Bool :=
  match encodeDecisionPackageInput katHInput with
  | none => false
  | some wire => decodeDecisionPackageInput (wire ++ [UInt8.ofNat 0]) = none

def gateProjectionTrailingBytesRejected : Bool :=
  match projectDecisionPackage katHInput with
  | none => false
  | some projection =>
      match encodeDecisionPackageProjection projection with
      | none => false
      | some wire => decodeDecisionPackageProjection (wire ++ [UInt8.ofNat 0]) = none

def decisionPackageKatLines : List (String × Bool) :=
  [ ("owner_h_ack_cash_reporting_separation", gateOwnerHAcknowledgment)
    , ("owner_h_unknowns_are_explicit", gateOwnerHUnknowns)
    , ("owner_action_kind_not_relabelled", gateOwnerActionKindPreserved)
    , ("source_refs_order_and_repeats", gateSourceRefsPreserved)
    , ("current_receipt_exact_binding", gateCurrentReceiptBinding)
    , ("current_receipt_fields_preserved", gateCurrentReceiptPreserved)
    , ("stale_obligation_revision_rejected", gateStaleObligationRevision)
    , ("stale_current_receipt_id_rejected", gateStaleCurrentReceiptId)
    , ("stale_current_receipt_digest_rejected", gateStaleCurrentReceiptDigest)
    , ("stale_prior_receipt_rejected", gateStalePriorReceiptRejected)
    , ("prior_receipt_supports_decision", gatePriorReceiptSupportsDecision)
    , ("nonzero_ack_cash_effect_rejected", gateNonzeroAcknowledgmentCashRejected)
    , ("v2_mirror_redactions_are_unknown", gateV2PopulationUnknown)
    , ("v2_population_binding_preserved", gateV2PopulationBindingPreserved)
    , ("input_codec_roundtrip", gateInputCodecRoundtrip)
    , ("projection_codec_roundtrip", gateProjectionCodecRoundtrip)
    , ("input_trailing_bytes_rejected", gateInputTrailingBytesRejected)
    , ("projection_trailing_bytes_rejected", gateProjectionTrailingBytesRejected) ]

def decisionPackageKatCount : Nat := decisionPackageKatLines.length
def decisionPackageKatsPass : Bool :=
  decisionPackageKatLines.all (fun entry => entry.2)

end BlindLedger.Financial.DecisionPackage
