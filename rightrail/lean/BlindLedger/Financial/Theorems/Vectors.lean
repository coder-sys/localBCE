import BlindLedger.Financial.Codec
import BlindLedger.Financial.Evaluation

namespace BlindLedger.Financial

def katDigest : Bytes := List.replicate digestBytes (UInt8.ofNat 0)

def katContext : FinancialContext :=
  { ownerId := "continuity-test-owner-v1"
    mode := .TEST
    provenance := .ROOT
    stateId := "fixture-state"
    deploymentId := "fixture-rightrail"
    programId := "fixture-provider-payment"
    periodId := "fixture-2026-period-01"
    populationId := "population:fixture-2026-01"
    itemId := "item-h"
    obligationId := "obligation:item-h:period-01"
    currency := "USD" }

def katAuthority : TrustedAuthority :=
  { authorityId := "synthetic-authority-v1"
    epoch := 1
    digest := katDigest
    syntheticOnly := true
    actors := [
      { actorId := "synthetic-official"
        roles := ["FINANCE_DECISION", "CASE_OWNER"] }
      , { actorId := "synthetic-reporter"
          roles := ["REPORTING_EDITOR"] }
      , { actorId := "synthetic-receiver"
          roles := ["RECEIVER"] } ] }

def katPack : ControlPack :=
  { packId := "control-pack:fixture-2026-01:v1"
    stateId := katContext.stateId
    deploymentId := katContext.deploymentId
    programId := katContext.programId
    periodId := katContext.periodId
    currency := "USD"
    version := 1
    sourceRefs := ["fixture-source:approved-schedule:v1"]
    effectiveStart := 100
    effectiveEnd := 200
    recordedAt := 1
    approvedAt := 2
    calculationRuleId := "calculation:per-recipient:v1"
    adjustmentRuleId := "adjustment:offset:v1"
    authorizedRoles := supportedRoles
    expectedTests := supportedTestsV1
    digest := katDigest
    status := .APPROVED }

def katObligation (reportingComplete : Bool := false) : Obligation :=
  { populationId := katContext.populationId
    itemId := katContext.itemId
    obligationId := katContext.obligationId
    owedCents := 10_000_000
    dueAt := 1_774_915_200_000
    ruleVersion := 1
    reportingComplete := reportingComplete }

def katPayment (amount : Nat := 9_700_000) (eventAt : Nat := 1_774_828_800_000) : Payment :=
  { paymentId := "payment:h:cash"
    obligationId := katContext.obligationId
    itemId := katContext.itemId
    evidenceId := "evidence:cash"
    commonOriginId := "origin:cash:h"
    amountCents := amount
    eventAt := eventAt
    reversalEvidenceId := none
    status := .ACTIVE }

def katClaim (status : ClaimStatus := .AUTHORIZED) : Claim :=
  { claimId := "claim:h:offset"
    obligationId := katContext.obligationId
    evidenceId := "evidence:offset"
    amountCents := 300_000
    ownerRole := "CASE_OWNER"
    deadlineAt := 1_774_915_200_000
    status := status }

def katDetermination (decision : DeterminationDecision := .OFFSET_AUTHORIZED) : OffsetDetermination :=
  { determinationId := "determination:action:h:offset"
    obligationId := katContext.obligationId
    claimId := "claim:h:offset"
    actorId := "synthetic-official"
    actorRole := "FINANCE_DECISION"
    authorityId := katAuthority.authorityId
    authorityEpoch := katAuthority.epoch
    authorityDigest := katAuthority.digest
    decision := decision
    amountCents := 300_000
    supportingEvidenceIds := ["evidence:offset"]
    expectedRevision := 0
    resultingRevision := 1
    decidedAt := 1_774_864_800_000 }

def katCashEvidence (amount : Option Nat := some 9_700_000) : EvidenceRecord :=
  { evidenceId := "evidence:cash"
    obligationId := katContext.obligationId
    itemId := katContext.itemId
    kind := "PAYMENT_CONFIRMATION"
    commonOriginId := "origin:cash:h"
    sourceId := "fixture-payment-file"
    sourceVersion := "cash-v1"
    localRef := "ref:cash:h:v1"
    applicableAt := 1_774_828_800_000
    eventAt := 1_774_828_800_000
    receivedAt := 1_774_828_800_000
    amountCents := amount
    reversalOf := none
    supersedes := none }

def katOffsetEvidence : EvidenceRecord :=
  { evidenceId := "evidence:offset"
    obligationId := katContext.obligationId
    itemId := katContext.itemId
    kind := "OFFSET_CLAIM"
    commonOriginId := "claim:h:offset"
    sourceId := "fixture-official"
    sourceVersion := "authority-v1"
    localRef := "ref:offset:h:approval"
    applicableAt := 1_774_864_800_000
    eventAt := 1_774_864_800_000
    receivedAt := 1_774_864_800_000
    amountCents := some 300_000
    reversalOf := none
    supersedes := none }

def katBase : FinancialInput :=
  { context := katContext
    authority := katAuthority
    pack := katPack
    obligation := katObligation
    beforeRevision := 0
    evaluatedAt := 1_774_922_400_000
    payments := []
    claims := []
    determinations := []
    evidence := []
    conflicts := []
    cases := [
      { caseId := "case:h:base"
        obligationId := katContext.obligationId
        reason := "OPEN"
        nextActionOwner := "CASE_OWNER"
        dueAt := katObligation.dueAt
        status := .OPEN
        updatedAt := 1_774_864_800_000 }]
    actions := [] }

def katAuthorizedAction : ActionRecord :=
  { actionId := "action:h:offset"
    obligationId := katContext.obligationId
    determinationId := some "determination:action:h:offset"
    kind := "OFFSET_AUTHORIZATION"
    amountCents := 300_000
    currency := "USD"
    revision := 1
    status := .READY
    payloadDigest := katDigest
    createdAt := 1_774_864_800_000 }

def katAuthorized : FinancialInput :=
  { katBase with
    payments := [katPayment]
    claims := [katClaim]
    determinations := [katDetermination]
    evidence := [katCashEvidence, katOffsetEvidence]
    cases := [
      { caseId := "case:h:authorized"
        obligationId := katContext.obligationId
        reason := "OFFSET_AUTHORIZED"
        nextActionOwner := "CASE_OWNER"
        dueAt := katObligation.dueAt
        status := .AUTHORIZED
        updatedAt := 1_774_864_800_000 }]
    actions := [katAuthorizedAction] }

def katMissing : FinancialInput := katBase

def katMissingCase : FinancialInput := { katBase with cases := [] }

def katConflictEvidence : EvidenceRecord :=
  { evidenceId := "evidence:conflict"
    obligationId := katContext.obligationId
    itemId := katContext.itemId
    kind := "PAYMENT_CONFIRMATION"
    commonOriginId := "origin:cash:h"
    sourceId := "fixture-payment-file"
    sourceVersion := "cash-conflict-v1"
    localRef := "ref:cash:h:conflict"
    applicableAt := 1_774_828_800_000
    eventAt := 1_774_828_800_000
    receivedAt := 1_774_828_800_000
    amountCents := some 300_001
    reversalOf := none
    supersedes := none }

def katConflict : FinancialConflict :=
  { conflictId := "conflict:h:cash"
    obligationId := katContext.obligationId
    commonOriginId := "origin:cash:h"
    existingPaymentId := "payment:h:cash"
    candidateEvidenceId := "evidence:conflict"
    existingAmountCents := 9_700_000
    candidateAmountCents := 300_001
    reason := "CONFLICTING_COMMON_ORIGIN_AMOUNT"
    visibleAt := 1_774_828_800_000 }

def katConflictInput : FinancialInput :=
  { katAuthorized with
    evidence := [katCashEvidence, katConflictEvidence, katOffsetEvidence]
    conflicts := [katConflict] }

def katDuplicateEvidence : EvidenceRecord :=
  { katCashEvidence with
    evidenceId := "evidence:cash:duplicate"
    sourceVersion := "cash-duplicate-v1"
    localRef := "ref:cash:h:duplicate" }

def katDuplicateInput : FinancialInput :=
  { katAuthorized with
    evidence := [katCashEvidence, katDuplicateEvidence, katOffsetEvidence] }

def katReversalEvidence : EvidenceRecord :=
  { katCashEvidence with
    evidenceId := "evidence:reversal"
    kind := "PAYMENT_REVERSAL"
    commonOriginId := "reversal:payment:h:cash"
    sourceVersion := "cash-reversal-v1"
    localRef := "reversal:payment:h:cash"
    applicableAt := 1_774_900_000_000
    eventAt := 1_774_900_000_000
    receivedAt := 1_774_900_000_000
    reversalOf := some "payment:h:cash" }

def katReversedInput : FinancialInput :=
  { katAuthorized with
    payments := [
      { katPayment with
        reversalEvidenceId := some "evidence:reversal"
        status := .REVERSED }]
    evidence := [katCashEvidence, katOffsetEvidence, katReversalEvidence] }

def katRepeatedReversalEvidence : EvidenceRecord :=
  { katReversalEvidence with
    evidenceId := "evidence:reversal:duplicate"
    sourceVersion := "cash-reversal-duplicate-v1"
    localRef := "reversal:payment:h:cash:duplicate"
    eventAt := 1_774_901_000_000
    receivedAt := 1_774_901_000_000 }

def katRepeatedReversalInput : FinancialInput :=
  { katReversedInput with
    evidence := [katCashEvidence, katOffsetEvidence, katReversalEvidence,
      katRepeatedReversalEvidence] }

def katActiveReversalInput : FinancialInput :=
  { katAuthorized with
    evidence := [katCashEvidence, katOffsetEvidence, katReversalEvidence] }

def katAcknowledged : FinancialInput :=
  { katBase with
    evaluatedAt := 1_774_926_000_000
    claims := [
      { katClaim .REJECTED with
        claimId := "claim:h:correction"
        evidenceId := "evidence:correction" }]
    determinations := [
      { katDetermination .OFFSET_REJECTED_CORRECTION_AUTHORIZED with
        determinationId := "determination:action:h:correction"
        claimId := "claim:h:correction"
        supportingEvidenceIds := ["evidence:correction"]
        decidedAt := 1_774_925_000_000 }]
    evidence := [
      { katOffsetEvidence with
        evidenceId := "evidence:correction"
        commonOriginId := "claim:h:correction" }]
    actions := [
      { actionId := "action:h:correction"
        obligationId := katContext.obligationId
        determinationId := some "determination:action:h:correction"
        kind := "CORRECTION_PAYMENT_REQUEST"
        amountCents := 300_000
        currency := "USD"
        revision := 1
        status := .ACKNOWLEDGED
        payloadDigest := katDigest
        createdAt := 1_774_926_000_000 }] }

def katLate : FinancialInput :=
  { katBase with
    evaluatedAt := 1_775_010_000_000
    obligation := katObligation true
    payments := [
      { katPayment 10_000_000 1_775_001_600_000 with
        paymentId := "payment:h:late"
        evidenceId := "evidence:late"
        commonOriginId := "origin:late:h" }]
    evidence := [
      { katCashEvidence (some 10_000_000) with
        evidenceId := "evidence:late"
        commonOriginId := "origin:late:h"
        applicableAt := 1_775_001_600_000
        eventAt := 1_775_001_600_000
        receivedAt := 1_775_001_600_000 }] }

def katEqualTimeCrossSourceCollision : FinancialInput :=
  { katAuthorized with
    obligation := { katObligation with owedCents := 600_000 }
    payments := [
      { katPayment 300_000 1_774_864_800_000 with
        paymentId := "a-payment"
        commonOriginId := "origin:tie:cash" }]
    evidence := [
      { katCashEvidence (some 300_000) with
        commonOriginId := "origin:tie:cash"
        applicableAt := 1_774_864_800_000
        eventAt := 1_774_864_800_000
        receivedAt := 1_774_864_800_000 },
      katOffsetEvidence] }

def katOverflow : FinancialInput :=
  { katBase with
    obligation := { katObligation with
      owedCents := maxCents }
    payments := [
      { katPayment maxCents with
        paymentId := "payment:a"
        evidenceId := "evidence:a"
        commonOriginId := "origin:a" },
      { katPayment maxCents with
        paymentId := "payment:b"
        evidenceId := "evidence:b"
        commonOriginId := "origin:b" }]
    evidence := [
      { katCashEvidence (some maxCents) with
        evidenceId := "evidence:a"
        commonOriginId := "origin:a" },
      { katCashEvidence (some maxCents) with
        evidenceId := "evidence:b"
        commonOriginId := "origin:b" }] }

def katMalformedOrder : FinancialInput :=
  { katConflictInput with evidence := [katOffsetEvidence, katCashEvidence, katConflictEvidence] }

def katScopeMutation : FinancialInput :=
  { katAuthorized with payments := [{ katPayment with itemId := "foreign-item" }] }

def katAuthorityMutation : FinancialInput :=
  { katAuthorized with determinations := [{ katDetermination with authorityId := "other-authority" }] }

def katAuthorityAtEpoch (epoch : Nat) : FinancialInput :=
  { katAuthorized with
    authority := { katAuthorized.authority with epoch := epoch }
    determinations := katAuthorized.determinations.map (fun determination =>
      { determination with authorityEpoch := epoch }) }

def katActorMutation : FinancialInput :=
  { katAuthorized with determinations := [{ katDetermination with actorRole := "RECEIVER" }] }

def katLowercaseAuthorityRole : FinancialInput :=
  { katAuthorized with authority := { katAuthorized.authority with actors := [
      { actorId := "synthetic-official"
        roles := ["FINANCE_DECISION", "audit_viewer"] }
      , { actorId := "synthetic-reporter"
          roles := ["REPORTING_EDITOR"] }
      , { actorId := "synthetic-receiver"
          roles := ["RECEIVER"] } ] } }

def katAdditionalAuthorityRole : FinancialInput :=
  { katAuthorized with authority := { katAuthorized.authority with actors := [
      { actorId := "synthetic-official"
        roles := ["FINANCE_DECISION", "CASE_OWNER", "AUDIT_VIEWER"] }
      , { actorId := "synthetic-reporter"
          roles := ["REPORTING_EDITOR"] }
      , { actorId := "synthetic-receiver"
          roles := ["RECEIVER"] } ] } }

def katUnauthorizedCaseOwner : FinancialInput :=
  { katAuthorized with
    cases := katAuthorized.cases.map (fun caseRecord =>
      { caseRecord with nextActionOwner := "AUDIT_VIEWER" }) }

def katLowercaseCaseOwner : FinancialInput :=
  { katAuthorized with
    cases := katAuthorized.cases.map (fun caseRecord =>
      { caseRecord with nextActionOwner := "case_owner" }) }

def katLowercaseEvidenceKind : FinancialInput :=
  { katBase with evidence := [
      { katCashEvidence none with
        evidenceId := "evidence:generic"
        kind := "support_record" } ] }

def katZeroAmountGenericEvidence : FinancialInput :=
  { katBase with evidence := [
      { katCashEvidence (some 0) with
        evidenceId := "evidence:generic"
        kind := "SUPPORT_RECORD" } ] }

def katInvalidAuthorizedClaim : FinancialInput :=
  { katBase with
    claims := [katClaim]
    evidence := [katOffsetEvidence] }

def katPackOrderVariant : FinancialInput :=
  { katBase with
    pack := { katPack with
      sourceRefs := ["stored source ref with spaces"]
      authorizedRoles := ["RECEIVER", "FINANCE_DECISION", "REPORTING_EDITOR"] }
    cases := katBase.cases.map (fun caseRecord =>
      { caseRecord with nextActionOwner := "RECEIVER" }) }

def katPackRepeatedReferenceVariant : FinancialInput :=
  { katBase with
    pack := { katPack with
      sourceRefs := ["stored source ref with spaces", "stored source ref with spaces"]
      authorizedRoles := ["RECEIVER", "FINANCE_DECISION", "REPORTING_EDITOR"] }
    cases := katBase.cases.map (fun caseRecord =>
      { caseRecord with nextActionOwner := "RECEIVER" }) }

def katLawfulDetermination : OffsetDetermination :=
  { katDetermination with
    determinationId := "determination:action:h:lawful"
    claimId := "claim:h:lawful"
    amountCents := 100
    supportingEvidenceIds := ["evidence:lawful"]
    decidedAt := 1_774_800_000_000 }

def katLawfulAction : ActionRecord :=
  { katAuthorizedAction with
    actionId := "action:h:lawful"
    determinationId := some "determination:action:h:lawful"
    amountCents := 100
    createdAt := 1_774_800_000_000 }

def katLawfulFallback : FinancialInput :=
  { katBase with
    obligation := { katObligation with owedCents := 100 }
    payments := [
      { katPayment 1 1_774_800_000_000 with
        paymentId := "payment:h:lawful"
        commonOriginId := "origin:lawful:h" }]
    claims := [
      { katClaim .AUTHORIZED with
        claimId := "claim:h:lawful"
        evidenceId := "evidence:lawful"
        amountCents := 100 }]
    evidence := [
      { katCashEvidence (some 1) with
        commonOriginId := "origin:lawful:h"
        applicableAt := 1_774_800_000_000
        eventAt := 1_774_800_000_000
        receivedAt := 1_774_800_000_000 }
      , { katOffsetEvidence with
          evidenceId := "evidence:lawful"
          commonOriginId := "claim:h:lawful"
          amountCents := some 100 }]
    determinations := [katLawfulDetermination]
    actions := [katLawfulAction] }

def katHistorical : FinancialInput :=
  { katAcknowledged with beforeRevision := 1 }

def katLatestAction : FinancialInput :=
  { katAuthorized with
    evaluatedAt := 1_774_950_000_000
    beforeRevision := 1
    claims := [
      { katClaim .REJECTED with
        claimId := "claim:h:correction"
        evidenceId := "evidence:correction" }
      , katClaim]
    determinations := [
      { katDetermination .OFFSET_REJECTED_CORRECTION_AUTHORIZED with
        determinationId := "determination:action:h:correction"
        claimId := "claim:h:correction"
        supportingEvidenceIds := ["evidence:correction"]
        expectedRevision := 1
        resultingRevision := 2
        decidedAt := 1_774_899_000_000 }
      , katDetermination]
    evidence := [katCashEvidence,
      { katOffsetEvidence with
        evidenceId := "evidence:correction"
        commonOriginId := "claim:h:correction" }, katOffsetEvidence]
    actions := [
      { actionId := "action:h:correction"
        obligationId := katContext.obligationId
        determinationId := some "determination:action:h:correction"
        kind := "CORRECTION_PAYMENT_REQUEST"
        amountCents := 300_000
        currency := "USD"
        revision := 2
        status := .ACKNOWLEDGED
        payloadDigest := katDigest
        createdAt := 1_774_900_000_000 }
      , katAuthorizedAction ] }

def replaceByte : Nat → UInt8 → Bytes → Bytes
  | _, _, [] => []
  | 0, replacement, _ :: rest => replacement :: rest
  | index + 1, replacement, first :: rest => first :: replaceByte index replacement rest

def katWire : Bytes := rawEncodeFinancialInput katAuthorized

def katEqualTimeCrossSourceWire : Bytes :=
  rawEncodeFinancialInput katEqualTimeCrossSourceCollision

def katResultWire : Option Bytes :=
  match evaluate katAuthorized with
  | none => none
  | some result => encodeFinancialResult result

def gateAuthorizedEvaluation : Bool :=
  match evaluate katAuthorized with
  | none => false
  | some result =>
      result.receivedCashCents = 9_700_000 &&
      result.claimedAdjustmentCents = 300_000 &&
      result.lawfulAdjustmentCents = 300_000 &&
      result.amountSatisfied && !result.cashSatisfied &&
      result.caseStatus = .ACTIONED && result.deliveryStatus = .READY

def gateMissingEvidence : Bool :=
  match evaluate katMissing, evaluate katZeroAmountGenericEvidence with
  | some missing, some zeroAmount =>
      missing.verificationStatus = .MISSING_EVIDENCE &&
        missing.caseStatus = .OPEN && !missing.amountSatisfied &&
        zeroAmount.verificationStatus = .SUPPORTED && zeroAmount.receivedCashCents = 0
  | _, _ => false

def gateConflictPrecedence : Bool :=
  match evaluate katConflictInput with
  | none => false
  | some result => result.verificationStatus = .CONFLICT_VISIBLE

def gateAckIsNotCash : Bool :=
  match evaluate katAcknowledged with
  | none => false
  | some result => result.receivedCashCents = 0 &&
      result.deliveryStatus = .ACKNOWLEDGED && !result.amountSatisfied

def gateEqualTimeCrossSourceCollision : Bool :=
  match decodeFinancialInput katEqualTimeCrossSourceWire with
  | none => false
  | some decoded =>
      match decoded.determinations, decoded.payments, evaluate decoded,
          specification decoded with
      | [determination], [payment], some result, some expected =>
          let leanOrder := evalSortContributions (evalContributions decoded)
          let ownerStableOrder : List SpecContribution := [
            { time := determination.decidedAt
              identity := determination.determinationId
              amountCents := determination.amountCents },
            { time := payment.eventAt
              identity := payment.paymentId
              amountCents := payment.amountCents }]
          let collisionTime := 1_774_864_800_000
          decoded = katEqualTimeCrossSourceCollision &&
            leanOrder.map EvalContribution.identity =
              ["a-payment", "determination:action:h:offset"] &&
            ownerStableOrder.map SpecContribution.identity =
              ["determination:action:h:offset", "a-payment"] &&
            evalCompletionLoop decoded.obligation.owedCents 0 leanOrder =
              some collisionTime &&
            specCompletionLoop decoded.obligation.owedCents 0 ownerStableOrder =
              some collisionTime &&
            result.completionAt = some collisionTime &&
            expected.completionAt = some collisionTime
      | _, _, _, _ => false

def gateLateCompletion : Bool :=
  match evaluate katLate with
  | none => false
  | some result => result.completionAt = some 1_775_001_600_000 &&
      result.amountSatisfied && !result.timely && result.caseStatus = .RESOLVED &&
      gateEqualTimeCrossSourceCollision

def gateOverflowRejects : Bool := evaluate katOverflow = none
def gateMalformedOrderRejects : Bool := evaluate katMalformedOrder = none
def gateScopeRejects : Bool := evaluate katScopeMutation = none
def gateAuthorityRejects : Bool :=
  evaluate katAuthorityMutation = none &&
    (evaluate (katAuthorityAtEpoch maxAuthorityEpoch)).isSome &&
    evaluate (katAuthorityAtEpoch (maxAuthorityEpoch + 1)) = none
def gateActorRejects : Bool :=
  evaluate katActorMutation = none && evaluate katLowercaseAuthorityRole = none &&
    financialInputWellFormed katAdditionalAuthorityRole
def gateInvalidAuthorizedClaimRejects : Bool := evaluate katInvalidAuthorizedClaim = none

def gateDuplicateConfirmationPreserved : Bool :=
  match evaluate katDuplicateInput with
  | none => false
  | some result => result.receivedCashCents = 9_700_000 &&
      result.evidenceIds = ["evidence:cash", "evidence:cash:duplicate", "evidence:offset"]

def gateActiveReversalRejects : Bool := evaluate katActiveReversalInput = none

def gateReversedPaymentExcludesCash : Bool :=
  match evaluate katReversedInput with
  | none => false
  | some result => result.receivedCashCents = 0 && !result.amountSatisfied

def gateRepeatedReversalIsPreserved : Bool :=
  match evaluate katRepeatedReversalInput with
  | none => false
  | some result => result.receivedCashCents = 0 &&
      result.evidenceIds = ["evidence:cash", "evidence:offset", "evidence:reversal",
        "evidence:reversal:duplicate"]

def gatePackStoredOrderAccepted : Bool :=
  match evaluate katPackOrderVariant with
  | none => false
  | some result => result.packId = katPack.packId

def gatePackRepeatedReferencePreserved : Bool :=
  let input := katPackRepeatedReferenceVariant
  if financialInputWellFormed input then
    let wire := rawEncodeFinancialInput input
    rawEncodeFinancialInput input ≠ rawEncodeFinancialInput katPackOrderVariant &&
      match decodeFinancialInput wire with
      | none => false
      | some decoded =>
          decoded.pack.sourceRefs =
              ["stored source ref with spaces", "stored source ref with spaces"] &&
            decoded.pack.sourceRefs = input.pack.sourceRefs &&
            decoded.pack.digest = input.pack.digest
  else false

def gateLawfulCompletionFallback : Bool :=
  match evaluate katLawfulFallback with
  | none => false
  | some result => result.completionAt = some 1_774_800_000_000 &&
      result.amountSatisfied && result.lawfulAdjustmentCents = 100

def gateHistoricalRevisionBinding : Bool := financialInputWellFormed katHistorical

def gateLatestDeliveryUsesTime : Bool :=
  match evaluate katLatestAction with
  | none => false
  | some result => result.deliveryStatus = .ACKNOWLEDGED

def gateDirectAddBounds : Bool :=
  evalAdd 0 (maxCents + 1) = none && specAdd 0 (maxCents + 1) = none

def gateCodecRoundtrip : Bool :=
  decodeFinancialInput katWire = some katAuthorized

def gateTrailingBytesReject : Bool :=
  decodeFinancialInput (katWire ++ [UInt8.ofNat 0]) = none

def gateMutationRejects : Bool :=
  decodeFinancialInput (UInt8.ofNat 0 :: katWire.tail!) = none &&
    decodeFinancialInput (rawEncodeFinancialInput katMissingCase) = none &&
    evaluate katLowercaseEvidenceKind = none && evaluate katUnauthorizedCaseOwner = none &&
    evaluate katLowercaseCaseOwner = none && evaluate katMissingCase = none

def gateEnumMutationRejects : Bool :=
  let offset := financialCodecMagic.length + (encodeString katContext.ownerId).length
  decodeFinancialInput (replaceByte offset (UInt8.ofNat 9) katWire) = none

def gateCountOverflowRejects : Bool :=
  let wirePrefix := financialCodecMagic ++ encodeContext katAuthorized.context ++
    encodeAuthority katAuthorized.authority ++ encodeControlPack katAuthorized.pack ++
    encodeObligation katAuthorized.obligation ++ natBE 8 katAuthorized.beforeRevision ++
    natBE 8 katAuthorized.evaluatedAt
  let offset := wirePrefix.length
  let mutated := replaceByte (offset + 0) (UInt8.ofNat 39)
    (replaceByte (offset + 1) (UInt8.ofNat 17) katWire)
  decodeFinancialInput mutated = none

def gateResultCodecRoundtrip : Bool :=
  match evaluate katAuthorized, katResultWire with
  | some result, some wire => decodeFinancialResult wire = some result
  | _, _ => false

def gateResultTrailingBytesReject : Bool :=
  match katResultWire with
  | some wire => decodeFinancialResult (wire ++ [UInt8.ofNat 0]) = none
  | none => false

def gateResultMutationRejects : Bool :=
  match katResultWire with
  | some wire => decodeFinancialResult (replaceByte 0 (UInt8.ofNat 0) wire) = none
  | none => false

def gateIndependentSpecification : Bool :=
  match decodeFinancialInput katWire with
  | none => false
  | some decoded =>
      match evaluate decoded, specification decoded with
      | some result, some expected =>
          decoded = katAuthorized &&
          result.context = decoded.context &&
          result.authorityId = decoded.authority.authorityId &&
          result.authorityEpoch = decoded.authority.epoch &&
          result.authorityDigest = decoded.authority.digest &&
          result.packId = decoded.pack.packId &&
          result.packDigest = decoded.pack.digest &&
          result.beforeRevision = decoded.beforeRevision &&
          result.afterRevision = decoded.beforeRevision + 1 &&
          result.evaluatedAt = decoded.evaluatedAt &&
          result.ruleVersion = decoded.obligation.ruleVersion &&
          result.evidenceIds = expected.evidenceIds &&
          result.completionAt = expected.completionAt &&
          result.owedCents = expected.owedCents &&
          result.claimedAdjustmentCents = expected.claimedAdjustmentCents &&
          result.lawfulAdjustmentCents = expected.lawfulAdjustmentCents &&
          result.receivedCashCents = expected.receivedCashCents &&
          result.shortfallCents = expected.shortfallCents &&
          result.overageCents = expected.overageCents &&
          result.cashSatisfied = expected.cashSatisfied &&
          result.amountSatisfied = expected.amountSatisfied &&
          result.timely = expected.timely &&
          result.reportingComplete = expected.reportingComplete &&
          result.verificationStatus = expected.verificationStatus &&
          result.caseStatus = expected.caseStatus &&
          result.deliveryStatus = expected.deliveryStatus
      | _, _ => false


end BlindLedger.Financial
