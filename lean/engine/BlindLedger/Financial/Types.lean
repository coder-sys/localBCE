import Std

namespace BlindLedger.Financial

/-!
  Additive, nonactivating financial-obligation boundary.

  The reference owner uses these application bounds: IDs are at most 128
  ASCII bytes, free text is at most 512 UTF-8 bytes, digests are 64 bytes,
  amounts and times are non-negative and at most `2^63 - 1`, each complete
  input set is capped at 10,000 rows, and one encoded input is capped at 8 MiB.
  Authority epochs use the owner's signed SQLite integer range.
  These are deliberately separate from the existing clearance-kernel wire
  grammar and from the native proof predicate.
 -/

abbrev Bytes := List UInt8

def maxCents : Nat := (2 : Nat) ^ 63 - 1
def maxTime : Nat := maxCents
def maxRevision : Nat := 10_000
/-- SQLite INTEGER ceiling used by the owner for persisted authority epochs. -/
def maxAuthorityEpoch : Nat := maxCents
def maxRows : Nat := 10_000
def maxIdBytes : Nat := 128
def maxTextBytes : Nat := 512
def digestBytes : Nat := 64
def maxTotalEncodedBytes : Nat := 8 * 1024 * 1024

inductive OwnerMode where
  | LIVE
  | SHADOW
  | TEST
deriving DecidableEq, Repr

inductive Provenance where
  | ROOT
  | CONTINUITY_RESTORE
deriving DecidableEq, Repr

inductive PackStatus where
  | APPROVED
  | REVOKED
deriving DecidableEq, Repr

inductive PaymentStatus where
  | ACTIVE
  | REVERSED
deriving DecidableEq, Repr

inductive ClaimStatus where
  | CLAIMED
  | AUTHORIZED
  | REJECTED
deriving DecidableEq, Repr

inductive DeterminationDecision where
  | OFFSET_AUTHORIZED
  | OFFSET_REJECTED_CORRECTION_AUTHORIZED
deriving DecidableEq, Repr

inductive CaseStatus where
  | OPEN
  | AUTHORIZED
  | CORRECTION_REQUIRED
  | ACTIONED
  | RESOLVED
deriving DecidableEq, Repr

inductive ActionStatus where
  | READY
  | ACKNOWLEDGED
  | CANCELLED
deriving DecidableEq, Repr

inductive VerificationStatus where
  | MISSING_EVIDENCE
  | SUPPORTED
  | CONFLICT_VISIBLE
deriving DecidableEq, Repr

inductive DeliveryStatus where
  | NONE
  | READY
  | ACKNOWLEDGED
  | CANCELLED
deriving DecidableEq, Repr

inductive EvaluationReject where
  | INVALID_INPUT
  | SCOPE_MISMATCH
  | AUTHORITY_MISMATCH
  | CONTROL_PACK_MISMATCH
  | CONTRADICTION
  | OVERFLOW
  | NON_CANONICAL
deriving DecidableEq, Repr

structure FinancialContext where
  ownerId : String
  mode : OwnerMode
  provenance : Provenance
  stateId : String
  deploymentId : String
  programId : String
  periodId : String
  populationId : String
  itemId : String
  obligationId : String
  currency : String
deriving DecidableEq, Repr

structure AuthorityActor where
  actorId : String
  roles : List String
deriving DecidableEq, Repr

structure TrustedAuthority where
  authorityId : String
  epoch : Nat
  digest : Bytes
  syntheticOnly : Bool
  actors : List AuthorityActor
deriving DecidableEq, Repr

structure ControlPack where
  packId : String
  stateId : String
  deploymentId : String
  programId : String
  periodId : String
  currency : String
  version : Nat
  sourceRefs : List String
  effectiveStart : Nat
  effectiveEnd : Nat
  recordedAt : Nat
  approvedAt : Nat
  calculationRuleId : String
  adjustmentRuleId : String
  authorizedRoles : List String
  expectedTests : List String
  digest : Bytes
  status : PackStatus
deriving DecidableEq, Repr

structure Obligation where
  populationId : String
  itemId : String
  obligationId : String
  owedCents : Nat
  dueAt : Nat
  ruleVersion : Nat
  reportingComplete : Bool
deriving DecidableEq, Repr

structure Payment where
  paymentId : String
  obligationId : String
  itemId : String
  evidenceId : String
  commonOriginId : String
  amountCents : Nat
  eventAt : Nat
  reversalEvidenceId : Option String
  status : PaymentStatus
deriving DecidableEq, Repr

structure Claim where
  claimId : String
  obligationId : String
  evidenceId : String
  amountCents : Nat
  ownerRole : String
  deadlineAt : Nat
  status : ClaimStatus
deriving DecidableEq, Repr

structure OffsetDetermination where
  determinationId : String
  obligationId : String
  claimId : String
  actorId : String
  actorRole : String
  authorityId : String
  authorityEpoch : Nat
  authorityDigest : Bytes
  decision : DeterminationDecision
  amountCents : Nat
  supportingEvidenceIds : List String
  expectedRevision : Nat
  resultingRevision : Nat
  decidedAt : Nat
deriving DecidableEq, Repr

structure EvidenceRecord where
  evidenceId : String
  obligationId : String
  itemId : String
  kind : String
  commonOriginId : String
  sourceId : String
  sourceVersion : String
  localRef : String
  applicableAt : Nat
  eventAt : Nat
  receivedAt : Nat
  amountCents : Option Nat
  reversalOf : Option String
  supersedes : Option String
deriving DecidableEq, Repr

structure FinancialConflict where
  conflictId : String
  obligationId : String
  commonOriginId : String
  existingPaymentId : String
  candidateEvidenceId : String
  existingAmountCents : Nat
  candidateAmountCents : Nat
  reason : String
  visibleAt : Nat
deriving DecidableEq, Repr

structure CaseRecord where
  caseId : String
  obligationId : String
  reason : String
  nextActionOwner : String
  dueAt : Nat
  status : CaseStatus
  updatedAt : Nat
deriving DecidableEq, Repr

structure ActionRecord where
  actionId : String
  obligationId : String
  determinationId : Option String
  kind : String
  amountCents : Nat
  currency : String
  revision : Nat
  status : ActionStatus
  payloadDigest : Bytes
  createdAt : Nat
deriving DecidableEq, Repr

structure FinancialInput where
  context : FinancialContext
  authority : TrustedAuthority
  pack : ControlPack
  obligation : Obligation
  beforeRevision : Nat
  evaluatedAt : Nat
  payments : List Payment
  claims : List Claim
  determinations : List OffsetDetermination
  evidence : List EvidenceRecord
  conflicts : List FinancialConflict
  cases : List CaseRecord
  actions : List ActionRecord
deriving DecidableEq, Repr

structure FinancialResult where
  context : FinancialContext
  authorityId : String
  authorityEpoch : Nat
  authorityDigest : Bytes
  packId : String
  packDigest : Bytes
  beforeRevision : Nat
  afterRevision : Nat
  evaluatedAt : Nat
  ruleVersion : Nat
  evidenceIds : List String
  completionAt : Option Nat
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
  verificationStatus : VerificationStatus
  caseStatus : CaseStatus
  deliveryStatus : DeliveryStatus
deriving DecidableEq, Repr

def byteNat (byte : UInt8) : Nat := byte.toNat

def asciiAlpha (byte : UInt8) : Bool :=
  let value := byteNat byte
  (65 ≤ value && value ≤ 90) || (97 ≤ value && value ≤ 122)

def asciiUpperAlpha (byte : UInt8) : Bool :=
  let value := byteNat byte
  65 ≤ value && value ≤ 90

def asciiDigit (byte : UInt8) : Bool :=
  let value := byteNat byte
  48 ≤ value && value ≤ 57

def asciiAlphaNumeric (byte : UInt8) : Bool :=
  asciiAlpha byte || asciiDigit byte

def asciiIdTail (byte : UInt8) : Bool :=
  asciiAlphaNumeric byte || byteNat byte = 46 || byteNat byte = 95 ||
    byteNat byte = 58 || byteNat byte = 45

def idWellFormed (value : String) : Bool :=
  let bytes := value.toUTF8.toList
  bytes.length ≥ 1 && bytes.length ≤ maxIdBytes &&
    match bytes with
    | [] => false
    | first :: rest => asciiAlphaNumeric first && rest.all asciiIdTail

def textWellFormed (value : String) : Bool :=
  let bytes := value.toUTF8.toList
  bytes.length ≥ 1 && bytes.length ≤ maxTextBytes &&
    bytes.all (fun byte => byteNat byte ≠ 0)

def tokenWellFormed (value : String) : Bool :=
  let bytes := value.toUTF8.toList
  bytes.length ≥ 1 && bytes.length ≤ 64 &&
    match bytes with
    | [] => false
    | first :: rest => asciiUpperAlpha first &&
        rest.all (fun byte => asciiUpperAlpha byte || asciiDigit byte || byteNat byte = 95)

def roleWellFormed (value : String) : Bool := tokenWellFormed value
def kindWellFormed (value : String) : Bool := tokenWellFormed value

def digestWellFormed (value : Bytes) : Bool := value.length = digestBytes

def amountWellFormed (value : Nat) : Bool := value ≤ maxCents
def positiveAmountWellFormed (value : Nat) : Bool := value > 0 && amountWellFormed value
def timeWellFormed (value : Nat) : Bool := value ≤ maxTime
def revisionWellFormed (value : Nat) : Bool := value ≤ maxRevision

def noDuplicates : List String → Bool
  | [] => true
  | value :: rest => !rest.contains value && noDuplicates rest

def strictlyAscending : List String → Bool
  | [] => true
  | [_] => true
  | first :: second :: rest => decide (first < second) && strictlyAscending (second :: rest)

def canonicalIdList (values : List String) : Bool :=
  values.length ≤ maxRows && values.all idWellFormed && strictlyAscending values

def boundedTextList (values : List String) : Bool :=
  values.length ≤ maxRows && values.all textWellFormed

def optionalIdWellFormed : Option String → Bool
  | none => true
  | some value => idWellFormed value

def findPayment : List Payment → String → Option Payment
  | [], _ => none
  | payment :: rest, identity =>
      if payment.paymentId = identity then some payment else findPayment rest identity

def findClaim : List Claim → String → Option Claim
  | [], _ => none
  | claim :: rest, identity =>
      if claim.claimId = identity then some claim else findClaim rest identity

def findEvidence : List EvidenceRecord → String → Option EvidenceRecord
  | [], _ => none
  | evidence :: rest, identity =>
      if evidence.evidenceId = identity then some evidence else findEvidence rest identity

def findDetermination : List OffsetDetermination → String → Option OffsetDetermination
  | [], _ => none
  | determination :: rest, identity =>
      if determination.determinationId = identity then some determination
      else findDetermination rest identity

def findAuthorityActor : List AuthorityActor → String → Option AuthorityActor
  | [], _ => none
  | actor :: rest, identity =>
      if actor.actorId = identity then some actor else findAuthorityActor rest identity

def allReferencesExist (known : List String) (references : List String) : Bool :=
  references.all (fun identity => known.contains identity)

def supportedRoles : List String :=
  ["FINANCE_DECISION", "CASE_OWNER", "REPORTING_EDITOR", "RECEIVER"]

def requiredRoles : List String :=
  ["FINANCE_DECISION", "REPORTING_EDITOR", "RECEIVER"]

def supportedTestsV1 : List String :=
  ["program-total=100000000", "H-owed=10000000", "other-total=90000000", "timeliness-separate"]

def supportedTestsV2 : List String :=
  ["period-02-uses-rule-v2", "period-01-evaluation-preserved", "retrospective-authority-required"]

def authorityActorWellFormed (actor : AuthorityActor) : Bool :=
  idWellFormed actor.actorId && actor.roles.length ≥ 1 && actor.roles.length ≤ maxRows &&
    actor.roles.all roleWellFormed && noDuplicates actor.roles

def authorityWellFormed (authority : TrustedAuthority) : Bool :=
  idWellFormed authority.authorityId && authority.epoch ≥ 1 &&
    authority.epoch ≤ maxAuthorityEpoch && digestWellFormed authority.digest &&
    authority.syntheticOnly && authority.actors.length ≥ 1 &&
    authority.actors.length ≤ maxRows &&
    noDuplicates (authority.actors.map AuthorityActor.actorId) &&
    authority.actors.all authorityActorWellFormed

def authorizedRolesWellFormed (roles : List String) : Bool :=
  roles.length ≤ maxRows && roles.all roleWellFormed && noDuplicates roles &&
    roles.all (fun role => supportedRoles.contains role) &&
    requiredRoles.all (fun role => roles.contains role)

def sourceRefsWellFormed (sourceRefs : List String) : Bool :=
  sourceRefs.length ≥ 1 && boundedTextList sourceRefs

def authorityActorBindingWellFormed (authority : TrustedAuthority)
    (actorId actorRole : String) : Bool :=
  match findAuthorityActor authority.actors actorId with
  | none => false
  | some actor => actor.roles.contains actorRole

def contextWellFormed (context : FinancialContext) : Bool :=
  [context.ownerId, context.stateId, context.deploymentId, context.programId,
    context.periodId, context.populationId, context.itemId, context.obligationId].all idWellFormed &&
    context.currency = "USD" &&
    match context.provenance with
    | .ROOT => true
    | .CONTINUITY_RESTORE => context.mode ≠ .LIVE

def controlPackRulesWellFormed (pack : ControlPack) : Bool :=
  (pack.version = 1 && pack.calculationRuleId = "calculation:per-recipient:v1" &&
      pack.adjustmentRuleId = "adjustment:offset:v1" && pack.expectedTests = supportedTestsV1) ||
    (pack.version = 2 && pack.calculationRuleId = "calculation:per-recipient:v2" &&
      pack.adjustmentRuleId = "adjustment:offset:v2" && pack.expectedTests = supportedTestsV2)

def controlPackWellFormed (pack : ControlPack) : Bool :=
    [pack.packId, pack.stateId, pack.deploymentId, pack.programId, pack.periodId,
    pack.currency, pack.calculationRuleId, pack.adjustmentRuleId].all idWellFormed &&
    pack.currency = "USD" && pack.version ≥ 1 && pack.version ≤ maxRevision &&
    sourceRefsWellFormed pack.sourceRefs &&
    timeWellFormed pack.effectiveStart && timeWellFormed pack.effectiveEnd &&
    timeWellFormed pack.recordedAt && timeWellFormed pack.approvedAt &&
    pack.effectiveStart < pack.effectiveEnd && pack.recordedAt ≤ pack.approvedAt &&
    authorizedRolesWellFormed pack.authorizedRoles &&
    pack.expectedTests.length ≤ maxRows && pack.expectedTests.all textWellFormed &&
    digestWellFormed pack.digest && pack.status = .APPROVED &&
    controlPackRulesWellFormed pack

def obligationWellFormed (obligation : Obligation) : Bool :=
  [obligation.populationId, obligation.itemId, obligation.obligationId].all idWellFormed &&
    positiveAmountWellFormed obligation.owedCents && timeWellFormed obligation.dueAt &&
    obligation.ruleVersion ≥ 1 && obligation.ruleVersion ≤ maxRevision

def paymentWellFormed (context : FinancialContext) (payment : Payment) : Bool :=
  [payment.paymentId, payment.obligationId, payment.itemId, payment.evidenceId,
    payment.commonOriginId].all idWellFormed &&
    payment.obligationId = context.obligationId && payment.itemId = context.itemId &&
    positiveAmountWellFormed payment.amountCents && timeWellFormed payment.eventAt &&
    optionalIdWellFormed payment.reversalEvidenceId

def claimWellFormed (context : FinancialContext) (claim : Claim) : Bool :=
  [claim.claimId, claim.obligationId, claim.evidenceId].all idWellFormed &&
    roleWellFormed claim.ownerRole && claim.obligationId = context.obligationId &&
    positiveAmountWellFormed claim.amountCents && timeWellFormed claim.deadlineAt &&
    match claim.status with
    | .CLAIMED | .AUTHORIZED | .REJECTED => true

def evidenceWellFormed (context : FinancialContext) (evidence : EvidenceRecord) : Bool :=
  [evidence.evidenceId, evidence.obligationId, evidence.itemId, evidence.commonOriginId,
    evidence.sourceId, evidence.sourceVersion, evidence.localRef].all idWellFormed &&
    kindWellFormed evidence.kind && evidence.obligationId = context.obligationId &&
    evidence.itemId = context.itemId && timeWellFormed evidence.applicableAt &&
    timeWellFormed evidence.eventAt && timeWellFormed evidence.receivedAt &&
    evidence.eventAt ≤ evidence.receivedAt &&
    (match evidence.amountCents with
    | none => true
    | some amount => amountWellFormed amount) &&
    optionalIdWellFormed evidence.reversalOf && optionalIdWellFormed evidence.supersedes

def sameAuthority (authority : TrustedAuthority) (authorityId : String)
    (epoch : Nat) (digest : Bytes) : Bool :=
  authority.authorityId = authorityId && authority.epoch = epoch && authority.digest = digest

def paymentEvidenceWellFormed (input : FinancialInput) (payment : Payment) : Bool :=
  match findEvidence input.evidence payment.evidenceId with
  | none => false
  | some evidence =>
      evidence.kind = "PAYMENT_CONFIRMATION" &&
        evidence.commonOriginId = payment.commonOriginId &&
        evidence.amountCents = some payment.amountCents &&
        evidence.eventAt = payment.eventAt

def claimEvidenceWellFormed (input : FinancialInput) (claim : Claim) : Bool :=
  match findEvidence input.evidence claim.evidenceId with
  | none => false
  | some evidence =>
      evidence.kind = "OFFSET_CLAIM" &&
        evidence.commonOriginId = claim.claimId &&
        evidence.amountCents = some claim.amountCents

def reversalEvidenceWellFormed (input : FinancialInput) (payment : Payment) : Bool :=
  match payment.status, payment.reversalEvidenceId with
  | .ACTIVE, none => true
  | .ACTIVE, some _ => false
  | .REVERSED, none => false
  | .REVERSED, some evidenceId =>
      match findEvidence input.evidence evidenceId with
      | none => false
      | some evidence =>
          evidence.kind = "PAYMENT_REVERSAL" &&
            evidence.itemId = payment.itemId &&
            evidence.reversalOf = some payment.paymentId &&
            evidence.amountCents = some payment.amountCents

def paymentConfirmationAccounted (input : FinancialInput) (evidence : EvidenceRecord) : Bool :=
  input.payments.any (fun payment => payment.evidenceId = evidence.evidenceId) ||
    input.conflicts.any (fun conflict => conflict.candidateEvidenceId = evidence.evidenceId) ||
    match evidence.amountCents with
    | none => false
    | some amount => input.payments.any (fun payment =>
        payment.commonOriginId = evidence.commonOriginId && payment.amountCents = amount)

def reversalEvidenceAccounted (input : FinancialInput) (evidence : EvidenceRecord) : Bool :=
  match evidence.reversalOf with
  | none => false
  | some paymentId =>
      match findPayment input.payments paymentId with
      | none => false
      | some payment =>
          payment.status = .REVERSED &&
            payment.reversalEvidenceId.isSome &&
            evidence.kind = "PAYMENT_REVERSAL" &&
            evidence.itemId = payment.itemId &&
            evidence.amountCents = some payment.amountCents

def determinationHistoryWellFormed (input : FinancialInput)
    (determination : OffsetDetermination) : Bool :=
  determination.expectedRevision ≤ input.beforeRevision &&
    determination.resultingRevision ≤ input.beforeRevision + 1

def determinationSupportingEvidenceWellFormed (input : FinancialInput)
    (determination : OffsetDetermination) : Bool :=
  match findClaim input.claims determination.claimId with
  | none => false
  | some claim => determination.supportingEvidenceIds.contains claim.evidenceId

def determinationActorWellFormed (input : FinancialInput)
    (determination : OffsetDetermination) : Bool :=
  idWellFormed determination.actorId && roleWellFormed determination.actorRole &&
    authorityActorBindingWellFormed input.authority determination.actorId determination.actorRole &&
    input.pack.authorizedRoles.contains determination.actorRole

def determinationsForClaim (input : FinancialInput) (claimId : String) : List OffsetDetermination :=
  input.determinations.filter (fun determination => determination.claimId = claimId)

def claimTerminalWellFormed (input : FinancialInput) (claim : Claim) : Bool :=
  let matching := determinationsForClaim input claim.claimId
  match claim.status with
  | .CLAIMED => matching.isEmpty
  | .AUTHORIZED => matching.length = 1 &&
      matching.all (fun determination => determination.decision = .OFFSET_AUTHORIZED)
  | .REJECTED => matching.length = 1 &&
      matching.all (fun determination =>
        determination.decision = .OFFSET_REJECTED_CORRECTION_AUTHORIZED)

def actionKindForDecision : DeterminationDecision → String
  | .OFFSET_AUTHORIZED => "OFFSET_AUTHORIZATION"
  | .OFFSET_REJECTED_CORRECTION_AUTHORIZED => "CORRECTION_PAYMENT_REQUEST"

def actionBindingWellFormed (input : FinancialInput) (action : ActionRecord) : Bool :=
  match action.determinationId with
  | none => false
  | some identity =>
      match findDetermination input.determinations identity with
      | none => false
      | some determination =>
          determination.determinationId = "determination:" ++ action.actionId &&
            action.kind = actionKindForDecision determination.decision &&
            action.amountCents = determination.amountCents &&
            action.revision = determination.resultingRevision &&
            determination.decidedAt ≤ action.createdAt &&
            action.createdAt ≤ input.evaluatedAt

def actionsForDetermination (input : FinancialInput) (determinationId : String) : List ActionRecord :=
  input.actions.filter (fun action => action.determinationId = some determinationId)

def determinationActionWellFormed (input : FinancialInput)
    (determination : OffsetDetermination) : Bool :=
  let matching := actionsForDetermination input determination.determinationId
  matching.length = 1 && matching.all (actionBindingWellFormed input)

def determinationWellFormed (input : FinancialInput)
    (determination : OffsetDetermination) : Bool :=
  [determination.determinationId, determination.obligationId, determination.claimId,
    determination.actorId, determination.authorityId].all idWellFormed &&
    roleWellFormed determination.actorRole &&
    determination.obligationId = input.context.obligationId &&
    sameAuthority input.authority determination.authorityId determination.authorityEpoch
      determination.authorityDigest &&
    revisionWellFormed determination.expectedRevision &&
    determination.resultingRevision = determination.expectedRevision + 1 &&
    revisionWellFormed determination.resultingRevision &&
    determinationHistoryWellFormed input determination &&
    determinationActorWellFormed input determination &&
    digestWellFormed determination.authorityDigest && positiveAmountWellFormed determination.amountCents &&
    timeWellFormed determination.decidedAt && determination.supportingEvidenceIds.length ≥ 1 &&
    canonicalIdList determination.supportingEvidenceIds &&
    determinationSupportingEvidenceWellFormed input determination &&
    determination.decidedAt ≤ input.evaluatedAt &&
    match findClaim input.claims determination.claimId with
    | none => false
    | some claim =>
        claim.amountCents = determination.amountCents &&
          match determination.decision with
          | .OFFSET_AUTHORIZED => claim.status = .AUTHORIZED
          | .OFFSET_REJECTED_CORRECTION_AUTHORIZED => claim.status = .REJECTED

def conflictWellFormed (input : FinancialInput) (conflict : FinancialConflict) : Bool :=
  [conflict.conflictId, conflict.obligationId, conflict.commonOriginId,
    conflict.existingPaymentId, conflict.candidateEvidenceId, conflict.reason].all idWellFormed &&
    conflict.obligationId = input.context.obligationId &&
    positiveAmountWellFormed conflict.existingAmountCents &&
    positiveAmountWellFormed conflict.candidateAmountCents && timeWellFormed conflict.visibleAt &&
    match findPayment input.payments conflict.existingPaymentId,
      findEvidence input.evidence conflict.candidateEvidenceId with
    | some payment, some evidence =>
        payment.commonOriginId = conflict.commonOriginId &&
          payment.amountCents = conflict.existingAmountCents &&
          evidence.commonOriginId = conflict.commonOriginId &&
          evidence.kind = "PAYMENT_CONFIRMATION" &&
          evidence.amountCents = some conflict.candidateAmountCents &&
          conflict.existingAmountCents ≠ conflict.candidateAmountCents &&
          conflict.reason = "CONFLICTING_COMMON_ORIGIN_AMOUNT"
    | _, _ => false

def caseWellFormed (input : FinancialInput) (caseRecord : CaseRecord) : Bool :=
  [caseRecord.caseId, caseRecord.obligationId, caseRecord.reason].all idWellFormed &&
    roleWellFormed caseRecord.nextActionOwner &&
    caseRecord.obligationId = input.context.obligationId &&
    input.pack.authorizedRoles.contains caseRecord.nextActionOwner &&
    timeWellFormed caseRecord.dueAt && timeWellFormed caseRecord.updatedAt

def actionWellFormed (input : FinancialInput) (action : ActionRecord) : Bool :=
  [action.actionId, action.obligationId, action.kind].all idWellFormed &&
    action.obligationId = input.context.obligationId && positiveAmountWellFormed action.amountCents &&
    action.currency = input.context.currency && revisionWellFormed action.revision &&
    digestWellFormed action.payloadDigest && timeWellFormed action.createdAt &&
    actionBindingWellFormed input action

def financialInputWellFormed (input : FinancialInput) : Bool :=
  contextWellFormed input.context && authorityWellFormed input.authority &&
    controlPackWellFormed input.pack && obligationWellFormed input.obligation &&
    input.beforeRevision < maxRevision && revisionWellFormed input.beforeRevision &&
    timeWellFormed input.evaluatedAt &&
    input.pack.stateId = input.context.stateId &&
    input.pack.deploymentId = input.context.deploymentId &&
    input.pack.programId = input.context.programId &&
    input.pack.periodId = input.context.periodId &&
    input.pack.currency = input.context.currency &&
    input.obligation.populationId = input.context.populationId &&
    input.obligation.itemId = input.context.itemId &&
    input.obligation.obligationId = input.context.obligationId &&
    input.obligation.ruleVersion = input.pack.version &&
    input.payments.length ≤ maxRows && input.claims.length ≤ maxRows &&
    input.determinations.length ≤ maxRows && input.evidence.length ≤ maxRows &&
    input.conflicts.length ≤ maxRows && input.cases.length ≥ 1 &&
    input.cases.length ≤ maxRows &&
    input.actions.length ≤ maxRows &&
    canonicalIdList (input.payments.map Payment.paymentId) &&
    canonicalIdList (input.claims.map Claim.claimId) &&
    canonicalIdList (input.determinations.map OffsetDetermination.determinationId) &&
    canonicalIdList (input.evidence.map EvidenceRecord.evidenceId) &&
    canonicalIdList (input.conflicts.map FinancialConflict.conflictId) &&
    canonicalIdList (input.cases.map CaseRecord.caseId) &&
    canonicalIdList (input.actions.map ActionRecord.actionId) &&
    input.payments.all (paymentWellFormed input.context) &&
    input.claims.all (claimWellFormed input.context) &&
    input.evidence.all (evidenceWellFormed input.context) &&
    input.determinations.all (determinationWellFormed input) &&
    input.conflicts.all (conflictWellFormed input) &&
    input.cases.all (caseWellFormed input) &&
    input.actions.all (actionWellFormed input) &&
    input.payments.all (paymentEvidenceWellFormed input) &&
    input.payments.all (reversalEvidenceWellFormed input) &&
    input.claims.all (claimEvidenceWellFormed input) &&
    input.claims.all (fun claim => input.pack.authorizedRoles.contains claim.ownerRole) &&
    input.determinations.all (determinationSupportingEvidenceWellFormed input) &&
    input.claims.all (claimTerminalWellFormed input) &&
    input.determinations.all (determinationActionWellFormed input) &&
    noDuplicates (input.determinations.map OffsetDetermination.claimId) &&
    noDuplicates (input.actions.filterMap ActionRecord.determinationId) &&
    input.evidence.all (fun evidence =>
      if evidence.kind = "PAYMENT_CONFIRMATION" then paymentConfirmationAccounted input evidence
      else if evidence.kind = "PAYMENT_REVERSAL" then reversalEvidenceAccounted input evidence
      else if evidence.kind = "OFFSET_CLAIM" then
        input.claims.any (fun claim => claim.evidenceId = evidence.evidenceId)
      else true) &&
    input.evidence.all (fun evidence => evidence.receivedAt ≤ input.evaluatedAt) &&
    input.cases.all (fun caseRecord => caseRecord.updatedAt ≤ input.evaluatedAt) &&
    allReferencesExist (input.evidence.map EvidenceRecord.evidenceId)
      (input.payments.map Payment.evidenceId) &&
    allReferencesExist (input.evidence.map EvidenceRecord.evidenceId)
      (input.payments.filterMap Payment.reversalEvidenceId) &&
    allReferencesExist (input.evidence.map EvidenceRecord.evidenceId)
      (input.claims.map Claim.evidenceId) &&
    input.determinations.all (fun determination =>
      allReferencesExist (input.evidence.map EvidenceRecord.evidenceId)
        determination.supportingEvidenceIds) &&
    noDuplicates (input.payments.map Payment.commonOriginId)

def financialResultWellFormed (result : FinancialResult) : Bool :=
  contextWellFormed result.context &&
    idWellFormed result.authorityId && result.authorityEpoch ≥ 1 &&
    result.authorityEpoch ≤ maxAuthorityEpoch && digestWellFormed result.authorityDigest &&
    idWellFormed result.packId && digestWellFormed result.packDigest &&
    result.beforeRevision < maxRevision && revisionWellFormed result.beforeRevision &&
    result.afterRevision = result.beforeRevision + 1 &&
    revisionWellFormed result.afterRevision && timeWellFormed result.evaluatedAt &&
    result.ruleVersion ≥ 1 && result.ruleVersion ≤ maxRevision &&
    canonicalIdList result.evidenceIds &&
    (match result.completionAt with
    | none => true
    | some completionAt => timeWellFormed completionAt) &&
    positiveAmountWellFormed result.owedCents && amountWellFormed result.claimedAdjustmentCents &&
    amountWellFormed result.lawfulAdjustmentCents && amountWellFormed result.receivedCashCents &&
    amountWellFormed result.shortfallCents && amountWellFormed result.overageCents

def contributionKeyBefore (leftTime leftAmount : Nat) (leftId : String)
    (rightTime rightAmount : Nat) (rightId : String) : Bool :=
  leftTime < rightTime ||
    (leftTime = rightTime &&
      (leftAmount < rightAmount ||
        (leftAmount = rightAmount && decide (leftId < rightId))))

end BlindLedger.Financial
