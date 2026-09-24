import BlindLedger.Financial.Types

namespace BlindLedger.Financial

/-! `BLFIN02` is a bounded, canonical, big-endian input codec.  Lengths are
    u16, application integers are u64 with the stricter application bounds
    checked by `financialInputWellFormed`, digests are fixed 64-byte values,
    arrays are count-prefixed and validated as unique canonical order, and
    the decoder rejects trailing bytes. -/

def financialCodecMagic : Bytes := "BLFIN02".toUTF8.toList

def natBE : Nat → Nat → Bytes
  | 0, _ => []
  | width + 1, value => natBE width (value / 256) ++ [UInt8.ofNat (value % 256)]

def readByte : Bytes → Option (UInt8 × Bytes)
  | [] => none
  | byte :: rest => some (byte, rest)

def readNatBE : Nat → Bytes → Option (Nat × Bytes)
  | 0, bytes => some (0, bytes)
  | width + 1, bytes => do
      let (accumulated, rest) ← readNatBE width bytes
      let (byte, tail) ← readByte rest
      pure (accumulated * 256 + byte.toNat, tail)

def encodeString (value : String) : Bytes :=
  let bytes := value.toUTF8.toList
  natBE 2 bytes.length ++ bytes

def readString (bytes : Bytes) : Option (String × Bytes) := do
  let (length, rest) ← readNatBE 2 bytes
  if length > rest.length then none else
    let raw := rest.take length
    let tail := rest.drop length
    let value ← String.fromUTF8? raw.toByteArray
    pure (value, tail)

def encodeDigest (digest : Bytes) : Bytes := digest

def readDigest (bytes : Bytes) : Option (Bytes × Bytes) :=
  if bytes.length < digestBytes then none
  else some (bytes.take digestBytes, bytes.drop digestBytes)

def encodeBool (value : Bool) : Bytes := [if value then UInt8.ofNat 1 else UInt8.ofNat 0]

def readBool (bytes : Bytes) : Option (Bool × Bytes) := do
  let (byte, rest) ← readByte bytes
  if byte.toNat = 0 then some (false, rest)
  else if byte.toNat = 1 then some (true, rest)
  else none

def encodeOptionNat : Option Nat → Bytes
  | none => [UInt8.ofNat 0]
  | some value => UInt8.ofNat 1 :: natBE 8 value

def readOptionNat (bytes : Bytes) : Option (Option Nat × Bytes) := do
  let (tag, rest) ← readByte bytes
  if tag.toNat = 0 then some (none, rest)
  else if tag.toNat = 1 then
    let (value, tail) ← readNatBE 8 rest
    pure (some value, tail)
  else none

def encodeOptionString : Option String → Bytes
  | none => [UInt8.ofNat 0]
  | some value => UInt8.ofNat 1 :: encodeString value

def readOptionString (bytes : Bytes) : Option (Option String × Bytes) := do
  let (tag, rest) ← readByte bytes
  if tag.toNat = 0 then some (none, rest)
  else if tag.toNat = 1 then
    let (value, tail) ← readString rest
    pure (some value, tail)
  else none

def encodeMode : OwnerMode → UInt8
  | .LIVE => UInt8.ofNat 1
  | .SHADOW => UInt8.ofNat 2
  | .TEST => UInt8.ofNat 3

def decodeMode (byte : UInt8) : Option OwnerMode :=
  if byte.toNat = 1 then some .LIVE
  else if byte.toNat = 2 then some .SHADOW
  else if byte.toNat = 3 then some .TEST
  else none

def encodeProvenance : Provenance → UInt8
  | .ROOT => UInt8.ofNat 1
  | .CONTINUITY_RESTORE => UInt8.ofNat 2

def decodeProvenance (byte : UInt8) : Option Provenance :=
  if byte.toNat = 1 then some .ROOT
  else if byte.toNat = 2 then some .CONTINUITY_RESTORE
  else none

def encodePackStatus : PackStatus → UInt8
  | .APPROVED => UInt8.ofNat 1
  | .REVOKED => UInt8.ofNat 2

def decodePackStatus (byte : UInt8) : Option PackStatus :=
  if byte.toNat = 1 then some .APPROVED
  else if byte.toNat = 2 then some .REVOKED
  else none

def encodePaymentStatus : PaymentStatus → UInt8
  | .ACTIVE => UInt8.ofNat 1
  | .REVERSED => UInt8.ofNat 2

def decodePaymentStatus (byte : UInt8) : Option PaymentStatus :=
  if byte.toNat = 1 then some .ACTIVE
  else if byte.toNat = 2 then some .REVERSED
  else none

def encodeClaimStatus : ClaimStatus → UInt8
  | .CLAIMED => UInt8.ofNat 1
  | .AUTHORIZED => UInt8.ofNat 2
  | .REJECTED => UInt8.ofNat 3

def decodeClaimStatus (byte : UInt8) : Option ClaimStatus :=
  if byte.toNat = 1 then some .CLAIMED
  else if byte.toNat = 2 then some .AUTHORIZED
  else if byte.toNat = 3 then some .REJECTED
  else none

def encodeDecision : DeterminationDecision → UInt8
  | .OFFSET_AUTHORIZED => UInt8.ofNat 1
  | .OFFSET_REJECTED_CORRECTION_AUTHORIZED => UInt8.ofNat 2

def decodeDecision (byte : UInt8) : Option DeterminationDecision :=
  if byte.toNat = 1 then some .OFFSET_AUTHORIZED
  else if byte.toNat = 2 then some .OFFSET_REJECTED_CORRECTION_AUTHORIZED
  else none

def encodeCaseStatus : CaseStatus → UInt8
  | .OPEN => UInt8.ofNat 1
  | .AUTHORIZED => UInt8.ofNat 2
  | .CORRECTION_REQUIRED => UInt8.ofNat 3
  | .ACTIONED => UInt8.ofNat 4
  | .RESOLVED => UInt8.ofNat 5

def decodeCaseStatus (byte : UInt8) : Option CaseStatus :=
  if byte.toNat = 1 then some .OPEN
  else if byte.toNat = 2 then some .AUTHORIZED
  else if byte.toNat = 3 then some .CORRECTION_REQUIRED
  else if byte.toNat = 4 then some .ACTIONED
  else if byte.toNat = 5 then some .RESOLVED
  else none

def encodeActionStatus : ActionStatus → UInt8
  | .READY => UInt8.ofNat 1
  | .ACKNOWLEDGED => UInt8.ofNat 2
  | .CANCELLED => UInt8.ofNat 3

def decodeActionStatus (byte : UInt8) : Option ActionStatus :=
  if byte.toNat = 1 then some .READY
  else if byte.toNat = 2 then some .ACKNOWLEDGED
  else if byte.toNat = 3 then some .CANCELLED
  else none

def encodeVerificationStatus : VerificationStatus → UInt8
  | .MISSING_EVIDENCE => UInt8.ofNat 1
  | .SUPPORTED => UInt8.ofNat 2
  | .CONFLICT_VISIBLE => UInt8.ofNat 3

def decodeVerificationStatus (byte : UInt8) : Option VerificationStatus :=
  if byte.toNat = 1 then some .MISSING_EVIDENCE
  else if byte.toNat = 2 then some .SUPPORTED
  else if byte.toNat = 3 then some .CONFLICT_VISIBLE
  else none

def encodeDeliveryStatus : DeliveryStatus → UInt8
  | .NONE => UInt8.ofNat 1
  | .READY => UInt8.ofNat 2
  | .ACKNOWLEDGED => UInt8.ofNat 3
  | .CANCELLED => UInt8.ofNat 4

def decodeDeliveryStatus (byte : UInt8) : Option DeliveryStatus :=
  if byte.toNat = 1 then some .NONE
  else if byte.toNat = 2 then some .READY
  else if byte.toNat = 3 then some .ACKNOWLEDGED
  else if byte.toNat = 4 then some .CANCELLED
  else none

def encodeList (encode : α → Bytes) (values : List α) : Bytes :=
  natBE 2 values.length ++ values.flatMap encode

def readMany (parse : Bytes → Option (α × Bytes)) : Nat → Bytes → Option (List α × Bytes)
  | 0, bytes => some ([], bytes)
  | count + 1, bytes => do
      let (value, rest) ← parse bytes
      let (tail, remaining) ← readMany parse count rest
      pure (value :: tail, remaining)

def readList (parse : Bytes → Option (α × Bytes)) (bytes : Bytes) :
    Option (List α × Bytes) := do
  let (count, rest) ← readNatBE 2 bytes
  if count > maxRows then none else readMany parse count rest

def encodeContext (context : FinancialContext) : Bytes :=
  encodeString context.ownerId ++ [encodeMode context.mode, encodeProvenance context.provenance] ++
    encodeString context.stateId ++ encodeString context.deploymentId ++
    encodeString context.programId ++ encodeString context.periodId ++
    encodeString context.populationId ++ encodeString context.itemId ++
    encodeString context.obligationId ++ encodeString context.currency

def decodeContext (bytes : Bytes) : Option (FinancialContext × Bytes) := do
  let (ownerId, rest) ← readString bytes
  let (modeByte, rest) ← readByte rest
  let mode ← decodeMode modeByte
  let (provenanceByte, rest) ← readByte rest
  let provenance ← decodeProvenance provenanceByte
  let (stateId, rest) ← readString rest
  let (deploymentId, rest) ← readString rest
  let (programId, rest) ← readString rest
  let (periodId, rest) ← readString rest
  let (populationId, rest) ← readString rest
  let (itemId, rest) ← readString rest
  let (obligationId, rest) ← readString rest
  let (currency, rest) ← readString rest
  pure
    ({ ownerId := ownerId
       mode := mode
       provenance := provenance
       stateId := stateId
       deploymentId := deploymentId
       programId := programId
       periodId := periodId
       populationId := populationId
       itemId := itemId
       obligationId := obligationId
       currency := currency }, rest)

def encodeAuthorityActor (actor : AuthorityActor) : Bytes :=
  encodeString actor.actorId ++ encodeList encodeString actor.roles

def decodeAuthorityActor (bytes : Bytes) : Option (AuthorityActor × Bytes) := do
  let (actorId, rest) ← readString bytes
  let (roles, rest) ← readList readString rest
  pure ({ actorId := actorId, roles := roles }, rest)

def encodeAuthority (authority : TrustedAuthority) : Bytes :=
  encodeString authority.authorityId ++ natBE 8 authority.epoch ++ encodeDigest authority.digest ++
    encodeBool authority.syntheticOnly ++ encodeList encodeAuthorityActor authority.actors

def decodeAuthority (bytes : Bytes) : Option (TrustedAuthority × Bytes) := do
  let (authorityId, rest) ← readString bytes
  let (epoch, rest) ← readNatBE 8 rest
  let (digest, rest) ← readDigest rest
  let (syntheticOnly, rest) ← readBool rest
  let (actors, rest) ← readList decodeAuthorityActor rest
  pure
    ({ authorityId := authorityId
       epoch := epoch
       digest := digest
       syntheticOnly := syntheticOnly
       actors := actors }, rest)

def encodeControlPack (pack : ControlPack) : Bytes :=
  encodeString pack.packId ++ encodeString pack.stateId ++ encodeString pack.deploymentId ++
    encodeString pack.programId ++ encodeString pack.periodId ++ encodeString pack.currency ++
    natBE 8 pack.version ++ encodeList encodeString pack.sourceRefs ++
    natBE 8 pack.effectiveStart ++ natBE 8 pack.effectiveEnd ++
    natBE 8 pack.recordedAt ++ natBE 8 pack.approvedAt ++
    encodeString pack.calculationRuleId ++ encodeString pack.adjustmentRuleId ++
    encodeList encodeString pack.authorizedRoles ++ encodeList encodeString pack.expectedTests ++
    encodeDigest pack.digest ++ [encodePackStatus pack.status]

def decodeControlPack (bytes : Bytes) : Option (ControlPack × Bytes) := do
  let (packId, rest) ← readString bytes
  let (stateId, rest) ← readString rest
  let (deploymentId, rest) ← readString rest
  let (programId, rest) ← readString rest
  let (periodId, rest) ← readString rest
  let (currency, rest) ← readString rest
  let (version, rest) ← readNatBE 8 rest
  let (sourceRefs, rest) ← readList readString rest
  let (effectiveStart, rest) ← readNatBE 8 rest
  let (effectiveEnd, rest) ← readNatBE 8 rest
  let (recordedAt, rest) ← readNatBE 8 rest
  let (approvedAt, rest) ← readNatBE 8 rest
  let (calculationRuleId, rest) ← readString rest
  let (adjustmentRuleId, rest) ← readString rest
  let (authorizedRoles, rest) ← readList readString rest
  let (expectedTests, rest) ← readList readString rest
  let (digest, rest) ← readDigest rest
  let (statusByte, rest) ← readByte rest
  let status ← decodePackStatus statusByte
  pure
    ({ packId := packId
       stateId := stateId
       deploymentId := deploymentId
       programId := programId
       periodId := periodId
       currency := currency
       version := version
       sourceRefs := sourceRefs
       effectiveStart := effectiveStart
       effectiveEnd := effectiveEnd
       recordedAt := recordedAt
       approvedAt := approvedAt
       calculationRuleId := calculationRuleId
       adjustmentRuleId := adjustmentRuleId
       authorizedRoles := authorizedRoles
       expectedTests := expectedTests
       digest := digest
       status := status }, rest)

def encodeObligation (obligation : Obligation) : Bytes :=
  encodeString obligation.populationId ++ encodeString obligation.itemId ++
    encodeString obligation.obligationId ++ natBE 8 obligation.owedCents ++
    natBE 8 obligation.dueAt ++ natBE 8 obligation.ruleVersion ++
    encodeBool obligation.reportingComplete

def decodeObligation (bytes : Bytes) : Option (Obligation × Bytes) := do
  let (populationId, rest) ← readString bytes
  let (itemId, rest) ← readString rest
  let (obligationId, rest) ← readString rest
  let (owedCents, rest) ← readNatBE 8 rest
  let (dueAt, rest) ← readNatBE 8 rest
  let (ruleVersion, rest) ← readNatBE 8 rest
  let (reportingComplete, rest) ← readBool rest
  pure
    ({ populationId := populationId
       itemId := itemId
       obligationId := obligationId
       owedCents := owedCents
       dueAt := dueAt
       ruleVersion := ruleVersion
       reportingComplete := reportingComplete }, rest)

def encodePayment (payment : Payment) : Bytes :=
  encodeString payment.paymentId ++ encodeString payment.obligationId ++
    encodeString payment.itemId ++ encodeString payment.evidenceId ++
    encodeString payment.commonOriginId ++ natBE 8 payment.amountCents ++
    natBE 8 payment.eventAt ++ encodeOptionString payment.reversalEvidenceId ++
    [encodePaymentStatus payment.status]

def decodePayment (bytes : Bytes) : Option (Payment × Bytes) := do
  let (paymentId, rest) ← readString bytes
  let (obligationId, rest) ← readString rest
  let (itemId, rest) ← readString rest
  let (evidenceId, rest) ← readString rest
  let (commonOriginId, rest) ← readString rest
  let (amountCents, rest) ← readNatBE 8 rest
  let (eventAt, rest) ← readNatBE 8 rest
  let (reversalEvidenceId, rest) ← readOptionString rest
  let (statusByte, rest) ← readByte rest
  let status ← decodePaymentStatus statusByte
  pure
    ({ paymentId := paymentId
       obligationId := obligationId
       itemId := itemId
       evidenceId := evidenceId
       commonOriginId := commonOriginId
       amountCents := amountCents
       eventAt := eventAt
       reversalEvidenceId := reversalEvidenceId
       status := status }, rest)

def encodeClaim (claim : Claim) : Bytes :=
  encodeString claim.claimId ++ encodeString claim.obligationId ++
    encodeString claim.evidenceId ++ natBE 8 claim.amountCents ++
    encodeString claim.ownerRole ++ natBE 8 claim.deadlineAt ++
    [encodeClaimStatus claim.status]

def decodeClaim (bytes : Bytes) : Option (Claim × Bytes) := do
  let (claimId, rest) ← readString bytes
  let (obligationId, rest) ← readString rest
  let (evidenceId, rest) ← readString rest
  let (amountCents, rest) ← readNatBE 8 rest
  let (ownerRole, rest) ← readString rest
  let (deadlineAt, rest) ← readNatBE 8 rest
  let (statusByte, rest) ← readByte rest
  let status ← decodeClaimStatus statusByte
  pure
    ({ claimId := claimId
       obligationId := obligationId
       evidenceId := evidenceId
       amountCents := amountCents
       ownerRole := ownerRole
       deadlineAt := deadlineAt
       status := status }, rest)

def encodeDetermination (determination : OffsetDetermination) : Bytes :=
  encodeString determination.determinationId ++ encodeString determination.obligationId ++
    encodeString determination.claimId ++ encodeString determination.actorId ++
    encodeString determination.actorRole ++ encodeString determination.authorityId ++
    natBE 8 determination.authorityEpoch ++ encodeDigest determination.authorityDigest ++
    [encodeDecision determination.decision] ++ natBE 8 determination.amountCents ++
    encodeList encodeString determination.supportingEvidenceIds ++
    natBE 8 determination.expectedRevision ++ natBE 8 determination.resultingRevision ++
    natBE 8 determination.decidedAt

def decodeDetermination (bytes : Bytes) : Option (OffsetDetermination × Bytes) := do
  let (determinationId, rest) ← readString bytes
  let (obligationId, rest) ← readString rest
  let (claimId, rest) ← readString rest
  let (actorId, rest) ← readString rest
  let (actorRole, rest) ← readString rest
  let (authorityId, rest) ← readString rest
  let (authorityEpoch, rest) ← readNatBE 8 rest
  let (authorityDigest, rest) ← readDigest rest
  let (decisionByte, rest) ← readByte rest
  let decision ← decodeDecision decisionByte
  let (amountCents, rest) ← readNatBE 8 rest
  let (supportingEvidenceIds, rest) ← readList readString rest
  let (expectedRevision, rest) ← readNatBE 8 rest
  let (resultingRevision, rest) ← readNatBE 8 rest
  let (decidedAt, rest) ← readNatBE 8 rest
  pure
    ({ determinationId := determinationId
       obligationId := obligationId
       claimId := claimId
       actorId := actorId
       actorRole := actorRole
       authorityId := authorityId
       authorityEpoch := authorityEpoch
       authorityDigest := authorityDigest
       decision := decision
       amountCents := amountCents
       supportingEvidenceIds := supportingEvidenceIds
       expectedRevision := expectedRevision
       resultingRevision := resultingRevision
       decidedAt := decidedAt }, rest)

def encodeEvidence (evidence : EvidenceRecord) : Bytes :=
  encodeString evidence.evidenceId ++ encodeString evidence.obligationId ++
    encodeString evidence.itemId ++ encodeString evidence.kind ++
    encodeString evidence.commonOriginId ++ encodeString evidence.sourceId ++
    encodeString evidence.sourceVersion ++ encodeString evidence.localRef ++
    natBE 8 evidence.applicableAt ++ natBE 8 evidence.eventAt ++
    natBE 8 evidence.receivedAt ++ encodeOptionNat evidence.amountCents ++
    encodeOptionString evidence.reversalOf ++ encodeOptionString evidence.supersedes

def decodeEvidence (bytes : Bytes) : Option (EvidenceRecord × Bytes) := do
  let (evidenceId, rest) ← readString bytes
  let (obligationId, rest) ← readString rest
  let (itemId, rest) ← readString rest
  let (kind, rest) ← readString rest
  let (commonOriginId, rest) ← readString rest
  let (sourceId, rest) ← readString rest
  let (sourceVersion, rest) ← readString rest
  let (localRef, rest) ← readString rest
  let (applicableAt, rest) ← readNatBE 8 rest
  let (eventAt, rest) ← readNatBE 8 rest
  let (receivedAt, rest) ← readNatBE 8 rest
  let (amountCents, rest) ← readOptionNat rest
  let (reversalOf, rest) ← readOptionString rest
  let (supersedes, rest) ← readOptionString rest
  pure
    ({ evidenceId := evidenceId
       obligationId := obligationId
       itemId := itemId
       kind := kind
       commonOriginId := commonOriginId
       sourceId := sourceId
       sourceVersion := sourceVersion
       localRef := localRef
       applicableAt := applicableAt
       eventAt := eventAt
       receivedAt := receivedAt
       amountCents := amountCents
       reversalOf := reversalOf
       supersedes := supersedes }, rest)

def encodeConflict (conflict : FinancialConflict) : Bytes :=
  encodeString conflict.conflictId ++ encodeString conflict.obligationId ++
    encodeString conflict.commonOriginId ++ encodeString conflict.existingPaymentId ++
    encodeString conflict.candidateEvidenceId ++ natBE 8 conflict.existingAmountCents ++
    natBE 8 conflict.candidateAmountCents ++ encodeString conflict.reason ++
    natBE 8 conflict.visibleAt

def decodeConflict (bytes : Bytes) : Option (FinancialConflict × Bytes) := do
  let (conflictId, rest) ← readString bytes
  let (obligationId, rest) ← readString rest
  let (commonOriginId, rest) ← readString rest
  let (existingPaymentId, rest) ← readString rest
  let (candidateEvidenceId, rest) ← readString rest
  let (existingAmountCents, rest) ← readNatBE 8 rest
  let (candidateAmountCents, rest) ← readNatBE 8 rest
  let (reason, rest) ← readString rest
  let (visibleAt, rest) ← readNatBE 8 rest
  pure
    ({ conflictId := conflictId
       obligationId := obligationId
       commonOriginId := commonOriginId
       existingPaymentId := existingPaymentId
       candidateEvidenceId := candidateEvidenceId
       existingAmountCents := existingAmountCents
       candidateAmountCents := candidateAmountCents
       reason := reason
       visibleAt := visibleAt }, rest)

def encodeCase (caseRecord : CaseRecord) : Bytes :=
  encodeString caseRecord.caseId ++ encodeString caseRecord.obligationId ++
    encodeString caseRecord.reason ++ encodeString caseRecord.nextActionOwner ++
    natBE 8 caseRecord.dueAt ++ [encodeCaseStatus caseRecord.status] ++
    natBE 8 caseRecord.updatedAt

def decodeCase (bytes : Bytes) : Option (CaseRecord × Bytes) := do
  let (caseId, rest) ← readString bytes
  let (obligationId, rest) ← readString rest
  let (reason, rest) ← readString rest
  let (nextActionOwner, rest) ← readString rest
  let (dueAt, rest) ← readNatBE 8 rest
  let (statusByte, rest) ← readByte rest
  let status ← decodeCaseStatus statusByte
  let (updatedAt, rest) ← readNatBE 8 rest
  pure
    ({ caseId := caseId
       obligationId := obligationId
       reason := reason
       nextActionOwner := nextActionOwner
       dueAt := dueAt
       status := status
       updatedAt := updatedAt }, rest)

def encodeAction (action : ActionRecord) : Bytes :=
  encodeString action.actionId ++ encodeString action.obligationId ++
    encodeOptionString action.determinationId ++ encodeString action.kind ++
    natBE 8 action.amountCents ++ encodeString action.currency ++ natBE 8 action.revision ++
    [encodeActionStatus action.status] ++ encodeDigest action.payloadDigest ++
    natBE 8 action.createdAt

def decodeAction (bytes : Bytes) : Option (ActionRecord × Bytes) := do
  let (actionId, rest) ← readString bytes
  let (obligationId, rest) ← readString rest
  let (determinationId, rest) ← readOptionString rest
  let (kind, rest) ← readString rest
  let (amountCents, rest) ← readNatBE 8 rest
  let (currency, rest) ← readString rest
  let (revision, rest) ← readNatBE 8 rest
  let (statusByte, rest) ← readByte rest
  let status ← decodeActionStatus statusByte
  let (payloadDigest, rest) ← readDigest rest
  let (createdAt, rest) ← readNatBE 8 rest
  pure
    ({ actionId := actionId
       obligationId := obligationId
       determinationId := determinationId
       kind := kind
       amountCents := amountCents
       currency := currency
       revision := revision
       status := status
       payloadDigest := payloadDigest
       createdAt := createdAt }, rest)

def rawEncodeFinancialInput (input : FinancialInput) : Bytes :=
  financialCodecMagic ++ encodeContext input.context ++ encodeAuthority input.authority ++
    encodeControlPack input.pack ++ encodeObligation input.obligation ++
    natBE 8 input.beforeRevision ++ natBE 8 input.evaluatedAt ++
    encodeList encodePayment input.payments ++ encodeList encodeClaim input.claims ++
    encodeList encodeDetermination input.determinations ++ encodeList encodeEvidence input.evidence ++
    encodeList encodeConflict input.conflicts ++ encodeList encodeCase input.cases ++
    encodeList encodeAction input.actions

def encodeFinancialInput (input : FinancialInput) : Option Bytes :=
  if financialInputWellFormed input then
    let wire := rawEncodeFinancialInput input
    if wire.length ≤ maxTotalEncodedBytes then some wire else none
  else none

def readMagic : Bytes → Option Bytes
  | bytes =>
      if financialCodecMagic.isPrefixOf bytes then
        some (bytes.drop financialCodecMagic.length)
      else none

def decodeFinancialInput (bytes : Bytes) : Option FinancialInput := do
  if bytes.length > maxTotalEncodedBytes then none else
    let rest ← readMagic bytes
    let (context, rest) ← decodeContext rest
    let (authority, rest) ← decodeAuthority rest
    let (pack, rest) ← decodeControlPack rest
    let (obligation, rest) ← decodeObligation rest
    let (beforeRevision, rest) ← readNatBE 8 rest
    let (evaluatedAt, rest) ← readNatBE 8 rest
    let (payments, rest) ← readList decodePayment rest
    let (claims, rest) ← readList decodeClaim rest
    let (determinations, rest) ← readList decodeDetermination rest
    let (evidence, rest) ← readList decodeEvidence rest
    let (conflicts, rest) ← readList decodeConflict rest
    let (cases, rest) ← readList decodeCase rest
    let (actions, rest) ← readList decodeAction rest
    if rest.isEmpty then
      let input :=
        { context := context
          authority := authority
          pack := pack
          obligation := obligation
          beforeRevision := beforeRevision
          evaluatedAt := evaluatedAt
          payments := payments
          claims := claims
          determinations := determinations
          evidence := evidence
          conflicts := conflicts
          cases := cases
          actions := actions }
      if financialInputWellFormed input then
        match encodeFinancialInput input with
        | some canonical => if canonical = bytes then some input else none
        | none => none
      else none
    else none

def financialResultCodecMagic : Bytes := "BLFRES02".toUTF8.toList

def rawEncodeFinancialResult (result : FinancialResult) : Bytes :=
  financialResultCodecMagic ++ encodeContext result.context ++
    encodeString result.authorityId ++ natBE 8 result.authorityEpoch ++
    encodeDigest result.authorityDigest ++ encodeString result.packId ++
    encodeDigest result.packDigest ++ natBE 8 result.beforeRevision ++
    natBE 8 result.afterRevision ++ natBE 8 result.evaluatedAt ++
    natBE 8 result.ruleVersion ++ encodeList encodeString result.evidenceIds ++
    encodeOptionNat result.completionAt ++ natBE 8 result.owedCents ++
    natBE 8 result.claimedAdjustmentCents ++ natBE 8 result.lawfulAdjustmentCents ++
    natBE 8 result.receivedCashCents ++ natBE 8 result.shortfallCents ++
    natBE 8 result.overageCents ++ encodeBool result.cashSatisfied ++
    encodeBool result.amountSatisfied ++ encodeBool result.timely ++
    encodeBool result.reportingComplete ++ [encodeVerificationStatus result.verificationStatus,
      encodeCaseStatus result.caseStatus, encodeDeliveryStatus result.deliveryStatus]

def encodeFinancialResult (result : FinancialResult) : Option Bytes :=
  if financialResultWellFormed result then
    let wire := rawEncodeFinancialResult result
    if wire.length ≤ maxTotalEncodedBytes then some wire else none
  else none

def readResultMagic : Bytes → Option Bytes
  | bytes =>
      if financialResultCodecMagic.isPrefixOf bytes then
        some (bytes.drop financialResultCodecMagic.length)
      else none

def decodeFinancialResult (bytes : Bytes) : Option FinancialResult := do
  if bytes.length > maxTotalEncodedBytes then none else
    let rest ← readResultMagic bytes
    let (context, rest) ← decodeContext rest
    let (authorityId, rest) ← readString rest
    let (authorityEpoch, rest) ← readNatBE 8 rest
    let (authorityDigest, rest) ← readDigest rest
    let (packId, rest) ← readString rest
    let (packDigest, rest) ← readDigest rest
    let (beforeRevision, rest) ← readNatBE 8 rest
    let (afterRevision, rest) ← readNatBE 8 rest
    let (evaluatedAt, rest) ← readNatBE 8 rest
    let (ruleVersion, rest) ← readNatBE 8 rest
    let (evidenceIds, rest) ← readList readString rest
    let (completionAt, rest) ← readOptionNat rest
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
    let (verificationByte, rest) ← readByte rest
    let verificationStatus ← decodeVerificationStatus verificationByte
    let (caseByte, rest) ← readByte rest
    let caseStatus ← decodeCaseStatus caseByte
    let (deliveryByte, rest) ← readByte rest
    let deliveryStatus ← decodeDeliveryStatus deliveryByte
    if rest.isEmpty then
      let result :=
        { context := context
          authorityId := authorityId
          authorityEpoch := authorityEpoch
          authorityDigest := authorityDigest
          packId := packId
          packDigest := packDigest
          beforeRevision := beforeRevision
          afterRevision := afterRevision
          evaluatedAt := evaluatedAt
          ruleVersion := ruleVersion
          evidenceIds := evidenceIds
          completionAt := completionAt
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
          deliveryStatus := deliveryStatus }
      if financialResultWellFormed result then
        match encodeFinancialResult result with
        | some canonical => if canonical = bytes then some result else none
        | none => none
      else none
    else none

end BlindLedger.Financial
