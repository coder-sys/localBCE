import BlindLedger.Financial.Codec

/-! Length-free twin of the `BLFIN02` decoder.  The reference decoder in `Codec.lean`
    measures the whole remaining input for every string and digest, which is quadratic
    in the record count.  The twins below are the same text with those two readers
    replaced; each `_eq` theorem proves the twin equal to the reference, so the
    readable decoder stays the specification and this file only adds speed. -/

namespace BlindLedger.Financial.Fast

def readString (bytes : Bytes) : Option (String × Bytes) := do
  let (length, rest) ← readNatBE 2 bytes
  let raw := rest.take length
  if raw.length < length then none else
    let tail := rest.drop length
    let value ← String.fromUTF8? raw.toByteArray
    pure (value, tail)

def readDigest (bytes : Bytes) : Option (Bytes × Bytes) :=
  let raw := bytes.take digestBytes
  if raw.length < digestBytes then none else some (raw, bytes.drop digestBytes)

def readOptionString (bytes : Bytes) : Option (Option String × Bytes) := do
  let (tag, rest) ← readByte bytes
  if tag.toNat = 0 then some (none, rest)
  else if tag.toNat = 1 then
    let (value, tail) ← readString rest
    pure (some value, tail)
  else none

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

def decodeAuthorityActor (bytes : Bytes) : Option (AuthorityActor × Bytes) := do
  let (actorId, rest) ← readString bytes
  let (roles, rest) ← readList readString rest
  pure ({ actorId := actorId, roles := roles }, rest)

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

theorem readString_eq : readString = BlindLedger.Financial.readString := by
  funext bytes
  unfold readString BlindLedger.Financial.readString
  cases readNatBE 2 bytes with
  | none => rfl
  | some p =>
    obtain ⟨length, rest⟩ := p
    by_cases h : length > rest.length
    · have h' : (rest.take length).length < length := by simp only [List.length_take]; omega
      simp [h, h', -List.length_take]
    · have h' : ¬ (rest.take length).length < length := by simp only [List.length_take]; omega
      simp [h, h', -List.length_take]

theorem readDigest_eq : readDigest = BlindLedger.Financial.readDigest := by
  funext bytes
  unfold readDigest BlindLedger.Financial.readDigest
  by_cases h : bytes.length < digestBytes
  · have h' : (bytes.take digestBytes).length < digestBytes := by
      simp only [List.length_take]; omega
    simp only [h, h', ↓reduceIte]
  · have h' : ¬ (bytes.take digestBytes).length < digestBytes := by
      simp only [List.length_take]; omega
    simp only [h, h', ↓reduceIte]

theorem readOptionString_eq :
    readOptionString = BlindLedger.Financial.readOptionString := by
  funext bytes
  simp only [readOptionString, BlindLedger.Financial.readOptionString, readString_eq]

theorem decodeContext_eq : decodeContext = BlindLedger.Financial.decodeContext := by
  funext bytes
  simp only [decodeContext, BlindLedger.Financial.decodeContext, readString_eq]

theorem decodeAuthorityActor_eq : decodeAuthorityActor = BlindLedger.Financial.decodeAuthorityActor := by
  funext bytes
  simp only [decodeAuthorityActor, BlindLedger.Financial.decodeAuthorityActor, readString_eq]

theorem decodeAuthority_eq : decodeAuthority = BlindLedger.Financial.decodeAuthority := by
  funext bytes
  simp only [decodeAuthority, BlindLedger.Financial.decodeAuthority, readString_eq, readDigest_eq, decodeAuthorityActor_eq]

theorem decodeControlPack_eq : decodeControlPack = BlindLedger.Financial.decodeControlPack := by
  funext bytes
  simp only [decodeControlPack, BlindLedger.Financial.decodeControlPack, readString_eq, readDigest_eq]

theorem decodeObligation_eq : decodeObligation = BlindLedger.Financial.decodeObligation := by
  funext bytes
  simp only [decodeObligation, BlindLedger.Financial.decodeObligation, readString_eq]

theorem decodePayment_eq : decodePayment = BlindLedger.Financial.decodePayment := by
  funext bytes
  simp only [decodePayment, BlindLedger.Financial.decodePayment, readString_eq, readOptionString_eq]

theorem decodeClaim_eq : decodeClaim = BlindLedger.Financial.decodeClaim := by
  funext bytes
  simp only [decodeClaim, BlindLedger.Financial.decodeClaim, readString_eq]

theorem decodeDetermination_eq : decodeDetermination = BlindLedger.Financial.decodeDetermination := by
  funext bytes
  simp only [decodeDetermination, BlindLedger.Financial.decodeDetermination, readString_eq, readDigest_eq]

theorem decodeEvidence_eq : decodeEvidence = BlindLedger.Financial.decodeEvidence := by
  funext bytes
  simp only [decodeEvidence, BlindLedger.Financial.decodeEvidence, readString_eq, readOptionString_eq]

theorem decodeConflict_eq : decodeConflict = BlindLedger.Financial.decodeConflict := by
  funext bytes
  simp only [decodeConflict, BlindLedger.Financial.decodeConflict, readString_eq]

theorem decodeCase_eq : decodeCase = BlindLedger.Financial.decodeCase := by
  funext bytes
  simp only [decodeCase, BlindLedger.Financial.decodeCase, readString_eq]

theorem decodeAction_eq : decodeAction = BlindLedger.Financial.decodeAction := by
  funext bytes
  simp only [decodeAction, BlindLedger.Financial.decodeAction, readString_eq, readDigest_eq, readOptionString_eq]

theorem decodeFinancialInputFast_eq (bytes : Bytes) :
    decodeFinancialInput bytes = BlindLedger.Financial.decodeFinancialInput bytes := by
  simp only [decodeFinancialInput, BlindLedger.Financial.decodeFinancialInput, decodeContext_eq, decodeAuthority_eq, decodeControlPack_eq, decodeObligation_eq, decodePayment_eq, decodeClaim_eq, decodeDetermination_eq, decodeEvidence_eq, decodeConflict_eq, decodeCase_eq, decodeAction_eq]
  rfl

end BlindLedger.Financial.Fast
