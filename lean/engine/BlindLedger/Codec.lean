import BlindLedger.StateTransition

namespace BlindLedger.Kernel

/-! A bounded canonical byte grammar for the semantic input.  Every integer is
    two big-endian bytes and every optional slot has an explicit tag.  This is
    a model wire format, not a replacement for the native cryptographic or
    transport encoding. -/

def codecMagic : List WireByte :=
  [byteOfNat 66, byteOfNat 76, byteOfNat 75, byteOfNat 49]

def encodeNat16 (value : Nat) : List WireByte :=
  [byteOfNat (value / 256), byteOfNat value]

def readByte : List WireByte → Option (WireByte × List WireByte)
  | [] => none
  | byte :: rest => some (byte, rest)

def readNat16 (bytes : List WireByte) : Option (Nat × List WireByte) := do
  let (high, rest) ← readByte bytes
  let (low, rest) ← readByte rest
  pure (high.val * 256 + low.val, rest)

def readId (bytes : List WireByte) : Option (Id × List WireByte) := do
  let (byte, rest) ← readByte bytes
  pure ({ value := byte }, rest)

def readTag (expected : Nat) (bytes : List WireByte) : Option (List WireByte) := do
  let (byte, rest) ← readByte bytes
  if byte.val = expected then some rest else none

def encodeId (identity : Id) : List WireByte :=
  [identity.value]

def encodeOptionId : Option Id → List WireByte
  | none => [byteOfNat 0]
  | some identity => byteOfNat 1 :: encodeId identity

def decodeOptionId
    (bytes : List WireByte) : Option (Option Id × List WireByte) := do
  let (tag, rest) ← readByte bytes
  if tag.val = 0 then
    pure (none, rest)
  else if tag.val = 1 then
    let (identity, rest) ← readId rest
    pure (some identity, rest)
  else
    none

def encodeEconomicStatus : EconomicStatus → WireByte
  | .open => byteOfNat 0
  | .cleared => byteOfNat 1

def decodeEconomicStatus : WireByte → Option EconomicStatus
  | byte =>
      if byte.val = 0 then some .open
      else if byte.val = 1 then some .cleared
      else none

def encodeState (state : LedgerState) : List WireByte :=
  encodeNat16 state.sequence ++
    encodeNat16 state.economicVersion ++
    [encodeEconomicStatus state.status] ++
    encodeOptionId state.lastAttempt ++
    encodeId state.auditHead

def decodeState (bytes : List WireByte) : Option (LedgerState × List WireByte) := do
  let (sequence, rest) ← readNat16 bytes
  let (economicVersion, rest) ← readNat16 rest
  let (statusByte, rest) ← readByte rest
  let status ← decodeEconomicStatus statusByte
  let (lastAttempt, rest) ← decodeOptionId rest
  let (auditHead, rest) ← readId rest
  pure
    ({ sequence := sequence
       economicVersion := economicVersion
       status := status
       lastAttempt := lastAttempt
       auditHead := auditHead }, rest)

def encodeEvidenceMode : EvidenceMode → WireByte
  | .DIRECT_STATE_OWNED => byteOfNat 1
  | .PRIVATE_ZK => byteOfNat 2

def decodeEvidenceMode : WireByte → Option EvidenceMode
  | byte =>
      if byte.val = 1 then some .DIRECT_STATE_OWNED
      else if byte.val = 2 then some .PRIVATE_ZK
      else none

def encodeConflictPolicy : ConflictPolicy → WireByte
  | .priorityThenHumanReview => byteOfNat 1
  | .rejectOnConflict => byteOfNat 2

def decodeConflictPolicy : WireByte → Option ConflictPolicy
  | byte =>
      if byte.val = 1 then some .priorityThenHumanReview
      else if byte.val = 2 then some .rejectOnConflict
      else none

def encodeControlSet (control : ControlSet) : List WireByte :=
  encodeEvidenceMode control.mode ::
    encodeId control.evaluatorId ++
    encodeId control.controlSetId ++
    encodeId control.scopeId ++
    [encodeConflictPolicy control.conflictPolicy] ++
    encodeNat16 control.effectiveStart ++
    encodeNat16 control.effectiveEnd ++
    encodeId control.ruleFirst ++
    encodeOptionId control.ruleSecond

def decodeControlSet
    (bytes : List WireByte) : Option (ControlSet × List WireByte) := do
  let (modeByte, rest) ← readByte bytes
  let mode ← decodeEvidenceMode modeByte
  let (evaluator, rest) ← readId rest
  let (controlSetId, rest) ← readId rest
  let (scopeId, rest) ← readId rest
  let (conflictByte, rest) ← readByte rest
  let conflictPolicy ← decodeConflictPolicy conflictByte
  let (effectiveStart, rest) ← readNat16 rest
  let (effectiveEnd, rest) ← readNat16 rest
  let (ruleFirst, rest) ← readId rest
  let (ruleSecond, rest) ← decodeOptionId rest
  pure
    ({ mode := mode
       evaluatorId := evaluator
       controlSetId := controlSetId
       scopeId := scopeId
       conflictPolicy := conflictPolicy
       effectiveStart := effectiveStart
       effectiveEnd := effectiveEnd
       ruleFirst := ruleFirst
       ruleSecond := ruleSecond }, rest)

def encodeRequest (request : Request) : List WireByte :=
  encodeId request.providerId ++
    encodeId request.credentialId ++
    encodeId request.enrollmentId ++
    encodeId request.subjectId ++
    encodeId request.attemptId ++
    encodeNat16 request.epoch ++
    encodeNat16 request.sequenceBefore ++
    encodeNat16 request.eventTime ++
    encodeNat16 request.observationTime ++
    encodeNat16 request.ruleEffectiveTime ++
    encodeNat16 request.decisionTime ++
    encodeState request.expectedBefore

def decodeRequest (bytes : List WireByte) : Option (Request × List WireByte) := do
  let (providerId, rest) ← readId bytes
  let (credentialId, rest) ← readId rest
  let (enrollmentId, rest) ← readId rest
  let (subjectId, rest) ← readId rest
  let (attemptId, rest) ← readId rest
  let (epoch, rest) ← readNat16 rest
  let (sequenceBefore, rest) ← readNat16 rest
  let (eventTime, rest) ← readNat16 rest
  let (observationTime, rest) ← readNat16 rest
  let (ruleEffectiveTime, rest) ← readNat16 rest
  let (decisionTime, rest) ← readNat16 rest
  let (expectedBefore, rest) ← decodeState rest
  pure
    ({ providerId := providerId
       credentialId := credentialId
       enrollmentId := enrollmentId
       subjectId := subjectId
       attemptId := attemptId
       epoch := epoch
       sequenceBefore := sequenceBefore
       eventTime := eventTime
       observationTime := observationTime
       ruleEffectiveTime := ruleEffectiveTime
       decisionTime := decisionTime
       expectedBefore := expectedBefore }, rest)

def encodeFactStatus : FactStatus → WireByte
  | .ACTIVE => byteOfNat 1
  | .EXPIRED => byteOfNat 2
  | .TERMINATED => byteOfNat 3

def decodeFactStatus : WireByte → Option FactStatus
  | byte =>
      if byte.val = 1 then some .ACTIVE
      else if byte.val = 2 then some .EXPIRED
      else if byte.val = 3 then some .TERMINATED
      else none

def encodeFact : Option Fact → List WireByte
  | none => [byteOfNat 0]
  | some fact =>
      byteOfNat 1 ::
        encodeId fact.subjectId ++
        encodeId fact.feedId ++
        [encodeFactStatus fact.status] ++
        encodeNat16 fact.issuedAt ++
        encodeNat16 fact.expiresAt ++
        encodeNat16 fact.terminatedAt ++
        encodeNat16 fact.observedAt ++
        encodeId fact.recordId

def decodeFact (bytes : List WireByte) : Option (Option Fact × List WireByte) := do
  let (tag, rest) ← readByte bytes
  if tag.val = 0 then
    pure (none, rest)
  else if tag.val = 1 then
    let (subjectId, rest) ← readId rest
    let (feedId, rest) ← readId rest
    let (statusByte, rest) ← readByte rest
    let status ← decodeFactStatus statusByte
    let (issuedAt, rest) ← readNat16 rest
    let (expiresAt, rest) ← readNat16 rest
    let (terminatedAt, rest) ← readNat16 rest
    let (observedAt, rest) ← readNat16 rest
    let (recordId, rest) ← readId rest
    pure
      (some
        { subjectId := subjectId
          feedId := feedId
          status := status
          issuedAt := issuedAt
          expiresAt := expiresAt
          terminatedAt := terminatedAt
          observedAt := observedAt
          recordId := recordId }, rest)
  else
    none

def encodeCompleteness (completeness : Completeness) : List WireByte :=
  encodeId completeness.feedId ++
    encodeId completeness.providerId ++
    encodeId completeness.scopeId ++
    encodeNat16 completeness.observationTime ++
    [if completeness.complete then byteOfNat 1 else byteOfNat 0] ++
    encodeOptionId completeness.absenceFirst ++
    encodeOptionId completeness.absenceSecond

def decodeCompleteness
    (bytes : List WireByte) : Option (Completeness × List WireByte) := do
  let (feedId, rest) ← readId bytes
  let (providerId, rest) ← readId rest
  let (scopeId, rest) ← readId rest
  let (observationTime, rest) ← readNat16 rest
  let (completeByte, rest) ← readByte rest
  let complete ←
    if completeByte.val = 0 then some false
    else if completeByte.val = 1 then some true
    else none
  let (absenceFirst, rest) ← decodeOptionId rest
  let (absenceSecond, rest) ← decodeOptionId rest
  pure
    ({ feedId := feedId
       providerId := providerId
       scopeId := scopeId
       observationTime := observationTime
       complete := complete
       absenceFirst := absenceFirst
       absenceSecond := absenceSecond }, rest)

def encodePolicyResult : PolicyResult → WireByte
  | .pass => byteOfNat 1
  | .missingEvidence => byteOfNat 2
  | .ambiguous => byteOfNat 3
  | .fail => byteOfNat 4

def decodePolicyResult : WireByte → Option PolicyResult
  | byte =>
      if byte.val = 1 then some .pass
      else if byte.val = 2 then some .missingEvidence
      else if byte.val = 3 then some .ambiguous
      else if byte.val = 4 then some .fail
      else none

def encodeException : Option ExceptionAuthorization → List WireByte
  | none => [byteOfNat 0]
  | some authorization =>
      byteOfNat 1 ::
        encodeId authorization.authorizationId ++
        encodeId authorization.signerId ++
        encodeId authorization.subjectId ++
        encodeId authorization.ruleId ++
        encodeId authorization.reasonId ++
        encodeId authorization.amountScope ++
        encodeNat16 authorization.effectiveAt ++
        encodeNat16 authorization.expiresAt ++
        [encodePolicyResult authorization.policyResult]

def decodeException
    (bytes : List WireByte) : Option (Option ExceptionAuthorization × List WireByte) := do
  let (tag, rest) ← readByte bytes
  if tag.val = 0 then
    pure (none, rest)
  else if tag.val = 1 then
    let (authorizationId, rest) ← readId rest
    let (signerId, rest) ← readId rest
    let (subjectId, rest) ← readId rest
    let (ruleId, rest) ← readId rest
    let (reasonId, rest) ← readId rest
    let (amountScope, rest) ← readId rest
    let (effectiveAt, rest) ← readNat16 rest
    let (expiresAt, rest) ← readNat16 rest
    let (policyByte, rest) ← readByte rest
    let policyResult ← decodePolicyResult policyByte
    pure
      (some
        { authorizationId := authorizationId
          signerId := signerId
          subjectId := subjectId
          ruleId := ruleId
          reasonId := reasonId
          amountScope := amountScope
          effectiveAt := effectiveAt
          expiresAt := expiresAt
          policyResult := policyResult }, rest)
  else
    none

def encodeAuthorityMode : AuthorityMode → WireByte
  | .observeOnly => byteOfNat 0
  | .operative => byteOfNat 1

def decodeAuthorityMode : WireByte → Option AuthorityMode
  | byte =>
      if byte.val = 0 then some .observeOnly
      else if byte.val = 1 then some .operative
      else none

def rawEncode (input : ClearanceInput) : List WireByte :=
  codecMagic ++
    encodeControlSet input.controlSet ++
    encodeRequest input.request ++
    encodeFact input.facts.first ++
    encodeFact input.facts.second ++
    encodeCompleteness input.completeness ++
    encodeException input.exception ++
    encodeState input.before ++
    [encodeAuthorityMode input.authority] ++
    [if input.proofAccepted then byteOfNat 1 else byteOfNat 0]

def canonicalEncode (input : ClearanceInput) : Option (List WireByte) :=
  if wellFormedInput input then some (rawEncode input) else none

def decode (bytes : List WireByte) : Option ClearanceInput := do
  let rest ← readTag 66 bytes
  let rest ← readTag 76 rest
  let rest ← readTag 75 rest
  let rest ← readTag 49 rest
  let (controlSet, rest) ← decodeControlSet rest
  let (request, rest) ← decodeRequest rest
  let (first, rest) ← decodeFact rest
  let (second, rest) ← decodeFact rest
  let (completeness, rest) ← decodeCompleteness rest
  let (exception, rest) ← decodeException rest
  let (before, rest) ← decodeState rest
  let (authorityByte, rest) ← readByte rest
  let authority ← decodeAuthorityMode authorityByte
  let (proofByte, rest) ← readByte rest
  let proofAccepted ←
    if proofByte.val = 0 then some false
    else if proofByte.val = 1 then some true
    else none
  let input : ClearanceInput :=
    { controlSet := controlSet
      request := request
      facts := { first := first, second := second }
      completeness := completeness
      exception := exception
      authority := authority
      proofAccepted := proofAccepted
      before := before }
  if rest.isEmpty && wellFormedInput input then some input else none

def encodedLength (input : ClearanceInput) : Nat :=
  (rawEncode input).length

end BlindLedger.Kernel
