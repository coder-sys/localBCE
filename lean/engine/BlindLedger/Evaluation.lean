import BlindLedger.ControlSet

namespace BlindLedger.Kernel

/-! Pure semantic evaluation.  The result is always a pair: the underlying
    policy result is retained even when a governed exception changes the
    effective directive.  Proof/session acceptance is deliberately not an
    input to this evaluator's decision branch. -/

inductive Reason where
  | validContinuity
  | authoritativeAbsence
  | expiredOrTerminated
  | incompleteOrAmbiguous
  | staleRuleInterval
  | controlInterval
deriving DecidableEq, Repr

structure SemanticResult where
  policyResult : PolicyResult
  effectiveDirective : EffectiveDirective
  reason : Reason
  exceptionId : Option Id
  sourceRoot : Id
  completenessId : Id
deriving DecidableEq, Repr

def isEconomicDirective : EffectiveDirective → Bool
  | .CLEAR => true
  | .EXCEPTION_APPROVED => true
  | _ => false

def sourceRootOf (input : ClearanceInput) : Id :=
  idOfNat
    (17 + input.completeness.feedId.value.val * 3 +
      input.request.providerId.value.val * 5 +
      input.request.subjectId.value.val * 7 +
      match input.facts.first, input.facts.second with
      | none, none => 0
      | some first, none => first.recordId.value.val
      | none, some second => second.recordId.value.val
      | some first, some second =>
          first.recordId.value.val * 11 + second.recordId.value.val * 13)

def completenessIdOf (input : ClearanceInput) : Id :=
  idOfNat
    (29 + input.completeness.feedId.value.val * 3 +
      input.completeness.providerId.value.val * 5 +
      input.completeness.scopeId.value.val * 7 +
      input.completeness.observationTime +
      if input.completeness.complete then 1 else 0)

def factWellFormed (request : Request) (completeness : Completeness)
    (fact : Fact) : Bool :=
  fact.subjectId.isNonzero &&
    fact.feedId.isNonzero &&
    fact.recordId.isNonzero &&
    fact.feedId = completeness.feedId &&
    fact.observedAt = request.observationTime &&
    fact.issuedAt ≤ 65535 &&
    fact.expiresAt ≤ 65535 &&
    fact.terminatedAt ≤ 65535 &&
    fact.observedAt ≤ 65535 &&
    fact.issuedAt < fact.expiresAt &&
    match fact.status with
    | .ACTIVE =>
        decide (fact.terminatedAt = 0 ∧
          fact.issuedAt ≤ fact.observedAt ∧ fact.observedAt < fact.expiresAt)
    | .EXPIRED =>
        decide (fact.terminatedAt = 0 ∧ fact.expiresAt ≤ fact.observedAt)
    | .TERMINATED =>
        decide (fact.issuedAt ≤ fact.terminatedAt ∧
          fact.terminatedAt ≤ fact.observedAt)

def factSlotsCanonical (facts : FactSlots) : Bool :=
  match facts.first, facts.second with
  | none, none => true
  | none, some _ => false
  | some _, none => true
  | some first, some second =>
      decide (first.recordId.value.val < second.recordId.value.val)

def factSlotsWellFormed (request : Request) (completeness : Completeness)
    (facts : FactSlots) : Bool :=
  factSlotsCanonical facts &&
    match facts.first, facts.second with
    | none, none => true
    | some first, none => factWellFormed request completeness first
    | none, some _ => false
    | some first, some second =>
        factWellFormed request completeness first &&
          factWellFormed request completeness second

def completenessWellFormed (request : Request)
    (completeness : Completeness) : Bool :=
  completeness.feedId.isNonzero &&
    completeness.providerId.isNonzero &&
    completeness.scopeId.isNonzero &&
    completeness.observationTime ≤ 65535 &&
    completeness.providerId = request.providerId &&
    completeness.scopeId = request.subjectId &&
    completeness.observationTime = request.observationTime &&
    (if completeness.complete then
      true
    else
      completeness.absenceFirst = none && completeness.absenceSecond = none) &&
    match completeness.absenceFirst, completeness.absenceSecond with
    | none, none => true
    | some first, none => first.isNonzero
    | none, some _ => false
    | some first, some second =>
        first.isNonzero && second.isNonzero &&
          decide (first.value.val < second.value.val)

def absenceContains (completeness : Completeness) (subject : Id) : Bool :=
  completeness.absenceFirst = some subject ||
    completeness.absenceSecond = some subject

def exceptionWellFormed : Option ExceptionAuthorization → Bool
  | none => true
  | some authorization =>
      authorization.authorizationId.isNotSentinel noExceptionSentinel &&
        authorization.signerId.isNonzero &&
        authorization.subjectId.isNonzero &&
        authorization.ruleId.isNonzero &&
        authorization.reasonId.isNonzero &&
        authorization.amountScope.isNonzero &&
        authorization.effectiveAt ≤ 65535 &&
        authorization.expiresAt ≤ 65535 &&
        authorization.effectiveAt < authorization.expiresAt

def stateWellFormed (state : LedgerState) : Bool :=
  state.sequence ≤ 65535 &&
    state.economicVersion ≤ 65535 &&
    state.auditHead.isNonzero &&
    match state.lastAttempt with
    | none => true
    | some attempt => attempt.isNonzero

def requestWellFormed (request : Request) : Bool :=
  request.chronology.strictBool &&
    request.providerId.isNonzero &&
    request.credentialId.isNonzero &&
    request.enrollmentId.isNonzero &&
    request.subjectId.isNonzero &&
    request.attemptId.isNonzero &&
    request.epoch ≤ 65535 &&
    request.sequenceBefore ≤ 65535 &&
    request.eventTime ≤ 65535 &&
    request.observationTime ≤ 65535 &&
    request.ruleEffectiveTime ≤ 65535 &&
    request.decisionTime ≤ 65535 &&
    stateWellFormed request.expectedBefore

def noMatchingFacts (input : ClearanceInput) : Bool :=
  match input.facts.first, input.facts.second with
  | none, none => true
  | some first, none => decide (first.subjectId ≠ input.request.subjectId)
  | none, some second => decide (second.subjectId ≠ input.request.subjectId)
  | some first, some second =>
      decide (first.subjectId ≠ input.request.subjectId ∧
        second.subjectId ≠ input.request.subjectId)

def matchingFacts (input : ClearanceInput) : List Fact :=
  (match input.facts.first with
   | none => []
   | some first => [first]) ++
    (match input.facts.second with
     | none => []
     | some second => [second]) |>.filter
      (fun fact => decide (fact.subjectId = input.request.subjectId))

def authoritativeAbsence (input : ClearanceInput) : Bool :=
  input.completeness.complete &&
    input.completeness.feedId = input.completeness.feedId &&
    input.completeness.providerId = input.request.providerId &&
    input.completeness.scopeId = input.request.subjectId &&
    input.completeness.observationTime = input.request.observationTime &&
    absenceContains input.completeness input.request.subjectId

def noFactAbsenceConflict (input : ClearanceInput) : Bool :=
  match input.facts.first, input.facts.second with
  | none, none => true
  | some first, none => first.subjectId ≠ input.request.subjectId ||
      !absenceContains input.completeness first.subjectId
  | none, some second => second.subjectId ≠ input.request.subjectId ||
      !absenceContains input.completeness second.subjectId
  | some first, some second =>
      (first.subjectId ≠ input.request.subjectId ||
        !absenceContains input.completeness first.subjectId) &&
      (second.subjectId ≠ input.request.subjectId ||
        !absenceContains input.completeness second.subjectId)

def wellFormedInput (input : ClearanceInput) : Bool :=
    controlSetWellFormed input.controlSet &&
    requestWellFormed input.request &&
    stateWellFormed input.before &&
    input.request.expectedBefore = input.before &&
    input.request.sequenceBefore = input.before.sequence &&
    factSlotsWellFormed input.request input.completeness input.facts &&
    completenessWellFormed input.request input.completeness &&
    exceptionWellFormed input.exception &&
    noFactAbsenceConflict input

def exactException
    (input : ClearanceInput) (base : SemanticResult)
    (authorization : ExceptionAuthorization) : Bool :=
  base.policyResult = .fail &&
    authorization.signerId = trustedAuthorizerId &&
    authorization.subjectId = input.request.subjectId &&
    authorization.ruleId = expectedRuleId &&
    authorization.reasonId = expectedReasonId &&
    authorization.amountScope = expectedAmountScope &&
    authorization.policyResult = .fail &&
    authorization.effectiveAt ≤ input.request.ruleEffectiveTime &&
    input.request.decisionTime < authorization.expiresAt

def baseEvaluation (input : ClearanceInput) : SemanticResult :=
  let sourceRoot := sourceRootOf input
  let completenessId := completenessIdOf input
  if !inControlInterval input.controlSet input.request.ruleEffectiveTime then
    { policyResult := .ambiguous
      effectiveDirective := .HUMAN_REVIEW
      reason := .staleRuleInterval
      exceptionId := none
      sourceRoot := sourceRoot
      completenessId := completenessId }
  else if !inControlInterval input.controlSet input.request.decisionTime then
    { policyResult := .ambiguous
      effectiveDirective := .HUMAN_REVIEW
      reason := .controlInterval
      exceptionId := none
      sourceRoot := sourceRoot
      completenessId := completenessId }
  else
    match matchingFacts input with
    | [] =>
        if authoritativeAbsence input then
          { policyResult := .missingEvidence
            effectiveDirective := .HOLD
            reason := .authoritativeAbsence
            exceptionId := none
            sourceRoot := sourceRoot
            completenessId := completenessId }
        else
          { policyResult := .ambiguous
            effectiveDirective := .HUMAN_REVIEW
            reason := .incompleteOrAmbiguous
            exceptionId := none
            sourceRoot := sourceRoot
            completenessId := completenessId }
    | [fact] =>
        match fact.status with
        | .ACTIVE =>
            { policyResult := .pass
              effectiveDirective := .CLEAR
              reason := .validContinuity
              exceptionId := none
              sourceRoot := sourceRoot
              completenessId := completenessId }
        | .EXPIRED | .TERMINATED =>
            { policyResult := .fail
              effectiveDirective := .BLOCK
              reason := .expiredOrTerminated
              exceptionId := none
              sourceRoot := sourceRoot
              completenessId := completenessId }
    | _ =>
        { policyResult := .ambiguous
          effectiveDirective := .HUMAN_REVIEW
          reason := .incompleteOrAmbiguous
          exceptionId := none
          sourceRoot := sourceRoot
          completenessId := completenessId }

def evaluate (input : ClearanceInput) : Option SemanticResult :=
  if wellFormedInput input = false then
    none
  else if controlSetMatches input.controlSet = false then
    none
  else
    let base := baseEvaluation input
    match input.exception with
    | none =>
        if policyDirectiveConsistent base.policyResult base.effectiveDirective then
          some base
        else
          none
    | some authorization =>
        if exactException input base authorization then
          some
            { base with
              effectiveDirective := .EXCEPTION_APPROVED
              exceptionId := some authorization.authorizationId }
        else
          none

def proofSessionOnly (_accepted : Bool) : Option EffectiveDirective :=
  none

def semanticResultIsHold (result : SemanticResult) : Bool :=
  result.policyResult = .missingEvidence &&
    result.effectiveDirective = .HOLD

def semanticResultIsException (result : SemanticResult) : Bool :=
  result.effectiveDirective = .EXCEPTION_APPROVED

def baseInput (attempt : Nat) : ClearanceInput :=
  let before := initialState
  { controlSet := fixedControlSet
    request :=
      { providerId := idOfNat 2
        credentialId := idOfNat 3
        enrollmentId := idOfNat 4
        subjectId := idOfNat 5
        attemptId := idOfNat attempt
        epoch := 7
        sequenceBefore := 0
        eventTime := 7000
        observationTime := 7001
        ruleEffectiveTime := 6999
        decisionTime := 7002
        expectedBefore := before }
    facts := emptyFactSlots
    completeness :=
      { feedId := idOfNat 20
        providerId := idOfNat 2
        scopeId := idOfNat 5
        observationTime := 7001
        complete := true
        absenceFirst := none
        absenceSecond := none }
    exception := none
    authority := .operative
    proofAccepted := false
    before := before }

def factFor (status : FactStatus) (record : Nat)
    (expiresAt terminatedAt : Nat) : Fact :=
  { subjectId := idOfNat 5
    feedId := idOfNat 20
    status := status
    issuedAt := 6000
    expiresAt := expiresAt
    terminatedAt := terminatedAt
    observedAt := 7001
    recordId := idOfNat record }

def validInput : ClearanceInput :=
  { baseInput 1 with
    facts := { first := some (factFor .ACTIVE 30 8000 0), second := none } }

def expiredInput : ClearanceInput :=
  { baseInput 2 with
    facts := { first := some (factFor .EXPIRED 31 6900 0), second := none } }

def terminatedInput : ClearanceInput :=
  { baseInput 3 with
    facts := { first := some (factFor .TERMINATED 32 8000 7000), second := none } }

def missingIncompleteInput : ClearanceInput :=
  { baseInput 4 with
    completeness := { (baseInput 4).completeness with complete := false } }

def authoritativeAbsenceInput : ClearanceInput :=
  { baseInput 5 with
    completeness :=
      { (baseInput 5).completeness with absenceFirst := some (idOfNat 5) } }

def conflictingFactsInput : ClearanceInput :=
  { baseInput 6 with
    facts :=
      { first := some (factFor .ACTIVE 33 8000 0)
        second := some (factFor .TERMINATED 34 8000 7000) } }

def staleRuleInput : ClearanceInput :=
  { baseInput 7 with
    request := { (baseInput 7).request with ruleEffectiveTime := 5999 } }

def governedException : ExceptionAuthorization :=
  { authorizationId := idOfNat 40
    signerId := trustedAuthorizerId
    subjectId := idOfNat 5
    ruleId := expectedRuleId
    reasonId := expectedReasonId
    amountScope := expectedAmountScope
    effectiveAt := 6998
    expiresAt := 7003
    policyResult := .fail }

def governedExceptionInput : ClearanceInput :=
  { baseInput 8 with
    facts := { first := some (factFor .TERMINATED 35 8000 7000), second := none }
    exception := some governedException }

def observeOnlyInput : ClearanceInput :=
  { validInput with authority := .observeOnly }

def wrongControlSetInput : ClearanceInput :=
  { validInput with
    controlSet := { fixedControlSet with scopeId := idOfNat 14 } }

def badChronologyInput : ClearanceInput :=
  { validInput with
    request := { validInput.request with observationTime := 6999 } }

def badExceptionInput : ClearanceInput :=
  { governedExceptionInput with
    exception := some { governedException with signerId := idOfNat 99 } }

inductive KnownCase where
  | validContinuity
  | expiredCredential
  | terminatedCredential
  | missingIncompleteFeed
  | authoritativeAbsence
  | conflictingFacts
  | staleRuleInterval
  | governedException
deriving DecidableEq, Repr

def KnownCase.name : KnownCase → String
  | .validContinuity => "valid-continuity"
  | .expiredCredential => "expired-credential"
  | .terminatedCredential => "terminated-credential"
  | .missingIncompleteFeed => "missing-incomplete-feed"
  | .authoritativeAbsence => "authoritative-absence"
  | .conflictingFacts => "conflicting-facts"
  | .staleRuleInterval => "stale-rule-interval"
  | .governedException => "governed-exception"

def KnownCase.input : KnownCase → ClearanceInput
  | .validContinuity => validInput
  | .expiredCredential => expiredInput
  | .terminatedCredential => terminatedInput
  | .missingIncompleteFeed => missingIncompleteInput
  | .authoritativeAbsence => authoritativeAbsenceInput
  | .conflictingFacts => conflictingFactsInput
  | .staleRuleInterval => staleRuleInput
  | .governedException => governedExceptionInput

def KnownCase.expected : KnownCase → PolicyResult × EffectiveDirective
  | .validContinuity => (.pass, .CLEAR)
  | .expiredCredential => (.fail, .BLOCK)
  | .terminatedCredential => (.fail, .BLOCK)
  | .missingIncompleteFeed => (.ambiguous, .HUMAN_REVIEW)
  | .authoritativeAbsence => (.missingEvidence, .HOLD)
  | .conflictingFacts => (.ambiguous, .HUMAN_REVIEW)
  | .staleRuleInterval => (.ambiguous, .HUMAN_REVIEW)
  | .governedException => (.fail, .EXCEPTION_APPROVED)

def knownCases : List KnownCase :=
  [ .validContinuity, .expiredCredential, .terminatedCredential,
    .missingIncompleteFeed, .authoritativeAbsence, .conflictingFacts,
    .staleRuleInterval, .governedException ]

theorem known_case_inputs_well_formed :
    ∀ case : KnownCase, wellFormedInput (KnownCase.input case) = true := by
  intro case
  cases case <;> decide

theorem known_case_evaluations_match :
    ∀ case : KnownCase, ∃ result, evaluate (KnownCase.input case) = some result ∧
      (result.policyResult, result.effectiveDirective) = KnownCase.expected case := by
  intro case
  cases case <;> decide

end BlindLedger.Kernel
