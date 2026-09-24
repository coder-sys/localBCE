import BlindLedger.Evaluation

namespace BlindLedger.Kernel

/-! Legal local state transition and the exact two-row decision/access join.
    This is an abstract pure transition: database serialization, durability,
    recovery, and concurrent linearizability remain outside this kernel. -/

def decisionIdOf (input : ClearanceInput) (result : SemanticResult) : Id :=
  idOfNat
    (41 + input.request.attemptId.value.val * 3 +
      result.sourceRoot.value.val * 5 + result.completenessId.value.val * 7)

def requestIdOf (request : Request) : Id :=
  idOfNat
    (51 + request.providerId.value.val * 3 + request.subjectId.value.val * 5 +
      request.attemptId.value.val * 7 + request.eventTime)

def auditHeadAfter
    (before : LedgerState) (decisionId : Id)
    (directive : EffectiveDirective) : Id :=
  idOfNat
    (before.auditHead.value.val + decisionId.value.val * 3 +
      match directive with
      | .CLEAR => 1
      | .HOLD => 2
      | .HUMAN_REVIEW => 3
      | .BLOCK => 4
      | .EXCEPTION_APPROVED => 5)

def advanceState
    (before : LedgerState) (attemptId decisionId : Id)
    (directive : EffectiveDirective) : Option LedgerState :=
  if before.sequence = 65535 then
    none
  else if isEconomicDirective directive && before.economicVersion = 65535 then
    none
  else if before.lastAttempt = some attemptId then
    none
  else
    some
      { sequence := before.sequence + 1
        economicVersion :=
          if isEconomicDirective directive then before.economicVersion + 1
          else before.economicVersion
        status :=
          if isEconomicDirective directive then .cleared else before.status
        lastAttempt := some attemptId
        auditHead := auditHeadAfter before decisionId directive }

structure Decision where
  decisionId : Id
  requestId : Id
  attemptId : Id
  request : Request
  semantic : SemanticResult
  before : LedgerState
  after : LedgerState
  operative : Bool
deriving DecidableEq, Repr

def makeDecision (input : ClearanceInput) : Option Decision :=
  if input.authority = .observeOnly then
    none
  else
    match evaluate input with
    | none => none
    | some result =>
        let decisionId := decisionIdOf input result
        match advanceState input.before input.request.attemptId decisionId
            result.effectiveDirective with
        | none => none
        | some after =>
            some
              { decisionId := decisionId
                requestId := requestIdOf input.request
                attemptId := input.request.attemptId
                request := input.request
                semantic := result
                before := input.before
                after := after
                operative := true }

def expectedAfter (decision : Decision) : Option LedgerState :=
  advanceState decision.before decision.attemptId decision.decisionId
    decision.semantic.effectiveDirective

def applyTransition
    (state : LedgerState) (decision : Decision) : Option LedgerState :=
  if decision.operative = false then
    none
  else if decision.before ≠ state then
    none
  else
    match expectedAfter decision with
    | none => none
    | some expected =>
        if expected = decision.after then some decision.after else none

def economicView (state : LedgerState) : EconomicStatus × Nat :=
  (state.status, state.economicVersion)

def sourceStateAddress : Id := idOfNat 61

def auditStateAddress : Id := idOfNat 62

structure AccessRow where
  decisionId : Id
  decisionIndex : Nat
  accessIndex : Nat
  accessCount : Nat
  time : Nat
  address : Id
  key : Id
  valueBefore : Id
  valueAfter : Id
  mode : AccessMode
deriving DecidableEq, Repr

def expectedAccesses (decision : Decision) : List AccessRow :=
  [ { decisionId := decision.decisionId
      decisionIndex := 0
      accessIndex := 0
      accessCount := 2
      time := decision.request.observationTime
      address := sourceStateAddress
      key := decision.request.subjectId
      valueBefore := decision.semantic.sourceRoot
      valueAfter := decision.semantic.sourceRoot
      mode := .READ },
    { decisionId := decision.decisionId
      decisionIndex := 0
      accessIndex := 1
      accessCount := 2
      time := decision.request.decisionTime
      address := auditStateAddress
      key := decision.decisionId
      valueBefore := decision.before.auditHead
      valueAfter := decision.after.auditHead
      mode := .WRITE } ]

structure DecisionAccessJoin where
  decision : Decision
  accesses : List AccessRow
deriving DecidableEq, Repr

def joinValid (join : DecisionAccessJoin) : Bool :=
  join.accesses = expectedAccesses join.decision

def buildJoin (decision : Decision) : Option DecisionAccessJoin :=
  some { decision := decision, accesses := expectedAccesses decision }

def transitionResult (input : ClearanceInput) : Option LedgerState :=
  match makeDecision input with
  | none => none
  | some decision => applyTransition input.before decision

theorem makeDecision_some_has_operative_authority
    {input : ClearanceInput} {decision : Decision}
    (h : makeDecision input = some decision) :
    decision.operative = true := by
  unfold makeDecision at h
  by_cases ha : input.authority = .observeOnly
  · simp [ha] at h
  · simp [ha] at h
    cases heval : evaluate input with
    | none => simp [heval] at h
    | some result =>
        cases hstate : advanceState input.before input.request.attemptId
            (decisionIdOf input result) result.effectiveDirective with
        | none => simp [heval, hstate] at h
        | some after =>
            simp [heval, hstate] at h
            cases h
            rfl

theorem applyTransition_rejects_wrong_before
    (state : LedgerState) (decision : Decision)
    (hwrong : decision.before ≠ state) :
    applyTransition state decision = none := by
  simp [applyTransition, hwrong]

theorem expected_accesses_are_exact
    (decision : Decision) :
    (expectedAccesses decision).length = 2 := by
  simp [expectedAccesses]

end BlindLedger.Kernel
