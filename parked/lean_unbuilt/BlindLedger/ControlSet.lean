import BlindLedger.Types

namespace BlindLedger.Kernel

/-! The evaluator has one verifier-owned control set.  Its identity is a
    structural value in this model, so a caller cannot substitute a different
    mode, ordered rule list, scope, conflict policy, or interval. -/

def trustedAuthorizerId : Id := idOfNat 21

def expectedRuleId : Id := idOfNat 22

def expectedReasonId : Id := idOfNat 23

def expectedAmountScope : Id := idOfNat 24

def noExceptionSentinel : Id := idOfNat 224

def evaluatorId : Id := idOfNat 11

def fixedControlSetId : Id := idOfNat 10

def fixedScopeId : Id := idOfNat 13

def fixedControlSet : ControlSet :=
  { mode := .DIRECT_STATE_OWNED
    evaluatorId := evaluatorId
    controlSetId := fixedControlSetId
    scopeId := fixedScopeId
    conflictPolicy := .priorityThenHumanReview
    effectiveStart := 6000
    effectiveEnd := 9000
    ruleFirst := expectedRuleId
    ruleSecond := none }

def controlSetWellFormed (control : ControlSet) : Bool :=
  control.effectiveStart < control.effectiveEnd &&
    control.effectiveStart ≤ 65535 &&
    control.effectiveEnd ≤ 65535 &&
    control.ruleFirst.isNonzero &&
    match control.ruleSecond with
    | none => true
    | some second => second.isNonzero && second ≠ control.ruleFirst

def controlSetMatches (control : ControlSet) : Bool :=
  decide (control = fixedControlSet)

def inControlInterval (control : ControlSet) (time : Nat) : Bool :=
  decide (control.effectiveStart ≤ time ∧ time < control.effectiveEnd)

theorem fixed_control_set_well_formed :
    controlSetWellFormed fixedControlSet = true := by
  decide

theorem control_set_mismatch_is_decidable (control : ControlSet) :
    control = fixedControlSet ∨ control ≠ fixedControlSet := by
  by_cases h : control = fixedControlSet
  · exact Or.inl h
  · exact Or.inr h

end BlindLedger.Kernel
