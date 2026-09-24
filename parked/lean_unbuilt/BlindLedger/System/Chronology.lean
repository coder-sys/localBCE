import Std
import BlindLedger.System.Types

namespace BlindLedger.System

/-! This module models the State chronology and its exact access records.  All
    inputs remain raw data: admission is checked by `validate`, rather than
    being encoded only in the type of a pre-validated constructor. -/

structure DecisionId where
  token : Nat
deriving DecidableEq, Repr

structure Chronology where
  ruleEffective : Nat
  event : Nat
  observation : Nat
  decision : Nat
deriving DecidableEq, Repr

def Chronology.Strict (chronology : Chronology) : Prop :=
  chronology.ruleEffective < chronology.event ∧
    chronology.event < chronology.observation ∧
    chronology.observation < chronology.decision

instance chronologyStrictDecidable (chronology : Chronology) :
    Decidable (Chronology.Strict chronology) := by
  unfold Chronology.Strict
  infer_instance

def Chronology.isStrict (chronology : Chronology) : Bool :=
  decide (Chronology.Strict chronology)

structure DecisionBinding where
  decisionId : DecisionId
  chronology : Chronology
deriving DecidableEq, Repr

structure RequestRecord where
  binding : DecisionBinding
deriving DecidableEq, Repr

structure StateDecisionRecord where
  binding : DecisionBinding
deriving DecidableEq, Repr

structure StateReceiptRecord where
  binding : DecisionBinding
deriving DecidableEq, Repr

structure RetryRecord where
  binding : DecisionBinding
  attempt : Nat
deriving DecidableEq, Repr

/-! An exact retry changes delivery metadata only; it cannot change the
    decision binding or any bound chronology time. -/
def RetryRecord.nextAttempt (record : RetryRecord) : RetryRecord :=
  { record with attempt := record.attempt + 1 }

theorem RetryRecord.nextAttempt_preserves_binding (record : RetryRecord) :
    (record.nextAttempt).binding = record.binding := by
  rfl

theorem RetryRecord.nextAttempt_preserves_decision_time (record : RetryRecord) :
    (record.nextAttempt).binding.chronology.decision =
      record.binding.chronology.decision := by
  rfl

inductive AccessRole where
  | READ
  | WRITE
deriving DecidableEq, Repr

structure RawAccessRecord where
  index : Nat
  decisionId : DecisionId
  role : AccessRole
  time : Nat
deriving DecidableEq, Repr

structure BoundAccessRecord where
  index : Fin 2
  decisionId : DecisionId
  role : AccessRole
  time : Nat
deriving DecidableEq, Repr

def accessZero : Fin 2 := ⟨0, by decide⟩

def accessOne : Fin 2 := ⟨1, by decide⟩

def boundAccess (index : Fin 2) (record : RawAccessRecord) : BoundAccessRecord :=
  { index := index
    decisionId := record.decisionId
    role := record.role
    time := record.time }

structure ChronologyAccessInput where
  request : RequestRecord
  stateDecision : StateDecisionRecord
  stateReceipt : StateReceiptRecord
  retry : RetryRecord
  decisionIndex : Nat
  accessCount : Nat
  accesses : List RawAccessRecord
deriving DecidableEq, Repr

/-! The four records are joined through one complete binding.  Equality here
    checks both the decision identity and all four chronology coordinates. -/
def bindingsAgree (input : ChronologyAccessInput) : Prop :=
  input.request.binding = input.stateDecision.binding ∧
    input.stateDecision.binding = input.stateReceipt.binding ∧
    input.stateReceipt.binding = input.retry.binding

def expectedRead (input : ChronologyAccessInput) : RawAccessRecord :=
  { index := 0
    decisionId := input.request.binding.decisionId
    role := .READ
    time := input.request.binding.chronology.observation }

def expectedWrite (input : ChronologyAccessInput) : RawAccessRecord :=
  { index := 1
    decisionId := input.request.binding.decisionId
    role := .WRITE
    time := input.request.binding.chronology.decision }

/-! Equality with this expected raw list is an executable exactness check: it
    rejects duplicate, omitted, extra, reordered, wrong-decision, wrong-role,
    and wrong-time rows. -/
def exactAccessRows (input : ChronologyAccessInput) : Prop :=
  input.accesses = [expectedRead input, expectedWrite input]

def Admission (input : ChronologyAccessInput) : Prop :=
  input.decisionIndex = 0 ∧
    input.accessCount = 2 ∧
    Chronology.Strict input.request.binding.chronology ∧
    bindingsAgree input ∧
    exactAccessRows input

instance admissionDecidable (input : ChronologyAccessInput) :
    Decidable (Admission input) := by
  unfold Admission bindingsAgree exactAccessRows
  infer_instance

structure ValidatedChronologyAccess where
  original : ChronologyAccessInput
  indexedAccesses : Fin 2 → BoundAccessRecord

def makeValidated
    (input : ChronologyAccessInput)
    (readRow writeRow : RawAccessRecord) : ValidatedChronologyAccess :=
  { original := input
    indexedAccesses := fun index =>
      if index.val = 0 then
        boundAccess accessZero readRow
      else
        boundAccess accessOne writeRow }

def validate (input : ChronologyAccessInput) : Option ValidatedChronologyAccess :=
  if _h : Admission input then
    match input.accesses with
    | [readRow, writeRow] => some (makeValidated input readRow writeRow)
    | _ => none
  else
    none

def accepted (input : ChronologyAccessInput) : Bool :=
  match validate input with
  | some _ => true
  | none => false

theorem validate_success_implies_admission
    {input : ChronologyAccessInput}
    {result : ValidatedChronologyAccess}
    (h : validate input = some result) :
    Admission input := by
  by_cases hadmission : Admission input
  · exact hadmission
  · simp [validate, hadmission] at h

theorem validate_success_preserves_original
    {input : ChronologyAccessInput}
    {result : ValidatedChronologyAccess}
    (h : validate input = some result) :
    result.original = input := by
  have hadmission := validate_success_implies_admission h
  have haccess : input.accesses = [expectedRead input, expectedWrite input] := by
    rcases hadmission with ⟨_, _, _, _, haccess⟩
    exact haccess
  have hresult :
      makeValidated input (expectedRead input) (expectedWrite input) = result := by
    simpa [validate, hadmission, haccess] using h
  cases hresult
  rfl

theorem validate_success_decision_index
    {input : ChronologyAccessInput}
    {result : ValidatedChronologyAccess}
    (h : validate input = some result) :
    input.decisionIndex = 0 := by
  rcases validate_success_implies_admission h with
    ⟨hindex, _, _, _, _⟩
  exact hindex

theorem validate_success_access_count
    {input : ChronologyAccessInput}
    {result : ValidatedChronologyAccess}
    (h : validate input = some result) :
    input.accessCount = 2 := by
  rcases validate_success_implies_admission h with
    ⟨_, hcount, _, _, _⟩
  exact hcount

theorem validate_success_strict_chronology
    {input : ChronologyAccessInput}
    {result : ValidatedChronologyAccess}
    (h : validate input = some result) :
    Chronology.Strict input.request.binding.chronology := by
  rcases validate_success_implies_admission h with
    ⟨_, _, hchronology, _, _⟩
  exact hchronology

theorem validate_success_bindings_agree
    {input : ChronologyAccessInput}
    {result : ValidatedChronologyAccess}
    (h : validate input = some result) :
    bindingsAgree input := by
  rcases validate_success_implies_admission h with
    ⟨_, _, _, hbindings, _⟩
  exact hbindings

theorem validate_success_accesses_exact
    {input : ChronologyAccessInput}
    {result : ValidatedChronologyAccess}
    (h : validate input = some result) :
    input.accesses = [expectedRead input, expectedWrite input] := by
  rcases validate_success_implies_admission h with
    ⟨_, _, _, _, haccess⟩
  exact haccess

theorem validate_success_access_length
    {input : ChronologyAccessInput}
    {result : ValidatedChronologyAccess}
    (h : validate input = some result) :
    input.accesses.length = 2 := by
  rw [validate_success_accesses_exact h]
  rfl

theorem validate_success_access_contract
    {input : ChronologyAccessInput}
    {result : ValidatedChronologyAccess}
    (h : validate input = some result) :
    ∃ readRow writeRow,
      input.accesses = [readRow, writeRow] ∧
        readRow.index = 0 ∧
        writeRow.index = 1 ∧
        readRow.decisionId = input.request.binding.decisionId ∧
        writeRow.decisionId = input.request.binding.decisionId ∧
        readRow.role = .READ ∧
        writeRow.role = .WRITE ∧
        readRow.time = input.request.binding.chronology.observation ∧
        writeRow.time = input.request.binding.chronology.decision := by
  have haccess := validate_success_accesses_exact h
  refine ⟨expectedRead input, expectedWrite input, haccess, ?_⟩
  simp [expectedRead, expectedWrite]

theorem validate_success_indexed_view
    {input : ChronologyAccessInput}
    {result : ValidatedChronologyAccess}
    (h : validate input = some result) :
    result.indexedAccesses accessZero =
        { index := accessZero
          decisionId := input.request.binding.decisionId
          role := .READ
          time := input.request.binding.chronology.observation } ∧
      result.indexedAccesses accessOne =
        { index := accessOne
          decisionId := input.request.binding.decisionId
          role := .WRITE
          time := input.request.binding.chronology.decision } := by
  have hadmission := validate_success_implies_admission h
  have haccess := validate_success_accesses_exact h
  have hresult :
      makeValidated input (expectedRead input) (expectedWrite input) = result := by
    simpa [validate, hadmission, haccess] using h
  cases hresult
  constructor <;>
    simp [makeValidated, boundAccess, expectedRead, expectedWrite,
      accessZero, accessOne]

theorem finTwo_index_cases (index : Fin 2) :
    index = accessZero ∨ index = accessOne := by
  have hlt := index.isLt
  have hval : index.val = 0 ∨ index.val = 1 := by
    omega
  rcases hval with hzero | hone
  · left
    apply Fin.ext
    exact hzero
  · right
    apply Fin.ext
    exact hone

/-! Deterministic accepted input and rejection cases. -/
def exampleDecisionId : DecisionId :=
  { token := 7 }

def exampleChronology : Chronology :=
  { ruleEffective := 10
    event := 20
    observation := 30
    decision := 40 }

def exampleBinding : DecisionBinding :=
  { decisionId := exampleDecisionId
    chronology := exampleChronology }

def exampleReadAccess : RawAccessRecord :=
  { index := 0
    decisionId := exampleDecisionId
    role := .READ
    time := 30 }

def exampleWriteAccess : RawAccessRecord :=
  { index := 1
    decisionId := exampleDecisionId
    role := .WRITE
    time := 40 }

def positiveInput : ChronologyAccessInput :=
  { request := { binding := exampleBinding }
    stateDecision := { binding := exampleBinding }
    stateReceipt := { binding := exampleBinding }
    retry := { binding := exampleBinding, attempt := 0 }
    decisionIndex := 0
    accessCount := 2
    accesses := [exampleReadAccess, exampleWriteAccess] }

def duplicateInput : ChronologyAccessInput :=
  { positiveInput with accesses := [exampleReadAccess, exampleReadAccess] }

def omittedInput : ChronologyAccessInput :=
  { positiveInput with accesses := [exampleReadAccess] }

def extraInput : ChronologyAccessInput :=
  { positiveInput with accesses :=
      [exampleReadAccess, exampleWriteAccess, exampleReadAccess] }

def reorderedInput : ChronologyAccessInput :=
  { positiveInput with accesses := [exampleWriteAccess, exampleReadAccess] }

def wrongDecisionAccess : RawAccessRecord :=
  { exampleReadAccess with decisionId := { token := 8 } }

def wrongDecisionInput : ChronologyAccessInput :=
  { positiveInput with accesses := [wrongDecisionAccess, exampleWriteAccess] }

def wrongTimeAccess : RawAccessRecord :=
  { exampleReadAccess with time := exampleChronology.decision }

def wrongTimeInput : ChronologyAccessInput :=
  { positiveInput with accesses := [wrongTimeAccess, exampleWriteAccess] }

def wrongRoleAccess : RawAccessRecord :=
  { exampleReadAccess with role := .WRITE }

def wrongRoleInput : ChronologyAccessInput :=
  { positiveInput with accesses := [wrongRoleAccess, exampleWriteAccess] }

def nonStrictChronology : Chronology :=
  { exampleChronology with observation := exampleChronology.event }

def nonStrictBinding : DecisionBinding :=
  { exampleBinding with chronology := nonStrictChronology }

def nonStrictInput : ChronologyAccessInput :=
  { request := { binding := nonStrictBinding }
    stateDecision := { binding := nonStrictBinding }
    stateReceipt := { binding := nonStrictBinding }
    retry := { binding := nonStrictBinding, attempt := 0 }
    decisionIndex := 0
    accessCount := 2
    accesses :=
      [ { exampleReadAccess with time := nonStrictChronology.observation },
        { exampleWriteAccess with time := nonStrictChronology.decision } ] }

def mismatchedReceiptInput : ChronologyAccessInput :=
  { positiveInput with
      stateReceipt := { binding := { exampleBinding with decisionId := { token := 9 } } } }

theorem positive_example_accepts : accepted positiveInput = true := by
  decide

theorem duplicate_example_rejects : accepted duplicateInput = false := by
  decide

theorem omitted_example_rejects : accepted omittedInput = false := by
  decide

theorem extra_example_rejects : accepted extraInput = false := by
  decide

theorem reordered_example_rejects : accepted reorderedInput = false := by
  decide

theorem wrong_decision_example_rejects : accepted wrongDecisionInput = false := by
  decide

theorem wrong_time_example_rejects : accepted wrongTimeInput = false := by
  decide

theorem wrong_role_example_rejects : accepted wrongRoleInput = false := by
  decide

theorem non_strict_example_rejects : accepted nonStrictInput = false := by
  decide

theorem mismatched_receipt_example_rejects :
    accepted mismatchedReceiptInput = false := by
  decide

theorem positive_retry_preserves_bound_time :
    (positiveInput.retry.nextAttempt).binding.chronology.decision = 40 := by
  rfl

end BlindLedger.System
