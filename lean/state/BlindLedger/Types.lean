import Std

namespace BlindLedger.Kernel

/-! Core semantic types for the bounded clearance kernel.  Identifiers are
    fixed-width one-byte model identities; they are bindings, not hash or
    cryptographic claims.  The surrounding native system owns those claims. -/

abbrev WireByte := Fin 256

structure Id where
  value : WireByte
deriving DecidableEq, Repr

def byteOfNat (value : Nat) : WireByte :=
  ⟨value % 256, Nat.mod_lt _ (by decide)⟩

def idOfNat (value : Nat) : Id :=
  { value := byteOfNat value }

def Id.isNonzero (identity : Id) : Bool :=
  decide (identity.value.val ≠ 0)

def Id.isNotSentinel (identity : Id) (sentinel : Id) : Bool :=
  identity.isNonzero && identity ≠ sentinel

inductive EffectiveDirective where
  | CLEAR
  | HOLD
  | HUMAN_REVIEW
  | BLOCK
  | EXCEPTION_APPROVED
deriving DecidableEq, Repr

inductive PolicyResult where
  | pass
  | missingEvidence
  | ambiguous
  | fail
deriving DecidableEq, Repr

def policyForDirective : EffectiveDirective → PolicyResult
  | .CLEAR => .pass
  | .HOLD => .missingEvidence
  | .HUMAN_REVIEW => .ambiguous
  | .BLOCK => .fail
  | .EXCEPTION_APPROVED => .fail

def policyDirectiveConsistent
    (policy : PolicyResult) (directive : EffectiveDirective) : Bool :=
  decide (policy = policyForDirective directive)

inductive FactStatus where
  | ACTIVE
  | EXPIRED
  | TERMINATED
deriving DecidableEq, Repr

inductive AuthorityMode where
  | observeOnly
  | operative
deriving DecidableEq, Repr

inductive EvidenceMode where
  | DIRECT_STATE_OWNED
  | PRIVATE_ZK
deriving DecidableEq, Repr

inductive ConflictPolicy where
  | priorityThenHumanReview
  | rejectOnConflict
deriving DecidableEq, Repr

structure ControlSet where
  mode : EvidenceMode
  evaluatorId : Id
  controlSetId : Id
  scopeId : Id
  conflictPolicy : ConflictPolicy
  effectiveStart : Nat
  effectiveEnd : Nat
  ruleFirst : Id
  ruleSecond : Option Id
deriving DecidableEq, Repr

inductive AccessMode where
  | READ
  | WRITE
deriving DecidableEq, Repr

inductive EconomicStatus where
  | open
  | cleared
deriving DecidableEq, Repr

structure LedgerState where
  sequence : Nat
  economicVersion : Nat
  status : EconomicStatus
  lastAttempt : Option Id
  auditHead : Id
deriving DecidableEq, Repr

def initialState : LedgerState :=
  { sequence := 0
    economicVersion := 0
    status := .open
    lastAttempt := none
    auditHead := idOfNat 1 }

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

def Chronology.strictBool (chronology : Chronology) : Bool :=
  decide chronology.Strict

structure Request where
  providerId : Id
  credentialId : Id
  enrollmentId : Id
  subjectId : Id
  attemptId : Id
  epoch : Nat
  sequenceBefore : Nat
  eventTime : Nat
  observationTime : Nat
  ruleEffectiveTime : Nat
  decisionTime : Nat
  expectedBefore : LedgerState
deriving DecidableEq, Repr

def Request.chronology (request : Request) : Chronology :=
  { ruleEffective := request.ruleEffectiveTime
    event := request.eventTime
    observation := request.observationTime
    decision := request.decisionTime }

structure Fact where
  subjectId : Id
  feedId : Id
  status : FactStatus
  issuedAt : Nat
  expiresAt : Nat
  terminatedAt : Nat
  observedAt : Nat
  recordId : Id
deriving DecidableEq, Repr

structure FactSlots where
  first : Option Fact
  second : Option Fact
deriving DecidableEq, Repr

def emptyFactSlots : FactSlots :=
  { first := none, second := none }

structure Completeness where
  feedId : Id
  providerId : Id
  scopeId : Id
  observationTime : Nat
  complete : Bool
  absenceFirst : Option Id
  absenceSecond : Option Id
deriving DecidableEq, Repr

def emptyCompleteness : Completeness :=
  { feedId := idOfNat 0
    providerId := idOfNat 0
    scopeId := idOfNat 0
    observationTime := 0
    complete := false
    absenceFirst := none
    absenceSecond := none }

structure ExceptionAuthorization where
  authorizationId : Id
  signerId : Id
  subjectId : Id
  ruleId : Id
  reasonId : Id
  amountScope : Id
  effectiveAt : Nat
  expiresAt : Nat
  policyResult : PolicyResult
deriving DecidableEq, Repr

structure ClearanceInput where
  controlSet : BlindLedger.Kernel.ControlSet
  request : Request
  facts : FactSlots
  completeness : Completeness
  exception : Option ExceptionAuthorization
  authority : AuthorityMode
  proofAccepted : Bool
  before : LedgerState
deriving DecidableEq, Repr

end BlindLedger.Kernel
