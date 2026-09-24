import Std

set_option exponentiation.threshold 4096

namespace BlindLedger.DirectMaskOpportunityV1

/-!
Local deterministic reducer for service-observed Direct Mask opportunities.

This module is deliberately not a global ledger or an authority.  Its state is
ordinary caller-held data; an owner adapter must atomically persist each
reservation, its receipt, and the new state before starting work.  The module
does not observe offline QRO queries, authenticate issuers or producers, or
provide durable storage, signatures, clone resistance, or rollback resistance.
-/

def schemaId : String := "BL/DIRECT-MASK/LOCAL-OPPORTUNITY-ACCOUNTING/v1"

def identityBound : Nat := 2 ^ 256
def maxA : Nat := 2 ^ 32
def maxS : Nat := 2 ^ 32
def maxEU : Nat := 2 ^ 32
def maxV : Nat := 2 ^ 32
def maxR0PerA : Nat := 2 ^ 16
def maxR2PerA : Nat := 2 ^ 12
def maxR3PerA : Nat := 2 ^ 22

structure ScopeId where
  value : Fin identityBound
  deriving BEq, DecidableEq, Repr

namespace ScopeId

def ofNat (n : Nat) : Option ScopeId :=
  if h : n < identityBound then some ⟨⟨n, h⟩⟩ else none

def encode (id : ScopeId) : String := toString id.value.val

end ScopeId

structure EventId where
  value : Fin identityBound
  deriving BEq, DecidableEq, Repr

namespace EventId

def ofNat (n : Nat) : Option EventId :=
  if h : n < identityBound then some ⟨⟨n, h⟩⟩ else none

def encode (id : EventId) : String := toString id.value.val

end EventId

structure CommitmentId where
  value : Fin identityBound
  deriving BEq, DecidableEq, Repr

namespace CommitmentId

def ofNat (n : Nat) : Option CommitmentId :=
  if h : n < identityBound then some ⟨⟨n, h⟩⟩ else none

def encode (id : CommitmentId) : String := toString id.value.val

end CommitmentId

inductive Stage where
  | r0
  | r2
  | r3
  deriving BEq, DecidableEq, Repr

namespace Stage

def encode : Stage → String
  | .r0 => "R0"
  | .r2 => "R2"
  | .r3 => "R3"

end Stage

inductive OpportunityBody where
  | attempt
  | sourceCommitment (commitment : CommitmentId)
  | freshCommitment (parentAttempt : EventId) (commitment : CommitmentId)
  | sourceUIssuance
  | verifierInvocation
  | stageReservation (parentAttempt : EventId) (stage : Stage)
  | stageEvaluation (parentAttempt : EventId) (stage : Stage)
  deriving BEq, DecidableEq, Repr

namespace OpportunityBody

def encode : OpportunityBody → String
  | .attempt => "A"
  | .sourceCommitment commitment => "S," ++ CommitmentId.encode commitment
  | .freshCommitment parent commitment =>
      "M," ++ EventId.encode parent ++ "," ++ CommitmentId.encode commitment
  | .sourceUIssuance => "E_U"
  | .verifierInvocation => "V"
  | .stageReservation parent stage =>
      Stage.encode stage ++ "," ++ EventId.encode parent
  | .stageEvaluation parent stage =>
      "EVAL_" ++ Stage.encode stage ++ "," ++ EventId.encode parent

end OpportunityBody

structure OpportunityRequest where
  eventId : EventId
  body : OpportunityBody
  deriving BEq, DecidableEq, Repr

inductive Outcome where
  | completed
  | rejected
  | failed
  | aborted
  | unknown
  deriving BEq, DecidableEq, Repr

namespace Outcome

def encode : Outcome → String
  | .completed => "COMPLETED"
  | .rejected => "REJECTED"
  | .failed => "FAILED"
  | .aborted => "ABORTED"
  | .unknown => "UNKNOWN"

end Outcome

structure Totals where
  a : Nat
  s : Nat
  m : Nat
  eu : Nat
  v : Nat
  r0 : Nat
  r2 : Nat
  r3 : Nat
  deriving BEq, DecidableEq, Repr

namespace Totals

def zero : Totals :=
  { a := 0, s := 0, m := 0, eu := 0, v := 0, r0 := 0, r2 := 0, r3 := 0 }

def increment (totals : Totals) (body : OpportunityBody) : Totals :=
  match body with
  | .attempt => { totals with a := totals.a + 1 }
  | .sourceCommitment _ => { totals with s := totals.s + 1 }
  | .freshCommitment _ _ => { totals with m := totals.m + 1 }
  | .sourceUIssuance => { totals with eu := totals.eu + 1 }
  | .verifierInvocation => { totals with v := totals.v + 1 }
  | .stageReservation _ .r0 => { totals with r0 := totals.r0 + 1 }
  | .stageReservation _ .r2 => { totals with r2 := totals.r2 + 1 }
  | .stageReservation _ .r3 => { totals with r3 := totals.r3 + 1 }
  | .stageEvaluation _ _ => totals

def WithinCaps (totals : Totals) : Prop :=
  totals.a ≤ maxA ∧
  totals.s ≤ maxS ∧
  totals.m ≤ totals.a ∧
  totals.eu ≤ maxEU ∧
  totals.v ≤ maxV ∧
  totals.r0 ≤ maxR0PerA * totals.a ∧
  totals.r2 ≤ maxR2PerA * totals.a ∧
  totals.r3 ≤ maxR3PerA * totals.a

instance instDecidableWithinCaps (totals : Totals) : Decidable (totals.WithinCaps) := by
  unfold WithinCaps
  infer_instance

/- Counts use Nat, so the reducer has no machine-integer wraparound.  This
   checked step rejects any transition beyond the protocol's explicit caps. -/
def checkedReserve (totals : Totals) (body : OpportunityBody) : Option Totals :=
  let next := totals.increment body
  if next.WithinCaps then some next else none

def encode (totals : Totals) : String :=
  "A=" ++ toString totals.a ++
  ",S=" ++ toString totals.s ++
  ",M=" ++ toString totals.m ++
  ",E_U=" ++ toString totals.eu ++
  ",V=" ++ toString totals.v ++
  ",R0=" ++ toString totals.r0 ++
  ",R2=" ++ toString totals.r2 ++
  ",R3=" ++ toString totals.r3

end Totals

/- These service-observed evaluation-attempt counts are kept separate from the
   R opportunity counters.  They do not add terms to the DMV2 query formulas. -/
structure StageEvaluationCounts where
  r0 : Nat
  r2 : Nat
  r3 : Nat
  deriving BEq, DecidableEq, Repr

namespace StageEvaluationCounts

def zero : StageEvaluationCounts := { r0 := 0, r2 := 0, r3 := 0 }

def increment (counts : StageEvaluationCounts) (body : OpportunityBody) :
    StageEvaluationCounts :=
  match body with
  | .stageEvaluation _ .r0 => { counts with r0 := counts.r0 + 1 }
  | .stageEvaluation _ .r2 => { counts with r2 := counts.r2 + 1 }
  | .stageEvaluation _ .r3 => { counts with r3 := counts.r3 + 1 }
  | _ => counts

def WithinReservations (counts : StageEvaluationCounts) (totals : Totals) : Prop :=
  counts.r0 ≤ totals.r0 ∧ counts.r2 ≤ totals.r2 ∧ counts.r3 ≤ totals.r3

instance instDecidableWithinReservations (counts : StageEvaluationCounts) (totals : Totals) :
    Decidable (counts.WithinReservations totals) := by
  unfold WithinReservations
  infer_instance

def checkedRecord (counts : StageEvaluationCounts) (totals : Totals)
    (body : OpportunityBody) : Option StageEvaluationCounts :=
  let next := counts.increment body
  if next.WithinReservations totals then some next else none

def encode (counts : StageEvaluationCounts) : String :=
  "EVAL_R0=" ++ toString counts.r0 ++
  ",EVAL_R2=" ++ toString counts.r2 ++
  ",EVAL_R3=" ++ toString counts.r3

end StageEvaluationCounts

structure OpportunityEntry where
  request : OpportunityRequest
  reservedTotals : Totals
  reservedEvaluations : StageEvaluationCounts
  outcome : Option Outcome
  deriving BEq, DecidableEq, Repr

/- The public data shape is not a protected store.  The reducer validates its
   local history before every transition; an owner still has to protect the
   persisted state from unauthorized edits, forks, and rollback. -/
structure LedgerState where
  scopeId : ScopeId
  totals : Totals
  stageEvaluations : StageEvaluationCounts
  entries : List OpportunityEntry
  deriving BEq, DecidableEq, Repr

namespace LedgerState

def empty (scopeId : ScopeId) : LedgerState :=
  { scopeId := scopeId, totals := Totals.zero,
    stageEvaluations := StageEvaluationCounts.zero, entries := [] }

end LedgerState

inductive RejectionReason where
  | invalidState
  | eventIdAlreadyUsed
  | parentAttemptMissingOrClosed
  | sourceCommitmentAlreadyCounted
  | freshCommitmentAlreadyCounted
  | attemptAlreadyHasFreshCommitment
  | evaluationExceedsReservations
  | counterCapExceeded
  | eventNotFound
  deriving BEq, DecidableEq, Repr

namespace RejectionReason

def encode : RejectionReason → String
  | .invalidState => "INVALID_STATE"
  | .eventIdAlreadyUsed => "EVENT_ID_ALREADY_USED"
  | .parentAttemptMissingOrClosed => "PARENT_ATTEMPT_MISSING_OR_CLOSED"
  | .sourceCommitmentAlreadyCounted => "SOURCE_COMMITMENT_ALREADY_COUNTED"
  | .freshCommitmentAlreadyCounted => "FRESH_COMMITMENT_ALREADY_COUNTED"
  | .attemptAlreadyHasFreshCommitment => "ATTEMPT_ALREADY_HAS_FRESH_COMMITMENT"
  | .evaluationExceedsReservations => "EVALUATION_EXCEEDS_RESERVATIONS"
  | .counterCapExceeded => "COUNTER_CAP_EXCEEDED"
  | .eventNotFound => "EVENT_NOT_FOUND"

end RejectionReason

/- Deterministic lookup, replay, receipt, and outcome helpers are exposed for
   the focused theorem module. Runtime callers should use the transition
   functions below rather than assembling or mutating entries directly. -/
def findEntry : List OpportunityEntry → EventId → Option OpportunityEntry
  | [], _ => none
  | entry :: remaining, eventId =>
      if entry.request.eventId = eventId then some entry else findEntry remaining eventId

def eventIdPresent (entries : List OpportunityEntry) (eventId : EventId) : Prop :=
  (findEntry entries eventId).isSome = true

instance instDecidableEventIdPresent (entries : List OpportunityEntry) (eventId : EventId) :
    Decidable (eventIdPresent entries eventId) := by
  unfold eventIdPresent
  infer_instance

private def parentAttemptPresent (entries : List OpportunityEntry) (parent : EventId) : Bool :=
  entries.any fun entry =>
    entry.request.eventId == parent &&
      (match entry.request.body with
      | .attempt => true
      | _ => false)

private def parentAttemptOpen (entries : List OpportunityEntry) (parent : EventId) : Bool :=
  entries.any fun entry =>
    entry.request.eventId == parent &&
      (match entry.request.body with
      | .attempt => entry.outcome.isNone
      | _ => false)

private def parentEligible (requireOpen : Bool) (entries : List OpportunityEntry)
    (parent : EventId) : Bool :=
  parentAttemptPresent entries parent &&
    (!requireOpen || parentAttemptOpen entries parent)

private def sourceCommitmentPresent (entries : List OpportunityEntry)
    (commitment : CommitmentId) : Bool :=
  entries.any fun entry =>
    (match entry.request.body with
    | .sourceCommitment prior => prior == commitment
    | _ => false)

private def freshCommitmentPresent (entries : List OpportunityEntry)
    (commitment : CommitmentId) : Bool :=
  entries.any fun entry =>
    (match entry.request.body with
    | .freshCommitment _ prior => prior == commitment
    | _ => false)

private def freshCommitmentForAttemptPresent (entries : List OpportunityEntry)
    (parent : EventId) : Bool :=
  entries.any fun entry =>
    (match entry.request.body with
    | .freshCommitment prior _ => prior == parent
    | _ => false)

private def capRejection (totals : Totals) (body : OpportunityBody) :
    Option RejectionReason :=
  match totals.checkedReserve body with
  | some _ => none
  | none => some .counterCapExceeded

/- Live admission requires an open parent. History replay only requires that
   the parent A precede the child: a terminal outcome is stored on the A entry
   after earlier child reservations and does not encode its own timeline. -/
def rejectionForRequest (requireOpen : Bool) (entries : List OpportunityEntry)
    (totals : Totals) (evaluations : StageEvaluationCounts)
    (request : OpportunityRequest) : Option RejectionReason :=
  if eventIdPresent entries request.eventId then
    some .eventIdAlreadyUsed
  else
    match request.body with
    | .attempt => capRejection totals request.body
    | .sourceCommitment commitment =>
        if sourceCommitmentPresent entries commitment then
          some .sourceCommitmentAlreadyCounted
        else
          capRejection totals request.body
    | .freshCommitment parent commitment =>
        if parentEligible requireOpen entries parent then
          if freshCommitmentForAttemptPresent entries parent then
            some .attemptAlreadyHasFreshCommitment
          else if freshCommitmentPresent entries commitment then
            some .freshCommitmentAlreadyCounted
          else
            capRejection totals request.body
        else
          some .parentAttemptMissingOrClosed
    | .sourceUIssuance => capRejection totals request.body
    | .verifierInvocation => capRejection totals request.body
    | .stageReservation parent _ =>
        if parentEligible requireOpen entries parent then
          capRejection totals request.body
        else
          some .parentAttemptMissingOrClosed
    | .stageEvaluation parent _ =>
        if parentEligible requireOpen entries parent then
          match StageEvaluationCounts.checkedRecord evaluations totals request.body with
          | some _ => none
          | none => some .evaluationExceedsReservations
        else
          some .parentAttemptMissingOrClosed

def replayEntries (priorEntries : List OpportunityEntry) (totals : Totals)
    (evaluations : StageEvaluationCounts) :
    List OpportunityEntry → Option (Totals × StageEvaluationCounts)
  | [] => some (totals, evaluations)
  | entry :: remaining =>
      match rejectionForRequest false priorEntries totals evaluations entry.request with
      | some _ => none
      | none =>
          match totals.checkedReserve entry.request.body with
          | none => none
          | some nextTotals =>
              match evaluations.checkedRecord nextTotals entry.request.body with
              | none => none
              | some nextEvaluations =>
                  if entry.reservedTotals = nextTotals ∧
                      entry.reservedEvaluations = nextEvaluations then
                    replayEntries (entry :: priorEntries) nextTotals nextEvaluations remaining
                  else
                    none

def LedgerState.WellFormed (state : LedgerState) : Prop :=
  replayEntries [] Totals.zero StageEvaluationCounts.zero state.entries =
    some (state.totals, state.stageEvaluations)

instance instDecidableWellFormed (state : LedgerState) : Decidable (state.WellFormed) := by
  unfold LedgerState.WellFormed
  infer_instance

def reservationReceipt (scopeId : ScopeId) (entry : OpportunityEntry) : String :=
  schemaId ++ "|RESERVED|" ++ ScopeId.encode scopeId ++ "|" ++
  EventId.encode entry.request.eventId ++ "|" ++ OpportunityBody.encode entry.request.body ++
  "|" ++ Totals.encode entry.reservedTotals ++ "|" ++
  StageEvaluationCounts.encode entry.reservedEvaluations

def terminalReceipt (scopeId : ScopeId) (entry : OpportunityEntry) (outcome : Outcome) : String :=
  schemaId ++ "|FINAL|" ++ ScopeId.encode scopeId ++ "|" ++
  EventId.encode entry.request.eventId ++ "|" ++ OpportunityBody.encode entry.request.body ++
  "|" ++ Totals.encode entry.reservedTotals ++ "|" ++
  StageEvaluationCounts.encode entry.reservedEvaluations ++ "|" ++ Outcome.encode outcome

private def optionalField (value : Option String) : String :=
  match value with
  | none => "NONE"
  | some text => "SOME:" ++ toString text.length ++ ":" ++ text

inductive ReserveDisposition where
  | reserved
  | exactRetry
  | inputConflict
  | rejected (reason : RejectionReason)
  deriving BEq, DecidableEq, Repr

namespace ReserveDisposition

def encode : ReserveDisposition → String
  | .reserved => "RESERVED"
  | .exactRetry => "EXACT_RETRY"
  | .inputConflict => "INPUT_CONFLICT"
  | .rejected reason => "REJECTED," ++ RejectionReason.encode reason

end ReserveDisposition

structure ReserveResult where
  state : LedgerState
  request : OpportunityRequest
  disposition : ReserveDisposition
  receipt : Option String
  terminalReceipt : Option String
  deriving BEq, DecidableEq, Repr

namespace ReserveResult

def encode (result : ReserveResult) : String :=
  schemaId ++ "|RESULT|RESERVE|" ++ ReserveDisposition.encode result.disposition ++ "|" ++
  ScopeId.encode result.state.scopeId ++ "|" ++ EventId.encode result.request.eventId ++ "|" ++
  OpportunityBody.encode result.request.body ++ "|" ++ Totals.encode result.state.totals ++ "|" ++
  StageEvaluationCounts.encode result.state.stageEvaluations ++ "|" ++
  optionalField result.receipt ++ "|" ++ optionalField result.terminalReceipt

end ReserveResult

def existingTerminalReceipt (scopeId : ScopeId) (entry : OpportunityEntry) :
    Option String :=
  match entry.outcome with
  | none => none
  | some outcome => some (terminalReceipt scopeId entry outcome)

def reserveOpportunity (state : LedgerState) (request : OpportunityRequest) : ReserveResult :=
  if state.WellFormed then
    match findEntry state.entries request.eventId with
    | some existing =>
        if existing.request = request then
          { state := state
            request := request
            disposition := .exactRetry
            receipt := some (reservationReceipt state.scopeId existing)
            terminalReceipt := existingTerminalReceipt state.scopeId existing }
        else
          { state := state
            request := request
            disposition := .inputConflict
            receipt := some (reservationReceipt state.scopeId existing)
            terminalReceipt := existingTerminalReceipt state.scopeId existing }
    | none =>
        match rejectionForRequest true state.entries state.totals state.stageEvaluations request with
        | some reason =>
            { state := state
              request := request
              disposition := .rejected reason
              receipt := none
              terminalReceipt := none }
        | none =>
            match state.totals.checkedReserve request.body with
            | none =>
                { state := state
                  request := request
                  disposition := .rejected .counterCapExceeded
                  receipt := none
                  terminalReceipt := none }
            | some nextTotals =>
                match state.stageEvaluations.checkedRecord nextTotals request.body with
                | none =>
                    { state := state
                      request := request
                      disposition := .rejected .evaluationExceedsReservations
                      receipt := none
                      terminalReceipt := none }
                | some nextEvaluations =>
                    let entry : OpportunityEntry :=
                      { request := request, reservedTotals := nextTotals,
                        reservedEvaluations := nextEvaluations, outcome := none }
                    let nextState : LedgerState :=
                      { scopeId := state.scopeId, totals := nextTotals,
                        stageEvaluations := nextEvaluations,
                        entries := state.entries ++ [entry] }
                    { state := nextState
                      request := request
                      disposition := .reserved
                      receipt := some (reservationReceipt state.scopeId entry)
                      terminalReceipt := none }
  else
    { state := state
      request := request
      disposition := .rejected .invalidState
      receipt := none
      terminalReceipt := none }

inductive FinalizeDisposition where
  | finalized
  | exactRetry
  | inputConflict
  | rejected (reason : RejectionReason)
  deriving BEq, DecidableEq, Repr

namespace FinalizeDisposition

def encode : FinalizeDisposition → String
  | .finalized => "FINALIZED"
  | .exactRetry => "EXACT_RETRY"
  | .inputConflict => "INPUT_CONFLICT"
  | .rejected reason => "REJECTED," ++ RejectionReason.encode reason

end FinalizeDisposition

structure FinalizeResult where
  state : LedgerState
  eventId : EventId
  requestedOutcome : Outcome
  disposition : FinalizeDisposition
  receipt : Option String
  deriving BEq, DecidableEq, Repr

namespace FinalizeResult

def encode (result : FinalizeResult) : String :=
  schemaId ++ "|RESULT|FINALIZE|" ++ FinalizeDisposition.encode result.disposition ++ "|" ++
  ScopeId.encode result.state.scopeId ++ "|" ++ EventId.encode result.eventId ++ "|" ++
  Outcome.encode result.requestedOutcome ++ "|" ++ Totals.encode result.state.totals ++ "|" ++
  StageEvaluationCounts.encode result.state.stageEvaluations ++ "|" ++
  optionalField result.receipt

end FinalizeResult

def withOutcome (entries : List OpportunityEntry) (eventId : EventId)
    (outcome : Outcome) : List OpportunityEntry :=
  entries.map fun entry =>
    if entry.request.eventId = eventId then { entry with outcome := some outcome } else entry

def finalizeOpportunity (state : LedgerState) (eventId : EventId)
    (outcome : Outcome) : FinalizeResult :=
  if state.WellFormed then
    match findEntry state.entries eventId with
    | none =>
        { state := state
          eventId := eventId
          requestedOutcome := outcome
          disposition := .rejected .eventNotFound
          receipt := none }
    | some existing =>
        match existing.outcome with
        | some prior =>
            if prior = outcome then
              { state := state
                eventId := eventId
                requestedOutcome := outcome
                disposition := .exactRetry
                receipt := some (terminalReceipt state.scopeId existing prior) }
            else
              { state := state
                eventId := eventId
                requestedOutcome := outcome
                disposition := .inputConflict
                receipt := some (terminalReceipt state.scopeId existing prior) }
        | none =>
            let nextState :=
              { state with entries := withOutcome state.entries eventId outcome }
            let finalizedEntry :=
              { existing with outcome := some outcome }
            { state := nextState
              eventId := eventId
              requestedOutcome := outcome
              disposition := .finalized
              receipt := some (terminalReceipt state.scopeId finalizedEntry outcome) }
  else
    { state := state
      eventId := eventId
      requestedOutcome := outcome
      disposition := .rejected .invalidState
      receipt := none }

end BlindLedger.DirectMaskOpportunityV1
