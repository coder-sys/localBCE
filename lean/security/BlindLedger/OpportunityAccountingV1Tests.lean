import BlindLedger.OpportunityAccountingV1Theorems

namespace BlindLedger.DirectMaskOpportunityV1Tests

open BlindLedger.DirectMaskOpportunityV1

def scope9 : ScopeId := ⟨⟨9, by decide⟩⟩
def event1 : EventId := ⟨⟨1, by decide⟩⟩
def event2 : EventId := ⟨⟨2, by decide⟩⟩
def event3 : EventId := ⟨⟨3, by decide⟩⟩
def commitment5 : CommitmentId := ⟨⟨5, by decide⟩⟩
def commitment6 : CommitmentId := ⟨⟨6, by decide⟩⟩

def attemptRequest : OpportunityRequest :=
  { eventId := event1, body := .attempt }

def firstAttemptResult : ReserveResult :=
  reserveOpportunity (LedgerState.empty scope9) attemptRequest

def attemptState : LedgerState := firstAttemptResult.state

def expectedAttemptReceipt : String :=
  "BL/DIRECT-MASK/LOCAL-OPPORTUNITY-ACCOUNTING/v1|RESERVED|9|1|A|A=1,S=0,M=0,E_U=0,V=0,R0=0,R2=0,R3=0|EVAL_R0=0,EVAL_R2=0,EVAL_R3=0"

example : schemaId = "BL/DIRECT-MASK/LOCAL-OPPORTUNITY-ACCOUNTING/v1" := by decide

example : firstAttemptResult.disposition = .reserved := by decide

example : firstAttemptResult.state.totals.a = 1 := by decide

set_option maxRecDepth 4096 in
example : firstAttemptResult.receipt = some
    "BL/DIRECT-MASK/LOCAL-OPPORTUNITY-ACCOUNTING/v1|RESERVED|9|1|A|A=1,S=0,M=0,E_U=0,V=0,R0=0,R2=0,R3=0|EVAL_R0=0,EVAL_R2=0,EVAL_R3=0" := by decide

set_option maxRecDepth 4096 in
example : ReserveResult.encode firstAttemptResult =
    "BL/DIRECT-MASK/LOCAL-OPPORTUNITY-ACCOUNTING/v1|RESULT|RESERVE|RESERVED|9|1|A|A=1,S=0,M=0,E_U=0,V=0,R0=0,R2=0,R3=0|EVAL_R0=0,EVAL_R2=0,EVAL_R3=0|SOME:" ++
      toString expectedAttemptReceipt.length ++ ":" ++ expectedAttemptReceipt ++ "|NONE" := by decide

example :
    let retry := reserveOpportunity attemptState attemptRequest
    retry.disposition = .exactRetry ∧ retry.receipt = firstAttemptResult.receipt ∧
      retry.state = attemptState := by decide

example :
    let changed := reserveOpportunity attemptState
      { eventId := event1, body := .verifierInvocation }
    changed.disposition = .inputConflict ∧ changed.state = attemptState := by decide

def finalizedA (outcome : Outcome) : FinalizeResult :=
  finalizeOpportunity attemptState event1 outcome

example : ∀ outcome : Outcome, (finalizedA outcome).state.totals.a = 1 := by
  intro outcome
  cases outcome <;> decide

set_option maxRecDepth 4096 in
example :
    let failed := finalizedA .failed
    failed.disposition = .finalized ∧ failed.state.totals.a = 1 ∧
      failed.receipt = some
        "BL/DIRECT-MASK/LOCAL-OPPORTUNITY-ACCOUNTING/v1|FINAL|9|1|A|A=1,S=0,M=0,E_U=0,V=0,R0=0,R2=0,R3=0|EVAL_R0=0,EVAL_R2=0,EVAL_R3=0|FAILED" := by decide

set_option maxRecDepth 4096 in
example :
    let failed := finalizedA .failed
    FinalizeResult.encode failed =
      "BL/DIRECT-MASK/LOCAL-OPPORTUNITY-ACCOUNTING/v1|RESULT|FINALIZE|FINALIZED|9|1|FAILED|A=1,S=0,M=0,E_U=0,V=0,R0=0,R2=0,R3=0|EVAL_R0=0,EVAL_R2=0,EVAL_R3=0|SOME:" ++
        toString ("BL/DIRECT-MASK/LOCAL-OPPORTUNITY-ACCOUNTING/v1|FINAL|9|1|A|A=1,S=0,M=0,E_U=0,V=0,R0=0,R2=0,R3=0|EVAL_R0=0,EVAL_R2=0,EVAL_R3=0|FAILED".length) ++
        ":BL/DIRECT-MASK/LOCAL-OPPORTUNITY-ACCOUNTING/v1|FINAL|9|1|A|A=1,S=0,M=0,E_U=0,V=0,R0=0,R2=0,R3=0|EVAL_R0=0,EVAL_R2=0,EVAL_R3=0|FAILED" := by decide

example :
    let failed := finalizedA .failed
    let retry := finalizeOpportunity failed.state event1 .failed
    retry.disposition = .exactRetry ∧ retry.receipt = failed.receipt ∧
      retry.state = failed.state := by decide

example :
    let failed := finalizedA .failed
    let changed := finalizeOpportunity failed.state event1 .aborted
    changed.disposition = .inputConflict ∧ changed.state = failed.state ∧
      changed.receipt = failed.receipt := by decide

def sourceRequest (eventId : EventId) : OpportunityRequest :=
  { eventId := eventId, body := .sourceCommitment commitment5 }

example :
    let first := reserveOpportunity (LedgerState.empty scope9) (sourceRequest event1)
    let duplicate := reserveOpportunity first.state (sourceRequest event2)
    duplicate.disposition = .rejected .sourceCommitmentAlreadyCounted ∧
      duplicate.state.totals.s = 1 := by decide

def freshRequest (eventId : EventId) (commitment : CommitmentId) : OpportunityRequest :=
  { eventId := eventId, body := .freshCommitment event1 commitment }

example :
    let noParent := reserveOpportunity (LedgerState.empty scope9) (freshRequest event2 commitment5)
    noParent.disposition = .rejected .parentAttemptMissingOrClosed ∧
      noParent.state.totals.m = 0 := by decide

example :
    let firstM := reserveOpportunity attemptState (freshRequest event2 commitment5)
    let secondM := reserveOpportunity firstM.state (freshRequest event3 commitment6)
    firstM.state.totals.m = 1 ∧
      secondM.disposition = .rejected .attemptAlreadyHasFreshCommitment ∧
      secondM.state.totals.m = 1 := by decide

def firstR0Result : ReserveResult :=
  reserveOpportunity attemptState
    { eventId := event2, body := .stageReservation event1 .r0 }

example :
    let closedAttempt := finalizeOpportunity firstR0Result.state event1 .completed
    closedAttempt.state.WellFormed ∧ closedAttempt.state.totals.r0 = 1 := by decide

def firstR0Evaluation : ReserveResult :=
  reserveOpportunity firstR0Result.state
    { eventId := event3, body := .stageEvaluation event1 .r0 }

example :
    firstR0Evaluation.disposition = .reserved ∧
      firstR0Evaluation.state.totals.r0 = 1 ∧
      firstR0Evaluation.state.stageEvaluations.r0 = 1 := by decide

set_option maxRecDepth 4096 in
example : firstR0Evaluation.receipt = some
    "BL/DIRECT-MASK/LOCAL-OPPORTUNITY-ACCOUNTING/v1|RESERVED|9|3|EVAL_R0,1|A=1,S=0,M=0,E_U=0,V=0,R0=1,R2=0,R3=0|EVAL_R0=1,EVAL_R2=0,EVAL_R3=0" := by decide

example :
    let secondEvaluation := reserveOpportunity firstR0Evaluation.state
      { eventId := ⟨⟨4, by decide⟩⟩, body := .stageEvaluation event1 .r0 }
    secondEvaluation.disposition = .rejected .evaluationExceedsReservations ∧
      secondEvaluation.state.stageEvaluations.r0 = 1 := by decide

example :
    let retry := reserveOpportunity firstR0Evaluation.state
      { eventId := event3, body := .stageEvaluation event1 .r0 }
    retry.disposition = .exactRetry ∧ retry.receipt = firstR0Evaluation.receipt ∧
      retry.state = firstR0Evaluation.state := by decide

example :
    let closedAttempt := finalizeOpportunity firstR0Evaluation.state event1 .unknown
    closedAttempt.state.stageEvaluations.r0 = 1 ∧ closedAttempt.state.totals.r0 = 1 := by decide

example :
    let closedAttempt := finalizeOpportunity firstR0Result.state event1 .completed
    let laterR0 := reserveOpportunity closedAttempt.state
      { eventId := event3, body := .stageReservation event1 .r0 }
    laterR0.disposition = .rejected .parentAttemptMissingOrClosed ∧
      laterR0.state = closedAttempt.state ∧ laterR0.state.totals.r0 = 1 := by decide

example : EventId.ofNat identityBound = none := by decide

def aAtCap : Totals := { Totals.zero with a := maxA }
def aBelowCap : Totals := { Totals.zero with a := maxA - 1 }
def r0AtCap : Totals := { Totals.zero with a := 1, r0 := maxR0PerA }
def r2AtCap : Totals := { Totals.zero with a := 1, r2 := maxR2PerA }
def r3AtCap : Totals := { Totals.zero with a := 1, r3 := maxR3PerA }
def sAtCap : Totals := { Totals.zero with s := maxS }
def euAtCap : Totals := { Totals.zero with eu := maxEU }
def vAtCap : Totals := { Totals.zero with v := maxV }

example : aBelowCap.checkedReserve .attempt = some aAtCap := by decide
example : aAtCap.checkedReserve .attempt = none := by decide
example : sAtCap.checkedReserve (.sourceCommitment commitment5) = none := by decide
example : euAtCap.checkedReserve .sourceUIssuance = none := by decide
example : vAtCap.checkedReserve .verifierInvocation = none := by decide
example : r0AtCap.checkedReserve (.stageReservation event1 .r0) = none := by decide
example : r2AtCap.checkedReserve (.stageReservation event1 .r2) = none := by decide
example : r3AtCap.checkedReserve (.stageReservation event1 .r3) = none := by decide
example : Totals.zero.checkedReserve (.freshCommitment event1 commitment5) = none := by decide

example : firstAttemptResult.state.WellFormed := by decide

example : firstAttemptResult.state.totals.WithinCaps ∧
    firstAttemptResult.state.stageEvaluations.WithinReservations
      firstAttemptResult.state.totals :=
  LedgerState.wellFormed_bounds firstAttemptResult.state (by decide)

example : EventIdsUnique firstAttemptResult.state.entries :=
  LedgerState.wellFormed_eventIdsUnique firstAttemptResult.state (by decide)

example : attemptState.totals.ComponentwiseLE
    (reserveOpportunity attemptState
      { eventId := event2, body := .verifierInvocation }).state.totals :=
  (reserveOpportunity_countersNeverDecrease attemptState
    { eventId := event2, body := .verifierInvocation }).1

example : (finalizeOpportunity attemptState event1 .failed).state.totals =
    attemptState.totals ∧
    (finalizeOpportunity attemptState event1 .failed).state.stageEvaluations =
      attemptState.stageEvaluations :=
  finalizeOpportunity_countersUnchanged attemptState event1 .failed

def acceptedAndRetriedTrace : List OpportunityCommand :=
  [ .reserve attemptRequest
  , .reserve { eventId := event2, body := .stageReservation event1 .r0 }
  , .reserve { eventId := event3, body := .stageEvaluation event1 .r0 }
  , .finalize event1 .unknown
  , .reserve { eventId := event3, body := .stageEvaluation event1 .r0 }
  , .finalize event1 .completed
  ]

example : AccountingInvariant
    (runOpportunityCommands (LedgerState.empty scope9) acceptedAndRetriedTrace) :=
  runOpportunityCommands_fromEmpty_invariants scope9 acceptedAndRetriedTrace

example : (LedgerState.empty scope9).totals.ComponentwiseLE
      (runOpportunityCommands (LedgerState.empty scope9) acceptedAndRetriedTrace).totals ∧
    (LedgerState.empty scope9).stageEvaluations.ComponentwiseLE
      (runOpportunityCommands (LedgerState.empty scope9) acceptedAndRetriedTrace).stageEvaluations :=
  runOpportunityCommands_countersNeverDecrease (LedgerState.empty scope9)
    acceptedAndRetriedTrace

end BlindLedger.DirectMaskOpportunityV1Tests
