import BlindLedger.OpportunityAccountingV1
import Lean.Elab.Tactic.Omega

set_option exponentiation.threshold 4096

namespace BlindLedger.DirectMaskOpportunityV1

/-!
These theorems concern one caller-held `LedgerState` and the ordered local
history accepted by `LedgerState.WellFormed`.  They do not authenticate the
scope or producers, enforce global scope/event-ID uniqueness, serialize
writers, or protect durable state from restore, clone, or rollback.  A real
owner must assign nonoverlapping scope identities and atomically persist the
state, history, and receipt before work, using a single writer or CAS for
concurrent callers.  These results do not constrain offline QRO queries or
work that bypasses this reducer.  Stage evaluation bounds are aggregate
counter bounds; they do not bind each evaluation to a particular reservation
row.
-/

def Totals.ComponentwiseLE (left right : Totals) : Prop :=
  left.a ≤ right.a ∧ left.s ≤ right.s ∧ left.m ≤ right.m ∧
  left.eu ≤ right.eu ∧ left.v ≤ right.v ∧ left.r0 ≤ right.r0 ∧
  left.r2 ≤ right.r2 ∧ left.r3 ≤ right.r3

def StageEvaluationCounts.ComponentwiseLE
    (left right : StageEvaluationCounts) : Prop :=
  left.r0 ≤ right.r0 ∧ left.r2 ≤ right.r2 ∧ left.r3 ≤ right.r3

def eventIds (entries : List OpportunityEntry) : List EventId :=
  entries.map fun entry => entry.request.eventId

def EventIdsUnique (entries : List OpportunityEntry) : Prop :=
  (eventIds entries).Nodup

theorem Totals.increment_componentwiseLE (totals : Totals)
    (body : OpportunityBody) :
    totals.ComponentwiseLE (totals.increment body) := by
  cases body with
  | attempt => simp [Totals.ComponentwiseLE, Totals.increment] <;> omega
  | sourceCommitment commitment => simp [Totals.ComponentwiseLE, Totals.increment] <;> omega
  | freshCommitment parent commitment => simp [Totals.ComponentwiseLE, Totals.increment] <;> omega
  | sourceUIssuance => simp [Totals.ComponentwiseLE, Totals.increment] <;> omega
  | verifierInvocation => simp [Totals.ComponentwiseLE, Totals.increment] <;> omega
  | stageReservation parent stage =>
      cases stage <;> simp [Totals.ComponentwiseLE, Totals.increment] <;> omega
  | stageEvaluation parent stage =>
      simp [Totals.ComponentwiseLE, Totals.increment] <;> omega

theorem StageEvaluationCounts.increment_componentwiseLE
    (counts : StageEvaluationCounts) (body : OpportunityBody) :
    counts.ComponentwiseLE (counts.increment body) := by
  cases body with
  | attempt =>
      simp [StageEvaluationCounts.ComponentwiseLE, StageEvaluationCounts.increment] <;> omega
  | sourceCommitment commitment =>
      simp [StageEvaluationCounts.ComponentwiseLE, StageEvaluationCounts.increment] <;> omega
  | freshCommitment parent commitment =>
      simp [StageEvaluationCounts.ComponentwiseLE, StageEvaluationCounts.increment] <;> omega
  | sourceUIssuance =>
      simp [StageEvaluationCounts.ComponentwiseLE, StageEvaluationCounts.increment] <;> omega
  | verifierInvocation =>
      simp [StageEvaluationCounts.ComponentwiseLE, StageEvaluationCounts.increment] <;> omega
  | stageReservation parent stage =>
      simp [StageEvaluationCounts.ComponentwiseLE, StageEvaluationCounts.increment] <;> omega
  | stageEvaluation parent stage =>
      cases stage <;>
        simp [StageEvaluationCounts.ComponentwiseLE, StageEvaluationCounts.increment] <;> omega

theorem Totals.ComponentwiseLE_trans {first middle last : Totals}
    (hFirst : first.ComponentwiseLE middle)
    (hSecond : middle.ComponentwiseLE last) : first.ComponentwiseLE last := by
  unfold Totals.ComponentwiseLE at *
  omega

theorem StageEvaluationCounts.ComponentwiseLE_trans
    {first middle last : StageEvaluationCounts}
    (hFirst : first.ComponentwiseLE middle)
    (hSecond : middle.ComponentwiseLE last) : first.ComponentwiseLE last := by
  unfold StageEvaluationCounts.ComponentwiseLE at *
  omega

theorem Totals.checkedReserve_withinCaps {totals : Totals} {body : OpportunityBody}
    {next : Totals} (h : totals.checkedReserve body = some next) :
    next.WithinCaps := by
  dsimp only [Totals.checkedReserve] at h
  split at h
  · injection h with hNext
    subst next
    assumption
  · simp at h

theorem StageEvaluationCounts.checkedRecord_withinReservations
    {counts : StageEvaluationCounts} {totals : Totals} {body : OpportunityBody}
    {next : StageEvaluationCounts}
    (h : counts.checkedRecord totals body = some next) :
    next.WithinReservations totals := by
  dsimp only [StageEvaluationCounts.checkedRecord] at h
  split at h
  · injection h with hNext
    subst next
    assumption
  · simp at h

theorem Totals.checkedReserve_componentwiseLE {totals : Totals}
    {body : OpportunityBody} {next : Totals}
    (h : totals.checkedReserve body = some next) :
    totals.ComponentwiseLE next := by
  dsimp only [Totals.checkedReserve] at h
  split at h
  · injection h with hEq
    subst next
    exact Totals.increment_componentwiseLE totals body
  · simp at h

theorem StageEvaluationCounts.checkedRecord_componentwiseLE
    {counts : StageEvaluationCounts} {totals : Totals} {body : OpportunityBody}
    {next : StageEvaluationCounts}
    (h : counts.checkedRecord totals body = some next) :
    counts.ComponentwiseLE next := by
  dsimp only [StageEvaluationCounts.checkedRecord] at h
  split at h
  · injection h with hEq
    subst next
    exact StageEvaluationCounts.increment_componentwiseLE counts body
  · simp at h

theorem replayEntries_preserves_bounds
    {priorEntries : List OpportunityEntry} {totals : Totals}
    {evaluations : StageEvaluationCounts} {entries : List OpportunityEntry}
    {finalTotals : Totals} {finalEvaluations : StageEvaluationCounts}
    (hTotals : totals.WithinCaps)
    (hEvaluations : evaluations.WithinReservations totals)
    (hReplay : replayEntries priorEntries totals evaluations entries =
      some (finalTotals, finalEvaluations)) :
    finalTotals.WithinCaps ∧
      finalEvaluations.WithinReservations finalTotals := by
  induction entries generalizing priorEntries totals evaluations finalTotals finalEvaluations with
  | nil =>
      change some (totals, evaluations) = some (finalTotals, finalEvaluations) at hReplay
      have hPair : (totals, evaluations) = (finalTotals, finalEvaluations) :=
        Option.some.inj hReplay
      cases hPair
      exact ⟨hTotals, hEvaluations⟩
  | cons entry remaining ih =>
      simp only [replayEntries] at hReplay
      cases hReject : rejectionForRequest false priorEntries totals evaluations entry.request with
      | some reason => simp [hReject] at hReplay
      | none =>
          cases hReserve : totals.checkedReserve entry.request.body with
          | none => simp [hReject, hReserve] at hReplay
          | some nextTotals =>
              cases hRecord : evaluations.checkedRecord nextTotals entry.request.body with
              | none => simp [hReject, hReserve, hRecord] at hReplay
              | some nextEvaluations =>
                  have hNextTotals := Totals.checkedReserve_withinCaps hReserve
                  have hNextEvaluations :=
                    StageEvaluationCounts.checkedRecord_withinReservations hRecord
                  by_cases hSnapshot :
                      entry.reservedTotals = nextTotals ∧
                        entry.reservedEvaluations = nextEvaluations
                  · have hTail :
                        replayEntries (entry :: priorEntries) nextTotals nextEvaluations remaining =
                          some (finalTotals, finalEvaluations) := by
                      simpa [hReject, hReserve, hRecord, hSnapshot] using hReplay
                    exact ih hNextTotals hNextEvaluations hTail
                  · simp [hReject, hReserve, hRecord, hSnapshot] at hReplay

theorem LedgerState.wellFormed_bounds (state : LedgerState)
    (h : state.WellFormed) :
    state.totals.WithinCaps ∧
      state.stageEvaluations.WithinReservations state.totals := by
  have hReplay : replayEntries [] Totals.zero StageEvaluationCounts.zero state.entries =
      some (state.totals, state.stageEvaluations) := h
  have hZeroTotals : Totals.zero.WithinCaps := by
    simp [Totals.WithinCaps, Totals.zero, maxA, maxS, maxEU, maxV,
      maxR0PerA, maxR2PerA, maxR3PerA]
  have hZeroEvaluations :
      StageEvaluationCounts.zero.WithinReservations Totals.zero := by
    simp [StageEvaluationCounts.WithinReservations, StageEvaluationCounts.zero, Totals.zero]
  exact replayEntries_preserves_bounds hZeroTotals hZeroEvaluations hReplay

theorem findEntry_none_iff_noEventId (entries : List OpportunityEntry)
    (eventId : EventId) :
    findEntry entries eventId = none ↔ eventId ∉ eventIds entries := by
  induction entries with
  | nil => simp [findEntry, eventIds]
  | cons entry remaining ih =>
      by_cases hEq : entry.request.eventId = eventId
      · simp [findEntry, eventIds, hEq]
      · have hNe : eventId ≠ entry.request.eventId := Ne.symm hEq
        simp [findEntry, eventIds, hEq, hNe, ih]

theorem rejection_none_implies_fresh_eventId
    {requireOpen : Bool} {entries : List OpportunityEntry}
    {totals : Totals} {evaluations : StageEvaluationCounts}
    {request : OpportunityRequest}
    (h : rejectionForRequest requireOpen entries totals evaluations request = none) :
    findEntry entries request.eventId = none := by
  cases hFind : findEntry entries request.eventId with
  | none => rfl
  | some existing =>
      simp [rejectionForRequest, eventIdPresent, hFind] at h

theorem nodup_append_singleton {α : Type} [DecidableEq α]
    (values : List α) (hUnique : values.Nodup) (value : α)
    (hFresh : value ∉ values) : (values ++ [value]).Nodup := by
  induction values with
  | nil => simp
  | cons head tail ih =>
      simp only [List.nodup_cons] at hUnique
      rcases hUnique with ⟨hHeadFresh, hTailUnique⟩
      change (head :: (tail ++ [value])).Nodup
      simp only [List.nodup_cons]
      constructor
      · intro hMem
        rcases List.mem_append.mp hMem with hMem | hEq
        · exact hHeadFresh hMem
        · simp only [List.mem_singleton] at hEq
          subst value
          exact hFresh (by simp)
      · apply ih hTailUnique
        intro hMem
        exact hFresh (List.mem_cons_of_mem head hMem)

theorem replayEntries_preserves_eventIdsUnique
    {priorEntries : List OpportunityEntry} {totals : Totals}
    {evaluations : StageEvaluationCounts} {entries : List OpportunityEntry}
    {finalTotals : Totals} {finalEvaluations : StageEvaluationCounts}
    (hPrefix : (eventIds priorEntries.reverse).Nodup)
    (hReplay : replayEntries priorEntries totals evaluations entries =
      some (finalTotals, finalEvaluations)) :
    (eventIds (priorEntries.reverse ++ entries)).Nodup := by
  induction entries generalizing priorEntries totals evaluations finalTotals finalEvaluations with
  | nil =>
      simp [replayEntries, eventIds] at hReplay
      cases hReplay
      simpa [eventIds] using hPrefix
  | cons entry remaining ih =>
      simp only [replayEntries] at hReplay
      cases hReject : rejectionForRequest false priorEntries totals evaluations entry.request with
      | some reason => simp [hReject] at hReplay
      | none =>
          have hFresh := rejection_none_implies_fresh_eventId hReject
          have hFreshReverse : entry.request.eventId ∉ eventIds priorEntries.reverse := by
            intro hMem
            have hMem' : entry.request.eventId ∈ (eventIds priorEntries).reverse := by
              simpa [eventIds, List.map_reverse] using hMem
            have hFreshPrefix : entry.request.eventId ∉ eventIds priorEntries :=
              (findEntry_none_iff_noEventId priorEntries entry.request.eventId).mp hFresh
            exact hFreshPrefix (by simpa using hMem')
          have hPrefixNext : (eventIds (entry :: priorEntries).reverse).Nodup := by
            rw [List.reverse_cons, eventIds, List.map_append]
            exact nodup_append_singleton (eventIds priorEntries.reverse) hPrefix
              entry.request.eventId hFreshReverse
          cases hReserve : totals.checkedReserve entry.request.body with
          | none => simp [hReject, hReserve] at hReplay
          | some nextTotals =>
              cases hRecord : evaluations.checkedRecord nextTotals entry.request.body with
              | none => simp [hReject, hReserve, hRecord] at hReplay
              | some nextEvaluations =>
                  by_cases hSnapshot :
                      entry.reservedTotals = nextTotals ∧
                        entry.reservedEvaluations = nextEvaluations
                  · have hTail :
                        replayEntries (entry :: priorEntries) nextTotals nextEvaluations remaining =
                          some (finalTotals, finalEvaluations) := by
                      simpa [hReject, hReserve, hRecord, hSnapshot] using hReplay
                    have hResult := ih hPrefixNext hTail
                    simpa [eventIds, List.reverse_cons, List.append_assoc] using hResult
                  · simp [hReject, hReserve, hRecord, hSnapshot] at hReplay

theorem LedgerState.wellFormed_eventIdsUnique (state : LedgerState)
    (h : state.WellFormed) : EventIdsUnique state.entries := by
  have hReplay : replayEntries [] Totals.zero StageEvaluationCounts.zero state.entries =
      some (state.totals, state.stageEvaluations) := h
  have hEmpty : (eventIds ([] : List OpportunityEntry).reverse).Nodup := by simp [eventIds]
  have hUnique := replayEntries_preserves_eventIdsUnique hEmpty hReplay
  simpa [EventIdsUnique, eventIds] using hUnique

theorem replayEntries_arbitrarySequence_invariants
    {priorEntries : List OpportunityEntry} {totals : Totals}
    {evaluations : StageEvaluationCounts} {entries : List OpportunityEntry}
    {finalTotals : Totals} {finalEvaluations : StageEvaluationCounts}
    (hPrefixUnique : (eventIds priorEntries.reverse).Nodup)
    (hTotals : totals.WithinCaps)
    (hEvaluations : evaluations.WithinReservations totals)
    (hReplay : replayEntries priorEntries totals evaluations entries =
      some (finalTotals, finalEvaluations)) :
    finalTotals.WithinCaps ∧
      finalEvaluations.WithinReservations finalTotals ∧
      (eventIds (priorEntries.reverse ++ entries)).Nodup := by
  exact ⟨(replayEntries_preserves_bounds hTotals hEvaluations hReplay).1,
    (replayEntries_preserves_bounds hTotals hEvaluations hReplay).2,
    replayEntries_preserves_eventIdsUnique hPrefixUnique hReplay⟩

theorem LedgerState.wellFormed_invariants (state : LedgerState)
    (h : state.WellFormed) :
    state.totals.WithinCaps ∧
      state.stageEvaluations.WithinReservations state.totals ∧
      EventIdsUnique state.entries := by
  exact ⟨(LedgerState.wellFormed_bounds state h).1,
    (LedgerState.wellFormed_bounds state h).2,
    LedgerState.wellFormed_eventIdsUnique state h⟩

theorem reserveOpportunity_exactRetry
    {state : LedgerState} {request : OpportunityRequest}
    {existing : OpportunityEntry}
    (hWellFormed : state.WellFormed)
    (hFind : findEntry state.entries request.eventId = some existing)
    (hRequest : existing.request = request) :
    let result := reserveOpportunity state request
    result.disposition = .exactRetry ∧ result.state = state ∧
      result.receipt = some (reservationReceipt state.scopeId existing) ∧
      result.terminalReceipt = existingTerminalReceipt state.scopeId existing := by
  simp [reserveOpportunity, hWellFormed, hFind, hRequest]

theorem reserveOpportunity_changedInput_conflicts
    {state : LedgerState} {request : OpportunityRequest}
    {existing : OpportunityEntry}
    (hWellFormed : state.WellFormed)
    (hFind : findEntry state.entries request.eventId = some existing)
    (hChanged : existing.request ≠ request) :
    let result := reserveOpportunity state request
    result.disposition = .inputConflict ∧ result.state = state ∧
      result.receipt = some (reservationReceipt state.scopeId existing) ∧
      result.terminalReceipt = existingTerminalReceipt state.scopeId existing := by
  simp [reserveOpportunity, hWellFormed, hFind, hChanged]

theorem reserveOpportunity_preAdmissionDenial_unchanged
    {state : LedgerState} {request : OpportunityRequest}
    {reason : RejectionReason}
    (hWellFormed : state.WellFormed)
    (hNoEvent : findEntry state.entries request.eventId = none)
    (hDenied : rejectionForRequest true state.entries state.totals
      state.stageEvaluations request = some reason) :
    let result := reserveOpportunity state request
    result.state = state ∧ result.disposition = .rejected reason ∧
      result.receipt = none ∧ result.terminalReceipt = none := by
  simp [reserveOpportunity, hWellFormed, hNoEvent, hDenied]

theorem reserveOpportunity_countersNeverDecrease
    (state : LedgerState) (request : OpportunityRequest) :
    state.totals.ComponentwiseLE (reserveOpportunity state request).state.totals ∧
      state.stageEvaluations.ComponentwiseLE
        (reserveOpportunity state request).state.stageEvaluations := by
  by_cases hWellFormed : state.WellFormed
  · simp only [reserveOpportunity, if_pos hWellFormed]
    cases hFind : findEntry state.entries request.eventId with
    | some existing =>
        by_cases hSame : existing.request = request <;>
          simp [hFind, hSame, Totals.ComponentwiseLE,
            StageEvaluationCounts.ComponentwiseLE]
    | none =>
        cases hReject : rejectionForRequest true state.entries state.totals
            state.stageEvaluations request with
        | some reason =>
            simp [hFind, hReject, Totals.ComponentwiseLE,
              StageEvaluationCounts.ComponentwiseLE]
        | none =>
            cases hReserve : state.totals.checkedReserve request.body with
            | none =>
                simp [hFind, hReject, hReserve, Totals.ComponentwiseLE,
                  StageEvaluationCounts.ComponentwiseLE]
            | some nextTotals =>
                cases hRecord : state.stageEvaluations.checkedRecord
                    nextTotals request.body with
                | none =>
                    simp [hFind, hReject, hReserve, hRecord, Totals.ComponentwiseLE,
                      StageEvaluationCounts.ComponentwiseLE]
                | some nextEvaluations =>
                    simpa only [hFind, hReject, hReserve, hRecord] using
                      And.intro
                        (Totals.checkedReserve_componentwiseLE hReserve)
                        (StageEvaluationCounts.checkedRecord_componentwiseLE hRecord)
  · simp [reserveOpportunity, hWellFormed, Totals.ComponentwiseLE,
      StageEvaluationCounts.ComponentwiseLE]

theorem finalizeOpportunity_terminalOutcomeStable
    {state : LedgerState} {eventId : EventId} {requested prior : Outcome}
    {existing : OpportunityEntry}
    (hWellFormed : state.WellFormed)
    (hFind : findEntry state.entries eventId = some existing)
    (hTerminal : existing.outcome = some prior) :
    let result := finalizeOpportunity state eventId requested
    if prior = requested then
      result.disposition = .exactRetry ∧ result.state = state ∧
        result.receipt = some (terminalReceipt state.scopeId existing prior)
    else
      result.disposition = .inputConflict ∧ result.state = state ∧
      result.receipt = some (terminalReceipt state.scopeId existing prior) := by
  by_cases hSame : prior = requested <;>
    simp [finalizeOpportunity, hWellFormed, hFind, hTerminal, hSame]

theorem finalizeOpportunity_countersUnchanged (state : LedgerState)
    (eventId : EventId) (outcome : Outcome) :
    let result := finalizeOpportunity state eventId outcome
    result.state.totals = state.totals ∧
      result.state.stageEvaluations = state.stageEvaluations := by
  by_cases hWellFormed : state.WellFormed
  · simp only [finalizeOpportunity, if_pos hWellFormed]
    cases hFind : findEntry state.entries eventId with
    | none => simp [hFind]
    | some existing =>
        cases hOutcome : existing.outcome with
        | none => simp [hFind, hOutcome, withOutcome]
        | some prior =>
            by_cases hSame : prior = outcome <;> simp [hFind, hOutcome, hSame]
  · simp [finalizeOpportunity, hWellFormed]

theorem reserveOpportunity_acceptedState_bounds
    (state : LedgerState) (request : OpportunityRequest)
    (hAccepted : (reserveOpportunity state request).disposition = .reserved) :
    (reserveOpportunity state request).state.totals.WithinCaps ∧
      (reserveOpportunity state request).state.stageEvaluations.WithinReservations
        (reserveOpportunity state request).state.totals := by
  by_cases hWellFormed : state.WellFormed
  · simp only [reserveOpportunity, if_pos hWellFormed] at hAccepted ⊢
    cases hFind : findEntry state.entries request.eventId with
    | some existing =>
        by_cases hSame : existing.request = request <;>
          simp [hFind, hSame] at hAccepted ⊢
    | none =>
        cases hReject : rejectionForRequest true state.entries state.totals
            state.stageEvaluations request with
        | some reason => simp [hFind, hReject] at hAccepted
        | none =>
            cases hReserve : state.totals.checkedReserve request.body with
            | none => simp [hFind, hReject, hReserve] at hAccepted
            | some nextTotals =>
                cases hRecord : state.stageEvaluations.checkedRecord nextTotals request.body with
                | none => simp [hFind, hReject, hReserve, hRecord] at hAccepted
                | some nextEvaluations =>
                    simp [hFind, hReject, hReserve, hRecord] at hAccepted ⊢
                    exact ⟨Totals.checkedReserve_withinCaps hReserve,
                      StageEvaluationCounts.checkedRecord_withinReservations hRecord⟩
  · simp [reserveOpportunity, hWellFormed] at hAccepted

theorem reserveOpportunity_nonreserved_state_eq
    (state : LedgerState) (request : OpportunityRequest)
    (hNotAccepted : (reserveOpportunity state request).disposition ≠ .reserved) :
    (reserveOpportunity state request).state = state := by
  by_cases hWellFormed : state.WellFormed
  · simp only [reserveOpportunity, if_pos hWellFormed] at hNotAccepted ⊢
    cases hFind : findEntry state.entries request.eventId with
    | some existing =>
        by_cases hSame : existing.request = request <;>
          simp [hFind, hSame]
    | none =>
        cases hReject : rejectionForRequest true state.entries state.totals
            state.stageEvaluations request with
        | some reason => simp [hFind, hReject]
        | none =>
            cases hReserve : state.totals.checkedReserve request.body with
            | none => simp [hFind, hReject, hReserve]
            | some nextTotals =>
                cases hRecord : state.stageEvaluations.checkedRecord
                    nextTotals request.body with
                | none => simp [hFind, hReject, hReserve, hRecord]
                | some nextEvaluations =>
                    simp [hFind, hReject, hReserve, hRecord] at hNotAccepted
  · simp [reserveOpportunity, hWellFormed]

theorem reserveOpportunity_success_appends
    (state : LedgerState) (request : OpportunityRequest)
    (hAccepted : (reserveOpportunity state request).disposition = .reserved) :
    ∃ entry, entry.request = request ∧
      (reserveOpportunity state request).state.entries = state.entries ++ [entry] ∧
      findEntry state.entries request.eventId = none := by
  by_cases hWellFormed : state.WellFormed
  · simp only [reserveOpportunity, if_pos hWellFormed] at hAccepted ⊢
    cases hFind : findEntry state.entries request.eventId with
    | some existing =>
        by_cases hSame : existing.request = request <;>
          simp [hFind, hSame] at hAccepted ⊢
    | none =>
        cases hReject : rejectionForRequest true state.entries state.totals
            state.stageEvaluations request with
        | some reason => simp [hFind, hReject] at hAccepted
        | none =>
            cases hReserve : state.totals.checkedReserve request.body with
            | none => simp [hFind, hReject, hReserve] at hAccepted
            | some nextTotals =>
                cases hRecord : state.stageEvaluations.checkedRecord
                    nextTotals request.body with
                | none => simp [hFind, hReject, hReserve, hRecord] at hAccepted
                | some nextEvaluations =>
                    let newEntry : OpportunityEntry :=
                      { request := request, reservedTotals := nextTotals,
                        reservedEvaluations := nextEvaluations, outcome := none }
                    refine ⟨newEntry, ?_⟩
                    constructor
                    · rfl
                    constructor
                    · simp [reserveOpportunity, hWellFormed, hFind, hReject,
                        hReserve, hRecord, newEntry]
                    · rfl
  · simp [reserveOpportunity, hWellFormed] at hAccepted

def AccountingInvariant (state : LedgerState) : Prop :=
  state.totals.WithinCaps ∧
    state.stageEvaluations.WithinReservations state.totals ∧
    EventIdsUnique state.entries

theorem reserveOpportunity_preserves_accountingInvariant
    (state : LedgerState) (request : OpportunityRequest)
    (hInvariant : AccountingInvariant state) :
    AccountingInvariant (reserveOpportunity state request).state := by
  by_cases hAccepted : (reserveOpportunity state request).disposition = .reserved
  · have hBounds := reserveOpportunity_acceptedState_bounds state request hAccepted
    obtain ⟨entry, hEntryRequest, hAppend, hFresh⟩ :=
      reserveOpportunity_success_appends state request hAccepted
    have hFreshIds : entry.request.eventId ∉ eventIds state.entries := by
      simpa [hEntryRequest] using
        (findEntry_none_iff_noEventId state.entries request.eventId).mp hFresh
    have hUnique : EventIdsUnique (state.entries ++ [entry]) := by
      simpa [EventIdsUnique, eventIds] using
        nodup_append_singleton (eventIds state.entries) hInvariant.2.2
          entry.request.eventId hFreshIds
    unfold AccountingInvariant
    rw [hAppend]
    exact ⟨hBounds.1, hBounds.2, hUnique⟩
  · rw [reserveOpportunity_nonreserved_state_eq state request hAccepted]
    exact hInvariant

theorem withOutcome_eventIds_unchanged (entries : List OpportunityEntry)
    (eventId : EventId) (outcome : Outcome) :
    eventIds (withOutcome entries eventId outcome) = eventIds entries := by
  simp only [eventIds, withOutcome, List.map_map]
  apply List.map_congr_left
  intro entry hMember
  by_cases hEq : entry.request.eventId = eventId <;> simp [hEq]

theorem finalizeOpportunity_eventIds_unchanged (state : LedgerState)
    (eventId : EventId) (outcome : Outcome) :
    eventIds (finalizeOpportunity state eventId outcome).state.entries =
      eventIds state.entries := by
  by_cases hWellFormed : state.WellFormed
  · simp only [finalizeOpportunity, if_pos hWellFormed]
    cases hFind : findEntry state.entries eventId with
    | none => simp [hFind]
    | some existing =>
        cases hOutcome : existing.outcome with
        | none => simp [hFind, hOutcome, withOutcome_eventIds_unchanged]
        | some prior =>
            by_cases hSame : prior = outcome <;> simp [hFind, hOutcome, hSame]
  · simp [finalizeOpportunity, hWellFormed]

theorem finalizeOpportunity_preserves_accountingInvariant
    (state : LedgerState) (eventId : EventId) (outcome : Outcome)
    (hInvariant : AccountingInvariant state) :
    AccountingInvariant (finalizeOpportunity state eventId outcome).state := by
  change (finalizeOpportunity state eventId outcome).state.totals.WithinCaps ∧
    (finalizeOpportunity state eventId outcome).state.stageEvaluations.WithinReservations
      (finalizeOpportunity state eventId outcome).state.totals ∧
    (eventIds (finalizeOpportunity state eventId outcome).state.entries).Nodup
  have hCounters := finalizeOpportunity_countersUnchanged state eventId outcome
  have hIds := finalizeOpportunity_eventIds_unchanged state eventId outcome
  exact ⟨by rw [hCounters.1]; exact hInvariant.1,
    ⟨by rw [hCounters.2, hCounters.1]; exact hInvariant.2.1,
      by rw [hIds]; exact hInvariant.2.2⟩⟩

inductive OpportunityCommand where
  | reserve (request : OpportunityRequest)
  | finalize (eventId : EventId) (outcome : Outcome)
  deriving Repr

def applyOpportunityCommand (state : LedgerState) : OpportunityCommand → LedgerState
  | .reserve request => (reserveOpportunity state request).state
  | .finalize eventId outcome => (finalizeOpportunity state eventId outcome).state

def runOpportunityCommands : LedgerState → List OpportunityCommand → LedgerState
  | state, [] => state
  | state, command :: remaining =>
      runOpportunityCommands (applyOpportunityCommand state command) remaining

theorem runOpportunityCommands_preserves_accountingInvariant
    (state : LedgerState) (commands : List OpportunityCommand)
    (hInvariant : AccountingInvariant state) :
    AccountingInvariant (runOpportunityCommands state commands) := by
  induction commands generalizing state with
  | nil => exact hInvariant
  | cons command remaining ih =>
      cases command with
      | reserve request =>
          exact ih (reserveOpportunity state request).state
            (reserveOpportunity_preserves_accountingInvariant state request hInvariant)
      | finalize eventId outcome =>
          exact ih (finalizeOpportunity state eventId outcome).state
            (finalizeOpportunity_preserves_accountingInvariant state eventId outcome hInvariant)

theorem runOpportunityCommands_countersNeverDecrease
    (state : LedgerState) (commands : List OpportunityCommand) :
    state.totals.ComponentwiseLE
        (runOpportunityCommands state commands).totals ∧
      state.stageEvaluations.ComponentwiseLE
        (runOpportunityCommands state commands).stageEvaluations := by
  induction commands generalizing state with
  | nil =>
      simp [runOpportunityCommands, Totals.ComponentwiseLE,
        StageEvaluationCounts.ComponentwiseLE]
  | cons command remaining ih =>
      cases command with
      | reserve request =>
          have hStep := reserveOpportunity_countersNeverDecrease state request
          have hTail := ih (reserveOpportunity state request).state
          simpa [runOpportunityCommands, applyOpportunityCommand] using
            And.intro
              (Totals.ComponentwiseLE_trans hStep.1 hTail.1)
              (StageEvaluationCounts.ComponentwiseLE_trans hStep.2 hTail.2)
      | finalize eventId outcome =>
          have hStep := finalizeOpportunity_countersUnchanged state eventId outcome
          have hStepTotals : state.totals.ComponentwiseLE
              (finalizeOpportunity state eventId outcome).state.totals := by
            rw [hStep.1]
            simp [Totals.ComponentwiseLE]
          have hStepEvaluations : state.stageEvaluations.ComponentwiseLE
              (finalizeOpportunity state eventId outcome).state.stageEvaluations := by
            rw [hStep.2]
            simp [StageEvaluationCounts.ComponentwiseLE]
          have hTail := ih (finalizeOpportunity state eventId outcome).state
          simpa [runOpportunityCommands, applyOpportunityCommand] using
            And.intro
              (Totals.ComponentwiseLE_trans hStepTotals hTail.1)
              (StageEvaluationCounts.ComponentwiseLE_trans hStepEvaluations hTail.2)

theorem runOpportunityCommands_fromEmpty_invariants
    (scopeId : ScopeId) (commands : List OpportunityCommand) :
    AccountingInvariant
      (runOpportunityCommands (LedgerState.empty scopeId) commands) := by
  apply runOpportunityCommands_preserves_accountingInvariant
  simp [AccountingInvariant, LedgerState.empty, Totals.WithinCaps, Totals.zero,
    StageEvaluationCounts.WithinReservations, StageEvaluationCounts.zero,
    EventIdsUnique, eventIds, maxA, maxS, maxEU, maxV, maxR0PerA, maxR2PerA,
    maxR3PerA]

#print axioms replayEntries_preserves_bounds
#print axioms replayEntries_arbitrarySequence_invariants
#print axioms LedgerState.wellFormed_bounds
#print axioms LedgerState.wellFormed_eventIdsUnique
#print axioms LedgerState.wellFormed_invariants
#print axioms reserveOpportunity_exactRetry
#print axioms reserveOpportunity_changedInput_conflicts
#print axioms reserveOpportunity_preAdmissionDenial_unchanged
#print axioms reserveOpportunity_countersNeverDecrease
#print axioms reserveOpportunity_success_appends
#print axioms reserveOpportunity_preserves_accountingInvariant
#print axioms finalizeOpportunity_preserves_accountingInvariant
#print axioms runOpportunityCommands_preserves_accountingInvariant
#print axioms runOpportunityCommands_countersNeverDecrease
#print axioms runOpportunityCommands_fromEmpty_invariants
#print axioms finalizeOpportunity_terminalOutcomeStable
#print axioms finalizeOpportunity_countersUnchanged
#print axioms reserveOpportunity_acceptedState_bounds

end BlindLedger.DirectMaskOpportunityV1
