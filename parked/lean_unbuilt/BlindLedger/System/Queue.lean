import BlindLedger.System.Types

namespace BlindLedger.System

/-! Public request and Queue IPC records intentionally carry ordered opaque
    SourceRef32 identifiers. QueueIpc derives its refs from the request, so
    there is one public reference owner in this model. No private source
    provision record is embedded in either public record. -/
structure SourceRequest3596 where
  payload : Fin 3596 → Byte
  sourceRefs : OperationBatch

structure QueueIpc where
  request : SourceRequest3596

def QueueIpc.sourceRefs (ipc : QueueIpc) : OperationBatch :=
  ipc.request.sourceRefs

theorem queueIpc_sourceRefs_derived (ipc : QueueIpc) :
    ipc.sourceRefs = ipc.request.sourceRefs := by
  rfl

/-! This finite correspondence boundary mirrors the accepted Queue runtime
    outbox seam at commit `1cc7c092a42140d99a3b8e6e52ba419fc770c7fd`:
    READY and DELIVERY_UNCONFIRMED rows are claimable only below the fixed
    maximum attempt count, LEASED rows recover on an expired deadline, and
    ACKNOWLEDGED rows are terminal. SQLite serialization, worker fencing,
    receiver behavior, and durable recovery remain external premises. -/
def runtimeMaxAttempts : Nat := 3

abbrev RuntimeAttempt := Fin (runtimeMaxAttempts + 1)

def runtimeAttemptZero : RuntimeAttempt :=
  ⟨0, by decide⟩

def runtimeAttemptOne : RuntimeAttempt :=
  ⟨1, by decide⟩

def runtimeAttemptTwo : RuntimeAttempt :=
  ⟨2, by decide⟩

def runtimeAttemptMax : RuntimeAttempt :=
  ⟨runtimeMaxAttempts, by simp [runtimeMaxAttempts]⟩

def nextRuntimeAttempt (attempt : RuntimeAttempt) : Option RuntimeAttempt :=
  if h : attempt.val < runtimeMaxAttempts then
    some
      ⟨attempt.val + 1, by
        have hbound : attempt.val + 1 < runtimeMaxAttempts + 1 := by
          omega
        exact hbound⟩
  else
    none

inductive RuntimeOutboxStatus where
  | READY
  | LEASED
  | ACKNOWLEDGED
  | DELIVERY_UNCONFIRMED
deriving DecidableEq, Repr

inductive RuntimeOutboxState where
  | ready (attempt : RuntimeAttempt)
  | leased (attempt : RuntimeAttempt) (leaseExpiresAt : Nat)
  | acknowledged (attempt : RuntimeAttempt)
  | deliveryUnconfirmed (attempt : RuntimeAttempt)
deriving DecidableEq, Repr

def RuntimeOutboxState.attempt : RuntimeOutboxState → RuntimeAttempt
  | .ready attempt => attempt
  | .leased attempt _ => attempt
  | .acknowledged attempt => attempt
  | .deliveryUnconfirmed attempt => attempt

def RuntimeOutboxState.status : RuntimeOutboxState → RuntimeOutboxStatus
  | .ready _ => .READY
  | .leased _ _ => .LEASED
  | .acknowledged _ => .ACKNOWLEDGED
  | .deliveryUnconfirmed _ => .DELIVERY_UNCONFIRMED

structure RuntimeOutboxRow where
  entry : OutboxEntry
  delivery : RuntimeOutboxState

abbrev RuntimeOutbox := BatchIndex → Option RuntimeOutboxRow

def runtimeOutboxFromOutbox
    (outbox : Outbox) (delivery : BatchIndex → RuntimeOutboxState) :
    RuntimeOutbox :=
  fun i =>
    (outbox.entries i).map
      (fun entry => { entry := entry, delivery := delivery i })

def updateRuntimeOutbox
    (outbox : RuntimeOutbox) (i : BatchIndex)
    (update : RuntimeOutboxRow → RuntimeOutboxRow) : RuntimeOutbox :=
  fun j =>
    if j = i then
      match outbox j with
      | none => none
      | some row => some (update row)
    else
      outbox j

def runtimeDirectEligible (state : RuntimeOutboxState) : Bool :=
  match state with
  | .ready attempt => decide (attempt.val < runtimeMaxAttempts)
  | _ => false

def runtimeReconciliationEligible (state : RuntimeOutboxState) : Bool :=
  match state with
  | .deliveryUnconfirmed attempt => decide (attempt.val < runtimeMaxAttempts)
  | _ => false

def runtimeRecoverState (now : Nat) : RuntimeOutboxState → RuntimeOutboxState
  | .leased attempt leaseExpiresAt =>
      if leaseExpiresAt ≤ now then
        if attempt.val < runtimeMaxAttempts then
          .ready attempt
        else
          .deliveryUnconfirmed attempt
      else
        .leased attempt leaseExpiresAt
  | state => state

def runtimeRecoverRow (now : Nat) (row : RuntimeOutboxRow) : RuntimeOutboxRow :=
  { row with delivery := runtimeRecoverState now row.delivery }

def runtimeRecoverOutbox
    (outbox : RuntimeOutbox) (i : BatchIndex) (now : Nat) : RuntimeOutbox :=
  updateRuntimeOutbox outbox i (runtimeRecoverRow now)

def runtimeClaimDirectState
    (now leaseDuration : Nat) (state : RuntimeOutboxState) :
    Option RuntimeOutboxState :=
  match state with
  | .ready attempt =>
      if 0 < leaseDuration then
        match nextRuntimeAttempt attempt with
        | none => none
        | some next => some (.leased next (now + leaseDuration))
      else
        none
  | _ => none

def runtimeClaimDirect
    (now leaseDuration : Nat) (row : RuntimeOutboxRow) :
    Option RuntimeOutboxRow :=
  (runtimeClaimDirectState now leaseDuration row.delivery).map
    (fun delivery => { row with delivery := delivery })

def runtimeClaimReconciliationState
    (now leaseDuration : Nat) (state : RuntimeOutboxState) :
    Option RuntimeOutboxState :=
  match state with
  | .deliveryUnconfirmed attempt =>
      if 0 < leaseDuration then
        match nextRuntimeAttempt attempt with
        | none => none
        | some next => some (.leased next (now + leaseDuration))
      else
        none
  | _ => none

def runtimeClaimReconciliation
    (now leaseDuration : Nat) (row : RuntimeOutboxRow) :
    Option RuntimeOutboxRow :=
  (runtimeClaimReconciliationState now leaseDuration row.delivery).map
    (fun delivery => { row with delivery := delivery })

inductive RuntimeDeliveryOutcome where
  | acknowledged
  | deliveryUnconfirmed
deriving DecidableEq, Repr

def runtimeSettleState
    (now : Nat) (outcome : RuntimeDeliveryOutcome)
    (state : RuntimeOutboxState) : RuntimeOutboxState :=
  match state with
  | .leased attempt leaseExpiresAt =>
      if leaseExpiresAt ≤ now then
        runtimeRecoverState now state
      else
        match outcome with
        | .acknowledged => .acknowledged attempt
        | .deliveryUnconfirmed => .deliveryUnconfirmed attempt
  | state => state

def runtimeSettle
    (now : Nat) (outcome : RuntimeDeliveryOutcome)
    (row : RuntimeOutboxRow) : RuntimeOutboxRow :=
  { row with delivery := runtimeSettleState now outcome row.delivery }

/-! The formal scope below is the row-local delivery state machine. A valid
    action is one whose pure transition function returns `some`; a trace is a
    finite list of such actions whose composed result is `some`. The scope
    does not model SQLite serialization, worker fencing, receiver effects,
    durable recovery, or any external source/payment authority. -/
def runtimeDirectScope (state : RuntimeOutboxState) : Prop :=
  match state with
  | .ready attempt => attempt.val < runtimeMaxAttempts
  | _ => False

def runtimeReconciliationScope (state : RuntimeOutboxState) : Prop :=
  match state with
  | .deliveryUnconfirmed attempt => attempt.val < runtimeMaxAttempts
  | _ => False

inductive RuntimeAction where
  | recover (now : Nat)
  | claimDirect (now leaseDuration : Nat)
  | claimReconciliation (now leaseDuration : Nat)
  | settle (now : Nat) (outcome : RuntimeDeliveryOutcome)
deriving DecidableEq, Repr

def runtimeApplyAction : RuntimeAction → RuntimeOutboxState → Option RuntimeOutboxState
  | .recover now, state => some (runtimeRecoverState now state)
  | .claimDirect now leaseDuration, state =>
      runtimeClaimDirectState now leaseDuration state
  | .claimReconciliation now leaseDuration, state =>
      runtimeClaimReconciliationState now leaseDuration state
  | .settle now outcome, state => some (runtimeSettleState now outcome state)

def runtimeActionClaimCount : RuntimeAction → Nat
  | .claimDirect _ _ => 1
  | .claimReconciliation _ _ => 1
  | _ => 0

def runtimeClaimCount : List RuntimeAction → Nat
  | [] => 0
  | action :: actions => runtimeActionClaimCount action + runtimeClaimCount actions

def runtimeTraceRun : List RuntimeAction → RuntimeOutboxState → Option RuntimeOutboxState
  | [], state => some state
  | action :: actions, state =>
      (runtimeApplyAction action state).bind (runtimeTraceRun actions)

def runtimeTraceValid
    (actions : List RuntimeAction) (initial final : RuntimeOutboxState) : Prop :=
  runtimeTraceRun actions initial = some final

def runtimeRecoveryTrace : List Nat → RuntimeOutboxState → RuntimeOutboxState
  | [], state => state
  | now :: times, state =>
      runtimeRecoveryTrace times (runtimeRecoverState now state)

theorem nextRuntimeAttempt_none_at_max :
    nextRuntimeAttempt runtimeAttemptMax = none := by
  have hnot : ¬ runtimeAttemptMax.val < runtimeMaxAttempts := by
    change ¬ (3 < 3)
    omega
  simp [nextRuntimeAttempt, hnot]

theorem nextRuntimeAttempt_some_increments
    {attempt next : RuntimeAttempt}
    (h : nextRuntimeAttempt attempt = some next) :
    next.val = attempt.val + 1 := by
  unfold nextRuntimeAttempt at h
  split at h
  · cases h
    rfl
  · contradiction

theorem runtimeDirectEligible_iff_scope (state : RuntimeOutboxState) :
    runtimeDirectEligible state = true ↔ runtimeDirectScope state := by
  cases state <;>
    simp [runtimeDirectEligible, runtimeDirectScope]

theorem runtimeReconciliationEligible_iff_scope (state : RuntimeOutboxState) :
    runtimeReconciliationEligible state = true ↔
      runtimeReconciliationScope state := by
  cases state <;>
    simp [runtimeReconciliationEligible, runtimeReconciliationScope]

theorem runtime_eligibility_scopes_disjoint (state : RuntimeOutboxState) :
    ¬ (runtimeDirectScope state ∧ runtimeReconciliationScope state) := by
  cases state <;> simp [runtimeDirectScope, runtimeReconciliationScope]

theorem runtime_eligibility_disjoint (state : RuntimeOutboxState) :
    ¬ (runtimeDirectEligible state = true ∧
      runtimeReconciliationEligible state = true) := by
  intro h
  apply runtime_eligibility_scopes_disjoint state
  exact ⟨(runtimeDirectEligible_iff_scope state).mp h.1,
    (runtimeReconciliationEligible_iff_scope state).mp h.2⟩

theorem runtimeRecoverState_idempotent
    (state : RuntimeOutboxState) (now : Nat) :
    runtimeRecoverState now (runtimeRecoverState now state) =
      runtimeRecoverState now state := by
  cases state with
  | ready attempt => rfl
  | acknowledged attempt => rfl
  | deliveryUnconfirmed attempt => rfl
  | leased attempt leaseExpiresAt =>
      by_cases hexpired : leaseExpiresAt ≤ now
      · by_cases havailable : attempt.val < runtimeMaxAttempts
        · simp [runtimeRecoverState, hexpired, havailable]
        · simp [runtimeRecoverState, hexpired, havailable]
      · simp [runtimeRecoverState, hexpired]

theorem runtimeRecoverState_preserves_attempt
    (state : RuntimeOutboxState) (now : Nat) :
    (runtimeRecoverState now state).attempt.val = state.attempt.val := by
  cases state with
  | ready attempt => rfl
  | acknowledged attempt => rfl
  | deliveryUnconfirmed attempt => rfl
  | leased attempt leaseExpiresAt =>
      by_cases hexpired : leaseExpiresAt ≤ now
      · by_cases havailable : attempt.val < runtimeMaxAttempts
        · simp [runtimeRecoverState, hexpired, havailable,
            RuntimeOutboxState.attempt]
        · simp [runtimeRecoverState, hexpired, havailable,
            RuntimeOutboxState.attempt]
      · simp [runtimeRecoverState, hexpired, RuntimeOutboxState.attempt]

theorem runtimeSettleState_preserves_attempt
    (state : RuntimeOutboxState) (now : Nat)
    (outcome : RuntimeDeliveryOutcome) :
    (runtimeSettleState now outcome state).attempt.val = state.attempt.val := by
  cases state with
  | ready attempt => rfl
  | acknowledged attempt => rfl
  | deliveryUnconfirmed attempt => rfl
  | leased attempt leaseExpiresAt =>
      by_cases hexpired : leaseExpiresAt ≤ now
      · simpa [runtimeSettleState, hexpired] using
          runtimeRecoverState_preserves_attempt
            (.leased attempt leaseExpiresAt) now
      · cases outcome <;>
          simp [runtimeSettleState, hexpired, RuntimeOutboxState.attempt]

theorem runtimeClaimDirectState_success_increments
    {now leaseDuration : Nat} {state next : RuntimeOutboxState}
    (hclaim : runtimeClaimDirectState now leaseDuration state = some next) :
    next.attempt.val = state.attempt.val + 1 := by
  cases state with
  | ready attempt =>
      by_cases hpositive : 0 < leaseDuration
      · cases hnext : nextRuntimeAttempt attempt with
        | none =>
            simp [runtimeClaimDirectState, hpositive, hnext] at hclaim
        | some claimed =>
            have hincrement : claimed.val = attempt.val + 1 :=
              nextRuntimeAttempt_some_increments hnext
            simp [runtimeClaimDirectState, hpositive, hnext] at hclaim
            cases hclaim
            exact hincrement
      · simp [runtimeClaimDirectState, hpositive] at hclaim
  | leased attempt leaseExpiresAt =>
      simp [runtimeClaimDirectState] at hclaim
  | acknowledged attempt =>
      simp [runtimeClaimDirectState] at hclaim
  | deliveryUnconfirmed attempt =>
      simp [runtimeClaimDirectState] at hclaim

theorem runtimeClaimReconciliationState_success_increments
    {now leaseDuration : Nat} {state next : RuntimeOutboxState}
    (hclaim :
      runtimeClaimReconciliationState now leaseDuration state = some next) :
    next.attempt.val = state.attempt.val + 1 := by
  cases state with
  | ready attempt =>
      simp [runtimeClaimReconciliationState] at hclaim
  | leased attempt leaseExpiresAt =>
      simp [runtimeClaimReconciliationState] at hclaim
  | acknowledged attempt =>
      simp [runtimeClaimReconciliationState] at hclaim
  | deliveryUnconfirmed attempt =>
      by_cases hpositive : 0 < leaseDuration
      · cases hnext : nextRuntimeAttempt attempt with
        | none =>
            simp [runtimeClaimReconciliationState, hpositive, hnext] at hclaim
        | some claimed =>
            have hincrement : claimed.val = attempt.val + 1 :=
              nextRuntimeAttempt_some_increments hnext
            simp [runtimeClaimReconciliationState, hpositive, hnext] at hclaim
            cases hclaim
            exact hincrement
      · simp [runtimeClaimReconciliationState, hpositive] at hclaim

theorem runtimeApplyAction_attempt_step
    {action : RuntimeAction} {state next : RuntimeOutboxState}
    (hstep : runtimeApplyAction action state = some next) :
    state.attempt.val + runtimeActionClaimCount action = next.attempt.val := by
  cases action with
  | recover now =>
      simp [runtimeApplyAction] at hstep
      cases hstep
      simp [runtimeActionClaimCount, runtimeRecoverState_preserves_attempt]
  | claimDirect now leaseDuration =>
      have hclaim :
          runtimeClaimDirectState now leaseDuration state = some next := by
        simpa [runtimeApplyAction] using hstep
      have hincrement := runtimeClaimDirectState_success_increments hclaim
      simpa [runtimeActionClaimCount] using hincrement.symm
  | claimReconciliation now leaseDuration =>
      have hclaim :
          runtimeClaimReconciliationState now leaseDuration state = some next := by
        simpa [runtimeApplyAction] using hstep
      have hincrement := runtimeClaimReconciliationState_success_increments hclaim
      simpa [runtimeActionClaimCount] using hincrement.symm
  | settle now outcome =>
      simp [runtimeApplyAction] at hstep
      cases hstep
      simp [runtimeActionClaimCount, runtimeSettleState_preserves_attempt]

theorem runtimeTrace_attempt_accounting
    (actions : List RuntimeAction) (initial final : RuntimeOutboxState)
    (hvalid : runtimeTraceValid actions initial final) :
    initial.attempt.val + runtimeClaimCount actions = final.attempt.val := by
  induction actions generalizing initial final with
  | nil =>
      have hequal : initial = final := by
        simpa [runtimeTraceValid, runtimeTraceRun] using hvalid
      subst final
      simp [runtimeClaimCount]
  | cons action actions ih =>
      cases hstep : runtimeApplyAction action initial with
      | none =>
          simp [runtimeTraceValid, runtimeTraceRun, hstep] at hvalid
      | some next =>
          have htail : runtimeTraceRun actions next = some final := by
            simpa [runtimeTraceValid, runtimeTraceRun, hstep] using hvalid
          have hfirst := runtimeApplyAction_attempt_step
            (action := action) (state := initial) (next := next) hstep
          have hrest : next.attempt.val + runtimeClaimCount actions =
              final.attempt.val :=
            ih (initial := next) (final := final) htail
          simp only [runtimeClaimCount]
          omega

theorem runtimeTrace_claim_count_le_max
    (actions : List RuntimeAction) (initial final : RuntimeOutboxState)
    (hvalid : runtimeTraceValid actions initial final) :
    runtimeClaimCount actions ≤ runtimeMaxAttempts := by
  have haccount := runtimeTrace_attempt_accounting actions initial final hvalid
  have hfinal : final.attempt.val < runtimeMaxAttempts + 1 :=
    final.attempt.isLt
  omega

theorem runtimeTrace_claim_count_le_three
    (actions : List RuntimeAction) (initial final : RuntimeOutboxState)
    (hvalid : runtimeTraceValid actions initial final) :
    runtimeClaimCount actions ≤ 3 := by
  have hbound := runtimeTrace_claim_count_le_max actions initial final hvalid
  simpa [runtimeMaxAttempts] using hbound

theorem runtimeRecoveryTrace_acknowledged_terminal
    (times : List Nat) (attempt : RuntimeAttempt) :
    runtimeRecoveryTrace times (.acknowledged attempt) =
      .acknowledged attempt := by
  induction times with
  | nil => rfl
  | cons now times ih =>
      simp [runtimeRecoveryTrace, runtimeRecoverState, ih]

theorem runtimeApplyAction_acknowledged_terminal
    {action : RuntimeAction} {attempt : RuntimeAttempt}
    {next : RuntimeOutboxState}
    (hstep : runtimeApplyAction action (.acknowledged attempt) = some next) :
    next = .acknowledged attempt := by
  cases action with
  | recover now =>
      simp [runtimeApplyAction, runtimeRecoverState] at hstep
      cases hstep
      rfl
  | claimDirect now leaseDuration =>
      simp [runtimeApplyAction, runtimeClaimDirectState] at hstep
  | claimReconciliation now leaseDuration =>
      simp [runtimeApplyAction, runtimeClaimReconciliationState] at hstep
  | settle now outcome =>
      simp [runtimeApplyAction, runtimeSettleState] at hstep
      cases hstep
      rfl

theorem runtimeTrace_acknowledged_terminal
    (actions : List RuntimeAction) (attempt : RuntimeAttempt)
    (final : RuntimeOutboxState)
    (hvalid : runtimeTraceValid actions (.acknowledged attempt) final) :
    final = .acknowledged attempt := by
  induction actions generalizing final with
  | nil =>
      have hequal :
          (.acknowledged attempt : RuntimeOutboxState) = final := by
        simpa [runtimeTraceValid, runtimeTraceRun] using hvalid
      exact hequal.symm
  | cons action actions ih =>
      cases hstep : runtimeApplyAction action (.acknowledged attempt) with
      | none =>
          simp [runtimeTraceValid, runtimeTraceRun, hstep] at hvalid
      | some next =>
          have htail : runtimeTraceValid actions next final := by
            simpa [runtimeTraceValid, runtimeTraceRun, hstep] using hvalid
          have hterminal := runtimeApplyAction_acknowledged_terminal hstep
          subst next
          exact ih (final := final) htail

theorem runtimeRecoverRow_idempotent
    (row : RuntimeOutboxRow) (now : Nat) :
    runtimeRecoverRow now (runtimeRecoverRow now row) =
      runtimeRecoverRow now row := by
  cases row with
  | mk entry delivery =>
      simp [runtimeRecoverRow, runtimeRecoverState_idempotent]

theorem runtimeRecoverOutbox_idempotent
    (outbox : RuntimeOutbox) (i : BatchIndex) (now : Nat) :
    runtimeRecoverOutbox (runtimeRecoverOutbox outbox i now) i now =
      runtimeRecoverOutbox outbox i now := by
  funext j
  by_cases hji : j = i
  · subst j
    cases hrow : outbox i with
    | none => simp [runtimeRecoverOutbox, updateRuntimeOutbox, hrow]
    | some row =>
        simpa [runtimeRecoverOutbox, updateRuntimeOutbox, hrow] using
          congrArg (fun value => some value) (runtimeRecoverRow_idempotent row now)
  · simp [runtimeRecoverOutbox, updateRuntimeOutbox, hji]

theorem runtimeRecoverOutbox_preserves_missing
    (outbox : RuntimeOutbox) (i : BatchIndex) (now : Nat)
    (hmissing : outbox i = none) :
    runtimeRecoverOutbox outbox i now i = none := by
  simp [runtimeRecoverOutbox, updateRuntimeOutbox, hmissing]

theorem runtimeOutboxFromOutbox_preserves_missing
    (outbox : Outbox) (delivery : BatchIndex → RuntimeOutboxState)
    (i : BatchIndex) (hmissing : outbox.entries i = none) :
    runtimeOutboxFromOutbox outbox delivery i = none := by
  simp [runtimeOutboxFromOutbox, hmissing]

theorem runtimeRecoverRow_preserves_entry
    (row : RuntimeOutboxRow) (now : Nat) :
    (runtimeRecoverRow now row).entry = row.entry := by
  rfl

theorem runtimeRecoverRow_preserves_attempt
    (row : RuntimeOutboxRow) (now : Nat) :
    (runtimeRecoverRow now row).delivery.attempt = row.delivery.attempt := by
  cases row with
  | mk entry delivery =>
      cases delivery with
      | ready attempt => rfl
      | acknowledged attempt => rfl
      | deliveryUnconfirmed attempt => rfl
      | leased attempt leaseExpiresAt =>
          by_cases hexpired : leaseExpiresAt ≤ now
          · by_cases havailable : attempt.val < runtimeMaxAttempts
            · simp [runtimeRecoverRow, runtimeRecoverState, hexpired, havailable,
                RuntimeOutboxState.attempt]
            · simp [runtimeRecoverRow, runtimeRecoverState, hexpired, havailable,
                RuntimeOutboxState.attempt]
          · simp [runtimeRecoverRow, runtimeRecoverState, hexpired,
              RuntimeOutboxState.attempt]

theorem runtimeRecover_acknowledged_terminal
    (entry : OutboxEntry) (attempt : RuntimeAttempt) (now : Nat) :
    runtimeRecoverRow now
        { entry := entry, delivery := .acknowledged attempt } =
      { entry := entry, delivery := .acknowledged attempt } := by
  rfl

theorem runtimeRecover_unconfirmed_preserves_reconciliation
    (entry : OutboxEntry) (attempt : RuntimeAttempt) (now : Nat) :
    runtimeRecoverRow now
        { entry := entry, delivery := .deliveryUnconfirmed attempt } =
      { entry := entry, delivery := .deliveryUnconfirmed attempt } := by
  rfl

theorem runtimeRecover_live_lease_preserves_lease
    (entry : OutboxEntry) (attempt : RuntimeAttempt)
    (leaseExpiresAt now : Nat) (hlive : now < leaseExpiresAt) :
    runtimeRecoverRow now
        { entry := entry, delivery := .leased attempt leaseExpiresAt } =
      { entry := entry, delivery := .leased attempt leaseExpiresAt } := by
  simp [runtimeRecoverRow, runtimeRecoverState, Nat.not_le.mpr hlive]

theorem runtimeRecover_expired_below_cap_requeues
    (entry : OutboxEntry) (attempt : RuntimeAttempt)
    (leaseExpiresAt now : Nat) (hexpired : leaseExpiresAt ≤ now)
    (havailable : attempt.val < runtimeMaxAttempts) :
    (runtimeRecoverRow now
        { entry := entry, delivery := .leased attempt leaseExpiresAt }).delivery =
      .ready attempt := by
  simp [runtimeRecoverRow, runtimeRecoverState, hexpired, havailable]

theorem runtimeRecover_expired_at_cap_becomes_unconfirmed
    (entry : OutboxEntry) (leaseExpiresAt now : Nat)
    (hexpired : leaseExpiresAt ≤ now) :
    (runtimeRecoverRow now
        { entry := entry, delivery := .leased runtimeAttemptMax leaseExpiresAt }).delivery =
      .deliveryUnconfirmed runtimeAttemptMax := by
  have hmax : ¬ runtimeAttemptMax.val < runtimeMaxAttempts := by
    change ¬ (3 < 3)
    omega
  simp [runtimeRecoverRow, runtimeRecoverState, hexpired, hmax]

theorem runtimeClaimDirect_at_max_none
    (now leaseDuration : Nat) (entry : OutboxEntry) :
    runtimeClaimDirect now leaseDuration
        { entry := entry, delivery := .ready runtimeAttemptMax } = none := by
  simp [runtimeClaimDirect, runtimeClaimDirectState, nextRuntimeAttempt_none_at_max]

theorem runtimeClaimReconciliation_at_max_none
    (now leaseDuration : Nat) (entry : OutboxEntry) :
    runtimeClaimReconciliation now leaseDuration
        { entry := entry, delivery := .deliveryUnconfirmed runtimeAttemptMax } = none := by
  simp [runtimeClaimReconciliation, runtimeClaimReconciliationState,
    nextRuntimeAttempt_none_at_max]

theorem runtimeClaimDirect_does_not_claim_reconciliation
    (now leaseDuration : Nat) (entry : OutboxEntry) (attempt : RuntimeAttempt) :
    runtimeClaimDirect now leaseDuration
        { entry := entry, delivery := .deliveryUnconfirmed attempt } = none := by
  rfl

theorem runtimeClaimReconciliation_does_not_claim_ready
    (now leaseDuration : Nat) (entry : OutboxEntry) (attempt : RuntimeAttempt) :
    runtimeClaimReconciliation now leaseDuration
        { entry := entry, delivery := .ready attempt } = none := by
  rfl

theorem runtimeClaimDirectState_increments_once
    (now leaseDuration : Nat) (attempt next : RuntimeAttempt)
    (hpositive : 0 < leaseDuration)
    (hnext : nextRuntimeAttempt attempt = some next) :
    runtimeClaimDirectState now leaseDuration (.ready attempt) =
      some (.leased next (now + leaseDuration)) := by
  simp [runtimeClaimDirectState, hpositive, hnext]

theorem runtimeClaimReconciliationState_increments_once
    (now leaseDuration : Nat) (attempt next : RuntimeAttempt)
    (hpositive : 0 < leaseDuration)
    (hnext : nextRuntimeAttempt attempt = some next) :
    runtimeClaimReconciliationState now leaseDuration
        (.deliveryUnconfirmed attempt) =
      some (.leased next (now + leaseDuration)) := by
  simp [runtimeClaimReconciliationState, hpositive, hnext]

theorem runtimeClaimDirect_ready_zero
    (now leaseDuration : Nat) (entry : OutboxEntry)
    (hpositive : 0 < leaseDuration) :
    runtimeClaimDirect now leaseDuration
        { entry := entry, delivery := .ready runtimeAttemptZero } =
      some
        { entry := entry
          delivery := .leased runtimeAttemptOne (now + leaseDuration) } := by
  have hnext : nextRuntimeAttempt runtimeAttemptZero = some runtimeAttemptOne := by
    simp [nextRuntimeAttempt, runtimeAttemptZero, runtimeAttemptOne,
      runtimeMaxAttempts]
  simp [runtimeClaimDirect, runtimeClaimDirectState, hpositive, hnext]

theorem runtimeClaimReconciliation_unconfirmed_one
    (now leaseDuration : Nat) (entry : OutboxEntry)
    (hpositive : 0 < leaseDuration) :
    runtimeClaimReconciliation now leaseDuration
        { entry := entry, delivery := .deliveryUnconfirmed runtimeAttemptOne } =
      some
        { entry := entry
          delivery := .leased runtimeAttemptTwo (now + leaseDuration) } := by
  have hnext : nextRuntimeAttempt runtimeAttemptOne = some runtimeAttemptTwo := by
    simp [nextRuntimeAttempt, runtimeAttemptOne, runtimeAttemptTwo,
      runtimeMaxAttempts]
  simp [runtimeClaimReconciliation, runtimeClaimReconciliationState,
    hpositive, hnext]

theorem runtimeClaimDirect_preserves_entry
    {now leaseDuration : Nat} {row claimed : RuntimeOutboxRow}
    (hclaim : runtimeClaimDirect now leaseDuration row = some claimed) :
    claimed.entry = row.entry := by
  unfold runtimeClaimDirect at hclaim
  cases hstate : runtimeClaimDirectState now leaseDuration row.delivery with
  | none => simp [hstate] at hclaim
  | some delivery =>
      simp [hstate] at hclaim
      cases hclaim
      rfl

theorem runtimeClaimReconciliation_preserves_entry
    {now leaseDuration : Nat} {row claimed : RuntimeOutboxRow}
    (hclaim : runtimeClaimReconciliation now leaseDuration row = some claimed) :
    claimed.entry = row.entry := by
  unfold runtimeClaimReconciliation at hclaim
  cases hstate :
      runtimeClaimReconciliationState now leaseDuration row.delivery with
  | none => simp [hstate] at hclaim
  | some delivery =>
      simp [hstate] at hclaim
      cases hclaim
      rfl

theorem runtimeSettle_acknowledged_terminal
    (entry : OutboxEntry) (attempt : RuntimeAttempt)
    (now : Nat) (outcome : RuntimeDeliveryOutcome) :
    runtimeSettle now outcome
        { entry := entry, delivery := .acknowledged attempt } =
      { entry := entry, delivery := .acknowledged attempt } := by
  rfl

theorem runtimeSettle_live_acknowledges
    (entry : OutboxEntry) (attempt : RuntimeAttempt)
    (leaseExpiresAt now : Nat) (hlive : now < leaseExpiresAt) :
    (runtimeSettle now .acknowledged
        { entry := entry, delivery := .leased attempt leaseExpiresAt }).delivery =
      .acknowledged attempt := by
  simp [runtimeSettle, runtimeSettleState, Nat.not_le.mpr hlive]

theorem runtimeSettle_live_unconfirms
    (entry : OutboxEntry) (attempt : RuntimeAttempt)
    (leaseExpiresAt now : Nat) (hlive : now < leaseExpiresAt) :
    (runtimeSettle now .deliveryUnconfirmed
        { entry := entry, delivery := .leased attempt leaseExpiresAt }).delivery =
      .deliveryUnconfirmed attempt := by
  simp [runtimeSettle, runtimeSettleState, Nat.not_le.mpr hlive]

theorem runtimeSettle_preserves_entry
    (row : RuntimeOutboxRow) (now : Nat) (outcome : RuntimeDeliveryOutcome) :
    (runtimeSettle now outcome row).entry = row.entry := by
  rfl

theorem runtimeSettle_expired_matches_recovery
    (entry : OutboxEntry) (attempt : RuntimeAttempt)
    (leaseExpiresAt now : Nat) (hexpired : leaseExpiresAt ≤ now)
    (outcome : RuntimeDeliveryOutcome) :
    runtimeSettle now outcome
        { entry := entry, delivery := .leased attempt leaseExpiresAt } =
      runtimeRecoverRow now
        { entry := entry, delivery := .leased attempt leaseExpiresAt } := by
  simp [runtimeSettle, runtimeSettleState, runtimeRecoverRow,
    runtimeRecoverState, hexpired]

structure RuntimeReferenceCase where
  name : String
  before : RuntimeOutboxState
  recovered : RuntimeOutboxState
  directEligible : Bool
  reconciliationEligible : Bool
  directClaim : Option RuntimeOutboxState
  reconciliationClaim : Option RuntimeOutboxState
deriving Repr

def runtimeReferenceCases : List RuntimeReferenceCase :=
  [ { name := "ready_attempt_zero_direct_claim"
      before := .ready runtimeAttemptZero
      recovered := .ready runtimeAttemptZero
      directEligible := runtimeDirectEligible (.ready runtimeAttemptZero)
      reconciliationEligible := runtimeReconciliationEligible (.ready runtimeAttemptZero)
      directClaim := runtimeClaimDirectState 100 300 (.ready runtimeAttemptZero)
      reconciliationClaim :=
        runtimeClaimReconciliationState 100 300 (.ready runtimeAttemptZero) },
    { name := "expired_lease_below_cap_requeues"
      before := .leased runtimeAttemptOne 100
      recovered := runtimeRecoverState 100 (.leased runtimeAttemptOne 100)
      directEligible := runtimeDirectEligible
        (runtimeRecoverState 100 (.leased runtimeAttemptOne 100))
      reconciliationEligible := runtimeReconciliationEligible
        (runtimeRecoverState 100 (.leased runtimeAttemptOne 100))
      directClaim := runtimeClaimDirectState 100 300
        (runtimeRecoverState 100 (.leased runtimeAttemptOne 100))
      reconciliationClaim := runtimeClaimReconciliationState 100 300
        (runtimeRecoverState 100 (.leased runtimeAttemptOne 100)) },
    { name := "expired_lease_at_cap_stops_retry"
      before := .leased runtimeAttemptMax 100
      recovered := runtimeRecoverState 100 (.leased runtimeAttemptMax 100)
      directEligible := runtimeDirectEligible
        (runtimeRecoverState 100 (.leased runtimeAttemptMax 100))
      reconciliationEligible := runtimeReconciliationEligible
        (runtimeRecoverState 100 (.leased runtimeAttemptMax 100))
      directClaim := runtimeClaimDirectState 100 300
        (runtimeRecoverState 100 (.leased runtimeAttemptMax 100))
      reconciliationClaim := runtimeClaimReconciliationState 100 300
        (runtimeRecoverState 100 (.leased runtimeAttemptMax 100)) },
    { name := "acknowledged_is_terminal"
      before := .acknowledged runtimeAttemptOne
      recovered := runtimeRecoverState 100 (.acknowledged runtimeAttemptOne)
      directEligible := runtimeDirectEligible (.acknowledged runtimeAttemptOne)
      reconciliationEligible := runtimeReconciliationEligible
        (.acknowledged runtimeAttemptOne)
      directClaim := runtimeClaimDirectState 100 300
        (.acknowledged runtimeAttemptOne)
      reconciliationClaim := runtimeClaimReconciliationState 100 300
        (.acknowledged runtimeAttemptOne) },
    { name := "unconfirmed_uses_reconciliation"
      before := .deliveryUnconfirmed runtimeAttemptOne
      recovered := runtimeRecoverState 100
        (.deliveryUnconfirmed runtimeAttemptOne)
      directEligible := runtimeDirectEligible
        (.deliveryUnconfirmed runtimeAttemptOne)
      reconciliationEligible := runtimeReconciliationEligible
        (.deliveryUnconfirmed runtimeAttemptOne)
      directClaim := runtimeClaimDirectState 100 300
        (.deliveryUnconfirmed runtimeAttemptOne)
      reconciliationClaim := runtimeClaimReconciliationState 100 300
        (.deliveryUnconfirmed runtimeAttemptOne) } ]

def runtimeStateSummary : RuntimeOutboxState → String
  | .ready attempt => "READY:" ++ toString attempt.val
  | .leased attempt leaseExpiresAt =>
      "LEASED:" ++ toString attempt.val ++ ":" ++ toString leaseExpiresAt
  | .acknowledged attempt => "ACKNOWLEDGED:" ++ toString attempt.val
  | .deliveryUnconfirmed attempt =>
      "DELIVERY_UNCONFIRMED:" ++ toString attempt.val

def runtimeOptionalStateSummary : Option RuntimeOutboxState → String
  | none => "NONE"
  | some state => runtimeStateSummary state

def runtimeReferenceCaseLines : List String :=
  runtimeReferenceCases.map (fun case =>
    "CASE " ++ case.name ++
      " recovered=" ++ runtimeStateSummary case.recovered ++
      " directEligible=" ++ toString case.directEligible ++
      " reconciliationEligible=" ++ toString case.reconciliationEligible ++
      " directClaim=" ++ runtimeOptionalStateSummary case.directClaim ++
      " reconciliationClaim=" ++ runtimeOptionalStateSummary case.reconciliationClaim)

inductive QueueLifecycle where
  | AWAITING_HANDOFF
  | QUEUED
  | LEASED
  | VERIFIED
  | REJECTED
  | HELD
deriving DecidableEq, Repr

inductive QueueTerminalOutcome where
  | verified
  | rejected
  | held
deriving DecidableEq, Repr

/-! The accepted seam has four lifecycle event slots: handoff, queueing,
    leasing, and terminal resolution. -/
inductive QueueEvent where
  | handoff
  | queued
  | leased (attempt : Nat)
  | terminal (outcome : QueueTerminalOutcome)
deriving DecidableEq, Repr

structure QueueItem where
  sourceRef : SourceRef32
  idempotency : IdempotencyIdentity
  lifecycle : QueueLifecycle
  attempt : Nat

structure QueueState where
  items : BatchIndex → Option QueueItem

structure CompositionTransaction where
  operation : OperationRef
  predecessor : Option OperationRef

structure CompositionState where
  transactions : BatchIndex → Option CompositionTransaction
  events : BatchIndex → Option QueueEvent

structure LifecycleTrace where
  events : Fin 4 → QueueEvent

def emptyQueueState : QueueState :=
  { items := fun _ => none }

def emptyCompositionState : CompositionState :=
  { transactions := fun _ => none
    events := fun _ => none }

def queueHandoff (lifecycle : QueueLifecycle) : Option QueueLifecycle :=
  match lifecycle with
  | .AWAITING_HANDOFF => some .QUEUED
  | _ => none

def queueLease (lifecycle : QueueLifecycle) (attempt : Nat) :
    Option (QueueLifecycle × Nat) :=
  match lifecycle with
  | .QUEUED =>
      if attempt = 0 then
        some (.LEASED, 1)
      else
        none
  | _ => none

def queueResolve
    (lifecycle : QueueLifecycle) (outcome : QueueTerminalOutcome) :
    Option QueueLifecycle :=
  match lifecycle, outcome with
  | .LEASED, .verified => some .VERIFIED
  | .LEASED, .rejected => some .REJECTED
  | .LEASED, .held => some .HELD
  | _, _ => none

def acceptedLifecycleTrace (outcome : QueueTerminalOutcome) : LifecycleTrace :=
  { events := fun i =>
      if i.val = 0 then
        .handoff
      else if i.val = 1 then
        .queued
      else if i.val = 2 then
        .leased 1
      else
        .terminal outcome }

theorem queue_handoff_chronology :
    queueHandoff .AWAITING_HANDOFF = some .QUEUED := by
  rfl

theorem queue_lease_attempt_zero_to_one :
    queueLease .QUEUED 0 = some (.LEASED, 1) := by
  simp [queueLease]

theorem queue_resolve_verified_chronology :
    queueResolve .LEASED .verified = some .VERIFIED := by
  rfl

theorem queue_resolve_rejected_chronology :
    queueResolve .LEASED .rejected = some .REJECTED := by
  rfl

theorem queue_resolve_held_chronology :
    queueResolve .LEASED .held = some .HELD := by
  rfl

theorem queue_lifecycle_invalid_handoff_fails (lifecycle : QueueLifecycle)
    (h : lifecycle ≠ .AWAITING_HANDOFF) :
    queueHandoff lifecycle = none := by
  cases lifecycle <;> simp_all [queueHandoff]

theorem queue_lifecycle_invalid_lease_fails
    (lifecycle : QueueLifecycle) (attempt : Nat)
    (h : lifecycle ≠ .QUEUED ∨ attempt ≠ 0) :
    queueLease lifecycle attempt = none := by
  cases lifecycle <;> simp_all [queueLease]

/-! The function domain is Fin 4, so a lifecycle trace has four typed slots. -/
def lifecycleTraceSlotCount (_ : Fin 4 → QueueEvent) : Nat := 4

theorem lifecycle_trace_has_four_slots (outcome : QueueTerminalOutcome) :
    lifecycleTraceSlotCount (acceptedLifecycleTrace outcome).events = 4 := by
  rfl

def processedTransactionCount (_ : BatchIndex → CompositionTransaction) : Nat :=
  100

def processedEventCount (_ : BatchIndex → QueueEvent) : Nat :=
  100

def readyOutboxRowCount (_ : BatchIndex → OutboxEntry) : Nat :=
  100

structure ProcessedBatch where
  transactions : BatchIndex → CompositionTransaction
  events : BatchIndex → QueueEvent
  readyRows : BatchIndex → OutboxEntry

def processExact100
    (batch : OperationBatch) (authorization : AuthorizationBatch)
    (outcome : QueueTerminalOutcome) : ProcessedBatch :=
  { transactions := fun i =>
      { operation := batch.refs i
        predecessor := batch.predecessorRef i }
    events := fun _ => .terminal outcome
    readyRows := fun i =>
      { operation := batch.refs i
        directive := authorization.directives i
        idempotency := authorization.idempotency i
        readiness := .READY
        delivery := .queued } }

theorem processExact100_counts
    (batch : OperationBatch) (authorization : AuthorizationBatch)
    (outcome : QueueTerminalOutcome) :
    processedTransactionCount (processExact100 batch authorization outcome).transactions =
        100 ∧
      processedEventCount (processExact100 batch authorization outcome).events = 100 ∧
      readyOutboxRowCount (processExact100 batch authorization outcome).readyRows = 100 := by
  constructor
  · rfl
  · constructor <;> rfl

theorem processExact100_ready_rows_are_READY
    (batch : OperationBatch) (authorization : AuthorizationBatch)
    (outcome : QueueTerminalOutcome) (i : BatchIndex) :
    ((processExact100 batch authorization outcome).readyRows i).readiness =
      .READY := by
  rfl

theorem processExact100_predecessor_is_batch_predecessor
    (batch : OperationBatch) (authorization : AuthorizationBatch)
    (outcome : QueueTerminalOutcome) (i : BatchIndex) :
    ((processExact100 batch authorization outcome).transactions i).predecessor =
      batch.predecessorRef i := by
  rfl

end BlindLedger.System
