import BlindLedger.System.Queue

namespace BlindLedger.System

/-! This is the exact-100-row pure batch boundary. It is deliberately
    separate from the older `processExact100` shape witness below: every
    counter here is computed by enumerating the supplied `RuntimeOutbox`, and
    every work/result mask is indexed by the actual `Fin 100` rows. -/

def runtimeBatchIndices : List BatchIndex :=
  List.ofFn (fun i : BatchIndex => i)

def runtimeCountOptions
    (predicate : RuntimeOutboxRow → Bool) :
    List (Option RuntimeOutboxRow) → Nat
  | [] => 0
  | none :: rows => runtimeCountOptions predicate rows
  | some row :: rows =>
      (if predicate row = true then 1 else 0) +
        runtimeCountOptions predicate rows

def runtimeCountPresent : List (Option RuntimeOutboxRow) → Nat
  | [] => 0
  | none :: rows => runtimeCountPresent rows
  | some _ :: rows => 1 + runtimeCountPresent rows

def runtimeBatchOptions (outbox : RuntimeOutbox) :
    List (Option RuntimeOutboxRow) :=
  List.ofFn (fun i : BatchIndex => outbox i)

def runtimeBatchStateVector (outbox : RuntimeOutbox) :
    List (Option RuntimeOutboxState) :=
  (runtimeBatchOptions outbox).map (Option.map RuntimeOutboxRow.delivery)

def runtimeBatchSyntheticByte (i : BatchIndex) (j : Fin 32) : Byte :=
  ⟨(i.val + j.val) % 256, Nat.mod_lt _ (by decide)⟩

def runtimeBatchSyntheticSourceRef (i : BatchIndex) : SourceRef32 :=
  { bytes := runtimeBatchSyntheticByte i }

def runtimeBatchSyntheticIdempotency (i : BatchIndex) : IdempotencyIdentity :=
  { bytes := runtimeBatchSyntheticByte i }

def runtimeBatchSyntheticEntry (i : BatchIndex) : OutboxEntry :=
  { operation := runtimeBatchSyntheticSourceRef i
    directive := .CLEAR
    idempotency := runtimeBatchSyntheticIdempotency i
    readiness := .READY
    delivery := .queued }

def runtimeBatchListAt {α : Type} : List α → Nat → Option α
  | [], _ => none
  | value :: _, 0 => some value
  | _ :: values, index + 1 => runtimeBatchListAt values index

def runtimeBatchWireOutbox
    (states : List (Option RuntimeOutboxState)) : RuntimeOutbox :=
  fun i =>
    (runtimeBatchListAt states i.val).bind (fun maybeDelivery =>
      maybeDelivery.bind (fun delivery =>
        some { entry := runtimeBatchSyntheticEntry i, delivery := delivery }))

def runtimeRowHasStatus
    (status : RuntimeOutboxStatus) (row : RuntimeOutboxRow) : Bool :=
  decide (row.delivery.status = status)

def runtimeBatchPresentCount (outbox : RuntimeOutbox) : Nat :=
  runtimeCountPresent (runtimeBatchOptions outbox)

def runtimeBatchStatusCount
    (outbox : RuntimeOutbox) (status : RuntimeOutboxStatus) : Nat :=
  runtimeCountOptions (runtimeRowHasStatus status)
    (runtimeBatchOptions outbox)

def runtimeBatchDirectEligibleCount (outbox : RuntimeOutbox) : Nat :=
  runtimeCountOptions
    (fun row => runtimeDirectEligible row.delivery)
    (runtimeBatchOptions outbox)

def runtimeBatchReconciliationEligibleCount
    (outbox : RuntimeOutbox) : Nat :=
  runtimeCountOptions
    (fun row => runtimeReconciliationEligible row.delivery)
    (runtimeBatchOptions outbox)

structure RuntimeBatchSummary where
  present : Nat
  ready : Nat
  leased : Nat
  acknowledged : Nat
  deliveryUnconfirmed : Nat
  directEligible : Nat
  reconciliationEligible : Nat
deriving DecidableEq, Repr

def runtimeBatchSummary (outbox : RuntimeOutbox) : RuntimeBatchSummary :=
  { present := runtimeBatchPresentCount outbox
    ready := runtimeBatchStatusCount outbox .READY
    leased := runtimeBatchStatusCount outbox .LEASED
    acknowledged := runtimeBatchStatusCount outbox .ACKNOWLEDGED
    deliveryUnconfirmed := runtimeBatchStatusCount outbox .DELIVERY_UNCONFIRMED
    directEligible := runtimeBatchDirectEligibleCount outbox
    reconciliationEligible := runtimeBatchReconciliationEligibleCount outbox }

def runtimeBatchHasReady (outbox : RuntimeOutbox) : Bool :=
  decide (runtimeBatchStatusCount outbox .READY > 0)

def runtimeBatchHasReconciliationEligible
    (outbox : RuntimeOutbox) : Bool :=
  decide (runtimeBatchReconciliationEligibleCount outbox > 0)

inductive RuntimeBatchOperation where
  | direct
  | reconciliation
deriving DecidableEq, Repr

def RuntimeBatchOperation.label : RuntimeBatchOperation → String
  | .direct => "DIRECT_DELIVERY"
  | .reconciliation => "RECONCILIATION"

/-! A work record retains the exact entry and lease identity for each row it
    claimed. The entry contains both the operation reference and the stable
    idempotency identity, so settlement cannot substitute a different row. -/
structure RuntimeBatchWork where
  operation : RuntimeBatchOperation
  claimed : BatchIndex → Bool
  entries : BatchIndex → Option OutboxEntry
  attempts : BatchIndex → Option RuntimeAttempt
  leaseExpiresAt : BatchIndex → Option Nat
  hasMore : Bool

/-! Equality of the opaque function-backed identifiers is not used directly in
    executable guards. This finite binding contains the exact operation and
    idempotency bytes plus the directive, and therefore has a computable
    equality while retaining the work's identity contract. -/
structure RuntimeBatchEntryBinding where
  operation : List Byte
  directive : EffectiveDirective
  idempotency : List Byte
deriving DecidableEq, Repr

def runtimeBatchEntryBinding (entry : OutboxEntry) : RuntimeBatchEntryBinding :=
  { operation := List.ofFn entry.operation.bytes
    directive := entry.directive
    idempotency := List.ofFn entry.idempotency.bytes }

inductive RuntimeBatchLastResult where
  | none
  | claim
      (operation : RuntimeBatchOperation)
      (claimed : BatchIndex → Bool)
      (hasMore : Bool)
  | settle
      (operation : RuntimeBatchOperation)
      (statuses : BatchIndex → Option RuntimeDeliveryOutcome)
      (hasMore : Bool)

structure RuntimeBatchMachine where
  outbox : RuntimeOutbox
  pending : Option RuntimeBatchWork
  lastResult : RuntimeBatchLastResult

def runtimeBatchInitial (outbox : RuntimeOutbox) : RuntimeBatchMachine :=
  { outbox := outbox, pending := none, lastResult := .none }

def runtimeBatchRecover (now : Nat) (outbox : RuntimeOutbox) : RuntimeOutbox :=
  fun i => (outbox i).map (runtimeRecoverRow now)

def runtimeBatchClaimMask
    (operation : RuntimeBatchOperation) (outbox : RuntimeOutbox) :
    BatchIndex → Bool :=
  fun i =>
    match outbox i with
    | none => false
    | some row =>
        match operation with
        | .direct => runtimeDirectEligible row.delivery
        | .reconciliation => runtimeReconciliationEligible row.delivery

def runtimeMaskCount (mask : BatchIndex → Bool) : List BatchIndex → Nat
  | [] => 0
  | index :: indices =>
      (if mask index = true then 1 else 0) + runtimeMaskCount mask indices

def runtimeBatchMaskCount (mask : BatchIndex → Bool) : Nat :=
  runtimeMaskCount mask runtimeBatchIndices

def runtimeBatchClaimedState
    (operation : RuntimeBatchOperation)
    (now leaseDuration : Nat)
    (outbox : RuntimeOutbox) (i : BatchIndex) :
    Option RuntimeOutboxState :=
  match outbox i with
  | none => none
  | some row =>
      match operation with
      | .direct => runtimeClaimDirectState now leaseDuration row.delivery
      | .reconciliation =>
          runtimeClaimReconciliationState now leaseDuration row.delivery

def runtimeBatchClaimedEntries
    (mask : BatchIndex → Bool) (outbox : RuntimeOutbox) :
    BatchIndex → Option OutboxEntry :=
  fun i =>
    if mask i = true then
      (outbox i).map RuntimeOutboxRow.entry
    else
      none

def runtimeBatchClaimedAttempts
    (operation : RuntimeBatchOperation)
    (now leaseDuration : Nat)
    (outbox : RuntimeOutbox) :
    BatchIndex → Option RuntimeAttempt :=
  fun i =>
    (runtimeBatchClaimedState operation now leaseDuration outbox i).map
      RuntimeOutboxState.attempt

def runtimeBatchClaimedExpiries
    (operation : RuntimeBatchOperation)
    (now leaseDuration : Nat)
    (outbox : RuntimeOutbox) :
    BatchIndex → Option Nat :=
  fun i =>
    match runtimeBatchClaimedState operation now leaseDuration outbox i with
    | some (.leased _ expiresAt) => some expiresAt
    | _ => none

structure RuntimeBatchClaim where
  outbox : RuntimeOutbox
  work : RuntimeBatchWork
  hasMore : Bool

def runtimeBatchClaimOutbox
    (operation : RuntimeBatchOperation)
    (now leaseDuration : Nat)
    (outbox : RuntimeOutbox) :
    Option RuntimeBatchClaim :=
  let mask := runtimeBatchClaimMask operation outbox
  if leaseDuration = 0 || runtimeBatchMaskCount mask = 0 then
    none
  else
    let nextOutbox : RuntimeOutbox := fun i =>
      match outbox i with
      | none => none
      | some row =>
          if mask i = true then
            (runtimeBatchClaimedState operation now leaseDuration outbox i).map
              (fun delivery => { row with delivery := delivery })
          else
            some row
    let work : RuntimeBatchWork :=
      { operation := operation
        claimed := mask
        entries := runtimeBatchClaimedEntries mask outbox
        attempts := runtimeBatchClaimedAttempts operation now leaseDuration outbox
        leaseExpiresAt :=
          runtimeBatchClaimedExpiries operation now leaseDuration outbox
        hasMore :=
          match operation with
          | .direct => runtimeBatchHasReady nextOutbox
          | .reconciliation =>
              runtimeBatchHasReconciliationEligible nextOutbox }
    some
      { outbox := nextOutbox
        work := work
        hasMore := work.hasMore }

def runtimeStateLeaseExpiry : RuntimeOutboxState → Option Nat
  | .leased _ expiresAt => some expiresAt
  | _ => none

def runtimeBatchWorkLive
    (work : RuntimeBatchWork) (now : Nat)
    (outbox : RuntimeOutbox) (i : BatchIndex) : Bool :=
  match work.entries i, work.attempts i, work.leaseExpiresAt i, outbox i with
  | some expectedEntry, some expectedAttempt, some expectedExpiry, some row =>
      match row.delivery with
      | .leased attempt expiry =>
          decide (runtimeBatchEntryBinding row.entry =
              runtimeBatchEntryBinding expectedEntry ∧
            attempt = expectedAttempt ∧ expiry = expectedExpiry ∧ now < expiry)
      | _ => false
  | _, _, _, _ => false

def runtimeBatchSettleStatuses
    (work : RuntimeBatchWork) (now : Nat)
    (outbox : RuntimeOutbox)
    (outcomes : BatchIndex → RuntimeDeliveryOutcome) :
    BatchIndex → Option RuntimeDeliveryOutcome :=
  fun i =>
    if work.claimed i = true then
      if runtimeBatchWorkLive work now outbox i then
        some (outcomes i)
      else
        some .deliveryUnconfirmed
    else
      none

def runtimeBatchSettleOutbox
    (work : RuntimeBatchWork) (now : Nat)
    (outbox : RuntimeOutbox)
    (outcomes : BatchIndex → RuntimeDeliveryOutcome) : RuntimeOutbox :=
  fun i =>
    match outbox i with
    | none => none
    | some row =>
        if work.claimed i = true ∧ runtimeBatchWorkLive work now outbox i = true then
          some (runtimeSettle now (outcomes i) row)
        else
          some row

inductive RuntimeBatchAction where
  | recover (now : Nat)
  | claimDirect (now leaseDuration : Nat)
  | claimReconciliation (now leaseDuration : Nat)
  | settle (now : Nat) (outcomes : BatchIndex → RuntimeDeliveryOutcome)

def runtimeBatchApplyAction :
    RuntimeBatchAction → RuntimeBatchMachine → Option RuntimeBatchMachine
  | .recover now, machine =>
      some
        { outbox := runtimeBatchRecover now machine.outbox
          pending := machine.pending
          lastResult := .none }
  | .claimDirect now leaseDuration, machine =>
      match runtimeBatchClaimOutbox .direct now leaseDuration
          (runtimeBatchRecover now machine.outbox) with
      | none => none
      | some claim =>
          some
            { outbox := claim.outbox
              pending := some claim.work
              lastResult :=
                .claim .direct claim.work.claimed claim.hasMore }
  | .claimReconciliation now leaseDuration, machine =>
      match runtimeBatchClaimOutbox .reconciliation now leaseDuration
          (runtimeBatchRecover now machine.outbox) with
      | none => none
      | some claim =>
          some
            { outbox := claim.outbox
              pending := some claim.work
              lastResult :=
                .claim .reconciliation claim.work.claimed claim.hasMore }
  | .settle now outcomes, machine =>
      let recovered := runtimeBatchRecover now machine.outbox
      match machine.pending with
      | none =>
          some
            { outbox := recovered
              pending := none
              lastResult :=
                .settle .direct (fun _ => none) false }
      | some work =>
          let statuses := runtimeBatchSettleStatuses work now recovered outcomes
          let settled := runtimeBatchSettleOutbox work now recovered outcomes
           let hasMoreAfter :=
             match work.operation with
             | .direct => runtimeBatchHasReady settled
             | .reconciliation =>
                 runtimeBatchHasReconciliationEligible settled
          some
             { outbox := settled
               pending := none
               lastResult := .settle work.operation statuses
                 (work.hasMore || hasMoreAfter) }

def runtimeBatchTraceRun :
    List RuntimeBatchAction → RuntimeBatchMachine →
      Option RuntimeBatchMachine
  | [], machine => some machine
  | action :: actions, machine =>
      (runtimeBatchApplyAction action machine).bind
        (runtimeBatchTraceRun actions)

def runtimeBatchEntriesPreserved
    (before after : RuntimeOutbox) : Prop :=
  ∀ i rowBefore rowAfter,
    before i = some rowBefore →
    after i = some rowAfter →
    rowAfter.entry = rowBefore.entry

theorem runtimeBatchRecover_preserves_entries
    (outbox : RuntimeOutbox) (now : Nat) :
    runtimeBatchEntriesPreserved outbox (runtimeBatchRecover now outbox) := by
  intro i rowBefore rowAfter hbefore hafter
  simp [runtimeBatchRecover] at hafter
  rcases hafter with ⟨row, hrow, hrecover⟩
  have hsame : row = rowBefore := Option.some.inj (hrow.symm.trans hbefore)
  subst row
  have hentry := congrArg RuntimeOutboxRow.entry hrecover
  simpa [runtimeRecoverRow] using hentry.symm

theorem runtimeBatchClaim_work_entries
    {operation : RuntimeBatchOperation} {now leaseDuration : Nat}
    {outbox : RuntimeOutbox} {claim : RuntimeBatchClaim}
    (hclaim : runtimeBatchClaimOutbox operation now leaseDuration outbox =
      some claim) (i : BatchIndex)
    (hclaimed : claim.work.claimed i = true) :
    claim.work.entries i = (outbox i).map RuntimeOutboxRow.entry := by
  cases operation with
  | direct =>
      simp [runtimeBatchClaimOutbox] at hclaim
      rcases hclaim with ⟨_, hclaim⟩
      cases hclaim
      dsimp at hclaimed
      change runtimeBatchClaimedEntries
        (runtimeBatchClaimMask .direct outbox) outbox i = _
      simp [runtimeBatchClaimedEntries, hclaimed]
  | reconciliation =>
      simp [runtimeBatchClaimOutbox] at hclaim
      rcases hclaim with ⟨_, hclaim⟩
      cases hclaim
      dsimp at hclaimed
      change runtimeBatchClaimedEntries
        (runtimeBatchClaimMask .reconciliation outbox) outbox i = _
      simp [runtimeBatchClaimedEntries, hclaimed]

theorem runtimeBatchClaim_preserves_unclaimed_entries
    {operation : RuntimeBatchOperation} {now leaseDuration : Nat}
    {outbox : RuntimeOutbox} {claim : RuntimeBatchClaim}
    (hclaim : runtimeBatchClaimOutbox operation now leaseDuration outbox =
      some claim) (i : BatchIndex)
    (hunclaimed : claim.work.claimed i = false) :
    claim.outbox i = outbox i := by
  cases operation with
  | direct =>
      simp [runtimeBatchClaimOutbox] at hclaim
      rcases hclaim with ⟨_, hclaim⟩
      cases hclaim
      dsimp at hunclaimed
      have hmask : runtimeBatchClaimMask .direct outbox i = false := by
        simpa using hunclaimed
      cases hrow : outbox i with
      | none => simp [hrow]
      | some row =>
          have hfalse : runtimeDirectEligible row.delivery = false := by
            simpa [runtimeBatchClaimMask, hrow] using hmask
          simp [hrow, hfalse, runtimeBatchClaimMask]
  | reconciliation =>
      simp [runtimeBatchClaimOutbox] at hclaim
      rcases hclaim with ⟨_, hclaim⟩
      cases hclaim
      dsimp at hunclaimed
      have hmask : runtimeBatchClaimMask .reconciliation outbox i = false := by
        simpa using hunclaimed
      cases hrow : outbox i with
      | none => simp [hrow]
      | some row =>
          have hfalse : runtimeReconciliationEligible row.delivery = false := by
            simpa [runtimeBatchClaimMask, hrow] using hmask
          simp [hrow, hfalse, runtimeBatchClaimMask]

theorem runtimeBatchSettleStatuses_not_live_unconfirmed
    {work : RuntimeBatchWork} {now : Nat}
    {outbox : RuntimeOutbox}
    {outcomes : BatchIndex → RuntimeDeliveryOutcome} {i : BatchIndex}
    (hclaimed : work.claimed i = true)
    (hnotlive : runtimeBatchWorkLive work now outbox i = false) :
    runtimeBatchSettleStatuses work now outbox outcomes i =
      some .deliveryUnconfirmed := by
  simp [runtimeBatchSettleStatuses, hclaimed, hnotlive]

theorem runtimeBatchSettleStatuses_live_agrees
    {work : RuntimeBatchWork} {now : Nat}
    {outbox : RuntimeOutbox}
    {outcomes : BatchIndex → RuntimeDeliveryOutcome} {i : BatchIndex}
    (hclaimed : work.claimed i = true)
    (hlive : runtimeBatchWorkLive work now outbox i = true) :
    runtimeBatchSettleStatuses work now outbox outcomes i =
      some (outcomes i) := by
  simp [runtimeBatchSettleStatuses, hclaimed, hlive]

theorem runtimeBatchSettleOutbox_not_live_preserves
    (work : RuntimeBatchWork) (now : Nat) (outbox : RuntimeOutbox)
    (outcomes : BatchIndex → RuntimeDeliveryOutcome) (i : BatchIndex)
    (hnotlive : runtimeBatchWorkLive work now outbox i = false) :
    runtimeBatchSettleOutbox work now outbox outcomes i = outbox i := by
  cases hrow : outbox i with
  | none => simp [runtimeBatchSettleOutbox, hrow]
  | some row => simp [runtimeBatchSettleOutbox, hrow, hnotlive]

theorem runtimeBatchSettleOutbox_live_applies
    {work : RuntimeBatchWork} {now : Nat}
    {outbox : RuntimeOutbox}
    {outcomes : BatchIndex → RuntimeDeliveryOutcome} {i : BatchIndex}
    {row : RuntimeOutboxRow}
    (hrow : outbox i = some row)
    (hclaimed : work.claimed i = true)
    (hlive : runtimeBatchWorkLive work now outbox i = true) :
    runtimeBatchSettleOutbox work now outbox outcomes i =
      some (runtimeSettle now (outcomes i) row) := by
  simp [runtimeBatchSettleOutbox, hrow, hclaimed, hlive]

theorem runtimeBatchWorkLive_rejects_mismatched_entry
    {work : RuntimeBatchWork} {now : Nat}
    {outbox : RuntimeOutbox} {i : BatchIndex}
    {expectedEntry row : OutboxEntry}
    {expectedAttempt : RuntimeAttempt} {expectedExpiry : Nat}
    {attempt : RuntimeAttempt} {expiry : Nat}
    (hentries : work.entries i = some expectedEntry)
    (hattempts : work.attempts i = some expectedAttempt)
    (hexpiries : work.leaseExpiresAt i = some expectedExpiry)
    (hrow : outbox i = some
      { entry := row, delivery := .leased attempt expiry })
    (hmismatch : runtimeBatchEntryBinding row ≠
      runtimeBatchEntryBinding expectedEntry) :
    runtimeBatchWorkLive work now outbox i = false := by
  simp [runtimeBatchWorkLive, hentries, hattempts, hexpiries, hrow, hmismatch]

def runtimeBatchStaleWorkFixture : RuntimeBatchWork :=
  { operation := .direct
    claimed := fun i => decide (i.val = 0)
    entries := fun i =>
      if i.val = 0 then some (runtimeBatchSyntheticEntry i) else none
    attempts := fun i => if i.val = 0 then some runtimeAttemptOne else none
    leaseExpiresAt := fun i => if i.val = 0 then some 400 else none
    hasMore := false }

def runtimeBatchStaleCurrentFixture : RuntimeOutbox := fun i =>
  if i.val = 0 then
    some { entry := runtimeBatchSyntheticEntry i
           delivery := .leased runtimeAttemptTwo 700 }
  else
    none

def runtimeBatchAcknowledgedOutcomes : BatchIndex → RuntimeDeliveryOutcome :=
  fun _ => .acknowledged

theorem runtimeBatch_stale_lease_fence_regression :
    runtimeBatchWorkLive runtimeBatchStaleWorkFixture 401
        runtimeBatchStaleCurrentFixture firstBatchIndex = false ∧
    runtimeBatchSettleStatuses runtimeBatchStaleWorkFixture 401
        runtimeBatchStaleCurrentFixture runtimeBatchAcknowledgedOutcomes
        firstBatchIndex = some .deliveryUnconfirmed ∧
    runtimeBatchSettleOutbox runtimeBatchStaleWorkFixture 401
        runtimeBatchStaleCurrentFixture runtimeBatchAcknowledgedOutcomes
        firstBatchIndex =
      some { entry := runtimeBatchSyntheticEntry firstBatchIndex
             delivery := .leased runtimeAttemptTwo 700 } := by
  simp [runtimeBatchStaleWorkFixture, runtimeBatchStaleCurrentFixture,
    runtimeBatchWorkLive,
    runtimeBatchSettleStatuses, runtimeBatchSettleOutbox, firstBatchIndex,
    runtimeBatchEntryBinding]

end BlindLedger.System
