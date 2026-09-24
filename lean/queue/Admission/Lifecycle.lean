import Admission.Model

namespace BlindLedger.Admission

/-
  This file is the pure seam for the two Queue transitions which are still
  Python-owned: submit_batch_handoff and _claim_next_batch.  List UInt8 fields
  are the already-canonicalized wire values from the Queue rows; the host
  converts Queue bytes at this boundary.  This kernel checks their binding
  shape and preserves them, but does not perform hashing, SQLite locking, RNG,
  or process cleanup.

  The 3-second value is the Python-owned Lean admission subprocess timeout.
  The Queue lease itself is the current 60-second _LEASE_MS value.
-/

abbrev LifecycleBytes := List UInt8

def lifecycleSchemaVersion : Nat := 13
def lifecycleProfileVersion : Nat := 12
def lifecycleProfileToken : String := "BLIND-DIRECT-MASK-FAEST256F-DEG3-V1"
def lifecycleSourceAuthProfile : String := "BLIND-MLDSA87-SOURCE-AUTH-DIRECT-MASK-V1-UNQUALIFIED"
def lifecycleCompositionVersion : Nat := 4
def lifecycleMemberCount : Nat := 100
def lifecycleProofAttemptsPerBatch : Nat := 101
def lifecycleProofAttemptsCap : Nat := counterMax
def lifecycleMaxAttempts : Nat := 1
def lifecycleLeanAdmissionTimeoutMs : Nat := 3_000
def lifecycleLeaseDurationMs : Nat := 60_000
def lifecycleMaxValidityWindowMs : Nat := 3_600_000
def lifecycleSourceAdmissionAUpper : Nat := 1
def lifecycleSourceAdmissionSUpper : Nat := 4_096
def lifecycleSourceAdmissionMUpper : Nat := lifecycleMemberCount
def lifecycleSourceAdmissionUUpper : Nat := 1
def lifecycleVerifierLaunchVUpper : Nat := 1

/-
  The five values above are the per-operation charges/upper bounds.  They are
  not the caps of the durable metadata counters.  Queue passes the one global
  proof-attempt cap to every counter when it invokes the Lean adapter; the
  counters below therefore model cumulative metadata, not one operation.
-/

def byteLength (value : LifecycleBytes) (expected : Nat) : Prop :=
  value.length = expected

def hasNonzeroByte (value : LifecycleBytes) : Prop :=
  value.any (fun item => item != 0) = true

structure LifecycleConfig where
  schemaVersion : Nat
  profileEpoch : Nat
  profileToken : String
  sourceAuthProfile : String
  compositionVersion : Nat
  sourceKeyEpoch : Nat
  admissionTimeoutMs : Nat
  leaseDurationMs : Nat
  queueId : String
  configDigest : LifecycleBytes
  deriving DecidableEq

def LifecycleConfig.WellFormed (config : LifecycleConfig) : Prop :=
  config.schemaVersion = lifecycleSchemaVersion ∧
    config.profileEpoch = lifecycleProfileVersion ∧
    config.profileToken = lifecycleProfileToken ∧
    config.sourceAuthProfile = lifecycleSourceAuthProfile ∧
    config.compositionVersion = lifecycleCompositionVersion ∧
    config.sourceKeyEpoch > 0 ∧
    config.admissionTimeoutMs = lifecycleLeanAdmissionTimeoutMs ∧
    config.leaseDurationMs = lifecycleLeaseDurationMs ∧
    config.sourceKeyEpoch ≤ wireNatMax ∧
    config.queueId.length > 0 ∧
    config.queueId.length ≤ 96 ∧
    byteLength config.configDigest 64

instance lifecycleConfigWellFormedDecidable (config : LifecycleConfig) :
    Decidable (config.WellFormed) := by
  unfold LifecycleConfig.WellFormed byteLength
  infer_instance

structure LifecycleIdentity where
  batchId : LifecycleBytes
  batchRoot : LifecycleBytes
  sessionRef : LifecycleBytes
  publicCoin : LifecycleBytes
  proofContext : LifecycleBytes
  identityDigest : LifecycleBytes
  assertionIdentifier : String
  assertionVersion : Nat
  stateProfileVersion : String
  approvedSourceRegistryRoot : Option LifecycleBytes
  qualificationFlags : LifecycleBytes
  memberCount : Nat
  admissionSeq : Nat
  deriving DecidableEq

def optionalRegistryRootWellFormed : Option LifecycleBytes → Prop
  | none => True
  | some root => byteLength root 64

def lifecycleTokenWellFormed (value : String) : Prop :=
  value.length > 0 ∧ value.length ≤ 96

def LifecycleIdentity.WellFormed (identity : LifecycleIdentity) : Prop :=
  byteLength identity.batchId 32 ∧
    byteLength identity.batchRoot 64 ∧
    byteLength identity.sessionRef 64 ∧
    byteLength identity.publicCoin 96 ∧
    hasNonzeroByte identity.publicCoin ∧
    byteLength identity.proofContext 64 ∧
    byteLength identity.identityDigest 64 ∧
    lifecycleTokenWellFormed identity.assertionIdentifier ∧
    identity.assertionVersion > 0 ∧
    identity.assertionVersion ≤ 2 ^ 31 ∧
    identity.stateProfileVersion = lifecycleProfileToken ∧
    optionalRegistryRootWellFormed identity.approvedSourceRegistryRoot ∧
    identity.qualificationFlags.length > 0 ∧
    identity.memberCount = lifecycleMemberCount ∧
    identity.admissionSeq > 0 ∧
    identity.admissionSeq ≤ wireNatMax

instance optionalRegistryRootWellFormedDecidable
    (root : Option LifecycleBytes) : Decidable (optionalRegistryRootWellFormed root) := by
  cases root with
  | none => exact isTrue trivial
  | some root =>
      unfold optionalRegistryRootWellFormed byteLength
      infer_instance

instance lifecycleIdentityWellFormedDecidable (identity : LifecycleIdentity) :
    Decidable (identity.WellFormed) := by
  unfold LifecycleIdentity.WellFormed byteLength lifecycleTokenWellFormed hasNonzeroByte
  infer_instance

structure LifecycleCounter where
  used : Nat
  cap : Nat
  deriving DecidableEq

def LifecycleCounter.WellFormed (counter : LifecycleCounter) : Prop :=
  counter.used ≤ counter.cap ∧ counter.cap ≤ counterMax

structure LifecycleAccounting where
  proof : LifecycleCounter
  sourceA : LifecycleCounter
  sourceS : LifecycleCounter
  sourceM : LifecycleCounter
  sourceU : LifecycleCounter
  verifierV : LifecycleCounter
  deriving DecidableEq

def LifecycleAccounting.WellFormed (accounting : LifecycleAccounting) : Prop :=
  accounting.proof.WellFormed ∧
    accounting.sourceA.WellFormed ∧
    accounting.sourceS.WellFormed ∧
    accounting.sourceM.WellFormed ∧
    accounting.sourceU.WellFormed ∧
    accounting.verifierV.WellFormed ∧
    accounting.proof.cap = lifecycleProofAttemptsCap ∧
    accounting.sourceA.cap = lifecycleProofAttemptsCap ∧
    accounting.sourceS.cap = lifecycleProofAttemptsCap ∧
    accounting.sourceM.cap = lifecycleProofAttemptsCap ∧
    accounting.sourceU.cap = lifecycleProofAttemptsCap ∧
    accounting.verifierV.cap = lifecycleProofAttemptsCap

instance lifecycleAccountingWellFormedDecidable (accounting : LifecycleAccounting) :
    Decidable (accounting.WellFormed) := by
  unfold LifecycleAccounting.WellFormed LifecycleCounter.WellFormed
  infer_instance

inductive LifecycleAttemptStatus
  | reserved
  | accepted
  | rejected
  | held
  deriving DecidableEq, Repr

structure LifecycleState where
  config : LifecycleConfig
  identity : LifecycleIdentity
  batch : BatchPhase
  source : SourcePhase
  verifier : VerifierPhase
  terminal : TerminalKind
  validFromMs : Nat
  validUntilMs : Nat
  nextEligibleMs : Nat
  updatedMs : Nat
  attempt : Nat
  attemptId : Nat
  attemptStatus : LifecycleAttemptStatus
  verifierVUpper : Nat
  /- Queue metadata: at most one live lease across all batches. -/
  globalLiveLeaseCount : Nat
  /- Selected-batch lease shape; this can be zero while another batch is leased. -/
  liveLeaseCount : Nat
  leaseExpiresMs : Nat
  claimSequence : Nat
  transitionSequence : Nat
  reservationBefore : Nat
  reservationAfter : Nat
  proofAttemptsPerBatch : Nat
  attemptSourceKeyEpoch : Nat
  handoffAttached : Bool
  accounting : LifecycleAccounting
  deriving DecidableEq

def lifecyclePhaseWellFormed (state : LifecycleState) : Prop :=
  (state.batch = .awaiting ∧
    (state.source = .absent ∨ state.source = .authorized ∨
      state.source = .started ∨ state.source = .completed) ∧
    state.verifier = .unreserved ∧ state.terminal = .none) ∨
  ((state.batch = .queued ∨ state.batch = .leased) ∧
    (state.source = .absent ∨ state.source = .completed) ∧
    state.verifier = .unreserved ∧ state.terminal = .none)

instance lifecyclePhaseWellFormedDecidable (state : LifecycleState) :
    Decidable (lifecyclePhaseWellFormed state) := by
  unfold lifecyclePhaseWellFormed
  infer_instance

def lifecycleLeaseShapeWellFormed (state : LifecycleState) : Prop :=
  (state.liveLeaseCount = 0 ∧ state.attempt = 0 ∧
      state.claimSequence = 0 ∧ state.leaseExpiresMs = 0 ∧
      ((state.batch = .awaiting ∧ state.handoffAttached = false) ∨
        (state.batch = .queued ∧ state.handoffAttached = true))) ∨
    (state.liveLeaseCount = 1 ∧ state.attempt = lifecycleMaxAttempts ∧
      state.claimSequence > 0 ∧ state.leaseExpiresMs > state.updatedMs ∧
      state.handoffAttached = true)

instance lifecycleLeaseShapeWellFormedDecidable (state : LifecycleState) :
    Decidable (lifecycleLeaseShapeWellFormed state) := by
  unfold lifecycleLeaseShapeWellFormed
  infer_instance

def lifecycleReservationWellFormed (state : LifecycleState) : Prop :=
  state.proofAttemptsPerBatch = lifecycleProofAttemptsPerBatch ∧
    state.attemptId = state.identity.admissionSeq ∧
    state.reservationBefore =
      (state.identity.admissionSeq - 1) * lifecycleProofAttemptsPerBatch ∧
    state.reservationAfter =
      state.identity.admissionSeq * lifecycleProofAttemptsPerBatch ∧
    state.reservationAfter = state.reservationBefore + lifecycleProofAttemptsPerBatch ∧
    state.reservationAfter ≤ state.accounting.proof.cap ∧
    state.reservationAfter ≤ state.accounting.proof.used ∧
    state.identity.admissionSeq ≤ state.accounting.sourceU.used ∧
    state.accounting.proof.used =
      state.accounting.sourceU.used * lifecycleProofAttemptsPerBatch

instance lifecycleReservationWellFormedDecidable (state : LifecycleState) :
    Decidable (lifecycleReservationWellFormed state) := by
  unfold lifecycleReservationWellFormed
  infer_instance

def LifecycleState.WellFormed (state : LifecycleState) : Prop :=
  state.config.WellFormed ∧
    state.globalLiveLeaseCount ≤ 1 ∧
    state.identity.WellFormed ∧
    lifecyclePhaseWellFormed state ∧
    state.validFromMs < state.validUntilMs ∧
    state.validUntilMs - state.validFromMs ≤ lifecycleMaxValidityWindowMs ∧
    state.validUntilMs ≤ wireNatMax ∧
    state.nextEligibleMs ≤ wireNatMax ∧
    state.updatedMs ≤ wireNatMax ∧
    state.transitionSequence > 0 ∧
    state.transitionSequence ≤ wireNatMax ∧
    state.attemptId > 0 ∧
    state.attemptId ≤ wireNatMax ∧
    state.identity.stateProfileVersion = state.config.profileToken ∧
    state.attemptSourceKeyEpoch = state.config.sourceKeyEpoch ∧
    state.attemptStatus = .reserved ∧
    state.verifierVUpper = lifecycleVerifierLaunchVUpper ∧
    state.accounting.WellFormed ∧
    lifecycleReservationWellFormed state ∧
    lifecycleLeaseShapeWellFormed state

instance lifecycleStateWellFormedDecidable (state : LifecycleState) :
    Decidable (state.WellFormed) := by
  unfold LifecycleState.WellFormed
  infer_instance

inductive LifecycleEventKind
  | batchIssued
  | handoffSubmitted
  | verificationStarted
  deriving DecidableEq, Repr

inductive LifecycleEventStatus
  | awaitingHandoff
  | queued
  | leased
  | held
  deriving DecidableEq, Repr

/-
  These are the bounded error identities which the Queue itself owns.  The
  pure kernel never fabricates one of them: a Python hold, expiry, cleanup, or
  post-commit ambiguity is a host outcome, not a successful kernel transition.
  The names are the fixed Queue codes used at this boundary.
-/
inductive LifecycleHeldCode
  | freshHandoffRequired
  | validityExpired
  | leaseExpired
  | leanAdmissionUnavailable
  deriving DecidableEq, Repr

inductive LifecycleHostRejectCode
  | queueIntegrityFailed
  | proofSessionActive
  | leanAdmissionRejected
  | computationalBudgetExhausted
  deriving DecidableEq, Repr

inductive LifecycleHostOutcome
  | kernelRejectedNoCommit
  | hostRejectedNoCommit (code : LifecycleHostRejectCode)
  | held (code : LifecycleHeldCode)
  | cleanupRequired
  | postCommitIndeterminate
  deriving DecidableEq, Repr

inductive LifecycleError
  | preconditionFailed
  deriving DecidableEq, Repr

/-
  `LifecycleError` is intentionally kernel-only: this result means the pure
  relation rejected before a state/event commit.  Queue-owned held, expiry,
  cleanup, and post-commit-unknown outcomes are represented by
  `LifecycleHostOutcome` and are not silently collapsed into this constructor.
-/

inductive LifecycleOp
  | submitHandoff
  | claimNextBatch
  deriving DecidableEq, Repr

structure LifecycleEvent where
  schemaVersion : Nat
  sequence : Nat
  kind : LifecycleEventKind
  batchId : LifecycleBytes
  status : LifecycleEventStatus
  errorCode : Option String
  attempt : Nat
  atMs : Nat
  memberCount : Nat
  receiptId : Option LifecycleBytes
  identityDigest : Option LifecycleBytes
  reservationBefore : Option Nat
  reservationAfter : Option Nat
  deriving DecidableEq

def lifecycleEventWellFormedCode (event : LifecycleEvent) : Bool :=
  (event.schemaVersion == lifecycleSchemaVersion) &&
    (event.sequence != 0) &&
    (decide (event.sequence ≤ wireNatMax)) &&
    (event.batchId.length == 32) &&
    (event.memberCount == lifecycleMemberCount) &&
    (decide (event.attempt ≤ lifecycleMaxAttempts)) &&
    (decide (event.atMs ≤ wireNatMax)) &&
    (event.errorCode == none) &&
    (event.receiptId == none) &&
    match event.kind with
    | .batchIssued =>
        (event.status == .awaitingHandoff) &&
          (event.attempt == 0) &&
          match event.identityDigest, event.reservationBefore, event.reservationAfter with
          | some digest, some before, some after =>
              (digest.length == 64) &&
                (after == before + lifecycleProofAttemptsPerBatch)
          | _, _, _ => false
    | .handoffSubmitted =>
        (event.status == .queued) &&
          (event.attempt == 0) &&
          (event.identityDigest == none) &&
          (event.reservationBefore == none) &&
          (event.reservationAfter == none)
    | .verificationStarted =>
        (event.status == .leased) &&
          (event.attempt == lifecycleMaxAttempts) &&
          (event.identityDigest == none) &&
          match event.reservationBefore, event.reservationAfter with
          | some before, some after =>
              after == before + lifecycleProofAttemptsPerBatch
          | _, _ => false

def lifecycleEventWellFormed (event : LifecycleEvent) : Prop :=
  lifecycleEventWellFormedCode event = true

instance lifecycleEventWellFormedDecidable (event : LifecycleEvent) :
    Decidable (lifecycleEventWellFormed event) := by
  unfold lifecycleEventWellFormed
  infer_instance

structure LifecycleTransition where
  after : LifecycleState
  event : LifecycleEvent
  deriving DecidableEq

instance lifecycleExceptTransitionDecidableEq :
    DecidableEq (Except LifecycleError LifecycleTransition) := by
  intro left right
  cases left with
  | error leftError =>
      cases right with
      | error rightError =>
          by_cases h : leftError = rightError
          · exact isTrue (by cases h; rfl)
          · exact isFalse (by
              intro hEqual
              apply h
              cases hEqual
              rfl)
      | ok _ => exact isFalse (by intro h; cases h)
  | ok leftTransition =>
      cases right with
      | error _ => exact isFalse (by intro h; cases h)
      | ok rightTransition =>
          by_cases h : leftTransition = rightTransition
          · exact isTrue (by cases h; rfl)
          · exact isFalse (by
              intro hEqual
              apply h
              cases hEqual
              rfl)

def lifecycleIssueEvent (state : LifecycleState) : LifecycleEvent :=
  { schemaVersion := lifecycleSchemaVersion
    sequence := state.transitionSequence
    kind := .batchIssued
    batchId := state.identity.batchId
    status := .awaitingHandoff
    errorCode := none
    attempt := 0
    atMs := state.updatedMs
    memberCount := lifecycleMemberCount
    receiptId := none
    identityDigest := some state.identity.identityDigest
    reservationBefore := some state.reservationBefore
    reservationAfter := some state.reservationAfter }

def lifecycleIssueEventRelation (state : LifecycleState) (event : LifecycleEvent) : Prop :=
  event.schemaVersion = lifecycleSchemaVersion ∧
    event.sequence = state.transitionSequence ∧
    event.kind = .batchIssued ∧
    event.batchId = state.identity.batchId ∧
    event.status = .awaitingHandoff ∧
    event.errorCode = none ∧
    event.attempt = 0 ∧
    event.atMs = state.updatedMs ∧
    event.memberCount = lifecycleMemberCount ∧
    event.receiptId = none ∧
    event.identityDigest = some state.identity.identityDigest ∧
    event.reservationBefore = some state.reservationBefore ∧
    event.reservationAfter = some state.reservationAfter

instance lifecycleIssueEventRelationDecidable (state : LifecycleState) (event : LifecycleEvent) :
    Decidable (lifecycleIssueEventRelation state event) := by
  unfold lifecycleIssueEventRelation
  infer_instance

def lifecycleSubmitEvent (before : LifecycleState) (nowMs : Nat) : LifecycleEvent :=
  { schemaVersion := lifecycleSchemaVersion
    sequence := before.transitionSequence + 1
    kind := .handoffSubmitted
    batchId := before.identity.batchId
    status := .queued
    errorCode := none
    attempt := 0
    atMs := nowMs
    memberCount := lifecycleMemberCount
    receiptId := none
    identityDigest := none
    reservationBefore := none
    reservationAfter := none }

def lifecycleClaimEvent (before : LifecycleState) (nowMs : Nat) : LifecycleEvent :=
  { schemaVersion := lifecycleSchemaVersion
    sequence := before.transitionSequence + 1
    kind := .verificationStarted
    batchId := before.identity.batchId
    status := .leased
    errorCode := none
    attempt := lifecycleMaxAttempts
    atMs := nowMs
    memberCount := lifecycleMemberCount
    receiptId := none
    identityDigest := none
    reservationBefore := some before.reservationBefore
    reservationAfter := some before.reservationAfter }

def lifecycleClockWellFormed (state : LifecycleState) (nowMs : Nat) : Prop :=
  nowMs ≤ wireNatMax ∧
    state.updatedMs ≤ nowMs ∧
    state.validFromMs ≤ nowMs ∧
    nowMs < state.validUntilMs ∧
    state.transitionSequence < wireNatMax

def lifecycleSubmitPrecondition (state : LifecycleState) (nowMs : Nat) : Prop :=
  state.WellFormed ∧
    lifecycleClockWellFormed state nowMs ∧
    state.batch = .awaiting ∧
    (state.source = .absent ∨ state.source = .completed) ∧
    state.verifier = .unreserved ∧
    state.terminal = .none ∧
    state.attempt = 0 ∧
    state.attemptStatus = .reserved ∧
    state.verifierVUpper = lifecycleVerifierLaunchVUpper ∧
    state.liveLeaseCount = 0 ∧
    state.claimSequence = 0 ∧
    state.handoffAttached = false

def lifecycleClaimPrecondition (state : LifecycleState) (nowMs : Nat) : Prop :=
  state.WellFormed ∧
    lifecycleClockWellFormed state nowMs ∧
    nowMs + state.config.leaseDurationMs ≤ wireNatMax ∧
    state.batch = .queued ∧
    (state.source = .absent ∨ state.source = .completed) ∧
    state.verifier = .unreserved ∧
    state.terminal = .none ∧
    state.attempt = 0 ∧
    state.attemptStatus = .reserved ∧
    state.verifierVUpper = lifecycleVerifierLaunchVUpper ∧
    state.liveLeaseCount = 0 ∧
    state.claimSequence = 0 ∧
    state.handoffAttached = true ∧
    state.nextEligibleMs ≤ nowMs ∧
    state.globalLiveLeaseCount = 0

def lifecyclePrecondition (op : LifecycleOp) (state : LifecycleState) (nowMs : Nat) : Prop :=
  match op with
  | .submitHandoff => lifecycleSubmitPrecondition state nowMs
  | .claimNextBatch => lifecycleClaimPrecondition state nowMs

instance lifecycleSubmitPreconditionDecidable (state : LifecycleState) (nowMs : Nat) :
    Decidable (lifecycleSubmitPrecondition state nowMs) := by
  unfold lifecycleSubmitPrecondition lifecycleClockWellFormed
  infer_instance

instance lifecycleClaimPreconditionDecidable (state : LifecycleState) (nowMs : Nat) :
    Decidable (lifecycleClaimPrecondition state nowMs) := by
  unfold lifecycleClaimPrecondition lifecycleClockWellFormed
  infer_instance

/-
  The host-side commit contract is deliberately the state delta below:
  submit writes QUEUED, next_eligible_ms=now, updated_ms=now, and one
  HANDOFF_SUBMITTED transition without changing accounting or the global lease
  count; its selected batch remains unleased. Claim writes LEASED/attempt=1,
  one selected-batch lease and one global live lease, claim sequence, and
  now+60,000 ms expiry, again without charging or refunding any counter. SQLite transactionality,
  the random lease token/fence digest, and volatile stream cleanup stay at the
  Python boundary.
-/

def lifecycleSubmitAfter (state : LifecycleState) (nowMs : Nat) : LifecycleState :=
  { state with
    batch := .queued
    nextEligibleMs := nowMs
    updatedMs := nowMs
    transitionSequence := state.transitionSequence + 1
    handoffAttached := true }

def lifecycleClaimAfter (state : LifecycleState) (nowMs : Nat) : LifecycleState :=
  let nextSequence := state.transitionSequence + 1
  { state with
    batch := .leased
    updatedMs := nowMs
    attempt := lifecycleMaxAttempts
    globalLiveLeaseCount := 1
    liveLeaseCount := 1
    leaseExpiresMs := nowMs + state.config.leaseDurationMs
    claimSequence := nextSequence
    transitionSequence := nextSequence }

def lifecycleSubmitStateRelation (before after : LifecycleState) (nowMs : Nat) : Prop :=
  after.config = before.config ∧
    after.identity = before.identity ∧
    after.batch = .queued ∧
    after.source = before.source ∧
    after.verifier = before.verifier ∧
    after.terminal = before.terminal ∧
    after.validFromMs = before.validFromMs ∧
    after.validUntilMs = before.validUntilMs ∧
    after.nextEligibleMs = nowMs ∧
    after.updatedMs = nowMs ∧
    after.attempt = before.attempt ∧
    after.attemptId = before.attemptId ∧
    after.attemptStatus = before.attemptStatus ∧
    after.verifierVUpper = before.verifierVUpper ∧
    after.globalLiveLeaseCount = before.globalLiveLeaseCount ∧
    after.liveLeaseCount = before.liveLeaseCount ∧
    after.leaseExpiresMs = before.leaseExpiresMs ∧
    after.claimSequence = before.claimSequence ∧
    after.transitionSequence = before.transitionSequence + 1 ∧
    after.reservationBefore = before.reservationBefore ∧
    after.reservationAfter = before.reservationAfter ∧
    after.proofAttemptsPerBatch = before.proofAttemptsPerBatch ∧
    after.attemptSourceKeyEpoch = before.attemptSourceKeyEpoch ∧
    after.handoffAttached = true ∧
    after.accounting = before.accounting

def lifecycleClaimStateRelation (before after : LifecycleState) (nowMs : Nat) : Prop :=
  after.config = before.config ∧
    after.identity = before.identity ∧
    after.batch = .leased ∧
    after.source = before.source ∧
    after.verifier = before.verifier ∧
    after.terminal = before.terminal ∧
    after.validFromMs = before.validFromMs ∧
    after.validUntilMs = before.validUntilMs ∧
    after.nextEligibleMs = before.nextEligibleMs ∧
    after.updatedMs = nowMs ∧
    after.attempt = lifecycleMaxAttempts ∧
    after.attemptId = before.attemptId ∧
    after.attemptStatus = before.attemptStatus ∧
    after.verifierVUpper = before.verifierVUpper ∧
    after.globalLiveLeaseCount = 1 ∧
    after.liveLeaseCount = 1 ∧
    after.leaseExpiresMs = nowMs + before.config.leaseDurationMs ∧
    after.claimSequence = before.transitionSequence + 1 ∧
    after.transitionSequence = before.transitionSequence + 1 ∧
    after.reservationBefore = before.reservationBefore ∧
    after.reservationAfter = before.reservationAfter ∧
    after.proofAttemptsPerBatch = before.proofAttemptsPerBatch ∧
    after.attemptSourceKeyEpoch = before.attemptSourceKeyEpoch ∧
    after.handoffAttached = before.handoffAttached ∧
    after.accounting = before.accounting

def lifecycleSubmitEventRelation (before : LifecycleState) (nowMs : Nat)
    (event : LifecycleEvent) : Prop :=
  event.schemaVersion = lifecycleSchemaVersion ∧
    event.sequence = before.transitionSequence + 1 ∧
    event.kind = .handoffSubmitted ∧
    event.batchId = before.identity.batchId ∧
    event.status = .queued ∧
    event.errorCode = none ∧
    event.attempt = 0 ∧
    event.atMs = nowMs ∧
    event.memberCount = lifecycleMemberCount ∧
    event.receiptId = none ∧
    event.identityDigest = none ∧
    event.reservationBefore = none ∧
    event.reservationAfter = none

instance lifecycleSubmitEventRelationDecidable (before : LifecycleState) (nowMs : Nat)
    (event : LifecycleEvent) : Decidable (lifecycleSubmitEventRelation before nowMs event) := by
  unfold lifecycleSubmitEventRelation
  infer_instance

def lifecycleClaimEventRelation (before : LifecycleState) (nowMs : Nat)
    (event : LifecycleEvent) : Prop :=
  event.schemaVersion = lifecycleSchemaVersion ∧
    event.sequence = before.transitionSequence + 1 ∧
    event.kind = .verificationStarted ∧
    event.batchId = before.identity.batchId ∧
    event.status = .leased ∧
    event.errorCode = none ∧
    event.attempt = lifecycleMaxAttempts ∧
    event.atMs = nowMs ∧
    event.memberCount = lifecycleMemberCount ∧
    event.receiptId = none ∧
    event.identityDigest = none ∧
    event.reservationBefore = some before.reservationBefore ∧
    event.reservationAfter = some before.reservationAfter

instance lifecycleClaimEventRelationDecidable (before : LifecycleState) (nowMs : Nat)
    (event : LifecycleEvent) : Decidable (lifecycleClaimEventRelation before nowMs event) := by
  unfold lifecycleClaimEventRelation
  infer_instance

def lifecycleRelation (op : LifecycleOp) (nowMs : Nat)
    (before : LifecycleState) (transition : LifecycleTransition) : Prop :=
  match op with
  | .submitHandoff =>
      lifecycleSubmitPrecondition before nowMs ∧
        lifecycleSubmitStateRelation before transition.after nowMs ∧
        lifecycleSubmitEventRelation before nowMs transition.event
  | .claimNextBatch =>
      lifecycleClaimPrecondition before nowMs ∧
        lifecycleClaimStateRelation before transition.after nowMs ∧
        lifecycleClaimEventRelation before nowMs transition.event

def lifecycleStep (op : LifecycleOp) (state : LifecycleState) (nowMs : Nat) :
    Except LifecycleError LifecycleTransition :=
  match op with
  | .submitHandoff =>
      if lifecycleSubmitPrecondition state nowMs then
        .ok { after := lifecycleSubmitAfter state nowMs
              event := lifecycleSubmitEvent state nowMs }
      else
        .error .preconditionFailed
  | .claimNextBatch =>
      if lifecycleClaimPrecondition state nowMs then
        .ok { after := lifecycleClaimAfter state nowMs
              event := lifecycleClaimEvent state nowMs }
      else
        .error .preconditionFailed

theorem lifecycleStep_sound (op : LifecycleOp) (state : LifecycleState)
    (nowMs : Nat) (transition : LifecycleTransition)
    (h : lifecycleStep op state nowMs = .ok transition) :
    lifecycleRelation op nowMs state transition := by
  cases op with
  | submitHandoff =>
      by_cases hPre : lifecycleSubmitPrecondition state nowMs
      · simp [lifecycleStep, hPre] at h
        cases h
        refine ⟨hPre, ?_, ?_⟩
        · simp [lifecycleSubmitStateRelation, lifecycleSubmitAfter]
        · simp [lifecycleSubmitEventRelation, lifecycleSubmitEvent]
      · simp [lifecycleStep, hPre] at h
  | claimNextBatch =>
      by_cases hPre : lifecycleClaimPrecondition state nowMs
      · simp [lifecycleStep, hPre] at h
        cases h
        refine ⟨hPre, ?_, ?_⟩
        · simp [lifecycleClaimStateRelation, lifecycleClaimAfter]
        · simp [lifecycleClaimEventRelation, lifecycleClaimEvent]
      · simp [lifecycleStep, hPre] at h

end BlindLedger.Admission
