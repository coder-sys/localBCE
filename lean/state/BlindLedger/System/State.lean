import BlindLedger.System.Types
import BlindLedger.System.Queue

namespace BlindLedger.System

/-! The authorized constructor is the only State constructor that carries
    effective directives. StateAuthorityStep below is the declared modeling
    boundary for authority transitions; generated Lean constructors remain
    public and are not runtime authority enforcement. -/
inductive State where
  | pending (batch : OperationBatch)
  | authorized (batch : OperationBatch) (authorization : AuthorizationBatch)

def State.effectiveDirective : State → BatchIndex → Option EffectiveDirective
  | .pending _, _ => none
  | .authorized _ authorization, i => some (authorization.directives i)

def State.authorizationCount : State → Nat
  | .pending _ => 0
  | .authorized _ _ => 1

/-! State and outbox are returned as one abstract system value. This models an
    atomic abstract transition only; it does not prove database durability or
    concurrent linearizability. -/
structure System where
  state : State
  queue : QueueState
  composition : CompositionState
  outbox : Outbox

def emptyOutbox : Outbox :=
  { entries := fun _ => none }

def pendingSystem (batch : OperationBatch) : System :=
  { state := .pending batch
    queue := emptyQueueState
    composition := emptyCompositionState
    outbox := emptyOutbox }

def outboxFromAuthorization
    (batch : OperationBatch) (authorization : AuthorizationBatch) : Outbox :=
  { entries := fun i =>
      some
        { operation := batch.refs i
          directive := authorization.directives i
          idempotency := authorization.idempotency i
          readiness := .READY
          delivery := .queued } }

inductive AuthorizationAction where
  | abort
  | commit (authorization : AuthorizationBatch)

/-! PolicyResult is input data with a distinct type; it is not a directive
    selector. The authorization batch is the state-authority decision. -/
def authorize
    (system : System) (_policy : PolicyResult)
    (action : AuthorizationAction) : System :=
  match action with
  | .abort => system
  | .commit authorization =>
      match system.state with
      | .pending batch =>
          { state := .authorized batch authorization
            queue := system.queue
            composition := system.composition
            outbox := outboxFromAuthorization batch authorization }
      | .authorized _ _ => system

def observeVerification
    (system : System) (_outcome : VerificationOutcome) : System :=
  system

/-! This relation records which transitions count as State-authority steps.
    It is intentionally narrower than Lean constructor visibility. -/
inductive StateAuthorityStep : System → System → Prop where
  | abort (system : System) (policy : PolicyResult) :
      StateAuthorityStep system (authorize system policy .abort)
  | commit (system : System) (policy : PolicyResult)
      (authorization : AuthorizationBatch) :
      StateAuthorityStep system
        (authorize system policy (.commit authorization))

inductive StateAuthorityReachable : System → Prop where
  | initial (batch : OperationBatch) :
      StateAuthorityReachable (pendingSystem batch)
  | step {before after : System} :
      StateAuthorityReachable before →
      StateAuthorityStep before after →
      StateAuthorityReachable after

theorem stateAuthorityStep_is_authorize
    {before after : System} (step : StateAuthorityStep before after) :
    ∃ policy action, after = authorize before policy action := by
  cases step with
  | abort policy =>
      exact ⟨policy, .abort, rfl⟩
  | commit policy authorization =>
      exact ⟨policy, .commit authorization, rfl⟩

def effectiveDirective (system : System) (i : BatchIndex) :
    Option EffectiveDirective :=
  system.state.effectiveDirective i

def outboxDirective (outbox : Outbox) (i : BatchIndex) :
    Option EffectiveDirective :=
  match outbox.entries i with
  | none => none
  | some entry => some entry.directive

def outboxIdempotency (outbox : Outbox) (i : BatchIndex) :
    Option IdempotencyIdentity :=
  match outbox.entries i with
  | none => none
  | some entry => some entry.idempotency

/-! Delivery transitions update delivery metadata only. -/
def updateEntry
    (outbox : Outbox) (i : BatchIndex)
    (update : OutboxEntry → OutboxEntry) : Outbox :=
  { entries := fun j =>
      if j = i then
        match outbox.entries j with
        | none => none
        | some entry => some (update entry)
      else
        outbox.entries j }

def setDelivery (entry : OutboxEntry) (delivery : DeliveryState) : OutboxEntry :=
  { entry with delivery := delivery }

def ack (system : System) (i : BatchIndex) : System :=
  { system with
      outbox := updateEntry system.outbox i
        (fun entry => setDelivery entry .acknowledged) }

def retry (system : System) (i : BatchIndex) (attempt : Nat) : System :=
  { system with
      outbox := updateEntry system.outbox i
        (fun entry => setDelivery entry (.retrying attempt)) }

def lease (system : System) (i : BatchIndex) (leaseRef : LeaseRef) : System :=
  { system with
      outbox := updateEntry system.outbox i
        (fun entry => setDelivery entry (.leased leaseRef)) }

/-! The abstract State transition below is the post-expiry lease reset only.
    The deadline-aware runtime correspondence, including the attempt cap and
    DELIVERY_UNCONFIRMED recovery branch, is `runtimeRecoverState` in Queue. -/
def recoverDelivery (entry : OutboxEntry) : OutboxEntry :=
  match entry.delivery with
  | .leased _ => setDelivery entry .queued
  | _ => entry

theorem recoverDelivery_idempotent (entry : OutboxEntry) :
    recoverDelivery (recoverDelivery entry) = recoverDelivery entry := by
  cases entry with
  | mk operation directive idempotency readiness delivery =>
      cases delivery <;> rfl

theorem recoverDelivery_preserves_directive (entry : OutboxEntry) :
    (recoverDelivery entry).directive = entry.directive := by
  cases entry with
  | mk operation directive idempotency readiness delivery =>
      cases delivery <;> rfl

theorem recoverDelivery_preserves_idempotency (entry : OutboxEntry) :
    (recoverDelivery entry).idempotency = entry.idempotency := by
  cases entry with
  | mk operation directive idempotency readiness delivery =>
      cases delivery <;> rfl

def recover (system : System) (i : BatchIndex) : System :=
  { system with
      outbox := updateEntry system.outbox i recoverDelivery }

/-! Recovery is a reconciliation transition: repeating it for the same row
    is idempotent, and it cannot create an outbox row that was absent. -/
theorem recover_idempotent (system : System) (i : BatchIndex) :
    recover (recover system i) i = recover system i := by
  cases system with
  | mk state queue composition outbox =>
      cases outbox with
      | mk entries =>
          simp only [recover, updateEntry]
          congr
          funext j
          by_cases hji : j = i
          · subst j
            cases hentry : entries i with
            | none => simp
            | some entry =>
                simpa using (recoverDelivery_idempotent entry)
          · simp [hji]

theorem recover_preserves_missing_entry
    (system : System) (i : BatchIndex)
    (hmissing : system.outbox.entries i = none) :
    (recover system i).outbox.entries i = none := by
  simp [recover, updateEntry, hmissing]

theorem authorize_pending_state
    (batch : OperationBatch) (policy : PolicyResult)
    (authorization : AuthorizationBatch) :
    (authorize (pendingSystem batch) policy (.commit authorization)).state =
      .authorized batch authorization := by
  rfl

theorem authorize_pending_outbox_entry
    (batch : OperationBatch) (policy : PolicyResult)
    (authorization : AuthorizationBatch) (i : BatchIndex) :
    (authorize (pendingSystem batch) policy (.commit authorization)).outbox.entries i =
      some
        { operation := batch.refs i
          directive := authorization.directives i
          idempotency := authorization.idempotency i
          readiness := .READY
          delivery := .queued } := by
  rfl

/-! Both halves of the authorization result are exposed by one theorem about
    one abstract transition. -/
theorem authorize_pending_atomic
    (batch : OperationBatch) (policy : PolicyResult)
    (authorization : AuthorizationBatch) (i : BatchIndex) :
    (authorize (pendingSystem batch) policy (.commit authorization)).state =
        .authorized batch authorization ∧
      (authorize (pendingSystem batch) policy (.commit authorization)).outbox.entries i =
        some
          { operation := batch.refs i
            directive := authorization.directives i
            idempotency := authorization.idempotency i
            readiness := .READY
            delivery := .queued } := by
  constructor <;> rfl

theorem authorize_identity_on_authorized
    (batch : OperationBatch) (oldAuthorization : AuthorizationBatch)
    (queue : QueueState) (composition : CompositionState) (outbox : Outbox)
    (policy : PolicyResult)
    (newAuthorization : AuthorizationBatch) :
    authorize
        { state := .authorized batch oldAuthorization
          queue := queue
          composition := composition
          outbox := outbox }
        policy (.commit newAuthorization) =
      { state := .authorized batch oldAuthorization
        queue := queue
        composition := composition
        outbox := outbox } := by
  rfl

theorem authorize_abort_preserves_queue_and_composition
    (system : System) (policy : PolicyResult) :
    (authorize system policy .abort).queue = system.queue ∧
      (authorize system policy .abort).composition = system.composition := by
  constructor <;> rfl

theorem verification_observation_preserves_system
    (system : System) (outcome : VerificationOutcome) :
    observeVerification system outcome = system := by
  rfl

theorem verified_observation_from_pending_has_no_directive
    (batch : OperationBatch) (i : BatchIndex) :
    effectiveDirective
        (observeVerification (pendingSystem batch) .verified) i = none := by
  rfl

theorem verified_observation_from_pending_cannot_create_clear
    (batch : OperationBatch) (i : BatchIndex) :
    effectiveDirective
        (observeVerification (pendingSystem batch) .verified) i = none ∧
      effectiveDirective
          (observeVerification (pendingSystem batch) .verified) i ≠ some .CLEAR := by
  constructor
  · rfl
  · simp [effectiveDirective, observeVerification, pendingSystem, State.effectiveDirective]

theorem policy_result_cannot_change_fixed_authorization_action
    (system : System) (first second : PolicyResult)
    (action : AuthorizationAction) :
    authorize system first action = authorize system second action := by
  cases action <;> rfl

theorem authorization_count_le_one (system : System) :
    system.state.authorizationCount ≤ 1 := by
  cases system.state <;> simp [State.authorizationCount]

theorem updateEntry_preserves_outboxDirective
    (outbox : Outbox) (i : BatchIndex)
    (update : OutboxEntry → OutboxEntry)
    (hupdate : ∀ entry, (update entry).directive = entry.directive)
    (j : BatchIndex) :
    outboxDirective (updateEntry outbox i update) j =
      outboxDirective outbox j := by
  by_cases hji : j = i
  · subst j
    cases hentry : outbox.entries i with
    | none => simp [outboxDirective, updateEntry, hentry]
    | some entry => simp [outboxDirective, updateEntry, hentry, hupdate entry]
  · simp [outboxDirective, updateEntry, hji]

theorem updateEntry_preserves_outboxIdempotency
    (outbox : Outbox) (i : BatchIndex)
    (update : OutboxEntry → OutboxEntry)
    (hupdate : ∀ entry, (update entry).idempotency = entry.idempotency)
    (j : BatchIndex) :
    outboxIdempotency (updateEntry outbox i update) j =
      outboxIdempotency outbox j := by
  by_cases hji : j = i
  · subst j
    cases hentry : outbox.entries i with
    | none => simp [outboxIdempotency, updateEntry, hentry]
    | some entry => simp [outboxIdempotency, updateEntry, hentry, hupdate entry]
  · simp [outboxIdempotency, updateEntry, hji]

theorem ack_preserves_state (system : System) (i : BatchIndex) :
    (ack system i).state = system.state := by
  rfl

theorem retry_preserves_state (system : System) (i : BatchIndex) (attempt : Nat) :
    (retry system i attempt).state = system.state := by
  rfl

theorem lease_preserves_state
    (system : System) (i : BatchIndex) (leaseRef : LeaseRef) :
    (lease system i leaseRef).state = system.state := by
  rfl

theorem recover_preserves_state (system : System) (i : BatchIndex) :
    (recover system i).state = system.state := by
  rfl

theorem ack_preserves_effectiveDirective (system : System) (i j : BatchIndex) :
    effectiveDirective (ack system i) j = effectiveDirective system j := by
  rfl

theorem retry_preserves_effectiveDirective
    (system : System) (i j : BatchIndex) (attempt : Nat) :
    effectiveDirective (retry system i attempt) j =
      effectiveDirective system j := by
  rfl

theorem lease_preserves_effectiveDirective
    (system : System) (i j : BatchIndex) (leaseRef : LeaseRef) :
    effectiveDirective (lease system i leaseRef) j =
      effectiveDirective system j := by
  rfl

theorem recover_preserves_effectiveDirective (system : System) (i j : BatchIndex) :
    effectiveDirective (recover system i) j = effectiveDirective system j := by
  rfl

theorem ack_preserves_outboxDirective (system : System) (i j : BatchIndex) :
    outboxDirective (ack system i).outbox j = outboxDirective system.outbox j := by
  change outboxDirective
    (updateEntry system.outbox i
      (fun entry => setDelivery entry .acknowledged)) j =
    outboxDirective system.outbox j
  apply updateEntry_preserves_outboxDirective
  intro entry
  rfl

theorem ack_preserves_outboxIdempotency (system : System) (i j : BatchIndex) :
    outboxIdempotency (ack system i).outbox j =
      outboxIdempotency system.outbox j := by
  change outboxIdempotency
    (updateEntry system.outbox i
      (fun entry => setDelivery entry .acknowledged)) j =
    outboxIdempotency system.outbox j
  apply updateEntry_preserves_outboxIdempotency
  intro entry
  rfl

theorem retry_preserves_outboxDirective
    (system : System) (i j : BatchIndex) (attempt : Nat) :
    outboxDirective (retry system i attempt).outbox j =
      outboxDirective system.outbox j := by
  change outboxDirective
    (updateEntry system.outbox i
      (fun entry => setDelivery entry (.retrying attempt))) j =
    outboxDirective system.outbox j
  apply updateEntry_preserves_outboxDirective
  intro entry
  rfl

theorem retry_preserves_outboxIdempotency
    (system : System) (i j : BatchIndex) (attempt : Nat) :
    outboxIdempotency (retry system i attempt).outbox j =
      outboxIdempotency system.outbox j := by
  change outboxIdempotency
    (updateEntry system.outbox i
      (fun entry => setDelivery entry (.retrying attempt))) j =
    outboxIdempotency system.outbox j
  apply updateEntry_preserves_outboxIdempotency
  intro entry
  rfl

theorem lease_preserves_outboxDirective
    (system : System) (i j : BatchIndex) (leaseRef : LeaseRef) :
    outboxDirective (lease system i leaseRef).outbox j =
      outboxDirective system.outbox j := by
  change outboxDirective
    (updateEntry system.outbox i
      (fun entry => setDelivery entry (.leased leaseRef))) j =
    outboxDirective system.outbox j
  apply updateEntry_preserves_outboxDirective
  intro entry
  rfl

theorem lease_preserves_outboxIdempotency
    (system : System) (i j : BatchIndex) (leaseRef : LeaseRef) :
    outboxIdempotency (lease system i leaseRef).outbox j =
      outboxIdempotency system.outbox j := by
  change outboxIdempotency
    (updateEntry system.outbox i
      (fun entry => setDelivery entry (.leased leaseRef))) j =
    outboxIdempotency system.outbox j
  apply updateEntry_preserves_outboxIdempotency
  intro entry
  rfl

theorem recover_preserves_outboxDirective (system : System) (i j : BatchIndex) :
    outboxDirective (recover system i).outbox j = outboxDirective system.outbox j := by
  change outboxDirective
    (updateEntry system.outbox i recoverDelivery) j =
    outboxDirective system.outbox j
  apply updateEntry_preserves_outboxDirective
  intro entry
  exact recoverDelivery_preserves_directive entry

theorem recover_preserves_outboxIdempotency (system : System) (i j : BatchIndex) :
    outboxIdempotency (recover system i).outbox j =
      outboxIdempotency system.outbox j := by
  change outboxIdempotency
    (updateEntry system.outbox i recoverDelivery) j =
    outboxIdempotency system.outbox j
  apply updateEntry_preserves_outboxIdempotency
  intro entry
  exact recoverDelivery_preserves_idempotency entry

/-! Recovery is the model's reconciliation transition. -/
abbrev reconcile := recover

theorem reconciliation_preserves_directive_and_idempotency
    (system : System) (i j : BatchIndex) :
    outboxDirective (reconcile system i).outbox j =
        outboxDirective system.outbox j ∧
      outboxIdempotency (reconcile system i).outbox j =
        outboxIdempotency system.outbox j := by
  constructor
  · exact recover_preserves_outboxDirective system i j
  · exact recover_preserves_outboxIdempotency system i j

theorem delivery_transitions_preserve_authorization_count
    (system : System) (i : BatchIndex) :
    (ack system i).state.authorizationCount = system.state.authorizationCount ∧
    (recover system i).state.authorizationCount = system.state.authorizationCount := by
  constructor <;> rfl

theorem delivery_transitions_preserve_directive_and_idempotency
    (system : System) (i j : BatchIndex) :
    outboxDirective (recover system i).outbox j = outboxDirective system.outbox j ∧
    outboxIdempotency (recover system i).outbox j =
      outboxIdempotency system.outbox j := by
  constructor
  · exact recover_preserves_outboxDirective system i j
  · exact recover_preserves_outboxIdempotency system i j

end BlindLedger.System
