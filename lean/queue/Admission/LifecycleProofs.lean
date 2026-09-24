import Admission.Lifecycle

namespace BlindLedger.Admission

def lifecycleAccountingUsedWithinCaps (accounting : LifecycleAccounting) : Prop :=
  accounting.proof.used ≤ accounting.proof.cap ∧
    accounting.sourceA.used ≤ accounting.sourceA.cap ∧
    accounting.sourceS.used ≤ accounting.sourceS.cap ∧
    accounting.sourceM.used ≤ accounting.sourceM.cap ∧
    accounting.sourceU.used ≤ accounting.sourceU.cap ∧
    accounting.verifierV.used ≤ accounting.verifierV.cap

theorem lifecycleAccountingUsedWithinCaps_of_wellFormed
    (accounting : LifecycleAccounting)
    (h : accounting.WellFormed) :
    lifecycleAccountingUsedWithinCaps accounting := by
  rcases h with ⟨hProof, hA, hS, hM, hU, hV, _⟩
  exact ⟨hProof.1, hA.1, hS.1, hM.1, hU.1, hV.1⟩

theorem lifecycleSubmitStateRelation_eq (before after : LifecycleState) (nowMs : Nat)
    (h : lifecycleSubmitStateRelation before after nowMs) :
    after = lifecycleSubmitAfter before nowMs := by
  cases before
  cases after
  simp_all [lifecycleSubmitStateRelation, lifecycleSubmitAfter]

theorem lifecycleClaimStateRelation_eq (before after : LifecycleState) (nowMs : Nat)
    (h : lifecycleClaimStateRelation before after nowMs) :
    after = lifecycleClaimAfter before nowMs := by
  cases before
  cases after
  simp_all [lifecycleClaimStateRelation, lifecycleClaimAfter]

theorem lifecycleSubmitEventRelation_eq (before : LifecycleState) (nowMs : Nat)
    (event : LifecycleEvent) (h : lifecycleSubmitEventRelation before nowMs event) :
    event = lifecycleSubmitEvent before nowMs := by
  cases before
  cases event
  simp_all [lifecycleSubmitEventRelation, lifecycleSubmitEvent]

theorem lifecycleClaimEventRelation_eq (before : LifecycleState) (nowMs : Nat)
    (event : LifecycleEvent) (h : lifecycleClaimEventRelation before nowMs event) :
    event = lifecycleClaimEvent before nowMs := by
  cases before
  cases event
  simp_all [lifecycleClaimEventRelation, lifecycleClaimEvent]

theorem lifecycleIssueEventRelation_eq (state : LifecycleState) (event : LifecycleEvent)
    (h : lifecycleIssueEventRelation state event) :
    event = lifecycleIssueEvent state := by
  cases state
  cases event
  simp_all [lifecycleIssueEventRelation, lifecycleIssueEvent]

theorem lifecycleRelation_deterministic (op : LifecycleOp) (nowMs : Nat)
    (before : LifecycleState) (transition1 transition2 : LifecycleTransition)
    (h1 : lifecycleRelation op nowMs before transition1)
    (h2 : lifecycleRelation op nowMs before transition2) :
    transition1 = transition2 := by
  cases op with
  | submitHandoff =>
      rcases h1 with ⟨_, hState1, hEvent1⟩
      rcases h2 with ⟨_, hState2, hEvent2⟩
      have hAfter1 := lifecycleSubmitStateRelation_eq before transition1.after nowMs hState1
      have hAfter2 := lifecycleSubmitStateRelation_eq before transition2.after nowMs hState2
      have hEvent1' := lifecycleSubmitEventRelation_eq before nowMs transition1.event hEvent1
      have hEvent2' := lifecycleSubmitEventRelation_eq before nowMs transition2.event hEvent2
      cases transition1
      cases transition2
      simp_all
  | claimNextBatch =>
      rcases h1 with ⟨_, hState1, hEvent1⟩
      rcases h2 with ⟨_, hState2, hEvent2⟩
      have hAfter1 := lifecycleClaimStateRelation_eq before transition1.after nowMs hState1
      have hAfter2 := lifecycleClaimStateRelation_eq before transition2.after nowMs hState2
      have hEvent1' := lifecycleClaimEventRelation_eq before nowMs transition1.event hEvent1
      have hEvent2' := lifecycleClaimEventRelation_eq before nowMs transition2.event hEvent2
      cases transition1
      cases transition2
      simp_all

theorem lifecycleStep_deterministic (op : LifecycleOp) (state : LifecycleState)
    (nowMs : Nat) (transition1 transition2 : LifecycleTransition)
    (h1 : lifecycleStep op state nowMs = .ok transition1)
    (h2 : lifecycleStep op state nowMs = .ok transition2) :
    transition1 = transition2 := by
  exact lifecycleRelation_deterministic op nowMs state transition1 transition2
    (lifecycleStep_sound op state nowMs transition1 h1)
    (lifecycleStep_sound op state nowMs transition2 h2)

theorem lifecycleRelation_after_wellFormed (op : LifecycleOp) (nowMs : Nat)
    (before : LifecycleState) (transition : LifecycleTransition)
    (h : lifecycleRelation op nowMs before transition) :
    transition.after.WellFormed := by
  cases op with
  | submitHandoff =>
      rcases h with ⟨hPre, hState, hEvent⟩
      rw [lifecycleSubmitStateRelation_eq before transition.after nowMs hState]
      rcases hPre with ⟨hStateBefore, hClock, hBatch, hSource, hVerifier,
        hTerminal, hAttempt, hAttemptStatus, hVerifierUpper, hLease,
        hClaimSequence, hHandoff⟩
      rcases hSource with hSource | hSource <;>
        simp_all [LifecycleState.WellFormed, lifecycleSubmitAfter,
          LifecycleConfig.WellFormed, lifecyclePhaseWellFormed,
          lifecycleLeaseShapeWellFormed, lifecycleReservationWellFormed,
          lifecycleClockWellFormed] <;>
        omega
  | claimNextBatch =>
      rcases h with ⟨hPre, hState, hEvent⟩
      rw [lifecycleClaimStateRelation_eq before transition.after nowMs hState]
      rcases hPre with ⟨hStateBefore, hClock, hLeaseBound, hBatch, hSource,
        hVerifier, hTerminal, hAttempt, hAttemptStatus, hVerifierUpper,
        hLiveLease, hClaimSequence, hHandoff, hEligible, hGlobalLiveLease⟩
      have hConfig : before.config.WellFormed := hStateBefore.1
      have hLeaseDuration : before.config.leaseDurationMs = lifecycleLeaseDurationMs := by
        rcases hConfig with ⟨_, _, _, _, _, _, _, hLeaseDuration, _, _, _, _⟩
        exact hLeaseDuration
      rcases hSource with hSource | hSource <;>
        simp_all [LifecycleState.WellFormed, lifecycleClaimAfter,
          LifecycleConfig.WellFormed, lifecyclePhaseWellFormed,
          lifecycleLeaseShapeWellFormed, lifecycleReservationWellFormed,
          lifecycleClockWellFormed, lifecycleLeaseDurationMs,
          lifecycleMaxAttempts] <;>
        omega

theorem lifecycle_identity_preserved (op : LifecycleOp) (nowMs : Nat)
    (before : LifecycleState) (transition : LifecycleTransition)
    (h : lifecycleRelation op nowMs before transition) :
    transition.after.identity = before.identity := by
  cases op with
  | submitHandoff =>
      rcases h with ⟨_, hState, _⟩
      rw [lifecycleSubmitStateRelation_eq before transition.after nowMs hState]
      simp [lifecycleSubmitAfter]
  | claimNextBatch =>
      rcases h with ⟨_, hState, _⟩
      rw [lifecycleClaimStateRelation_eq before transition.after nowMs hState]
      simp [lifecycleClaimAfter]

theorem lifecycle_config_preserved (op : LifecycleOp) (nowMs : Nat)
    (before : LifecycleState) (transition : LifecycleTransition)
    (h : lifecycleRelation op nowMs before transition) :
    transition.after.config = before.config := by
  cases op with
  | submitHandoff =>
      rcases h with ⟨_, hState, _⟩
      rw [lifecycleSubmitStateRelation_eq before transition.after nowMs hState]
      simp [lifecycleSubmitAfter]
  | claimNextBatch =>
      rcases h with ⟨_, hState, _⟩
      rw [lifecycleClaimStateRelation_eq before transition.after nowMs hState]
      simp [lifecycleClaimAfter]

theorem lifecycle_source_verifier_preserved (op : LifecycleOp) (nowMs : Nat)
    (before : LifecycleState) (transition : LifecycleTransition)
    (h : lifecycleRelation op nowMs before transition) :
    transition.after.source = before.source ∧ transition.after.verifier = before.verifier ∧
      transition.after.terminal = before.terminal := by
  cases op with
  | submitHandoff =>
      rcases h with ⟨_, hState, _⟩
      rw [lifecycleSubmitStateRelation_eq before transition.after nowMs hState]
      simp [lifecycleSubmitAfter]
  | claimNextBatch =>
      rcases h with ⟨_, hState, _⟩
      rw [lifecycleClaimStateRelation_eq before transition.after nowMs hState]
      simp [lifecycleClaimAfter]

theorem lifecycle_accounting_preserved (op : LifecycleOp) (nowMs : Nat)
    (before : LifecycleState) (transition : LifecycleTransition)
    (h : lifecycleRelation op nowMs before transition) :
    transition.after.accounting = before.accounting := by
  cases op with
  | submitHandoff =>
      rcases h with ⟨_, hState, _⟩
      rw [lifecycleSubmitStateRelation_eq before transition.after nowMs hState]
      rfl
  | claimNextBatch =>
      rcases h with ⟨_, hState, _⟩
      rw [lifecycleClaimStateRelation_eq before transition.after nowMs hState]
      rfl

theorem lifecycle_no_refund (op : LifecycleOp) (nowMs : Nat)
    (before : LifecycleState) (transition : LifecycleTransition)
    (h : lifecycleRelation op nowMs before transition) :
    before.accounting.proof.used ≤ transition.after.accounting.proof.used ∧
      before.accounting.sourceA.used ≤ transition.after.accounting.sourceA.used ∧
      before.accounting.sourceS.used ≤ transition.after.accounting.sourceS.used ∧
      before.accounting.sourceM.used ≤ transition.after.accounting.sourceM.used ∧
      before.accounting.sourceU.used ≤ transition.after.accounting.sourceU.used ∧
      before.accounting.verifierV.used ≤ transition.after.accounting.verifierV.used := by
  have preserved := lifecycle_accounting_preserved op nowMs before transition h
  rw [preserved]
  exact ⟨Nat.le_refl _, Nat.le_refl _, Nat.le_refl _,
    Nat.le_refl _, Nat.le_refl _, Nat.le_refl _⟩

theorem lifecycle_counter_caps_preserved (op : LifecycleOp) (nowMs : Nat)
    (before : LifecycleState) (transition : LifecycleTransition)
    (hBefore : before.accounting.WellFormed)
    (h : lifecycleRelation op nowMs before transition) :
    lifecycleAccountingUsedWithinCaps transition.after.accounting := by
  rw [lifecycle_accounting_preserved op nowMs before transition h]
  exact lifecycleAccountingUsedWithinCaps_of_wellFormed before.accounting hBefore

theorem lifecycle_accounting_wellFormed_preserved (op : LifecycleOp) (nowMs : Nat)
    (before : LifecycleState) (transition : LifecycleTransition)
    (hBefore : before.accounting.WellFormed)
    (h : lifecycleRelation op nowMs before transition) :
    transition.after.accounting.WellFormed := by
  rw [lifecycle_accounting_preserved op nowMs before transition h]
  exact hBefore

theorem lifecycle_one_lease (nowMs : Nat) (before : LifecycleState)
    (transition : LifecycleTransition)
    (h : lifecycleRelation .claimNextBatch nowMs before transition) :
    transition.after.globalLiveLeaseCount = 1 ∧
      transition.after.liveLeaseCount = 1 ∧ transition.after.attempt = 1 ∧
      transition.after.claimSequence = before.transitionSequence + 1 ∧
      transition.after.leaseExpiresMs = nowMs + before.config.leaseDurationMs := by
  rcases h with ⟨_, hState, _⟩
  rw [lifecycleClaimStateRelation_eq before transition.after nowMs hState]
  simp [lifecycleClaimAfter, lifecycleMaxAttempts]

theorem lifecycle_never_creates_two_leases (op : LifecycleOp) (nowMs : Nat)
    (before : LifecycleState) (transition : LifecycleTransition)
    (h : lifecycleRelation op nowMs before transition) :
    transition.after.liveLeaseCount ≤ 1 := by
  cases op with
  | submitHandoff =>
      rcases h with ⟨hPre, hState, _⟩
      rw [lifecycleSubmitStateRelation_eq before transition.after nowMs hState]
      rcases hPre with ⟨_, _, _, _, _, _, _, _, _, hLiveLease, _, _⟩
      simp [lifecycleSubmitAfter, hLiveLease]
  | claimNextBatch =>
      rcases h with ⟨_, hState, _⟩
      rw [lifecycleClaimStateRelation_eq before transition.after nowMs hState]
      simp [lifecycleClaimAfter, lifecycleMaxAttempts]

theorem lifecycle_global_live_lease_count_bounded (op : LifecycleOp) (nowMs : Nat)
    (before : LifecycleState) (transition : LifecycleTransition)
    (h : lifecycleRelation op nowMs before transition) :
    transition.after.globalLiveLeaseCount ≤ 1 := by
  have hAfter := lifecycleRelation_after_wellFormed op nowMs before transition h
  exact hAfter.2.1

theorem lifecycle_submit_preserves_global_live_lease_count (nowMs : Nat)
    (before : LifecycleState) (transition : LifecycleTransition)
    (h : lifecycleRelation .submitHandoff nowMs before transition) :
    transition.after.globalLiveLeaseCount = before.globalLiveLeaseCount := by
  rcases h with ⟨_, hState, _⟩
  rw [lifecycleSubmitStateRelation_eq before transition.after nowMs hState]
  simp [lifecycleSubmitAfter]

theorem lifecycle_submit_has_no_lease (nowMs : Nat) (before : LifecycleState)
    (transition : LifecycleTransition)
    (h : lifecycleRelation .submitHandoff nowMs before transition) :
    transition.after.liveLeaseCount = 0 ∧ transition.after.attempt = 0 ∧
      transition.after.claimSequence = 0 := by
  rcases h with ⟨hPre, hState, _⟩
  rw [lifecycleSubmitStateRelation_eq before transition.after nowMs hState]
  rcases hPre with ⟨_, _, _, _, _, _, hAttempt, _, _, hLiveLease,
    hClaimSequence, _⟩
  simp [lifecycleSubmitAfter, hAttempt, hLiveLease, hClaimSequence]

theorem lifecycle_reservation_preserved (op : LifecycleOp) (nowMs : Nat)
    (before : LifecycleState) (transition : LifecycleTransition)
    (h : lifecycleRelation op nowMs before transition) :
    transition.after.reservationBefore = before.reservationBefore ∧
      transition.after.reservationAfter = before.reservationAfter ∧
      transition.after.proofAttemptsPerBatch = before.proofAttemptsPerBatch := by
  cases op with
  | submitHandoff =>
      rcases h with ⟨_, hState, _⟩
      rw [lifecycleSubmitStateRelation_eq before transition.after nowMs hState]
      simp [lifecycleSubmitAfter]
  | claimNextBatch =>
      rcases h with ⟨_, hState, _⟩
      rw [lifecycleClaimStateRelation_eq before transition.after nowMs hState]
      simp [lifecycleClaimAfter]

theorem lifecycle_step_rejects (op : LifecycleOp) (state : LifecycleState)
    (nowMs : Nat) (h : ¬ lifecyclePrecondition op state nowMs) :
    lifecycleStep op state nowMs = .error .preconditionFailed := by
  cases op with
  | submitHandoff =>
      have h' : ¬ lifecycleSubmitPrecondition state nowMs := by
        simpa [lifecyclePrecondition] using h
      simp [lifecycleStep, h']
  | claimNextBatch =>
      have h' : ¬ lifecycleClaimPrecondition state nowMs := by
        simpa [lifecyclePrecondition] using h
      simp [lifecycleStep, h']

end BlindLedger.Admission
