import Admission.LifecycleProofs

namespace BlindLedger.Admission

def lifecycleCaseBytes (length : Nat) : LifecycleBytes :=
  List.replicate length (UInt8.ofNat 1)

def lifecycleCaseSecondBytes (length : Nat) : LifecycleBytes :=
  UInt8.ofNat 2 :: List.replicate (length - 1) (UInt8.ofNat 1)

def lifecycleCaseConfig : LifecycleConfig :=
  { schemaVersion := 13
    profileEpoch := 12
    profileToken := lifecycleProfileToken
    sourceAuthProfile := lifecycleSourceAuthProfile
    compositionVersion := 4
    sourceKeyEpoch := 1
    admissionTimeoutMs := 3_000
    leaseDurationMs := 60_000
    queueId := "profile12-focused"
    configDigest := lifecycleCaseBytes 64 }

def lifecycleCaseIdentity : LifecycleIdentity :=
  { batchId := lifecycleCaseBytes 32
    batchRoot := lifecycleCaseBytes 64
    sessionRef := lifecycleCaseBytes 64
    publicCoin := lifecycleCaseBytes 96
    proofContext := lifecycleCaseBytes 64
    identityDigest := lifecycleCaseBytes 64
    assertionIdentifier := "profile12-assertion"
    assertionVersion := 1
    stateProfileVersion := lifecycleProfileToken
    approvedSourceRegistryRoot := some (lifecycleCaseBytes 64)
    qualificationFlags := lifecycleCaseBytes 4
    memberCount := 100
    admissionSeq := 1 }

def lifecycleCaseSecondIdentity : LifecycleIdentity :=
  { lifecycleCaseIdentity with
    batchId := lifecycleCaseSecondBytes 32
    identityDigest := lifecycleCaseSecondBytes 64
    admissionSeq := 2 }

def lifecycleCaseAccounting : LifecycleAccounting :=
  { proof := { used := 101, cap := lifecycleProofAttemptsCap }
    sourceA := { used := 0, cap := lifecycleProofAttemptsCap }
    sourceS := { used := 0, cap := lifecycleProofAttemptsCap }
    sourceM := { used := 0, cap := lifecycleProofAttemptsCap }
    sourceU := { used := 1, cap := lifecycleProofAttemptsCap }
    verifierV := { used := 0, cap := lifecycleProofAttemptsCap } }

def lifecycleCaseSecondAccounting : LifecycleAccounting :=
  { proof := { used := 202, cap := lifecycleProofAttemptsCap }
    sourceA := { used := 0, cap := lifecycleProofAttemptsCap }
    sourceS := { used := 0, cap := lifecycleProofAttemptsCap }
    sourceM := { used := 0, cap := lifecycleProofAttemptsCap }
    sourceU := { used := 2, cap := lifecycleProofAttemptsCap }
    verifierV := { used := 0, cap := lifecycleProofAttemptsCap } }

def lifecycleCaseAwaiting : LifecycleState :=
  { config := lifecycleCaseConfig
    identity := lifecycleCaseIdentity
    batch := .awaiting
    source := .absent
    verifier := .unreserved
    terminal := .none
    validFromMs := 100
    validUntilMs := 1_000
    nextEligibleMs := 0
    updatedMs := 100
    attempt := 0
    attemptId := 1
    attemptStatus := .reserved
    verifierVUpper := 1
    globalLiveLeaseCount := 0
    liveLeaseCount := 0
    leaseExpiresMs := 0
    claimSequence := 0
    transitionSequence := 1
    reservationBefore := 0
    reservationAfter := 101
    proofAttemptsPerBatch := 101
    attemptSourceKeyEpoch := 1
    handoffAttached := false
    accounting := lifecycleCaseAccounting }

def lifecycleCaseQueued : LifecycleState :=
  lifecycleSubmitAfter lifecycleCaseAwaiting 200

def lifecycleCaseLeased : LifecycleState :=
  lifecycleClaimAfter lifecycleCaseQueued 250

def lifecycleCaseCompletedSource : LifecycleState :=
  { lifecycleCaseAwaiting with
    source := .completed
    accounting :=
      { lifecycleCaseAccounting with
        sourceA := { used := 1, cap := lifecycleProofAttemptsCap }
        sourceS := { used := 4_096, cap := lifecycleProofAttemptsCap }
        sourceM := { used := 100, cap := lifecycleProofAttemptsCap } } }

def lifecycleCaseCompletedQueued : LifecycleState :=
  lifecycleSubmitAfter lifecycleCaseCompletedSource 200

def lifecycleCaseSecondAwaiting : LifecycleState :=
  { lifecycleCaseAwaiting with
    identity := lifecycleCaseSecondIdentity
    attemptId := 2
    transitionSequence := 2
    updatedMs := 150
    reservationBefore := 101
    reservationAfter := 202
    accounting := lifecycleCaseSecondAccounting }

def lifecycleCaseSecondQueued : LifecycleState :=
  lifecycleSubmitAfter lifecycleCaseSecondAwaiting 250

def lifecycleCaseSecondLeased : LifecycleState :=
  lifecycleClaimAfter lifecycleCaseSecondQueued 300

/- Timeline: issue1/submit1/claim1 use sequences 1/2/3; issue2 is sequence 4.
   The second batch is still locally unleased while the first batch owns the
   one global queue lease. -/
def lifecycleCaseSecondAwaitingWhileFirstLeased : LifecycleState :=
  { lifecycleCaseSecondAwaiting with
    globalLiveLeaseCount := lifecycleCaseLeased.globalLiveLeaseCount
    transitionSequence := lifecycleCaseLeased.transitionSequence + 1
    updatedMs := 350 }

def lifecycleCaseSecondQueuedWhileFirstLeased : LifecycleState :=
  lifecycleSubmitAfter lifecycleCaseSecondAwaitingWhileFirstLeased 400

/- The first batch remains claimable after a later batch has reserved [101,202]. -/
def lifecycleCaseFirstQueuedWithLaterReservation : LifecycleState :=
  { lifecycleSubmitAfter lifecycleCaseAwaiting 350 with
    transitionSequence := 3
    accounting := lifecycleCaseSecondAccounting }

def lifecycleCaseSecondQueuedTogether : LifecycleState :=
  { lifecycleCaseSecondQueued with transitionSequence := 4 }

def lifecycleCaseSecondCompletedSource : LifecycleState :=
  { lifecycleCaseSecondAwaiting with source := .completed }

def lifecycleCaseSecondCompletedQueued : LifecycleState :=
  lifecycleSubmitAfter lifecycleCaseSecondCompletedSource 350

def lifecycleCaseBoundaryAdmissionSeq : Nat :=
  lifecycleProofAttemptsCap / lifecycleProofAttemptsPerBatch

def lifecycleCaseBoundaryIdentity : LifecycleIdentity :=
  { lifecycleCaseIdentity with
    batchId := lifecycleCaseSecondBytes 32
    identityDigest := lifecycleCaseSecondBytes 64
    admissionSeq := lifecycleCaseBoundaryAdmissionSeq }

def lifecycleCaseBoundaryAccounting : LifecycleAccounting :=
  { lifecycleCaseSecondAccounting with
    proof :=
      { used := lifecycleCaseBoundaryAdmissionSeq * lifecycleProofAttemptsPerBatch
        cap := lifecycleProofAttemptsCap }
    sourceU :=
      { used := lifecycleCaseBoundaryAdmissionSeq
        cap := lifecycleProofAttemptsCap } }

def lifecycleCaseBoundaryAwaiting : LifecycleState :=
  { lifecycleCaseAwaiting with
    identity := lifecycleCaseBoundaryIdentity
    attemptId := lifecycleCaseBoundaryAdmissionSeq
    transitionSequence := 1
    reservationBefore :=
      (lifecycleCaseBoundaryAdmissionSeq - 1) * lifecycleProofAttemptsPerBatch
    reservationAfter :=
      lifecycleCaseBoundaryAdmissionSeq * lifecycleProofAttemptsPerBatch
    accounting := lifecycleCaseBoundaryAccounting }

def lifecycleCaseMismatchedAttemptId : LifecycleState :=
  { lifecycleCaseAwaiting with attemptId := 2 }

def lifecycleCaseForgedReservation : LifecycleState :=
  { lifecycleCaseAwaiting with reservationBefore := 7, reservationAfter := 108 }

def lifecycleCaseOverCapIdentity : LifecycleIdentity :=
  { lifecycleCaseBoundaryIdentity with
    admissionSeq := lifecycleCaseBoundaryAdmissionSeq + 1 }

def lifecycleCaseOverCap : LifecycleState :=
  { lifecycleCaseBoundaryAwaiting with
    identity := lifecycleCaseOverCapIdentity
    attemptId := lifecycleCaseBoundaryAdmissionSeq + 1
    reservationBefore := lifecycleCaseBoundaryAdmissionSeq * lifecycleProofAttemptsPerBatch
    reservationAfter :=
      (lifecycleCaseBoundaryAdmissionSeq + 1) * lifecycleProofAttemptsPerBatch }

def lifecycleCaseSubmitTransition : LifecycleTransition :=
  { after := lifecycleCaseQueued
    event := lifecycleSubmitEvent lifecycleCaseAwaiting 200 }

def lifecycleCaseClaimTransition : LifecycleTransition :=
  { after := lifecycleCaseLeased
    event := lifecycleClaimEvent lifecycleCaseQueued 250 }

def lifecycleCaseSecondClaimTransition : LifecycleTransition :=
  { after := lifecycleCaseSecondLeased
    event := lifecycleClaimEvent lifecycleCaseSecondQueued 300 }

def lifecycleCaseSecondSubmitWhileFirstLeasedTransition : LifecycleTransition :=
  { after := lifecycleCaseSecondQueuedWhileFirstLeased
    event := lifecycleSubmitEvent lifecycleCaseSecondAwaitingWhileFirstLeased 400 }

example : lifecycleCaseAwaiting.WellFormed := by
  decide

example : lifecycleCaseSecondAwaiting.WellFormed := by
  decide

example : lifecycleCaseSecondAwaitingWhileFirstLeased.WellFormed := by
  decide

example : lifecycleSubmitPrecondition lifecycleCaseSecondAwaitingWhileFirstLeased 400 := by
  decide

example : lifecycleStep .submitHandoff lifecycleCaseSecondAwaitingWhileFirstLeased 400 =
    .ok lifecycleCaseSecondSubmitWhileFirstLeasedTransition := by
  decide

example : ¬ lifecycleClaimPrecondition lifecycleCaseSecondQueuedWhileFirstLeased 500 := by
  decide

example : lifecycleStep .claimNextBatch lifecycleCaseSecondQueuedWhileFirstLeased 500 =
    .error .preconditionFailed := by
  decide

example : lifecycleCaseBoundaryAwaiting.WellFormed := by
  decide

example : lifecycleSubmitPrecondition lifecycleCaseAwaiting 200 := by
  decide

example : lifecycleStep .submitHandoff lifecycleCaseAwaiting 200 =
    .ok lifecycleCaseSubmitTransition := by
  decide

example : lifecycleClaimPrecondition lifecycleCaseQueued 250 := by
  decide

example : lifecycleStep .claimNextBatch lifecycleCaseQueued 250 =
    .ok lifecycleCaseClaimTransition := by
  decide

example : lifecycleStep .claimNextBatch lifecycleCaseSecondQueued 300 =
    .ok lifecycleCaseSecondClaimTransition := by
  decide

example : lifecycleCaseFirstQueuedWithLaterReservation.WellFormed := by
  decide

example : lifecycleClaimPrecondition lifecycleCaseFirstQueuedWithLaterReservation 400 := by
  decide

example : lifecycleClaimPrecondition lifecycleCaseSecondQueuedTogether 500 := by
  decide

example : lifecycleCaseSecondCompletedQueued.WellFormed := by
  decide

example : lifecycleClaimPrecondition lifecycleCaseSecondCompletedQueued 400 := by
  decide

example : lifecycleEventWellFormed (lifecycleIssueEvent lifecycleCaseAwaiting) := by
  decide

example : lifecycleIssueEventRelation lifecycleCaseAwaiting
    (lifecycleIssueEvent lifecycleCaseAwaiting) := by
  decide

example : lifecycleEventWellFormed lifecycleCaseSubmitTransition.event := by
  decide

example : lifecycleEventWellFormed lifecycleCaseClaimTransition.event := by
  decide

example : ¬ lifecycleCaseMismatchedAttemptId.WellFormed := by
  decide

example : ¬ lifecycleCaseForgedReservation.WellFormed := by
  decide

example : ¬ lifecycleCaseOverCap.WellFormed := by
  decide

example : lifecycleStep .submitHandoff lifecycleCaseMismatchedAttemptId 200 =
    .error .preconditionFailed := by
  decide

example : lifecycleStep .submitHandoff lifecycleCaseForgedReservation 200 =
    .error .preconditionFailed := by
  decide

example : lifecycleStep .submitHandoff lifecycleCaseOverCap 200 =
    .error .preconditionFailed := by
  decide

example : lifecycleStep .submitHandoff lifecycleCaseQueued 300 =
    .error .preconditionFailed := by
  decide

example : lifecycleStep .claimNextBatch lifecycleCaseAwaiting 200 =
    .error .preconditionFailed := by
  decide

example : lifecycleStep .claimNextBatch lifecycleCaseQueued 1_000 =
    .error .preconditionFailed := by
  decide

example : lifecycleStep .claimNextBatch lifecycleCaseLeased 300 =
    .error .preconditionFailed := by
  decide

def lifecycleCaseChecks : List (String × Bool) :=
  [ ("awaiting_well_formed", decide lifecycleCaseAwaiting.WellFormed)
  , ("issue_event_sequence_one", decide ((lifecycleIssueEvent lifecycleCaseAwaiting).sequence = 1))
  , ("issue_event_identity_reservation_bound", decide
      (lifecycleIssueEventRelation lifecycleCaseAwaiting (lifecycleIssueEvent lifecycleCaseAwaiting)))
  , ("issue_event_well_formed", decide
      (lifecycleEventWellFormed (lifecycleIssueEvent lifecycleCaseAwaiting)))
  , ("first_global_proof_101", decide (lifecycleCaseAwaiting.accounting.proof.used = 101))
  , ("first_global_u_1", decide (lifecycleCaseAwaiting.accounting.sourceU.used = 1))
  , ("submit_absent_source", decide (lifecycleSubmitPrecondition lifecycleCaseAwaiting 200))
  , ("submit_to_queued", decide (lifecycleStep .submitHandoff lifecycleCaseAwaiting 200 =
      .ok lifecycleCaseSubmitTransition))
  , ("submit_event_kind", decide (lifecycleCaseSubmitTransition.event.kind = .handoffSubmitted))
  , ("submit_event_status", decide (lifecycleCaseSubmitTransition.event.status = .queued))
  , ("submit_event_relation", decide
      (lifecycleSubmitEventRelation lifecycleCaseAwaiting 200 lifecycleCaseSubmitTransition.event))
  , ("submit_event_sequence_two", decide (lifecycleCaseSubmitTransition.event.sequence = 2))
  , ("queued_status", decide (lifecycleCaseQueued.batch = .queued))
  , ("handoff_attached", decide (lifecycleCaseQueued.handoffAttached = true))
  , ("submit_updates_eligibility", decide (lifecycleCaseQueued.nextEligibleMs = 200))
  , ("claim_ready", decide (lifecycleClaimPrecondition lifecycleCaseQueued 250))
  , ("claim_to_leased", decide (lifecycleStep .claimNextBatch lifecycleCaseQueued 250 =
      .ok lifecycleCaseClaimTransition))
  , ("claim_event_kind", decide (lifecycleCaseClaimTransition.event.kind = .verificationStarted))
  , ("claim_event_status", decide (lifecycleCaseClaimTransition.event.status = .leased))
  , ("claim_event_relation", decide
      (lifecycleClaimEventRelation lifecycleCaseQueued 250 lifecycleCaseClaimTransition.event))
  , ("claim_event_sequence_three", decide (lifecycleCaseClaimTransition.event.sequence = 3))
  , ("first_claim_sets_global_lease", decide (lifecycleCaseLeased.globalLiveLeaseCount = 1))
  , ("single_lease", decide (lifecycleCaseLeased.liveLeaseCount = 1))
  , ("claim_attempt_one", decide (lifecycleCaseLeased.attempt = 1))
  , ("attempt_id_bound", decide (lifecycleCaseLeased.attemptId = lifecycleCaseLeased.identity.admissionSeq))
  , ("attempt_reserved", decide (lifecycleCaseLeased.attemptStatus = .reserved))
  , ("verifier_upper_one", decide (lifecycleCaseLeased.verifierVUpper = 1))
  , ("claim_expiry_sixty_seconds", decide (lifecycleCaseLeased.leaseExpiresMs = 60_250))
  , ("reservation_101", decide (lifecycleCaseLeased.reservationBefore = 0 ∧
      lifecycleCaseLeased.reservationAfter = 101))
  , ("no_proof_refund", decide (lifecycleCaseLeased.accounting.proof.used = 101))
  , ("identity_preserved", decide (lifecycleCaseLeased.identity = lifecycleCaseQueued.identity))
  , ("completed_source_allowed", decide (lifecycleStep .submitHandoff lifecycleCaseCompletedSource 200 =
      .ok { after := lifecycleCaseCompletedQueued
            event := lifecycleSubmitEvent lifecycleCaseCompletedSource 200 }))
  , ("completed_source_accounting_preserved", decide
      (lifecycleCaseCompletedQueued.accounting = lifecycleCaseCompletedSource.accounting))
  , ("second_well_formed", decide lifecycleCaseSecondAwaiting.WellFormed)
  , ("second_global_proof_202", decide (lifecycleCaseSecondAwaiting.accounting.proof.used = 202))
  , ("second_global_u_2", decide (lifecycleCaseSecondAwaiting.accounting.sourceU.used = 2))
  , ("second_exact_interval", decide
      (lifecycleCaseSecondAwaiting.reservationBefore = 101 ∧
        lifecycleCaseSecondAwaiting.reservationAfter = 202))
  , ("second_attempt_id_bound", decide
      (lifecycleCaseSecondAwaiting.attemptId = lifecycleCaseSecondAwaiting.identity.admissionSeq))
  , ("second_local_lease_empty_during_first_lease", decide
      (lifecycleCaseSecondAwaitingWhileFirstLeased.globalLiveLeaseCount = 1 ∧
        lifecycleCaseSecondAwaitingWhileFirstLeased.liveLeaseCount = 0 ∧
        lifecycleCaseSecondAwaitingWhileFirstLeased.claimSequence = 0 ∧
        lifecycleCaseSecondAwaitingWhileFirstLeased.leaseExpiresMs = 0))
  , ("second_submit_permitted_with_unrelated_global_lease", decide
      (lifecycleSubmitPrecondition lifecycleCaseSecondAwaitingWhileFirstLeased 400))
  , ("second_submit_preserves_global_lease", decide
      (lifecycleCaseSecondQueuedWhileFirstLeased.globalLiveLeaseCount = 1))
  , ("second_submit_expected_transition", decide
      (lifecycleStep .submitHandoff lifecycleCaseSecondAwaitingWhileFirstLeased 400 =
        .ok lifecycleCaseSecondSubmitWhileFirstLeasedTransition))
  , ("second_submit_event_sequence_five", decide
      (lifecycleCaseSecondSubmitWhileFirstLeasedTransition.event.sequence = 5))
  , ("second_submit_accounting_preserved", decide
      (lifecycleCaseSecondQueuedWhileFirstLeased.accounting.proof.used = 202 ∧
        lifecycleCaseSecondQueuedWhileFirstLeased.accounting.sourceU.used = 2))
  , ("second_claim_blocked_by_global_lease", decide
      (¬ lifecycleClaimPrecondition lifecycleCaseSecondQueuedWhileFirstLeased 500))
  , ("second_claim_step_rejected_while_first_lease_live", decide
      (lifecycleStep .claimNextBatch lifecycleCaseSecondQueuedWhileFirstLeased 500 =
        .error .preconditionFailed))
  , ("second_claim_valid", decide (lifecycleClaimPrecondition lifecycleCaseSecondQueued 300))
  , ("oldest_claim_preserves_later_global_reservation", decide
      (lifecycleCaseFirstQueuedWithLaterReservation.accounting.proof.used = 202 ∧
        lifecycleCaseFirstQueuedWithLaterReservation.reservationAfter = 101 ∧
        lifecycleClaimPrecondition lifecycleCaseFirstQueuedWithLaterReservation 400))
  , ("two_queued_order_is_oldest_first", decide
      (lifecycleCaseFirstQueuedWithLaterReservation.identity.admissionSeq <
        lifecycleCaseSecondQueuedTogether.identity.admissionSeq))
  , ("two_queued_second_also_valid", decide
      (lifecycleClaimPrecondition lifecycleCaseSecondQueuedTogether 500))
  , ("terminal_source_later_issue_valid", decide lifecycleCaseSecondCompletedQueued.WellFormed)
  , ("boundary_admission_seq", decide
      (lifecycleCaseBoundaryAdmissionSeq * lifecycleProofAttemptsPerBatch ≤ lifecycleProofAttemptsCap))
  , ("boundary_state_valid", decide lifecycleCaseBoundaryAwaiting.WellFormed)
  , ("mismatched_attempt_id_rejected", decide
      (lifecycleStep .submitHandoff lifecycleCaseMismatchedAttemptId 200 =
        .error .preconditionFailed))
  , ("forged_interval_rejected", decide
      (lifecycleStep .submitHandoff lifecycleCaseForgedReservation 200 =
        .error .preconditionFailed))
  , ("over_cap_rejected", decide
      (lifecycleStep .submitHandoff lifecycleCaseOverCap 200 =
        .error .preconditionFailed))
  , ("duplicate_handoff_rejected", decide (lifecycleStep .submitHandoff lifecycleCaseQueued 300 =
      .error .preconditionFailed))
  , ("claim_before_handoff_rejected", decide (lifecycleStep .claimNextBatch lifecycleCaseAwaiting 200 =
      .error .preconditionFailed))
  , ("expired_claim_rejected", decide (lifecycleStep .claimNextBatch lifecycleCaseQueued 1_000 =
      .error .preconditionFailed))
  , ("active_lease_rejected", decide (lifecycleStep .claimNextBatch lifecycleCaseLeased 300 =
      .error .preconditionFailed))
  , ("constant_schema_13", decide (lifecycleSchemaVersion = 13))
  , ("constant_profile_12", decide (lifecycleProfileVersion = 12))
  , ("constant_composition_4", decide (lifecycleCompositionVersion = 4))
  , ("constant_member_count_100", decide (lifecycleMemberCount = 100))
  , ("constant_reservation_101", decide (lifecycleProofAttemptsPerBatch = 101))
  , ("constant_max_attempts_one", decide (lifecycleMaxAttempts = 1))
  , ("constant_admission_timeout_3s", decide (lifecycleLeanAdmissionTimeoutMs = 3_000))
  , ("constant_queue_lease_60s", decide (lifecycleLeaseDurationMs = 60_000)) ]

def lifecycleCaseFailures : List String :=
  lifecycleCaseChecks.filterMap (fun item => if item.2 then none else some item.1)

def main : IO Unit := do
  let failures := lifecycleCaseFailures
  if failures.isEmpty then
    IO.println s!"LIFECYCLE_CASES=PASS cases={lifecycleCaseChecks.length}"
  else
    let message := s!"LIFECYCLE_CASES=FAIL cases={lifecycleCaseChecks.length} failures={failures}"
    IO.println message
    throw (IO.userError message)

end BlindLedger.Admission

def main : IO Unit := BlindLedger.Admission.main
