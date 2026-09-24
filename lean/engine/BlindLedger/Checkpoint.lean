import BlindLedger.Theorems

namespace BlindLedger.Semantic

/- The checkpoint is an audit commitment only.  The batch is an explicit
   ordered byte sequence, and `next` is required to equal the pure audit-head
   construction used by `exactAdvance`; it is not a payment or clearance
   authority. -/
def exactCheckpointCommitment (previous : Bytes) (batch : List Bytes) : Bytes :=
  digest "BL/NATIVE-V3/CONTINUITY/AUDIT-HEAD/v2"
    (previous :: batch)

def exactCheckpointBatchWellFormed : List Bytes → Bool
  | [] => false
  | head :: tail => head.size > 0 && tail.all (fun value => value.size > 0)

structure ExactCheckpoint where
  sequence : Nat
  previous : Bytes
  batch : List Bytes
  next : Bytes
  operative : Bool
  deriving DecidableEq

def exactCheckpointWellFormed (checkpoint : ExactCheckpoint) : Bool :=
  nonzero64 checkpoint.previous && nonzero64 checkpoint.next &&
    exactCheckpointBatchWellFormed checkpoint.batch &&
    equal checkpoint.next (exactCheckpointCommitment checkpoint.previous checkpoint.batch) &&
    checkpoint.operative = false

def exactCheckpointTip : List ExactCheckpoint → Bytes
  | [] => EMPTY_AUDIT
  | checkpoint :: rest =>
      match rest with
      | [] => checkpoint.next
      | _ => exactCheckpointTip rest

def appendExactCheckpoint
    (chain : List ExactCheckpoint) (checkpoint : ExactCheckpoint) :
    Option (List ExactCheckpoint) :=
  if exactCheckpointWellFormed checkpoint &&
      checkpoint.sequence = chain.length &&
      checkpoint.previous = exactCheckpointTip chain then
    some (chain ++ [checkpoint])
  else
    none

theorem checkpoint_chain_append_only
    {chain result : List ExactCheckpoint} {checkpoint : ExactCheckpoint}
    (h : appendExactCheckpoint chain checkpoint = some result) :
    result = chain ++ [checkpoint] ∧ checkpoint.operative = false ∧
      exactCheckpointWellFormed checkpoint = true ∧
      checkpoint.sequence = chain.length ∧
      checkpoint.previous = exactCheckpointTip chain ∧
      exactCheckpointBatchWellFormed checkpoint.batch = true ∧
      checkpoint.next = exactCheckpointCommitment checkpoint.previous checkpoint.batch := by
  unfold appendExactCheckpoint at h
  split at h
  · have hvalid : exactCheckpointWellFormed checkpoint = true := by
      simp_all
    have hvalid' := hvalid
    simp [exactCheckpointWellFormed, Bool.and_eq_true] at hvalid'
    have hcommitment : checkpoint.next =
        exactCheckpointCommitment checkpoint.previous checkpoint.batch := by
      exact of_decide_eq_true hvalid'.left.right
    refine ⟨?_, hvalid'.right, hvalid, ?_, ?_, hvalid'.left.left.right, hcommitment⟩
    · simpa using h.symm
    · simp_all
    · simp_all
  · simp_all

def exactTraceAuditCheckpoint {parts : PartsRaw} (trace : ExactExecutionTrace parts) :
    ExactCheckpoint :=
  { sequence := trace.before.sequence
    previous := trace.before.audit
    batch := [trace.receipt.decision.decisionId, oneByte trace.outcome.directive]
    next := trace.after.audit
    operative := false }

theorem trace_transition_audit {parts : PartsRaw} (trace : ExactExecutionTrace parts) :
    trace.transitioned.audit =
      auditAfter trace.before.audit trace.receipt.decision.decisionId trace.outcome.directive := by
  have htransition := trace.transitionProof
  unfold exactAdvance at htransition
  split at htransition
  · simp_all
  · split at htransition
    · simp_all
    · split at htransition
      · simp_all
      · have hstate := Option.some.inj htransition
        have haudit := congrArg ExactLedgerState.audit hstate
        simpa [exactStateOf] using haudit.symm

theorem trace_guard_audit {parts : PartsRaw} (trace : ExactExecutionTrace parts) :
    trace.after.audit = trace.transitioned.audit := by
  have hguard := trace.transitionBindingProof
  simp [exactTransitionGuard, equal, stateRawOf, Bool.and_eq_true] at hguard
  have ha := hguard.left.left.left.left.left.left
  exact of_decide_eq_true ha

theorem trace_before_checkpoint_properties {parts : PartsRaw}
    (trace : ExactExecutionTrace parts) :
    trace.before.sequence = 0 ∧ trace.before.audit = EMPTY_AUDIT ∧
      nonzero64 trace.before.audit = true := by
  have hbefore := trace.beforeStateProof
  simp [exactBeforeStateGuard, equal, Bool.and_eq_true] at hbefore
  exact ⟨hbefore.1.1.1.1.1.2, hbefore.1.1.1.2, hbefore.2⟩

theorem trace_after_audit_nonzero {parts : PartsRaw} (trace : ExactExecutionTrace parts) :
    nonzero64 trace.after.audit = true := by
  have hafter := trace.afterStateProof
  simp [exactAfterStateGuard, Bool.and_eq_true] at hafter
  exact hafter.2

theorem trace_decision_nonzero {parts : PartsRaw} (trace : ExactExecutionTrace parts) :
    nonzero64 trace.receipt.decision.decisionId = true := by
  have hreceipt := trace.receiptBindingProof
  simp [exactReceiptGuard, Bool.and_eq_true] at hreceipt
  exact hreceipt.2

theorem trace_decision_width {parts : PartsRaw} (trace : ExactExecutionTrace parts) :
    trace.receipt.decision.decisionId.size = 64 := by
  have h := trace_decision_nonzero trace
  simp [nonzero64, Bool.and_eq_true] at h
  exact h.1

theorem trace_checkpoint_batch_well_formed {parts : PartsRaw}
    (trace : ExactExecutionTrace parts) :
    exactCheckpointBatchWellFormed
      [trace.receipt.decision.decisionId, oneByte trace.outcome.directive] = true := by
  have hone : (oneByte trace.outcome.directive).size = 1 := by
    simp [oneByte, ByteArray.size, Array.size]
  simp [exactCheckpointBatchWellFormed, trace_decision_width trace, hone]

theorem trace_checkpoint_well_formed {parts : PartsRaw}
    (trace : ExactExecutionTrace parts)
    (haudit : trace.after.audit =
      auditAfter trace.before.audit trace.receipt.decision.decisionId trace.outcome.directive) :
    exactCheckpointWellFormed (exactTraceAuditCheckpoint trace) = true := by
  have hbefore := trace_before_checkpoint_properties trace
  have hafter := trace_after_audit_nonzero trace
  have hbatch := trace_checkpoint_batch_well_formed trace
  have hafter' : nonzero64
      (auditAfter trace.before.audit trace.receipt.decision.decisionId trace.outcome.directive) = true := by
    rw [← haudit]
    exact hafter
  have hafter'' : nonzero64
      (digest "BL/NATIVE-V3/CONTINUITY/AUDIT-HEAD/v2"
        [trace.before.audit, trace.receipt.decision.decisionId,
          oneByte trace.outcome.directive]) = true := by
    simpa [auditAfter] using hafter'
  simp [exactTraceAuditCheckpoint, exactCheckpointWellFormed,
    exactCheckpointCommitment, auditAfter, equal, haudit, hbefore.2.2,
    hafter'', hbatch]

theorem trace_checkpoint_append {parts : PartsRaw} (trace : ExactExecutionTrace parts)
    (hcheckpoint : exactCheckpointWellFormed (exactTraceAuditCheckpoint trace) = true) :
    appendExactCheckpoint [] (exactTraceAuditCheckpoint trace) =
      some [exactTraceAuditCheckpoint trace] := by
  have hbefore := trace_before_checkpoint_properties trace
  have hsequence : (exactTraceAuditCheckpoint trace).sequence = 0 := by
    simpa [exactTraceAuditCheckpoint] using hbefore.1
  have hprevious : (exactTraceAuditCheckpoint trace).previous = EMPTY_AUDIT := by
    simpa [exactTraceAuditCheckpoint] using hbefore.2.1
  simp [appendExactCheckpoint, exactCheckpointTip, hcheckpoint,
    hsequence, hprevious]

set_option maxHeartbeats 800000 in
theorem trace_checkpoint_binds_actual_audit
    {parts : PartsRaw} {result : SemanticResult}
    (h : verifyParts parts = .ok result) :
    ∃ trace : ExactExecutionTrace parts,
      verifyPartsTrace parts = .ok trace ∧ trace.result = result ∧
      exactCheckpointWellFormed (exactTraceAuditCheckpoint trace) = true ∧
      (exactTraceAuditCheckpoint trace).previous = trace.before.audit ∧
      (exactTraceAuditCheckpoint trace).next = trace.after.audit ∧
      (exactTraceAuditCheckpoint trace).batch =
        [trace.receipt.decision.decisionId, oneByte trace.outcome.directive] ∧
      (exactTraceAuditCheckpoint trace).operative = false ∧
      appendExactCheckpoint [] (exactTraceAuditCheckpoint trace) =
        some [exactTraceAuditCheckpoint trace] := by
  rcases verifyParts_success_has_executable_trace h with ⟨trace, htrace, hresult⟩
  have haudit : trace.after.audit =
      auditAfter trace.before.audit trace.receipt.decision.decisionId trace.outcome.directive :=
    (trace_guard_audit trace).trans (trace_transition_audit trace)
  have hcheckpoint := trace_checkpoint_well_formed trace haudit
  have happend := trace_checkpoint_append trace hcheckpoint
  refine ⟨trace, htrace, hresult, hcheckpoint, rfl, rfl, rfl, rfl, happend⟩

end BlindLedger.Semantic
