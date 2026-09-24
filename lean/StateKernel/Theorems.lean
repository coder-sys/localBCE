import StateKernel.ExactKernel

namespace BlindLedger.Semantic

/-!
  This module is the checked theorem boundary for the exact-width evaluator.
  The legacy `BlindLedger.Kernel` model is intentionally not imported here.
  The dependent execution trace is named once and the manifest properties use
  small predicates, avoiding repeated elaboration of the full trace type.
 -/

structure TraceWitness (parts : PartsRaw) (result : SemanticResult) where
  trace : ExactExecutionTrace parts
  verified : verifyPartsTrace parts = .ok trace
  resultEq : trace.result = result

def traceWitness_of_success
    {parts : PartsRaw} {result : SemanticResult}
    (h : verifyParts parts = .ok result) :
    TraceWitness parts result := by
  unfold verifyParts at h
  cases htrace : verifyPartsTrace parts with
  | error error =>
      simp [htrace] at h
      cases h
  | ok trace =>
      simp [htrace] at h
      change (.ok trace.result : Except String SemanticResult) = .ok result at h
      exact {
        trace := trace
        verified := htrace
        resultEq := Except.ok.inj h }

theorem parseFactSet_image_raw
    {data : Bytes} {value : FactSetRaw}
    (h : parseFactSet? data = some value) :
    value.raw = data := by
  unfold parseFactSet? at h
  cases hheader : header? data "BLCFST02".toUTF8 with
  | none => rw [hheader] at h; simp at h
  | some cursor =>
      rw [hheader] at h
      simp at h
      cases hfeed : readBytes? cursor 64 with
      | none => simp [hfeed] at h
      | some feedCursor =>
          simp [hfeed] at h
          cases hcount : readNat? feedCursor.2 4 with
          | none => simp [hcount] at h
          | some countCursor =>
              simp [hcount] at h
              by_cases hcap : 8 < countCursor.1
              · have hnot : ¬ countCursor.1 ≤ 8 := Nat.not_le_of_lt hcap
                exact False.elim (hnot h.1)
              · cases hloops : parseFactsLoop? countCursor.2 countCursor.1 with
                | none => simp [hloops] at h
                | some factsCursor =>
                    simp [hloops] at h
                    cases hfinish : finish? factsCursor.2 with
                    | none => simp [hfinish] at h
                    | some _ =>
                        simp [hfinish] at h
                        by_cases hasc : strictlyAscending (factsCursor.1.map (fun fact => fact.recordId))
                        · by_cases hcanon : factSetCanonical feedCursor.1 factsCursor.1 = data
                          · simp [hasc, hcanon] at h
                            rcases h with ⟨_, hvalue⟩
                            exact (congrArg FactSetRaw.raw hvalue).symm
                          · simp [hasc, hcanon] at h
                            rcases h with ⟨_, ⟨_, hvalue⟩⟩
                            exact (congrArg FactSetRaw.raw hvalue).symm
                        · simp [hasc] at h

theorem evaluation_deterministic_helper
    {input : ExactSemanticInput} {left right : Outcome}
    (hleft : exactEvaluate input = .ok left)
    (hright : exactEvaluate input = .ok right) :
    left = right := by
  have hsame : (Except.ok left : Except String Outcome) = .ok right :=
    hleft.symm.trans hright
  cases hsame
  rfl

theorem exactEvaluate_policy_preserved
    {input : ExactSemanticInput} {base outcome : Outcome}
    (hbase : exactBaseOutcome input = .ok base)
    (heval : exactEvaluate input = .ok outcome) :
    outcome.policy = base.policy := by
  cases hException : input.exception with
  | none =>
      unfold exactEvaluate at heval
      rw [hException] at heval
      rw [hbase] at heval
      simp only [Bind.bind, Except.bind] at heval
      cases hpolicy : directivePolicy base.directive with
      | none =>
          simp [hpolicy] at heval
      | some expected =>
          by_cases hguard : base.policy = expected ∧ equal base.exceptionId SENTINEL = true
          · simp [hpolicy, hguard] at heval
            cases heval
            rfl
          · have hrequire :
                (decide (base.policy = expected) &&
                  equal base.exceptionId SENTINEL) = false := by
              by_cases hpolicyEq : base.policy = expected
              · have hsentinel : equal base.exceptionId SENTINEL ≠ true := by
                  intro hsentinel
                  exact hguard ⟨hpolicyEq, hsentinel⟩
                simp [hpolicyEq, hsentinel]
              · simp [hpolicyEq]
            simp [hpolicy, hrequire] at heval
            cases heval
  | some authorization =>
      unfold exactEvaluate at heval
      rw [hException] at heval
      rw [hbase] at heval
      simp only [Bind.bind, Except.bind] at heval
      cases happly : exactApplyException input base authorization with
      | none =>
          simp [happly] at heval
      | some value =>
          have hscope : exactExceptionScope input base authorization = true := by
            unfold exactApplyException at happly
            split at happly
            · assumption
            · simp_all
          have hbasePolicy : base.policy = 4 := by
            by_cases hpolicy : base.policy = 4
            · exact hpolicy
            · have hscope' := hscope
              simp [exactExceptionScope, hpolicy] at hscope'
          simp [happly] at heval
          cases heval
          simp [exactApplyException, hscope] at happly
          cases happly
          simp [hbasePolicy]

def parseEvaluateTransitionEvidence (parts : PartsRaw)
    (trace : ExactExecutionTrace parts) : Prop :=
  (parseRequest? parts.request = some trace.request ∧
    parseFactSet? parts.facts = some trace.factSet ∧
    parseCompleteness? parts.completeness = some trace.completeness ∧
    parseException? parts.exception = some trace.exception ∧
    parseState? parts.before = some trace.before ∧
    parseState? parts.after = some trace.after ∧
    parseReceipt? parts.receipt = some trace.receipt) ∧
  (exactSemanticInput? trace.request trace.factSet trace.completeness
    trace.exception controlSetIdDerived = some trace.semanticInput ∧
    exactBaseOutcome trace.semanticInput = .ok trace.baseOutcome ∧
    exactEvaluate trace.semanticInput = .ok trace.outcome ∧
    exactAdvance (exactStateOf trace.before none) trace.request.attempt
      trace.receipt.decision.decisionId (sourceRoot parts.facts)
      trace.outcome.directive = some trace.transitioned)

def observeOnlyEvidence {parts : PartsRaw} {result : SemanticResult}
    (witness : TraceWitness parts result) : Prop :=
  exactAccessJoinGuard witness.trace.request witness.trace.before witness.trace.after
    witness.trace.receipt.decision witness.trace.receipt (sourceRoot parts.facts) = true ∧
  result.economicMutation = false

def absenceEvidence {parts : PartsRaw} {result : SemanticResult}
    (witness : TraceWitness parts result) : Prop :=
  witness.trace.semanticInput.completeness.complete = true

def policyEvidence {parts : PartsRaw} {result : SemanticResult}
    (witness : TraceWitness parts result) : Prop :=
  (∃ expectedPolicy, directivePolicy witness.trace.outcome.directive = some expectedPolicy ∧
    exactPolicyDirectiveGuard witness.trace.outcome witness.trace.receipt.decision
      witness.trace.request.raw witness.trace.before witness.trace.after controlSetIdDerived
      (sourceRoot parts.facts) (completenessId witness.trace.completeness.raw) expectedPolicy = true) ∧
  witness.trace.outcome.policy = witness.trace.baseOutcome.policy ∧
  result.policy = witness.trace.outcome.policy

def chronologyEvidence {parts : PartsRaw} {result : SemanticResult}
    (witness : TraceWitness parts result) : Prop :=
  exactRequestBinding witness.trace.semanticInput = true ∧
  exactSemanticWidths witness.trace.semanticInput.request witness.trace.semanticInput.factSet
    witness.trace.semanticInput.completeness witness.trace.semanticInput.exception = true ∧
  strictChronology witness.trace.semanticInput.request = true

theorem verifyParts_success_has_executable_trace
    {parts : PartsRaw} {result : SemanticResult}
    (h : verifyParts parts = .ok result) :
    ∃ trace : ExactExecutionTrace parts,
      verifyPartsTrace parts = .ok trace ∧ trace.result = result := by
  let witness := traceWitness_of_success h
  exact ⟨witness.trace, witness.verified, witness.resultEq⟩

theorem verifyParts_success_executes_parse_evaluate_transition
    {parts : PartsRaw} {result : SemanticResult}
    (h : verifyParts parts = .ok result) :
    ∃ trace : ExactExecutionTrace parts,
      verifyPartsTrace parts = .ok trace ∧ trace.result = result ∧
      parseEvaluateTransitionEvidence parts trace := by
  let witness := traceWitness_of_success h
  refine ⟨witness.trace, witness.verified, witness.resultEq, ?_⟩
  exact ⟨
    ⟨witness.trace.requestParseProof, witness.trace.factSetParseProof,
      witness.trace.completenessParseProof, witness.trace.exceptionParseProof,
      witness.trace.beforeParseProof, witness.trace.afterParseProof,
      witness.trace.receiptParseProof⟩,
    ⟨witness.trace.semanticInputProof, witness.trace.baseEvaluationProof,
      witness.trace.evaluationProof, witness.trace.transitionProof⟩⟩

theorem evaluation_deterministic :
    ∀ {input : ExactSemanticInput} {left right : Outcome},
      exactEvaluate input = .ok left →
      exactEvaluate input = .ok right →
      left = right := by
  intro input left right hleft hright
  exact evaluation_deterministic_helper hleft hright

theorem proof_acceptance_ne_clear
    {parts : PartsRaw} {result : SemanticResult}
    (h : verifyParts parts = .ok result) :
    result.proofSessionAccepted = false ∧ result.economicMutation = false := by
  let witness := traceWitness_of_success h
  constructor
  · rw [← witness.resultEq]
    exact witness.trace.resultFlagsProof.1
  · rw [← witness.resultEq]
    exact witness.trace.resultFlagsProof.2.1

theorem stateless_replay_limitation
    {parts : PartsRaw} {result : SemanticResult}
    (h : verifyParts parts = .ok result) :
    result.replayStateful = false := by
  let witness := traceWitness_of_success h
  rw [← witness.resultEq]
  exact witness.trace.resultFlagsProof.2.2

theorem observe_only_no_operative_clearance
    {parts : PartsRaw} {result : SemanticResult}
    (h : verifyParts parts = .ok result) :
    ∃ witness : TraceWitness parts result, observeOnlyEvidence witness := by
  let witness := traceWitness_of_success h
  refine ⟨witness, ?_⟩
  exact ⟨witness.trace.accessJoinProof, by
    rw [← witness.resultEq]
    exact witness.trace.resultFlagsProof.2.1⟩

theorem absence_requires_authoritative_completeness
    {parts : PartsRaw} {result : SemanticResult}
    (h : verifyParts parts = .ok result) (hdirective : result.directive = 2) :
    ∃ witness : TraceWitness parts result, absenceEvidence witness := by
  let witness := traceWitness_of_success h
  have hdirTrace : witness.trace.result.directive = 2 := by
    rw [witness.resultEq]
    exact hdirective
  have hdirOutcome : witness.trace.outcome.directive = 2 :=
    witness.trace.resultOutcomeProof.2.1.symm.trans hdirTrace
  have hbase : witness.trace.baseOutcome.directive = 2 := by
    simpa [exactBaseDirectiveGuard, hdirOutcome] using witness.trace.baseDirectiveProof
  have habs : exactAuthoritativeAbsence witness.trace.semanticInput = true := by
    simpa [exactAbsenceOutcomeGuard, hbase] using witness.trace.absenceOutcomeProof
  have hparts := habs
  unfold exactAuthoritativeAbsence at hparts
  rw [Bool.and_eq_true] at hparts
  have hfirst := hparts.left
  rw [Bool.and_eq_true] at hfirst
  exact ⟨witness, hfirst.left⟩

theorem policy_effective_separation
    {parts : PartsRaw} {result : SemanticResult}
    (h : verifyParts parts = .ok result) :
    ∃ witness : TraceWitness parts result, policyEvidence witness := by
  let witness := traceWitness_of_success h
  exact ⟨witness, witness.trace.policyDirectiveProof,
    exactEvaluate_policy_preserved witness.trace.baseEvaluationProof
      witness.trace.evaluationProof,
    (congrArg SemanticResult.policy witness.resultEq.symm).trans
      witness.trace.resultOutcomeProof.1⟩

theorem exception_requires_exact_authorization
    {input : ExactSemanticInput} {base : Outcome} {authorization : ExceptionRaw}
    (h : exactExceptionScope input base authorization = true) :
    equal authorization.authorization (authorizationId (authorizationBody authorization.raw)) = true ∧
      equal authorization.signature
        (authorizationSignature authorization.signer (authorizationBody authorization.raw)) = true ∧
      base.policy = 4 ∧
      equal authorization.signer TRUSTED_AUTHORIZER_ID = true ∧
      equal authorization.subject input.request.credential = true ∧
      equal authorization.rule RULE_ID = true ∧
      equal authorization.reason EXPECTED_REASON_ID = true ∧
      equal authorization.amount EXPECTED_AMOUNT_SCOPE = true ∧
      authorization.policy = 4 ∧
      authorization.effectiveAt ≤ input.request.ruleEffective ∧
      authorization.effectiveAt < authorization.expiresAt ∧
      input.request.decision < authorization.expiresAt ∧
      nonzero64 authorization.authorization = true ∧
      nonzero64 authorization.signature = true := by
  simpa [exactExceptionScope, Bool.and_eq_true, and_assoc] using h

theorem nonclear_no_economic_mutation
    {parts : PartsRaw} {result : SemanticResult}
    (h : verifyParts parts = .ok result)
    (_hdirective : result.directive = 2 ∨ result.directive = 3 ∨ result.directive = 4) :
    result.economicMutation = false := by
  let witness := traceWitness_of_success h
  rw [← witness.resultEq]
  exact witness.trace.resultFlagsProof.2.1

theorem wrong_control_set_rejects
    {input : ExactSemanticInput}
    (hcontrol : input.controlSetId ≠ CONTROL_SET_ID) :
    exactBaseOutcome input = .error "control-set" := by
  unfold exactBaseOutcome
  have heq : equal input.controlSetId CONTROL_SET_ID = false := by
    simp [equal, hcontrol]
  simp [heq]

theorem chronology_strict
    {parts : PartsRaw} {result : SemanticResult}
    (h : verifyParts parts = .ok result) :
    ∃ witness : TraceWitness parts result, chronologyEvidence witness := by
  let witness := traceWitness_of_success h
  have hrequest := witness.trace.requestBindingProof
  simp [exactRequestBinding] at hrequest
  exact ⟨witness, witness.trace.requestBindingProof,
    witness.trace.semanticInput.widthProof, hrequest.2⟩

structure ExactAccessShape where
  decisionId : Bytes
  decisionIndex : Nat
  accessIndex : Nat
  accessCount : Nat
  time : Nat
  address : Bytes
  key : Bytes
  before : Bytes
  after : Bytes
  mode : Nat
  deriving DecidableEq

def accessShape (access : AccessRaw) : ExactAccessShape :=
  { decisionId := access.decisionId
    decisionIndex := access.decisionIndex
    accessIndex := access.accessIndex
    accessCount := access.accessCount
    time := access.time
    address := access.address
    key := access.key
    before := access.before
    after := access.after
    mode := access.mode }

structure ExactJoinContext where
  decisionId : Bytes
  provider : Bytes
  subject : Bytes
  sourceRoot : Bytes
  observation : Nat
  decisionTime : Nat
  beforeAudit : Bytes
  afterAudit : Bytes
  deriving DecidableEq

def expectedAccessShapes (context : ExactJoinContext) : List ExactAccessShape :=
  [ { decisionId := context.decisionId
      decisionIndex := 0
      accessIndex := 0
      accessCount := 2
      time := context.observation
      address := sourceAddress context.provider
      key := context.subject
      before := context.sourceRoot
      after := context.sourceRoot
      mode := 1 },
    { decisionId := context.decisionId
      decisionIndex := 0
      accessIndex := 1
      accessCount := 2
      time := context.decisionTime
      address := auditAddress context.provider
      key := context.decisionId
      before := context.beforeAudit
      after := context.afterAudit
      mode := 2 } ]

def exactJoinValid (context : ExactJoinContext) (accesses : List AccessRaw) : Bool :=
  accesses.map accessShape = expectedAccessShapes context

structure ExactDecisionAccessJoin where
  context : ExactJoinContext
  accesses : List AccessRaw
  valid : exactJoinValid context accesses = true

theorem replay_preserves_state
    (state : ExactLedgerState) (attempt decision source : Bytes) (directive : Nat)
    (hreplay : state.lastAttempt = some attempt) :
    exactAdvance state attempt decision source directive = none := by
  simp [exactAdvance, hreplay]

theorem decision_access_join_unique
    {left right : ExactDecisionAccessJoin}
    (hcontext : left.context = right.context) :
    left.accesses.map accessShape = right.accesses.map accessShape := by
  cases left with
  | mk leftContext leftAccesses leftValid =>
      cases right with
      | mk rightContext rightAccesses rightValid =>
          cases hcontext
          have hleft : leftAccesses.map accessShape = expectedAccessShapes leftContext := by
            simpa [exactJoinValid] using leftValid
          have hright : rightAccesses.map accessShape = expectedAccessShapes leftContext := by
            simpa [exactJoinValid] using rightValid
          exact hleft.trans hright.symm

theorem canonical_encoding_injective
    {leftData rightData : Bytes} {left right : FactSetRaw}
    (hleft : parseFactSet? leftData = some left)
    (hright : parseFactSet? rightData = some right)
    (hsame : factSetCanonical left.feed left.facts =
      factSetCanonical right.feed right.facts) :
    left = right := by
  have hleftRaw := parseFactSet_image_raw hleft
  have hrightRaw := parseFactSet_image_raw hright
  have hdata : leftData = rightData := by
    calc
      leftData = left.raw := hleftRaw.symm
      _ = factSetCanonical left.feed left.facts := left.canonicalProof.symm
      _ = factSetCanonical right.feed right.facts := hsame
      _ = right.raw := right.canonicalProof
      _ = rightData := hrightRaw
  have hparsed : parseFactSet? leftData = parseFactSet? rightData := by rw [hdata]
  exact Option.some.inj (hleft.symm.trans (hparsed.trans hright))

theorem decode_encode_roundtrip_and_canonical_encoding_injective :
    (∀ {data : Bytes} {value : FactSetRaw},
      parseFactSet? data = some value →
      factSetCanonical value.feed value.facts = value.raw) ∧
    (∀ {leftData rightData : Bytes} {left right : FactSetRaw},
      parseFactSet? leftData = some left →
      parseFactSet? rightData = some right →
      factSetCanonical left.feed left.facts = factSetCanonical right.feed right.facts →
      left = right) := by
  constructor
  · intro data value hparsed
    exact value.canonicalProof
  · intro leftData rightData left right hleft hright hsame
    exact canonical_encoding_injective hleft hright hsame

structure ExactCheckpoint where
  sequence : Nat
  previous : Bytes
  batch : List Bytes
  next : Bytes
  operative : Bool
  deriving DecidableEq

def exactCheckpointWellFormed (checkpoint : ExactCheckpoint) : Bool :=
  width64 checkpoint.previous && width64 checkpoint.next &&
    checkpoint.batch.length > 0 && checkpoint.operative = false

def exactCheckpointTip : List ExactCheckpoint → Bytes
  | [] => zeros 64
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
    result = chain ++ [checkpoint] ∧ checkpoint.operative = false := by
  unfold appendExactCheckpoint at h
  split at h
  · constructor
    · simpa using h.symm
    · have hvalid : exactCheckpointWellFormed checkpoint = true := by
        simp_all
      have hvalid' := hvalid
      simp [exactCheckpointWellFormed] at hvalid'
      exact hvalid'.2
  · simp_all

theorem state_transition_is_one_successor
    (request : StateRequestRaw) (evidence : SemanticResult)
    (sequence : Nat) (beforeStateId beforeAuditHead beforeRoot : Bytes) :
    (stateOperationFromEvidence request evidence sequence beforeStateId beforeAuditHead beforeRoot).sequenceAfter =
      (stateOperationFromEvidence request evidence sequence beforeStateId beforeAuditHead beforeRoot).sequenceBefore + 1 := by
  rfl

theorem accepted_state_request_has_verified_evidence
    (output : StateKernelOutput) :
    verifyResult output.request.bundle = .ok output.evidence :=
  output.evidenceVerified

theorem state_clearance_flag_matches_allowed_directive
    (directive : Nat) (h : directive ∈ [1, 2, 3, 4, 5]) :
    stateEconomicDirective directive = true ↔ directive = 1 ∨ directive = 5 := by
  simp only [List.mem_cons, List.not_mem_nil, or_false] at h
  rcases h with h | h | h | h | h
  · subst directive
    simp [stateEconomicDirective]
  · subst directive
    simp [stateEconomicDirective]
  · subst directive
    simp [stateEconomicDirective]
  · subst directive
    simp [stateEconomicDirective]
  · subst directive
    simp [stateEconomicDirective]

def theoremManifest : List String :=
  [ "evaluation_deterministic"
    , "verifyParts_success_has_executable_trace"
    , "verifyParts_success_executes_parse_evaluate_transition"
    , "proof_acceptance_ne_clear"
    , "stateless_replay_limitation"
    , "observe_only_no_operative_clearance"
    , "absence_requires_authoritative_completeness"
    , "policy_effective_separation"
    , "exception_requires_exact_authorization"
    , "nonclear_no_economic_mutation"
    , "wrong_control_set_rejects"
    , "chronology_strict"
    , "replay_preserves_state"
    , "decision_access_join_unique"
    , "decode_encode_roundtrip_and_canonical_encoding_injective"
    , "checkpoint_chain_append_only"
    , "state_transition_is_one_successor"
    , "accepted_state_request_has_verified_evidence"
    , "state_clearance_flag_matches_allowed_directive" ]

theorem theoremManifest_count : theoremManifest.length = 19 := by
  rfl

end BlindLedger.Semantic
