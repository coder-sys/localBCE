import BlindLedger.ExactKernel

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

def traceAccesses {parts : PartsRaw} (trace : ExactExecutionTrace parts) : List AccessRaw :=
  [trace.receipt.firstAccess, trace.receipt.secondAccess]

/- The relation is intentionally indexed by the successful executable trace.
   It cannot be satisfied by inventing a separate context and a separate
   valid-by-construction list: the actual receipt, decision, before/after
   state, source root, join digest, and exact access guard all participate. -/
def exactDecisionAccessJoin
    {parts : PartsRaw} (trace : ExactExecutionTrace parts) (accesses : List AccessRaw) : Prop :=
  accesses = traceAccesses trace ∧
    exactReceiptGuard trace.receipt trace.before trace.after controlSetIdDerived
      (sourceRoot parts.facts) = true ∧
    exactAccessJoinGuard trace.request trace.before trace.after trace.receipt.decision
      trace.receipt (sourceRoot parts.facts) = true

theorem replay_preserves_state
    (state : ExactLedgerState) (attempt decision source : Bytes) (directive : Nat)
    (hreplay : state.lastAttempt = some attempt) :
    exactAdvance state attempt decision source directive = none := by
  simp [exactAdvance, hreplay]

theorem decision_access_join_unique
    {parts : PartsRaw} {result : SemanticResult}
    (h : verifyParts parts = .ok result) :
    ∃ trace : ExactExecutionTrace parts,
      verifyPartsTrace parts = .ok trace ∧ trace.result = result ∧
      exactDecisionAccessJoin trace (traceAccesses trace) ∧
      (traceAccesses trace).length = 2 ∧
      (∀ {left right : List AccessRaw},
        exactDecisionAccessJoin trace left →
        exactDecisionAccessJoin trace right →
        left = right ∧ left = traceAccesses trace) := by
  let witness := traceWitness_of_success h
  refine ⟨witness.trace, witness.verified, witness.resultEq, ?_, rfl, ?_⟩
  · exact ⟨rfl, witness.trace.receiptBindingProof, witness.trace.accessJoinProof⟩
  · intro left right hleft hright
    exact ⟨hleft.1.trans hright.1.symm, hleft.1⟩

theorem decode_encode_roundtrip_and_canonical_encoding_injective
    {parts : PartsRaw} {result : SemanticResult}
    (h : verifyParts parts = .ok result) :
    ∃ trace : ExactExecutionTrace parts,
      verifyPartsTrace parts = .ok trace ∧ trace.result = result ∧
      requestEncode trace.request = trace.request.raw ∧
      factSetEncode trace.factSet = trace.factSet.raw ∧
      completenessEncode trace.completeness = trace.completeness.raw ∧
      (match trace.exception with
       | none => exceptionEncode none = SENTINEL
       | some authorization => exceptionEncode (some authorization) = authorization.raw) ∧
      stateEncode trace.before = trace.before.raw ∧
      stateEncode trace.after = trace.after.raw ∧
      decisionEncode trace.receipt.decision = trace.receipt.decision.raw ∧
      accessEncode trace.receipt.firstAccess = trace.receipt.firstAccess.raw ∧
      accessEncode trace.receipt.secondAccess = trace.receipt.secondAccess.raw ∧
      receiptEncode trace.receipt = trace.receipt.raw ∧
      bundleEncode parts = parts.raw ∧
      (∀ {value : RequestRaw},
        parseRequest? parts.request = some value → value = trace.request) ∧
      (∀ {value : FactSetRaw},
        parseFactSet? parts.facts = some value → value = trace.factSet) ∧
      (∀ {value : CompletenessRaw},
        parseCompleteness? parts.completeness = some value → value = trace.completeness) ∧
      (∀ {value : Option ExceptionRaw},
        parseException? parts.exception = some value → value = trace.exception) ∧
      (∀ {value : StateRaw},
        parseState? parts.before = some value → value = trace.before) ∧
      (∀ {value : StateRaw},
        parseState? parts.after = some value → value = trace.after) ∧
      (∀ {value : ReceiptRaw},
        parseReceipt? parts.receipt = some value → value = trace.receipt) := by
  let witness := traceWitness_of_success h
  have hrequest : requestEncode witness.trace.request = witness.trace.request.raw := by
    simpa [requestEncode] using witness.trace.request.canonicalProof
  have hfactSet : factSetEncode witness.trace.factSet = witness.trace.factSet.raw := by
    simpa [factSetEncode] using witness.trace.factSet.canonicalProof
  have hcompleteness : completenessEncode witness.trace.completeness =
      witness.trace.completeness.raw := by
    simpa [completenessEncode] using witness.trace.completeness.canonicalProof
  have hexception :
      (match witness.trace.exception with
       | none => exceptionEncode none = SENTINEL
       | some authorization => exceptionEncode (some authorization) = authorization.raw) := by
    cases hex : witness.trace.exception with
    | none => rfl
    | some authorization =>
        simpa [hex, exceptionEncode] using authorization.canonicalProof
  have hbefore : stateEncode witness.trace.before = witness.trace.before.raw := by
    simpa [stateEncode] using witness.trace.before.canonicalProof
  have hafter : stateEncode witness.trace.after = witness.trace.after.raw := by
    simpa [stateEncode] using witness.trace.after.canonicalProof
  have hdecision : decisionEncode witness.trace.receipt.decision =
      witness.trace.receipt.decision.raw := by
    simpa [decisionEncode] using witness.trace.receipt.decision.canonicalProof
  have hfirst : accessEncode witness.trace.receipt.firstAccess =
      witness.trace.receipt.firstAccess.raw := by
    simpa [accessEncode] using witness.trace.receipt.firstAccess.canonicalProof
  have hsecond : accessEncode witness.trace.receipt.secondAccess =
      witness.trace.receipt.secondAccess.raw := by
    simpa [accessEncode] using witness.trace.receipt.secondAccess.canonicalProof
  have hreceipt : receiptEncode witness.trace.receipt = witness.trace.receipt.raw := by
    simpa [receiptEncode] using witness.trace.receipt.canonicalProof
  have hbundle : bundleEncode parts = parts.raw := by
    simpa [bundleEncode] using parts.canonicalProof
  have hrequestUnique : ∀ {value : RequestRaw},
      parseRequest? parts.request = some value → value = witness.trace.request := by
    intro value hvalue
    exact Option.some.inj (hvalue.symm.trans witness.trace.requestParseProof)
  have hfactSetUnique : ∀ {value : FactSetRaw},
      parseFactSet? parts.facts = some value → value = witness.trace.factSet := by
    intro value hvalue
    exact Option.some.inj (hvalue.symm.trans witness.trace.factSetParseProof)
  have hcompletenessUnique : ∀ {value : CompletenessRaw},
      parseCompleteness? parts.completeness = some value → value = witness.trace.completeness := by
    intro value hvalue
    exact Option.some.inj (hvalue.symm.trans witness.trace.completenessParseProof)
  have hexceptionUnique : ∀ {value : Option ExceptionRaw},
      parseException? parts.exception = some value → value = witness.trace.exception := by
    intro value hvalue
    exact Option.some.inj (hvalue.symm.trans witness.trace.exceptionParseProof)
  have hbeforeUnique : ∀ {value : StateRaw},
      parseState? parts.before = some value → value = witness.trace.before := by
    intro value hvalue
    exact Option.some.inj (hvalue.symm.trans witness.trace.beforeParseProof)
  have hafterUnique : ∀ {value : StateRaw},
      parseState? parts.after = some value → value = witness.trace.after := by
    intro value hvalue
    exact Option.some.inj (hvalue.symm.trans witness.trace.afterParseProof)
  have hreceiptUnique : ∀ {value : ReceiptRaw},
      parseReceipt? parts.receipt = some value → value = witness.trace.receipt := by
    intro value hvalue
    exact Option.some.inj (hvalue.symm.trans witness.trace.receiptParseProof)
  exact ⟨witness.trace, witness.verified, witness.resultEq, hrequest, hfactSet,
    hcompleteness, hexception, hbefore, hafter, hdecision, hfirst, hsecond, hreceipt,
    hbundle, hrequestUnique, hfactSetUnique, hcompletenessUnique, hexceptionUnique,
    hbeforeUnique, hafterUnique, hreceiptUnique⟩

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
    , "exportedRunBytes_corresponds" ]

theorem theoremManifest_count : theoremManifest.length = 17 := by
  rfl

end BlindLedger.Semantic
