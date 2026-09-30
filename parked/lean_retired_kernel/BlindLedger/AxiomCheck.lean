import BlindLedger.Theorems
import BlindLedger.Checkpoint
import BlindLedger.SemanticExecutable

/- Independent environment check.  The guarded checker invocation reads the
   raw output of every named theorem; this file deliberately does not import
   the generated executable artifact or rely on a cached axiom manifest. -/
#print axioms BlindLedger.Semantic.evaluation_deterministic
#print axioms BlindLedger.Semantic.verifyParts_success_has_executable_trace
#print axioms BlindLedger.Semantic.verifyParts_success_executes_parse_evaluate_transition
#print axioms BlindLedger.Semantic.proof_acceptance_ne_clear
#print axioms BlindLedger.Semantic.stateless_replay_limitation
#print axioms BlindLedger.Semantic.observe_only_no_operative_clearance
#print axioms BlindLedger.Semantic.absence_requires_authoritative_completeness
#print axioms BlindLedger.Semantic.policy_effective_separation
#print axioms BlindLedger.Semantic.exception_requires_exact_authorization
#print axioms BlindLedger.Semantic.nonclear_no_economic_mutation
#print axioms BlindLedger.Semantic.wrong_control_set_rejects
#print axioms BlindLedger.Semantic.chronology_strict
#print axioms BlindLedger.Semantic.replay_preserves_state
#print axioms BlindLedger.Semantic.decision_access_join_unique
#print axioms BlindLedger.Semantic.decode_encode_roundtrip_and_canonical_encoding_injective
#print axioms BlindLedger.Semantic.checkpoint_chain_append_only
#print axioms BlindLedger.Semantic.trace_checkpoint_binds_actual_audit
#print axioms BlindLedger.Semantic.exportedRunBytes_corresponds
