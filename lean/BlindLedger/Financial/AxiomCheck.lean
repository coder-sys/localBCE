import BlindLedger.Financial.Executable
import BlindLedger.Financial.CodecLaws
import BlindLedger.Financial.CodecLawsCheck
import BlindLedger.Financial.CodecLaws.Correction
import BlindLedger.Financial.CorrectionTransition.PaidSumTheorems
import BlindLedger.Financial.WorkerLaws
import BlindLedger.Financial.BatchLaws
import BlindLedger.Financial.CursorDifferential
import BlindLedger.Financial.Theorems.Conservation
import BlindLedger.Financial.CorrectionTransition.Theorems.Core
import BlindLedger.Financial.Payment.Bridge
import BlindLedger.Financial.Payment.CodecLaws
import BlindLedger.Financial.Payment.KAT
import BlindLedger.Financial.Payment.OpenLaws
import BlindLedger.Financial.DecisionPackage.Laws

namespace BlindLedger.Financial

/-! `#guard_msgs` fails this build if a pinned theorem's dependency set changes.  The 17 theorems the
    semantic assurance gate checks (its manifest, `--trust=0` axiom stage) are printed, not pinned: the gate
    is their one authority.  29 of the 66 rest on a `native_decide` axiom, `authorized_kat_is_correct`
    through `evaluator_corresponds_to_independent_specification`.  All 10 `WorkerLaws` theorems are pinned (build
    `kd-dev3`); the codec and decoder equalities among the printed ones are not `WorkerLaws`. -/

/-- info: 'BlindLedger.Financial.evaluation_deterministic' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.evaluation_deterministic
/-- info: 'BlindLedger.Financial.evaluateWellFormed_matches_specification' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.evaluateWellFormed_matches_specification
/-- info: 'BlindLedger.Financial.evaluate_rejects_not_well_formed' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.evaluate_rejects_not_well_formed
/-- info: 'BlindLedger.Financial.evaluate_satisfies_specification' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.evaluate_satisfies_specification
/-- info: 'BlindLedger.Financial.accepted_evaluation_contract' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.accepted_evaluation_contract
/-- info: 'BlindLedger.Financial.evaluate_rejects_total_overflow' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.evaluate_rejects_total_overflow
/-- info: 'BlindLedger.Financial.evalAdd_rejects_left_out_of_bounds' depends on axioms: [propext] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.evalAdd_rejects_left_out_of_bounds
/-- info: 'BlindLedger.Financial.evalAdd_rejects_right_out_of_bounds' depends on axioms: [propext] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.evalAdd_rejects_right_out_of_bounds
/-- info: 'BlindLedger.Financial.authorized_kat_is_correct' depends on axioms: [propext, Classical.choice, Quot.sound, authorized_kat_is_correct._native.native_decide.ax_1_1] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.authorized_kat_is_correct
/-- info: 'BlindLedger.Financial.missing_evidence_requires_support' depends on axioms: [propext, Classical.choice, Quot.sound, missing_evidence_requires_support._native.native_decide.ax_1_1] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.missing_evidence_requires_support
/-- info: 'BlindLedger.Financial.conflict_precedence_is_visible' depends on axioms: [propext, Classical.choice, Quot.sound, conflict_precedence_is_visible._native.native_decide.ax_1_1] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.conflict_precedence_is_visible
/-- info: 'BlindLedger.Financial.acknowledgement_is_not_cash' depends on axioms: [propext, Classical.choice, Quot.sound, acknowledgement_is_not_cash._native.native_decide.ax_1_1] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.acknowledgement_is_not_cash
/-- info: 'BlindLedger.Financial.late_completion_is_deterministic' depends on axioms: [propext, Classical.choice, Quot.sound, late_completion_is_deterministic._native.native_decide.ax_1_1] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.late_completion_is_deterministic
/-- info: 'BlindLedger.Financial.overflow_is_rejected' depends on axioms: [propext, Classical.choice, Quot.sound, overflow_is_rejected._native.native_decide.ax_1_1] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.overflow_is_rejected
/-- info: 'BlindLedger.Financial.malformed_order_is_rejected' depends on axioms: [propext, Classical.choice, Quot.sound, malformed_order_is_rejected._native.native_decide.ax_1_1] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.malformed_order_is_rejected
/-- info: 'BlindLedger.Financial.scope_mutation_is_rejected' depends on axioms: [propext, Classical.choice, Quot.sound, scope_mutation_is_rejected._native.native_decide.ax_1_1] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.scope_mutation_is_rejected
/-- info: 'BlindLedger.Financial.authority_mutation_is_rejected' depends on axioms: [propext, Classical.choice, Quot.sound, authority_mutation_is_rejected._native.native_decide.ax_1_1] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.authority_mutation_is_rejected
/-- info: 'BlindLedger.Financial.actor_role_mutation_is_rejected' depends on axioms: [propext, Classical.choice, Quot.sound, actor_role_mutation_is_rejected._native.native_decide.ax_1_1] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.actor_role_mutation_is_rejected
/-- info: 'BlindLedger.Financial.terminal_authorization_requires_determination' depends on axioms: [propext, Classical.choice, Quot.sound, terminal_authorization_requires_determination._native.native_decide.ax_1_1] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.terminal_authorization_requires_determination
/-- info: 'BlindLedger.Financial.duplicate_confirmation_is_preserved' depends on axioms: [propext, Classical.choice, Quot.sound, duplicate_confirmation_is_preserved._native.native_decide.ax_1_1] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.duplicate_confirmation_is_preserved
/-- info: 'BlindLedger.Financial.active_reversal_evidence_is_rejected' depends on axioms: [propext, Classical.choice, Quot.sound, active_reversal_evidence_is_rejected._native.native_decide.ax_1_1] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.active_reversal_evidence_is_rejected
/-- info: 'BlindLedger.Financial.reversed_payment_excludes_cash' depends on axioms: [propext, Classical.choice, Quot.sound, reversed_payment_excludes_cash._native.native_decide.ax_1_1] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.reversed_payment_excludes_cash
/-- info: 'BlindLedger.Financial.repeated_reversal_evidence_is_preserved' depends on axioms: [propext, Classical.choice, Quot.sound, repeated_reversal_evidence_is_preserved._native.native_decide.ax_1_1] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.repeated_reversal_evidence_is_preserved
/-- info: 'BlindLedger.Financial.pack_source_refs_and_roles_keep_owner_order' depends on axioms: [propext, Classical.choice, Quot.sound, pack_source_refs_and_roles_keep_owner_order._native.native_decide.ax_1_1] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.pack_source_refs_and_roles_keep_owner_order
/-- info: 'BlindLedger.Financial.repeated_pack_source_refs_preserve_wire_and_digest' depends on axioms: [propext, Classical.choice, Quot.sound, repeated_pack_source_refs_preserve_wire_and_digest._native.native_decide.ax_1_1] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.repeated_pack_source_refs_preserve_wire_and_digest
/-- info: 'BlindLedger.Financial.lawful_completion_fallback_is_preserved' depends on axioms: [propext, Classical.choice, Quot.sound, lawful_completion_fallback_is_preserved._native.native_decide.ax_1_1] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.lawful_completion_fallback_is_preserved
/-- info: 'BlindLedger.Financial.historical_revision_binding_is_checked' depends on axioms: [propext, Classical.choice, Quot.sound, historical_revision_binding_is_checked._native.native_decide.ax_1_1] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.historical_revision_binding_is_checked
/-- info: 'BlindLedger.Financial.latest_delivery_uses_timestamp_then_id' depends on axioms: [propext, Classical.choice, Quot.sound, latest_delivery_uses_timestamp_then_id._native.native_decide.ax_1_1] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.latest_delivery_uses_timestamp_then_id
/-- info: 'BlindLedger.Financial.direct_add_operands_are_bounded' depends on axioms: [direct_add_operands_are_bounded._native.native_decide.ax_1_1] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.direct_add_operands_are_bounded
/-- info: 'BlindLedger.Financial.codec_roundtrip_kat' depends on axioms: [propext, Classical.choice, Quot.sound, codec_roundtrip_kat._native.native_decide.ax_1_1] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.codec_roundtrip_kat
/-- info: 'BlindLedger.Financial.codec_trailing_bytes_rejected' depends on axioms: [propext, Classical.choice, Quot.sound, codec_trailing_bytes_rejected._native.native_decide.ax_1_1] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.codec_trailing_bytes_rejected
/-- info: 'BlindLedger.Financial.codec_mutation_rejected' depends on axioms: [propext, Classical.choice, Quot.sound, codec_mutation_rejected._native.native_decide.ax_1_1] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.codec_mutation_rejected
/-- info: 'BlindLedger.Financial.codec_enum_mutation_rejected' depends on axioms: [propext, Classical.choice, Quot.sound, codec_enum_mutation_rejected._native.native_decide.ax_1_1] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.codec_enum_mutation_rejected
/-- info: 'BlindLedger.Financial.codec_count_overflow_rejected' depends on axioms: [propext, Classical.choice, Quot.sound, codec_count_overflow_rejected._native.native_decide.ax_1_1] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.codec_count_overflow_rejected
/-- info: 'BlindLedger.Financial.result_codec_roundtrip_kat' depends on axioms: [propext, Classical.choice, Quot.sound, result_codec_roundtrip_kat._native.native_decide.ax_1_1] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.result_codec_roundtrip_kat
/-- info: 'BlindLedger.Financial.result_codec_trailing_bytes_rejected' depends on axioms: [propext, Classical.choice, Quot.sound, result_codec_trailing_bytes_rejected._native.native_decide.ax_1_1] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.result_codec_trailing_bytes_rejected
/-- info: 'BlindLedger.Financial.result_codec_mutation_rejected' depends on axioms: [propext, Classical.choice, Quot.sound, result_codec_mutation_rejected._native.native_decide.ax_1_1] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.result_codec_mutation_rejected
/-- info: 'BlindLedger.Financial.evaluator_corresponds_to_independent_specification' depends on axioms: [propext, Classical.choice, Quot.sound, evaluator_corresponds_to_independent_specification._native.native_decide.ax_1_1] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.evaluator_corresponds_to_independent_specification
/-- info: 'BlindLedger.Financial.exportedEvaluate_is_evaluate' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.exportedEvaluate_is_evaluate
/-- info: 'BlindLedger.Financial.codecLawsProofManifest' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.codecLawsProofManifest
/-- info: 'BlindLedger.Financial.codecLawsNoTrailingManifest' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.codecLawsNoTrailingManifest
/-- info: 'BlindLedger.Financial.codecLawsWholeWireManifest' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.codecLawsWholeWireManifest
/-- info: 'BlindLedger.Financial.decodeWorkerOutcome_encodeWorkerOutcome' depends on axioms: [propext] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.decodeWorkerOutcome_encodeWorkerOutcome
#print axioms BlindLedger.Financial.Fast.decodeFinancialInputFast_eq
#print axioms BlindLedger.Financial.Fast.rawEncodeFinancialInputBA_eq
#print axioms BlindLedger.Financial.Fast.decodeFinancialInputBA₂_eq
#print axioms BlindLedger.Financial.financialInputWellFormed_of_decodeFinancialInput
#print axioms BlindLedger.Financial.evaluate_eq_evaluateWellFormed
#print axioms BlindLedger.Financial.workerRespondBA_eq
/-- info: 'BlindLedger.Financial.evaluateWire_evaluated' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.evaluateWire_evaluated
/-- info: 'BlindLedger.Financial.workerRespond_length_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.workerRespond_length_le

/-- info: 'BlindLedger.Financial.workerRespond_evaluator_unchanged' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.workerRespond_evaluator_unchanged

/-- info: 'BlindLedger.Financial.workerRespond_payment' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.workerRespond_payment

/-- info: 'BlindLedger.Financial.paymentRespond_length_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.paymentRespond_length_le
/-- info: 'BlindLedger.Financial.maxWorkerFrameBytes_fits_u32' does not depend on any axioms -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.maxWorkerFrameBytes_fits_u32
#print axioms BlindLedger.Financial.CorrectionTransition.canonicalActionPayload_dispatch_is_synthetic_record_only
#print axioms BlindLedger.Financial.CorrectionTransition.applyCorrectionTransition_mutation_links
#print axioms BlindLedger.Financial.CorrectionTransition.applyCorrectionTransition_nonaccepted_has_no_mutation
#print axioms BlindLedger.Financial.CorrectionTransition.rejectedCorrectionTransition_has_no_mutation
#print axioms BlindLedger.Financial.CorrectionTransition.duplicateCorrectionTransition_has_no_mutation
#print axioms BlindLedger.Financial.CorrectionTransition.linkedActivePaidCents_reverse
#print axioms BlindLedger.Financial.CorrectionTransition.linkedActivePaidCents_retarget
#print axioms BlindLedger.Financial.CorrectionTransition.linkedActivePaidCents_total_le_active
#print axioms BlindLedger.Financial.CorrectionTransition.derivedCorrectionPaid_sound
#print axioms BlindLedger.Financial.CorrectionTransition.derivedCorrectionPaid_complete
#print axioms BlindLedger.Financial.CorrectionTransition.outstandingCorrectionCents_eq_linked
#print axioms BlindLedger.Financial.CorrectionTransition.applyCorrectionTransition_links_admissible
#print axioms BlindLedger.Financial.CorrectionTransition.applyCorrectionTransition_paid_eq_linked
#print axioms BlindLedger.Financial.CorrectionTransition.applyCorrectionTransition_action_amount_eq_linked
#print axioms BlindLedger.Financial.CorrectionTransition.applyCorrectionTransition_outstanding_within_shortfall_linked
#print axioms BlindLedger.Financial.CorrectionTransition.readPaymentLink_append
#print axioms BlindLedger.Financial.CorrectionTransition.readPaymentLinks_append
/-- info: 'BlindLedger.Financial.CorrectionTransition.outstandingCorrectionCents_eq_uncancelled' depends on axioms: [propext, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.CorrectionTransition.outstandingCorrectionCents_eq_uncancelled
#print axioms BlindLedger.Financial.CorrectionTransition.applyCorrectionTransition_zero_shortfall_has_no_mutation
#print axioms BlindLedger.Financial.CorrectionTransition.evaluate_positive_shortfall_balance
#print axioms BlindLedger.Financial.CorrectionTransition.applyCorrectionTransition_amounts_conserved
#print axioms BlindLedger.Financial.CorrectionTransition.executionDenial_none_implies_valid_axes
#print axioms BlindLedger.Financial.CorrectionTransition.assessAcceptedCorrectionReuse_allowed_implies_valid_axes
#print axioms BlindLedger.Financial.CorrectionTransition.assessCorrectionReuse_allowed_implies_valid_axes
#print axioms BlindLedger.Financial.CorrectionTransition.assessCorrectionReuse_calculation_independent_of_approval_and_execution_observations
#print axioms BlindLedger.Financial.CorrectionTransition.assessCorrectionReuse_approval_independent_of_calculation_and_execution_observations
#print axioms BlindLedger.Financial.CorrectionTransition.assessCorrectionReuse_local_permission_matches_denial
#print axioms BlindLedger.Financial.CorrectionTransition.assessCorrectionReuse_never_permits_external_dispatch
/-- info: 'BlindLedger.Financial.CorrectionTransition.decodeCorrectionTransitionRequest_of_encode' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.CorrectionTransition.decodeCorrectionTransitionRequest_of_encode
/-- info: 'BlindLedger.Financial.CorrectionTransition.encodeCorrectionTransitionRequest_of_decode' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.CorrectionTransition.encodeCorrectionTransitionRequest_of_decode
/-- info: 'BlindLedger.Financial.CorrectionTransition.decodeCorrectionTransitionRequest_rejects_trailing' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.CorrectionTransition.decodeCorrectionTransitionRequest_rejects_trailing
/-- info: 'BlindLedger.Financial.CorrectionTransition.decodeCorrectionTransitionResult_of_encode' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.CorrectionTransition.decodeCorrectionTransitionResult_of_encode
/-- info: 'BlindLedger.Financial.CorrectionTransition.encodeCorrectionTransitionResult_of_decode' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.CorrectionTransition.encodeCorrectionTransitionResult_of_decode
/-- info: 'BlindLedger.Financial.CorrectionTransition.decodeCorrectionTransitionResult_rejects_trailing' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.CorrectionTransition.decodeCorrectionTransitionResult_rejects_trailing
/-- info: 'BlindLedger.Financial.readUpTo_pipe' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms readUpTo_pipe
/-- info: 'BlindLedger.Financial.serveWorker_run' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms serveWorker_run
/-- info: 'BlindLedger.Financial.workerRun_frames' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms workerRun_frames
/-- info: 'BlindLedger.Financial.serveWorker_stateless' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms serveWorker_stateless
/-- info: 'BlindLedger.Financial.workerRun_oversize' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms workerRun_oversize
/-- info: 'BlindLedger.Financial.workerRun_truncated' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms workerRun_truncated
/-- info: 'BlindLedger.Financial.evaluate_balance' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.evaluate_balance
/-- info: 'BlindLedger.Financial.evalContributions_sum' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.evalContributions_sum
/-- info: 'BlindLedger.Financial.evaluate_completion_iff_satisfied' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.evaluate_completion_iff_satisfied
/-- info: 'BlindLedger.Financial.evaluate_completionAt_first' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.evaluate_completionAt_first
/-- info: 'BlindLedger.Financial.evaluate_monotone' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.evaluate_monotone
/-- info: 'BlindLedger.Financial.evaluate_evaluatedAt_irrelevant' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.evaluate_evaluatedAt_irrelevant
/-- info: 'BlindLedger.Financial.evaluate_encodes' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.evaluate_encodes
/-- info: 'BlindLedger.Financial.evaluateWire_ne_encodingRejected' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.evaluateWire_ne_encodingRejected
/-- info: 'BlindLedger.Financial.CorrectionTransition.linkedOutstandingCents_perm' depends on axioms: [propext, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.CorrectionTransition.linkedOutstandingCents_perm
/-- info: 'BlindLedger.Financial.CorrectionTransition.applyCorrectionTransition_money_unchanged' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.CorrectionTransition.applyCorrectionTransition_money_unchanged
/-- info: 'BlindLedger.Financial.CorrectionTransition.applyCorrectionTransition_post_within_shortfall' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.CorrectionTransition.applyCorrectionTransition_post_within_shortfall
/-- info: 'BlindLedger.Financial.CorrectionTransition.applyCorrectionTransition_mutation_authorized' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.CorrectionTransition.applyCorrectionTransition_mutation_authorized
/-- info: 'BlindLedger.Financial.CorrectionTransition.assessCorrectionReuse_allowed_authorized' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.CorrectionTransition.assessCorrectionReuse_allowed_authorized
/-- info: 'BlindLedger.Financial.CorrectionTransition.ite_error_ok' depends on axioms: [propext] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.CorrectionTransition.ite_error_ok
/-- info: 'BlindLedger.Financial.CorrectionTransition.buildAccepted_facts' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.CorrectionTransition.buildAccepted_facts
/-- info: 'BlindLedger.Financial.CorrectionTransition.preflightCorrectionTransition_ready_facts' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.CorrectionTransition.preflightCorrectionTransition_ready_facts
/-- info: 'BlindLedger.Financial.CorrectionTransition.applyCorrectionTransition_resultWellFormed' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.CorrectionTransition.applyCorrectionTransition_resultWellFormed
/-- info: 'BlindLedger.Financial.CorrectionTransition.applyCorrectionTransition_encodes_unless_oversize' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.CorrectionTransition.applyCorrectionTransition_encodes_unless_oversize

/-- info: 'BlindLedger.Financial.Cursor.decodeFinancialInput_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Cursor.decodeFinancialInput_eq
/-- info: 'BlindLedger.Financial.Cursor.decodeCorrectionTransitionRequest_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Cursor.decodeCorrectionTransitionRequest_eq
/-- info: 'BlindLedger.Financial.Batch.parseBatchRequestBA_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Batch.parseBatchRequestBA_eq
/-- info: 'BlindLedger.Financial.Batch.respondBatchBA_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Batch.respondBatchBA_eq
/-- info: 'BlindLedger.Financial.Batch.respondBatch_map' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Batch.respondBatch_map
/-- info: 'BlindLedger.Financial.Batch.parseBatchRequest_exact' depends on axioms: [propext, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Batch.parseBatchRequest_exact
/-- info: 'BlindLedger.Financial.Batch.respondBatch_rejects' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Batch.respondBatch_rejects
/-- info: 'BlindLedger.Financial.Batch.batch_isolation' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Batch.batch_isolation
/-- info: 'BlindLedger.Financial.Batch.encodeBatchResponse_inj' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Batch.encodeBatchResponse_inj
/-- info: 'BlindLedger.Financial.Batch.workerRespond_lt_u32' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Batch.workerRespond_lt_u32
/-- info: 'BlindLedger.Financial.Payment.paymentTransition_mutated_post' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.paymentTransition_mutated_post
/-- info: 'BlindLedger.Financial.Payment.paymentTransition_alias_post' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.paymentTransition_alias_post
/-- info: 'BlindLedger.Financial.Payment.rawEncode_applyWrites_length' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.rawEncode_applyWrites_length
/-- info: 'BlindLedger.Financial.Payment.paymentTransition_result_cash' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.paymentTransition_result_cash
/-- info: 'BlindLedger.Financial.Payment.record_amount_zero' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.record_amount_zero
/-- info: 'BlindLedger.Financial.Payment.record_link_within_request' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.record_link_within_request
/-- info: 'BlindLedger.Financial.Payment.reverse_exact' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.reverse_exact
/-- info: 'BlindLedger.Financial.Payment.conflict_changes_no_cash' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.conflict_changes_no_cash
/-- info: 'BlindLedger.Financial.Payment.run_records_payment_once' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.run_records_payment_once
/-- info: 'BlindLedger.Financial.Payment.run_records_origin_once' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.run_records_origin_once
/-- info: 'BlindLedger.Financial.Payment.run_reverses_once' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.run_reverses_once
/-- info: 'BlindLedger.Financial.Payment.run_inserts_evidence_once' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.run_inserts_evidence_once
/-- info: 'BlindLedger.Financial.Payment.run_record_retry_duplicate' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.run_record_retry_duplicate
/-- info: 'BlindLedger.Financial.Payment.run_reverse_retry_duplicate' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.run_reverse_retry_duplicate
/-- info: 'BlindLedger.Financial.Payment.step_unchanged_of_quiet' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.step_unchanged_of_quiet
/-- info: 'BlindLedger.Financial.Payment.run_rows_append_only' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.run_rows_append_only
/-- info: 'BlindLedger.Financial.Payment.record_then_reverse_restores' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.record_then_reverse_restores
/-- info: 'BlindLedger.Financial.Payment.run_conservation' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.run_conservation
/-- info: 'BlindLedger.Financial.Payment.run_paid_total' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.run_paid_total
/-- info: 'BlindLedger.Financial.Payment.step_ledgerPaid' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.step_ledgerPaid
/-- info: 'BlindLedger.Financial.Payment.run_ledgerPaid' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.run_ledgerPaid
/-- info: 'BlindLedger.Financial.Payment.run_within_requests' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.run_within_requests
/-- info: 'BlindLedger.Financial.Payment.applyCorrectionTransition_paid_eq_ledger' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.applyCorrectionTransition_paid_eq_ledger

/-- info: 'BlindLedger.Financial.Payment.decodePaymentRequest_wellFormed' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.decodePaymentRequest_wellFormed
/-- info: 'BlindLedger.Financial.Payment.decodePaymentRequest_canonical' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.decodePaymentRequest_canonical
/-- info: 'BlindLedger.Financial.Payment.decodePaymentRequest_encode' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.decodePaymentRequest_encode
/-- info: 'BlindLedger.Financial.Payment.paymentMagic_disjoint' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.paymentMagic_disjoint

/-! The decision package (`DecisionPackage.Laws`): the section 4.1 to 4.4 theorems, plus the two definitions the
    worker will call, which depend on no axiom. -/

/-- info: 'BlindLedger.Financial.DecisionPackage.conclude' depends on axioms: [propext] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.DecisionPackage.conclude
/-- info: 'BlindLedger.Financial.DecisionPackage.packageRespond' depends on axioms: [propext] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.DecisionPackage.packageRespond
/-- info: 'BlindLedger.Financial.DecisionPackage.conclude_missingCents' depends on axioms: [propext] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.DecisionPackage.conclude_missingCents
/-- info: 'BlindLedger.Financial.DecisionPackage.conclude_missingCents_zero_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.DecisionPackage.conclude_missingCents_zero_iff
/-- info: 'BlindLedger.Financial.DecisionPackage.conclude_cash_supported_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.DecisionPackage.conclude_cash_supported_iff
/-- info: 'BlindLedger.Financial.DecisionPackage.conclude_cash_conflicted_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.DecisionPackage.conclude_cash_conflicted_iff
/-- info: 'BlindLedger.Financial.DecisionPackage.factsOfEvaluation_sums' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.DecisionPackage.factsOfEvaluation_sums
/-- info: 'BlindLedger.Financial.DecisionPackage.factsOfEvaluation_not_conflicted' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.DecisionPackage.factsOfEvaluation_not_conflicted
/-- info: 'BlindLedger.Financial.DecisionPackage.factsOfEvaluation_missingCents_zero_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.DecisionPackage.factsOfEvaluation_missingCents_zero_iff
/-- info: 'BlindLedger.Financial.DecisionPackage.conclude_amount_supported_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.DecisionPackage.conclude_amount_supported_iff
/-- info: 'BlindLedger.Financial.DecisionPackage.conclude_delivery_supported_iff' depends on axioms: [propext, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.DecisionPackage.conclude_delivery_supported_iff
/-- info: 'BlindLedger.Financial.DecisionPackage.conclude_missingMask_zero_iff' depends on axioms: [propext, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.DecisionPackage.conclude_missingMask_zero_iff
/-- info: 'BlindLedger.Financial.DecisionPackage.conclude_missingMask_lt' depends on axioms: [propext, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.DecisionPackage.conclude_missingMask_lt
/-- info: 'BlindLedger.Financial.DecisionPackage.conclude_not_resolved_iff' depends on axioms: [propext] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.DecisionPackage.conclude_not_resolved_iff
/-- info: 'BlindLedger.Financial.DecisionPackage.conclude_assessment_supported_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.DecisionPackage.conclude_assessment_supported_iff
/-- info: 'BlindLedger.Financial.DecisionPackage.conclude_supported_has_evidence' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.DecisionPackage.conclude_supported_has_evidence
/-- info: 'BlindLedger.Financial.DecisionPackage.conclude_cash_independent_of_action' depends on axioms: [propext] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.DecisionPackage.conclude_cash_independent_of_action
/-- info: 'BlindLedger.Financial.DecisionPackage.decodePackageFacts_canonical' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.DecisionPackage.decodePackageFacts_canonical
/-- info: 'BlindLedger.Financial.DecisionPackage.decodePackageFacts_encode' depends on axioms: [propext, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.DecisionPackage.decodePackageFacts_encode
/-- info: 'BlindLedger.Financial.DecisionPackage.decodePackageFacts_wellFormed' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.DecisionPackage.decodePackageFacts_wellFormed
/-- info: 'BlindLedger.Financial.DecisionPackage.decodePackageAnswer_respond' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.DecisionPackage.decodePackageAnswer_respond

end BlindLedger.Financial
/-- info: 'BlindLedger.Financial.Payment.paymentRespond_decode_none' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.paymentRespond_decode_none
/-- info: 'BlindLedger.Financial.Payment.decodeStepOutcome_encode' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.decodeStepOutcome_encode
/-- info: 'BlindLedger.Financial.Payment.refusals_complete' depends on axioms: [propext] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.refusals_complete
/-- info: 'BlindLedger.Financial.Payment.absorb_summarize' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.absorb_summarize
/-- info: 'BlindLedger.Financial.Payment.evaluateState_summarize' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.evaluateState_summarize
/-- info: 'BlindLedger.Financial.Payment.state_requests_paid' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.state_requests_paid
/-- info: 'BlindLedger.Financial.Payment.anchorItem_fits' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.anchorItem_fits
/-- info: 'BlindLedger.Financial.Payment.anchorItem_length' depends on axioms: [propext, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.anchorItem_length
/-- info: 'BlindLedger.Financial.Payment.step_anchor_fits' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.step_anchor_fits
/-- info: 'BlindLedger.Financial.Payment.decodePaymentItem_encode' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.decodePaymentItem_encode
/-- info: 'BlindLedger.Financial.Payment.run_conflict_retry_unchanged' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.run_conflict_retry_unchanged
/-- info: 'BlindLedger.Financial.Payment.step_wellFormed' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.step_wellFormed
/-- info: 'BlindLedger.Financial.Payment.record_link_within_shortfall' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.record_link_within_shortfall
/-- info: 'BlindLedger.Financial.Payment.run_balance_identity' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.run_balance_identity
/-- info: 'BlindLedger.Financial.Payment.paymentTransition_shadow_refused' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.paymentTransition_shadow_refused
/-- info: 'BlindLedger.Financial.Payment.decodePaymentItem_command' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.decodePaymentItem_command
/-- info: 'BlindLedger.Financial.Payment.decodePaymentItem_coherent' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.decodePaymentItem_coherent
/-- info: 'BlindLedger.Financial.Payment.stepView_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.stepView_eq
/-- info: 'BlindLedger.Financial.Payment.chain_fold_eq_full' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.chain_fold_eq_full
-- R2 (open amounts of correction requests); #2 `requests_within_balance` is core-theorems-v1 section 4.4 item 1,
-- and with #6 `record_link_within_open` it replaces the dropped run-level R1 law (section 4.4, `run_linked_within_shortfall`).
/-- info: 'BlindLedger.Financial.Payment.openTotal_eq_min' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.openTotal_eq_min
/-- info: 'BlindLedger.Financial.Payment.openCents_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.openCents_le
/-- info: 'BlindLedger.Financial.Payment.requests_within_balance' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.requests_within_balance
/-- info: 'BlindLedger.Financial.Payment.openCents_eq_unpaid_of_within' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.openCents_eq_unpaid_of_within
/-- info: 'BlindLedger.Financial.Payment.engine_requestable_agrees' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.engine_requestable_agrees
/-- info: 'BlindLedger.Financial.Payment.openCents_pay_local' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.openCents_pay_local
/-- info: 'BlindLedger.Financial.Payment.record_link_within_open' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.record_link_within_open
/-- info: 'BlindLedger.Financial.Payment.linkRefusal_implies_r1' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms BlindLedger.Financial.Payment.linkRefusal_implies_r1
