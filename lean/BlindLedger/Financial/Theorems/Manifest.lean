import BlindLedger.Financial.Theorems.Correspondence
import BlindLedger.Financial.Theorems.Vectors

namespace BlindLedger.Financial

theorem evaluation_deterministic
    (input : FinancialInput) (left right : FinancialResult)
    (leftResult : evaluate input = some left)
    (rightResult : evaluate input = some right) :
    left = right := by
  rw [leftResult] at rightResult
  exact Option.some.inj rightResult

theorem authorized_kat_is_correct : gateAuthorizedEvaluation = true := by native_decide
theorem missing_evidence_requires_support : gateMissingEvidence = true := by native_decide
theorem conflict_precedence_is_visible : gateConflictPrecedence = true := by native_decide
theorem acknowledgement_is_not_cash : gateAckIsNotCash = true := by native_decide
theorem late_completion_is_deterministic : gateLateCompletion = true := by native_decide
theorem overflow_is_rejected : gateOverflowRejects = true := by native_decide
theorem malformed_order_is_rejected : gateMalformedOrderRejects = true := by native_decide
theorem scope_mutation_is_rejected : gateScopeRejects = true := by native_decide
theorem authority_mutation_is_rejected : gateAuthorityRejects = true := by native_decide
theorem actor_role_mutation_is_rejected : gateActorRejects = true := by native_decide
theorem terminal_authorization_requires_determination :
    gateInvalidAuthorizedClaimRejects = true := by native_decide
theorem duplicate_confirmation_is_preserved :
    gateDuplicateConfirmationPreserved = true := by native_decide
theorem active_reversal_evidence_is_rejected :
    gateActiveReversalRejects = true := by native_decide
theorem reversed_payment_excludes_cash :
    gateReversedPaymentExcludesCash = true := by native_decide
theorem repeated_reversal_evidence_is_preserved :
    gateRepeatedReversalIsPreserved = true := by native_decide
theorem pack_source_refs_and_roles_keep_owner_order :
    gatePackStoredOrderAccepted = true := by native_decide
theorem repeated_pack_source_refs_preserve_wire_and_digest :
    gatePackRepeatedReferencePreserved = true := by native_decide
theorem lawful_completion_fallback_is_preserved : gateLawfulCompletionFallback = true := by native_decide
theorem historical_revision_binding_is_checked : gateHistoricalRevisionBinding = true := by native_decide
theorem latest_delivery_uses_timestamp_then_id : gateLatestDeliveryUsesTime = true := by native_decide
theorem direct_add_operands_are_bounded : gateDirectAddBounds = true := by native_decide
theorem codec_roundtrip_kat : gateCodecRoundtrip = true := by native_decide
theorem codec_trailing_bytes_rejected : gateTrailingBytesReject = true := by native_decide
theorem codec_mutation_rejected : gateMutationRejects = true := by native_decide
theorem codec_enum_mutation_rejected : gateEnumMutationRejects = true := by native_decide
theorem codec_count_overflow_rejected : gateCountOverflowRejects = true := by native_decide
theorem result_codec_roundtrip_kat : gateResultCodecRoundtrip = true := by native_decide
theorem result_codec_trailing_bytes_rejected : gateResultTrailingBytesReject = true := by native_decide
theorem result_codec_mutation_rejected : gateResultMutationRejects = true := by native_decide
theorem evaluator_corresponds_to_independent_specification :
    gateIndependentSpecification = true := by native_decide

def financialTheoremNames : List String :=
  ["evaluateWellFormed_matches_specification", "evaluate_rejects_not_well_formed",
    "evaluate_satisfies_specification", "accepted_evaluation_contract",
    "evaluate_rejects_total_overflow", "evalAdd_rejects_left_out_of_bounds",
    "evalAdd_rejects_right_out_of_bounds", "evaluation_deterministic",
    "authorized_kat_is_correct",
    "missing_evidence_requires_support", "conflict_precedence_is_visible",
    "acknowledgement_is_not_cash", "late_completion_is_deterministic",
    "overflow_is_rejected", "malformed_order_is_rejected",
    "scope_mutation_is_rejected", "authority_mutation_is_rejected",
    "actor_role_mutation_is_rejected", "terminal_authorization_requires_determination",
    "duplicate_confirmation_is_preserved", "active_reversal_evidence_is_rejected",
    "reversed_payment_excludes_cash", "repeated_reversal_evidence_is_preserved",
    "pack_source_refs_and_roles_keep_owner_order",
    "repeated_pack_source_refs_preserve_wire_and_digest",
    "lawful_completion_fallback_is_preserved", "historical_revision_binding_is_checked",
    "latest_delivery_uses_timestamp_then_id", "direct_add_operands_are_bounded",
    "codec_roundtrip_kat", "codec_trailing_bytes_rejected",
    "codec_mutation_rejected", "codec_enum_mutation_rejected",
    "codec_count_overflow_rejected", "result_codec_roundtrip_kat",
    "result_codec_trailing_bytes_rejected", "result_codec_mutation_rejected",
    "evaluator_corresponds_to_independent_specification"]


end BlindLedger.Financial
