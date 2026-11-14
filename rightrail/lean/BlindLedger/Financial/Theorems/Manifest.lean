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

-- Each `_vector` theorem checks one fixed test vector, not a general law.
theorem authorized_kat_is_correct_vector : gateAuthorizedEvaluation = true := by native_decide
theorem missing_evidence_requires_support_vector : gateMissingEvidence = true := by native_decide
theorem conflict_precedence_is_visible_vector : gateConflictPrecedence = true := by native_decide
theorem acknowledgement_is_not_cash_vector : gateAckIsNotCash = true := by native_decide
theorem late_completion_is_deterministic_vector : gateLateCompletion = true := by native_decide
theorem overflow_is_rejected_vector : gateOverflowRejects = true := by native_decide
theorem malformed_order_is_rejected_vector : gateMalformedOrderRejects = true := by native_decide
theorem scope_mutation_is_rejected_vector : gateScopeRejects = true := by native_decide
theorem authority_mutation_is_rejected_vector : gateAuthorityRejects = true := by native_decide
theorem actor_role_mutation_is_rejected_vector : gateActorRejects = true := by native_decide
theorem terminal_authorization_requires_determination_vector :
    gateInvalidAuthorizedClaimRejects = true := by native_decide
theorem duplicate_confirmation_is_preserved_vector :
    gateDuplicateConfirmationPreserved = true := by native_decide
theorem active_reversal_evidence_is_rejected_vector :
    gateActiveReversalRejects = true := by native_decide
theorem reversed_payment_excludes_cash_vector :
    gateReversedPaymentExcludesCash = true := by native_decide
theorem repeated_reversal_evidence_is_preserved_vector :
    gateRepeatedReversalIsPreserved = true := by native_decide
theorem pack_source_refs_and_roles_keep_owner_order_vector :
    gatePackStoredOrderAccepted = true := by native_decide
theorem repeated_pack_source_refs_preserve_wire_and_digest_vector :
    gatePackRepeatedReferencePreserved = true := by native_decide
theorem lawful_completion_fallback_is_preserved_vector : gateLawfulCompletionFallback = true := by native_decide
theorem historical_revision_binding_is_checked_vector : gateHistoricalRevisionBinding = true := by native_decide
theorem latest_delivery_uses_timestamp_then_id_vector : gateLatestDeliveryUsesTime = true := by native_decide
theorem direct_add_operands_are_bounded_vector : gateDirectAddBounds = true := by native_decide
theorem codec_roundtrip_kat : gateCodecRoundtrip = true := by native_decide
theorem codec_trailing_bytes_rejected_vector : gateTrailingBytesReject = true := by native_decide
theorem codec_mutation_rejected_vector : gateMutationRejects = true := by native_decide
theorem codec_enum_mutation_rejected_vector : gateEnumMutationRejects = true := by native_decide
theorem codec_count_overflow_rejected_vector : gateCountOverflowRejects = true := by native_decide
theorem result_codec_roundtrip_kat : gateResultCodecRoundtrip = true := by native_decide
theorem result_codec_trailing_bytes_rejected_vector : gateResultTrailingBytesReject = true := by native_decide
theorem result_codec_mutation_rejected_vector : gateResultMutationRejects = true := by native_decide
theorem evaluator_corresponds_to_independent_specification_vector :
    gateIndependentSpecification = true := by native_decide

def financialTheoremNames : List String :=
  ["evaluateWellFormed_matches_specification", "evaluate_rejects_not_well_formed",
    "evaluate_satisfies_specification", "accepted_evaluation_contract",
    "evaluate_rejects_total_overflow", "evalAdd_rejects_left_out_of_bounds",
    "evalAdd_rejects_right_out_of_bounds", "evaluation_deterministic",
    "authorized_kat_is_correct_vector",
    "missing_evidence_requires_support_vector", "conflict_precedence_is_visible_vector",
    "acknowledgement_is_not_cash_vector", "late_completion_is_deterministic_vector",
    "overflow_is_rejected_vector", "malformed_order_is_rejected_vector",
    "scope_mutation_is_rejected_vector", "authority_mutation_is_rejected_vector",
    "actor_role_mutation_is_rejected_vector", "terminal_authorization_requires_determination_vector",
    "duplicate_confirmation_is_preserved_vector", "active_reversal_evidence_is_rejected_vector",
    "reversed_payment_excludes_cash_vector", "repeated_reversal_evidence_is_preserved_vector",
    "pack_source_refs_and_roles_keep_owner_order_vector",
    "repeated_pack_source_refs_preserve_wire_and_digest_vector",
    "lawful_completion_fallback_is_preserved_vector", "historical_revision_binding_is_checked_vector",
    "latest_delivery_uses_timestamp_then_id_vector", "direct_add_operands_are_bounded_vector",
    "codec_roundtrip_kat", "codec_trailing_bytes_rejected_vector",
    "codec_mutation_rejected_vector", "codec_enum_mutation_rejected_vector",
    "codec_count_overflow_rejected_vector", "result_codec_roundtrip_kat",
    "result_codec_trailing_bytes_rejected_vector", "result_codec_mutation_rejected_vector",
    "evaluator_corresponds_to_independent_specification_vector"]


end BlindLedger.Financial
