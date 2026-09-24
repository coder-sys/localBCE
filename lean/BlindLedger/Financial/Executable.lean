import BlindLedger.Financial.Theorems

namespace BlindLedger.Financial

/-! The exported financial function is exactly the evaluator definition.  A
    later State adapter may bind this narrow seam after its own snapshot and
    transaction checks; this module does not perform storage or mutation. -/

def exportedEvaluate (input : FinancialInput) : Option FinancialResult :=
  evaluate input

theorem exportedEvaluate_is_evaluate (input : FinancialInput) :
    exportedEvaluate input = evaluate input := rfl

def executableGateLines : List (String × Bool) :=
  [ ("authorized_kat", gateAuthorizedEvaluation)
    , ("missing_evidence", gateMissingEvidence)
    , ("conflict_precedence", gateConflictPrecedence)
    , ("ack_not_cash", gateAckIsNotCash)
    , ("late_completion", gateLateCompletion)
    , ("overflow_rejection", gateOverflowRejects)
    , ("malformed_order_rejection", gateMalformedOrderRejects)
    , ("scope_rejection", gateScopeRejects)
    , ("authority_rejection", gateAuthorityRejects)
    , ("actor_role_rejection", gateActorRejects)
    , ("terminal_authorization_rejection", gateInvalidAuthorizedClaimRejects)
    , ("duplicate_confirmation_preserved", gateDuplicateConfirmationPreserved)
    , ("active_reversal_rejection", gateActiveReversalRejects)
    , ("reversed_payment_excludes_cash", gateReversedPaymentExcludesCash)
    , ("repeated_reversal_preserved", gateRepeatedReversalIsPreserved)
    , ("pack_stored_order", gatePackStoredOrderAccepted)
    , ("pack_repeated_reference_preserved", gatePackRepeatedReferencePreserved)
    , ("lawful_completion_fallback", gateLawfulCompletionFallback)
    , ("historical_revision_binding", gateHistoricalRevisionBinding)
    , ("latest_delivery_timestamp_id", gateLatestDeliveryUsesTime)
    , ("direct_add_bounds", gateDirectAddBounds)
    , ("codec_roundtrip", gateCodecRoundtrip)
    , ("trailing_bytes_rejection", gateTrailingBytesReject)
    , ("mutation_rejection", gateMutationRejects)
    , ("enum_mutation_rejection", gateEnumMutationRejects)
    , ("count_overflow_rejection", gateCountOverflowRejects)
    , ("result_codec_roundtrip", gateResultCodecRoundtrip)
    , ("result_trailing_bytes_rejection", gateResultTrailingBytesReject)
    , ("result_mutation_rejection", gateResultMutationRejects)
    , ("specification_correspondence", gateIndependentSpecification) ]

def executableGatesPass : Bool :=
  executableGateLines.all (fun entry => entry.2)

end BlindLedger.Financial
