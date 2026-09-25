import BlindLedger.Financial.CorrectionTransition.Reuse

namespace BlindLedger.Financial.CorrectionTransition

open BlindLedger.Financial
open BlindLedger.Financial.DecisionPackage (EvaluationReceipt)

theorem applyCorrectionTransition_mutation_links
    (request : CorrectionTransitionRequest) (mutation : CorrectionMutation)
    (hMutation : (applyCorrectionTransition request).mutation = some mutation) :
      (applyCorrectionTransition request).status = .ACCEPTED ∧
      (applyCorrectionTransition request).actionId = some request.command.actionId ∧
      (applyCorrectionTransition request).determinationId =
        some ("determination:" ++ request.command.actionId) ∧
      (applyCorrectionTransition request).explanation.transition =
        some .OFFSET_REJECTED_CORRECTION_AUTHORIZED ∧
      (applyCorrectionTransition request).explanation.resultingRevision =
        some mutation.resultingResult.afterRevision ∧
      request.currentInput.beforeRevision + 1 = request.command.expectedRevision ∧
      CorrectionMutationLinkFacts request mutation := by
  unfold applyCorrectionTransition at hMutation ⊢
  cases hPreflight : preflightCorrectionTransition request with
  | error reason =>
      simp [hPreflight, reject] at hMutation
  | ok preflight =>
      cases preflight with
      | duplicate =>
          simp [hPreflight, duplicate] at hMutation
      | ready currentResult claim inputRevisionMatches hEvaluates hShortfall =>
          dsimp only
          cases hBuild : buildAccepted request currentResult claim hEvaluates hShortfall with
          | error reason =>
              simp [hPreflight, hBuild, reject] at hMutation
          | ok certified =>
              simp [hPreflight, hBuild] at hMutation
              cases hMutation
              exact ⟨rfl, rfl, rfl, rfl, rfl, inputRevisionMatches, certified.property⟩

/-- A correction never requests more than the shortfall Lean evaluated before the
    decision: it requests the smaller of the rejected claim and that shortfall. -/
theorem applyCorrectionTransition_action_amount_le_shortfall
    (request : CorrectionTransitionRequest) (mutation : CorrectionMutation)
    (hMutation : (applyCorrectionTransition request).mutation = some mutation) :
    ∃ result, evaluate request.currentInput = some result ∧ 0 < result.shortfallCents ∧
      mutation.action.amountCents =
        min mutation.dependencies.claimBefore.amountCents result.shortfallCents ∧
      mutation.action.amountCents ≤ result.shortfallCents := by
  have hLinks := (applyCorrectionTransition_mutation_links request mutation hMutation).2.2.2.2.2.2
  obtain ⟨result, hEval, hShortfall, hPositive⟩ := hLinks.inputShortfall
  refine ⟨result, hEval, hPositive, ?_, ?_⟩
  · rw [hLinks.amountRule, hLinks.claimAmount, hShortfall]
  · rw [hLinks.amountRule, hShortfall]
    exact Nat.min_le_right _ _

/-- When nothing is short, no correction payment request is created. -/
theorem applyCorrectionTransition_zero_shortfall_has_no_mutation
    (request : CorrectionTransitionRequest) (result : FinancialResult)
    (hEval : evaluate request.currentInput = some result)
    (hZero : result.shortfallCents = 0) :
    (applyCorrectionTransition request).mutation = none := by
  cases hMutation : (applyCorrectionTransition request).mutation with
  | none => rfl
  | some mutation =>
      obtain ⟨other, hOther, hPositive, _, _⟩ :=
        applyCorrectionTransition_action_amount_le_shortfall request mutation hMutation
      rw [hEval] at hOther
      have hSame : result = other := Option.some.inj hOther
      subst hSame
      omega

private theorem evalAdd_some_eq {left right total : Nat}
    (hAdd : evalAdd left right = some total) : total = left + right := by
  unfold evalAdd at hAdd
  split at hAdd
  · exact (Option.some.inj hAdd).symm
  · contradiction

private theorem evaluateTotals_total {input : FinancialInput} {totals : EvaluatedTotals}
    (hTotals : evaluateTotals input = some totals) : totals.total = totals.cash + totals.lawful := by
  unfold evaluateTotals at hTotals
  split at hTotals <;> try contradiction
  split at hTotals <;> try contradiction
  split at hTotals <;> try contradiction
  split at hTotals <;> try contradiction
  rename_i hAdd
  cases hTotals
  exact evalAdd_some_eq hAdd

/-- A positive shortfall is exactly what cash and lawful adjustments leave unpaid. -/
theorem evaluate_positive_shortfall_balance (input : FinancialInput) (result : FinancialResult)
    (hEval : evaluate input = some result) (hPositive : 0 < result.shortfallCents) :
    result.receivedCashCents + result.lawfulAdjustmentCents + result.shortfallCents =
      result.owedCents := by
  unfold evaluate at hEval
  split at hEval
  · unfold evaluateWellFormed at hEval
    cases hTotals : evaluateTotals input with
    | none =>
        rw [hTotals] at hEval
        contradiction
    | some totals =>
        rw [hTotals] at hEval
        have hResult : evaluateResult input totals.cash totals.claimed totals.lawful totals.total =
            result := Option.some.inj hEval
        subst hResult
        have hTotal := evaluateTotals_total hTotals
        change 0 < (if input.obligation.owedCents > totals.total then
          input.obligation.owedCents - totals.total else 0) at hPositive
        change totals.cash + totals.lawful + (if input.obligation.owedCents > totals.total then
          input.obligation.owedCents - totals.total else 0) = input.obligation.owedCents
        by_cases hShort : input.obligation.owedCents > totals.total
        · rw [if_pos hShort]
          omega
        · rw [if_neg hShort] at hPositive
          omega
  · contradiction

/-- Amounts are conserved: the rejected offset is recorded at the claim's amount,
    the request is no more than that offset, and cash plus lawful adjustments plus
    the request never exceed what is owed. -/
theorem applyCorrectionTransition_amounts_conserved
    (request : CorrectionTransitionRequest) (mutation : CorrectionMutation)
    (hMutation : (applyCorrectionTransition request).mutation = some mutation) :
    ∃ result, evaluate request.currentInput = some result ∧
      mutation.determination.amountCents = mutation.dependencies.claimBefore.amountCents ∧
      mutation.action.amountCents ≤ mutation.determination.amountCents ∧
      result.receivedCashCents + result.lawfulAdjustmentCents + mutation.action.amountCents ≤
        result.owedCents := by
  have hLinks := (applyCorrectionTransition_mutation_links request mutation hMutation).2.2.2.2.2.2
  obtain ⟨result, hEval, hPositive, _, hBound⟩ :=
    applyCorrectionTransition_action_amount_le_shortfall request mutation hMutation
  have hBalance := evaluate_positive_shortfall_balance request.currentInput result hEval hPositive
  refine ⟨result, hEval, hLinks.claimAmount, ?_, by omega⟩
  rw [hLinks.amountRule]
  exact Nat.min_le_left _ _

theorem applyCorrectionTransition_nonaccepted_has_no_mutation
    (request : CorrectionTransitionRequest)
    (hStatus : (applyCorrectionTransition request).status ≠ .ACCEPTED) :
    (applyCorrectionTransition request).mutation = none := by
  cases hMutation : (applyCorrectionTransition request).mutation with
  | none => rfl
  | some mutation =>
      have hAccepted := (applyCorrectionTransition_mutation_links request mutation hMutation).1
      exact False.elim (hStatus hAccepted)

theorem rejectedCorrectionTransition_has_no_mutation
    (request : CorrectionTransitionRequest)
    (hStatus : (applyCorrectionTransition request).status = .REJECTED) :
    (applyCorrectionTransition request).mutation = none := by
  apply applyCorrectionTransition_nonaccepted_has_no_mutation
  intro hAccepted
  rw [hStatus] at hAccepted
  cases hAccepted

theorem duplicateCorrectionTransition_has_no_mutation
    (request : CorrectionTransitionRequest)
    (hStatus : (applyCorrectionTransition request).status = .DUPLICATE) :
    (applyCorrectionTransition request).mutation = none := by
  apply applyCorrectionTransition_nonaccepted_has_no_mutation
  intro hAccepted
  rw [hStatus] at hAccepted
  cases hAccepted

theorem executionDenial_none_implies_valid_axes
    (request : CorrectionReuseRequest) (mutation : CorrectionMutation)
    (calculationValidity : CorrectionCalculationValidity)
    (humanApprovalValidity : CorrectionApprovalValidity)
    (hDenial : executionDenial request mutation calculationValidity humanApprovalValidity = none) :
    calculationValidity = .VALID ∧ humanApprovalValidity = .VALID := by
  cases hEnvironment : executionEnvironmentDenial request mutation with
  | some denial =>
      simp [executionDenial, hEnvironment] at hDenial
  | none =>
      cases calculationValidity <;> cases humanApprovalValidity <;>
        simp [executionDenial, hEnvironment, correctionExecutionAxisDenial] at hDenial ⊢

theorem assessAcceptedCorrectionReuse_allowed_implies_valid_axes
    (request : CorrectionReuseRequest) (mutation : CorrectionMutation)
    (hAllowed : (assessAcceptedCorrectionReuse request mutation).localExecutionPermission = .ALLOWED) :
    (assessAcceptedCorrectionReuse request mutation).calculationValidity = .VALID ∧
      (assessAcceptedCorrectionReuse request mutation).humanApprovalValidity = .VALID := by
  let calculation := calculationValidityOfReason (calculationReason request mutation)
  let approval := approvalValidityOfReason (approvalReason request mutation)
  let denial := executionDenial request mutation calculation approval
  change executionPermissionOfDenial denial = .ALLOWED at hAllowed
  change calculation = .VALID ∧ approval = .VALID
  have hDenial : denial = none := by
    cases hExecution : denial with
    | none => rfl
    | some reason => simp [executionPermissionOfDenial, hExecution] at hAllowed
  exact executionDenial_none_implies_valid_axes request mutation calculation approval hDenial

theorem assessCorrectionReuse_allowed_implies_valid_axes
    (request : CorrectionReuseRequest)
    (hAllowed : (assessCorrectionReuse request).localExecutionPermission = .ALLOWED) :
    (assessCorrectionReuse request).calculationValidity = .VALID ∧
      (assessCorrectionReuse request).humanApprovalValidity = .VALID := by
  cases hStatus : request.acceptedResult.status with
  | ACCEPTED =>
      cases hMutation : request.acceptedResult.mutation with
      | none =>
          simp [assessCorrectionReuse, hStatus, hMutation, executionPermissionOfDenial] at hAllowed ⊢
      | some mutation =>
          have hAcceptedAllowed :
              (assessAcceptedCorrectionReuse request mutation).localExecutionPermission = .ALLOWED := by
            simpa [assessCorrectionReuse, hStatus, hMutation] using hAllowed
          have hAxes := assessAcceptedCorrectionReuse_allowed_implies_valid_axes
            request mutation hAcceptedAllowed
          simpa [assessCorrectionReuse, hStatus, hMutation] using hAxes
  | DUPLICATE =>
      cases hMutation : request.acceptedResult.mutation <;>
        simp [assessCorrectionReuse, hStatus, hMutation, executionPermissionOfDenial] at hAllowed ⊢
  | REJECTED =>
      cases hMutation : request.acceptedResult.mutation <;>
        simp [assessCorrectionReuse, hStatus, hMutation, executionPermissionOfDenial] at hAllowed ⊢

theorem assessCorrectionReuse_calculation_independent_of_approval_and_execution_observations
    (request : CorrectionReuseRequest) (determination : Option OffsetDetermination)
    (outbox : Option CorrectionOutboxDelta) (ownerNowMs : Nat) :
    (assessCorrectionReuse { request with
      currentDetermination := determination
      currentOutbox := outbox
      currentOwnerNowMs := ownerNowMs }).calculationValidity =
      (assessCorrectionReuse request).calculationValidity := by
  cases hStatus : request.acceptedResult.status <;>
    cases hMutation : request.acceptedResult.mutation <;>
      simp [assessCorrectionReuse, assessAcceptedCorrectionReuse, calculationReason,
        hStatus, hMutation] <;>
      rfl

theorem assessCorrectionReuse_approval_independent_of_calculation_and_execution_observations
    (request : CorrectionReuseRequest) (currentInput : FinancialInput)
    (currentReceipt : EvaluationReceipt) (outbox : Option CorrectionOutboxDelta)
    (ownerNowMs : Nat) :
    (assessCorrectionReuse { request with
      currentInput := currentInput
      currentReceipt := currentReceipt
      currentOutbox := outbox
      currentOwnerNowMs := ownerNowMs }).humanApprovalValidity =
      (assessCorrectionReuse request).humanApprovalValidity := by
  cases hStatus : request.acceptedResult.status <;>
    cases hMutation : request.acceptedResult.mutation <;>
      simp [assessCorrectionReuse, assessAcceptedCorrectionReuse, approvalReason,
        hStatus, hMutation] <;>
      rfl

theorem assessCorrectionReuse_local_permission_matches_denial
    (request : CorrectionReuseRequest) :
    (assessCorrectionReuse request).localExecutionPermission =
      executionPermissionOfDenial (assessCorrectionReuse request).executionDenial := by
  cases hStatus : request.acceptedResult.status <;>
    cases hMutation : request.acceptedResult.mutation <;>
      simp [assessCorrectionReuse, assessAcceptedCorrectionReuse, executionPermissionOfDenial,
        hStatus, hMutation]

theorem assessCorrectionReuse_never_permits_external_dispatch
    (request : CorrectionReuseRequest) :
    (assessCorrectionReuse request).externalDispatchPermitted = false := by
  cases hStatus : request.acceptedResult.status <;>
    cases hMutation : request.acceptedResult.mutation <;>
      simp [assessCorrectionReuse, assessAcceptedCorrectionReuse, hStatus, hMutation]

end BlindLedger.Financial.CorrectionTransition
