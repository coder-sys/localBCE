import BlindLedger.Financial.CorrectionTransition.Reuse
import BlindLedger.Financial.Theorems.Conservation

namespace BlindLedger.Financial.CorrectionTransition

open BlindLedger.Financial
open BlindLedger.Financial.DecisionPackage (EvaluationReceipt)

theorem canonicalActionPayload_dispatch_is_synthetic_record_only
    (request : CorrectionTransitionRequest) (determinationId : String)
    (resultingRevision amountCents : Nat) :
    (canonicalActionPayload request determinationId resultingRevision amountCents).dispatchMode =
      .SYNTHETIC_RECORD_ONLY := by
  rfl

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
      | ready currentResult claim inputRevisionMatches hEvaluates paid hDerived hRequestable =>
          dsimp only
          cases hBuild : buildAccepted request currentResult claim hEvaluates paid hDerived hRequestable with
          | error reason =>
              simp [hPreflight, hBuild, reject] at hMutation
          | ok certified =>
              simp [hPreflight, hBuild] at hMutation
              cases hMutation
              exact ⟨rfl, rfl, rfl, rfl, rfl, inputRevisionMatches, certified.property⟩

/-- When nothing is short, no correction payment request is created. -/
theorem applyCorrectionTransition_zero_shortfall_has_no_mutation
    (request : CorrectionTransitionRequest) (result : FinancialResult)
    (hEval : evaluate request.currentInput = some result)
    (hZero : result.shortfallCents = 0) :
    (applyCorrectionTransition request).mutation = none := by
  cases hMutation : (applyCorrectionTransition request).mutation with
  | none => rfl
  | some mutation =>
      obtain ⟨other, hOther, _, hBelow⟩ :=
        (applyCorrectionTransition_mutation_links request mutation hMutation).2.2.2.2.2.2.inputShortfall
      rw [hEval] at hOther
      have hSame : result = other := Option.some.inj hOther
      subst hSame
      omega

/-- A positive shortfall is exactly what cash and lawful adjustments leave unpaid. -/
theorem evaluate_positive_shortfall_balance (input : FinancialInput) (result : FinancialResult)
    (hEval : evaluate input = some result) (hPositive : 0 < result.shortfallCents) :
    result.receivedCashCents + result.lawfulAdjustmentCents + result.shortfallCents =
      result.owedCents := by
  obtain ⟨h1, h2, -⟩ := evaluate_balance hEval
  omega

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
  obtain ⟨result, hEval, hShortfall, hBelow⟩ := hLinks.inputShortfall
  have hBound : mutation.action.amountCents ≤ result.shortfallCents := by
    rw [hLinks.amountRule, hShortfall]
    exact Nat.le_trans (Nat.min_le_right _ _) (Nat.sub_le _ _)
  have hBalance := evaluate_positive_shortfall_balance request.currentInput result hEval
    (Nat.lt_of_le_of_lt (Nat.zero_le _) hBelow)
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

/-- A1: a CANCELLED correction request asks for nothing; only uncancelled
    requests reduce the balance a new correction may request (with B2). -/
theorem outstandingCorrectionCents_eq_uncancelled (paid : List CorrectionPaid)
    (actions : List ActionRecord) :
    outstandingCorrectionCents paid actions =
      outstandingCorrectionCents paid
        (actions.filter (fun action => action.status ≠ ActionStatus.CANCELLED)) := by
  induction actions with
  | nil => rfl
  | cons action rest ih =>
      by_cases hCancelled : action.status = ActionStatus.CANCELLED
      · simp [List.filter, hCancelled, outstandingCorrectionCents, ih]
      · simp [List.filter, hCancelled, outstandingCorrectionCents, ih]

end BlindLedger.Financial.CorrectionTransition
