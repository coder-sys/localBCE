import BlindLedger.Financial.CorrectionTransition.Reuse

namespace BlindLedger.Financial.CorrectionTransition

open BlindLedger.Financial
open BlindLedger.Semantic
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
      | ready currentResult claim inputRevisionMatches =>
          dsimp only
          cases hBuild : buildAccepted request currentResult claim with
          | error reason =>
              simp [hPreflight, hBuild, reject] at hMutation
          | ok certified =>
              simp [hPreflight, hBuild] at hMutation
              cases hMutation
              exact ⟨rfl, rfl, rfl, rfl, rfl, inputRevisionMatches, certified.property⟩

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
    (determinationDigest : Option Bytes) (outbox : Option CorrectionOutboxDelta)
    (ownerNowMs : Nat) :
    (assessCorrectionReuse { request with
      currentDetermination := determination
      currentDeterminationDigest := determinationDigest
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
