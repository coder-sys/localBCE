import BlindLedger.Financial.CorrectionTransition.Theorems

/-! UNCHECKED STATEMENTS.  They name `CorrectionCommand.paymentLinks` and
    `derivedCorrectionPaid`, which the builder adds (docs/CORE_REDESIGN.md,
    "Lean paid sum", builder handoff).  Nothing imports this file until the
    builder has type-checked every statement and filled every `sorry`.  They
    replace, alongside and never by edit, the caller-trusting
    `applyCorrectionTransition_action_amount_eq_b2` and
    `applyCorrectionTransition_outstanding_within_shortfall`. -/

namespace BlindLedger.Financial.CorrectionTransition

open BlindLedger.Financial

/-! ## Derivation contract (`derivedCorrectionPaid`, O(n + k log k)) -/

/-- What the derivation returns is canonical, comes only from admissible
    links, and is exactly the linked active cash per action. -/
theorem derivedCorrectionPaid_sound (payments : List Payment) (actions : List ActionRecord)
    (links : List PaymentLink) (paid : List CorrectionPaid)
    (hDerived : derivedCorrectionPaid payments actions links = some paid) :
    correctionPaidWellFormed paid = true ∧
      paymentLinksAdmissible payments actions links = true ∧
      ∀ actionId, correctionPaidCents paid actionId =
        linkedActivePaidCents payments links actionId := by
  sorry

/-- An honest snapshot is never refused: admissible, canonical links over a
    well-formed input that evaluates always derive. -/
theorem derivedCorrectionPaid_complete (input : FinancialInput) (links : List PaymentLink)
    (result : FinancialResult)
    (hInput : financialInputWellFormed input = true)
    (hLinks : paymentLinksWellFormed links = true)
    (hAdmissible : paymentLinksAdmissible input.payments input.actions links = true)
    (hEval : evaluate input = some result) :
    ∃ paid, derivedCorrectionPaid input.payments input.actions links = some paid := by
  sorry

theorem outstandingCorrectionCents_eq_linked (paid : List CorrectionPaid)
    (payments : List Payment) (links : List PaymentLink) (actions : List ActionRecord)
    (hPaid : ∀ actionId, correctionPaidCents paid actionId =
      linkedActivePaidCents payments links actionId) :
    outstandingCorrectionCents paid actions = linkedOutstandingCents payments links actions := by
  sorry

/-! ## Transition statements -/

/-- An accepted correction only ever used links naming snapshot payment rows
    and snapshot correction requests. -/
theorem applyCorrectionTransition_links_admissible
    (request : CorrectionTransitionRequest) (mutation : CorrectionMutation)
    (hMutation : (applyCorrectionTransition request).mutation = some mutation) :
    paymentLinksAdmissible request.currentInput.payments request.currentInput.actions
      request.command.paymentLinks = true := by
  sorry

/-- Main theorem: for every action, the paid-so-far Lean decided with (and
    echoes in the facts) is the sum of the active snapshot payment rows linked
    to it.  No caller-supplied total exists. -/
theorem applyCorrectionTransition_paid_eq_linked
    (request : CorrectionTransitionRequest) (mutation : CorrectionMutation)
    (hMutation : (applyCorrectionTransition request).mutation = some mutation) :
    ∀ actionId, correctionPaidCents mutation.dependencies.correctionPaid actionId =
      linkedActivePaidCents request.currentInput.payments request.command.paymentLinks
        actionId := by
  sorry

/-- Corollary (B2 over derived paid): the request is the smaller of the
    rejected claim and the shortfall less what open corrections, net of their
    linked active payments, still ask for. -/
theorem applyCorrectionTransition_action_amount_eq_linked
    (request : CorrectionTransitionRequest) (mutation : CorrectionMutation)
    (hMutation : (applyCorrectionTransition request).mutation = some mutation) :
    ∃ result, evaluate request.currentInput = some result ∧
      linkedOutstandingCents request.currentInput.payments request.command.paymentLinks
          request.currentInput.actions < result.shortfallCents ∧
      mutation.action.amountCents = min mutation.dependencies.claimBefore.amountCents
        (result.shortfallCents -
          linkedOutstandingCents request.currentInput.payments request.command.paymentLinks
            request.currentInput.actions) ∧
      mutation.action.amountCents ≤ result.shortfallCents := by
  sorry

/-- H1 over derived paid. -/
theorem applyCorrectionTransition_outstanding_within_shortfall_linked
    (request : CorrectionTransitionRequest) (mutation : CorrectionMutation)
    (hMutation : (applyCorrectionTransition request).mutation = some mutation) :
    ∃ result, evaluate request.currentInput = some result ∧
      linkedOutstandingCents request.currentInput.payments request.command.paymentLinks
          (mutation.action :: request.currentInput.actions) ≤ result.shortfallCents := by
  sorry

end BlindLedger.Financial.CorrectionTransition
