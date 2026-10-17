import BlindLedger.Financial.Codec
import BlindLedger.Financial.Evaluation

namespace BlindLedger.Financial

def specToEvalContribution (contribution : SpecContribution) : EvalContribution :=
  { time := contribution.time
    identity := contribution.identity
    amountCents := contribution.amountCents }

theorem evalAdd_matches_specAdd (left right : Nat) :
    evalAdd left right = specAdd left right := rfl

theorem evalPaymentSum_matches_spec (payments : List Payment) :
    evalPaymentSum payments = specSum (specPaymentAmounts payments) := by
  induction payments with
  | nil => rfl
  | cons payment rest ih =>
      by_cases h : payment.status = .ACTIVE
      · simp [evalPaymentSum, specPaymentAmounts, ih, evalAdd_matches_specAdd, h,
          specSum]
      · simp [evalPaymentSum, specPaymentAmounts, ih, evalAdd_matches_specAdd, h,
          specSum]

theorem evalClaimedSum_matches_spec (claims : List Claim) :
    evalClaimedSum claims = specSum (specClaimedAmounts claims) := by
  induction claims with
  | nil => rfl
  | cons claim rest ih =>
      by_cases h : claim.status = .CLAIMED || claim.status = .AUTHORIZED
      · simp [evalClaimedSum, specClaimedAmounts, ih, evalAdd_matches_specAdd, h,
          specSum]
      · simp [evalClaimedSum, specClaimedAmounts, ih, evalAdd_matches_specAdd, h,
          specSum]

theorem evalLawfulSum_matches_spec (claims : List Claim) :
    evalLawfulSum claims = specSum (specLawfulAmounts claims) := by
  induction claims with
  | nil => rfl
  | cons claim rest ih =>
      by_cases h : claim.status = .AUTHORIZED
      · simp [evalLawfulSum, specLawfulAmounts, ih, evalAdd_matches_specAdd, h,
          specSum]
      · simp [evalLawfulSum, specLawfulAmounts, ih, evalAdd_matches_specAdd, h,
          specSum]

theorem evalPaymentContributions_matches_spec (payments : List Payment) :
    payments.foldr
        (fun payment rest =>
          if payment.status = .ACTIVE then
            { time := payment.eventAt
              identity := payment.paymentId
              amountCents := payment.amountCents } :: rest
          else rest) [] =
      (payments.filterMap (fun payment =>
        if payment.status = .ACTIVE then
          some
            { time := payment.eventAt
              identity := payment.paymentId
              amountCents := payment.amountCents }
        else none)).map specToEvalContribution := by
  induction payments with
  | nil => rfl
  | cons payment rest ih =>
      by_cases h : payment.status = .ACTIVE
      · simp [ih, h]
        rfl
      · simp [ih, h]

theorem evalDeterminationContributions_matches_spec
    (determinations : List OffsetDetermination) :
    determinations.foldr
        (fun determination rest =>
          if determination.decision = .OFFSET_AUTHORIZED then
            { time := determination.decidedAt
              identity := determination.determinationId
              amountCents := determination.amountCents } :: rest
          else rest) [] =
      (determinations.filterMap (fun determination =>
        if determination.decision = .OFFSET_AUTHORIZED then
          some
            { time := determination.decidedAt
              identity := determination.determinationId
              amountCents := determination.amountCents }
        else none)).map specToEvalContribution := by
  induction determinations with
  | nil => rfl
  | cons determination rest ih =>
      by_cases h : determination.decision = .OFFSET_AUTHORIZED
      · simp [ih, h]
        rfl
      · simp [ih, h]

theorem evalContributions_matches_spec (input : FinancialInput) :
    evalContributions input =
      (specContributions input).map specToEvalContribution := by
  simp [evalContributions, specContributions,
    evalPaymentContributions_matches_spec,
    evalDeterminationContributions_matches_spec]

private theorem specContributionBefore_matches_contributionKeyBefore
    (left right : SpecContribution) :
    specContributionBefore left right =
      contributionKeyBefore left.time left.amountCents left.identity
        right.time right.amountCents right.identity := by
  rfl

theorem evalInsertContribution_matches_spec (value : SpecContribution)
    (values : List SpecContribution) :
    evalInsertContribution (specToEvalContribution value)
        (values.map specToEvalContribution) =
      (specInsertContribution value values).map specToEvalContribution := by
  induction values with
  | nil => rfl
  | cons first rest ih =>
      by_cases h : contributionKeyBefore value.time value.amountCents value.identity
          first.time first.amountCents first.identity
      · simp [evalInsertContribution, specInsertContribution,
          specContributionBefore_matches_contributionKeyBefore,
          specToEvalContribution, h]
      · simpa [evalInsertContribution, specInsertContribution,
          specContributionBefore_matches_contributionKeyBefore,
          specToEvalContribution, h] using ih

theorem evalSortContributions_matches_spec (values : List SpecContribution) :
    evalSortContributions (values.map specToEvalContribution) =
      (specSortContributions values).map specToEvalContribution := by
  induction values with
  | nil => rfl
  | cons first rest ih =>
      simp [evalSortContributions, specSortContributions, ih,
        evalInsertContribution_matches_spec]

theorem evalCompletionLoop_matches_spec (owed total : Nat)
    (values : List SpecContribution) :
    evalCompletionLoop owed total (values.map specToEvalContribution) =
      specCompletionLoop owed total values := by
  induction values generalizing total with
  | nil => rfl
  | cons value rest ih =>
      cases hAdd : specAdd total value.amountCents with
      | none => simp [evalCompletionLoop, specCompletionLoop,
          specToEvalContribution, evalAdd_matches_specAdd, hAdd]
      | some next =>
          by_cases hDone : next ≥ owed
          · simp [evalCompletionLoop, specCompletionLoop,
              specToEvalContribution, evalAdd_matches_specAdd, hAdd, hDone]
          · simp [evalCompletionLoop, specCompletionLoop,
              specToEvalContribution, evalAdd_matches_specAdd, hAdd, hDone, ih]

theorem evalLatestContributionTime_matches_spec (values : List SpecContribution) :
    evalLatestContributionTime (values.map specToEvalContribution) =
      specLatestContributionTime values := by
  induction values with
  | nil => rfl
  | cons value rest ih =>
      simp only [List.map_cons, evalLatestContributionTime,
        specLatestContributionTime, specToEvalContribution]
      rw [ih]
      rfl

theorem evalCompletion_matches_spec (input : FinancialInput) :
    evalCompletion input = specCompletion input input.obligation.owedCents := by
  simp [evalCompletion, specCompletion, evalContributions_matches_spec,
    evalSortContributions_matches_spec, evalCompletionLoop_matches_spec,
    evalPaymentSum_matches_spec, evalLawfulSum_matches_spec,
    evalAdd_matches_specAdd, evalLatestContributionTime_matches_spec]
  rfl

theorem evalLatestCase_matches_spec (cases : List CaseRecord) :
    evalLatestCase cases = specLatestCaseValue cases := by
  induction cases with
  | nil => rfl
  | cons caseRecord rest ih =>
      cases rest with
      | nil => rfl
      | cons second tail => simp [evalLatestCase, specLatestCaseValue, ih]

theorem evalLatestAction_matches_spec (actions : List ActionRecord) :
    evalLatestAction actions = specLatestActionRecord actions := by
  induction actions with
  | nil => rfl
  | cons action rest ih =>
      simp [evalLatestAction, specLatestActionRecord, evalActionIsLater,
        specActionIsLater, ih]
      rfl

theorem evalLatestDelivery_matches_spec (actions : List ActionRecord) :
    evalLatestDelivery actions = specLatestAction actions := by
  cases actions <;>
    simp [evalLatestDelivery, specLatestAction, evalLatestAction_matches_spec]
  rfl

theorem specTimely_identity (input : FinancialInput) :
    (match specCompletion input input.obligation.owedCents with
    | none => false
    | some completionTime => decide (completionTime ≤ input.obligation.dueAt)) =
    (match specCompletion input input.obligation.owedCents with
    | none => false
    | some completionTime => decide (completionTime ≤ input.obligation.dueAt)) := by
  rfl

theorem evalTimely_matches_spec (input : FinancialInput) :
    (match evalCompletion input with
    | none => false
    | some completionTime => decide (completionTime ≤ input.obligation.dueAt)) =
    (match specCompletion input input.obligation.owedCents with
    | none => false
    | some completionTime => decide (completionTime ≤ input.obligation.dueAt)) := by
  rw [evalCompletion_matches_spec]

theorem evaluateWellFormed_matches_specification
    (input : FinancialInput) (result : FinancialResult)
    (hInput : financialInputWellFormed input = true)
    (h : evaluateWellFormed input = some result) :
    satisfiesSpecification input result := by
  simp only [evaluateWellFormed, Option.map_eq_some_iff] at h
  rcases h with ⟨totals, hTotals, hResult⟩
  have hCashNe : evalPaymentSum input.payments ≠ none := by
    intro hNone
    have hTotalsNone : evaluateTotals input = none := by
      simpa only [evaluateTotals, hNone]
    have hImpossible : (none : Option EvaluatedTotals) = some totals :=
      hTotalsNone.symm.trans hTotals
    cases hImpossible
  obtain ⟨cash, hCash⟩ := Option.ne_none_iff_exists'.mp hCashNe
  have hClaimedNe : evalClaimedSum input.claims ≠ none := by
    intro hNone
    have hTotalsNone : evaluateTotals input = none := by
      simpa only [evaluateTotals, hCash, hNone]
    have hImpossible : (none : Option EvaluatedTotals) = some totals :=
      hTotalsNone.symm.trans hTotals
    cases hImpossible
  obtain ⟨claimed, hClaimed⟩ := Option.ne_none_iff_exists'.mp hClaimedNe
  have hLawfulNe : evalLawfulSum input.claims ≠ none := by
    intro hNone
    have hTotalsNone : evaluateTotals input = none := by
      simpa only [evaluateTotals, hCash, hClaimed, hNone]
    have hImpossible : (none : Option EvaluatedTotals) = some totals :=
      hTotalsNone.symm.trans hTotals
    cases hImpossible
  obtain ⟨lawful, hLawful⟩ := Option.ne_none_iff_exists'.mp hLawfulNe
  have hTotalNe : evalAdd cash lawful ≠ none := by
    intro hNone
    have hTotalsNone : evaluateTotals input = none := by
      simpa only [evaluateTotals, hCash, hClaimed, hLawful, hNone]
    have hImpossible : (none : Option EvaluatedTotals) = some totals :=
      hTotalsNone.symm.trans hTotals
    cases hImpossible
  obtain ⟨total, hTotal⟩ := Option.ne_none_iff_exists'.mp hTotalNe
  have hTotalsExpected :
      ({ cash := cash, claimed := claimed, lawful := lawful, total := total } : EvaluatedTotals) = totals := by
    have hTotalsReduced :
        some ({ cash := cash, claimed := claimed, lawful := lawful, total := total } : EvaluatedTotals) =
          some totals := by
      simpa only [evaluateTotals, hCash, hClaimed, hLawful, hTotal] using hTotals
    exact Option.some.inj hTotalsReduced
  cases hTotalsExpected
  have hCashSpec : specSum (specPaymentAmounts input.payments) = some cash := by
    rw [← evalPaymentSum_matches_spec input.payments]
    exact hCash
  have hClaimedSpec : specSum (specClaimedAmounts input.claims) = some claimed := by
    rw [← evalClaimedSum_matches_spec input.claims]
    exact hClaimed
  have hLawfulSpec : specSum (specLawfulAmounts input.claims) = some lawful := by
    rw [← evalLawfulSum_matches_spec input.claims]
    exact hLawful
  have hTotalSpec : specAdd cash lawful = some total := by
    rw [← evalAdd_matches_specAdd]
    exact hTotal
  have hResult' : evaluateResult input cash claimed lawful total = result := hResult
  cases hResult'
  let expected : SpecProjection :=
    { evidenceIds := input.evidence.map EvidenceRecord.evidenceId
      completionAt := specCompletion input input.obligation.owedCents
      owedCents := input.obligation.owedCents
      claimedAdjustmentCents := claimed
      lawfulAdjustmentCents := lawful
      receivedCashCents := cash
      shortfallCents := if input.obligation.owedCents > total then
        input.obligation.owedCents - total else 0
      overageCents := if total > input.obligation.owedCents then
        total - input.obligation.owedCents else 0
      cashSatisfied := cash ≥ input.obligation.owedCents
      amountSatisfied := total ≥ input.obligation.owedCents
      timely := match specCompletion input input.obligation.owedCents with
        | none => false
        | some completionTime => completionTime ≤ input.obligation.dueAt
      reportingComplete := input.obligation.reportingComplete
      verificationStatus := specVerificationStatus input
      caseStatus := specCaseStatus input (total ≥ input.obligation.owedCents)
      deliveryStatus := specLatestAction input.actions }
  have hSpec : specification input = some expected := by
    dsimp [expected]
    simp [specification, hInput, hCashSpec, hClaimedSpec, hLawfulSpec, hTotalSpec] <;> rfl
  unfold satisfiesSpecification
  rw [hSpec]
  simp [expected, evaluateResult, evalTimely_matches_spec,
    evalLatestCase_matches_spec, evalLatestDelivery_matches_spec,
    evalVerificationStatus, specVerificationStatus,
    evalCaseStatus, caseStatusFrom, specCaseStatus]
  have hCompletion := evalCompletion_matches_spec input
  have hTimely := evalTimely_matches_spec input
  have hSpecTimely := specTimely_identity input
  constructor
  · exact hCompletion
  · exact hTimely
  all_goals (exact hSpecTimely)

theorem evaluate_rejects_not_well_formed
    (input : FinancialInput)
    (hInput : financialInputWellFormed input = false) :
    evaluate input = none := by
  simp [evaluate, hInput]

theorem evaluate_satisfies_specification
    (input : FinancialInput) (result : FinancialResult)
    (h : evaluate input = some result) :
    satisfiesSpecification input result := by
  by_cases hInput : financialInputWellFormed input = true
  · have hWell : evaluateWellFormed input = some result := by
      simpa [evaluate, hInput] using h
    exact evaluateWellFormed_matches_specification input result hInput hWell
  · have hFalse : financialInputWellFormed input = false := by
      cases hValue : financialInputWellFormed input <;> simp_all
    simp [evaluate, hFalse] at h

theorem accepted_evaluation_contract
    (input : FinancialInput) (result : FinancialResult)
    (h : evaluate input = some result) :
    financialInputWellFormed input = true ∧
      satisfiesSpecification input result := by
  by_cases hInput : financialInputWellFormed input = true
  · exact ⟨hInput, evaluate_satisfies_specification input result h⟩
  · have hFalse : financialInputWellFormed input = false := by
      cases hValue : financialInputWellFormed input <;> simp_all
    simp [evaluate, hFalse] at h

theorem evaluate_rejects_total_overflow
    (input : FinancialInput) (cash claimed lawful : Nat)
    (hCash : evalPaymentSum input.payments = some cash)
    (hClaimed : evalClaimedSum input.claims = some claimed)
    (hLawful : evalLawfulSum input.claims = some lawful)
    (hOverflow : evalAdd cash lawful = none) :
    evaluate input = none := by
  by_cases hInput : financialInputWellFormed input = true
  · simp [evaluate, hInput, evaluateWellFormed, evaluateTotals,
      hCash, hClaimed, hLawful, hOverflow]
  · have hFalse : financialInputWellFormed input = false := by
      cases hValue : financialInputWellFormed input <;> simp_all
    exact evaluate_rejects_not_well_formed input hFalse

theorem evalAdd_rejects_left_out_of_bounds
    (left right : Nat) (h : maxCents < left) :
    evalAdd left right = none := by
  simp [evalAdd, Nat.not_le.mpr h]

theorem evalAdd_rejects_right_out_of_bounds
    (left right : Nat) (h : maxCents < right) :
    evalAdd left right = none := by
  simp [evalAdd, Nat.not_le.mpr h]


end BlindLedger.Financial
