import BlindLedger.Financial.CorrectionTransition.PaidSumTheorems
import BlindLedger.Financial.Theorems.Conservation

/-! core-theorems-v1 §4.3: a correction moves no money (T2), its open requests stay within the
    balance it leaves (T1.1), and its actor and authority were checked (A1, A1'). -/

namespace BlindLedger.Financial.CorrectionTransition

open BlindLedger.Financial

private theorem linkedOutstandingCents_eq_sum (payments : List Payment) (links : List PaymentLink) :
    ∀ l : List ActionRecord, linkedOutstandingCents payments links l =
      (l.map fun a => if a.kind = "CORRECTION_PAYMENT_REQUEST" ∧ a.status ≠ .CANCELLED then
        a.amountCents - linkedActivePaidCents payments links a.actionId else 0).sum
  | [] => rfl
  | a :: r => by
      simp only [linkedOutstandingCents, List.map_cons, List.sum_cons,
        linkedOutstandingCents_eq_sum payments links r]

theorem linkedOutstandingCents_perm (payments : List Payment) (links : List PaymentLink)
    {l l' : List ActionRecord} (h : l.Perm l') :
    linkedOutstandingCents payments links l = linkedOutstandingCents payments links l' := by
  rw [linkedOutstandingCents_eq_sum, linkedOutstandingCents_eq_sum]
  exact (h.map _).sum_nat

/-- T2: a correction moves no money. -/
theorem applyCorrectionTransition_money_unchanged (request : CorrectionTransitionRequest)
    (mutation : CorrectionMutation)
    (hMutation : (applyCorrectionTransition request).mutation = some mutation) :
    ∃ before, evaluate request.currentInput = some before ∧
      evaluate mutation.resultingInput = some mutation.resultingResult ∧
      mutation.resultingResult.owedCents = before.owedCents ∧
      mutation.resultingResult.receivedCashCents = before.receivedCashCents ∧
      mutation.resultingResult.lawfulAdjustmentCents = before.lawfulAdjustmentCents ∧
      mutation.resultingResult.shortfallCents = before.shortfallCents ∧
      mutation.resultingResult.overageCents = before.overageCents ∧
      mutation.resultingResult.cashSatisfied = before.cashSatisfied ∧
      mutation.resultingResult.amountSatisfied = before.amountSatisfied ∧
      mutation.resultingResult.completionAt = before.completionAt ∧
      mutation.resultingResult.timely = before.timely := by
  have hL := (applyCorrectionTransition_mutation_links request mutation hMutation).2.2.2.2.2.2
  obtain ⟨before, hBefore, -, -⟩ := hL.inputShortfall
  refine ⟨before, hBefore, hL.resultingEvaluates, ?_⟩
  obtain ⟨hWf0, cash0, claimed0, lawful0, hp0, -, hl0, -, hr0⟩ := evaluate_facts hBefore
  obtain ⟨hWf1, cash1, claimed1, lawful1, hp1, -, hl1, -, hr1⟩ :=
    evaluate_facts hL.resultingEvaluates
  obtain ⟨-, -, -, hObl, hPay, -, -⟩ := hL.resultingFrame
  have hCash : cash1 = cash0 := by
    rw [hPay, hp0] at hp1
    exact (Option.some.inj hp1).symm
  have hLawful : lawful1 = lawful0 := by
    rw [← (evalLawfulSum_active _ _ hl1).1, ← (evalLawfulSum_active _ _ hl0).1, ← offset_sum hWf1,
      ← offset_sum hWf0, hL.authorizedDeterminations]
  subst hCash hLawful
  have hc : evalContributions mutation.resultingInput = evalContributions request.currentInput :=
    evalContributions_congr hPay hL.authorizedDeterminations
  have hComp : evalCompletion mutation.resultingInput = evalCompletion request.currentInput := by
    simp only [evalCompletion, hc, hObl, hPay, hl1, hl0]
  subst hr0
  simp only [hr1, evaluateResult, hObl, hComp, and_self]

/-- T1.1: after a correction, open requests are within the balance the correction leaves. -/
theorem applyCorrectionTransition_post_within_shortfall (request : CorrectionTransitionRequest)
    (mutation : CorrectionMutation)
    (hMutation : (applyCorrectionTransition request).mutation = some mutation) :
    evaluate mutation.resultingInput = some mutation.resultingResult ∧
      linkedOutstandingCents mutation.resultingInput.payments request.command.paymentLinks
          mutation.resultingInput.actions ≤ mutation.resultingResult.shortfallCents := by
  have hL := (applyCorrectionTransition_mutation_links request mutation hMutation).2.2.2.2.2.2
  obtain ⟨before, hBefore, -, -, -, -, hShort, -⟩ :=
    applyCorrectionTransition_money_unchanged request mutation hMutation
  obtain ⟨r, hr, hLe⟩ :=
    applyCorrectionTransition_outstanding_within_shortfall_linked request mutation hMutation
  rw [hBefore] at hr
  cases hr
  obtain ⟨-, -, -, -, hPay, -, -⟩ := hL.resultingFrame
  refine ⟨hL.resultingEvaluates, ?_⟩
  rw [hPay, linkedOutstandingCents_perm _ _ hL.resultingActions, hShort]
  exact hLe

private theorem ite_error_ok {c : Prop} [Decidable c] {ε α} {e : ε} {X : Except ε α} {r : α}
    (h : (if c then Except.error e else X) = Except.ok r) : ¬ c ∧ X = Except.ok r := by
  split at h <;> simp_all

/-- A ready preflight has passed the live-mode, well-formedness, authority and actor checks. -/
private theorem preflight_ready_facts {request : CorrectionTransitionRequest}
    {currentResult : FinancialResult} {claim : Claim} {a b paid c d}
    (h : preflightCorrectionTransition request = .ok
      (.ready currentResult claim a b paid c d)) :
    request.currentInput.context.mode ≠ .SHADOW ∧
      financialInputWellFormed request.currentInput = true ∧
      sameAuthority request.currentInput.authority request.command.currentAuthorityId
        request.command.currentAuthorityEpoch request.command.currentAuthorityDigest = true ∧
      authorityActorBindingWellFormed request.currentInput.authority request.command.actorId
        request.command.actorRole = true ∧
      request.currentInput.pack.authorizedRoles.contains request.command.actorRole = true := by
  unfold preflightCorrectionTransition at h
  simp only [bind, Except.bind, pure, Except.pure, throw, throwThe, MonadExceptOf.throw] at h
  obtain ⟨-, h⟩ := ite_error_ok h
  obtain ⟨-, h⟩ := ite_error_ok h
  generalize request.command.actionLookup = L at h
  cases L
  · dsimp only at h
    obtain ⟨-, h⟩ := ite_error_ok h
    obtain ⟨-, h⟩ := ite_error_ok h
    obtain ⟨hShadow, h⟩ := ite_error_ok h
    obtain ⟨hWf, h⟩ := ite_error_ok h
    split at h
    · obtain ⟨-, h⟩ := ite_error_ok h
      obtain ⟨hAuth, h⟩ := ite_error_ok h
      obtain ⟨hActor, -⟩ := ite_error_ok h
      grind
    · exact nomatch h
  · exfalso
    dsimp only at h
    split at h <;> (try split at h) <;> simp at h
  · dsimp only at h
    exact nomatch h

/-- A1: every correction mutation passed the live-mode, authority, actor and pack checks,
    and the recorded determination names exactly that actor and authority. -/
theorem applyCorrectionTransition_mutation_authorized (request : CorrectionTransitionRequest)
    (mutation : CorrectionMutation)
    (hMutation : (applyCorrectionTransition request).mutation = some mutation) :
    request.currentInput.context.mode ≠ .SHADOW ∧
      sameAuthority request.currentInput.authority request.command.currentAuthorityId
        request.command.currentAuthorityEpoch request.command.currentAuthorityDigest = true ∧
      authorityActorBindingWellFormed request.currentInput.authority request.command.actorId
        request.command.actorRole = true ∧
      request.currentInput.pack.authorizedRoles.contains request.command.actorRole = true ∧
      request.currentInput.pack.status = .APPROVED ∧
      mutation.determination.actorId = request.command.actorId ∧
      mutation.determination.actorRole = request.command.actorRole ∧
      mutation.determination.authorityId = request.command.currentAuthorityId ∧
      mutation.determination.authorityEpoch = request.command.currentAuthorityEpoch ∧
      mutation.determination.authorityDigest = request.command.currentAuthorityDigest := by
  have hL := (applyCorrectionTransition_mutation_links request mutation hMutation).2.2.2.2.2.2
  have hReady : ∃ cr claim a b paid c d, preflightCorrectionTransition request =
      .ok (.ready cr claim a b paid c d) := by
    unfold applyCorrectionTransition at hMutation
    cases hP : preflightCorrectionTransition request with
    | error r => simp [hP, reject] at hMutation
    | ok p =>
        cases p with
        | duplicate => simp [hP, duplicate] at hMutation
        | ready cr claim a b paid c d => exact ⟨cr, claim, a, b, paid, c, d, rfl⟩
  obtain ⟨cr, claim, a, b, paid, c, d, hP⟩ := hReady
  obtain ⟨hm, hWf, hs, hbind, hc⟩ := preflight_ready_facts hP
  have hApproved : request.currentInput.pack.status = .APPROVED := by
    have hPack : controlPackWellFormed request.currentInput.pack = true := by
      unfold financialInputWellFormed at hWf
      simp only [Bool.and_eq_true, decide_eq_true_eq] at hWf
      grind
    simp only [controlPackWellFormed, Bool.and_eq_true, decide_eq_true_eq] at hPack
    grind
  obtain ⟨hd1, hd2, hd3, hd4, hd5⟩ := hL.determinationActor
  have hs' := hs
  simp only [sameAuthority, Bool.and_eq_true, decide_eq_true_eq] at hs'
  exact ⟨hm, hs, hbind, hc, hApproved, hd1, hd2, hd3.trans hs'.1.1, hd4.trans hs'.1.2,
    hd5.trans hs'.2⟩

/-- A reuse is allowed only when no environment check denies it. -/
private theorem environment_none_facts {request : CorrectionReuseRequest}
    {mutation : CorrectionMutation}
    (h : executionEnvironmentDenial request mutation = none) :
    request.currentInput.context.mode ≠ .SHADOW ∧
      sameAuthority request.currentInput.authority mutation.dependencies.authorityId
        mutation.dependencies.authorityEpoch mutation.dependencies.authorityDigest = true ∧
      authorityActorBindingWellFormed request.currentInput.authority mutation.determination.actorId
        mutation.determination.actorRole = true ∧
      request.currentInput.pack.authorizedRoles.contains mutation.determination.actorRole = true ∧
      request.currentInput.pack.status = .APPROVED := by
  have hm : request.currentInput.context.mode ≠ .SHADOW := fun hm => by
    simp [executionEnvironmentDenial, hm] at h
  have hs : sameAuthority request.currentInput.authority mutation.dependencies.authorityId
      mutation.dependencies.authorityEpoch mutation.dependencies.authorityDigest = true := by
    refine Classical.byContradiction fun hn => ?_
    simp at hn
    simp [executionEnvironmentDenial, hm, hn] at h
  have hb : authorityActorBindingWellFormed request.currentInput.authority
      mutation.determination.actorId mutation.determination.actorRole = true := by
    refine Classical.byContradiction fun hn => ?_
    simp at hn
    simp [executionEnvironmentDenial, hm, hs, hn] at h
  have hc : request.currentInput.pack.authorizedRoles.contains mutation.determination.actorRole =
      true := by
    refine Classical.byContradiction fun hn => ?_
    simp at hn
    simp [executionEnvironmentDenial, hm, hs, hb, hn] at h
  have hp : request.currentInput.pack.status = .APPROVED := by
    refine Classical.byContradiction fun hn => ?_
    have hc' : mutation.determination.actorRole ∈ request.currentInput.pack.authorizedRoles := by
      simpa using hc
    simp [executionEnvironmentDenial, hm, hs, hb, hc', hn] at h
  exact ⟨hm, hs, hb, hc, hp⟩

/-- A1′: a reuse is ALLOWED only when the stored mutation's actor is still authorized now. -/
theorem assessCorrectionReuse_allowed_authorized (request : CorrectionReuseRequest)
    (hAllowed : (assessCorrectionReuse request).localExecutionPermission = .ALLOWED) :
    ∃ mutation, request.acceptedResult.mutation = some mutation ∧
      request.currentInput.context.mode ≠ .SHADOW ∧
      sameAuthority request.currentInput.authority mutation.dependencies.authorityId
        mutation.dependencies.authorityEpoch mutation.dependencies.authorityDigest = true ∧
      authorityActorBindingWellFormed request.currentInput.authority mutation.determination.actorId
        mutation.determination.actorRole = true ∧
      request.currentInput.pack.authorizedRoles.contains mutation.determination.actorRole = true ∧
      request.currentInput.pack.status = .APPROVED := by
  cases hStatus : request.acceptedResult.status <;>
    cases hMutation : request.acceptedResult.mutation <;>
    simp [assessCorrectionReuse, hStatus, hMutation, executionPermissionOfDenial] at hAllowed
  rename_i mutation
  refine ⟨mutation, rfl, environment_none_facts ?_⟩
  cases hE : executionEnvironmentDenial request mutation with
  | none => rfl
  | some d =>
      exfalso
      simp [assessAcceptedCorrectionReuse, executionDenial, hE, executionPermissionOfDenial]
        at hAllowed

end BlindLedger.Financial.CorrectionTransition
