import BlindLedger.Financial.CorrectionTransition.Theorems.Core

/-! M4 (design 3.3): the A1 closure for the correction path, and the authorize-offset decision
    (A3): who may decide, what it writes, and that it moves exactly the claim's cents into the
    lawful sum and nothing else. -/

namespace BlindLedger.Financial.CorrectionTransition

open BlindLedger.Financial BlindLedger.Financial.DecisionPackage

/-- A1 closure: the command's digest is the digest of the roster that authorized the actor. -/
theorem applyCorrectionTransition_authority_bound (request : CorrectionTransitionRequest)
    (mutation : CorrectionMutation)
    (hMutation : (applyCorrectionTransition request).mutation = some mutation) :
    authorityDigestOf request.currentInput.authority = request.command.currentAuthorityDigest ∧
      mutation.determination.authorityDigest = request.command.currentAuthorityDigest ∧
      request.currentInput.pack.approvedAt ≤ mutation.determination.decidedAt ∧
      mutation.determination.decidedAt ≤ request.command.ownerNowMs := by
  unfold applyCorrectionTransition at hMutation
  cases hP : preflightCorrectionTransition request with
  | error r => simp [hP, reject] at hMutation
  | ok p =>
    cases p with
    | duplicate => simp [hP, duplicate] at hMutation
    | ready cr claim a b paid c d =>
      dsimp only at hMutation
      cases hB : buildAccepted request cr claim b paid c d with
      | error r => simp [hP, hB, reject] at hMutation
      | ok certified =>
        obtain ⟨m, links⟩ := certified
        simp [hP, hB] at hMutation
        subst hMutation
        obtain ⟨hDig, hPack, hNow, -, -, hs, -⟩ :=
          preflightOffsetDecision_ready_facts (preflightCorrectionTransition_shared hP)
        obtain ⟨-, -, -, -, hDecided, -⟩ := buildAccepted_facts hB
        have hs' := hs
        simp only [sameAuthority, Bool.and_eq_true, decide_eq_true_eq] at hs'
        exact ⟨hDig, links.determinationActor.2.2.2.2.trans hs'.2, hDecided ▸ hPack, hDecided ▸ hNow⟩

private theorem offsetAuth_ready {request : CorrectionTransitionRequest} {mutation : CorrectionMutation}
    (h : (applyOffsetAuthorization request).mutation = some mutation) :
    ∃ cr claim a b paid c,
      preflightOffsetDecision .OFFSET_AUTHORIZED request = .ok (.ready cr claim a b paid c) ∧
      buildAuthorized request cr claim paid = .ok mutation := by
  unfold applyOffsetAuthorization at h
  cases hP : preflightOffsetDecision .OFFSET_AUTHORIZED request with
  | error r => simp [hP, reject] at h
  | ok p =>
    cases p with
    | duplicate => simp [hP, duplicateOf, duplicate] at h
    | ready cr claim a b paid c =>
      cases hB : buildAuthorized request cr claim paid with
      | error r => simp [hP, hB, reject] at h
      | ok m =>
        simp [hP, hB] at h
        subst h
        exact ⟨cr, claim, a, b, paid, c, rfl, hB⟩

/-- A3: A1's conjuncts for the second decision path, with the digest binding. -/
theorem applyOffsetAuthorization_mutation_authorized (request : CorrectionTransitionRequest)
    (mutation : CorrectionMutation)
    (hMutation : (applyOffsetAuthorization request).mutation = some mutation) :
    request.currentInput.context.mode ≠ .SHADOW ∧
      sameAuthority request.currentInput.authority request.command.currentAuthorityId
        request.command.currentAuthorityEpoch request.command.currentAuthorityDigest = true ∧
      authorityDigestOf request.currentInput.authority = request.command.currentAuthorityDigest ∧
      authorityActorBindingWellFormed request.currentInput.authority request.command.actorId
        request.command.actorRole = true ∧
      request.currentInput.pack.authorizedRoles.contains request.command.actorRole = true ∧
      request.currentInput.pack.status = .APPROVED ∧
      request.currentInput.pack.approvedAt ≤ mutation.determination.decidedAt ∧
      mutation.determination.decidedAt ≤ request.command.ownerNowMs ∧
      mutation.determination.decision = .OFFSET_AUTHORIZED ∧
      mutation.determination.actorId = request.command.actorId ∧
      mutation.determination.actorRole = request.command.actorRole ∧
      mutation.determination.authorityId = request.command.currentAuthorityId ∧
      mutation.determination.authorityEpoch = request.command.currentAuthorityEpoch ∧
      mutation.determination.authorityDigest = request.command.currentAuthorityDigest := by
  obtain ⟨cr, claim, a, b, paid, c, hP, hB⟩ := offsetAuth_ready hMutation
  obtain ⟨hDig, hPack, hNow, hm, hWf, hs, hbind, hc, -⟩ := preflightOffsetDecision_ready_facts hP
  obtain ⟨-, -, hDec, hA1, hA2, hA3, hA4, hA5, hDecided, -⟩ := buildAuthorized_spec hB
  have hApproved : request.currentInput.pack.status = .APPROVED := by
    have hPackWf : controlPackWellFormed request.currentInput.pack = true := by
      unfold financialInputWellFormed at hWf
      simp only [envWellFormed, envOf, Bool.and_eq_true, decide_eq_true_eq] at hWf
      grind
    simp only [controlPackWellFormed, Bool.and_eq_true, decide_eq_true_eq] at hPackWf
    grind
  have hs' := hs
  simp only [sameAuthority, Bool.and_eq_true, decide_eq_true_eq] at hs'
  exact ⟨hm, hs, hDig, hbind, hc, hApproved, hDecided ▸ hPack, hDecided ▸ hNow, hDec, hA1, hA2,
    hA3.trans hs'.1.1, hA4.trans hs'.1.2, hA5.trans hs'.2⟩

/-- Flipping the one claim from CLAIMED to AUTHORIZED adds its cents to the authorized sum. -/
private theorem authorized_sum_flip (c : Claim) (hc : c.status = .CLAIMED) :
    ∀ cs : List Claim, c ∈ cs → (cs.map Claim.claimId).Nodup →
      (((cs.map (fun x => if x.claimId = c.claimId then { c with status := .AUTHORIZED } else x)).filter
          fun y => y.status = .AUTHORIZED).map Claim.amountCents).sum =
        ((cs.filter fun y => y.status = .AUTHORIZED).map Claim.amountCents).sum + c.amountCents
  | [], h, _ => absurd h List.not_mem_nil
  | x :: xs, hmem, hn => by
    simp only [List.map_cons, List.nodup_cons] at hn
    by_cases hx : x = c
    · subst hx
      have hmap : xs.map (fun z => if z.claimId = x.claimId then { x with status := .AUTHORIZED }
          else z) = xs := by
        have this : ∀ y ∈ xs, y.claimId ≠ x.claimId :=
          fun y hy h => hn.1 (h ▸ List.mem_map.2 ⟨y, hy, rfl⟩)
        exact (List.map_congr_left (fun y hy => by simp [this y hy])).trans (List.map_id xs)
      simp [hc, hmap]
      omega
    · have hmx : c ∈ xs := (List.mem_cons.1 hmem).resolve_left (Ne.symm hx)
      have hxid : x.claimId ≠ c.claimId := fun h => hn.1 (h ▸ List.mem_map.2 ⟨c, hmx, rfl⟩)
      have ih := authorized_sum_flip c hc xs hmx hn.2
      by_cases hs : x.status = .AUTHORIZED <;> simp [hxid, hs, ih] <;> omega

/-- The same flip leaves the claimed sum alone. -/
private theorem claimed_sum_flip (c : Claim) (hc : c.status = .CLAIMED) :
    ∀ cs : List Claim, (∀ x ∈ cs, x.claimId = c.claimId → x = c) →
      evalClaimedSum (cs.map (fun x => if x.claimId = c.claimId then { c with status := .AUTHORIZED }
        else x)) = evalClaimedSum cs
  | [], _ => rfl
  | x :: xs, h => by
    have ih := claimed_sum_flip c hc xs (fun y hy => h y (List.mem_cons_of_mem _ hy))
    by_cases hx : x.claimId = c.claimId
    · have := h x (List.mem_cons_self ..) hx
      subst this
      simp [List.map_cons, evalClaimedSum, ih, hc]
    · simp [List.map_cons, evalClaimedSum, ih, hx]

/-- RESTATED (evaluator-v1 5.4 `stepAuthorizeOffset_adds_lawful`): authorizing moves the claim's cents
    into the lawful sum and leaves cash, the claimed sum and what is owed alone. -/
theorem applyOffsetAuthorization_adds_lawful (request : CorrectionTransitionRequest)
    (mutation : CorrectionMutation)
    (hMutation : (applyOffsetAuthorization request).mutation = some mutation) :
    ∃ before claim, evaluate request.currentInput = some before ∧ claim ∈ request.currentInput.claims ∧
      claim.claimId = request.command.claimId ∧ claim.status = .CLAIMED ∧
      evaluate mutation.resultingInput = some mutation.resultingResult ∧
      mutation.resultingResult.lawfulAdjustmentCents = before.lawfulAdjustmentCents + claim.amountCents ∧
      mutation.resultingResult.claimedAdjustmentCents = before.claimedAdjustmentCents ∧
      mutation.resultingResult.receivedCashCents = before.receivedCashCents ∧
      mutation.resultingResult.owedCents = before.owedCents ∧
      mutation.resultingResult.shortfallCents = before.shortfallCents - claim.amountCents ∧
      mutation.determination.amountCents = claim.amountCents ∧
      mutation.action.amountCents = claim.amountCents := by
  obtain ⟨cr, claim, a, b, paid, c, hP, hB⟩ := offsetAuth_ready hMutation
  obtain ⟨-, -, -, -, hWf, -, -, -, hFind, hSt, -⟩ := preflightOffsetDecision_ready_facts hP
  obtain ⟨hcMem, hcId⟩ := findClaim_mem _ _ _ hFind
  obtain ⟨-, -, -, -, -, -, -, -, -, hAmtD, -, -, hAmtA, -, -, hClaims, hPay, hObl, hEval, -⟩ :=
    buildAuthorized_spec hB
  obtain ⟨-, cash0, claimed0, lawful0, hp0, hc0, hl0, -, hr0⟩ := evaluate_facts b
  obtain ⟨-, cash1, claimed1, lawful1, hp1, hc1, hl1, -, hr1⟩ := evaluate_facts hEval
  have hNodup : (request.currentInput.claims.map Claim.claimId).Nodup :=
    (canonical_facts (wf_claim_ids hWf)).2.2.imp (fun {a b} h hab => by
      subst hab
      exact String.lt_irrefl _ h)
  have hCash : cash1 = cash0 := by
    rw [hPay, hp0] at hp1
    exact (Option.some.inj hp1).symm
  rw [← hcId] at hClaims
  have hClaimed : claimed1 = claimed0 := by
    rw [hClaims, claimed_sum_flip claim hSt _ (fun x hx hid =>
      by
        have h1 := findClaim_of_mem _ x hx hNodup
        rw [hid] at h1
        exact Option.some.inj (h1.symm.trans (findClaim_of_mem _ claim hcMem hNodup))), hc0] at hc1
    exact (Option.some.inj hc1).symm
  have hLawful : lawful1 = lawful0 + claim.amountCents := by
    have h1 := (evalLawfulSum_active _ _ hl1).1
    have h0 := (evalLawfulSum_active _ _ hl0).1
    rw [hClaims, authorized_sum_flip claim hSt _ hcMem hNodup, h0] at h1
    exact h1.symm
  subst hr0
  refine ⟨_, claim, b, hcMem, hcId, hSt, hEval, ?_, ?_, ?_, ?_, ?_, hAmtD, hAmtA⟩ <;>
    rw [hr1] <;> simp only [evaluateResult, hObl, hCash, hLawful, hClaimed]
  split <;> split <;> omega

/-- The claim row becomes AUTHORIZED and nothing else about it changes; the action is the authorization. -/
theorem applyOffsetAuthorization_claim_authorized (request : CorrectionTransitionRequest)
    (mutation : CorrectionMutation)
    (hMutation : (applyOffsetAuthorization request).mutation = some mutation) :
    { mutation.dependencies.claimBefore with status := .AUTHORIZED } ∈ mutation.resultingInput.claims ∧
      mutation.dependencies.claimBefore.claimId = request.command.claimId ∧
      mutation.action.kind = "OFFSET_AUTHORIZATION" ∧
      mutation.action.actionId = request.command.actionId ∧
      mutation.action.payloadDigest = correctionActionPayloadDigest
        (offsetActionPayload "OFFSET_AUTHORIZATION" request mutation.determination.determinationId
          mutation.action.revision mutation.action.amountCents) := by
  obtain ⟨cr, claim, a, b, paid, c, hP, hB⟩ := offsetAuth_ready hMutation
  obtain ⟨-, -, -, -, -, -, -, -, hFind, -⟩ := preflightOffsetDecision_ready_facts hP
  obtain ⟨hcMem, hcId⟩ := findClaim_mem _ _ _ hFind
  obtain ⟨hCB, -, -, -, -, -, -, -, -, -, hK, hAid, -, -, hPay, hClaims, -⟩ := buildAuthorized_spec hB
  rw [hCB, hClaims]
  exact ⟨List.mem_map.2 ⟨claim, hcMem, by simp [hcId]⟩, hcId, hK, hAid, hPay⟩

/-- At most once: a claim that is not CLAIMED is never authorized. -/
theorem applyOffsetAuthorization_needs_claimed (request : CorrectionTransitionRequest)
    (h : ∀ claim, findClaim request.currentInput.claims request.command.claimId = some claim →
      claim.status ≠ .CLAIMED) :
    (applyOffsetAuthorization request).mutation = none := by
  unfold applyOffsetAuthorization
  cases hP : preflightOffsetDecision .OFFSET_AUTHORIZED request with
  | error r => simp [hP, reject]
  | ok p =>
    cases p with
    | duplicate => simp [hP, duplicateOf, duplicate]
    | ready cr claim a b paid c =>
      obtain ⟨-, -, -, -, -, -, -, -, hFind, hSt, -⟩ := preflightOffsetDecision_ready_facts hP
      exact absurd hSt (h claim hFind)

/-- Authorization moves no cash and creates no debt: shortfall never grows. -/
theorem applyOffsetAuthorization_shortfall_le (request : CorrectionTransitionRequest)
    (mutation : CorrectionMutation)
    (hMutation : (applyOffsetAuthorization request).mutation = some mutation) :
    ∃ before, evaluate request.currentInput = some before ∧
      mutation.resultingResult.shortfallCents ≤ before.shortfallCents := by
  obtain ⟨before, claim, hb, -, -, -, -, -, -, -, -, hS, -, -⟩ :=
    applyOffsetAuthorization_adds_lawful request mutation hMutation
  exact ⟨before, hb, by omega⟩

/-- An accepted authorization dated on or before the due date is written on or before it
    (Python `decision_time_backdated_past_due`, checker `action:backdated-past-due`). -/
theorem applyOffsetAuthorization_not_backdated (request : CorrectionTransitionRequest)
    (mutation : CorrectionMutation)
    (hMutation : (applyOffsetAuthorization request).mutation = some mutation) :
    mutation.determination.decidedAt ≤ request.currentInput.obligation.dueAt →
      mutation.action.createdAt ≤ request.currentInput.obligation.dueAt := by
  obtain ⟨cr, claim, a, b, paid, c, hP, hB⟩ := offsetAuth_ready hMutation
  obtain ⟨-, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, hBack⟩ :=
    preflightOffsetDecision_ready_facts hP
  obtain ⟨-, -, -, -, -, -, -, -, hDecided, -, -, -, -, -, -, -, -, -, -, hCreated⟩ :=
    buildAuthorized_spec hB
  intro hle
  rw [hCreated]
  exact hBack rfl (hDecided ▸ hle)

/-- M1: an accepted authorization never claims more than the shortfall it closes (Python
    `offset_exceeds_shortfall`, checker `action:exceeds-shortfall`), so overage stays 0. -/
theorem applyOffsetAuthorization_within_shortfall (request : CorrectionTransitionRequest)
    (mutation : CorrectionMutation)
    (hMutation : (applyOffsetAuthorization request).mutation = some mutation) :
    ∃ before, evaluate request.currentInput = some before ∧
      mutation.determination.amountCents ≤ before.shortfallCents := by
  obtain ⟨cr, claim, a, b, paid, c, hP, hB⟩ := offsetAuth_ready hMutation
  have hWithin := preflightOffsetDecision_ready_within_shortfall hP
  obtain ⟨-, -, -, -, -, -, -, -, -, hAmtD, -⟩ := buildAuthorized_spec hB
  refine ⟨cr, b, ?_⟩
  rw [hAmtD]
  exact hWithin rfl

/-- Each entry point reports only its own transition kind: a correction retry never comes back as
    an authorization, nor an authorization retry as a correction. -/
theorem applyOffsetAuthorization_transition_kind (request : CorrectionTransitionRequest) :
    (applyOffsetAuthorization request).explanation.transition = none ∨
      (applyOffsetAuthorization request).explanation.transition = some .OFFSET_AUTHORIZED := by
  unfold applyOffsetAuthorization
  cases preflightOffsetDecision .OFFSET_AUTHORIZED request with
  | error r => simp [reject]
  | ok p =>
    cases p with
    | duplicate => simp [duplicateOf]
    | ready cr claim a b paid c =>
      rcases hB : buildAuthorized request cr claim paid with r | m <;> simp [hB, reject]

theorem applyCorrectionTransition_transition_kind (request : CorrectionTransitionRequest) :
    (applyCorrectionTransition request).explanation.transition = none ∨
      (applyCorrectionTransition request).explanation.transition =
        some .OFFSET_REJECTED_CORRECTION_AUTHORIZED := by
  unfold applyCorrectionTransition
  cases preflightCorrectionTransition request with
  | error r => simp [reject]
  | ok p =>
    cases p with
    | duplicate => simp [duplicate]
    | ready cr claim a b paid c d =>
      rcases hB : buildAccepted request cr claim b paid c d with r | m <;> simp [hB, reject]

private theorem bind_ite' {ε α β : Type} (c : Prop) [Decidable c] (a b : Except ε α) (k : α → Except ε β) :
    (ite c a b >>= k) = ite c (a >>= k) (b >>= k) := by split <;> rfl
private theorem bind_dite' {ε α β : Type} (c : Prop) [Decidable c] (a : c → Except ε α)
    (b : ¬c → Except ε α) (k : α → Except ε β) :
    (dite c a b >>= k) = dite c (fun h => a h >>= k) (fun h => b h >>= k) := by split <;> rfl
private theorem throw_bind' {ε α β : Type} (e : ε) (k : α → Except ε β) :
    ((throw e : Except ε α) >>= k) = throw e := rfl
private theorem map_throw' {ε α β : Type} (e : ε) (f : α → β) :
    (f <$> (throw e : Except ε α)) = throw e := rfl

/-- Once a request passes the three M4 checks (roster digest, control-pack date, owner clock),
    the M4 correction preflight returns exactly what the pre-M4 one returned. -/
theorem preflightCorrectionTransition_agrees_v0 (request : CorrectionTransitionRequest)
    (hDigest : authorityDigestOf request.currentInput.authority = request.command.currentAuthorityDigest)
    (hPack : request.currentInput.pack.approvedAt ≤ request.command.decisionAtMs)
    (hNow : request.command.decisionAtMs ≤ request.command.ownerNowMs) :
    (preflightCorrectionTransition request).toOption.isSome =
        (preflightCorrectionTransitionV0 request).toOption.isSome ∧
      (match preflightCorrectionTransition request, preflightCorrectionTransitionV0 request with
        | .error a, .error b => a = b
        | .ok _, .ok _ => True
        | _, _ => False) := by
  have h1 := Nat.not_lt.2 hPack
  have h2 := Nat.not_lt.2 hNow
  have hEq : preflightCorrectionTransition request = preflightCorrectionTransitionV0 request := by
    unfold preflightCorrectionTransition preflightOffsetDecision preflightCorrectionTransitionV0
    cases hal : request.command.actionLookup <;>
      simp [bind_ite', throw_bind', pure_bind, hDigest, h1, h2, hal]
    all_goals (try rfl)
    cases optionWithProof (derivedCorrectionPaid request.currentInput.payments
        request.currentInput.actions request.command.paymentLinks) <;>
      cases findClaim request.currentInput.claims request.command.claimId <;>
      cases evaluateWithProof request.currentInput <;>
      (try simp [bind_ite', bind_dite', throw_bind', map_throw', pure_bind]) <;> rfl
  rw [hEq]
  exact ⟨rfl, by cases preflightCorrectionTransitionV0 request <;> simp⟩


end BlindLedger.Financial.CorrectionTransition
