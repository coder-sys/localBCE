import BlindLedger.Financial.Theorems.Correspondence
import BlindLedger.Financial.WorkerLaws

namespace BlindLedger.Financial

/-! Conservation and totality theorems for the evaluator (docs/core-theorems-v1.md,
    E1-E5, N1a, N1).  Every statement is exactly as approved. -/

/-! ## Sums -/

theorem evalAdd_some {l r t : Nat} (h : evalAdd l r = some t) : t = l + r ∧ t ≤ maxCents := by
  unfold evalAdd at h
  split at h
  · cases h
    rename_i hc
    simp only [Bool.and_eq_true, decide_eq_true_eq] at hc
    exact ⟨rfl, by omega⟩
  · cases h

theorem evalAdd_of_le {l r : Nat} (h : l + r ≤ maxCents) : evalAdd l r = some (l + r) := by
  unfold evalAdd
  split
  · rfl
  · rename_i hc
    simp only [Bool.and_eq_true, decide_eq_true_eq] at hc
    exfalso
    omega

theorem evalPaymentSum_active : ∀ (ps : List Payment) (t : Nat),
    evalPaymentSum ps = some t →
    ((ps.filter fun p => p.status = .ACTIVE).map Payment.amountCents).sum = t ∧ t ≤ maxCents
  | [], t, h => by
      simp only [evalPaymentSum] at h
      cases h
      exact ⟨rfl, Nat.zero_le _⟩
  | p :: ps, t, h => by
      cases hT : evalPaymentSum ps with
      | none => simp [evalPaymentSum, hT] at h
      | some t' =>
          obtain ⟨e1, e2⟩ := evalPaymentSum_active ps t' hT
          by_cases hs : p.status = .ACTIVE
          · simp only [evalPaymentSum, hT, hs, if_true] at h
            obtain ⟨e3, e4⟩ := evalAdd_some (l := p.amountCents) (r := t') h
            refine ⟨?_, e4⟩
            simp [hs, e1, e3]
          · simp only [evalPaymentSum, hT, hs, if_false] at h
            cases h
            exact ⟨by simp [hs, e1], e2⟩

theorem evalLawfulSum_active : ∀ (cs : List Claim) (t : Nat),
    evalLawfulSum cs = some t →
    ((cs.filter fun c => c.status = .AUTHORIZED).map Claim.amountCents).sum = t ∧ t ≤ maxCents
  | [], t, h => by
      simp only [evalLawfulSum] at h
      cases h
      exact ⟨rfl, Nat.zero_le _⟩
  | c :: cs, t, h => by
      cases hT : evalLawfulSum cs with
      | none => simp [evalLawfulSum, hT] at h
      | some t' =>
          obtain ⟨e1, e2⟩ := evalLawfulSum_active cs t' hT
          by_cases hs : c.status = .AUTHORIZED
          · simp only [evalLawfulSum, hT, hs, if_true] at h
            obtain ⟨e3, e4⟩ := evalAdd_some (l := c.amountCents) (r := t') h
            refine ⟨?_, e4⟩
            simp [hs, e1, e3]
          · simp only [evalLawfulSum, hT, hs, if_false] at h
            cases h
            exact ⟨by simp [hs, e1], e2⟩

theorem evalLawfulSum_le_claimed : ∀ (cs : List Claim) (a b : Nat),
    evalLawfulSum cs = some a → evalClaimedSum cs = some b → a ≤ b
  | [], a, b, ha, hb => by
      simp only [evalLawfulSum] at ha
      simp only [evalClaimedSum] at hb
      cases ha
      cases hb
      exact Nat.le_refl _
  | c :: cs, a, b, ha, hb => by
      cases hA : evalLawfulSum cs with
      | none => simp [evalLawfulSum, hA] at ha
      | some a' =>
          cases hB : evalClaimedSum cs with
          | none => simp [evalClaimedSum, hB] at hb
          | some b' =>
              have ih := evalLawfulSum_le_claimed cs a' b' hA hB
              cases hst : c.status
              · simp only [evalLawfulSum, evalClaimedSum, hA, hB, hst] at ha hb
                obtain ⟨e, -⟩ := evalAdd_some (by simpa using hb)
                simp at ha
                omega
              · simp only [evalLawfulSum, evalClaimedSum, hA, hB, hst] at ha hb
                obtain ⟨e1, -⟩ := evalAdd_some (by simpa using ha)
                obtain ⟨e2, -⟩ := evalAdd_some (by simpa using hb)
                omega
              · simp only [evalLawfulSum, evalClaimedSum, hA, hB, hst] at ha hb
                simp at ha hb
                omega

/-! ## Well-formedness facts -/

theorem strictlyAscending_iff :
    ∀ l : List String, strictlyAscending l = true ↔ l.Pairwise (· < ·)
  | [] => by simp [strictlyAscending]
  | [a] => by simp [strictlyAscending]
  | a :: b :: rest => by
      rw [strictlyAscending, Bool.and_eq_true, decide_eq_true_eq, strictlyAscending_iff (b :: rest)]
      constructor
      · rintro ⟨hab, h⟩
        refine List.pairwise_cons.2 ⟨?_, h⟩
        intro x hx
        rcases List.mem_cons.1 hx with rfl | hx
        · exact hab
        · exact String.lt_trans hab ((List.pairwise_cons.1 h).1 x hx)
      · intro h
        obtain ⟨h1, h2⟩ := List.pairwise_cons.1 h
        exact ⟨h1 b (List.mem_cons_self ..), h2⟩

theorem canonical_facts {l : List String} (h : canonicalIdList l = true) :
    l.length ≤ maxRows ∧ (∀ x ∈ l, idWellFormed x = true) ∧ l.Pairwise (· < ·) := by
  simp only [canonicalIdList, Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true] at h
  exact ⟨h.1.1, h.1.2, (strictlyAscending_iff l).1 h.2⟩

theorem noDuplicates_iff : ∀ l : List String, noDuplicates l = true ↔ l.Nodup
  | [] => by simp [noDuplicates]
  | v :: rest => by simp [noDuplicates, noDuplicates_iff rest]

theorem wf_claim_ids {input : FinancialInput} (h : financialInputWellFormed input = true) :
    canonicalIdList (input.claims.map Claim.claimId) = true := by
  unfold financialInputWellFormed at h
  simp only [Bool.and_eq_true] at h
  grind

theorem wf_determinations {input : FinancialInput} (h : financialInputWellFormed input = true) :
    input.determinations.all (determinationWellFormed input) = true := by
  unfold financialInputWellFormed at h
  simp only [Bool.and_eq_true] at h
  grind

theorem wf_claims_terminal {input : FinancialInput} (h : financialInputWellFormed input = true) :
    input.claims.all (claimTerminalWellFormed input) = true := by
  unfold financialInputWellFormed at h
  simp only [Bool.and_eq_true] at h
  grind

theorem wf_determination_claims {input : FinancialInput} (h : financialInputWellFormed input = true) :
    noDuplicates (input.determinations.map OffsetDetermination.claimId) = true := by
  unfold financialInputWellFormed at h
  simp only [Bool.and_eq_true] at h
  grind

theorem wf_owed_pos {input : FinancialInput} (h : financialInputWellFormed input = true) :
    0 < input.obligation.owedCents := by
  have hO : obligationWellFormed input.obligation = true := by
    unfold financialInputWellFormed at h
    simp only [envWellFormed, envOf, Bool.and_eq_true] at h
    grind
  simp only [obligationWellFormed, positiveAmountWellFormed, Bool.and_eq_true, decide_eq_true_eq]
    at hO
  grind

theorem findClaim_mem : ∀ (l : List Claim) (id : String) (c : Claim),
    findClaim l id = some c → c ∈ l ∧ c.claimId = id
  | [], _, _, h => by simp [findClaim] at h
  | x :: xs, id, c, h => by
      by_cases hx : x.claimId = id
      · simp only [findClaim, hx, if_true] at h
        cases h
        exact ⟨by simp, hx⟩
      · simp only [findClaim, hx, if_false] at h
        obtain ⟨hm, hi⟩ := findClaim_mem xs id c h
        exact ⟨by simp [hm], hi⟩

theorem findClaim_of_mem : ∀ (l : List Claim) (c : Claim), c ∈ l →
    (l.map Claim.claimId).Nodup → findClaim l c.claimId = some c
  | [], _, h, _ => by simp at h
  | x :: xs, c, hc, hn => by
      simp only [List.map_cons, List.nodup_cons] at hn
      by_cases hx : x.claimId = c.claimId
      · have hcx : c = x := by
          rcases List.mem_cons.1 hc with h | h
          · exact h
          · exfalso
            exact hn.1 (by rw [hx]; exact List.mem_map.2 ⟨c, h, rfl⟩)
        subst hcx
        simp [findClaim]
      · simp only [findClaim, hx, if_false]
        rcases List.mem_cons.1 hc with h | h
        · subst h
          exact absurd rfl hx
        · exact findClaim_of_mem xs c h hn.2

theorem determination_claim {input : FinancialInput} {d : OffsetDetermination}
    (hd : determinationWellFormed input d = true) :
    ∃ claim, findClaim input.claims d.claimId = some claim ∧ claim.amountCents = d.amountCents ∧
      (d.decision = .OFFSET_AUTHORIZED → claim.status = .AUTHORIZED) := by
  unfold determinationWellFormed at hd
  simp only [Bool.and_eq_true] at hd
  have hm := hd.2
  clear hd
  cases hF : findClaim input.claims d.claimId with
  | none =>
      rw [hF] at hm
      simp at hm
  | some claim =>
      rw [hF] at hm
      refine ⟨claim, rfl, ?_⟩
      cases hdec : d.decision <;> simp [hdec] at hm ⊢ <;> first | exact hm | exact hm.1

theorem claim_authorized_determination {input : FinancialInput} {claim : Claim}
    (ht : claimTerminalWellFormed input claim = true) (hs : claim.status = .AUTHORIZED) :
    ∃ d ∈ input.determinations, d.claimId = claim.claimId ∧ d.decision = .OFFSET_AUTHORIZED := by
  unfold claimTerminalWellFormed determinationsForClaim at ht
  simp only [hs, Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true] at ht
  obtain ⟨hlen, hall⟩ := ht
  obtain ⟨a, ha⟩ := List.length_eq_one_iff.1 hlen
  have hmem : a ∈ input.determinations.filter (fun d => decide (d.claimId = claim.claimId)) := by
    rw [ha]
    simp
  obtain ⟨hin, hid⟩ := List.mem_filter.1 hmem
  exact ⟨a, hin, by simpa using hid, by simpa using hall a hmem⟩

/-- The determinations that authorize an offset carry the same cents as the authorized claims. -/
theorem offset_sum {input : FinancialInput} (hWf : financialInputWellFormed input = true) :
    ((input.determinations.filter fun d => d.decision = .OFFSET_AUTHORIZED).map
        OffsetDetermination.amountCents).sum =
      ((input.claims.filter fun c => c.status = .AUTHORIZED).map Claim.amountCents).sum := by
  have hClaimNodup : (input.claims.map Claim.claimId).Nodup :=
    (canonical_facts (wf_claim_ids hWf)).2.2.imp (fun {a b} h hab => by
      subst hab
      exact String.lt_irrefl _ h)
  have hDetNodup : (input.determinations.map OffsetDetermination.claimId).Nodup :=
    (noDuplicates_iff _).1 (wf_determination_claims hWf)
  have hAll := List.all_eq_true.1 (wf_determinations hWf)
  have hTerm := List.all_eq_true.1 (wf_claims_terminal hWf)
  let f : String → Nat := fun id => ((findClaim input.claims id).map Claim.amountCents).getD 0
  have hD : (input.determinations.filter fun d => d.decision = .OFFSET_AUTHORIZED).map
      OffsetDetermination.amountCents =
      ((input.determinations.filter fun d => d.decision = .OFFSET_AUTHORIZED).map
        OffsetDetermination.claimId).map f := by
    rw [List.map_map]
    apply List.map_congr_left
    intro d hd
    obtain ⟨hdm, -⟩ := List.mem_filter.1 hd
    obtain ⟨cl, hfc, hamt, -⟩ := determination_claim (hAll d hdm)
    simp [f, hfc, hamt]
  have hA : (input.claims.filter fun c => c.status = .AUTHORIZED).map Claim.amountCents =
      ((input.claims.filter fun c => c.status = .AUTHORIZED).map Claim.claimId).map f := by
    rw [List.map_map]
    apply List.map_congr_left
    intro c hc
    obtain ⟨hcm, -⟩ := List.mem_filter.1 hc
    simp [f, findClaim_of_mem _ c hcm hClaimNodup]
  have hNodupD : ((input.determinations.filter fun d => d.decision = .OFFSET_AUTHORIZED).map
      OffsetDetermination.claimId).Nodup :=
    hDetNodup.sublist ((List.filter_sublist).map _)
  have hNodupA : ((input.claims.filter fun c => c.status = .AUTHORIZED).map Claim.claimId).Nodup :=
    hClaimNodup.sublist ((List.filter_sublist).map _)
  have hPerm : ((input.determinations.filter fun d => d.decision = .OFFSET_AUTHORIZED).map
      OffsetDetermination.claimId).Perm
      ((input.claims.filter fun c => c.status = .AUTHORIZED).map Claim.claimId) := by
    rw [List.perm_ext_iff_of_nodup hNodupD hNodupA]
    intro x
    constructor
    · intro hx
      obtain ⟨d, hd, rfl⟩ := List.mem_map.1 hx
      obtain ⟨hdm, hdec⟩ := List.mem_filter.1 hd
      obtain ⟨cl, hfc, -, hstat⟩ := determination_claim (hAll d hdm)
      obtain ⟨hcm, hcid⟩ := findClaim_mem _ _ _ hfc
      exact List.mem_map.2 ⟨cl, List.mem_filter.2 ⟨hcm, by simpa using hstat (by simpa using hdec)⟩, hcid⟩
    · intro hx
      obtain ⟨c, hc, rfl⟩ := List.mem_map.1 hx
      obtain ⟨hcm, hcs⟩ := List.mem_filter.1 hc
      obtain ⟨d, hdm, hdid, hddec⟩ :=
        claim_authorized_determination (hTerm c hcm) (by simpa using hcs)
      exact List.mem_map.2 ⟨d, List.mem_filter.2 ⟨hdm, by simpa using hddec⟩, hdid⟩
  rw [hD, hA]
  exact (hPerm.map f).sum_nat

/-! ## The evaluator's result and its contributions -/

theorem evaluate_facts {input : FinancialInput} {r : FinancialResult}
    (h : evaluate input = some r) :
    financialInputWellFormed input = true ∧ ∃ cash claimed lawful,
      evalPaymentSum input.payments = some cash ∧ evalClaimedSum input.claims = some claimed ∧
      evalLawfulSum input.claims = some lawful ∧ cash + lawful ≤ maxCents ∧
      r = evaluateResult input cash claimed lawful (cash + lawful) := by
  have hWf : financialInputWellFormed input = true := by
    refine Classical.byContradiction fun hne => ?_
    have hf : financialInputWellFormed input = false := by simpa using hne
    simp [evaluate, hf] at h
  refine ⟨hWf, ?_⟩
  have h' : evaluateWellFormed input = some r := by simpa [evaluate, hWf] using h
  unfold evaluateWellFormed at h'
  cases h1 : evalPaymentSum input.payments with
  | none => simp [evaluateTotals, h1] at h'
  | some cash =>
      cases h2 : evalClaimedSum input.claims with
      | none => simp [evaluateTotals, h1, h2] at h'
      | some claimed =>
          cases h3 : evalLawfulSum input.claims with
          | none => simp [evaluateTotals, h1, h2, h3] at h'
          | some lawful =>
              cases h4 : evalAdd cash lawful with
              | none => simp [evaluateTotals, h1, h2, h3, h4] at h'
              | some total =>
                  obtain ⟨e1, e2⟩ := evalAdd_some h4
                  subst e1
                  simp [evaluateTotals, h1, h2, h3, h4] at h'
                  exact ⟨cash, claimed, lawful, rfl, rfl, rfl, e2, h'.symm⟩

theorem evaluate_fields {input : FinancialInput} {r : FinancialResult}
    (h : evaluate input = some r) :
    r.owedCents = input.obligation.owedCents ∧
      r.amountSatisfied = decide (input.obligation.owedCents ≤
        r.receivedCashCents + r.lawfulAdjustmentCents) ∧
      r.timely = (match r.completionAt with
        | none => false
        | some ct => decide (ct ≤ input.obligation.dueAt)) := by
  obtain ⟨-, cash, claimed, lawful, -, -, -, -, rfl⟩ := evaluate_facts h
  exact ⟨rfl, rfl, rfl⟩

theorem evaluate_balance {input : FinancialInput} {r : FinancialResult}
    (h : evaluate input = some r) :
    r.receivedCashCents + r.lawfulAdjustmentCents + r.shortfallCents =
        r.owedCents + r.overageCents ∧
      (r.shortfallCents = 0 ∨ r.overageCents = 0) ∧
      r.amountSatisfied = decide (r.shortfallCents = 0) ∧
      (r.cashSatisfied = true → r.amountSatisfied = true) ∧
      r.lawfulAdjustmentCents ≤ r.claimedAdjustmentCents := by
  obtain ⟨-, cash, claimed, lawful, -, h2, h3, -, rfl⟩ := evaluate_facts h
  refine ⟨?_, ?_, ?_, ?_, evalLawfulSum_le_claimed _ _ _ h3 h2⟩ <;>
    simp only [evaluateResult, gt_iff_lt] <;>
    by_cases hlt : cash + lawful < input.obligation.owedCents <;>
    by_cases hgt : input.obligation.owedCents < cash + lawful <;>
    simp [hlt, hgt] <;> omega

theorem evalContributions_amounts (input : FinancialInput) :
    (evalContributions input).map EvalContribution.amountCents =
      ((input.payments.filter fun p => p.status = .ACTIVE).map Payment.amountCents) ++
      ((input.determinations.filter fun d => d.decision = .OFFSET_AUTHORIZED).map
        OffsetDetermination.amountCents) := by
  unfold evalContributions
  generalize input.payments = ps
  generalize input.determinations = ds
  rw [List.map_append]
  congr 1
  · induction ps with
    | nil => rfl
    | cons p ps ih => by_cases hp : p.status = .ACTIVE <;> simp [hp, ih]
  · induction ds with
    | nil => rfl
    | cons d ds ih => by_cases hd : d.decision = .OFFSET_AUTHORIZED <;> simp [hd, ih]

/-- Contributions read only the payments and the authorized determinations. -/
theorem evalContributions_congr {a b : FinancialInput} (hp : a.payments = b.payments)
    (hd : (a.determinations.filter fun d => d.decision = .OFFSET_AUTHORIZED) =
      (b.determinations.filter fun d => d.decision = .OFFSET_AUTHORIZED)) :
    evalContributions a = evalContributions b := by
  have key : ∀ x : FinancialInput, evalContributions x = evalContributions
      { x with determinations := x.determinations.filter fun d => d.decision = .OFFSET_AUTHORIZED } := by
    intro x
    simp only [evalContributions]
    congr 1
    generalize x.determinations = ds
    induction ds with
    | nil => rfl
    | cons d ds ih => by_cases h : d.decision = .OFFSET_AUTHORIZED <;> simp [h, ih]
  rw [key a, key b]
  simp only [evalContributions, hp, hd]

theorem evalContributions_sum {input : FinancialInput} {r : FinancialResult}
    (h : evaluate input = some r) :
    ((evalContributions input).map EvalContribution.amountCents).sum =
      r.receivedCashCents + r.lawfulAdjustmentCents := by
  obtain ⟨hWf, cash, claimed, lawful, h1, -, h3, -, rfl⟩ := evaluate_facts h
  show _ = cash + lawful
  rw [evalContributions_amounts, List.sum_append, (evalPaymentSum_active _ _ h1).1,
    offset_sum hWf, (evalLawfulSum_active _ _ h3).1]

/-! ## The completion clock -/

theorem evalInsertContribution_perm (v : EvalContribution) :
    ∀ l, (evalInsertContribution v l).Perm (v :: l)
  | [] => List.Perm.refl _
  | x :: xs => by
      unfold evalInsertContribution
      split
      · exact List.Perm.refl _
      · exact ((evalInsertContribution_perm v xs).cons x).trans (List.Perm.swap v x xs)

theorem evalSortContributions_perm : ∀ l, (evalSortContributions l).Perm l
  | [] => List.Perm.refl _
  | x :: xs =>
      (evalInsertContribution_perm x _).trans ((evalSortContributions_perm xs).cons x)

theorem evalInsertContribution_sorted (v : EvalContribution) :
    ∀ l : List EvalContribution, l.Pairwise (fun a b => a.time ≤ b.time) →
      (evalInsertContribution v l).Pairwise (fun a b => a.time ≤ b.time)
  | [], _ => by simp [evalInsertContribution]
  | x :: xs, h => by
      obtain ⟨hx, hxs⟩ := List.pairwise_cons.1 h
      unfold evalInsertContribution
      split
      · rename_i hb
        simp only [contributionKeyBefore, Bool.or_eq_true, Bool.and_eq_true,
          decide_eq_true_eq] at hb
        refine List.pairwise_cons.2 ⟨?_, h⟩
        intro y hy
        have hvx : v.time ≤ x.time := by rcases hb with h | ⟨h, _⟩ <;> omega
        rcases List.mem_cons.1 hy with hyx | hyx
        · rw [hyx]
          exact hvx
        · exact Nat.le_trans hvx (hx y hyx)
      · rename_i hb
        simp only [contributionKeyBefore, Bool.or_eq_true, Bool.and_eq_true,
          decide_eq_true_eq, not_or] at hb
        refine List.pairwise_cons.2 ⟨?_, evalInsertContribution_sorted v xs hxs⟩
        intro y hy
        rcases List.mem_cons.1 ((evalInsertContribution_perm v xs).mem_iff.1 hy) with hyv | hyx
        · rw [hyv]
          exact Nat.not_lt.1 hb.1
        · exact hx y hyx

theorem evalSortContributions_sorted :
    ∀ l, (evalSortContributions l).Pairwise (fun a b => a.time ≤ b.time)
  | [] => List.Pairwise.nil
  | x :: xs => evalInsertContribution_sorted x _ (evalSortContributions_sorted xs)

theorem evalCompletionLoop_none (owed : Nat) : ∀ (l : List EvalContribution) (acc : Nat),
    acc < owed → acc + (l.map EvalContribution.amountCents).sum ≤ maxCents →
    evalCompletionLoop owed acc l = none →
    acc + (l.map EvalContribution.amountCents).sum < owed
  | [], acc, hlt, _, _ => by simpa using hlt
  | c :: cs, acc, hlt, hb, h => by
      simp only [List.map_cons, List.sum_cons] at hb ⊢
      have hAdd := evalAdd_of_le (l := acc) (r := c.amountCents) (by omega)
      unfold evalCompletionLoop at h
      by_cases hd : acc + c.amountCents ≥ owed
      · simp [hAdd, hd] at h
      · simp [hAdd, hd] at h
        have := evalCompletionLoop_none owed cs (acc + c.amountCents) (by omega) (by omega) h
        omega

theorem evalCompletionLoop_some (owed : Nat) : ∀ (l : List EvalContribution) (acc t : Nat),
    acc < owed → acc + (l.map EvalContribution.amountCents).sum ≤ maxCents →
    evalCompletionLoop owed acc l = some t →
    ∃ pre c post, l = pre ++ c :: post ∧ c.time = t ∧
      acc + (pre.map EvalContribution.amountCents).sum < owed ∧
      owed ≤ acc + (pre.map EvalContribution.amountCents).sum + c.amountCents
  | [], acc, t, _, _, h => by simp [evalCompletionLoop] at h
  | c :: cs, acc, t, hlt, hb, h => by
      simp only [List.map_cons, List.sum_cons] at hb
      have hAdd := evalAdd_of_le (l := acc) (r := c.amountCents) (by omega)
      unfold evalCompletionLoop at h
      by_cases hd : acc + c.amountCents ≥ owed
      · simp [hAdd, hd] at h
        exact ⟨[], c, cs, rfl, h, by simpa using hlt, by simp only [List.map_nil, List.sum_nil]; omega⟩
      · simp [hAdd, hd] at h
        obtain ⟨pre, c', post, hl, ht, h1, h2⟩ :=
          evalCompletionLoop_some owed cs (acc + c.amountCents) t (by omega) (by omega) h
        refine ⟨c :: pre, c', post, by simp [hl], ht, ?_, ?_⟩ <;>
          simp only [List.map_cons, List.sum_cons] <;> omega

/-- Reading the completion time back: the loop's stopping point, with the sums around it. -/
theorem evaluate_completion_some {input : FinancialInput} {r : FinancialResult} {t : Nat}
    (h : evaluate input = some r) (ht : r.completionAt = some t) :
    ∃ pre c post, evalSortContributions (evalContributions input) = pre ++ c :: post ∧
      c.time = t ∧ (pre.map EvalContribution.amountCents).sum < input.obligation.owedCents ∧
      input.obligation.owedCents ≤ (pre.map EvalContribution.amountCents).sum + c.amountCents := by
  obtain ⟨hWf, cash, claimed, lawful, h1, h2, h3, hb, rfl⟩ := evaluate_facts h
  have hsum : ((evalContributions input).map EvalContribution.amountCents).sum = cash + lawful :=
    evalContributions_sum h
  have hL : ((evalSortContributions (evalContributions input)).map
      EvalContribution.amountCents).sum = cash + lawful := by
    rw [((evalSortContributions_perm _).map _).sum_nat]
    exact hsum
  have hpos := wf_owed_pos hWf
  have ht' : evalCompletion input = some t := ht
  unfold evalCompletion at ht'
  cases hLoop : evalCompletionLoop input.obligation.owedCents 0
      (evalSortContributions (evalContributions input)) with
  | some c =>
      simp only [hLoop] at ht'
      cases ht'
      obtain ⟨pre, c', post, hl, hct, hp1, hp2⟩ := evalCompletionLoop_some _ _ 0 t hpos
        (by omega) hLoop
      exact ⟨pre, c', post, hl, hct, by simpa using hp1, by simpa using hp2⟩
  | none =>
      have hlt := evalCompletionLoop_none _ _ 0 hpos (by omega) hLoop
      have hnot : ¬ input.obligation.owedCents ≤ lawful + cash := by omega
      simp [hLoop, h1, h3, evalAdd_of_le (show lawful + cash ≤ maxCents by omega), hnot] at ht'

theorem evaluate_completion_none {input : FinancialInput} {r : FinancialResult}
    (h : evaluate input = some r) (hn : r.completionAt = none) :
    r.receivedCashCents + r.lawfulAdjustmentCents < input.obligation.owedCents := by
  obtain ⟨hWf, cash, claimed, lawful, h1, h2, h3, hb, rfl⟩ := evaluate_facts h
  have hsum : ((evalContributions input).map EvalContribution.amountCents).sum = cash + lawful :=
    evalContributions_sum h
  have hL : ((evalSortContributions (evalContributions input)).map
      EvalContribution.amountCents).sum = cash + lawful := by
    rw [((evalSortContributions_perm _).map _).sum_nat]
    exact hsum
  have hpos := wf_owed_pos hWf
  have hn' : evalCompletion input = none := hn
  unfold evalCompletion at hn'
  cases hLoop : evalCompletionLoop input.obligation.owedCents 0
      (evalSortContributions (evalContributions input)) with
  | some c => simp [hLoop] at hn'
  | none =>
      have := evalCompletionLoop_none _ _ 0 hpos (by omega) hLoop
      show cash + lawful < _
      omega

theorem evaluate_completion_iff_satisfied {input : FinancialInput} {r : FinancialResult}
    (h : evaluate input = some r) :
    r.completionAt.isSome = r.amountSatisfied ∧ (r.timely = true → r.amountSatisfied = true) := by
  obtain ⟨-, hAmt, hTim⟩ := evaluate_fields h
  have hSome : ∀ t, r.completionAt = some t →
      input.obligation.owedCents ≤ r.receivedCashCents + r.lawfulAdjustmentCents := by
    intro t ht
    obtain ⟨pre, c, post, hL, -, -, hp2⟩ := evaluate_completion_some h ht
    have hsum := evalContributions_sum h
    have hL' : ((evalSortContributions (evalContributions input)).map
        EvalContribution.amountCents).sum = r.receivedCashCents + r.lawfulAdjustmentCents := by
      rw [((evalSortContributions_perm _).map _).sum_nat]
      exact hsum
    rw [hL] at hL'
    simp only [List.map_append, List.map_cons, List.sum_append, List.sum_cons] at hL'
    omega
  constructor
  · rw [hAmt]
    cases hc : r.completionAt with
    | none =>
        have := evaluate_completion_none h hc
        simp
        omega
    | some t =>
        have := hSome t hc
        simp
        omega
  · intro ht
    rw [hAmt]
    rw [hTim] at ht
    cases hc : r.completionAt with
    | none => simp [hc] at ht
    | some t =>
        have := hSome t hc
        simp
        omega

theorem sum_filter_le (p : EvalContribution → Bool) : ∀ l : List EvalContribution,
    ((l.filter p).map EvalContribution.amountCents).sum ≤ (l.map EvalContribution.amountCents).sum
  | [] => by simp
  | x :: xs => by
      have := sum_filter_le p xs
      by_cases hx : p x = true <;> simp [List.filter_cons, hx] <;> omega

/-- The completion time is the earliest contribution time by which the contributions
    dated at or before it reach what is owed. -/
theorem evaluate_completionAt_first {input : FinancialInput} {r : FinancialResult} {t : Nat}
    (h : evaluate input = some r) (ht : r.completionAt = some t) :
    input.obligation.owedCents ≤
        (((evalContributions input).filter (fun c => decide (c.time ≤ t))).map
          EvalContribution.amountCents).sum ∧
      t ∈ (evalContributions input).map EvalContribution.time ∧
      ∀ s < t, (((evalContributions input).filter (fun c => decide (c.time ≤ s))).map
          EvalContribution.amountCents).sum < input.obligation.owedCents := by
  obtain ⟨pre, c, post, hL, hct, hpre, hown⟩ := evaluate_completion_some h ht
  have hsorted := evalSortContributions_sorted (evalContributions input)
  have hperm := evalSortContributions_perm (evalContributions input)
  rw [hL] at hsorted hperm
  obtain ⟨-, hcpost, hcross⟩ := List.pairwise_append.1 hsorted
  have hpreLe : ∀ x ∈ pre, x.time ≤ t := fun x hx =>
    hct ▸ hcross x hx c (List.mem_cons_self ..)
  have hpostLe : ∀ x ∈ post, t ≤ x.time := fun x hx =>
    hct ▸ (List.pairwise_cons.1 hcpost).1 x hx
  refine ⟨?_, ?_, ?_⟩
  · rw [← ((hperm.filter _).map _).sum_nat]
    rw [List.filter_append, List.filter_cons_of_pos (by simp [hct]),
      (List.filter_eq_self (l := pre)).2 (fun x hx => by simpa using hpreLe x hx)]
    simp only [List.map_append, List.map_cons, List.sum_append, List.sum_cons]
    omega
  · exact List.mem_map.2 ⟨c, hperm.mem_iff.1 (by simp), hct⟩
  · intro s hs
    rw [← ((hperm.filter _).map _).sum_nat]
    rw [List.filter_append, List.filter_cons_of_neg (by simp; omega),
      (List.filter_eq_nil_iff (l := post)).2 (fun x hx => by have := hpostLe x hx; simp; omega)]
    have := sum_filter_le (fun c => decide (c.time ≤ s)) pre
    simp only [List.map_append, List.sum_append, List.map_nil, List.sum_nil]
    omega

/-- One input extends another: same obligation, every contribution kept, more may be added. -/
def contributionsExtend (input input' : FinancialInput) : Prop :=
  input'.obligation = input.obligation ∧
    ∃ extra, (evalContributions input').Perm (evalContributions input ++ extra)

theorem evaluate_monotone {input input' : FinancialInput} {r r' : FinancialResult}
    (h : evaluate input = some r) (h' : evaluate input' = some r')
    (hExt : contributionsExtend input input') :
    r'.shortfallCents ≤ r.shortfallCents ∧ r.overageCents ≤ r'.overageCents ∧
      (r.amountSatisfied = true → r'.amountSatisfied = true) ∧
      (∀ t, r.completionAt = some t → ∃ t', r'.completionAt = some t' ∧ t' ≤ t) ∧
      (r.timely = true → r'.timely = true) := by
  obtain ⟨hObl, extra, hperm⟩ := hExt
  have hs := evalContributions_sum h
  have hs' := evalContributions_sum h'
  have hSumP : ((evalContributions input').map EvalContribution.amountCents).sum =
      ((evalContributions input).map EvalContribution.amountCents).sum +
        (extra.map EvalContribution.amountCents).sum := by
    rw [(hperm.map _).sum_nat]
    simp [List.sum_append]
  obtain ⟨hO, hA, hTm⟩ := evaluate_fields h
  obtain ⟨hO', hA', hTm'⟩ := evaluate_fields h'
  rw [hObl] at hO' hA' hTm'
  obtain ⟨b1, b2, -, -, -⟩ := evaluate_balance h
  obtain ⟨b1', b2', -, -, -⟩ := evaluate_balance h'
  have hT : r.receivedCashCents + r.lawfulAdjustmentCents ≤
      r'.receivedCashCents + r'.lawfulAdjustmentCents := by omega
  have hCompl : ∀ t, r.completionAt = some t → ∃ t', r'.completionAt = some t' ∧ t' ≤ t := by
    intro t ht
    obtain ⟨hf1, -, -⟩ := evaluate_completionAt_first h ht
    have hsat : r'.amountSatisfied = true := by
      obtain ⟨hp, -, -⟩ := evaluate_completionAt_first h ht
      rw [hA']
      have := (evaluate_completion_iff_satisfied h).1
      rw [ht, hA] at this
      simp at this ⊢
      omega
    have hsome : r'.completionAt.isSome = true := by
      rw [(evaluate_completion_iff_satisfied h').1]
      exact hsat
    obtain ⟨t', ht'⟩ := Option.isSome_iff_exists.1 hsome
    refine ⟨t', ht', ?_⟩
    refine Classical.byContradiction fun hlt => ?_
    have hmin := (evaluate_completionAt_first h' ht').2.2 t (by omega)
    have hfilt : (((evalContributions input').filter (fun c => decide (c.time ≤ t))).map
        EvalContribution.amountCents).sum =
        (((evalContributions input).filter (fun c => decide (c.time ≤ t))).map
          EvalContribution.amountCents).sum +
        (((extra).filter (fun c => decide (c.time ≤ t))).map
          EvalContribution.amountCents).sum := by
      rw [((hperm.filter _).map _).sum_nat]
      simp [List.filter_append, List.sum_append]
    rw [hObl] at hmin
    omega
  refine ⟨by omega, by omega, ?_, hCompl, ?_⟩
  · intro hsat
    rw [hA] at hsat
    rw [hA']
    simp at hsat ⊢
    omega
  · intro ht
    rw [hTm] at ht
    cases hc : r.completionAt with
    | none => simp [hc] at ht
    | some t =>
        rw [hc] at ht
        simp at ht
        obtain ⟨t', ht', hle⟩ := hCompl t hc
        rw [hTm', ht']
        simp
        omega

theorem evaluate_evaluatedAt_irrelevant {input : FinancialInput} {r : FinancialResult} (t : Nat)
    (h : evaluate input = some r)
    (hWf : financialInputWellFormed { input with evaluatedAt := t } = true) :
    evaluate { input with evaluatedAt := t } = some { r with evaluatedAt := t } := by
  obtain ⟨-, cash, claimed, lawful, h1, h2, h3, hb, rfl⟩ := evaluate_facts h
  have hAdd := evalAdd_of_le hb
  simp [evaluate, hWf, evaluateWellFormed, evaluateTotals, h1, h2, h3, hAdd]
  rfl

/-! ## Results always encode (N1a, N1) -/

theorem evalClaimedSum_le : ∀ (cs : List Claim) (t : Nat), evalClaimedSum cs = some t →
    t ≤ maxCents
  | [], t, h => by
      simp only [evalClaimedSum] at h
      cases h
      exact Nat.zero_le _
  | c :: cs, t, h => by
      cases hT : evalClaimedSum cs with
      | none => simp [evalClaimedSum, hT] at h
      | some t' =>
          have ih := evalClaimedSum_le cs t' hT
          by_cases hs : c.status = .CLAIMED ∨ c.status = .AUTHORIZED
          · simp only [evalClaimedSum, hT, hs, or_self, Bool.or_eq_true, decide_eq_true_eq,
              if_true] at h
            exact (evalAdd_some h).2
          · simp only [evalClaimedSum, hT, Bool.or_eq_true, decide_eq_true_eq, hs, if_false] at h
            cases h
            exact ih

theorem evalContributions_time_le {input : FinancialInput}
    (hp : input.payments.all (paymentWellFormed input.context) = true)
    (hd : input.determinations.all (determinationWellFormed input) = true) :
    ∀ c ∈ evalContributions input, c.time ≤ maxTime := by
  have hPay : ∀ (ps : List Payment), (∀ p ∈ ps, p.eventAt ≤ maxTime) →
      ∀ c ∈ ps.foldr (fun payment rest =>
        if payment.status = .ACTIVE then
          { time := payment.eventAt, identity := payment.paymentId,
            amountCents := payment.amountCents : EvalContribution } :: rest
        else rest) [], c.time ≤ maxTime := by
    intro ps
    induction ps with
    | nil => intro _ c hc; simp at hc
    | cons p ps ih =>
        intro h c hc
        by_cases hs : p.status = .ACTIVE
        · simp only [List.foldr_cons, hs, if_true, List.mem_cons] at hc
          rcases hc with rfl | hc
          · exact h p (by simp)
          · exact ih (fun q hq => h q (by simp [hq])) c hc
        · simp only [List.foldr_cons, hs, if_false] at hc
          exact ih (fun q hq => h q (by simp [hq])) c hc
  have hDet : ∀ (ds : List OffsetDetermination), (∀ d ∈ ds, d.decidedAt ≤ maxTime) →
      ∀ c ∈ ds.foldr (fun determination rest =>
        if determination.decision = .OFFSET_AUTHORIZED then
          { time := determination.decidedAt, identity := determination.determinationId,
            amountCents := determination.amountCents : EvalContribution } :: rest
        else rest) [], c.time ≤ maxTime := by
    intro ds
    induction ds with
    | nil => intro _ c hc; simp at hc
    | cons d ds ih =>
        intro h c hc
        by_cases hs : d.decision = .OFFSET_AUTHORIZED
        · simp only [List.foldr_cons, hs, if_true, List.mem_cons] at hc
          rcases hc with rfl | hc
          · exact h d (by simp)
          · exact ih (fun q hq => h q (by simp [hq])) c hc
        · simp only [List.foldr_cons, hs, if_false] at hc
          exact ih (fun q hq => h q (by simp [hq])) c hc
  intro c hc
  unfold evalContributions at hc
  simp only [List.mem_append] at hc
  rcases hc with hc | hc
  · refine hPay _ (fun p hpm => ?_) c hc
    have := List.all_eq_true.1 hp p hpm
    simp only [paymentWellFormed, timeWellFormed, Bool.and_eq_true, decide_eq_true_eq] at this
    grind
  · refine hDet _ (fun d hdm => ?_) c hc
    have := List.all_eq_true.1 hd d hdm
    unfold determinationWellFormed at this
    simp only [Bool.and_eq_true, decide_eq_true_eq, timeWellFormed] at this
    grind

theorem length_encodeString (s : String) :
    (encodeString s).length = 2 + s.toUTF8.toList.length := by
  simp [encodeString, CorrectionTransition.length_natBE]

theorem length_encodeString_id {s : String} (h : idWellFormed s = true) :
    (encodeString s).length ≤ 130 := by
  unfold idWellFormed at h
  simp only [Bool.and_eq_true, decide_eq_true_eq] at h
  have hLen := h.1.2
  unfold maxIdBytes at hLen
  rw [length_encodeString]
  omega

theorem length_flatMap_le {α : Type} (f : α → Bytes) (b : Nat) :
    ∀ l : List α, (∀ x ∈ l, (f x).length ≤ b) → (l.flatMap f).length ≤ l.length * b
  | [], _ => by simp
  | x :: xs, h => by
      have h1 := h x (by simp)
      have h2 := length_flatMap_le f b xs (fun y hy => h y (by simp [hy]))
      simp only [List.flatMap_cons, List.length_append, List.length_cons, Nat.succ_mul]
      omega

theorem length_encodeContext_le {c : FinancialContext} (h : contextWellFormed c = true) :
    (encodeContext c).length ≤ 1200 := by
  unfold contextWellFormed at h
  simp only [Bool.and_eq_true, List.all_cons, List.all_nil, decide_eq_true_eq] at h
  have h1 := length_encodeString_id (s := c.ownerId) (by grind)
  have h2 := length_encodeString_id (s := c.stateId) (by grind)
  have h3 := length_encodeString_id (s := c.deploymentId) (by grind)
  have h4 := length_encodeString_id (s := c.programId) (by grind)
  have h5 := length_encodeString_id (s := c.periodId) (by grind)
  have h6 := length_encodeString_id (s := c.populationId) (by grind)
  have h7 := length_encodeString_id (s := c.itemId) (by grind)
  have h8 := length_encodeString_id (s := c.obligationId) (by grind)
  have hC : c.currency = "USD" := by grind
  have h9 : (encodeString c.currency).length ≤ 14 := by
    rw [hC, length_encodeString]
    have hBytes := CorrectionTransition.string_utf8_length_le "USD"
    have hChars : "USD".toList.length = 3 := by decide
    omega
  simp only [encodeContext, List.length_append, List.length_cons, List.length_nil]
  omega

theorem length_encodeIds_le {ids : List String} (h : canonicalIdList ids = true) :
    (encodeList encodeString ids).length ≤ 2 + maxRows * 130 := by
  unfold canonicalIdList at h
  simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true] at h
  have hFlat := length_flatMap_le encodeString 130 ids
    (fun x hx => length_encodeString_id (h.1.2 x hx))
  have hMul : ids.length * 130 ≤ maxRows * 130 := Nat.mul_le_mul_right _ h.1.1
  simp only [encodeList, List.length_append, CorrectionTransition.length_natBE]
  omega

theorem length_resultMagic_le : financialResultCodecMagic.length ≤ 32 := by
  have hB := CorrectionTransition.string_utf8_length_le "BLFRES02"
  have hChars : "BLFRES02".toList.length = 8 := by decide
  unfold financialResultCodecMagic
  omega

theorem length_encodeOptionNat_le (o : Option Nat) : (encodeOptionNat o).length ≤ 9 := by
  cases o <;> simp [encodeOptionNat, CorrectionTransition.length_natBE]

theorem length_rawEncodeFinancialResult (r : FinancialResult) :
    (rawEncodeFinancialResult r).length = financialResultCodecMagic.length +
      (encodeContext r.context).length + (encodeString r.authorityId).length +
      r.authorityDigest.length + (encodeString r.packId).length + r.packDigest.length +
      (encodeList encodeString r.evidenceIds).length + (encodeOptionNat r.completionAt).length + 95 := by
  unfold rawEncodeFinancialResult
  generalize financialResultCodecMagic = magic
  simp only [List.length_append, CorrectionTransition.length_natBE,
    encodeDigest, encodeBool, List.length_cons, List.length_nil]
  omega

theorem length_rawEncodeFinancialResult_le {r : FinancialResult}
    (h : financialResultWellFormed r = true) :
    (rawEncodeFinancialResult r).length ≤ maxTotalEncodedBytes := by
  unfold financialResultWellFormed at h
  simp only [Bool.and_eq_true, decide_eq_true_eq, and_assoc] at h
  obtain ⟨hCtxW, hAid, -, -, hAdig, hPid, hPdig, -, -, -, -, -, -, -, hIds, -⟩ := h
  have hCtx := length_encodeContext_le hCtxW
  have hA := length_encodeString_id hAid
  have hP := length_encodeString_id hPid
  have hE := length_encodeIds_le hIds
  have hAd : r.authorityDigest.length = digestBytes := of_decide_eq_true hAdig
  have hPd : r.packDigest.length = digestBytes := of_decide_eq_true hPdig
  have hMagic := length_resultMagic_le
  have hO := length_encodeOptionNat_le r.completionAt
  unfold maxRows at hE
  unfold maxTotalEncodedBytes
  unfold digestBytes at hAd hPd
  rw [length_rawEncodeFinancialResult]
  generalize financialResultCodecMagic.length = m at hMagic ⊢
  omega

/-- Every result the evaluator returns is well-formed. -/
theorem evaluate_resultWellFormed {input : FinancialInput} {r : FinancialResult}
    (h : evaluate input = some r) : financialResultWellFormed r = true := by
  obtain ⟨hWf, cash, claimed, lawful, hp, hc, hl, hb, hr⟩ := evaluate_facts h
  have hCash := (evalPaymentSum_active _ _ hp).2
  have hLaw := (evalLawfulSum_active _ _ hl).2
  have hClaimed := evalClaimedSum_le _ _ hc
  have hTime : ∀ t, r.completionAt = some t → t ≤ maxTime := by
    intro t ht
    obtain ⟨pre, c, post, hs, hct, -, -⟩ := evaluate_completion_some h ht
    have hmem : c ∈ evalContributions input :=
      (evalSortContributions_perm _).subset (by rw [hs]; simp)
    rw [← hct]
    refine evalContributions_time_le ?_ ?_ c hmem <;>
      (unfold financialInputWellFormed at hWf; simp only [Bool.and_eq_true, decide_eq_true_eq] at hWf;
        grind)
  have hIn : contextWellFormed input.context = true ∧ authorityWellFormed input.authority = true ∧
      controlPackWellFormed input.pack = true ∧ obligationWellFormed input.obligation = true ∧
      input.beforeRevision < maxRevision ∧ revisionWellFormed input.beforeRevision = true ∧
      timeWellFormed input.evaluatedAt = true ∧
      canonicalIdList (input.evidence.map EvidenceRecord.evidenceId) = true := by
    unfold financialInputWellFormed at hWf
    simp only [envWellFormed, envOf, Bool.and_eq_true, decide_eq_true_eq] at hWf
    grind
  obtain ⟨hCtx, hAuth, hPack, hObl, hBef, hRev, hEv, hIds⟩ := hIn
  simp only [authorityWellFormed, Bool.and_eq_true, decide_eq_true_eq] at hAuth
  simp only [controlPackWellFormed, Bool.and_eq_true, decide_eq_true_eq, List.all_cons,
    List.all_nil] at hPack
  simp only [obligationWellFormed, positiveAmountWellFormed, amountWellFormed,
    Bool.and_eq_true, decide_eq_true_eq] at hObl
  have hRule : r.ruleVersion = input.obligation.ruleVersion := by rw [hr]; rfl
  have hFields : r.context = input.context ∧ r.authorityId = input.authority.authorityId ∧
      r.authorityEpoch = input.authority.epoch ∧ r.authorityDigest = input.authority.digest ∧
      r.packId = input.pack.packId ∧ r.packDigest = input.pack.digest ∧
      r.beforeRevision = input.beforeRevision ∧ r.afterRevision = input.beforeRevision + 1 ∧
      r.evaluatedAt = input.evaluatedAt ∧
      r.evidenceIds = input.evidence.map EvidenceRecord.evidenceId ∧
      r.owedCents = input.obligation.owedCents ∧ r.claimedAdjustmentCents = claimed ∧
      r.lawfulAdjustmentCents = lawful ∧ r.receivedCashCents = cash ∧
      r.shortfallCents ≤ input.obligation.owedCents ∧ r.overageCents ≤ cash + lawful := by
    rw [hr]
    refine ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, ?_, ?_⟩ <;>
      simp only [evaluateResult] <;> split <;> omega
  obtain ⟨f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12, f13, f14, f15, f16⟩ := hFields
  have hT : (match r.completionAt with | none => true | some t => timeWellFormed t) = true := by
    cases hcc : r.completionAt with
    | none => rfl
    | some t => simpa [timeWellFormed] using hTime t hcc
  unfold financialResultWellFormed
  simp only [f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12, f13, f14, Bool.and_eq_true,
    decide_eq_true_eq, hCtx, hRule, hIds, hT, amountWellFormed, positiveAmountWellFormed,
    timeWellFormed, revisionWellFormed, digestWellFormed] at *
  grind

/-- N1a: every result the evaluator returns encodes. -/
theorem evaluate_encodes {input : FinancialInput} {r : FinancialResult}
    (h : evaluate input = some r) :
    encodeFinancialResult r = some (rawEncodeFinancialResult r) := by
  have hW := evaluate_resultWellFormed h
  simp [encodeFinancialResult, hW, length_rawEncodeFinancialResult_le hW]

/-- N1: the worker never answers `encodingRejected`. -/
theorem evaluateWire_ne_encodingRejected (wire : Bytes) :
    evaluateWire wire ≠ .encodingRejected := by
  unfold evaluateWire
  cases hIn : Fast.decodeFinancialInput wire with
  | none => simp
  | some input =>
      cases hEval : evaluate input with
      | none => simp [hEval]
      | some result => simp [hEval, evaluate_encodes hEval]

end BlindLedger.Financial
