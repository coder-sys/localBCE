import BlindLedger.Financial.DecisionPackage.Wire
import BlindLedger.Financial.CodecLaws.Primitives
import BlindLedger.Financial.BatchLaws

namespace BlindLedger.Financial.DecisionPackage
open BlindLedger.Financial

/-! The decision package's laws: the figures equal the ledger's, the verdict is as the design says, and the
    `BLFDPK01` codec is canonical.  The answer is a total function of the facts, so there is no window to prove. -/

/-! ### 4.1 Figures equal the ledger's -/

theorem conclude_missingCents (f : PackageFacts) :
    (conclude f).missingCents = f.owedCents - f.receivedCashCents := rfl

theorem conclude_missingCents_zero_iff (f : PackageFacts) :
    (conclude f).missingCents = 0 ↔ f.owedCents ≤ f.receivedCashCents := by
  rw [conclude_missingCents]; omega

private theorem activeSum_nil {f : PackageFacts} (h : (activePayments f).length = 0) : activeSum f = 0 := by
  simp [activeSum, List.eq_nil_of_length_eq_zero h]

theorem conclude_cash_supported_iff (f : PackageFacts) :
    (conclude f).cash = .SUPPORTED ↔ (activePayments f).length ≠ 0 ∧ activeSum f = f.receivedCashCents := by
  show paymentSupport f = .SUPPORTED ↔ _
  unfold paymentSupport
  (repeat' split) <;> first | grind | simp_all

/-- The cash figure is flagged exactly when the stored figure is not the sum of the active rows. -/
theorem conclude_cash_conflicted_iff (f : PackageFacts) :
    (conclude f).cash = .CONFLICTED ↔ activeSum f ≠ f.receivedCashCents := by
  show paymentSupport f = .CONFLICTED ↔ _
  unfold paymentSupport
  by_cases hl : (activePayments f).length = 0
  · have h0 := activeSum_nil hl
    (repeat' split) <;> first | grind | simp_all
  · (repeat' split) <;> first | grind | simp_all

private theorem adjustment_nil {f : PackageFacts} (h : adjustmentClaims f = []) :
    claimedSum f = 0 ∧ lawfulSum f = 0 := by
  have hl : authorizedClaims f = [] := by
    simp only [adjustmentClaims, authorizedClaims, List.filter_eq_nil_iff] at h ⊢
    intro c hc
    have := h c hc
    simp_all
  simp [claimedSum, lawfulSum, h, hl]

private theorem adjustmentSupport_conflicted_iff (f : PackageFacts) :
    adjustmentSupport f = .CONFLICTED ↔ claimedSum f ≠ f.claimedAdjustmentCents ∨ lawfulSum f ≠ f.lawfulAdjustmentCents := by
  unfold adjustmentSupport
  by_cases hl : adjustmentClaims f = []
  · obtain ⟨h1, h2⟩ := adjustment_nil hl
    (repeat' split) <;> first | grind | simp_all
  · (repeat' split) <;> first | grind | simp_all

/-- The package's view of an evaluation input and the pinned evaluator's result for it. -/
def factsOfEvaluation (input : FinancialInput) (r : FinancialResult) (reportCount conflictCount : Nat)
    (caseStatus : Option CaseStatus) (action : Option PkgAction) : PackageFacts where
  owedCents := r.owedCents
  receivedCashCents := r.receivedCashCents
  claimedAdjustmentCents := r.claimedAdjustmentCents
  lawfulAdjustmentCents := r.lawfulAdjustmentCents
  amountSatisfied := r.amountSatisfied
  reportingComplete := r.reportingComplete
  verification := r.verificationStatus
  payments := input.payments.map fun p => { amountCents := p.amountCents, active := p.status = .ACTIVE }
  claims := input.claims.map fun c => { amountCents := c.amountCents, status := c.status }
  reportCount := reportCount
  conflictCount := conflictCount
  caseStatus := caseStatus
  action := action

private theorem evalAdd_some {a b s : Nat} (h : evalAdd a b = some s) : s = a + b := by
  unfold evalAdd at h
  (repeat' split at h) <;> simp_all

private theorem evaluate_shape {input : FinancialInput} {r : FinancialResult} (h : evaluate input = some r) :
    ∃ cash claimed lawful total, r = evaluateResult input cash claimed lawful total ∧
      evalPaymentSum input.payments = some cash ∧ evalClaimedSum input.claims = some claimed ∧
      evalLawfulSum input.claims = some lawful := by
  unfold evaluate at h
  split at h
  · unfold evaluateWellFormed evaluateTotals at h
    rcases hc : evalPaymentSum input.payments with _ | cash
    · simp [hc] at h
    rcases hcl : evalClaimedSum input.claims with _ | claimed
    · simp [hc, hcl] at h
    rcases hl : evalLawfulSum input.claims with _ | lawful
    · simp [hc, hcl, hl] at h
    rcases ha : evalAdd cash lawful with _ | total
    · simp [hc, hcl, hl, ha] at h
    · simp [hc, hcl, hl, ha] at h
      exact ⟨cash, claimed, lawful, total, h.symm, rfl, rfl, rfl⟩
  · simp at h

private theorem paymentSum_eq : ∀ (ps : List Payment) (s : Nat), evalPaymentSum ps = some s →
    (((ps.map (fun p => ({ amountCents := p.amountCents, active := decide (p.status = .ACTIVE) } : PkgPayment))).filter
      (·.active)).map (·.amountCents)).sum = s
  | [], s, h => by simp_all [evalPaymentSum]
  | p :: rest, s, h => by
      unfold evalPaymentSum at h
      rcases ht : evalPaymentSum rest with _ | t
      · simp [ht] at h
      · have ih := paymentSum_eq rest t ht
        cases hs : p.status
        · simp only [ht, hs] at h
          have := evalAdd_some (by simpa using h)
          simp [hs, ih]; omega
        · simp only [ht, hs] at h
          simp_all

private theorem claimedSum_eq : ∀ (cs : List Claim) (s : Nat), evalClaimedSum cs = some s →
    (((cs.map (fun c => ({ amountCents := c.amountCents, status := c.status } : PkgClaim))).filter
      (fun c => c.status = .CLAIMED || c.status = .AUTHORIZED)).map (·.amountCents)).sum = s
  | [], s, h => by simp_all [evalClaimedSum]
  | c :: rest, s, h => by
      unfold evalClaimedSum at h
      rcases ht : evalClaimedSum rest with _ | t
      · simp [ht] at h
      · have ih := claimedSum_eq rest t ht
        cases hs : c.status
        · simp only [ht, hs] at h
          have := evalAdd_some (by simpa using h)
          simp [hs, ih]; omega
        · simp only [ht, hs] at h
          have := evalAdd_some (by simpa using h)
          simp [hs, ih]; omega
        · simp only [ht, hs] at h
          simp_all

private theorem lawfulSum_eq : ∀ (cs : List Claim) (s : Nat), evalLawfulSum cs = some s →
    (((cs.map (fun c => ({ amountCents := c.amountCents, status := c.status } : PkgClaim))).filter
      (fun c => c.status = .AUTHORIZED)).map (·.amountCents)).sum = s
  | [], s, h => by simp_all [evalLawfulSum]
  | c :: rest, s, h => by
      unfold evalLawfulSum at h
      rcases ht : evalLawfulSum rest with _ | t
      · simp [ht] at h
      · have ih := lawfulSum_eq rest t ht
        cases hs : c.status
        · simp only [ht, hs] at h
          simp_all
        · simp only [ht, hs] at h
          have := evalAdd_some (by simpa using h)
          simp [hs, ih]; omega
        · simp only [ht, hs] at h
          simp_all

/-- Every sum the package checks is the sum the pinned evaluator computed (`evalPaymentSum`,
    `evalClaimedSum`, `evalLawfulSum`). -/
theorem factsOfEvaluation_sums {input : FinancialInput} {r : FinancialResult} (h : evaluate input = some r)
    (n k : Nat) (c : Option CaseStatus) (a : Option PkgAction) :
    let f := factsOfEvaluation input r n k c a
    activeSum f = r.receivedCashCents ∧ claimedSum f = r.claimedAdjustmentCents ∧
    lawfulSum f = r.lawfulAdjustmentCents := by
  obtain ⟨cash, claimed, lawful, total, rfl, hc, hcl, hl⟩ := evaluate_shape h
  exact ⟨paymentSum_eq _ _ hc, claimedSum_eq _ _ hcl, lawfulSum_eq _ _ hl⟩

/-- Rows and figures from one evaluation never show a cash or adjustment conflict. -/
theorem factsOfEvaluation_not_conflicted {input : FinancialInput} {r : FinancialResult} (h : evaluate input = some r)
    (n k : Nat) (c : Option CaseStatus) (a : Option PkgAction) :
    let f := factsOfEvaluation input r n k c a
    paymentSupport f ≠ .CONFLICTED ∧ adjustmentSupport f ≠ .CONFLICTED := by
  intro f
  obtain ⟨h1, h2, h3⟩ := factsOfEvaluation_sums h n k c a
  refine ⟨fun hc => (conclude_cash_conflicted_iff f).1 hc h1, fun hc => ?_⟩
  rcases (adjustmentSupport_conflicted_iff f).1 hc with hx | hx
  · exact hx h2
  · exact hx h3

theorem factsOfEvaluation_missingCents_zero_iff {input : FinancialInput} {r : FinancialResult}
    (h : evaluate input = some r) (n k : Nat) (c : Option CaseStatus) (a : Option PkgAction) :
    (conclude (factsOfEvaluation input r n k c a)).missingCents = 0 ↔ r.cashSatisfied = true := by
  obtain ⟨cash, claimed, lawful, total, rfl, -, -, -⟩ := evaluate_shape h
  rw [conclude_missingCents_zero_iff]
  simp [factsOfEvaluation, evaluateResult]

/-! ### 4.2 The verdict -/

theorem conclude_amount_supported_iff (f : PackageFacts) :
    (conclude f).amount = .SUPPORTED ↔
      paymentSupport f ≠ .CONFLICTED ∧ adjustmentSupport f ≠ .CONFLICTED ∧ f.verification ≠ .CONFLICT_VISIBLE ∧
      (activePayments f).length + (authorizedClaims f).length ≠ 0 := by
  show amountSupport f = .SUPPORTED ↔ _
  unfold amountSupport
  (repeat' split) <;> first | grind | simp_all

theorem conclude_delivery_supported_iff (f : PackageFacts) :
    (conclude f).delivery = .SUPPORTED ↔ ∃ a, f.action = some a ∧ a.status = .ACKNOWLEDGED ∧ a.acknowledged = true := by
  show deliverySupport f = .SUPPORTED ↔ _
  unfold deliverySupport
  rcases hf : f.action with _ | a
  · simp
  · (repeat' split) <;> simp_all

theorem conclude_missingMask_zero_iff (f : PackageFacts) :
    (conclude f).missingMask = 0 ↔ ∀ s ∈ requirements f, s = .SUPPORTED := by
  show missingMask f = 0 ↔ _
  unfold missingMask
  by_cases h1 : requiredAmount f = .SUPPORTED <;> by_cases h2 : deliverySupport f = .SUPPORTED <;>
    by_cases h3 : reportingSupport f = .SUPPORTED <;> simp [requirements, h1, h2, h3]

theorem conclude_missingMask_lt (f : PackageFacts) : (conclude f).missingMask < 8 := by
  show missingMask f < 8
  unfold missingMask
  (repeat' split) <;> omega

theorem conclude_not_resolved_iff (f : PackageFacts) :
    (conclude f).assessment = .NOT_RESOLVED ↔ f.caseStatus ≠ some .RESOLVED := by
  show assessment f = .NOT_RESOLVED ↔ _
  unfold assessment
  (repeat' split) <;> simp_all

private theorem requiredAmount_conflicted {f : PackageFacts} (h : amountSupport f = .CONFLICTED) :
    requiredAmount f = .CONFLICTED := by
  unfold requiredAmount; simp [h]

private theorem requiredAmount_supported {f : PackageFacts} (h : requiredAmount f = .SUPPORTED) :
    f.amountSatisfied = true ∧ amountSupport f = .SUPPORTED := by
  unfold requiredAmount at h
  (repeat' split at h) <;> simp_all

theorem conclude_assessment_supported_iff (f : PackageFacts) :
    (conclude f).assessment = .SUPPORTED ↔
      f.caseStatus = some .RESOLVED ∧ f.conflictCount = 0 ∧ ∀ s ∈ requirements f, s = .SUPPORTED := by
  have hmask : missingMask f = 0 ↔ ∀ s ∈ requirements f, s = .SUPPORTED := conclude_missingMask_zero_iff f
  have hconf := @requiredAmount_conflicted f
  have hsup := @requiredAmount_supported f
  show assessment f = .SUPPORTED ↔ _
  unfold assessment
  simp only [requirements, List.mem_cons, List.not_mem_nil, or_false, forall_eq_or_imp, forall_eq] at hmask ⊢
  (repeat' split) <;> first | grind | simp_all

private theorem reportingSupport_supported {f : PackageFacts} (h : reportingSupport f = .SUPPORTED) :
    f.reportingComplete = true ∧ f.reportCount ≠ 0 := by
  unfold reportingSupport at h
  (repeat' split at h) <;> simp_all

/-- What an auditor may rely on when the package says SUPPORTED. -/
theorem conclude_supported_has_evidence (f : PackageFacts) (h : (conclude f).assessment = .SUPPORTED) :
    f.amountSatisfied = true ∧ f.reportingComplete = true ∧ f.reportCount ≠ 0 ∧
    (activePayments f).length + (authorizedClaims f).length ≠ 0 ∧
    activeSum f = f.receivedCashCents ∧ claimedSum f = f.claimedAdjustmentCents ∧
    lawfulSum f = f.lawfulAdjustmentCents := by
  obtain ⟨-, -, hall⟩ := (conclude_assessment_supported_iff f).1 h
  have hr : requiredAmount f = .SUPPORTED := hall _ (by simp [requirements])
  have hp : reportingSupport f = .SUPPORTED := hall _ (by simp [requirements])
  obtain ⟨hsat, hamt⟩ := requiredAmount_supported hr
  obtain ⟨hpc, hac, -, hcnt⟩ := (conclude_amount_supported_iff f).1 (show amountSupport f = .SUPPORTED from hamt)
  have h1 : activeSum f = f.receivedCashCents := Classical.byContradiction fun hne => hpc ((conclude_cash_conflicted_iff f).2 hne)
  have h2 : claimedSum f = f.claimedAdjustmentCents :=
    Classical.byContradiction fun hx => hac ((adjustmentSupport_conflicted_iff f).2 (Or.inl hx))
  have h3 : lawfulSum f = f.lawfulAdjustmentCents :=
    Classical.byContradiction fun hx => hac ((adjustmentSupport_conflicted_iff f).2 (Or.inr hx))
  obtain ⟨hrc, hrn⟩ := reportingSupport_supported hp
  exact ⟨hsat, hrc, hrn, hcnt, h1, h2, h3⟩

/-- An acknowledgment never moves cash (test_c05's claim, now a theorem). -/
theorem conclude_cash_independent_of_action (f : PackageFacts) (a : Option PkgAction) :
    (conclude { f with action := a }).cash = (conclude f).cash ∧
    (conclude { f with action := a }).amount = (conclude f).amount ∧
    (conclude { f with action := a }).missingCents = (conclude f).missingCents :=
  ⟨rfl, rfl, rfl⟩

/-! ### 4.4 Canonical encoding -/

private theorem ofNat_of_toNat {b : UInt8} {n : Nat} (h : b.toNat = n) : UInt8.ofNat n = b := by
  subst h; exact UInt8.ofNat_toNat

private theorem readBool_inv {l : Bytes} {v : Bool} {r : Bytes} (h : readBool l = some (v, r)) :
    l = encodeBool v ++ r := by
  unfold readBool at h
  rcases l with _ | ⟨b, t⟩
  · simp [readByte] at h
  · by_cases h0 : b.toNat = 0
    · simp [readByte, h0] at h
      obtain ⟨rfl, rfl⟩ := h
      have hb := ofNat_of_toNat h0
      subst hb
      simp [encodeBool]
    · by_cases h1 : b.toNat = 1
      · simp [readByte, h1] at h
        obtain ⟨rfl, rfl⟩ := h
        have hb := ofNat_of_toNat h1
        subst hb
        simp [encodeBool]
      · simp [readByte, h0, h1] at h

private theorem readCents_inv {b : Bytes} {v : Nat} {r : Bytes} (h : readCents b = some (v, r)) :
    b = natBE 8 v ++ r ∧ v ≤ maxCents := by
  unfold readCents at h
  rcases hn : readNatBE 8 b with _ | ⟨a, t⟩
  · simp [hn] at h
  · simp only [hn, Option.bind_eq_bind, Option.bind_some] at h
    split at h
    · simp at h
    · simp only [Option.pure_def, Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      exact ⟨(Batch.readNatBE_inv hn).1, by omega⟩

private theorem decodeClaimStatus_inv {b : UInt8} {s : ClaimStatus} (h : decodeClaimStatus b = some s) :
    encodeClaimStatus s = b := by
  unfold decodeClaimStatus at h
  repeat' split at h
  all_goals first
    | (obtain rfl := Option.some.inj h; exact ofNat_of_toNat (by assumption))
    | cases h

private theorem decodeVerificationStatus_inv {b : UInt8} {s : VerificationStatus}
    (h : decodeVerificationStatus b = some s) : encodeVerificationStatus s = b := by
  unfold decodeVerificationStatus at h
  repeat' split at h
  all_goals first
    | (obtain rfl := Option.some.inj h; exact ofNat_of_toNat (by assumption))
    | cases h

private theorem decodeCaseStatus_inv {b : UInt8} {s : CaseStatus} (h : decodeCaseStatus b = some s) :
    encodeCaseStatus s = b := by
  unfold decodeCaseStatus at h
  repeat' split at h
  all_goals first
    | (obtain rfl := Option.some.inj h; exact ofNat_of_toNat (by assumption))
    | cases h

private theorem decodeActionStatus_inv {b : UInt8} {s : ActionStatus} (h : decodeActionStatus b = some s) :
    encodeActionStatus s = b := by
  unfold decodeActionStatus at h
  repeat' split at h
  all_goals first
    | (obtain rfl := Option.some.inj h; exact ofNat_of_toNat (by assumption))
    | cases h

private theorem readTagged_inv {α : Type} {decode : UInt8 → Option α} {enc : α → UInt8}
    (hd : ∀ b v, decode b = some v → enc v = b) {l : Bytes} {v : α} {r : Bytes}
    (h : readTagged decode l = some (v, r)) : l = enc v :: r := by
  unfold readTagged at h
  rcases l with _ | ⟨b, t⟩
  · simp [readByte] at h
  · rcases hv : decode b with _ | w
    · simp [readByte, hv] at h
    · simp [readByte, hv] at h
      obtain ⟨rfl, rfl⟩ := h
      rw [hd b w hv]

private def optTag {α : Type} (enc : α → UInt8) : Option α → Bytes
  | none => [0]
  | some v => [enc v]

private theorem readOptionTagged_inv {α : Type} {decode : UInt8 → Option α} {enc : α → UInt8}
    (hd : ∀ b v, decode b = some v → enc v = b) {l : Bytes} {o : Option α} {r : Bytes}
    (h : readOptionTagged decode l = some (o, r)) :
    l = optTag enc o ++ r := by
  unfold readOptionTagged at h
  rcases l with _ | ⟨b, t⟩
  · simp [readByte] at h
  · by_cases h0 : b.toNat = 0
    · simp [readByte, h0] at h
      obtain ⟨rfl, rfl⟩ := h
      have hb := ofNat_of_toNat h0
      subst hb
      rfl
    · rcases hv : decode b with _ | w
      · simp [readByte, h0, hv] at h
      · simp [readByte, h0, hv] at h
        obtain ⟨rfl, rfl⟩ := h
        simp [optTag, hd b w hv]

private theorem readMany_inv' {α : Type} {enc : α → Bytes} {parse : Bytes → Option (α × Bytes)} {Q : α → Prop}
    (hp : ∀ b v r, parse b = some (v, r) → b = enc v ++ r ∧ Q v) {n : Nat} {l : Bytes} {vs : List α} {r : Bytes}
    (h : readMany parse n l = some (vs, r)) :
    vs.length = n ∧ (∀ v ∈ vs, Q v) ∧ l = vs.flatMap enc ++ r := by
  induction n generalizing l vs r with
  | zero =>
    simp only [readMany, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    simp
  | succ n ih =>
    simp only [readMany] at h
    rcases hi : parse l with _ | ⟨v, l1⟩
    · simp [hi] at h
    · rcases hm : readMany parse n l1 with _ | ⟨ts, r1⟩
      · simp [hi, hm] at h
      · simp only [hi, hm, Option.bind_eq_bind, Option.bind_some, Option.pure_def, Option.some.injEq,
          Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        obtain ⟨h1, h2⟩ := hp l v l1 hi
        obtain ⟨g1, g2, g3⟩ := ih hm
        refine ⟨by simp [g1], ?_, ?_⟩
        · intro x hx
          rcases List.mem_cons.1 hx with rfl | hx
          · exact h2
          · exact g2 x hx
        · rw [List.flatMap_cons, List.append_assoc, ← g3]; exact h1

private theorem readList_inv {α : Type} {enc : α → Bytes} {parse : Bytes → Option (α × Bytes)} {Q : α → Prop}
    (hp : ∀ b v r, parse b = some (v, r) → b = enc v ++ r ∧ Q v) {b : Bytes} {vs : List α} {r : Bytes}
    (h : readList parse b = some (vs, r)) :
    b = encodeList enc vs ++ r ∧ vs.length ≤ maxRows ∧ ∀ v ∈ vs, Q v := by
  unfold readList at h
  rcases hn : readNatBE 2 b with _ | ⟨count, rest⟩
  · simp [hn] at h
  · simp only [hn, Option.bind_eq_bind, Option.bind_some] at h
    split at h
    · simp at h
    · rename_i hc
      obtain ⟨g1, g2, g3⟩ := readMany_inv' hp h
      have i := (Batch.readNatBE_inv hn).1
      refine ⟨?_, by omega, g2⟩
      simp [encodeList, i, g3, g1, List.append_assoc]

private theorem readPkgPayment_inv {b : Bytes} {p : PkgPayment} {r : Bytes} (h : readPkgPayment b = some (p, r)) :
    b = (natBE 8 p.amountCents ++ encodeBool p.active) ++ r ∧ p.amountCents ≤ maxCents := by
  unfold readPkgPayment at h
  rcases e1 : readCents b with _ | ⟨a, b1⟩
  · simp [e1] at h
  · rcases e2 : readBool b1 with _ | ⟨x, b2⟩
    · simp [e1, e2] at h
    · simp [e1, e2] at h
      obtain ⟨rfl, rfl⟩ := h
      obtain ⟨i1, w1⟩ := readCents_inv e1
      have i2 := readBool_inv e2
      subst i1 i2
      exact ⟨by simp [List.append_assoc], w1⟩

private theorem readPkgClaim_inv {b : Bytes} {p : PkgClaim} {r : Bytes} (h : readPkgClaim b = some (p, r)) :
    b = (natBE 8 p.amountCents ++ [encodeClaimStatus p.status]) ++ r ∧ p.amountCents ≤ maxCents := by
  unfold readPkgClaim at h
  rcases e1 : readCents b with _ | ⟨a, b1⟩
  · simp [e1] at h
  · rcases e2 : readTagged decodeClaimStatus b1 with _ | ⟨x, b2⟩
    · simp [e1, e2] at h
    · simp [e1, e2] at h
      obtain ⟨rfl, rfl⟩ := h
      obtain ⟨i1, w1⟩ := readCents_inv e1
      have i2 := readTagged_inv (fun _ _ => decodeClaimStatus_inv) e2
      subst i1 i2
      exact ⟨by simp [List.append_assoc], w1⟩

set_option linter.unusedSimpArgs false in
private theorem decode_facts {b : Bytes} {f : PackageFacts} (h : decodePackageFacts b = some f) :
    encodePackageFacts f = b ∧ packageFactsWellFormed f := by
  unfold decodePackageFacts at h
  have hm : packageItemMagic.isPrefixOf b = true := by
    cases hq : packageItemMagic.isPrefixOf b
    · simp [hq] at h
    · rfl
  obtain ⟨t0, rfl⟩ := List.isPrefixOf_iff_prefix.1 hm
  simp only [hm, Bool.not_true, Bool.false_eq_true, ↓reduceIte, List.drop_left] at h
  rcases e1 : readCents t0 with _ | ⟨owed, b1⟩
  · simp [e1] at h
  simp only [e1, Option.bind_eq_bind, Option.bind_some] at h
  rcases e2 : readCents b1 with _ | ⟨recv, b2⟩
  · simp [e2] at h
  simp only [e2, Option.bind_eq_bind, Option.bind_some] at h
  rcases e3 : readCents b2 with _ | ⟨claimed, b3⟩
  · simp [e3] at h
  simp only [e3, Option.bind_eq_bind, Option.bind_some] at h
  rcases e4 : readCents b3 with _ | ⟨lawful, b4⟩
  · simp [e4] at h
  simp only [e4, Option.bind_eq_bind, Option.bind_some] at h
  rcases e5 : readBool b4 with _ | ⟨amt, b5⟩
  · simp [e5] at h
  simp only [e5, Option.bind_eq_bind, Option.bind_some] at h
  rcases e6 : readBool b5 with _ | ⟨rep, b6⟩
  · simp [e6] at h
  simp only [e6, Option.bind_eq_bind, Option.bind_some] at h
  rcases e7 : readTagged decodeVerificationStatus b6 with _ | ⟨ver, b7⟩
  · simp [e7] at h
  simp only [e7, Option.bind_eq_bind, Option.bind_some] at h
  rcases e8 : readList readPkgPayment b7 with _ | ⟨pays, b8⟩
  · simp [e8] at h
  simp only [e8, Option.bind_eq_bind, Option.bind_some] at h
  rcases e9 : readList readPkgClaim b8 with _ | ⟨claims, b9⟩
  · simp [e9] at h
  simp only [e9, Option.bind_eq_bind, Option.bind_some] at h
  rcases e10 : readCents b9 with _ | ⟨rc, b10⟩
  · simp [e10] at h
  simp only [e10, Option.bind_eq_bind, Option.bind_some] at h
  rcases e11 : readCents b10 with _ | ⟨cc, b11⟩
  · simp [e11] at h
  simp only [e11, Option.bind_eq_bind, Option.bind_some] at h
  rcases e12 : readOptionTagged decodeCaseStatus b11 with _ | ⟨cs, b12⟩
  · simp [e12] at h
  simp only [e12, Option.bind_eq_bind, Option.bind_some] at h
  rcases e13 : readOptionTagged decodeActionStatus b12 with _ | ⟨as, b13⟩
  · simp [e13] at h
  simp only [e13, Option.bind_eq_bind, Option.bind_some] at h
  rcases e14 : readBool b13 with _ | ⟨ack, b14⟩
  · simp [e14] at h
  simp only [e14, Option.bind_eq_bind, Option.bind_some] at h
  have hb : b14 = [] := Classical.byContradiction fun hb => by simp [hb] at h
  subst hb
  obtain ⟨i1, w1⟩ := readCents_inv e1
  obtain ⟨i2, w2⟩ := readCents_inv e2
  obtain ⟨i3, w3⟩ := readCents_inv e3
  obtain ⟨i4, w4⟩ := readCents_inv e4
  have i5 := readBool_inv e5
  have i6 := readBool_inv e6
  have i7 := readTagged_inv (fun _ _ => decodeVerificationStatus_inv) e7
  obtain ⟨i8, l8, q8⟩ := readList_inv
    (enc := fun p : PkgPayment => natBE 8 p.amountCents ++ encodeBool p.active)
    (Q := fun p : PkgPayment => p.amountCents ≤ maxCents) (fun _ _ _ => readPkgPayment_inv) e8
  obtain ⟨i9, l9, q9⟩ := readList_inv
    (enc := fun p : PkgClaim => natBE 8 p.amountCents ++ [encodeClaimStatus p.status])
    (Q := fun p : PkgClaim => p.amountCents ≤ maxCents) (fun _ _ _ => readPkgClaim_inv) e9
  obtain ⟨i10, w10⟩ := readCents_inv e10
  obtain ⟨i11, w11⟩ := readCents_inv e11
  have i12 := readOptionTagged_inv (fun _ _ => decodeCaseStatus_inv) e12
  have i13 := readOptionTagged_inv (fun _ _ => decodeActionStatus_inv) e13
  have i14 := readBool_inv e14
  subst i1 i2 i3 i4 i5 i6 i7 i8 i9 i10 i11 i12 i13 i14
  rcases as with _ | a <;> rcases cs with _ | c <;> cases ack <;> simp at h <;> subst h <;>
    refine ⟨by simp [encodePackageFacts, optTag, List.append_assoc, encodeBool], ?_⟩ <;>
    (unfold packageFactsWellFormed; exact ⟨w1, w2, w3, w4, w10, w11, l8, l9, q8, q9⟩)

theorem decodePackageFacts_canonical {b : Bytes} {f : PackageFacts} (h : decodePackageFacts b = some f) :
    encodePackageFacts f = b := (decode_facts h).1

theorem decodePackageFacts_wellFormed {b : Bytes} {f : PackageFacts} (h : decodePackageFacts b = some f) :
    packageFactsWellFormed f := (decode_facts h).2

private theorem magic_prefix (X : Bytes) : packageItemMagic.isPrefixOf (packageItemMagic ++ X) = true :=
  List.isPrefixOf_iff_prefix.2 (List.prefix_append _ _)

private theorem answerMagic_prefix (X : Bytes) : packageAnswerMagic.isPrefixOf (packageAnswerMagic ++ X) = true :=
  List.isPrefixOf_iff_prefix.2 (List.prefix_append _ _)

private theorem readCents_enc {v : Nat} (h : v ≤ maxCents) (r : Bytes) :
    readCents (natBE 8 v ++ r) = some (v, r) := by
  simp [readCents, readNatBE_natBE_append 8 v r (Nat.lt_of_le_of_lt h maxCents_fits_u64), Nat.not_lt.mpr h]

private theorem readBool_zero : readBool [0] = some (false, []) := rfl

private theorem readBool_enc (v : Bool) : readBool (encodeBool v) = some (v, []) := by cases v <;> rfl

private theorem readTagged_enc {α : Type} {decode : UInt8 → Option α} {enc : α → UInt8} {v : α}
    (hd : decode (enc v) = some v) (r : Bytes) : readTagged decode (enc v :: r) = some (v, r) := by
  simp [readTagged, readByte, hd]

private theorem readVerification_enc (v : VerificationStatus) (r : Bytes) :
    readTagged decodeVerificationStatus (encodeVerificationStatus v :: r) = some (v, r) :=
  readTagged_enc (decodeVerificationStatus_encodeVerificationStatus v) r

private theorem readClaimStatus_enc (v : ClaimStatus) (r : Bytes) :
    readTagged decodeClaimStatus (encodeClaimStatus v :: r) = some (v, r) :=
  readTagged_enc (decodeClaimStatus_encodeClaimStatus v) r

private theorem readOptionTagged_some {α : Type} {decode : UInt8 → Option α} {enc : α → UInt8} {v : α}
    (hd : decode (enc v) = some v) (hnz : (enc v).toNat ≠ 0) (r : Bytes) :
    readOptionTagged decode (enc v :: r) = some (some v, r) := by
  simp [readOptionTagged, readByte, hd, hnz]

private theorem readOptionTagged_none {α : Type} (decode : UInt8 → Option α) (r : Bytes) :
    readOptionTagged decode ((0 : UInt8) :: r) = some (none, r) := by
  simp [readOptionTagged, readByte]

private theorem readCase_enc (c : CaseStatus) (r : Bytes) :
    readOptionTagged decodeCaseStatus (encodeCaseStatus c :: r) = some (some c, r) :=
  readOptionTagged_some (decodeCaseStatus_encodeCaseStatus c) (by cases c <;> decide) r

private theorem readAction_enc (a : ActionStatus) (r : Bytes) :
    readOptionTagged decodeActionStatus (encodeActionStatus a :: r) = some (some a, r) :=
  readOptionTagged_some (decodeActionStatus_encodeActionStatus a) (by cases a <;> decide) r

private theorem readPkgPayment_enc {p : PkgPayment} (h : p.amountCents ≤ maxCents) (r : Bytes) :
    readPkgPayment (natBE 8 p.amountCents ++ encodeBool p.active ++ r) = some (p, r) := by
  simp [readPkgPayment, List.append_assoc, readCents_enc h, readBool_encodeBool_append]

private theorem readPkgClaim_enc {p : PkgClaim} (h : p.amountCents ≤ maxCents) (r : Bytes) :
    readPkgClaim (natBE 8 p.amountCents ++ [encodeClaimStatus p.status] ++ r) = some (p, r) := by
  simp [readPkgClaim, List.append_assoc, readCents_enc h, readClaimStatus_enc]

private theorem readPayments_enc {ps : List PkgPayment} (h1 : ps.length ≤ maxRows)
    (h2 : ∀ p ∈ ps, p.amountCents ≤ maxCents) (r : Bytes) :
    readList readPkgPayment (encodeList (fun p : PkgPayment => natBE 8 p.amountCents ++ encodeBool p.active) ps ++ r) =
      some (ps, r) :=
  readList_encodeList_append_of_mem _ _ ps r h1 (Nat.lt_of_le_of_lt h1 (by decide))
    (fun p hp t => readPkgPayment_enc (h2 p hp) t)

private theorem readClaims_enc {cs : List PkgClaim} (h1 : cs.length ≤ maxRows)
    (h2 : ∀ c ∈ cs, c.amountCents ≤ maxCents) (r : Bytes) :
    readList readPkgClaim (encodeList (fun p : PkgClaim => natBE 8 p.amountCents ++ [encodeClaimStatus p.status]) cs ++ r) =
      some (cs, r) :=
  readList_encodeList_append_of_mem _ _ cs r h1 (Nat.lt_of_le_of_lt h1 (by decide))
    (fun c hc t => readPkgClaim_enc (h2 c hc) t)

theorem decodePackageFacts_encode {f : PackageFacts} (h : packageFactsWellFormed f) :
    decodePackageFacts (encodePackageFacts f) = some f := by
  rcases f with ⟨owed, recv, claimed, lawful, amt, rep, ver, pays, claims, rc, cc, cs, ac⟩
  simp only [packageFactsWellFormed] at h
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10⟩ := h
  unfold decodePackageFacts encodePackageFacts
  rcases cs with _ | c <;> rcases ac with _ | ⟨st, ak⟩ <;>
    simp [List.append_assoc, magic_prefix, readCents_enc h1, readCents_enc h2, readCents_enc h3,
      readCents_enc h4, readCents_enc h5, readCents_enc h6, readBool_encodeBool_append, readBool_enc, readBool_zero,
      readVerification_enc, readPayments_enc h7 h9, readClaims_enc h8 h10, readCase_enc, readAction_enc,
      readOptionTagged_none]

private theorem decodeSupport_supportByte (s : Support) : decodeSupport (supportByte s) = some s := by
  cases s <;> decide

private theorem decodeAssessment_assessmentByte (a : Assessment) : decodeAssessment (assessmentByte a) = some a := by
  cases a <;> decide

private theorem answer_roundtrip {c : Conclusions} (hm : c.missingMask < 8) (hc : c.missingCents ≤ maxCents)
    (h1 : c.activePaymentCount < 256 ^ 2) (h2 : c.authorizedClaimCount < 256 ^ 2) :
    decodePackageAnswer (encodePackageAnswer c) = some c := by
  rcases c with ⟨cash, amount, reporting, delivery, req, mask, assess, mc, apc, acc⟩
  simp only at hm hc h1 h2
  have hmask : (UInt8.ofNat mask).toNat = mask := by simp [Nat.mod_eq_of_lt (by omega : mask < 256)]
  have hm7 : ¬ mask > 7 := by omega
  have e2 : ∀ r, readNatBE 2 (natBE 2 apc ++ r) = some (apc, r) := fun r => readNatBE_natBE_append 2 apc r h1
  have e3 : ∀ r, readNatBE 2 (natBE 2 acc ++ r) = some (acc, r) := fun r => readNatBE_natBE_append 2 acc r h2
  have e3' : readNatBE 2 (natBE 2 acc) = some (acc, []) := by simpa using e3 []
  unfold decodePackageAnswer encodePackageAnswer
  simp [List.append_assoc, answerMagic_prefix, readCents_enc hc, readTagged_enc (decodeSupport_supportByte _),
    readTagged_enc (decodeAssessment_assessmentByte _), readByte, hmask, hm7, e2, e3']

theorem decodePackageAnswer_respond {item : Bytes} {f : PackageFacts} (h : decodePackageFacts item = some f) :
    packageRespond item = UInt8.ofNat 0 :: encodePackageAnswer (conclude f) ∧
    decodePackageAnswer (encodePackageAnswer (conclude f)) = some (conclude f) := by
  refine ⟨by simp [packageRespond, h], ?_⟩
  obtain ⟨hw1, hw2, hw3, hw4, hw5, hw6, hw7, hw8, hw9, hw10⟩ := decodePackageFacts_wellFormed h
  have hp := List.length_filter_le (·.active) f.payments
  have hc := List.length_filter_le (fun c => c.status = .AUTHORIZED) f.claims
  apply answer_roundtrip
  · exact conclude_missingMask_lt f
  · show f.owedCents - f.receivedCashCents ≤ maxCents
    omega
  · exact Nat.lt_of_le_of_lt (Nat.le_trans hp hw7) (by decide)
  · exact Nat.lt_of_le_of_lt (Nat.le_trans hc hw8) (by decide)

/-! ### 4.6 Known answers -/

def kH : PackageFacts :=
  { owedCents := 10000, receivedCashCents := 10000, claimedAdjustmentCents := 0, lawfulAdjustmentCents := 0,
    amountSatisfied := true, reportingComplete := true, verification := .SUPPORTED,
    payments := [{ amountCents := 6000, active := true }, { amountCents := 4000, active := true }],
    claims := [{ amountCents := 4000, status := .REJECTED }], reportCount := 1, conflictCount := 0,
    caseStatus := some .RESOLVED, action := some { status := .ACKNOWLEDGED, acknowledged := true } }
def kShort : PackageFacts :=
  { kH with receivedCashCents := 6000, amountSatisfied := false, payments := [{ amountCents := 6000, active := true }] }

#guard packageItemMagic == "BLFDPK01".toUTF8.toList
#guard packageAnswerMagic == "BLFDPA01".toUTF8.toList
#guard (conclude kH).assessment == .SUPPORTED
#guard (conclude kH).missingMask == 0
#guard decodePackageFacts (encodePackageFacts kH) == some kH
#guard (encodePackageFacts kH).length == 93
#guard packageRespond (encodePackageFacts kH) == UInt8.ofNat 0 :: encodePackageAnswer (conclude kH)
#guard (packageRespond (encodePackageFacts kH)).length == 28
#guard decodePackageAnswer (encodePackageAnswer (conclude kH)) == some (conclude kH)
#guard (conclude { kShort with caseStatus := some .ACTIONED }).assessment == .NOT_RESOLVED
#guard (conclude kShort).assessment == .UNSUPPORTED
#guard (conclude kShort).missingCents == 4000
#guard (conclude kShort).requiredAmount == .NOT_SATISFIED
#guard (conclude { kH with receivedCashCents := 9999 }).assessment == .CONFLICTED
#guard (conclude { kH with conflictCount := 1 }).assessment == .CONFLICTED
#guard (conclude { kH with action := some { status := .ACKNOWLEDGED, acknowledged := false } }).missingMask == 2
#guard (conclude { kH with action := none }).assessment == .UNKNOWN
#guard (conclude { kH with reportCount := 0 }).reporting == .UNKNOWN
#guard (conclude { kH with reportingComplete := false }).reporting == .CONFLICTED
#guard (conclude { kH with verification := .CONFLICT_VISIBLE }).requiredAmount == .CONFLICTED
#guard (conclude { kH with receivedCashCents := 0, payments := [] }).cash == .NO_LINKED_EVIDENCE
#guard (conclude { kH with receivedCashCents := 0, payments := [] }).amount == .UNKNOWN
#guard packageRespond (encodePackageFacts kH ++ [0]) == [1]
#guard packageRespond ((encodePackageFacts { kH with action := none }).dropLast ++ [1]) == [1]
#guard packageRespond (packageItemMagic ++ natBE 8 (2 ^ 63) ++ (encodePackageFacts kH).drop 16) == [1]
#guard packageRespond packageItemMagic == [1]

end BlindLedger.Financial.DecisionPackage
