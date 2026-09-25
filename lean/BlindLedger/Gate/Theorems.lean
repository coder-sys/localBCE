import BlindLedger.Gate.Spec

namespace BlindLedger.Gate

/-! What the payer's steps and the Merkle path guarantee, for every `Crypto`. -/

/-- The nine payer checks, as one proposition. -/
def NineChecks (c : Crypto) (s : PayerState) (p : Payment) (bytes : Bytes) (t : Token) : Prop :=
  decodeToken bytes = some t ∧ certValid s t = true ∧ batchSigned c s t = true ∧
    aboveFence s t = true ∧ unexpired s t = true ∧ paymentMatches c p t = true ∧
    allows t = true ∧ granted s t = true ∧ unreleased s t = true

/-- `verifyToken` accepts exactly when all nine checks hold. -/
theorem verifyToken_iff (c : Crypto) (s : PayerState) (p : Payment) (bytes : Bytes) :
    verifyToken c s p bytes = true ↔ ∃ t, NineChecks c s p bytes t := by
  unfold verifyToken NineChecks
  cases h : decodeToken bytes with
  | none => simp
  | some t => simp [Bool.and_eq_true, and_assoc]

/-- No accepted token is below its tenant's fence (the model's `NoFencedTokenAccepted`). -/
theorem verifyToken_epoch_ge_fence {c : Crypto} {s : PayerState} {p : Payment} {bytes : Bytes}
    (h : verifyToken c s p bytes = true) :
    ∃ t, decodeToken bytes = some t ∧ s.fence t.leaf.tenantId ≤ t.leaf.epoch := by
  obtain ⟨t, hd, -, -, h4, -⟩ := (verifyToken_iff c s p bytes).1 h
  exact ⟨t, hd, by simpa [aboveFence] using h4⟩

theorem raiseFence_ge {f : Bytes → Nat} {tenant : Bytes} {e : Nat} (x : Bytes) :
    f x ≤ raiseFence f tenant e x := by
  unfold raiseFence
  split
  · exact Nat.le_max_left _ _
  · exact Nat.le_refl _

/-- Installing a certificate never lowers a fence and lifts its tenant's to
    at least its epoch (the model's `PayerLearnFence`). -/
theorem installCert_raises_fence {c : Crypto} {s s' : PayerState} {e : EpochCert}
    (h : installCert c s e = some s') :
    e.epoch ≤ s'.fence e.tenantId ∧ ∀ x, s.fence x ≤ s'.fence x := by
  unfold installCert at h
  split at h
  · obtain rfl := Option.some.inj h
    refine ⟨?_, fun x => raiseFence_ge x⟩
    show e.epoch ≤ raiseFence s.fence e.tenantId e.epoch e.tenantId
    unfold raiseFence
    rw [if_pos rfl]
    exact Nat.le_max_right _ _
  · simp at h

/-- `release` happens exactly on the bytes `verifyToken` accepts. -/
theorem release_isSome (c : Crypto) (s : PayerState) (p : Payment) (bytes : Bytes) :
    (release c s p bytes).isSome = verifyToken c s p bytes := by
  unfold release
  cases hd : decodeToken bytes with
  | none => simp [verifyToken, hd]
  | some t => by_cases hv : verifyToken c s p bytes = true <;> simp [hv]

/-- The fence never moves down (the model's `EpochMonotone` on the payer side). -/
theorem release_fence_monotone {c : Crypto} {s s' : PayerState} {p : Payment} {bytes : Bytes}
    (h : release c s p bytes = some s') (x : Bytes) : s.fence x ≤ s'.fence x := by
  unfold release at h
  split at h
  · simp at h
  · split at h
    · obtain rfl := Option.some.inj h
      exact raiseFence_ge x
    · simp at h

/-- At most one release per payment (the model's `AtMostOnceRelease`): after a
    release, every token for the same tenant, program, flow and payment id is
    rejected. -/
theorem release_at_most_once {c : Crypto} {s s' : PayerState} {p p' : Payment}
    {bytes bytes' : Bytes} {t t' : Token} (h : release c s p bytes = some s')
    (hd : decodeToken bytes = some t) (hd' : decodeToken bytes' = some t')
    (hk : payKey t' = payKey t) : verifyToken c s' p' bytes' = false := by
  unfold release at h
  rw [hd] at h
  dsimp only at h
  split at h
  · obtain rfl := Option.some.inj h
    simp [verifyToken, hd', unreleased, hk]
  · simp at h

/-- Honest but weak: `verifyPath` compares one fold against one root, so a
    path cannot pass under two different roots.  This says nothing about the
    hash; the reduction below is the security statement. -/
theorem verifyPath_rejects_other_root {H : Bytes → Bytes} {d x : Bytes} {i n : Nat}
    {path : List Bytes} {r r' : Bytes} (h : verifyPath H d x i n path r = true) (hr : r' ≠ r) :
    verifyPath H d x i n path r' = false := by
  cases h' : verifyPath H d x i n path r' with
  | false => rfl
  | true =>
    simp only [verifyPath, Bool.and_eq_true, beq_iff_eq] at h h'
    exact absurd (Option.some.inj (h'.2.symm.trans h.2)) hr

/-- Whatever `pathCollision` returns is a collision: distinct inputs, one output. -/
theorem pathCollision_sound {H : Bytes → Bytes} {d : Bytes} (fuel : Nat) :
    ∀ (i n : Nat) (a b : Bytes) (p q : List Bytes) (x y : Bytes),
      pathCollision H d fuel i n a b p q = some (x, y) → x ≠ y ∧ H x = H y := by
  induction fuel with
  | zero => intro i n a b p q x y h; simp [pathCollision] at h
  | succ fuel ih =>
    intro i n a b p q x y h
    simp only [pathCollision] at h
    by_cases hn : n ≤ 1
    · rw [if_pos hn] at h
      exact absurd h (by simp)
    rw [if_neg hn] at h
    by_cases hc : (i % 2 == 0 && i + 1 == n) = true
    · rw [if_pos hc] at h
      exact ih _ _ _ _ _ _ _ _ h
    rw [if_neg hc] at h
    cases p with
    | nil => simp at h
    | cons s ps =>
    cases q with
    | nil => simp at h
    | cons t qs =>
    simp only at h
    by_cases hx : stepInput d i a s ≠ stepInput d i b t ∧
        H (stepInput d i a s) = H (stepInput d i b t)
    · rw [if_pos hx] at h
      obtain ⟨rfl, rfl⟩ := Prod.mk.inj (Option.some.inj h)
      exact hx
    · rw [if_neg hx] at h
      exact ih _ _ _ _ _ _ _ _ h

/-- Two different equal-length nodes folding to one root at one position make
    `pathCollision` return a pair, provided every hash output has one length. -/
theorem pathCollision_complete {H : Bytes → Bytes} {d : Bytes}
    (hlen : ∀ z, (H z).length = digestBytes) (fuel : Nat) :
    ∀ (i n : Nat) (a b : Bytes) (p q : List Bytes) (r : Bytes), a ≠ b → a.length = b.length →
      pathRoot H d fuel i n a p = some r → pathRoot H d fuel i n b q = some r →
      pathCollision H d fuel i n a b p q ≠ none := by
  induction fuel with
  | zero => intro i n a b p q r _ _ ha _; simp [pathRoot] at ha
  | succ fuel ih =>
    intro i n a b p q r hne hl ha hb
    simp only [pathRoot] at ha hb
    simp only [pathCollision]
    by_cases hn : n ≤ 1
    · rw [if_pos hn] at ha hb
      have hra : a = r := by
        split at ha
        · exact Option.some.inj ha
        · exact absurd ha (by simp)
      have hrb : b = r := by
        split at hb
        · exact Option.some.inj hb
        · exact absurd hb (by simp)
      exact absurd (hra.trans hrb.symm) hne
    rw [if_neg hn] at ha hb
    rw [if_neg hn]
    by_cases hc : (i % 2 == 0 && i + 1 == n) = true
    · rw [if_pos hc] at ha hb
      rw [if_pos hc]
      exact ih _ _ a b p q r hne hl ha hb
    rw [if_neg hc] at ha hb
    rw [if_neg hc]
    cases p with
    | nil => simp at ha
    | cons s ps =>
    cases q with
    | nil => simp at hb
    | cons t qs =>
    simp only at ha hb ⊢
    have hstep : stepInput d i a s ≠ stepInput d i b t := by
      intro heq
      unfold stepInput at heq
      have h2 := (List.cons.inj (List.append_cancel_left heq)).2
      by_cases he : (i % 2 == 0) = true
      · rw [if_pos he, if_pos he] at h2
        exact hne (List.append_inj h2 hl).1
      · rw [if_neg he, if_neg he] at h2
        exact hne (List.append_inj' h2 hl).2
    by_cases hx : stepInput d i a s ≠ stepInput d i b t ∧
        H (stepInput d i a s) = H (stepInput d i b t)
    · rw [if_pos hx]
      simp
    · rw [if_neg hx]
      exact ih _ _ _ _ ps qs r (fun e => hx ⟨hstep, e⟩) (by rw [hlen, hlen]) ha hb

/-- The Merkle reduction: if one root, index and batch size accept two
    different leaves, `leafCollision` returns an explicit SHA3 collision
    (distinct inputs, one output).  So a second leaf under a signed root costs
    a collision the caller can print. -/
theorem verifyPath_collision {H : Bytes → Bytes} {d : Bytes}
    (hlen : ∀ z, (H z).length = digestBytes) {x y : Bytes} {i n : Nat} {p q : List Bytes}
    {r : Bytes} (hx : verifyPath H d x i n p r = true) (hy : verifyPath H d y i n q r = true)
    (hne : x ≠ y) : ∃ a b, leafCollision H d x y i n p q = some (a, b) ∧ a ≠ b ∧ H a = H b := by
  simp only [verifyPath, Bool.and_eq_true, beq_iff_eq] at hx hy
  unfold leafCollision
  by_cases hc : d ++ (0 :: x) ≠ d ++ (0 :: y) ∧ H (d ++ (0 :: x)) = H (d ++ (0 :: y))
  · rw [if_pos hc]
    exact ⟨_, _, rfl, hc⟩
  · rw [if_neg hc]
    have hin : d ++ (0 :: x) ≠ d ++ (0 :: y) := fun e =>
      hne (List.cons.inj (List.append_cancel_left e)).2
    have hH : leafHash H d x ≠ leafHash H d y := fun e => hc ⟨hin, e⟩
    match hm : pathCollision H d treeFuel i n (leafHash H d x) (leafHash H d y) p q with
    | some (a, b) => exact ⟨a, b, rfl, pathCollision_sound _ _ _ _ _ _ _ _ _ hm⟩
    | none =>
      exact absurd hm (pathCollision_complete hlen _ _ _ _ _ _ _ _ hH
        (by simp [leafHash, hlen]) hx.2 hy.2)

end BlindLedger.Gate
