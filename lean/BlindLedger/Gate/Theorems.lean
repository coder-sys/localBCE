import BlindLedger.Gate.Spec

namespace BlindLedger.Gate

/-! What `verifyToken` and the Merkle path guarantee, for every `Crypto`. -/

/-- The nine payer checks, as one proposition. -/
def NineChecks (c : Crypto) (s : PayerState) (p : Payment) (bytes : Bytes) (t : Token) : Prop :=
  decodeToken bytes = some t ∧ certValid c s t = true ∧ batchSigned c s t = true ∧
    aboveFence s t = true ∧ unexpired s t = true ∧ paymentMatches c p t = true ∧
    allows t = true ∧ granted s t = true ∧ unreleased s t = true

/-- `verifyToken` accepts exactly when all nine checks hold. -/
theorem verifyToken_iff (c : Crypto) (s : PayerState) (p : Payment) (bytes : Bytes) :
    verifyToken c s p bytes = true ↔ ∃ t, NineChecks c s p bytes t := by
  unfold verifyToken NineChecks
  cases h : decodeToken bytes with
  | none => simp
  | some t => simp [Bool.and_eq_true, and_assoc]

theorem verifyToken_epoch_ge_fence {c : Crypto} {s : PayerState} {p : Payment} {bytes : Bytes}
    (h : verifyToken c s p bytes = true) :
    ∃ t, decodeToken bytes = some t ∧ s.fence ≤ t.leaf.epoch := by
  obtain ⟨t, hd, -, -, h4, -⟩ := (verifyToken_iff c s p bytes).1 h
  exact ⟨t, hd, by simpa [aboveFence] using h4⟩

/-- A hash collision: two different inputs with one output. -/
def Collision (H : Bytes → Bytes) : Prop := ∃ x y, x ≠ y ∧ H x = H y

/-- An accepted path names one root: the same path under a different root is rejected. -/
theorem verifyPath_rejects_other_root {H : Bytes → Bytes} {x : Bytes} {i n : Nat}
    {path : List Bytes} {r r' : Bytes} (h : verifyPath H x i n path r = true) (hr : r' ≠ r) :
    verifyPath H x i n path r' = false := by
  cases h' : verifyPath H x i n path r' with
  | false => rfl
  | true =>
    simp only [verifyPath, Bool.and_eq_true, beq_iff_eq] at h h'
    exact absurd (Option.some.inj (h'.2.symm.trans h.2)) hr

private theorem hash_inputs {H : Bytes → Bytes} {x y : Bytes} (h : H x = H y) :
    x = y ∨ Collision H := by
  by_cases hxy : x = y
  · exact Or.inl hxy
  · exact Or.inr ⟨x, y, hxy, h⟩

/-- Two nodes of equal length that fold to one root at one position are equal,
    unless the hash has a collision. -/
theorem pathRoot_binding {H : Bytes → Bytes} (hlen : ∀ x, (H x).length = digestBytes) :
    ∀ (fuel i n : Nat) (a b : Bytes) (p q : List Bytes) (r : Bytes), a.length = b.length →
      pathRoot H fuel i n a p = some r → pathRoot H fuel i n b q = some r → a = b ∨ Collision H := by
  intro fuel
  induction fuel with
  | zero => intro i n a b p q r _ ha _; simp [pathRoot] at ha
  | succ fuel ih =>
    intro i n a b p q r hl ha hb
    simp only [pathRoot] at ha hb
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
      exact Or.inl (hra.trans hrb.symm)
    rw [if_neg hn] at ha hb
    by_cases hc : (i % 2 == 0 && i + 1 == n) = true
    · rw [if_pos hc] at ha hb
      exact ih _ _ a b p q r hl ha hb
    rw [if_neg hc] at ha hb
    cases p with
    | nil => simp at ha
    | cons s ps =>
    cases q with
    | nil => simp at hb
    | cons t qs =>
    simp only at ha hb
    have hup := ih _ _ _ _ ps qs r (by split <;> split <;> simp [nodeHash, hlen]) ha hb
    rcases hup with hup | hup
    · by_cases he : (i % 2 == 0) = true
      · rw [if_pos he, if_pos he] at hup
        unfold nodeHash at hup
        rcases hash_inputs hup with hin | hin
        · exact Or.inl (List.append_inj (List.cons.inj (List.append_cancel_left hin)).2 hl).1
        · exact Or.inr hin
      · rw [if_neg he, if_neg he] at hup
        unfold nodeHash at hup
        rcases hash_inputs hup with hin | hin
        · exact Or.inl (List.append_inj' (List.cons.inj (List.append_cancel_left hin)).2 hl).2
        · exact Or.inr hin
    · exact Or.inr hup

/-- Under one root, index and batch size, a path accepts a second, different
    leaf only by exhibiting a hash collision. -/
theorem verifyPath_other_leaf_is_collision {H : Bytes → Bytes}
    (hlen : ∀ x, (H x).length = digestBytes) {x y : Bytes} {i n : Nat} {p q : List Bytes}
    {r : Bytes} (hx : verifyPath H x i n p r = true) (hy : verifyPath H y i n q r = true)
    (hne : x ≠ y) : Collision H := by
  simp only [verifyPath, Bool.and_eq_true, beq_iff_eq] at hx hy
  rcases pathRoot_binding hlen _ _ _ _ _ _ _ _ (by simp [leafHash, hlen]) hx.2 hy.2 with h | h
  · rcases hash_inputs h with hin | hin
    · exact absurd (List.cons.inj (List.append_cancel_left hin)).2 hne
    · exact hin
  · exact h

end BlindLedger.Gate
