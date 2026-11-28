import BlindLedger.X12.Run

/-! Cutting the fold over interchanges.  `outerWith` keeps nothing from one interchange to the next but its state, so
    where its fold bounded by `j` ends right after an interchange its `IEA` closed (the flag), the fold bounded by any
    `N ≥ j` is the fold up to `j`, then the fold from `j` on, started from the state reached there.  The stream cuts
    only at such places (`Stream.lean`).  What this asks of the reader of one interchange (`step`) is in the hypotheses
    of `outerWith_split`: it ends past its header, it does not end past its bound, and an interchange that ends before
    the bound, or is closed at it, is read the same with any larger bound. -/

namespace BlindLedger.X12

theorem skipSp_ge (d : ByteArray) (i n : Nat) : i ≤ skipSp d i n := by
  rw [skipSp.eq_1 d i n]
  by_cases hin : i < n
  · rw [if_pos hin]
    by_cases hs : isSpace d[i]! = true
    · rw [if_pos hs]; have := skipSp_ge d (i + 1) n; omega
    · rw [if_neg hs]; omega
  · rw [if_neg hin]; omega
termination_by n - i

theorem skipSp_le (d : ByteArray) (i n : Nat) (h : i ≤ n) : skipSp d i n ≤ n := by
  rw [skipSp.eq_1 d i n]
  by_cases hin : i < n
  · rw [if_pos hin]
    by_cases hs : isSpace d[i]! = true
    · rw [if_pos hs]; exact skipSp_le d (i + 1) n (by omega)
    · rw [if_neg hs]; omega
  · rw [if_neg hin]; omega
termination_by n - i

theorem skipSp_at (d : ByteArray) (i n : Nat) (h : n ≤ i) : skipSp d i n = i := by
  rw [skipSp.eq_1 d i n, if_neg (by omega)]

/-- Where the skip stops before its bound, a larger bound does not change it. -/
theorem skipSp_below (d : ByteArray) (i j N : Nat) (hjN : j ≤ N) (h : skipSp d i j < j) :
    skipSp d i N = skipSp d i j := by
  by_cases hij : i < j
  · have hiN : i < N := by omega
    rw [skipSp.eq_1 d i j, if_pos hij] at h
    rw [skipSp.eq_1 d i N, skipSp.eq_1 d i j, if_pos hij, if_pos hiN]
    by_cases hs : isSpace d[i]! = true
    · rw [if_pos hs] at h
      rw [if_pos hs, if_pos hs]
      exact skipSp_below d (i + 1) j N hjN h
    · rw [if_neg hs, if_neg hs]
  · rw [skipSp_at d i j (by omega)] at h; omega
termination_by j - i

/-- Where the skip reaches its bound and the byte there is not white space, a larger bound stops there too. -/
theorem skipSp_reach (d : ByteArray) (i j N : Nat) (hij : i ≤ j) (hjN : j ≤ N) (h : skipSp d i j = j)
    (hsp : j < N → isSpace d[j]! = false) : skipSp d i N = j := by
  by_cases hlt : i < j
  · have hiN : i < N := by omega
    rw [skipSp.eq_1 d i j, if_pos hlt] at h
    rw [skipSp.eq_1 d i N, if_pos hiN]
    by_cases hs : isSpace d[i]! = true
    · rw [if_pos hs] at h
      rw [if_pos hs]
      exact skipSp_reach d (i + 1) j N (by omega) hjN h hsp
    · rw [if_neg hs] at h; omega
  · have hj : i = j := by omega
    rw [skipSp.eq_1 d i N]
    by_cases hiN : i < N
    · have hs : isSpace d[i]! = false := by rw [hj]; exact hsp (by omega)
      rw [if_pos hiN, if_neg (by simp [hs])]; exact hj
    · rw [if_neg hiN]; exact hj
termination_by j - i

/-- The fold bounded by `N` is the fold bounded by `j`, then the fold from `j` from the state it reached, when the
    first reached `j` right after an interchange its `IEA` closed and no white space starts at `j`. -/
theorem outerWith_split (step : Nat → Nat → Delims → Carry × Out → Nat × Bool × (Carry × Out)) (d : ByteArray)
    (j N : Nat) (hjN : j ≤ N) (hcut : j < N → isSpace d[j]! = false)
    (hprog : ∀ dl st, j < (step N j dl st).1)
    (hle : ∀ ofs dl st, ofs < j → (step j ofs dl st).1 ≤ j)
    (hsame : ∀ ofs dl st, ofs < j → ((step j ofs dl st).1 < j ∨ (step j ofs dl st).2.1 = true) →
      step N ofs dl st = step j ofs dl st)
    (pos : Nat) (st : Carry × Out) (last : Bool) (hpos : pos ≤ j) (hflag : (outerWith step d j pos st last).2 = true) :
    outerWith step d N pos st last = outerWith step d N j (outerWith step d j pos st last).1 true := by
  have hle' : ∀ ofs dl st p cl s', ofs < j → step j ofs dl st = (p, cl, s') → p ≤ j := by
    intro ofs dl st p cl s' h1 h2; have := hle ofs dl st h1; rw [h2] at this; exact this
  have hsame' : ∀ ofs dl st p cl s', ofs < j → step j ofs dl st = (p, cl, s') → (p < j ∨ cl = true) →
      step N ofs dl st = (p, cl, s') := by
    intro ofs dl st p cl s' h1 h2 h3; rw [hsame ofs dl st h1 (by rw [h2]; exact h3), h2]
  have hprog' : ∀ dl st p cl s', step N j dl st = (p, cl, s') → j < p := by
    intro dl st p cl s' h; have := hprog dl st; rw [h] at this; exact this
  rw [outerWith.eq_1 step d j pos st last] at hflag
  rw [outerWith.eq_1 step d N pos st last, outerWith.eq_1 step d j pos st last]
  by_cases hA : skipSp d pos j < j
  · -- an interchange starts before `j`: both folds read it alike, then go on from where it ends
    have hnj : ¬ (skipSp d pos j ≥ j) := by omega
    have hnN : ¬ (skipSp d pos j ≥ N) := by omega
    rw [skipSp_below d pos j N hjN hA]
    rw [if_neg hnj] at hflag
    rw [if_neg hnN, if_neg hnj]
    split at hflag
    · repeat' split at hflag
      all_goals exact (Bool.false_ne_true hflag).elim
    · rename_i dl hi
      split at hflag
      rename_i p cl s' hstep
      by_cases hc : pos < p ∧ pos < j
      · rw [dif_pos hc] at hflag
        have hpj : p ≤ j := hle' _ dl _ p cl s' hA hstep
        have hcl : p < j ∨ cl = true := by
          by_cases hpj' : p < j
          · exact Or.inl hpj'
          · right
            have hp : p = j := by omega
            rw [hp, outerWith.eq_1 step d j j s' cl, skipSp_at d j j (Nat.le_refl j),
              if_pos (Nat.le_refl j), if_neg (Nat.lt_irrefl j)] at hflag
            exact hflag
        simp only [hsame' _ dl _ p cl s' hA hstep hcl]
        rw [dif_pos ⟨hc.1, by omega⟩, dif_pos hc]
        have := hc.1
        exact outerWith_split step d j N hjN hcut hprog hle hsame p s' cl hpj hflag
      · rw [dif_neg hc] at hflag; exact (Bool.false_ne_true hflag).elim
  · -- the fold bounded by `j` reached it after white space only: so does the other, at a header
    have hge : skipSp d pos j = j := by have := skipSp_le d pos j hpos; omega
    have hN := skipSp_reach d pos j N hpos hjN hge hcut
    rw [hge] at hflag
    rw [if_pos (Nat.le_refl j)] at hflag
    simp only at hflag
    rw [hN, hge, if_pos (Nat.le_refl j), show ∀ (a : Carry × Out) (b : Bool), (a, b).1 = a from fun _ _ => rfl,
      outerWith.eq_1 step d N j _ true]
    by_cases hjN' : j < N
    · have hjj : skipSp d j N = j := skipSp_reach d j j N (Nat.le_refl j) hjN (skipSp_at d j j (Nat.le_refl j)) hcut
      rw [hjj, if_neg (Nat.lt_irrefl j), if_neg (show ¬ (j ≥ N) by omega), if_neg (show ¬ (j ≥ N) by omega)]
      split
      · rfl
      · rename_i dl hi
        split
        rename_i p cl s' hstep
        have := hprog' dl _ p cl s' hstep
        rw [dif_pos ⟨by omega, by omega⟩, dif_pos ⟨this, hjN'⟩]
    · have hj : j = N := by omega
      subst hj
      rw [skipSp_at d j j (Nat.le_refl j), if_neg (Nat.lt_irrefl j), if_pos (Nat.le_refl j),
        if_pos (Nat.le_refl j), hflag]
termination_by j - pos

end BlindLedger.X12
