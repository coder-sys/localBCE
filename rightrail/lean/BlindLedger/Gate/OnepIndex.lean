import BlindLedger.Gate.Rules.FastEq

/-! The history index's byte codec and its capped decision: minimal LEB128 (`leb`, `unleb`) and `capD`, the decision a
    row gets when a key it reads is cut short (HOLD with `POSTING_CAP`, fail closed).  The index itself is `Flat/`. -/

namespace BlindLedger.Gate.OnepIndex

open BlindLedger.Gate BlindLedger.Gate.Rules

def leb (n : Nat) : Bytes :=
  if h : n < 128 then [n.toUInt8] else (n % 128 + 128).toUInt8 :: leb (n / 128)
termination_by n
decreasing_by omega

/-- Refuses a non-minimal encoding (a final 0x00 group after a continuation byte). -/
def unleb : Bytes → Option (Nat × Bytes)
  | [] => none
  | b :: r =>
    if b < 128 then some (b.toNat, r) else
    match unleb r with
    | some (n, r') => if n = 0 then none else some ((b - 128).toNat + 128 * n, r')
    | none => none



/-- Adds `POSTING_CAP` in `reasons` order and recomputes the outcome: HOLD (`posting_cap_hold`). -/
def capD (d : Decision) : Decision :=
  let rs := reasons.filter fun r => r == .POSTING_CAP || d.reasons.contains r
  { d with outcome := outcomeOf rs, reasons := rs }

theorem unleb_leb (n : Nat) (r : Bytes) : unleb (leb n ++ r) = some (n, r) := by
  induction n using Nat.strongRecOn with
  | _ n ih =>
    by_cases h : n < 128
    · rw [leb, dif_pos h]
      have h1 : (n.toUInt8).toNat = n := by simp; omega
      have h2 : n.toUInt8 < 128 := by rw [UInt8.lt_iff_toNat_lt]; simp [UInt8.toNat_ofNat]; omega
      simp [unleb, h2, h1]
    · rw [leb, dif_neg h]
      have h1 : ((n % 128 + 128).toUInt8).toNat = n % 128 + 128 := by
        simp [UInt8.toNat_ofNat]; omega
      have h2 : ¬ ((n % 128 + 128).toUInt8 < 128) := by
        rw [UInt8.lt_iff_toNat_lt]; simp [UInt8.toNat_ofNat]; omega
      have h3 := ih (n / 128) (by omega)
      have h4 : ((n % 128 + 128).toUInt8 - 128).toNat = n % 128 := by
        have c128 : (128 : UInt8).toNat = 128 := rfl
        have hle : (128 : UInt8) ≤ (n % 128 + 128).toUInt8 := by
          rw [UInt8.le_iff_toNat_le]; omega
        rw [UInt8.toNat_sub_of_le _ _ hle]; omega
      simp only [List.cons_append, unleb, h2, if_false, h3]
      have h5 : n / 128 ≠ 0 := by omega
      simp [h5]
      omega

theorem capD_rel (d : Decision) :
    (capD d).outcome = .HOLD ∧ Reason.POSTING_CAP ∈ (capD d).reasons := by
  have hm : Reason.POSTING_CAP ∈ reasons.filter fun r => r == Reason.POSTING_CAP || d.reasons.contains r :=
    List.mem_filter.2 ⟨by simp [reasons], by simp⟩
  exact ⟨posting_cap_hold hm, hm⟩

end BlindLedger.Gate.OnepIndex
