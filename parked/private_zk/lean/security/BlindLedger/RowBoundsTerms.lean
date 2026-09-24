import BlindLedger.RowBoundsSupport

set_option exponentiation.threshold 4096
set_option maxRecDepth 100000

namespace BlindLedger.SecurityArithmetic

open ExactFrac

theorem row_h0_term (j : Nat) :
    (pow2Frac j 768).le (pow2Frac (102 * j) 512) := by
  apply exactFrac_pow2Frac_le_of_cross
  have hpow : pow2 512 ≤ pow2 768 := by decide
  calc
    j * pow2 512 ≤ j * pow2 768 := Nat.mul_le_mul_left _ hpow
    _ ≤ (102 * j) * pow2 768 := by
      apply Nat.mul_le_mul_right
      omega

theorem row_h1_term (j : Nat) :
    (pow2Frac (34 * j) 512).le (pow2Frac (102 * j) 512) := by
  apply exactFrac_pow2Frac_le_of_cross
  apply Nat.mul_le_mul_right
  omega

theorem row_h1_outer_term (j : Nat) :
    (pow2Frac (2 * j) 512).le (pow2Frac (102 * j) 512) := by
  apply exactFrac_pow2Frac_le_of_cross
  apply Nat.mul_le_mul_right
  omega

theorem row_fs1_term (j : Nat) :
    (pow2Frac (2 * j) 2112).le (pow2Frac (102 * j) 512) := by
  apply exactFrac_pow2Frac_le_of_cross
  have hpow : pow2 512 ≤ pow2 2112 := by decide
  calc
    (2 * j) * pow2 512 ≤ (102 * j) * pow2 512 := by
      apply Nat.mul_le_mul_right
      omega
    _ ≤ (102 * j) * pow2 2112 := Nat.mul_le_mul_left _ hpow

theorem row_fs2_term (j : Nat) :
    (pow2Frac (2 * j) 832).le (pow2Frac (102 * j) 512) := by
  apply exactFrac_pow2Frac_le_of_cross
  have hpow : pow2 512 ≤ pow2 832 := by decide
  calc
    (2 * j) * pow2 512 ≤ (102 * j) * pow2 512 := by
      apply Nat.mul_le_mul_right
      omega
    _ ≤ (102 * j) * pow2 832 := Nat.mul_le_mul_left _ hpow

theorem row_zero_term (j : Nat) :
    zeroFrac.le (pow2Frac (102 * j) 512) := by
  simp [zeroFrac, ExactFrac.le, ExactFrac.pow2Frac, ExactFrac.ofNat,
    Int.mul_comm, Int.mul_left_comm] <;> omega

end BlindLedger.SecurityArithmetic
