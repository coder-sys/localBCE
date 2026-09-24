import BlindLedger.RowBoundsTerms

set_option exponentiation.threshold 4096
set_option maxRecDepth 100000

namespace BlindLedger.SecurityArithmetic

open ExactFrac

theorem row_h0_bound (j : Nat) :
    (ExactFrac.add (pow2Frac j 768) e0).le
      (ExactFrac.add (pow2Frac (102 * j) 512) e3) := by
  exact exactFrac_le_trans
    (exactFrac_add_left_mono (c := e0) (row_h0_term j))
    (exactFrac_add_right_mono (c := pow2Frac (102 * j) 512) e0_le_e3)

end BlindLedger.SecurityArithmetic
