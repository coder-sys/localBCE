import BlindLedger.RowBoundsTerms

set_option exponentiation.threshold 4096
set_option maxRecDepth 100000

namespace BlindLedger.SecurityArithmetic

open ExactFrac

theorem row_fs2_bound (j : Nat) :
    (ExactFrac.add (pow2Frac (2 * j) 832) e2).le
      (ExactFrac.add (pow2Frac (102 * j) 512) e3) := by
  exact exactFrac_le_trans
    (exactFrac_add_left_mono (c := e2) (row_fs2_term j))
    (exactFrac_add_right_mono (c := pow2Frac (102 * j) 512) e2_le_e3)

end BlindLedger.SecurityArithmetic
