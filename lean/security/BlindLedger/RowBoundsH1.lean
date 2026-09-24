import BlindLedger.RowBoundsTerms

set_option exponentiation.threshold 4096
set_option maxRecDepth 100000

namespace BlindLedger.SecurityArithmetic

open ExactFrac

theorem row_h1_bound (j : Nat) :
    (pow2Frac (34 * j) 512).le
      (ExactFrac.add (pow2Frac (102 * j) 512) e3) := by
  exact exactFrac_le_trans (row_h1_term j)
    (exactFrac_le_add_right_of_nonnegative (a := pow2Frac (102 * j) 512)
      (c := e3) (by decide))

end BlindLedger.SecurityArithmetic
