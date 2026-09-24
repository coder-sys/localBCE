import BlindLedger.RowBoundsTerms

set_option exponentiation.threshold 4096
set_option maxRecDepth 100000

namespace BlindLedger.SecurityArithmetic

open ExactFrac

theorem row_fs3_bound (j : Nat) :
    e3.le (ExactFrac.add (pow2Frac (102 * j) 512) e3) := by
  exact exactFrac_le_trans (exactFrac_le_add_zero_left e3)
    (exactFrac_add_left_mono (c := e3) (row_zero_term j))

end BlindLedger.SecurityArithmetic
