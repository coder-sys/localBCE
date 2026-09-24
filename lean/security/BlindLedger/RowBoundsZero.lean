import BlindLedger.RowBoundsFS3

set_option exponentiation.threshold 4096
set_option maxRecDepth 100000

namespace BlindLedger.SecurityArithmetic

open ExactFrac

theorem row_zero_bound (j : Nat) :
    zeroFrac.le (ExactFrac.add (pow2Frac (102 * j) 512) e3) := by
  exact exactFrac_le_trans zeroFrac_le_e3 (row_fs3_bound j)

end BlindLedger.SecurityArithmetic
