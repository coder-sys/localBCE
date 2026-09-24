import BlindLedger.RowBoundsH0
import BlindLedger.RowBoundsH1
import BlindLedger.RowBoundsH1Outer
import BlindLedger.RowBoundsFS1
import BlindLedger.RowBoundsFS2
import BlindLedger.RowBoundsFS3
import BlindLedger.RowBoundsZero

set_option exponentiation.threshold 4096
set_option maxRecDepth 100000

namespace BlindLedger.SecurityArithmetic

open ExactFrac

theorem row_bounds_simplified (j : Nat) :
    (rowEval j).maximum.le (rowEval j).simplified := by
  change (rowEval j).maximum.le (ExactFrac.add (pow2Frac (102 * j) 512) e3)
  exact row_maximum_le_of_components j (ExactFrac.add (pow2Frac (102 * j) 512) e3)
    (row_h0_bound j) (row_h1_bound j) (row_h1_outer_bound j) (row_fs1_bound j)
    (row_fs2_bound j) (row_fs3_bound j) (row_zero_bound j)

end BlindLedger.SecurityArithmetic
