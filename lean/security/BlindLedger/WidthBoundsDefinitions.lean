import BlindLedger.RowBounds

set_option exponentiation.threshold 4096
set_option maxRecDepth 100000

namespace BlindLedger.SecurityArithmetic

open ExactFrac

def widthRowH0 (w : WidthEval) (k : Nat) : ExactFrac :=
  ExactFrac.add w.eLeaf (ExactFrac.mul w.h0Completion (ExactFrac.ofNat k 1 (by decide)))

def widthRowH1Vector (_w : WidthEval) (k : Nat) : ExactFrac :=
  pow2Frac (34 * k) 512

def widthRowH1Outer (_w : WidthEval) (k : Nat) : ExactFrac :=
  pow2Frac (2 * k) 512

def widthRowFS1 (_w : WidthEval) (k : Nat) : ExactFrac :=
  ExactFrac.add (pow2Frac (2 * k) 2112) eKOS

def widthRowFS2 (_w : WidthEval) (k : Nat) : ExactFrac :=
  ExactFrac.add (pow2Frac (2 * k) 832) e2

def widthRowFS3 (w : WidthEval) (_k : Nat) : ExactFrac := w.fs3Bound

def widthRowMaximum (w : WidthEval) (k : Nat) : ExactFrac :=
  maxFrac
    (maxFrac
      (maxFrac
        (maxFrac
          (maxFrac
            (maxFrac (widthRowH0 w k) (widthRowH1Vector w k))
              (widthRowH1Outer w k))
          (widthRowFS1 w k))
        (widthRowFS2 w k))
      (widthRowFS3 w k))
    zeroFrac

end BlindLedger.SecurityArithmetic
