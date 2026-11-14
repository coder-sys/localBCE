import BlindLedger.Sha3Lanes

/-! `Lanes.permA` is `Quick.perm permSteps`: both are the same 24 written-out rounds (`Quick.perm` two to a step, read
    constants from `rcs`; `Lanes.steps` four to a step, constants from the list), so after unfolding they are the same term. -/
namespace BlindLedger.Semantic
namespace Lanes

open Quick

set_option maxRecDepth 100000 in
theorem permA_eq (a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 a10 a11 a12 a13 a14 a15 a16 a17 a18 a19 a20 a21 a22 a23 a24 : UInt64) :
    permA a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 a10 a11 a12 a13 a14 a15 a16 a17 a18 a19 a20 a21 a22 a23 a24 =
      perm permSteps a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 a10 a11 a12 a13 a14 a15 a16 a17 a18 a19 a20 a21 a22 a23 a24 := rfl

end Lanes
end BlindLedger.Semantic
