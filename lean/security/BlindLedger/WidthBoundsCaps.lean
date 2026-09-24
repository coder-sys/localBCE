import BlindLedger.WidthBoundsDefinitions

set_option exponentiation.threshold 4096
set_option maxRecDepth 100000

namespace BlindLedger.SecurityArithmetic

theorem width384_cap_row_terms_le_e3 :
    (widthRowH0 width384 width384.qEffV3).le e3 ∧
    (widthRowH1Vector width384 width384.qEffV3).le e3 ∧
    (widthRowH1Outer width384 width384.qEffV3).le e3 ∧
    (widthRowFS1 width384 width384.qEffV3).le e3 ∧
    (widthRowFS2 width384 width384.qEffV3).le e3 ∧
    (widthRowFS3 width384 width384.qEffV3).eq e3 := by
  decide

theorem width512_cap_row_terms_le_e3 :
    (widthRowH0 width512 width512.qEffV3).le e3 ∧
    (widthRowH1Vector width512 width512.qEffV3).le e3 ∧
    (widthRowH1Outer width512 width512.qEffV3).le e3 ∧
    (widthRowFS1 width512 width512.qEffV3).le e3 ∧
    (widthRowFS2 width512 width512.qEffV3).le e3 ∧
    (widthRowFS3 width512 width512.qEffV3).eq e3 := by
  decide

end BlindLedger.SecurityArithmetic
