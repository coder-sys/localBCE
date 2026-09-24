import BlindLedger.WidthBoundsCaps

set_option exponentiation.threshold 4096
set_option maxRecDepth 100000

namespace BlindLedger.SecurityArithmetic

open ExactFrac

theorem width384_delta_cap_all_k {k : Nat} (hk : k ≤ width384.qEffV3) :
    (widthRowMaximum width384 k).eq e3 := by
  have h0Term :
      (width384.h0Completion.mul (ExactFrac.ofNat k 1 (by decide))).le
        (width384.h0Completion.mul (ExactFrac.ofNat width384.qEffV3 1 (by decide))) := by
    apply exactFrac_mul_ofNat_one_le
    · change 0 ≤ (pow2Frac 1 1439).num
      decide
    · exact hk
  have h1Term : (widthRowH1Vector width384 k).le
      (widthRowH1Vector width384 width384.qEffV3) := by
    apply exactFrac_pow2Frac_le_same_exponent
    omega
  have h1OuterTerm : (widthRowH1Outer width384 k).le
      (widthRowH1Outer width384 width384.qEffV3) := by
    apply exactFrac_pow2Frac_le_same_exponent
    omega
  have hfs1Term : (widthRowFS1 width384 k).le
      (widthRowFS1 width384 width384.qEffV3) := by
    apply exactFrac_add_le_add
    · apply exactFrac_pow2Frac_le_same_exponent
      omega
    · exact exactFrac_le_refl eKOS
  have hfs2Term : (widthRowFS2 width384 k).le
      (widthRowFS2 width384 width384.qEffV3) := by
    apply exactFrac_add_le_add
    · apply exactFrac_pow2Frac_le_same_exponent
      omega
    · exact exactFrac_le_refl e2
  have h0Row : (widthRowH0 width384 k).le
      (widthRowH0 width384 width384.qEffV3) := by
    exact exactFrac_add_le_add (exactFrac_le_refl width384.eLeaf) h0Term
  have h0Cap : (widthRowH0 width384 width384.qEffV3).le e3 := width384_cap_row_terms_le_e3.1
  have h1Cap : (widthRowH1Vector width384 width384.qEffV3).le e3 := width384_cap_row_terms_le_e3.2.1
  have h1OuterCap : (widthRowH1Outer width384 width384.qEffV3).le e3 := width384_cap_row_terms_le_e3.2.2.1
  have hfs1Cap : (widthRowFS1 width384 width384.qEffV3).le e3 := width384_cap_row_terms_le_e3.2.2.2.1
  have hfs2Cap : (widthRowFS2 width384 width384.qEffV3).le e3 := width384_cap_row_terms_le_e3.2.2.2.2.1
  have hzero : zeroFrac.le e3 := by
    decide
  have h0 := exactFrac_le_trans h0Row h0Cap
  have h1 := exactFrac_le_trans h1Term h1Cap
  have h1Outer := exactFrac_le_trans h1OuterTerm h1OuterCap
  have hfs1 := exactFrac_le_trans hfs1Term hfs1Cap
  have hfs2 := exactFrac_le_trans hfs2Term hfs2Cap
  have hfs3 : (widthRowFS3 width384 k).le e3 := by
    change e3.le e3
    exact exactFrac_le_refl e3
  have hmax : (widthRowMaximum width384 k).le e3 := by
    apply maxFrac_le_of_le
    · apply maxFrac_le_of_le
      · apply maxFrac_le_of_le
        · apply maxFrac_le_of_le
          · apply maxFrac_le_of_le
            · exact maxFrac_le_of_le h0 h1
            · exact h1Outer
          · exact hfs1
        · exact hfs2
      · exact hfs3
    · exact hzero
  have hlower : e3.le (widthRowMaximum width384 k) := by
    have hfs3Lower : e3.le (widthRowFS3 width384 k) := by
      change e3.le e3
      exact exactFrac_le_refl e3
    have hE : e3.le (maxFrac
        (maxFrac
          (maxFrac
            (maxFrac
              (maxFrac (widthRowH0 width384 k) (widthRowH1Vector width384 k))
                (widthRowH1Outer width384 k))
            (widthRowFS1 width384 k))
          (widthRowFS2 width384 k))
        (widthRowFS3 width384 k)) :=
      exactFrac_le_trans hfs3Lower maxFrac_ge_right
    exact exactFrac_le_trans hE maxFrac_ge_left
  exact exactFrac_eq_of_le_of_le hmax hlower

theorem width512_delta_cap_all_k {k : Nat} (hk : k ≤ width512.qEffV3) :
    (widthRowMaximum width512 k).eq e3 := by
  have h0Term :
      (width512.h0Completion.mul (ExactFrac.ofNat k 1 (by decide))).le
        (width512.h0Completion.mul (ExactFrac.ofNat width512.qEffV3 1 (by decide))) := by
    apply exactFrac_mul_ofNat_one_le
    · change 0 ≤ (pow2Frac 1 1823).num
      decide
    · exact hk
  have h1Term : (widthRowH1Vector width512 k).le
      (widthRowH1Vector width512 width512.qEffV3) := by
    apply exactFrac_pow2Frac_le_same_exponent
    omega
  have h1OuterTerm : (widthRowH1Outer width512 k).le
      (widthRowH1Outer width512 width512.qEffV3) := by
    apply exactFrac_pow2Frac_le_same_exponent
    omega
  have hfs1Term : (widthRowFS1 width512 k).le
      (widthRowFS1 width512 width512.qEffV3) := by
    apply exactFrac_add_le_add
    · apply exactFrac_pow2Frac_le_same_exponent
      omega
    · exact exactFrac_le_refl eKOS
  have hfs2Term : (widthRowFS2 width512 k).le
      (widthRowFS2 width512 width512.qEffV3) := by
    apply exactFrac_add_le_add
    · apply exactFrac_pow2Frac_le_same_exponent
      omega
    · exact exactFrac_le_refl e2
  have h0Row : (widthRowH0 width512 k).le
      (widthRowH0 width512 width512.qEffV3) := by
    exact exactFrac_add_le_add (exactFrac_le_refl width512.eLeaf) h0Term
  have h0Cap : (widthRowH0 width512 width512.qEffV3).le e3 := width512_cap_row_terms_le_e3.1
  have h1Cap : (widthRowH1Vector width512 width512.qEffV3).le e3 := width512_cap_row_terms_le_e3.2.1
  have h1OuterCap : (widthRowH1Outer width512 width512.qEffV3).le e3 := width512_cap_row_terms_le_e3.2.2.1
  have hfs1Cap : (widthRowFS1 width512 width512.qEffV3).le e3 := width512_cap_row_terms_le_e3.2.2.2.1
  have hfs2Cap : (widthRowFS2 width512 width512.qEffV3).le e3 := width512_cap_row_terms_le_e3.2.2.2.2.1
  have hzero : zeroFrac.le e3 := by
    decide
  have h0 := exactFrac_le_trans h0Row h0Cap
  have h1 := exactFrac_le_trans h1Term h1Cap
  have h1Outer := exactFrac_le_trans h1OuterTerm h1OuterCap
  have hfs1 := exactFrac_le_trans hfs1Term hfs1Cap
  have hfs2 := exactFrac_le_trans hfs2Term hfs2Cap
  have hfs3 : (widthRowFS3 width512 k).le e3 := by
    change e3.le e3
    exact exactFrac_le_refl e3
  have hmax : (widthRowMaximum width512 k).le e3 := by
    apply maxFrac_le_of_le
    · apply maxFrac_le_of_le
      · apply maxFrac_le_of_le
        · apply maxFrac_le_of_le
          · apply maxFrac_le_of_le
            · exact maxFrac_le_of_le h0 h1
            · exact h1Outer
          · exact hfs1
        · exact hfs2
      · exact hfs3
    · exact hzero
  have hlower : e3.le (widthRowMaximum width512 k) := by
    have hfs3Lower : e3.le (widthRowFS3 width512 k) := by
      change e3.le e3
      exact exactFrac_le_refl e3
    have hE : e3.le (maxFrac
        (maxFrac
          (maxFrac
            (maxFrac
              (maxFrac (widthRowH0 width512 k) (widthRowH1Vector width512 k))
                (widthRowH1Outer width512 k))
            (widthRowFS1 width512 k))
          (widthRowFS2 width512 k))
        (widthRowFS3 width512 k)) :=
      exactFrac_le_trans hfs3Lower maxFrac_ge_right
    exact exactFrac_le_trans hE maxFrac_ge_left
  exact exactFrac_eq_of_le_of_le hmax hlower

end BlindLedger.SecurityArithmetic
