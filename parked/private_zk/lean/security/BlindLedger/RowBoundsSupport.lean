import BlindLedger.Arithmetic

set_option exponentiation.threshold 4096
set_option maxRecDepth 100000

namespace BlindLedger.SecurityArithmetic

open ExactFrac

theorem maxFrac_le_of_le {a b c : ExactFrac} (ha : a.le c) (hb : b.le c) :
    (maxFrac a b).le c := by
  unfold maxFrac
  split
  · exact hb
  · exact ha

theorem exactFrac_add_le_add {a b c d : ExactFrac} (hac : a.le c) (hbd : b.le d) :
    (ExactFrac.add a b).le (ExactFrac.add c d) := by
  unfold ExactFrac.le at hac hbd ⊢
  have hbden : (0 : Int) ≤ (b.den : Int) := by omega
  have hdden : (0 : Int) ≤ (d.den : Int) := by omega
  have haden : (0 : Int) ≤ (a.den : Int) := by omega
  have hcden : (0 : Int) ≤ (c.den : Int) := by omega
  have hbd_nonneg : (0 : Int) ≤ (b.den : Int) * (d.den : Int) :=
    Int.mul_nonneg hbden hdden
  have hac_scaled := Int.mul_le_mul_of_nonneg_right hac hbd_nonneg
  have hacd_nonneg : (0 : Int) ≤ (a.den : Int) * (c.den : Int) :=
    Int.mul_nonneg haden hcden
  have hbd_scaled := Int.mul_le_mul_of_nonneg_right hbd hacd_nonneg
  have hsum := Int.add_le_add hac_scaled hbd_scaled
  simpa [ExactFrac.add, Int.add_mul, Int.mul_add, Int.mul_assoc, Int.mul_comm,
    Int.mul_left_comm] using hsum

theorem exactFrac_le_refl (a : ExactFrac) : a.le a := by
  unfold ExactFrac.le
  omega

theorem exactFrac_add_left_mono {a b c : ExactFrac} (h : a.le b) :
    (ExactFrac.add a c).le (ExactFrac.add b c) := by
  exact exactFrac_add_le_add h (exactFrac_le_refl c)

theorem exactFrac_add_right_mono {a b c : ExactFrac} (h : a.le b) :
    (ExactFrac.add c a).le (ExactFrac.add c b) := by
  exact exactFrac_add_le_add (exactFrac_le_refl c) h

theorem zeroFrac_le_of_nonnegative {a : ExactFrac} (h : 0 ≤ a.num) :
    zeroFrac.le a := by
  simpa [zeroFrac, ExactFrac.le, ExactFrac.ofNat] using h

theorem exactFrac_le_add_zero_right (a : ExactFrac) :
    a.le (ExactFrac.add a zeroFrac) := by
  simp [ExactFrac.le, ExactFrac.add, zeroFrac, ExactFrac.ofNat,
    Int.mul_comm]

theorem exactFrac_le_trans {a b c : ExactFrac} (hab : a.le b) (hbc : b.le c) :
    a.le c := by
  unfold ExactFrac.le at hab hbc ⊢
  have hcbden : (0 : Int) ≤ (c.den : Int) := by omega
  have habden : (0 : Int) ≤ (a.den : Int) := by omega
  have hfirst : (a.num * b.den) * c.den ≤ (b.num * a.den) * c.den :=
    Int.mul_le_mul_of_nonneg_right hab hcbden
  have hsecond : (b.num * c.den) * a.den ≤ (c.num * b.den) * a.den :=
    Int.mul_le_mul_of_nonneg_right hbc habden
  have hmiddle : (a.num * c.den) * b.den ≤ (c.num * a.den) * b.den := by
    calc
      (a.num * c.den) * b.den = (a.num * b.den) * c.den := by
        simp [Int.mul_assoc, Int.mul_comm, Int.mul_left_comm]
      _ ≤ (b.num * a.den) * c.den := hfirst
      _ = (b.num * c.den) * a.den := by
        simp [Int.mul_assoc, Int.mul_comm, Int.mul_left_comm]
      _ ≤ (c.num * b.den) * a.den := hsecond
      _ = (c.num * a.den) * b.den := by
        simp [Int.mul_assoc, Int.mul_comm, Int.mul_left_comm]
  exact Int.le_of_mul_le_mul_right hmiddle (by exact_mod_cast b.den_pos)

theorem exactFrac_le_add_right_of_nonnegative {a c : ExactFrac}
    (hc : 0 ≤ c.num) : a.le (ExactFrac.add a c) := by
  exact exactFrac_le_trans (exactFrac_le_add_zero_right a)
    (exactFrac_add_right_mono (c := a) (zeroFrac_le_of_nonnegative hc))

theorem exactFrac_eq_of_le_of_le {a b : ExactFrac} (hab : a.le b) (hba : b.le a) :
    a.eq b := by
  unfold ExactFrac.le at hab hba
  unfold ExactFrac.eq
  omega

theorem exactFrac_pow2Frac_le_of_cross {a b e f : Nat}
    (h : a * pow2 f ≤ b * pow2 e) :
    (pow2Frac a e).le (pow2Frac b f) := by
  change (a : Int) * (pow2 f : Int) ≤ (b : Int) * (pow2 e : Int)
  exact_mod_cast h

theorem exactFrac_pow2Frac_le_same_exponent {a b e : Nat} (h : a ≤ b) :
    (pow2Frac a e).le (pow2Frac b e) := by
  apply exactFrac_pow2Frac_le_of_cross
  exact Nat.mul_le_mul_right _ h

theorem exactFrac_mul_ofNat_one_le {a : ExactFrac} {k n : Nat}
    (ha : 0 ≤ a.num) (hkn : k ≤ n) :
    (a.mul (ExactFrac.ofNat k 1 (by decide))).le
      (a.mul (ExactFrac.ofNat n 1 (by decide))) := by
  unfold ExactFrac.le ExactFrac.mul ExactFrac.ofNat
  have hknInt : (k : Int) ≤ (n : Int) := by exact_mod_cast hkn
  have hnum : a.num * (k : Int) ≤ a.num * (n : Int) :=
    Int.mul_le_mul_of_nonneg_left hknInt ha
  have hden : (0 : Int) ≤ (a.den : Int) := by omega
  have hscaled := Int.mul_le_mul_of_nonneg_right hnum hden
  simpa [ExactFrac.ofNat, ExactFrac.mul, Int.mul_assoc, Int.mul_comm,
    Int.mul_left_comm] using hscaled

theorem maxFrac_ge_left {a b : ExactFrac} : a.le (maxFrac a b) := by
  unfold maxFrac
  split
  · assumption
  · exact exactFrac_le_refl a

theorem maxFrac_ge_right {a b : ExactFrac} : b.le (maxFrac a b) := by
  unfold maxFrac
  split
  · exact exactFrac_le_refl b
  · rename_i h
    unfold ExactFrac.le at h ⊢
    omega

theorem maxFrac_append_right {a b c : ExactFrac} (h : a.le b) :
    a.le (maxFrac b c) := by
  exact exactFrac_le_trans h (maxFrac_ge_left (a := b) (b := c))

theorem row_maximum_le_of_components (j : Nat) (bound : ExactFrac)
    (h0 : (ExactFrac.add (pow2Frac j 768) e0).le bound)
    (h1 : (pow2Frac (34 * j) 512).le bound)
    (h1Outer : (pow2Frac (2 * j) 512).le bound)
    (hfs1 : (ExactFrac.add (pow2Frac (2 * j) 2112) eKOS).le bound)
    (hfs2 : (ExactFrac.add (pow2Frac (2 * j) 832) e2).le bound)
    (hfs3 : e3.le bound)
    (hzero : zeroFrac.le bound) :
    (rowEval j).maximum.le bound := by
  simp only [rowEval]
  exact maxFrac_le_of_le
    (maxFrac_le_of_le
      (maxFrac_le_of_le
        (maxFrac_le_of_le
          (maxFrac_le_of_le
            (maxFrac_le_of_le h0 h1)
            h1Outer)
          hfs1)
        hfs2)
      hfs3)
    hzero

theorem row_h0_le_max (j : Nat) :
    (ExactFrac.add (pow2Frac j 768) e0).le (rowEval j).maximum := by
  simp only [rowEval]
  have h01 : (ExactFrac.add (pow2Frac j 768) e0).le
      (maxFrac (ExactFrac.add (pow2Frac j 768) e0) (pow2Frac (34 * j) 512)) :=
    maxFrac_ge_left
  have h012 : (ExactFrac.add (pow2Frac j 768) e0).le
      (maxFrac
        (maxFrac (ExactFrac.add (pow2Frac j 768) e0) (pow2Frac (34 * j) 512))
        (pow2Frac (2 * j) 512)) := maxFrac_append_right h01
  have h0123 : (ExactFrac.add (pow2Frac j 768) e0).le
      (maxFrac
        (maxFrac
          (maxFrac (ExactFrac.add (pow2Frac j 768) e0) (pow2Frac (34 * j) 512))
            (pow2Frac (2 * j) 512))
        (ExactFrac.add (pow2Frac (2 * j) 2112) eKOS)) := maxFrac_append_right h012
  have h01234 : (ExactFrac.add (pow2Frac j 768) e0).le
      (maxFrac
        (maxFrac
          (maxFrac
            (maxFrac (ExactFrac.add (pow2Frac j 768) e0) (pow2Frac (34 * j) 512))
              (pow2Frac (2 * j) 512))
            (ExactFrac.add (pow2Frac (2 * j) 2112) eKOS))
        (ExactFrac.add (pow2Frac (2 * j) 832) e2)) := maxFrac_append_right h0123
  have h012345 : (ExactFrac.add (pow2Frac j 768) e0).le
      (maxFrac
        (maxFrac
          (maxFrac
            (maxFrac
              (maxFrac (ExactFrac.add (pow2Frac j 768) e0) (pow2Frac (34 * j) 512))
                (pow2Frac (2 * j) 512))
            (ExactFrac.add (pow2Frac (2 * j) 2112) eKOS))
          (ExactFrac.add (pow2Frac (2 * j) 832) e2))
        e3) := maxFrac_append_right h01234
  exact maxFrac_append_right h012345

theorem row_fs1_le_max (j : Nat) :
    (ExactFrac.add (pow2Frac (2 * j) 2112) eKOS).le (rowEval j).maximum := by
  simp only [rowEval]
  have hbase : (ExactFrac.add (pow2Frac (2 * j) 2112) eKOS).le
      (maxFrac
        (maxFrac
          (maxFrac (ExactFrac.add (pow2Frac j 768) e0) (pow2Frac (34 * j) 512))
            (pow2Frac (2 * j) 512))
        (ExactFrac.add (pow2Frac (2 * j) 2112) eKOS)) := maxFrac_ge_right
  have hfs12 : (ExactFrac.add (pow2Frac (2 * j) 2112) eKOS).le
      (maxFrac
        (maxFrac
          (maxFrac
            (maxFrac (ExactFrac.add (pow2Frac j 768) e0) (pow2Frac (34 * j) 512))
              (pow2Frac (2 * j) 512))
            (ExactFrac.add (pow2Frac (2 * j) 2112) eKOS))
        (ExactFrac.add (pow2Frac (2 * j) 832) e2)) := maxFrac_append_right hbase
  have hfs123 : (ExactFrac.add (pow2Frac (2 * j) 2112) eKOS).le
      (maxFrac
        (maxFrac
          (maxFrac
            (maxFrac
              (maxFrac (ExactFrac.add (pow2Frac j 768) e0) (pow2Frac (34 * j) 512))
                (pow2Frac (2 * j) 512))
            (ExactFrac.add (pow2Frac (2 * j) 2112) eKOS))
          (ExactFrac.add (pow2Frac (2 * j) 832) e2))
        e3) := maxFrac_append_right hfs12
  exact maxFrac_append_right hfs123

theorem row_fs2_le_max (j : Nat) :
    (ExactFrac.add (pow2Frac (2 * j) 832) e2).le (rowEval j).maximum := by
  simp only [rowEval]
  have hbase : (ExactFrac.add (pow2Frac (2 * j) 832) e2).le
      (maxFrac
        (maxFrac
          (maxFrac
            (maxFrac (ExactFrac.add (pow2Frac j 768) e0) (pow2Frac (34 * j) 512))
              (pow2Frac (2 * j) 512))
            (ExactFrac.add (pow2Frac (2 * j) 2112) eKOS))
        (ExactFrac.add (pow2Frac (2 * j) 832) e2)) := maxFrac_ge_right
  have hfs2e3 : (ExactFrac.add (pow2Frac (2 * j) 832) e2).le
      (maxFrac
        (maxFrac
          (maxFrac
            (maxFrac
              (maxFrac (ExactFrac.add (pow2Frac j 768) e0) (pow2Frac (34 * j) 512))
                (pow2Frac (2 * j) 512))
            (ExactFrac.add (pow2Frac (2 * j) 2112) eKOS))
          (ExactFrac.add (pow2Frac (2 * j) 832) e2))
        e3) := maxFrac_append_right hbase
  exact maxFrac_append_right hfs2e3

theorem exactFrac_le_of_eq {a b : ExactFrac} (h : a.eq b) : a.le b := by
  unfold ExactFrac.eq at h
  unfold ExactFrac.le
  omega

theorem exactFrac_le_add_zero_left (a : ExactFrac) :
    a.le (ExactFrac.add zeroFrac a) := by
  simp [ExactFrac.le, ExactFrac.add, zeroFrac, ExactFrac.ofNat,
    Int.mul_comm]

theorem zeroFrac_le_e3 : zeroFrac.le e3 := by
  decide

theorem e0_le_e3 : e0.le e3 := by
  have hzero : e0.le (ExactFrac.add (pow2Frac 0 768) e0) := by
    simp [ExactFrac.le, ExactFrac.add, ExactFrac.pow2Frac, ExactFrac.ofNat,
      Int.mul_comm, Int.mul_left_comm]
  exact exactFrac_le_trans hzero
    (exactFrac_le_trans (row_h0_le_max 0) (exactFrac_le_of_eq row_bounds_zero_max_e3))

theorem eKOS_le_e3 : eKOS.le e3 := by
  have hzero : eKOS.le (ExactFrac.add (pow2Frac 0 2112) eKOS) := by
    simp [ExactFrac.le, ExactFrac.add, ExactFrac.pow2Frac, ExactFrac.ofNat,
      Int.mul_comm, Int.mul_left_comm]
  exact exactFrac_le_trans hzero
    (exactFrac_le_trans (row_fs1_le_max 0) (exactFrac_le_of_eq row_bounds_zero_max_e3))

theorem e2_le_e3 : e2.le e3 := by
  have hzero : e2.le (ExactFrac.add (pow2Frac 0 832) e2) := by
    simp [ExactFrac.le, ExactFrac.add, ExactFrac.pow2Frac, ExactFrac.ofNat,
      Int.mul_comm, Int.mul_left_comm]
  exact exactFrac_le_trans hzero
    (exactFrac_le_trans (row_fs2_le_max 0) (exactFrac_le_of_eq row_bounds_zero_max_e3))

end BlindLedger.SecurityArithmetic
