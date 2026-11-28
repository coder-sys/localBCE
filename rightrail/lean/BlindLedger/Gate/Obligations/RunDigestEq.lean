import BlindLedger.Gate.Obligations.RunDigest
import BlindLedger.Gate.Engine3.Sha3Range
import BlindLedger.Gate.Flat.Bin

namespace BlindLedger.Gate.Obligations

open BlindLedger.Gate.FactCodec

/-! ## The program's digests are the model's -/

open BlindLedger.Gate.Flat.Bin (toList_eq')

/-- The records `s` to `s + t` of a log whose record `k` is the bytes `k - o` of `b` (`o ≤ s`), side by side, are the
    bytes of `b` between. -/
theorem flatMap_rec {rec : Nat → Option Bytes} {b : ByteArray} {o : Nat} :
    ∀ (t s : Nat), o ≤ s → (s - o + t) * recBytes ≤ b.size →
      (∀ k, s ≤ k → k < s + t → rec k = some (b.extract ((k - o) * recBytes) ((k - o + 1) * recBytes)).toList) →
      (List.range' s t).flatMap (fun k => (rec k).getD []) =
        (b.extract ((s - o) * recBytes) ((s - o + t) * recBytes)).toList := by
  intro t
  induction t with
  | zero =>
    intro s ho hb hr
    simp [ByteArray.extract_same, toList_eq']
  | succ t ih =>
    intro s ho hb hr
    rw [List.range'_succ, List.flatMap_cons, hr s (Nat.le_refl _) (by omega), Option.getD_some]
    have h1 := ih (s + 1) (by omega) (by rw [show s + 1 - o + t = s - o + (t + 1) by omega]; exact hb)
      (fun k hk hk' => hr k (by omega) (by omega))
    rw [h1, show s + 1 - o = s - o + 1 by omega]
    have e1 : min ((s - o) * recBytes) ((s - o + 1) * recBytes) = (s - o) * recBytes :=
      Nat.min_eq_left (Nat.mul_le_mul_right _ (by omega))
    have e2 : max ((s - o + 1) * recBytes) ((s - o + 1 + t) * recBytes) = (s - o + (t + 1)) * recBytes := by
      rw [Nat.max_eq_right (Nat.mul_le_mul_right _ (by omega))]
      congr 1
      omega
    simp only [toList_eq']
    rw [← ByteArray.toList_data_append, ByteArray.extract_append_extract, e1, e2]

theorem spanDig_congr {rec rec' : Nat → Option Bytes} {s i : Nat} {prev : Bytes}
    (h : ∀ k, s ≤ k → k < i → rec' k = rec k) : spanDig rec' s prev i = spanDig rec s prev i := by
  have : (List.range' s (i - s)).flatMap (fun k => (rec' k).getD []) =
      (List.range' s (i - s)).flatMap (fun k => (rec k).getD []) := by
    have hm : (List.range' s (i - s)).map (fun k => (rec' k).getD []) =
        (List.range' s (i - s)).map (fun k => (rec k).getD []) := by
      apply List.map_congr_left
      intro k hk
      rw [List.mem_range'_1] at hk
      rw [h k hk.1 (by omega)]
    simp only [List.flatMap, hm]
  unfold spanDig
  rw [this]

/-- The bytes a digest is taken over, as the model has them: a header and the records. -/
theorem hdr_append (L : Bytes) (x : ByteArray) : (⟨L.toArray⟩ : ByteArray) ++ x = ⟨(L ++ x.toList).toArray⟩ := by
  apply ByteArray.ext
  simp [toList_eq']

/-- `digOf` is `spanDig` of the records of `b`. -/
theorem digOf_eq {b : ByteArray} {n s i : Nat} {prev : Bytes} (hs : s ≤ i) (hi : i ≤ n) (hb : n * recBytes ≤ b.size) :
    digOf b s prev i = spanDig (recOf b n) s prev i := by
  have hlen : (s + (i - s)) * recBytes ≤ b.size :=
    Nat.le_trans (Nat.mul_le_mul_right _ (by omega)) hb
  have hm := flatMap_rec (rec := recOf b n) (b := b) (o := 0) (i - s) s (by omega) (by simpa using hlen)
    (fun k hk hk' => by simp [recOf, show k < n by omega])
  unfold digOf spanDig H digHdr
  rw [BlindLedger.Gate.Engine3.sha3_512Into_eq _ _ _ _ _ (by rw [← Nat.add_mul]; exact hlen), hm]
  simp only [Nat.sub_zero, ByteArray.empty_append, hdr_append, List.append_assoc]
  rw [← Nat.add_mul, show s + (i - s) = s + (i - s) from rfl]


/-- `digAt` is `spanDig` of the records of `recAt`: the log of `base` records of `old` and `m` of `tail`. -/
theorem digAt_eq {old tail : ByteArray} {base m s i : Nat} {prev : Bytes} (hs : s ≤ i) (hi : i ≤ base + m)
    (ho : base * recBytes ≤ old.size) (ht : m * recBytes ≤ tail.size) :
    digAt old tail base s prev i = spanDig (recAt old tail base m) s prev i := by
  unfold digAt
  split
  · rename_i hb
    have hlen : (s - base + (i - s)) * recBytes ≤ tail.size := Nat.le_trans (Nat.mul_le_mul_right _ (by omega)) ht
    have hm := flatMap_rec (rec := recAt old tail base m) (b := tail) (o := base) (i - s) s hb hlen
      (fun k hk hk' => by simp [recAt, recOf, show ¬ k < base by omega, show k - base < m by omega])
    unfold spanDig H digHdr
    rw [BlindLedger.Gate.Engine3.sha3_512Into_eq _ _ _ _ _ (by rw [← Nat.add_mul]; exact hlen), hm]
    simp only [ByteArray.empty_append, hdr_append, List.append_assoc, ← Nat.add_mul]
  · split
    · rename_i hb hib
      rw [digOf_eq hs hib ho]
      apply spanDig_congr
      intro k hk hk'
      simp [recAt, show k < base by omega]
    · rename_i hb hib
      have hr : List.range' s (i - s) = List.range' s (base - s) ++ List.range' base (i - base) := by
        have := List.range'_append_1 (s := s) (m := base - s) (n := i - base)
        rw [show s + (base - s) = base by omega, show base - s + (i - base) = i - s by omega] at this
        exact this.symm
      have h1 := flatMap_rec (rec := recAt old tail base m) (b := old) (o := 0) (base - s) s (by omega)
        (Nat.le_trans (Nat.mul_le_mul_right _ (by omega)) ho)
        (fun k hk hk' => by simp [recAt, recOf, show k < base by omega])
      have h2 := flatMap_rec (rec := recAt old tail base m) (b := tail) (o := base) (i - base) base (Nat.le_refl _)
        (Nat.le_trans (Nat.mul_le_mul_right _ (by omega)) ht)
        (fun k hk hk' => by simp [recAt, recOf, show ¬ k < base by omega, show k - base < m by omega])
      unfold spanDig H digHdr
      rw [hr, List.flatMap_append, h1, h2, BlindLedger.Gate.Engine3.sha3_512Into_eq _ _ _ _ _
        (Nat.le_trans (by omega) (Nat.le_trans (Nat.mul_le_mul_right _ (show i - base ≤ m by omega)) ht))]
      simp only [ByteArray.empty_append, hdr_append, List.append_assoc, Nat.sub_zero, Nat.sub_self, Nat.zero_add, Nat.zero_mul,
        show s + (base - s) = base by omega]

end BlindLedger.Gate.Obligations
