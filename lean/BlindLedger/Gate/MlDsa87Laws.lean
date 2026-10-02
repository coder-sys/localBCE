import BlindLedger.Gate.MlDsa87
import BlindLedger.Sha3

/-! Laws of the bounded ML-DSA-87 samplers (lean-partials-v1, section 2.2).  Not in any executable's closure. -/
namespace BlindLedger.Gate.MlDsa87

open BlindLedger.Semantic

private theorem get!_append_left {s t : ByteArray} {i : Nat} (h : i < s.size) : (s ++ t).get! i = s.get! i := by
  have h' : i < (s ++ t).size := by rw [ByteArray.size_append]; omega
  show (s ++ t).data[i]! = s.data[i]!
  rw [getElem!_pos (s ++ t).data i (by simpa using h'), getElem!_pos s.data i (by simpa using h)]
  exact ByteArray.getElem_append_left h

theorem rejNttFrom_size {s : ByteArray} {a : Poly} (h : rejNttFrom s = some a) : a.size = 256 := by
  by_cases hc : (rejScan s 0 #[]).size = 256 <;> simp [rejNttFrom, hc] at h
  subst h; exact hc

private theorem rejScan_append (t : ByteArray) {s : ByteArray} {p : Nat} {out : Array Nat}
    (h : (rejScan s p out).size = 256) : rejScan (s ++ t) p out = rejScan s p out := by
  revert h
  fun_induction rejScan s p out
  · rename_i p out hc z ih
    intro hs
    have e0 := get!_append_left (s := s) (t := t) (i := p) (by omega)
    have e1 := get!_append_left (s := s) (t := t) (i := p + 1) (by omega)
    have e2 := get!_append_left (s := s) (t := t) (i := p + 2) (by omega)
    rw [rejScan, dif_pos ⟨hc.1, by rw [ByteArray.size_append]; omega⟩]
    simp only [e0, e1, e2]
    exact ih hs
  · rename_i p out hc
    intro hs
    rw [rejScan, dif_neg (fun h => by rw [ByteArray.size_append] at h; omega)]

theorem rejNttFrom_append {s t : ByteArray} {a : Poly} (h : rejNttFrom s = some a) : rejNttFrom (s ++ t) = some a := by
  have hs := rejNttFrom_size h
  by_cases hc : (rejScan s 0 #[]).size = 256 <;> simp [rejNttFrom, hc] at h
  subst h
  simp [rejNttFrom, rejScan_append t hc, hc]
/-- `sampleInBallFrom`'s loop body, spelled out so the loop can be reasoned about over any list of indices. -/
private def sibStep (s : ByteArray) (i : Nat) (st : Array Nat × Nat) : Option (ForInStep (Array Nat × Nat)) := do
  let x ← drawAtMost s i st.snd
  pure (ForInStep.yield ((st.fst.set! i st.fst[x.fst]!).set! x.fst (if bitAt s (i + tau - 256) = 0 then 1 else q - 1), x.snd))

private theorem sib_eq (s : ByteArray) : sampleInBallFrom s =
    (do let r ← forIn (List.range' (256 - tau) 60 1) (Array.replicate 256 0, 8) (sibStep s); pure r.fst) := by
  simp only [sampleInBallFrom, Std.Legacy.Range.forIn_eq_forIn_range']
  rfl

private theorem sib_loop_size (s : ByteArray) : ∀ (l : List Nat) (c : Array Nat) (p : Nat) (r : Array Nat × Nat),
    c.size = 256 → forIn l (c, p) (sibStep s) = some r → r.fst.size = 256 := by
  intro l
  induction l with
  | nil => intro c p r hc h; simp at h; subst h; exact hc
  | cons a l ih =>
    intro c p r hc h
    simp only [List.forIn_cons, sibStep] at h
    cases hd : drawAtMost s a p with
    | none => simp [hd] at h
    | some x =>
      simp only [hd, bind_pure_comp] at h
      exact ih _ _ r (by simp [hc]) h

theorem sampleInBallFrom_size {s : ByteArray} {c : Poly} (h : sampleInBallFrom s = some c) : c.size = 256 := by
  rw [sib_eq] at h
  cases hl : forIn (List.range' (256 - tau) 60 1) (Array.replicate 256 0, 8) (sibStep s) with
  | none => simp [hl] at h
  | some r =>
    simp [hl] at h
    subst h
    exact sib_loop_size s _ _ _ _ (by simp) hl

private theorem drawAtMost_append (t : ByteArray) {s : ByteArray} {i p : Nat} {x : Nat × Nat}
    (h : drawAtMost s i p = some x) : p < s.size ∧ p < x.2 ∧ drawAtMost (s ++ t) i p = some x := by
  revert h
  fun_induction drawAtMost s i p
  · rename_i p h1 h2
    intro hh
    cases hh
    refine ⟨h1, Nat.lt_succ_self _, ?_⟩
    rw [drawAtMost, dif_pos (by rw [ByteArray.size_append]; omega), get!_append_left h1, if_pos h2]
  · rename_i p h1 h2 ih
    intro hh
    obtain ⟨_, _, h3⟩ := ih hh
    refine ⟨h1, by omega, ?_⟩
    rw [drawAtMost, dif_pos (by rw [ByteArray.size_append]; omega), get!_append_left h1, if_neg h2]
    exact h3
  · intro hh
    cases hh

private theorem sib_loop_append (s t : ByteArray) : ∀ (l : List Nat) (c : Array Nat) (p : Nat) (r : Array Nat × Nat),
    8 ≤ p → (∀ a ∈ l, a < 256) → forIn l (c, p) (sibStep s) = some r → forIn l (c, p) (sibStep (s ++ t)) = some r := by
  intro l
  induction l with
  | nil => intro c p r _ _ h; exact h
  | cons a l ih =>
    intro c p r hp hl h
    simp only [List.forIn_cons, sibStep] at h ⊢
    cases hd : drawAtMost s a p with
    | none => simp [hd] at h
    | some x =>
      obtain ⟨h1, h2, h3⟩ := drawAtMost_append t hd
      have ht : tau = 60 := rfl
      have ha := hl a (by simp)
      have hbit : bitAt (s ++ t) (a + tau - 256) = bitAt s (a + tau - 256) := by
        unfold bitAt
        rw [get!_append_left (by omega)]
      simp only [hd, h3, bind_pure_comp, hbit] at h ⊢
      exact ih _ _ r (by omega) (fun b hb => hl b (by simp [hb])) h

theorem sampleInBallFrom_append {s t : ByteArray} {c : Poly} (h : sampleInBallFrom s = some c) :
    sampleInBallFrom (s ++ t) = some c := by
  rw [sib_eq] at h ⊢
  cases hl : forIn (List.range' (256 - tau) 60 1) (Array.replicate 256 0, 8) (sibStep s) with
  | none => simp [hl] at h
  | some r =>
    simp [hl] at h
    have ht : tau = 60 := rfl
    rw [sib_loop_append s t _ _ _ r (by omega) (fun a ha => by simp [List.mem_range'] at ha; omega) hl]
    simpa using h
theorem verify_rejects_sampleInBall_none {pk msg sig : ByteArray} (h : sampleInBall (sig.extract 0 64) = none) :
    verify pk msg sig = false := by
  unfold verify
  split
  · rfl
  · split
    · rfl
    · simp only [h, ite_self]

private theorem listMapM_none {α β : Type} (f : α → Option β) {a : α} :
    ∀ {l : List α}, a ∈ l → f a = none → l.mapM f = none
  | [], ha, _ => by simp at ha
  | b :: l, ha, h => by
    rcases List.mem_cons.1 ha with rfl | ha
    · simp [List.mapM_cons, h]
    · cases hb : f b <;> simp [List.mapM_cons, hb, listMapM_none f ha h]

private theorem arrayMapM_none {α β : Type} {f : α → Option β} {as : Array α} {a : α} (ha : a ∈ as) (h : f a = none) :
    as.mapM f = none := by
  rw [Array.mapM_eq_mapM_toList, listMapM_none f (Array.mem_toList_iff.2 ha) h]
  rfl

theorem verify_rejects_rejNtt_none {pk msg sig : ByteArray} {r s : Nat} (hr : r < k) (hs : s < l)
    (h : rejNtt (pk.extract 0 32 ++ ByteArray.mk #[s.toUInt8, r.toUInt8]) = none) : verify pk msg sig = false := by
  have hA : expandA (pk.extract 0 32) = none :=
    arrayMapM_none (a := r) (Array.mem_range.2 hr) (arrayMapM_none (a := s) (Array.mem_range.2 hs) h)
  unfold verify
  split
  · rfl
  · split
    · rfl
    · simp only [hA]
      split
      · rfl
      · cases sampleInBall (sig.extract 0 64) <;> rfl

private def rep (n : Nat) (b : UInt8) : ByteArray := ⟨Array.replicate n b⟩
#guard rejNttBytes == 894 && sampleInBallBytes == 221                              -- FIPS 204 Table 3
-- 0xFF triple = 2^23 - 1 >= q: rejected.  42 rejects + 256 zeros = 894 bytes: succeeds at the bound.
#guard (rejNttFrom (rep 126 0xFF ++ rep 768 0)).map (·.toList) == some (List.replicate 256 0)
-- 43 rejects + 255 zeros = 894 bytes: one coefficient short -> none (the bounded-iteration failure).
#guard rejNttFrom (rep 129 0xFF ++ rep 765 0) == none
#guard rejNttFrom (rep 894 0xFF) == none
-- 8 sign bytes, then 153 bytes of 0xFF (accepted only when i = 255) and 60 zeros = 221 bytes: succeeds.
#guard (sampleInBallFrom (rep 8 0 ++ rep 153 0xFF ++ rep 60 0)).isSome
-- 154 rejects + 59 zeros = 221 bytes: the draw for i = 255 runs out -> none.
#guard sampleInBallFrom (rep 8 0 ++ rep 154 0xFF ++ rep 59 0) == none
#guard sampleInBallFrom (rep 8 0 ++ rep 213 0xFF) == none
-- SHAKE extends its own prefix (the tested half of the equivalence).
#guard ((shake128 (rep 34 7) 894).extract 0 840).data == (shake128 (rep 34 7) 840).data
#guard ((shake256 (rep 64 7) 272).extract 0 221).data == (shake256 (rep 64 7) 221).data
-- Block-boundary KATs (rate - 1, rate, rate + 1; SHAKE squeezes 200 bytes, past one block), expected values from Python hashlib;
-- a SHAKE output is compared through its SHA3-512 digest.
private def pat (n : Nat) : ByteArray := ⟨(Array.range n).map fun i => UInt8.ofNat ((i * 7 + 3) % 256)⟩
private def kh (b : ByteArray) : String := String.join (b.toList.map fun x => String.ofList [Nat.digitChar (x.toNat / 16), Nat.digitChar (x.toNat % 16)])
#guard kh (sha3_512 (pat 71)) == "a02d5795bffd44cb0ac3cc3401ae89056b8017242eaf7e802033e974672ce7945811760c3b0d9578bc51bf90c364636ac87cda9b4f3e45620ea9c030421e9d86"
#guard kh (sha3_512 (pat 72)) == "2ec0da5ff440c192d33033c4257eb39dcbd27edd7e41b5ac8db9daf13db501a2ef938151aaddd82f600335654f77512cbcc926ec5abb05b79282ec716d685618"
#guard kh (sha3_512 (pat 73)) == "d26d1f9fc91b1d6c31405cc4a546f246fa7777f698d956c26a15170bccdd696aab3ee2e0597ee6f33bc7ac0336b1e4bfa0cc4355ab9faf8111cf27312640fd65"
#guard kh (sha3_512 (shake128 (pat 167) 200)) == "930cb4cb909abe0bff89aa388bd8bfe33c18f06d2a4ecc70fa7379102e89f19d099e627d7a231c9a672a1c8fbb8f018aa555f6a32fa2422d689b3b7d6f9706ab"
#guard kh (sha3_512 (shake128 (pat 168) 200)) == "5687100592e574d4cbe34a35e6f1aac5a879fe7905b573dd2023376fdb9430acbc5c5654fe71c1cea062d787e8c4fa6c72edb6bb79c84f300c2d0879150f3c07"
#guard kh (sha3_512 (shake128 (pat 169) 200)) == "c9cd6d66542a7894fa3c782e249a6bdcc6d3f0967d54ba679699dd89f0de4a01d44e43fdfdbbbacb0d1ee95f72628453e286f42915a2b0e30105407b784c4bcf"
#guard kh (sha3_512 (shake256 (pat 135) 200)) == "c9f5769c8a0653450247cebd8ba4e3c444c1b34a54a559ac325739a542540275b7af1b5780016f0caa4c0c9ad6569e36b9718f0bdda029c34ff40ede567ad376"
#guard kh (sha3_512 (shake256 (pat 136) 200)) == "736f25ed2d57dc253abd3be212a96953c07ba301494aca9342d60bf8181ac3bbf0ca232223662e8d27332937a8121b5e383ce893aaa68e55a1b12ba82096030a"
#guard kh (sha3_512 (shake256 (pat 137) 200)) == "abe98a25f3a56a6afc6de59d1e93f2ddd93187b7db23f514465f3dca67918f7a17aaf77dd005b47fb8ff0007c3de006d2027aa1c36c6fb8551d4d68bd1bf0832"
-- the ntt/invNtt loop rewrite still round-trips
#guard let p := (Array.range 256).map (· * 7919 % q); invNtt (ntt p) == p

end BlindLedger.Gate.MlDsa87
