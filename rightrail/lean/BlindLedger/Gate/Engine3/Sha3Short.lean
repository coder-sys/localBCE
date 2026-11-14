import Std.Tactic.BVDecide
import BlindLedger.Sha3Quick
import BlindLedger.Sha3LanesEq
import BlindLedger.Gate.Engine3.Keys
import BlindLedger.Gate.Engine3.Sha3Fused

/-! One-block SHA3-256 for key digests (conformance/ENGINE_V3.md section 2): `H256(dom KEY2 ‖ s ‖ kb)` is 48 bytes of
    prefix and at most 86 key bytes, so a single permutation.  `sha3_256Quick` spends about 0.3 us per call around its
    0.72 us permutation: it joins the three pieces, copies the tail into a padded buffer, tests 25 lane conditions,
    builds the state, and writes the digest through a zero buffer.  Here the prefix is read into six lanes once per
    store (`KeyCtx`), the key bytes are read straight into the lanes they fall in, and the permutation's state is the
    only object made.  `keyDigestFast` equals `sha3_256Quick` of the same message (`keyDigestFast_eq`, stated). -/

namespace BlindLedger.Gate.Engine3

open BlindLedger.Semantic Quick

/-- Eight bytes of `d` from `o`, little endian, zero past the end.  Compiled as one load when all eight exist. -/
@[extern c inline "(lean_is_scalar(#2) && lean_unbox(#2) + 8 <= lean_sarray_size(#1) ? *(uint64_t*)(lean_sarray_cptr(#1) + lean_unbox(#2)) : lean_is_scalar(#2) && lean_unbox(#2) < lean_sarray_size(#1) ? ({ uint64_t v_ = 0; __builtin_memcpy(&v_, lean_sarray_cptr(#1) + lean_unbox(#2), lean_sarray_size(#1) - lean_unbox(#2)); v_; }) : (uint64_t)0)"]
def ld64 (d : @& ByteArray) (o : @& Nat) : UInt64 :=
  (d.get! o).toUInt64 ||| ((d.get! (o + 1)).toUInt64 <<< 8) ||| ((d.get! (o + 2)).toUInt64 <<< 16) |||
    ((d.get! (o + 3)).toUInt64 <<< 24) ||| ((d.get! (o + 4)).toUInt64 <<< 32) ||| ((d.get! (o + 5)).toUInt64 <<< 40) |||
    ((d.get! (o + 6)).toUInt64 <<< 48) ||| ((d.get! (o + 7)).toUInt64 <<< 56)

/-- The first 48 bytes of every key message (`dom KEY2 ‖ s`), as six lanes, and the secret (for keys too long for one
    block). -/
structure KeyCtx where
  p0 : UInt64
  p1 : UInt64
  p2 : UInt64
  p3 : UInt64
  p4 : UInt64
  p5 : UInt64
  sec : ByteArray

def KeyCtx.ofSecret (sec : ByteArray) : KeyCtx :=
  let pre := keyDom ++ sec
  ⟨ld64 pre 0, ld64 pre 8, ld64 pre 16, ld64 pre 24, ld64 pre 32, ld64 pre 40, sec⟩

/-- Key messages up to this many key bytes fit one block with the prefix. -/
def shortMax : Nat := 86

/-- Lane of `kb ‖ 0x06 ‖ zeros` from byte `o` (the tail of the message after its prefix), `kb` of length `n`. -/
@[inline] def tailLane (kb : ByteArray) (n o : Nat) : UInt64 :=
  if o + 8 ≤ n then ld64 kb o
  else if n < o then 0
  else
    let r := (n - o) * 8
    ((ld64 kb o) &&& (((1 : UInt64) <<< r.toUInt64) - 1)) ||| ((6 : UInt64) <<< r.toUInt64)

/-- The state after absorbing the one block of `dom KEY2 ‖ s ‖ kb` (`kb.size ≤ shortMax`), in the stored (complemented)
    form of `Sha3Quick`, and permuting (`Lanes.permA`, equal to `perm permSteps` by `Lanes.permA_eq`). -/
def keyState (c : KeyCtx) (kb : ByteArray) : St :=
  let n := kb.size
  Lanes.permA
    c.p0 (ones ^^^ c.p1) (ones ^^^ c.p2) c.p3 c.p4
    c.p5 (tailLane kb n 0) (tailLane kb n 8)
    (ones ^^^ tailLane kb n 16) (tailLane kb n 24) (tailLane kb n 32) (tailLane kb n 40)
    (ones ^^^ tailLane kb n 48) (tailLane kb n 56) (tailLane kb n 64) (tailLane kb n 72)
    (tailLane kb n 80 ||| 0x8000000000000000)
    ones 0 0 ones 0 0 0 0

/-- The digest's four lanes: sort hash and directory hash, released then unresolved set. -/
@[inline] def khSt (s : St) (unres : Bool) : UInt64 := if unres then s.a1 ^^^ ones else s.a0
@[inline] def dhSt (s : St) (unres : Bool) : UInt64 := if unres then s.a3 else s.a2 ^^^ ones

/-- The 32-byte digest, as `keyDigest` returns it. -/
def keyDigestFast (c : KeyCtx) (kb : ByteArray) : ByteArray :=
  let s := keyState c kb
  set8 (set8 (set8 (set8 (zeros.extract 0 32) 0 s.a0) 8 (s.a1 ^^^ ones)) 16 (s.a2 ^^^ ones)) 24 s.a3

/-! ## Proof of `keyDigestFast_eq`

    Byte facts first (`get!` is `[·]!`, a lane is eight bytes `L8`), then the padded tail, then the lanes. -/

theorem get!_eq' (d : ByteArray) (i : Nat) : d.get! i = d[i]! := by
  by_cases h : i < d.size
  · rw [getElem!_pos d i h]
    show d.data[i]! = _
    rw [getElem!_pos d.data i h]
    rfl
  · rw [getElem!_neg d i h]
    show d.data[i]! = _
    rw [getElem!_neg d.data i h]

theorem ld64_eq' (d : ByteArray) (o : Nat) :
    ld64 d o = L8 d[o]! d[o + 1]! d[o + 2]! d[o + 3]! d[o + 4]! d[o + 5]! d[o + 6]! d[o + 7]! := by
  simp only [ld64, L8, get!_eq']

theorem ld_eq' (d : ByteArray) (o : Nat) (h : o + 7 < d.size) :
    ld d o = L8 d[o]! d[o + 1]! d[o + 2]! d[o + 3]! d[o + 4]! d[o + 5]! d[o + 6]! d[o + 7]! := by
  unfold ld L8
  rw [dif_pos h, getElem!_pos d o (by omega), getElem!_pos d (o + 1) (by omega), getElem!_pos d (o + 2) (by omega),
    getElem!_pos d (o + 3) (by omega), getElem!_pos d (o + 4) (by omega), getElem!_pos d (o + 5) (by omega),
    getElem!_pos d (o + 6) (by omega), getElem!_pos d (o + 7) (by omega)]

/-- The byte at index `i` of `kb ‖ 0x06 ‖ 0…`. -/
def Bf (kb : ByteArray) (i : Nat) : UInt8 := if i < kb.size then kb[i]! else if i = kb.size then 6 else 0

theorem tailLane_spec (kb : ByteArray) (o : Nat) :
    tailLane kb kb.size o = L8 (Bf kb o) (Bf kb (o + 1)) (Bf kb (o + 2)) (Bf kb (o + 3)) (Bf kb (o + 4))
      (Bf kb (o + 5)) (Bf kb (o + 6)) (Bf kb (o + 7)) := by
  unfold tailLane
  dsimp only
  split
  · next h1 =>
    have e : ∀ k, k < 8 → Bf kb (o + k) = kb[o + k]! := fun k hk => by unfold Bf; rw [if_pos (by omega)]
    have e0 : Bf kb o = kb[o]! := e 0 (by omega)
    rw [ld64_eq', e0, e 1 (by omega), e 2 (by omega), e 3 (by omega), e 4 (by omega), e 5 (by omega),
      e 6 (by omega), e 7 (by omega)]
  · next h1 =>
    split
    · next h2 =>
      have e : ∀ k, Bf kb (o + k) = 0 := fun k => by unfold Bf; rw [if_neg (by omega), if_neg (by omega)]
      have e0 : Bf kb o = 0 := e 0
      rw [e0, e 1, e 2, e 3, e 4, e 5, e 6, e 7]
      decide
    · next h2 =>
      obtain ⟨s, hs⟩ : ∃ s, kb.size = o + s := ⟨kb.size - o, by omega⟩
      have hs8 : s < 8 := by omega
      have hr : (kb.size - o) * 8 = s * 8 := by rw [hs]; congr 1; omega
      have e : ∀ k, Bf kb (o + k) = if k < s then kb[o + k]! else if k = s then 6 else 0 := by
        intro k; unfold Bf; rw [hs]
        by_cases a : k < s
        · rw [if_pos (show o + k < o + s by omega), if_pos a]
        · by_cases b : k = s
          · rw [if_neg (show ¬ o + k < o + s by omega), if_pos (show o + k = o + s by omega), if_neg a, if_pos b]
          · rw [if_neg (show ¬ o + k < o + s by omega), if_neg (show ¬ o + k = o + s by omega), if_neg a, if_neg b]
      have e0 : Bf kb o = if 0 < s then kb[o]! else if 0 = s then 6 else 0 := e 0
      rw [hr, ld64_eq', e0, e 1, e 2, e 3, e 4, e 5, e 6, e 7]
      generalize kb[o]! = g0
      generalize kb[o + 1]! = g1
      generalize kb[o + 2]! = g2
      generalize kb[o + 3]! = g3
      generalize kb[o + 4]! = g4
      generalize kb[o + 5]! = g5
      generalize kb[o + 6]! = g6
      generalize kb[o + 7]! = g7
      clear e e0 hr hs h1 h2
      rcases s with _ | _ | _ | _ | _ | _ | _ | _ | s
      all_goals first | (exfalso; omega) | (simp [L8]; try bv_decide)

/-- The padded final block of a short message, as `Quick.sponge` builds it. -/
def tailBuf (d : ByteArray) : ByteArray :=
  let t := (d.copySlice 0 zeros 0 d.size).set! d.size 6
  t.set! 135 (t.get! 135 ||| 0x80)

theorem zeros_size : zeros.size = 168 := by
  show (Array.replicate 168 0).size = 168
  exact Array.size_replicate ..

theorem app_get (x y : ByteArray) (j : Nat) : (x ++ y)[j]! = if j < x.size then x[j]! else y[j - x.size]! := by
  by_cases h : j < x.size
  · rw [if_pos h, getElem!_pos x j h, getElem!_pos (x ++ y) j (by simp [ByteArray.size_append]; omega)]
    simp [ByteArray.getElem_append_left h]
  · rw [if_neg h]
    by_cases h2 : j < (x ++ y).size
    · have h3 : j - x.size < y.size := by simp [ByteArray.size_append] at h2; omega
      rw [getElem!_pos y _ h3, getElem!_pos (x ++ y) j h2]
      rw [ByteArray.getElem_append_right (by omega)]
    · have h3 : ¬ j - x.size < y.size := by simp [ByteArray.size_append] at h2; omega
      rw [getElem!_neg y (j - x.size) h3, getElem!_neg (x ++ y) j h2]

theorem zext_get (r i : Nat) : (zeros.extract r 168)[i]! = 0 := by
  by_cases h : i < (zeros.extract r 168).size
  · rw [getElem!_pos (zeros.extract r 168) i h]
    simp [ByteArray.getElem_extract, zeros]
    simp [ByteArray.getElem_eq_getElem_data]
  · rw [getElem!_neg (zeros.extract r 168) i h]
    rfl

theorem copy_eq (d : ByteArray) (hd : d.size ≤ 168) :
    d.copySlice 0 zeros 0 d.size = d ++ zeros.extract d.size 168 := by
  rw [ByteArray.copySlice_eq_append]
  have h0 : zeros.extract 0 0 = ByteArray.empty := ByteArray.extract_same
  have h1 : d.extract 0 (0 + d.size) = d := by simpa using ByteArray.extract_zero_size
  rw [h0, ByteArray.empty_append, h1]
  have e1 : 0 + min d.size (d.data.size - 0) = d.size := by
    have := ByteArray.size_data (a := d)
    omega
  have e2 : zeros.data.size = 168 := zeros_size
  rw [e1, e2]

theorem tailBuf_size (d : ByteArray) (hd : d.size < 135) : (tailBuf d).size = 168 := by
  unfold tailBuf
  simp only [ByteArray.size_set!, copy_eq d (by omega), ByteArray.size_append, ByteArray.size_extract, zeros_size]
  omega

theorem tailBuf_get (d : ByteArray) (hd : d.size < 135) (j : Nat) :
    (tailBuf d)[j]! = if j < d.size then d[j]! else if j = d.size then 6 else if j = 135 then 128 else 0 := by
  have hc : ∀ j, (d.copySlice 0 zeros 0 d.size)[j]! = if j < d.size then d[j]! else 0 := fun j => by
    rw [copy_eq d (by omega), app_get, zext_get]
  have hsz : (d.copySlice 0 zeros 0 d.size).size = 168 := by
    rw [copy_eq d (by omega)]
    simp only [ByteArray.size_append, ByteArray.size_extract, zeros_size]
    omega
  have h1 : ∀ i, ((d.copySlice 0 zeros 0 d.size).set! d.size 6)[i]! =
      if d.size = i then 6 else (d.copySlice 0 zeros 0 d.size)[i]! :=
    fun i => ByteArray.getElem!_set! _ _ _ i (by omega)
  have hsz1 : ((d.copySlice 0 zeros 0 d.size).set! d.size 6).size = 168 := by rw [ByteArray.size_set!, hsz]
  have h2 : ∀ v i, (((d.copySlice 0 zeros 0 d.size).set! d.size 6).set! 135 v)[i]! =
      if 135 = i then v else ((d.copySlice 0 zeros 0 d.size).set! d.size 6)[i]! :=
    fun v i => ByteArray.getElem!_set! _ _ _ i (by omega)
  have hc135 : (d.copySlice 0 zeros 0 d.size)[135]! = 0 := by rw [hc 135, if_neg (by omega)]
  have hne : d.size ≠ 135 := by omega
  have hne' : (135 : Nat) ≠ d.size := by omega
  have hnl : ¬ 135 < d.size := by omega
  unfold tailBuf
  simp only [get!_eq', h2, h1, hc]
  by_cases a : j < d.size <;> by_cases b : j = d.size <;> by_cases c : j = 135 <;> (try simp [a, b, c, hc135, hne, hne', hnl, eq_comm (a := 135) (b := j), eq_comm (a := d.size) (b := j)]) <;> (try (exfalso; omega))

theorem sponge_short (data : ByteArray) (h : data.size < 135) :
    sponge 136 6 data 32 = squeezeK (absorbF flipped (tailBuf data) 0 17 (data.size / 8)) 32 := by
  have hf : data.size / 136 = 0 := Nat.div_eq_of_lt (by omega)
  simp only [Quick.sponge, hf, Nat.zero_mul, Nat.sub_zero, absorbAll]
  have go_eq : ∀ st, Quick.sponge.go 136 (32 / 136 + 1) st ByteArray.empty 32 = squeezeK st 32 := by
    intro st
    simp [Quick.sponge.go, ByteArray.size_empty]
  rw [go_eq]
  rfl

theorem digestFast_eq (c : KeyCtx) (kb : ByteArray) : keyDigestFast c kb = squeezeK (keyState c kb) 32 := by
  unfold keyDigestFast squeezeK
  simp

theorem cond_lane (a x : UInt64) (m lim : Nat) (hm : m < 17) (hz : lim < m → m ≠ 16 → x = 0) :
    (if m < 17 && (m ≤ lim || m + 1 == 17) then a ^^^ x else a) = a ^^^ x := by
  by_cases h : m ≤ lim ∨ m + 1 = 17
  · rw [if_pos (by simp [hm]; try omega)]
  · have hx := hz (by omega) (by omega)
    rw [if_neg (by simp [hm]; try omega), hx]
    bv_decide

theorem absorbF_17 (s : St) (T : ByteArray) (lim : Nat) (hz : ∀ m, m < 16 → lim < m → ld T (8 * m) = 0) :
    absorbF s T 0 17 lim = perm permSteps (s.a0 ^^^ ld T 0) (s.a1 ^^^ ld T 8) (s.a2 ^^^ ld T 16) (s.a3 ^^^ ld T 24) (s.a4 ^^^ ld T 32) (s.a5 ^^^ ld T 40) (s.a6 ^^^ ld T 48) (s.a7 ^^^ ld T 56) (s.a8 ^^^ ld T 64) (s.a9 ^^^ ld T 72) (s.a10 ^^^ ld T 80) (s.a11 ^^^ ld T 88) (s.a12 ^^^ ld T 96) (s.a13 ^^^ ld T 104) (s.a14 ^^^ ld T 112) (s.a15 ^^^ ld T 120) (s.a16 ^^^ ld T 128) s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23 s.a24 := by
  have c0 := cond_lane s.a0 (ld T 0) 0 lim (by omega) (fun h1 _ => hz 0 (by omega) h1)
  have c1 := cond_lane s.a1 (ld T 8) 1 lim (by omega) (fun h1 _ => hz 1 (by omega) h1)
  have c2 := cond_lane s.a2 (ld T 16) 2 lim (by omega) (fun h1 _ => hz 2 (by omega) h1)
  have c3 := cond_lane s.a3 (ld T 24) 3 lim (by omega) (fun h1 _ => hz 3 (by omega) h1)
  have c4 := cond_lane s.a4 (ld T 32) 4 lim (by omega) (fun h1 _ => hz 4 (by omega) h1)
  have c5 := cond_lane s.a5 (ld T 40) 5 lim (by omega) (fun h1 _ => hz 5 (by omega) h1)
  have c6 := cond_lane s.a6 (ld T 48) 6 lim (by omega) (fun h1 _ => hz 6 (by omega) h1)
  have c7 := cond_lane s.a7 (ld T 56) 7 lim (by omega) (fun h1 _ => hz 7 (by omega) h1)
  have c8 := cond_lane s.a8 (ld T 64) 8 lim (by omega) (fun h1 _ => hz 8 (by omega) h1)
  have c9 := cond_lane s.a9 (ld T 72) 9 lim (by omega) (fun h1 _ => hz 9 (by omega) h1)
  have c10 := cond_lane s.a10 (ld T 80) 10 lim (by omega) (fun h1 _ => hz 10 (by omega) h1)
  have c11 := cond_lane s.a11 (ld T 88) 11 lim (by omega) (fun h1 _ => hz 11 (by omega) h1)
  have c12 := cond_lane s.a12 (ld T 96) 12 lim (by omega) (fun h1 _ => hz 12 (by omega) h1)
  have c13 := cond_lane s.a13 (ld T 104) 13 lim (by omega) (fun h1 _ => hz 13 (by omega) h1)
  have c14 := cond_lane s.a14 (ld T 112) 14 lim (by omega) (fun h1 _ => hz 14 (by omega) h1)
  have c15 := cond_lane s.a15 (ld T 120) 15 lim (by omega) (fun h1 _ => hz 15 (by omega) h1)
  have c16 := cond_lane s.a16 (ld T 128) 16 lim (by omega) (fun _ h => absurd rfl h)
  unfold absorbF
  rw [c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16]
  simp

theorem keyDom_size : keyDom.size = 16 := by
  first | decide | rfl | simp [keyDom, Bin.bytesOf, domain] | decide +kernel

theorem keyState_eq (sec kb : ByteArray) (hs : sec.size = 32) (hk : kb.size ≤ shortMax) :
    keyState (KeyCtx.ofSecret sec) kb =
      absorbF flipped (tailBuf (keyDom ++ sec ++ kb)) 0 17 ((keyDom ++ sec ++ kb).size / 8) := by
  have hkd := keyDom_size
  unfold shortMax at hk
  obtain ⟨d, hd⟩ : ∃ d, d = keyDom ++ sec ++ kb := ⟨_, rfl⟩
  rw [← hd]
  have hpre : (keyDom ++ sec).size = 48 := by simp only [ByteArray.size_append, hkd, hs]
  have hdsz : d.size = 48 + kb.size := by rw [hd]; simp only [ByteArray.size_append, hkd, hs]; try omega
  have hT := tailBuf_get d (by omega)
  have hTs := tailBuf_size d (by omega)
  have dpre : ∀ j, j < 48 → d[j]! = (keyDom ++ sec)[j]! := by
    intro j hj
    rw [hd, app_get, if_pos (by omega)]
  have dkb : ∀ j, 48 ≤ j → d[j]! = kb[j - 48]! := by
    intro j hj
    rw [hd, app_get, if_neg (by omega), hpre]
  generalize tailBuf d = T at hT hTs
  have hTb : ∀ j, j < 48 → T[j]! = (keyDom ++ sec)[j]! := by
    intro j hj
    rw [hT, if_pos (by omega), dpre j hj]
  have hTk : ∀ j, 48 ≤ j → j < 135 → T[j]! = Bf kb (j - 48) := by
    intro j hj1 hj2
    rw [hT]
    unfold Bf
    by_cases a : j < d.size
    · rw [if_pos a, if_pos (by omega), dkb j hj1]
    · by_cases b : j = d.size
      · rw [if_neg a, if_pos b, if_neg (by omega), if_pos (by omega)]
      · rw [if_neg a, if_neg b, if_neg (by omega), if_neg (by omega), if_neg (by omega)]
      -- the last branch needs j ≠ 135
  have hp : ∀ o, o + 8 ≤ 48 → ld T o = ld64 (keyDom ++ sec) o := by
    intro o ho
    rw [ld_eq' T o (by omega), ld64_eq', hTb o (by omega), hTb (o + 1) (by omega), hTb (o + 2) (by omega),
      hTb (o + 3) (by omega), hTb (o + 4) (by omega), hTb (o + 5) (by omega), hTb (o + 6) (by omega),
      hTb (o + 7) (by omega)]
  have hkk : ∀ i, i + 8 ≤ 80 → ld T (48 + i) = tailLane kb kb.size i := by
    intro i hi
    have e : ∀ k, k < 8 → T[48 + i + k]! = Bf kb (i + k) := by
      intro k hk
      rw [hTk _ (by omega) (by omega)]
      congr 1
      omega
    have e0 : T[48 + i]! = Bf kb i := by
      rw [hTk _ (by omega) (by omega)]
      congr 1
      omega
    rw [ld_eq' T _ (by omega), tailLane_spec, e0, e 1 (by omega), e 2 (by omega), e 3 (by omega), e 4 (by omega),
      e 5 (by omega), e 6 (by omega), e 7 (by omega)]
  have h128 : ld T (48 + 80) = tailLane kb kb.size 80 ||| 0x8000000000000000 := by
    have e : ∀ k, k < 7 → T[48 + 80 + k]! = Bf kb (80 + k) := by
      intro k hk
      rw [hTk _ (by omega) (by omega)]
      congr 1
      omega
    have e0 : T[48 + 80]! = Bf kb 80 := by
      rw [hTk _ (by omega) (by omega)] <;> (congr 1 <;> omega)
    have z135 : T[48 + 80 + 7]! = 128 := by
      show T[135]! = 128
      rw [hT, if_neg (by omega), if_neg (by omega), if_pos rfl]
    have b87 : Bf kb (80 + 7) = 0 := by
      unfold Bf; rw [if_neg (by omega), if_neg (by omega)]
    rw [ld_eq' T _ (by omega), tailLane_spec, e0, e 1 (by omega), e 2 (by omega), e 3 (by omega), e 4 (by omega),
      e 5 (by omega), e 6 (by omega), z135, b87]
    generalize Bf kb 80 = b0
    generalize Bf kb (80 + 1) = b1
    generalize Bf kb (80 + 2) = b2
    generalize Bf kb (80 + 3) = b3
    generalize Bf kb (80 + 4) = b4
    generalize Bf kb (80 + 5) = b5
    generalize Bf kb (80 + 6) = b6
    simp only [L8]
    bv_decide
  have hz : ∀ m, m < 16 → d.size / 8 < m → ld T (8 * m) = 0 := by
    intro m hm hl
    have z : ∀ j, d.size < j → j < 135 → T[j]! = 0 := by
      intro j h1 h2
      rw [hT, if_neg (by omega), if_neg (by omega), if_neg (by omega)]
    rw [ld_eq' T _ (by omega), z (8 * m) (by omega) (by omega), z (8 * m + 1) (by omega) (by omega),
      z (8 * m + 2) (by omega) (by omega), z (8 * m + 3) (by omega) (by omega), z (8 * m + 4) (by omega) (by omega),
      z (8 * m + 5) (by omega) (by omega), z (8 * m + 6) (by omega) (by omega), z (8 * m + 7) (by omega) (by omega)]
    decide
  have hz0 : ∀ x : UInt64, (0 : UInt64) ^^^ x = x := by intro x; bv_decide
  have l0 := hp 0 (by omega)
  have l1 := hp 8 (by omega)
  have l2 := hp 16 (by omega)
  have l3 := hp 24 (by omega)
  have l4 := hp 32 (by omega)
  have l5 := hp 40 (by omega)
  have l6 : ld T 48 = tailLane kb kb.size 0 := hkk 0 (by omega)
  have l7 : ld T 56 = tailLane kb kb.size 8 := hkk 8 (by omega)
  have l8 : ld T 64 = tailLane kb kb.size 16 := hkk 16 (by omega)
  have l9 : ld T 72 = tailLane kb kb.size 24 := hkk 24 (by omega)
  have l10 : ld T 80 = tailLane kb kb.size 32 := hkk 32 (by omega)
  have l11 : ld T 88 = tailLane kb kb.size 40 := hkk 40 (by omega)
  have l12 : ld T 96 = tailLane kb kb.size 48 := hkk 48 (by omega)
  have l13 : ld T 104 = tailLane kb kb.size 56 := hkk 56 (by omega)
  have l14 : ld T 112 = tailLane kb kb.size 64 := hkk 64 (by omega)
  have l15 : ld T 120 = tailLane kb kb.size 72 := hkk 72 (by omega)
  have l16 : ld T 128 = tailLane kb kb.size 80 ||| 0x8000000000000000 := h128
  rw [absorbF_17 _ T _ hz]
  unfold keyState
  simp only [Lanes.permA_eq, flipped, KeyCtx.ofSecret, l0, l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, hz0]

theorem digest_lanes (st : St) :
    let D := set8 (set8 (set8 (set8 (zeros.extract 0 32) 0 st.a0) 8 (st.a1 ^^^ ones)) 16 (st.a2 ^^^ ones)) 24 st.a3
    le64At D 0 = st.a0 ∧ le64At D 8 = st.a1 ^^^ ones ∧ le64At D 16 = st.a2 ^^^ ones ∧ le64At D 24 = st.a3 := by
  have hz : (zeros.extract 0 32).size = 32 := by simp [ByteArray.size_extract, zeros_size]
  generalize zeros.extract 0 32 = z at hz
  generalize st.a0 = w0
  generalize st.a1 ^^^ ones = w1
  generalize st.a2 ^^^ ones = w2
  generalize st.a3 = w3
  intro D
  simp only [D, le64At, set8]
  refine ⟨?_, ?_, ?_, ?_⟩ <;> (simp [ByteArray.getElem!_set!, hz]; try bv_decide)

/-- Equal to the SHA3-256 of the joined message, for every key short enough. -/
theorem keyDigestFast_eq (sec kb : ByteArray) (hs : sec.size = 32) (hk : kb.size ≤ shortMax) :
    keyDigestFast (KeyCtx.ofSecret sec) kb = keyDigest sec kb := by
  have hkd := keyDom_size
  unfold shortMax at hk
  have hsz : (keyDom ++ sec ++ kb).size < 135 := by simp only [ByteArray.size_append, hkd, hs]; omega
  unfold keyDigest BlindLedger.Semantic.sha3_256Quick
  rw [digestFast_eq, keyState_eq sec kb hs (by unfold shortMax; omega), sponge_short _ hsz]

theorem khSt_eq (sec kb : ByteArray) (hs : sec.size = 32) (hk : kb.size ≤ shortMax) (u : Bool) :
    khSt (keyState (KeyCtx.ofSecret sec) kb) u = khAt (keyDigest sec kb) u := by
  rw [← keyDigestFast_eq sec kb hs hk]
  obtain ⟨h0, h1, h2, h3⟩ := digest_lanes (keyState (KeyCtx.ofSecret sec) kb)
  unfold keyDigestFast khSt khAt
  cases u
  · simp only [Bool.false_eq_true, if_false]; rw [h0]
  · simp only [if_true]; rw [h1]

theorem dhSt_eq (sec kb : ByteArray) (hs : sec.size = 32) (hk : kb.size ≤ shortMax) (u : Bool) :
    dhSt (keyState (KeyCtx.ofSecret sec) kb) u = dhAt (keyDigest sec kb) u := by
  rw [← keyDigestFast_eq sec kb hs hk]
  obtain ⟨h0, h1, h2, h3⟩ := digest_lanes (keyState (KeyCtx.ofSecret sec) kb)
  unfold keyDigestFast dhSt dhAt
  cases u
  · simp only [Bool.false_eq_true, if_false]; rw [h2]
  · simp only [if_true]; rw [h3]

end BlindLedger.Gate.Engine3
