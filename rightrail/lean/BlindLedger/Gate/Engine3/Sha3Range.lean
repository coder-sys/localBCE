import BlindLedger.Gate.Engine3.Sha3Fused
import BlindLedger.Gate.Engine3.Sha3Short
import BlindLedger.Sha3QuickEq
import BlindLedger.Sha3LanesEq
import BlindLedger.Sha3FastEq

/-! SHA3-512 of `pre ‖ d[off, off + len)` appended to a buffer the caller supplies, for the store's commitments.
    `sha3_512Quick (pre ++ d.extract …)` copies the range and the prefix into a new array, copies the tail into a padded
    buffer and tests 25 lane conditions per block.  Here each block is nine lane reads straight from `pre` or from `d`;
    only a lane that holds the end of `pre`, and the lane that holds the end of the message, are built byte by byte.
    Pure Lean, no extern, so the statements pin the code that runs.  `sha3_512Into_spec`: equal to the specification's `sha3_512` of the joined message. -/

namespace BlindLedger.Gate.Engine3

open BlindLedger.Semantic Quick



theorem uget_eq (d : ByteArray) (i : USize) (h : i.toNat < d.size) (n : Nat) (hn : i.toNat = n) : d.uget i h = d[n]! := by
  subst hn
  rw [getElem!_pos d i.toNat h]
  rfl

theorem ldu_eq' (d : ByteArray) (o : Nat) (h : o + 7 < d.size) :
    ldu d o = L8 d[o]! d[o + 1]! d[o + 2]! d[o + 3]! d[o + 4]! d[o + 5]! d[o + 6]! d[o + 7]! := by
  unfold ldu
  split
  · next hh =>
    have g : ∀ k (hk : k < 8), d.uget (USize.ofNat o + USize.ofNat k) (uidx_lt d o k hh hk) = d[o + k]! :=
      fun k hk => uget_eq d _ _ (o + k) (uadd o k (by omega))
    dsimp only
    rw [g 0 (by decide), g 1 (by decide), g 2 (by decide), g 3 (by decide), g 4 (by decide), g 5 (by decide),
      g 6 (by decide), g 7 (by decide), Nat.add_zero]
    rfl
  · exact ld_eq' d o h


theorem ldb_eq (d : ByteArray) (o : Nat) (h : o + 8 ≤ d.size ∧ o + 8 < 4294967295) : ldb d o h = ldu d o := by
  unfold ldu ldb
  rw [dif_pos h]


/-- XOR nine lanes (one 72-byte block) into `s`, then permute. -/
@[inline] def absorb9 (s : St) (l0 l1 l2 l3 l4 l5 l6 l7 l8 : UInt64) : St :=
  Lanes.permA (s.a0 ^^^ l0) (s.a1 ^^^ l1) (s.a2 ^^^ l2) (s.a3 ^^^ l3) (s.a4 ^^^ l4) (s.a5 ^^^ l5) (s.a6 ^^^ l6)
    (s.a7 ^^^ l7) (s.a8 ^^^ l8) s.a9 s.a10 s.a11 s.a12 s.a13 s.a14 s.a15 s.a16 s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23
    s.a24

/-- Absorb `n` full blocks of the message from byte `o`. -/
def blocks (pre d : ByteArray) (off : Nat) : (n : Nat) → (o : Nat) → St → St
  | 0, _, s => s
  | n + 1, o, s =>
    blocks pre d off n (o + 72) (absorb9 s (mLane pre d off o) (mLane pre d off (o + 8)) (mLane pre d off (o + 16))
      (mLane pre d off (o + 24)) (mLane pre d off (o + 32)) (mLane pre d off (o + 40)) (mLane pre d off (o + 48))
      (mLane pre d off (o + 56)) (mLane pre d off (o + 64)))

/-- One block read in place from `x` at byte `p`: a single bounds test, then nine lane loads with no test of their own. -/
@[inline] def absorbIn (s : St) (x : ByteArray) (p : Nat) (h : p + 72 ≤ x.size ∧ p + 72 < 4294967295) : St :=
  absorb9 s (ldb x p (by omega)) (ldb x (p + 8) (by omega)) (ldb x (p + 16) (by omega)) (ldb x (p + 24) (by omega))
    (ldb x (p + 32) (by omega)) (ldb x (p + 40) (by omega)) (ldb x (p + 48) (by omega)) (ldb x (p + 56) (by omega))
    (ldb x (p + 64) (by omega))

/-- The block at byte `o` when it straddles `pre` and `d`, or the range is too long for machine-word indices: lane by lane. -/
@[noinline] def blkSlow (pre d : ByteArray) (off o : Nat) (s : St) : St :=
  absorb9 s (mLane pre d off o) (mLane pre d off (o + 8)) (mLane pre d off (o + 16))
    (mLane pre d off (o + 24)) (mLane pre d off (o + 32)) (mLane pre d off (o + 40)) (mLane pre d off (o + 48))
    (mLane pre d off (o + 56)) (mLane pre d off (o + 64))

/-- Absorb the block at byte `o` of `pre ‖ d[off, …)`: read in place from `pre` or from `d` when the block lies wholly in one. -/
@[inline] def blk (pre d : ByteArray) (off o : Nat) (s : St) : St :=
  if h1 : pre.size ≤ o then
    if h : off + (o - pre.size) + 72 ≤ d.size ∧ off + (o - pre.size) + 72 < 4294967295 then absorbIn s d (off + (o - pre.size)) h
    else blkSlow pre d off o s
  else if h : o + 72 ≤ pre.size ∧ o + 72 < 4294967295 then absorbIn s pre o h
  else blkSlow pre d off o s

/-- `blocks`, one `blk` per block (`blocksF_eq`). -/
def blocksF (pre d : ByteArray) (off : Nat) : (n : Nat) → (o : Nat) → St → St
  | 0, _, s => s
  | n + 1, o, s => blocksF pre d off n (o + 72) (blk pre d off o s)

theorem mLane_in_d (pre d : ByteArray) (off q p : Nat) (h : pre.size ≤ q) (hp : p = off + (q - pre.size)) :
    mLane pre d off q = ldu d p := by
  subst hp; unfold mLane; rw [if_neg (by omega), if_pos h]

theorem mLane_in_pre (pre d : ByteArray) (off q : Nat) (h : q + 8 ≤ pre.size) : mLane pre d off q = ldu pre q := by
  unfold mLane; rw [if_pos h]

theorem blk_eq (pre d : ByteArray) (off o : Nat) (s : St) : blk pre d off o s = blkSlow pre d off o s := by
  unfold blk
  split
  · next h1 =>
    split
    · next h =>
      unfold absorbIn blkSlow
      simp only [ldb_eq]
      rw [mLane_in_d pre d off o _ h1 rfl, mLane_in_d pre d off (o + 8) (off + (o - pre.size) + 8) (by omega) (by omega),
        mLane_in_d pre d off (o + 16) (off + (o - pre.size) + 16) (by omega) (by omega),
        mLane_in_d pre d off (o + 24) (off + (o - pre.size) + 24) (by omega) (by omega),
        mLane_in_d pre d off (o + 32) (off + (o - pre.size) + 32) (by omega) (by omega),
        mLane_in_d pre d off (o + 40) (off + (o - pre.size) + 40) (by omega) (by omega),
        mLane_in_d pre d off (o + 48) (off + (o - pre.size) + 48) (by omega) (by omega),
        mLane_in_d pre d off (o + 56) (off + (o - pre.size) + 56) (by omega) (by omega),
        mLane_in_d pre d off (o + 64) (off + (o - pre.size) + 64) (by omega) (by omega)]
    · rfl
  · split
    · next h =>
      unfold absorbIn blkSlow
      simp only [ldb_eq]
      rw [mLane_in_pre pre d off o (by omega), mLane_in_pre pre d off (o + 8) (by omega),
        mLane_in_pre pre d off (o + 16) (by omega), mLane_in_pre pre d off (o + 24) (by omega),
        mLane_in_pre pre d off (o + 32) (by omega), mLane_in_pre pre d off (o + 40) (by omega),
        mLane_in_pre pre d off (o + 48) (by omega), mLane_in_pre pre d off (o + 56) (by omega),
        mLane_in_pre pre d off (o + 64) (by omega)]
    · rfl

theorem blocksF_eq (pre d : ByteArray) (off : Nat) : ∀ n o s, blocksF pre d off n o s = blocks pre d off n o s := by
  intro n
  induction n with
  | zero => intro o s; rfl
  | succ n ih => intro o s; simp only [blocksF, blocks]; rw [ih, blk_eq]; rfl


/-- The reference for `sha3_512Into`: the state is a value passed from block to block. -/
def sha3_512Ref (acc pre d : ByteArray) (off len : Nat) : ByteArray :=
  let n := pre.size + len
  let fb := n / 72 * 72
  let rem := n - fb
  let s := blocksF pre d off (n / 72) 0 flipped
  acc ++ squeezeK (absorb9 s (tL pre d off fb rem 0) (tL pre d off fb rem 8) (tL pre d off fb rem 16)
    (tL pre d off fb rem 24) (tL pre d off fb rem 32) (tL pre d off fb rem 40) (tL pre d off fb rem 48)
    (tL pre d off fb rem 56) (tL pre d off fb rem 64)) 64

/-! ## Proof of `sha3_512Into_spec`

    The message's bytes are `mB`, so its lanes are `mLane` (`lane_eq`); full blocks absorb as `blocks` (`blocks_eq`); the
    padded tail's bytes are `tB` (`tail_get`), so its lanes are `tLane` (`tail_lane`). -/

theorem msg_get (pre d : ByteArray) (off len i : Nat) (h : off + len ≤ d.size) (hi : i < pre.size + len) :
    (pre ++ d.extract off (off + len))[i]! = mB pre d off i := by
  rw [app_get]
  unfold mB
  by_cases a : i < pre.size
  · rw [if_pos a, if_pos a]
  · rw [if_neg a, if_neg a]
    have hs : i - pre.size < (d.extract off (off + len)).size := by
      simp only [ByteArray.size_extract]; omega
    rw [getElem!_pos (d.extract off (off + len)) (i - pre.size) hs, getElem!_pos d (off + (i - pre.size)) (by omega),
      ByteArray.getElem_extract]

theorem mLane_spec (pre d : ByteArray) (off len o : Nat) (h : off + len ≤ d.size) (ho : o + 8 ≤ pre.size + len) :
    mLane pre d off o = L8 (mB pre d off o) (mB pre d off (o + 1)) (mB pre d off (o + 2)) (mB pre d off (o + 3))
      (mB pre d off (o + 4)) (mB pre d off (o + 5)) (mB pre d off (o + 6)) (mB pre d off (o + 7)) := by
  unfold mLane
  split
  · next h1 =>
    have e : ∀ k, k < 8 → mB pre d off (o + k) = pre[o + k]! := fun k hk => by unfold mB; rw [if_pos (by omega)]
    have e0 : mB pre d off o = pre[o]! := e 0 (by omega)
    rw [ldu_eq' pre o (by omega), e0, e 1 (by omega), e 2 (by omega), e 3 (by omega), e 4 (by omega), e 5 (by omega),
      e 6 (by omega), e 7 (by omega)]
  · next h1 =>
    split
    · next h2 =>
      have e : ∀ k, mB pre d off (o + k) = d[off + (o - pre.size) + k]! := fun k => by
        unfold mB; rw [if_neg (by omega), show off + (o + k - pre.size) = off + (o - pre.size) + k by omega]
      have e0 : mB pre d off o = d[off + (o - pre.size)]! := e 0
      rw [ldu_eq' d _ (by omega), e0, e 1, e 2, e 3, e 4, e 5, e 6, e 7]
    · rfl

theorem lane_eq (pre d : ByteArray) (off len o : Nat) (h : off + len ≤ d.size) (ho : o + 8 ≤ pre.size + len) :
    ld (pre ++ d.extract off (off + len)) o = mLane pre d off o := by
  have hM : (pre ++ d.extract off (off + len)).size = pre.size + len := by
    simp only [ByteArray.size_append, ByteArray.size_extract]; omega
  rw [ld_eq' _ _ (by omega), mLane_spec pre d off len o h ho, msg_get pre d off len o h (by omega), msg_get pre d off len (o + 1) h (by omega),
    msg_get pre d off len (o + 2) h (by omega), msg_get pre d off len (o + 3) h (by omega),
    msg_get pre d off len (o + 4) h (by omega), msg_get pre d off len (o + 5) h (by omega),
    msg_get pre d off len (o + 6) h (by omega), msg_get pre d off len (o + 7) h (by omega)]

theorem cond9 (a x : UInt64) (m lim : Nat) (hm : m < 9) (hz : lim < m → m ≠ 8 → x = 0) :
    (if m < 9 && (m ≤ lim || m + 1 == 9) then a ^^^ x else a) = a ^^^ x := by
  by_cases h : m ≤ lim ∨ m + 1 = 9
  · rw [if_pos (by simp [hm]; try omega)]
  · rw [if_neg (by simp [hm]; try omega), hz (by omega) (by omega), UInt64.xor_zero]

theorem absorbF_9 (s : St) (T : ByteArray) (o lim : Nat) (hz : ∀ m, m < 8 → lim < m → ld T (o + 8 * m) = 0) :
    absorbF s T o 9 lim = absorb9 s (ld T o) (ld T (o + 8)) (ld T (o + 16)) (ld T (o + 24)) (ld T (o + 32))
      (ld T (o + 40)) (ld T (o + 48)) (ld T (o + 56)) (ld T (o + 64)) := by
  have c0 := cond9 s.a0 (ld T o) 0 lim (by omega) (fun h1 _ => by simpa using hz 0 (by omega) h1)
  have c1 := cond9 s.a1 (ld T (o + 8)) 1 lim (by omega) (fun h1 _ => by simpa using hz 1 (by omega) h1)
  have c2 := cond9 s.a2 (ld T (o + 16)) 2 lim (by omega) (fun h1 _ => by simpa using hz 2 (by omega) h1)
  have c3 := cond9 s.a3 (ld T (o + 24)) 3 lim (by omega) (fun h1 _ => by simpa using hz 3 (by omega) h1)
  have c4 := cond9 s.a4 (ld T (o + 32)) 4 lim (by omega) (fun h1 _ => by simpa using hz 4 (by omega) h1)
  have c5 := cond9 s.a5 (ld T (o + 40)) 5 lim (by omega) (fun h1 _ => by simpa using hz 5 (by omega) h1)
  have c6 := cond9 s.a6 (ld T (o + 48)) 6 lim (by omega) (fun h1 _ => by simpa using hz 6 (by omega) h1)
  have c7 := cond9 s.a7 (ld T (o + 56)) 7 lim (by omega) (fun h1 _ => by simpa using hz 7 (by omega) h1)
  have c8 := cond9 s.a8 (ld T (o + 64)) 8 lim (by omega) (fun _ h => absurd rfl h)
  unfold absorbF absorb9
  rw [Lanes.permA_eq, c0, c1, c2, c3, c4, c5, c6, c7, c8]
  simp

theorem blocks_eq (pre d : ByteArray) (off len : Nat) (h : off + len ≤ d.size) :
    ∀ n blk s, (blk + n) * 72 ≤ pre.size + len →
      absorbAll 72 (pre ++ d.extract off (off + len)) n blk s = blocks pre d off n (blk * 72) s := by
  intro n
  induction n with
  | zero => intro blk s _; rfl
  | succ n ih =>
    intro blk s hn
    have hb : (blk + 1 + n) * 72 ≤ pre.size + len := by omega
    simp only [absorbAll, blocks]
    rw [ih (blk + 1) _ hb, show (blk + 1) * 72 = blk * 72 + 72 by omega, show (72 : Nat) / 8 = 9 from rfl,
      absorbF_9 _ _ _ 25 (fun m _ h25 => absurd h25 (by omega))]
    rw [lane_eq pre d off len (blk * 72) h (by omega), lane_eq pre d off len (blk * 72 + 8) h (by omega),
      lane_eq pre d off len (blk * 72 + 16) h (by omega), lane_eq pre d off len (blk * 72 + 24) h (by omega),
      lane_eq pre d off len (blk * 72 + 32) h (by omega), lane_eq pre d off len (blk * 72 + 40) h (by omega),
      lane_eq pre d off len (blk * 72 + 48) h (by omega), lane_eq pre d off len (blk * 72 + 56) h (by omega),
      lane_eq pre d off len (blk * 72 + 64) h (by omega)]

/-- The padded final block, as `Quick.sponge` builds it for rate 72. -/
def tailT (M : ByteArray) : ByteArray :=
  let t := (M.copySlice (M.size / 72 * 72) zeros 0 (M.size - M.size / 72 * 72)).set! (M.size - M.size / 72 * 72) 6
  t.set! 71 (t.get! 71 ||| 0x80)

theorem sponge_512 (M : ByteArray) :
    sponge 72 0x06 M 64 = squeezeK (absorbF (absorbAll 72 M (M.size / 72) 0 flipped) (tailT M) 0 9
      ((M.size - M.size / 72 * 72) / 8)) 64 := by
  have go_eq : ∀ st, Quick.sponge.go 72 (64 / 72 + 1) st ByteArray.empty 64 = squeezeK st 64 := by
    intro st
    simp [Quick.sponge.go, ByteArray.size_empty]
  simp only [Quick.sponge]
  rw [go_eq]
  rfl

theorem copy_get (M : ByteArray) (fb rem j : Nat) (hr : fb + rem ≤ M.size) (hr2 : rem ≤ 168) :
    (M.copySlice fb zeros 0 rem)[j]! = if j < rem then M[fb + j]! else 0 := by
  rw [ByteArray.copySlice_eq_append]
  have h0 : zeros.extract 0 0 = ByteArray.empty := ByteArray.extract_same
  have e1 : 0 + min rem (M.data.size - fb) = rem := by
    have := ByteArray.size_data (a := M)
    omega
  have e2 : zeros.data.size = 168 := zeros_size
  rw [h0, ByteArray.empty_append, e1, e2, app_get, zext_get]
  have hs : (M.extract fb (fb + rem)).size = rem := by simp only [ByteArray.size_extract]; omega
  rw [hs]
  by_cases a : j < rem
  · rw [if_pos a, if_pos a, getElem!_pos (M.extract fb (fb + rem)) j (by omega), getElem!_pos M (fb + j) (by omega),
      ByteArray.getElem_extract]
  · rw [if_neg a, if_neg a]

theorem tail_get (pre d : ByteArray) (off len j : Nat) (h : off + len ≤ d.size) (hj : j < 72) :
    (tailT (pre ++ d.extract off (off + len)))[j]! =
      tB pre d off ((pre.size + len) / 72 * 72) ((pre.size + len) - (pre.size + len) / 72 * 72) j := by
  have hM : (pre ++ d.extract off (off + len)).size = pre.size + len := by
    simp only [ByteArray.size_append, ByteArray.size_extract]; omega
  generalize hn : pre.size + len = n at hM
  have hfb : n / 72 * 72 ≤ n := Nat.div_mul_le_self n 72
  have hrem : n - n / 72 * 72 < 72 := by omega
  have hc : ∀ i, ((pre ++ d.extract off (off + len)).copySlice (n / 72 * 72) zeros 0 (n - n / 72 * 72))[i]! =
      if i < n - n / 72 * 72 then mB pre d off (n / 72 * 72 + i) else 0 := fun i => by
    rw [copy_get _ _ _ _ (by omega) (by omega)]
    by_cases a : i < n - n / 72 * 72
    · rw [if_pos a, if_pos a, msg_get pre d off len _ h (by omega)]
    · rw [if_neg a, if_neg a]
  have hsz : ((pre ++ d.extract off (off + len)).copySlice (n / 72 * 72) zeros 0 (n - n / 72 * 72)).size = 168 := by
    rw [ByteArray.copySlice_eq_append]
    simp only [ByteArray.size_append, ByteArray.size_extract, zeros_size]
    have := ByteArray.size_data (a := pre ++ d.extract off (off + len))
    have e2 : zeros.data.size = 168 := zeros_size
    rw [e2]
    omega
  unfold tailT
  rw [hM]
  generalize ((pre ++ d.extract off (off + len)).copySlice (n / 72 * 72) zeros 0 (n - n / 72 * 72)) = c at hc hsz
  have h1 : ∀ i, (c.set! (n - n / 72 * 72) 6)[i]! = if n - n / 72 * 72 = i then 6 else c[i]! :=
    fun i => ByteArray.getElem!_set! _ _ _ i (by omega)
  have hsz1 : (c.set! (n - n / 72 * 72) 6).size = 168 := by rw [ByteArray.size_set!, hsz]
  have h2 : ∀ v i, ((c.set! (n - n / 72 * 72) 6).set! 71 v)[i]! = if 71 = i then v else (c.set! (n - n / 72 * 72) 6)[i]! :=
    fun v i => ByteArray.getElem!_set! _ _ _ i (by omega)
  unfold tB
  simp only [get!_eq', h2, h1, hc]
  generalize n - n / 72 * 72 = r at hrem
  by_cases a : j = 71
  · subst a
    have b : ¬ 71 < r := by omega
    by_cases c : r = 71
    · subst c; simp
    · simp [b, c, Ne.symm c]
  · by_cases b : j < r
    · simp [a, b, Ne.symm a, show r ≠ j by omega]
    · by_cases c : j = r
      · subst c; simp [a, Ne.symm a]
      · simp [a, b, c, Ne.symm a, Ne.symm c]

theorem tLane_spec (pre d : ByteArray) (off len fb rem o : Nat) (h : off + len ≤ d.size) (hn : fb + rem = pre.size + len)
    (ho : o ≤ 64) (hr : rem < 72) :
    tLane pre d off fb rem o = L8 (tB pre d off fb rem o) (tB pre d off fb rem (o + 1)) (tB pre d off fb rem (o + 2))
      (tB pre d off fb rem (o + 3)) (tB pre d off fb rem (o + 4)) (tB pre d off fb rem (o + 5))
      (tB pre d off fb rem (o + 6)) (tB pre d off fb rem (o + 7)) := by
  unfold tLane
  split
  · next h1 =>
    have e : ∀ k, k < 8 → tB pre d off fb rem (o + k) = mB pre d off (fb + o + k) := fun k hk => by
      unfold tB; rw [if_neg (by omega), if_pos (by omega), Nat.add_assoc]
    have e0 : tB pre d off fb rem o = mB pre d off (fb + o) := e 0 (by omega)
    rw [mLane_spec pre d off len (fb + o) h (by omega), e0, e 1 (by omega), e 2 (by omega), e 3 (by omega), e 4 (by omega), e 5 (by omega),
      e 6 (by omega), e 7 (by omega)]
  · next h1 =>
    split
    · next h2 =>
      have e : ∀ k, k < 8 → o + k ≠ 71 → tB pre d off fb rem (o + k) = 0 := fun k _ h71 => by
        unfold tB; rw [if_neg (by omega), if_neg (by omega), if_neg (by omega)]
      split
      · next h3 =>
        subst h3
        have e7 : tB pre d off fb rem (64 + 7) = 0x80 := by
          simp [tB, show ¬ (64 + 7 < rem) by omega, show 64 + 7 ≠ rem by omega] <;> decide
        have e0 : tB pre d off fb rem 64 = 0 := e 0 (by omega) (by omega)
        rw [e0, e 1 (by omega) (by omega), e 2 (by omega) (by omega), e 3 (by omega) (by omega),
          e 4 (by omega) (by omega), e 5 (by omega) (by omega), e 6 (by omega) (by omega), e7]
        decide
      · next h3 =>
        have e0 : tB pre d off fb rem o = 0 := e 0 (by omega) (by omega)
        rw [e0, e 1 (by omega) (by omega), e 2 (by omega) (by omega), e 3 (by omega) (by omega),
          e 4 (by omega) (by omega), e 5 (by omega) (by omega), e 6 (by omega) (by omega), e 7 (by omega) (by omega)]
        decide
    · rfl

theorem tail_lane (pre d : ByteArray) (off len o : Nat) (h : off + len ≤ d.size) (ho : o ≤ 64) :
    ld (tailT (pre ++ d.extract off (off + len))) o =
      tLane pre d off ((pre.size + len) / 72 * 72) ((pre.size + len) - (pre.size + len) / 72 * 72) o := by
  have hsz : (tailT (pre ++ d.extract off (off + len))).size = 168 := by
    unfold tailT
    simp only [ByteArray.size_set!, ByteArray.copySlice_eq_append, ByteArray.size_append, ByteArray.size_extract,
      zeros_size]
    have := ByteArray.size_data (a := pre ++ d.extract off (off + len))
    have e2 : zeros.data.size = 168 := zeros_size
    rw [e2]
    simp only [ByteArray.size_append, ByteArray.size_extract] at *
    omega
  have hfb : (pre.size + len) / 72 * 72 ≤ pre.size + len := Nat.div_mul_le_self _ 72
  rw [ld_eq' _ _ (by omega), tLane_spec _ _ _ len _ _ _ h (by omega) ho (by omega), tail_get _ _ _ _ _ h (by omega),
    tail_get _ _ _ _ (o + 1) h (by omega), tail_get _ _ _ _ (o + 2) h (by omega), tail_get _ _ _ _ (o + 3) h (by omega),
    tail_get _ _ _ _ (o + 4) h (by omega), tail_get _ _ _ _ (o + 5) h (by omega), tail_get _ _ _ _ (o + 6) h (by omega),
    tail_get _ _ _ _ (o + 7) h (by omega)]

theorem sha3_512Ref_eq (acc pre d : ByteArray) (off len : Nat) (h : off + len ≤ d.size) :
    sha3_512Ref acc pre d off len = acc ++ sha3_512Quick (pre ++ d.extract off (off + len)) := by
  have hM : (pre ++ d.extract off (off + len)).size = pre.size + len := by
    simp only [ByteArray.size_append, ByteArray.size_extract]; omega
  have hz : ∀ m, m < 8 → ((pre.size + len) - (pre.size + len) / 72 * 72) / 8 < m →
      ld (tailT (pre ++ d.extract off (off + len))) (0 + 8 * m) = 0 := fun m hm hl => by
    rw [Nat.zero_add, tail_lane _ _ _ _ _ h (by omega)]
    unfold tLane
    rw [if_neg (by omega), if_pos (by omega), if_neg (by omega)]
  unfold sha3_512Ref tL sha3_512Quick
  rw [sponge_512, hM, blocks_eq pre d off len h _ 0 _ (by have := Nat.div_mul_le_self (pre.size + len) 72; omega),
    Nat.zero_mul, absorbF_9 _ _ 0 _ hz]
  simp only [Nat.zero_add]
  rw [blocksF_eq, tail_lane _ _ _ _ 0 h (by omega), tail_lane _ _ _ _ 8 h (by omega), tail_lane _ _ _ _ 16 h (by omega),
    tail_lane _ _ _ _ 24 h (by omega), tail_lane _ _ _ _ 32 h (by omega), tail_lane _ _ _ _ 40 h (by omega),
    tail_lane _ _ _ _ 48 h (by omega), tail_lane _ _ _ _ 56 h (by omega), tail_lane _ _ _ _ 64 h (by omega)]


theorem blk_d (pre d : ByteArray) (off o : Nat) (s : St) (h1 : pre.size ≤ o)
    (h : off + (o - pre.size) + 72 ≤ d.size ∧ off + (o - pre.size) + 72 < 4294967295) :
    blk pre d off o s = absorbIn s d (off + (o - pre.size)) h := by
  unfold blk; rw [dif_pos h1, dif_pos h]

theorem blk_p (pre d : ByteArray) (off o : Nat) (s : St) (h1 : ¬ pre.size ≤ o) (h : o + 72 ≤ pre.size ∧ o + 72 < 4294967295) :
    blk pre d off o s = absorbIn s pre o h := by
  unfold blk; rw [dif_neg h1, dif_pos h]

theorem blk_sd (pre d : ByteArray) (off o : Nat) (s : St) (h1 : pre.size ≤ o)
    (h : ¬ (off + (o - pre.size) + 72 ≤ d.size ∧ off + (o - pre.size) + 72 < 4294967295)) :
    blk pre d off o s = blkSlow pre d off o s := by
  unfold blk; rw [dif_pos h1, dif_neg h]

theorem blk_sp (pre d : ByteArray) (off o : Nat) (s : St) (h1 : ¬ pre.size ≤ o) (h : ¬ (o + 72 ≤ pre.size ∧ o + 72 < 4294967295)) :
    blk pre d off o s = blkSlow pre d off o s := by
  unfold blk; rw [dif_neg h1, dif_neg h]

/-! ## One function per sponge

    `run` takes the 25 lanes as arguments and carries them through a tail loop: four rounds per step (`Lanes.rounds4`), then, when
    the round list is used up, the next block is read from its bytes and xored in.  No state object is built: the only memory
    is the input and the output.  `n` blocks are still to be absorbed (the padded last block counts), `o` is the byte where the
    next one starts.  `run_eq` states that it is `sha3_512Ref`. -/


theorem sqLanes_eq (s : St) : sqLanes s.a0 s.a1 s.a2 s.a3 s.a4 s.a5 s.a6 s.a7 = squeezeK s 64 := by
  unfold sqLanes squeezeK
  simp



/-- The reference run: the state is a value, one `blk` per full block and the padded block last. -/
def runS (acc pre d : ByteArray) (off fb rem : Nat) : Nat → Nat → St → ByteArray
  | 0, _, s => acc ++ squeezeK s 64
  | n + 1, o, s => runS acc pre d off fb rem n (o + 72)
      (if n = 0 then absorb9 s (tL pre d off fb rem 0) (tL pre d off fb rem 8) (tL pre d off fb rem 16) (tL pre d off fb rem 24) (tL pre d off fb rem 32) (tL pre d off fb rem 40) (tL pre d off fb rem 48) (tL pre d off fb rem 56) (tL pre d off fb rem 64) else blk pre d off o s)

theorem run_steps (acc pre d : ByteArray) (off fb rem : Nat) : ∀ (t : Lanes.Rc) (n o : Nat) (s : St),
    run acc pre d off fb rem t n o s.a0 s.a1 s.a2 s.a3 s.a4 s.a5 s.a6 s.a7 s.a8 s.a9 s.a10 s.a11 s.a12 s.a13 s.a14 s.a15 s.a16 s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23 s.a24 =
      run acc pre d off fb rem .nil n o (Lanes.steps t s.a0 s.a1 s.a2 s.a3 s.a4 s.a5 s.a6 s.a7 s.a8 s.a9 s.a10 s.a11 s.a12 s.a13 s.a14 s.a15 s.a16 s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23 s.a24).a0 (Lanes.steps t s.a0 s.a1 s.a2 s.a3 s.a4 s.a5 s.a6 s.a7 s.a8 s.a9 s.a10 s.a11 s.a12 s.a13 s.a14 s.a15 s.a16 s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23 s.a24).a1 (Lanes.steps t s.a0 s.a1 s.a2 s.a3 s.a4 s.a5 s.a6 s.a7 s.a8 s.a9 s.a10 s.a11 s.a12 s.a13 s.a14 s.a15 s.a16 s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23 s.a24).a2 (Lanes.steps t s.a0 s.a1 s.a2 s.a3 s.a4 s.a5 s.a6 s.a7 s.a8 s.a9 s.a10 s.a11 s.a12 s.a13 s.a14 s.a15 s.a16 s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23 s.a24).a3 (Lanes.steps t s.a0 s.a1 s.a2 s.a3 s.a4 s.a5 s.a6 s.a7 s.a8 s.a9 s.a10 s.a11 s.a12 s.a13 s.a14 s.a15 s.a16 s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23 s.a24).a4 (Lanes.steps t s.a0 s.a1 s.a2 s.a3 s.a4 s.a5 s.a6 s.a7 s.a8 s.a9 s.a10 s.a11 s.a12 s.a13 s.a14 s.a15 s.a16 s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23 s.a24).a5 (Lanes.steps t s.a0 s.a1 s.a2 s.a3 s.a4 s.a5 s.a6 s.a7 s.a8 s.a9 s.a10 s.a11 s.a12 s.a13 s.a14 s.a15 s.a16 s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23 s.a24).a6 (Lanes.steps t s.a0 s.a1 s.a2 s.a3 s.a4 s.a5 s.a6 s.a7 s.a8 s.a9 s.a10 s.a11 s.a12 s.a13 s.a14 s.a15 s.a16 s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23 s.a24).a7 (Lanes.steps t s.a0 s.a1 s.a2 s.a3 s.a4 s.a5 s.a6 s.a7 s.a8 s.a9 s.a10 s.a11 s.a12 s.a13 s.a14 s.a15 s.a16 s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23 s.a24).a8 (Lanes.steps t s.a0 s.a1 s.a2 s.a3 s.a4 s.a5 s.a6 s.a7 s.a8 s.a9 s.a10 s.a11 s.a12 s.a13 s.a14 s.a15 s.a16 s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23 s.a24).a9 (Lanes.steps t s.a0 s.a1 s.a2 s.a3 s.a4 s.a5 s.a6 s.a7 s.a8 s.a9 s.a10 s.a11 s.a12 s.a13 s.a14 s.a15 s.a16 s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23 s.a24).a10 (Lanes.steps t s.a0 s.a1 s.a2 s.a3 s.a4 s.a5 s.a6 s.a7 s.a8 s.a9 s.a10 s.a11 s.a12 s.a13 s.a14 s.a15 s.a16 s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23 s.a24).a11 (Lanes.steps t s.a0 s.a1 s.a2 s.a3 s.a4 s.a5 s.a6 s.a7 s.a8 s.a9 s.a10 s.a11 s.a12 s.a13 s.a14 s.a15 s.a16 s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23 s.a24).a12 (Lanes.steps t s.a0 s.a1 s.a2 s.a3 s.a4 s.a5 s.a6 s.a7 s.a8 s.a9 s.a10 s.a11 s.a12 s.a13 s.a14 s.a15 s.a16 s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23 s.a24).a13 (Lanes.steps t s.a0 s.a1 s.a2 s.a3 s.a4 s.a5 s.a6 s.a7 s.a8 s.a9 s.a10 s.a11 s.a12 s.a13 s.a14 s.a15 s.a16 s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23 s.a24).a14 (Lanes.steps t s.a0 s.a1 s.a2 s.a3 s.a4 s.a5 s.a6 s.a7 s.a8 s.a9 s.a10 s.a11 s.a12 s.a13 s.a14 s.a15 s.a16 s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23 s.a24).a15 (Lanes.steps t s.a0 s.a1 s.a2 s.a3 s.a4 s.a5 s.a6 s.a7 s.a8 s.a9 s.a10 s.a11 s.a12 s.a13 s.a14 s.a15 s.a16 s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23 s.a24).a16 (Lanes.steps t s.a0 s.a1 s.a2 s.a3 s.a4 s.a5 s.a6 s.a7 s.a8 s.a9 s.a10 s.a11 s.a12 s.a13 s.a14 s.a15 s.a16 s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23 s.a24).a17 (Lanes.steps t s.a0 s.a1 s.a2 s.a3 s.a4 s.a5 s.a6 s.a7 s.a8 s.a9 s.a10 s.a11 s.a12 s.a13 s.a14 s.a15 s.a16 s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23 s.a24).a18 (Lanes.steps t s.a0 s.a1 s.a2 s.a3 s.a4 s.a5 s.a6 s.a7 s.a8 s.a9 s.a10 s.a11 s.a12 s.a13 s.a14 s.a15 s.a16 s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23 s.a24).a19 (Lanes.steps t s.a0 s.a1 s.a2 s.a3 s.a4 s.a5 s.a6 s.a7 s.a8 s.a9 s.a10 s.a11 s.a12 s.a13 s.a14 s.a15 s.a16 s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23 s.a24).a20 (Lanes.steps t s.a0 s.a1 s.a2 s.a3 s.a4 s.a5 s.a6 s.a7 s.a8 s.a9 s.a10 s.a11 s.a12 s.a13 s.a14 s.a15 s.a16 s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23 s.a24).a21 (Lanes.steps t s.a0 s.a1 s.a2 s.a3 s.a4 s.a5 s.a6 s.a7 s.a8 s.a9 s.a10 s.a11 s.a12 s.a13 s.a14 s.a15 s.a16 s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23 s.a24).a22 (Lanes.steps t s.a0 s.a1 s.a2 s.a3 s.a4 s.a5 s.a6 s.a7 s.a8 s.a9 s.a10 s.a11 s.a12 s.a13 s.a14 s.a15 s.a16 s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23 s.a24).a23 (Lanes.steps t s.a0 s.a1 s.a2 s.a3 s.a4 s.a5 s.a6 s.a7 s.a8 s.a9 s.a10 s.a11 s.a12 s.a13 s.a14 s.a15 s.a16 s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23 s.a24).a24 := by
  intro t
  induction t with
  | nil => intro n o s; rfl
  | cons r0 r1 r2 r3 tl ih =>
    intro n o s
    rw [run.eq_3]
    exact ih n o (Lanes.rounds4 r0 r1 r2 r3 s.a0 s.a1 s.a2 s.a3 s.a4 s.a5 s.a6 s.a7 s.a8 s.a9 s.a10 s.a11 s.a12 s.a13 s.a14 s.a15 s.a16 s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23 s.a24)

set_option maxHeartbeats 2000000 in
theorem run_nil (acc pre d : ByteArray) (off fb rem : Nat) : ∀ (n o : Nat) (s : St),
    run acc pre d off fb rem .nil n o s.a0 s.a1 s.a2 s.a3 s.a4 s.a5 s.a6 s.a7 s.a8 s.a9 s.a10 s.a11 s.a12 s.a13 s.a14 s.a15 s.a16 s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23 s.a24 = runS acc pre d off fb rem n o s := by
  intro n
  induction n with
  | zero => intro o s; rw [run.eq_1, sqLanes_eq]; rfl
  | succ n ih =>
    intro o s
    have key : ∀ (o' : Nat) (s' : St), run acc pre d off fb rem Lanes.rcTab n o' s'.a0 s'.a1 s'.a2 s'.a3 s'.a4 s'.a5 s'.a6 s'.a7 s'.a8
        s'.a9 s'.a10 s'.a11 s'.a12 s'.a13 s'.a14 s'.a15 s'.a16 s'.a17 s'.a18 s'.a19 s'.a20 s'.a21 s'.a22 s'.a23 s'.a24 =
        runS acc pre d off fb rem n o' (Lanes.permA s'.a0 s'.a1 s'.a2 s'.a3 s'.a4 s'.a5 s'.a6 s'.a7 s'.a8 s'.a9 s'.a10 s'.a11
          s'.a12 s'.a13 s'.a14 s'.a15 s'.a16 s'.a17 s'.a18 s'.a19 s'.a20 s'.a21 s'.a22 s'.a23 s'.a24) :=
      fun o' s' => (run_steps acc pre d off fb rem Lanes.rcTab n o' s').trans (ih o' _)
    have key2 : ∀ (o' : Nat) (s : St) (l0 l1 l2 l3 l4 l5 l6 l7 l8 : UInt64),
        run acc pre d off fb rem Lanes.rcTab n o' (s.a0 ^^^ l0) (s.a1 ^^^ l1) (s.a2 ^^^ l2) (s.a3 ^^^ l3) (s.a4 ^^^ l4) (s.a5 ^^^ l5) (s.a6 ^^^ l6) (s.a7 ^^^ l7) (s.a8 ^^^ l8) s.a9 s.a10 s.a11 s.a12 s.a13 s.a14 s.a15 s.a16 s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23 s.a24 =
          runS acc pre d off fb rem n o' (absorb9 s l0 l1 l2 l3 l4 l5 l6 l7 l8) :=
      fun o' s l0 l1 l2 l3 l4 l5 l6 l7 l8 => key o' ⟨s.a0 ^^^ l0, s.a1 ^^^ l1, s.a2 ^^^ l2, s.a3 ^^^ l3, s.a4 ^^^ l4, s.a5 ^^^ l5, s.a6 ^^^ l6, s.a7 ^^^ l7, s.a8 ^^^ l8, s.a9, s.a10, s.a11, s.a12, s.a13, s.a14, s.a15, s.a16, s.a17, s.a18, s.a19, s.a20, s.a21, s.a22, s.a23, s.a24⟩
    rw [run.eq_2]
    show _ = runS acc pre d off fb rem n (o + 72) (if n = 0 then absorb9 s (tL pre d off fb rem 0) (tL pre d off fb rem 8) (tL pre d off fb rem 16) (tL pre d off fb rem 24) (tL pre d off fb rem 32) (tL pre d off fb rem 40) (tL pre d off fb rem 48) (tL pre d off fb rem 56) (tL pre d off fb rem 64) else blk pre d off o s)
    by_cases hn : n = 0
    · rw [if_pos hn, if_pos hn]
      exact key2 (o + 72) s _ _ _ _ _ _ _ _ _
    · rw [if_neg hn, if_neg hn]
      by_cases h1 : pre.size ≤ o
      · rw [dif_pos h1]
        by_cases h : off + (o - pre.size) + 72 ≤ d.size ∧ off + (o - pre.size) + 72 < 4294967295
        · rw [dif_pos h, blk_d pre d off o s h1 h]
          exact key2 (o + 72) s _ _ _ _ _ _ _ _ _
        · rw [dif_neg h, blk_sd pre d off o s h1 h]
          exact key2 (o + 72) s _ _ _ _ _ _ _ _ _
      · rw [dif_neg h1]
        by_cases h : o + 72 ≤ pre.size ∧ o + 72 < 4294967295
        · rw [dif_pos h, blk_p pre d off o s h1 h]
          exact key2 (o + 72) s _ _ _ _ _ _ _ _ _
        · rw [dif_neg h, blk_sp pre d off o s h1 h]
          exact key2 (o + 72) s _ _ _ _ _ _ _ _ _

theorem runS_eq (acc pre d : ByteArray) (off fb rem : Nat) : ∀ (m o : Nat) (s : St),
    runS acc pre d off fb rem (m + 1) o s = acc ++ squeezeK (absorb9 (blocksF pre d off m o s) (tL pre d off fb rem 0) (tL pre d off fb rem 8) (tL pre d off fb rem 16) (tL pre d off fb rem 24) (tL pre d off fb rem 32) (tL pre d off fb rem 40) (tL pre d off fb rem 48) (tL pre d off fb rem 56) (tL pre d off fb rem 64)) 64 := by
  intro m
  induction m with
  | zero => intro o s; rfl
  | succ m ih => intro o s; rw [runS, if_neg (by omega), ih]; rfl


theorem sha3_512Into_ref (acc pre d : ByteArray) (off len : Nat) : sha3_512Into acc pre d off len = sha3_512Ref acc pre d off len := by
  unfold sha3_512Into sha3_512Ref
  rw [run_nil acc pre d off _ _ _ 0 flipped, runS_eq]

/-- Equal to `sha3_512Quick` of the joined message, appended to `acc`. -/
theorem sha3_512Into_eq (acc pre d : ByteArray) (off len : Nat) (h : off + len ≤ d.size) :
    sha3_512Into acc pre d off len = acc ++ sha3_512Quick (pre ++ d.extract off (off + len)) := by
  rw [sha3_512Into_ref, sha3_512Ref_eq acc pre d off len h]

/-- Equal to the specification's SHA3-512 (`Sha3.lean`) of the joined message, appended to `acc`. -/
theorem sha3_512Into_spec (acc pre d : ByteArray) (off len : Nat) (h : off + len ≤ d.size) :
    sha3_512Into acc pre d off len = acc ++ sha3_512 (pre ++ d.extract off (off + len)) := by
  rw [sha3_512Into_eq acc pre d off len h, sha3_512Quick_eq, ← sha3_512_eq]

/-- `acc` followed by the SHA3-512 of `pre ‖ x`, with `x` read in place. -/
theorem sha3_512Into_all (acc pre x : ByteArray) :
    sha3_512Into acc pre x 0 x.size = acc ++ sha3_512Quick (pre ++ x) := by
  rw [sha3_512Into_eq _ _ _ _ _ (by omega), Nat.zero_add, ByteArray.extract_zero_size]

/-- The SHA3-512 of `pre ‖ x`, with `x` read in place (`hashDom_eq`). -/
def hashDom (pre x : ByteArray) : ByteArray := sha3_512Into ByteArray.empty pre x 0 x.size

theorem hashDom_eq (pre x : ByteArray) : hashDom pre x = sha3_512Quick (pre ++ x) := by
  unfold hashDom; rw [sha3_512Into_all, ByteArray.empty_append]

end BlindLedger.Gate.Engine3
