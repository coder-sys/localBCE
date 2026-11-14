import BlindLedger.Sha3Quick
import BlindLedger.Sha3Lanes

/-! The fused SHA3-512 of `pre ‖ d[off, off + len)` appended to a buffer the caller supplies (`sha3_512Into`).  Only the
    definitions are here, so that the byte helpers `Gate/Flat/Bin.lean` can use them; `Sha3Range.lean` proves that it equals
    `sha3_512Quick` of the joined message and the specification's `sha3_512`.  Pure Lean, no extern. -/

namespace BlindLedger.Gate.Engine3

open BlindLedger.Semantic Quick

def L8 (b0 b1 b2 b3 b4 b5 b6 b7 : UInt8) : UInt64 :=
  b0.toUInt64 ||| (b1.toUInt64 <<< 8) ||| (b2.toUInt64 <<< 16) ||| (b3.toUInt64 <<< 24) |||
    (b4.toUInt64 <<< 32) ||| (b5.toUInt64 <<< 40) ||| (b6.toUInt64 <<< 48) ||| (b7.toUInt64 <<< 56)

theorem uadd (o k : Nat) (h : o + k < 4294967296) : (USize.ofNat o + USize.ofNat k).toNat = o + k := by
  rw [USize.toNat_add, USize.toNat_ofNat_of_lt_32 (by omega), USize.toNat_ofNat_of_lt_32 (by omega)]
  exact Nat.mod_eq_of_lt (Nat.lt_of_lt_of_le h USize.le_size)

theorem uidx_lt (d : ByteArray) (o k : Nat) (h : o + 8 ≤ d.size ∧ o + 8 < 4294967295) (hk : k < 8) :
    (USize.ofNat o + USize.ofNat k).toNat < d.size := by
  rw [uadd o k (by omega)]; omega

/-- `Quick.ld` with one bounds test and machine-word indices, so the eight byte reads compile to plain loads
    (`ldu_eq'`).  The bound stays below 2^32 so it compiles to a small constant, not a big number built per call. -/
@[inline] def ldu (d : ByteArray) (o : Nat) : UInt64 :=
  if h : o + 8 ≤ d.size ∧ o + 8 < 4294967295 then
    let u := USize.ofNat o
    (d.uget (u + USize.ofNat 0) (uidx_lt d o 0 h (by decide))).toUInt64 |||
      ((d.uget (u + USize.ofNat 1) (uidx_lt d o 1 h (by decide))).toUInt64 <<< 8) |||
      ((d.uget (u + USize.ofNat 2) (uidx_lt d o 2 h (by decide))).toUInt64 <<< 16) |||
      ((d.uget (u + USize.ofNat 3) (uidx_lt d o 3 h (by decide))).toUInt64 <<< 24) |||
      ((d.uget (u + USize.ofNat 4) (uidx_lt d o 4 h (by decide))).toUInt64 <<< 32) |||
      ((d.uget (u + USize.ofNat 5) (uidx_lt d o 5 h (by decide))).toUInt64 <<< 40) |||
      ((d.uget (u + USize.ofNat 6) (uidx_lt d o 6 h (by decide))).toUInt64 <<< 48) |||
      ((d.uget (u + USize.ofNat 7) (uidx_lt d o 7 h (by decide))).toUInt64 <<< 56)
  else ld d o

/-- `ldu` when the bounds test is already known to hold, so a caller that checks a whole block once reads each lane without a test. -/
@[inline] def ldb (d : ByteArray) (o : Nat) (h : o + 8 ≤ d.size ∧ o + 8 < 4294967295) : UInt64 :=
  let u := USize.ofNat o
  (d.uget (u + USize.ofNat 0) (uidx_lt d o 0 h (by decide))).toUInt64 |||
    ((d.uget (u + USize.ofNat 1) (uidx_lt d o 1 h (by decide))).toUInt64 <<< 8) |||
    ((d.uget (u + USize.ofNat 2) (uidx_lt d o 2 h (by decide))).toUInt64 <<< 16) |||
    ((d.uget (u + USize.ofNat 3) (uidx_lt d o 3 h (by decide))).toUInt64 <<< 24) |||
    ((d.uget (u + USize.ofNat 4) (uidx_lt d o 4 h (by decide))).toUInt64 <<< 32) |||
    ((d.uget (u + USize.ofNat 5) (uidx_lt d o 5 h (by decide))).toUInt64 <<< 40) |||
    ((d.uget (u + USize.ofNat 6) (uidx_lt d o 6 h (by decide))).toUInt64 <<< 48) |||
    ((d.uget (u + USize.ofNat 7) (uidx_lt d o 7 h (by decide))).toUInt64 <<< 56)

/-- Byte `i` of `pre ‖ d[off, …)`. -/
@[inline] def mB (pre d : ByteArray) (off i : Nat) : UInt8 :=
  if i < pre.size then pre[i]! else d[off + (i - pre.size)]!

/-- The lane at byte `o` of `pre ‖ d[off, …)`. -/
@[inline] def mLane (pre d : ByteArray) (off o : Nat) : UInt64 :=
  if o + 8 ≤ pre.size then ldu pre o
  else if pre.size ≤ o then ldu d (off + (o - pre.size))
  else L8 (mB pre d off o) (mB pre d off (o + 1)) (mB pre d off (o + 2)) (mB pre d off (o + 3)) (mB pre d off (o + 4))
    (mB pre d off (o + 5)) (mB pre d off (o + 6)) (mB pre d off (o + 7))

/-- Byte `j` of the padded final block: `rem` message bytes from `fb`, the suffix 0x06, zeros, and 0x80 in byte 71. -/
@[inline] def tB (pre d : ByteArray) (off fb rem j : Nat) : UInt8 :=
  let b : UInt8 := if j < rem then mB pre d off (fb + j) else if j = rem then 6 else 0
  if j = 71 then b ||| 0x80 else b

/-- The lane at byte `o` (`o ≤ 64`) of the padded final block. -/
@[inline] def tLane (pre d : ByteArray) (off fb rem o : Nat) : UInt64 :=
  if o + 8 ≤ rem then mLane pre d off (fb + o)
  else if rem < o then (if o = 64 then 0x8000000000000000 else 0)
  else L8 (tB pre d off fb rem o) (tB pre d off fb rem (o + 1)) (tB pre d off fb rem (o + 2)) (tB pre d off fb rem (o + 3))
    (tB pre d off fb rem (o + 4)) (tB pre d off fb rem (o + 5)) (tB pre d off fb rem (o + 6)) (tB pre d off fb rem (o + 7))

/-- `tLane`, compiled once instead of at each of the nine lanes of the final block. -/
@[noinline] def tL (pre d : ByteArray) (off fb rem o : Nat) : UInt64 := tLane pre d off fb rem o

/-- The 64 digest bytes from the first eight lanes, as `squeezeK` writes them. -/
def sqLanes (a0 a1 a2 a3 a4 a5 a6 a7 : UInt64) : ByteArray :=
  let out := zeros.extract 0 64
  set8 (set8 (set8 (set8 (set8 (set8 (set8 (set8 out 0 a0) 8 (a1 ^^^ ones)) 16 (a2 ^^^ ones)) 24 a3) 32 a4) 40 a5) 48 a6) 56 a7

/-- `mLane`, compiled once. -/
@[noinline] def mLaneN (pre d : ByteArray) (off o : Nat) : UInt64 := mLane pre d off o

def run (acc pre d : ByteArray) (off fb rem : Nat) :
    (t : @& Lanes.Rc) → (n o : Nat) → (a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 a10 a11 a12 a13 a14 a15 a16 a17 a18 a19 a20 a21 a22 a23 a24 : UInt64) → ByteArray
  | .nil, 0, _, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24 =>
    acc ++ sqLanes a0 a1 a2 a3 a4 a5 a6 a7
  | .nil, n + 1, o, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24 =>
    if n = 0 then
      run acc pre d off fb rem Lanes.rcTab n (o + 72) (a0 ^^^ (tL pre d off fb rem 0)) (a1 ^^^ (tL pre d off fb rem 8)) (a2 ^^^ (tL pre d off fb rem 16)) (a3 ^^^ (tL pre d off fb rem 24)) (a4 ^^^ (tL pre d off fb rem 32)) (a5 ^^^ (tL pre d off fb rem 40)) (a6 ^^^ (tL pre d off fb rem 48)) (a7 ^^^ (tL pre d off fb rem 56)) (a8 ^^^ (tL pre d off fb rem 64)) a9 a10 a11 a12 a13 a14 a15 a16 a17 a18 a19 a20 a21 a22 a23 a24
    else if h1 : pre.size ≤ o then
      if h : off + (o - pre.size) + 72 ≤ d.size ∧ off + (o - pre.size) + 72 < 4294967295 then
        run acc pre d off fb rem Lanes.rcTab n (o + 72) (a0 ^^^ (ldb d (off + (o - pre.size)) (by omega))) (a1 ^^^ (ldb d (off + (o - pre.size) + 8) (by omega))) (a2 ^^^ (ldb d (off + (o - pre.size) + 16) (by omega))) (a3 ^^^ (ldb d (off + (o - pre.size) + 24) (by omega))) (a4 ^^^ (ldb d (off + (o - pre.size) + 32) (by omega))) (a5 ^^^ (ldb d (off + (o - pre.size) + 40) (by omega))) (a6 ^^^ (ldb d (off + (o - pre.size) + 48) (by omega))) (a7 ^^^ (ldb d (off + (o - pre.size) + 56) (by omega))) (a8 ^^^ (ldb d (off + (o - pre.size) + 64) (by omega))) a9 a10 a11 a12 a13 a14 a15 a16 a17 a18 a19 a20 a21 a22 a23 a24
      else
        run acc pre d off fb rem Lanes.rcTab n (o + 72) (a0 ^^^ (mLaneN pre d off o)) (a1 ^^^ (mLaneN pre d off (o + 8))) (a2 ^^^ (mLaneN pre d off (o + 16))) (a3 ^^^ (mLaneN pre d off (o + 24))) (a4 ^^^ (mLaneN pre d off (o + 32))) (a5 ^^^ (mLaneN pre d off (o + 40))) (a6 ^^^ (mLaneN pre d off (o + 48))) (a7 ^^^ (mLaneN pre d off (o + 56))) (a8 ^^^ (mLaneN pre d off (o + 64))) a9 a10 a11 a12 a13 a14 a15 a16 a17 a18 a19 a20 a21 a22 a23 a24
    else if h : o + 72 ≤ pre.size ∧ o + 72 < 4294967295 then
      run acc pre d off fb rem Lanes.rcTab n (o + 72) (a0 ^^^ (ldb pre o (by omega))) (a1 ^^^ (ldb pre (o + 8) (by omega))) (a2 ^^^ (ldb pre (o + 16) (by omega))) (a3 ^^^ (ldb pre (o + 24) (by omega))) (a4 ^^^ (ldb pre (o + 32) (by omega))) (a5 ^^^ (ldb pre (o + 40) (by omega))) (a6 ^^^ (ldb pre (o + 48) (by omega))) (a7 ^^^ (ldb pre (o + 56) (by omega))) (a8 ^^^ (ldb pre (o + 64) (by omega))) a9 a10 a11 a12 a13 a14 a15 a16 a17 a18 a19 a20 a21 a22 a23 a24
    else
      run acc pre d off fb rem Lanes.rcTab n (o + 72) (a0 ^^^ (mLaneN pre d off o)) (a1 ^^^ (mLaneN pre d off (o + 8))) (a2 ^^^ (mLaneN pre d off (o + 16))) (a3 ^^^ (mLaneN pre d off (o + 24))) (a4 ^^^ (mLaneN pre d off (o + 32))) (a5 ^^^ (mLaneN pre d off (o + 40))) (a6 ^^^ (mLaneN pre d off (o + 48))) (a7 ^^^ (mLaneN pre d off (o + 56))) (a8 ^^^ (mLaneN pre d off (o + 64))) a9 a10 a11 a12 a13 a14 a15 a16 a17 a18 a19 a20 a21 a22 a23 a24
  | .cons r0 r1 r2 r3 tl, n, o, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24 =>
    let s := Lanes.rounds4 r0 r1 r2 r3 a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 a10 a11 a12 a13 a14 a15 a16 a17 a18 a19 a20 a21 a22 a23 a24
    run acc pre d off fb rem tl n o s.a0 s.a1 s.a2 s.a3 s.a4 s.a5 s.a6 s.a7 s.a8 s.a9 s.a10 s.a11 s.a12 s.a13 s.a14 s.a15 s.a16 s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23 s.a24
termination_by t n => (n, t)

/-- `acc` followed by the SHA3-512 of `pre ‖ d[off, off + len)`, in one loop that carries the lanes as arguments (`run_nil`, `runS_eq`). -/
def sha3_512Into (acc pre d : ByteArray) (off len : Nat) : ByteArray :=
  run acc pre d off ((pre.size + len) / 72 * 72) ((pre.size + len) - (pre.size + len) / 72 * 72) .nil ((pre.size + len) / 72 + 1) 0
    flipped.a0 flipped.a1 flipped.a2 flipped.a3 flipped.a4 flipped.a5 flipped.a6 flipped.a7 flipped.a8 flipped.a9 flipped.a10 flipped.a11 flipped.a12 flipped.a13 flipped.a14 flipped.a15 flipped.a16 flipped.a17 flipped.a18 flipped.a19 flipped.a20 flipped.a21 flipped.a22 flipped.a23 flipped.a24

end BlindLedger.Gate.Engine3
