/-! Faster twin of `Sha3Fast.lean`: the permutation runs as a tail loop over 25 `UInt64` arguments (no state object per
    round), lanes are read eight bytes at a time straight from the input, the last block is padded in one small buffer,
    and the digest is written lane by lane.  Pure Lean, no `@[extern]`, no `unsafe`, no `partial`.  The equality with
    `Sha3Fast` (and so with FIPS 202) is stated in `Sha3QuickEq.lean`. -/
namespace BlindLedger.Semantic
namespace Quick

@[inline] def rl (v : UInt64) (n : UInt64) : UInt64 := (v <<< n) ||| (v >>> (64 - n))

def rcs : Array UInt64 := #[
  0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
  0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
  0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
  0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
  0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
  0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]

structure St where
  a0 : UInt64
  a1 : UInt64
  a2 : UInt64
  a3 : UInt64
  a4 : UInt64
  a5 : UInt64
  a6 : UInt64
  a7 : UInt64
  a8 : UInt64
  a9 : UInt64
  a10 : UInt64
  a11 : UInt64
  a12 : UInt64
  a13 : UInt64
  a14 : UInt64
  a15 : UInt64
  a16 : UInt64
  a17 : UInt64
  a18 : UInt64
  a19 : UInt64
  a20 : UInt64
  a21 : UInt64
  a22 : UInt64
  a23 : UInt64
  a24 : UInt64

set_option maxRecDepth 100000 in
/-- Keccak-f[1600] with six lanes held complemented (lanes 1, 2, 8, 12, 17, 20), which removes most of the NOT steps of chi: a stored lane is the true lane xor `flip` (all ones for those six).
    2 rounds are written out per loop step, each in plane order (`plane_order`). -/
def perm : (n : Nat) → (a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 a10 a11 a12 a13 a14 a15 a16 a17 a18 a19 a20 a21 a22 a23 a24 : UInt64) → St
  | 0, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24 => ⟨a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24⟩
  | n + 1, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24 =>
    let c0_0 := (a0 ^^^ a5 ^^^ a10 ^^^ a15 ^^^ a20)
    let c1_0 := (a1 ^^^ a6 ^^^ a11 ^^^ a16 ^^^ a21)
    let c2_0 := (a2 ^^^ a7 ^^^ a12 ^^^ a17 ^^^ a22)
    let c3_0 := (a3 ^^^ a8 ^^^ a13 ^^^ a18 ^^^ a23)
    let c4_0 := (a4 ^^^ a9 ^^^ a14 ^^^ a19 ^^^ a24)
    let d0_0 := (c4_0 ^^^ (rl c1_0 1))
    let d1_0 := (c0_0 ^^^ (rl c2_0 1))
    let d2_0 := (c1_0 ^^^ (rl c3_0 1))
    let d3_0 := (c2_0 ^^^ (rl c4_0 1))
    let d4_0 := (c3_0 ^^^ (rl c0_0 1))
    let b0_0 := (a0 ^^^ d0_0)
    let b1_0 := (rl (a6 ^^^ d1_0) 44)
    let b2_0 := (rl (a12 ^^^ d2_0) 43)
    let b3_0 := (rl (a18 ^^^ d3_0) 21)
    let b4_0 := (rl (a24 ^^^ d4_0) 14)
    let o0_0 := (b0_0 ^^^ (b1_0 ||| b2_0) ^^^ (rcs[2*(12-(n+1))+0]!))
    let o1_0 := (~~~(b1_0 ^^^ (b2_0 &&& (~~~b3_0))))
    let o2_0 := (b2_0 ^^^ (b3_0 &&& b4_0))
    let o3_0 := (b3_0 ^^^ (b4_0 ||| b0_0))
    let o4_0 := (b4_0 ^^^ (b0_0 &&& b1_0))
    let b5_0 := (rl (a3 ^^^ d3_0) 28)
    let b6_0 := (rl (a9 ^^^ d4_0) 20)
    let b7_0 := (rl (a10 ^^^ d0_0) 3)
    let b8_0 := (rl (a16 ^^^ d1_0) 45)
    let b9_0 := (rl (a22 ^^^ d2_0) 61)
    let o5_0 := (b5_0 ^^^ (b6_0 ||| b7_0))
    let o6_0 := (b6_0 ^^^ (b7_0 &&& b8_0))
    let o7_0 := (~~~(b7_0 ^^^ ((~~~b8_0) &&& b9_0)))
    let o8_0 := (b8_0 ^^^ (b9_0 ||| b5_0))
    let o9_0 := (b9_0 ^^^ (b5_0 &&& b6_0))
    let b10_0 := (rl (a1 ^^^ d1_0) 1)
    let b11_0 := (rl (a7 ^^^ d2_0) 6)
    let b12_0 := (rl (a13 ^^^ d3_0) 25)
    let b13_0 := (rl (a19 ^^^ d4_0) 8)
    let b14_0 := (rl (a20 ^^^ d0_0) 18)
    let o10_0 := (b10_0 ^^^ (b11_0 ||| b12_0))
    let o11_0 := (b11_0 ^^^ (b12_0 &&& b13_0))
    let o12_0 := (b12_0 ^^^ ((~~~b13_0) &&& b14_0))
    let o13_0 := (~~~(b13_0 ^^^ (b14_0 ||| b10_0)))
    let o14_0 := (b14_0 ^^^ (b10_0 &&& b11_0))
    let b15_0 := (rl (a4 ^^^ d4_0) 27)
    let b16_0 := (rl (a5 ^^^ d0_0) 36)
    let b17_0 := (rl (a11 ^^^ d1_0) 10)
    let b18_0 := (rl (a17 ^^^ d2_0) 15)
    let b19_0 := (rl (a23 ^^^ d3_0) 56)
    let o15_0 := (b15_0 ^^^ (b16_0 &&& b17_0))
    let o16_0 := (b16_0 ^^^ (b17_0 ||| b18_0))
    let o17_0 := (~~~(b17_0 ^^^ (b18_0 &&& (~~~b19_0))))
    let o18_0 := (~~~(b18_0 ^^^ (b19_0 &&& b15_0)))
    let o19_0 := (b19_0 ^^^ (b15_0 ||| b16_0))
    let b20_0 := (rl (a2 ^^^ d2_0) 62)
    let b21_0 := (rl (a8 ^^^ d3_0) 55)
    let b22_0 := (rl (a14 ^^^ d4_0) 39)
    let b23_0 := (rl (a15 ^^^ d0_0) 41)
    let b24_0 := (rl (a21 ^^^ d1_0) 2)
    let o20_0 := (b20_0 ^^^ ((~~~b21_0) &&& b22_0))
    let o21_0 := (~~~(b21_0 ^^^ (b22_0 ||| b23_0)))
    let o22_0 := (b22_0 ^^^ (b23_0 &&& b24_0))
    let o23_0 := (b23_0 ^^^ (b24_0 ||| b20_0))
    let o24_0 := (b24_0 ^^^ (b20_0 &&& b21_0))
    let c0_1 := (o0_0 ^^^ o5_0 ^^^ o10_0 ^^^ o15_0 ^^^ o20_0)
    let c1_1 := (o1_0 ^^^ o6_0 ^^^ o11_0 ^^^ o16_0 ^^^ o21_0)
    let c2_1 := (o2_0 ^^^ o7_0 ^^^ o12_0 ^^^ o17_0 ^^^ o22_0)
    let c3_1 := (o3_0 ^^^ o8_0 ^^^ o13_0 ^^^ o18_0 ^^^ o23_0)
    let c4_1 := (o4_0 ^^^ o9_0 ^^^ o14_0 ^^^ o19_0 ^^^ o24_0)
    let d0_1 := (c4_1 ^^^ (rl c1_1 1))
    let d1_1 := (c0_1 ^^^ (rl c2_1 1))
    let d2_1 := (c1_1 ^^^ (rl c3_1 1))
    let d3_1 := (c2_1 ^^^ (rl c4_1 1))
    let d4_1 := (c3_1 ^^^ (rl c0_1 1))
    let b0_1 := (o0_0 ^^^ d0_1)
    let b1_1 := (rl (o6_0 ^^^ d1_1) 44)
    let b2_1 := (rl (o12_0 ^^^ d2_1) 43)
    let b3_1 := (rl (o18_0 ^^^ d3_1) 21)
    let b4_1 := (rl (o24_0 ^^^ d4_1) 14)
    let o0_1 := (b0_1 ^^^ (b1_1 ||| b2_1) ^^^ (rcs[2*(12-(n+1))+1]!))
    let o1_1 := (~~~(b1_1 ^^^ (b2_1 &&& (~~~b3_1))))
    let o2_1 := (b2_1 ^^^ (b3_1 &&& b4_1))
    let o3_1 := (b3_1 ^^^ (b4_1 ||| b0_1))
    let o4_1 := (b4_1 ^^^ (b0_1 &&& b1_1))
    let b5_1 := (rl (o3_0 ^^^ d3_1) 28)
    let b6_1 := (rl (o9_0 ^^^ d4_1) 20)
    let b7_1 := (rl (o10_0 ^^^ d0_1) 3)
    let b8_1 := (rl (o16_0 ^^^ d1_1) 45)
    let b9_1 := (rl (o22_0 ^^^ d2_1) 61)
    let o5_1 := (b5_1 ^^^ (b6_1 ||| b7_1))
    let o6_1 := (b6_1 ^^^ (b7_1 &&& b8_1))
    let o7_1 := (~~~(b7_1 ^^^ ((~~~b8_1) &&& b9_1)))
    let o8_1 := (b8_1 ^^^ (b9_1 ||| b5_1))
    let o9_1 := (b9_1 ^^^ (b5_1 &&& b6_1))
    let b10_1 := (rl (o1_0 ^^^ d1_1) 1)
    let b11_1 := (rl (o7_0 ^^^ d2_1) 6)
    let b12_1 := (rl (o13_0 ^^^ d3_1) 25)
    let b13_1 := (rl (o19_0 ^^^ d4_1) 8)
    let b14_1 := (rl (o20_0 ^^^ d0_1) 18)
    let o10_1 := (b10_1 ^^^ (b11_1 ||| b12_1))
    let o11_1 := (b11_1 ^^^ (b12_1 &&& b13_1))
    let o12_1 := (b12_1 ^^^ ((~~~b13_1) &&& b14_1))
    let o13_1 := (~~~(b13_1 ^^^ (b14_1 ||| b10_1)))
    let o14_1 := (b14_1 ^^^ (b10_1 &&& b11_1))
    let b15_1 := (rl (o4_0 ^^^ d4_1) 27)
    let b16_1 := (rl (o5_0 ^^^ d0_1) 36)
    let b17_1 := (rl (o11_0 ^^^ d1_1) 10)
    let b18_1 := (rl (o17_0 ^^^ d2_1) 15)
    let b19_1 := (rl (o23_0 ^^^ d3_1) 56)
    let o15_1 := (b15_1 ^^^ (b16_1 &&& b17_1))
    let o16_1 := (b16_1 ^^^ (b17_1 ||| b18_1))
    let o17_1 := (~~~(b17_1 ^^^ (b18_1 &&& (~~~b19_1))))
    let o18_1 := (~~~(b18_1 ^^^ (b19_1 &&& b15_1)))
    let o19_1 := (b19_1 ^^^ (b15_1 ||| b16_1))
    let b20_1 := (rl (o2_0 ^^^ d2_1) 62)
    let b21_1 := (rl (o8_0 ^^^ d3_1) 55)
    let b22_1 := (rl (o14_0 ^^^ d4_1) 39)
    let b23_1 := (rl (o15_0 ^^^ d0_1) 41)
    let b24_1 := (rl (o21_0 ^^^ d1_1) 2)
    let o20_1 := (b20_1 ^^^ ((~~~b21_1) &&& b22_1))
    let o21_1 := (~~~(b21_1 ^^^ (b22_1 ||| b23_1)))
    let o22_1 := (b22_1 ^^^ (b23_1 &&& b24_1))
    let o23_1 := (b23_1 ^^^ (b24_1 ||| b20_1))
    let o24_1 := (b24_1 ^^^ (b20_1 &&& b21_1))
    perm n o0_1 o1_1 o2_1 o3_1 o4_1 o5_1 o6_1 o7_1 o8_1 o9_1 o10_1 o11_1 o12_1 o13_1 o14_1 o15_1 o16_1 o17_1 o18_1 o19_1 o20_1 o21_1 o22_1 o23_1 o24_1

/-- Loop steps for one full permutation. -/
def permSteps : Nat := 12

def keccakF (s : St) : St :=
  perm permSteps s.a0 s.a1 s.a2 s.a3 s.a4 s.a5 s.a6 s.a7 s.a8 s.a9 s.a10 s.a11 s.a12 s.a13 s.a14 s.a15 s.a16 s.a17 s.a18 s.a19 s.a20 s.a21 s.a22 s.a23 s.a24

def ones : UInt64 := 0xFFFFFFFFFFFFFFFF

/-- Little-endian lane at byte `o`; zero past the end (never reached by the sponge). -/
@[inline] def ld (d : ByteArray) (o : Nat) : UInt64 :=
  if h : o + 7 < d.size then
    (d[o]'(by omega)).toUInt64 ||| ((d[o+1]'(by omega)).toUInt64 <<< 8) ||| ((d[o+2]'(by omega)).toUInt64 <<< 16) |||
    ((d[o+3]'(by omega)).toUInt64 <<< 24) ||| ((d[o+4]'(by omega)).toUInt64 <<< 32) ||| ((d[o+5]'(by omega)).toUInt64 <<< 40) |||
    ((d[o+6]'(by omega)).toUInt64 <<< 48) ||| ((d[o+7]'(by omega)).toUInt64 <<< 56)
  else 0

/-- XOR the first `nl` lanes of the block at byte `o` of `d` into `s`, then permute.  Lanes after `lim` other than the last are
    known to be zero (the padded tail) and are skipped. -/
def absorbF (s : St) (d : ByteArray) (o nl lim : Nat) : St :=
  perm permSteps
    (if 0 < nl && (0 ≤ lim || 0 + 1 == nl) then s.a0 ^^^ ld d o else s.a0) (if 1 < nl && (1 ≤ lim || 1 + 1 == nl) then s.a1 ^^^ ld d (o + 8) else s.a1)
    (if 2 < nl && (2 ≤ lim || 2 + 1 == nl) then s.a2 ^^^ ld d (o + 16) else s.a2) (if 3 < nl && (3 ≤ lim || 3 + 1 == nl) then s.a3 ^^^ ld d (o + 24) else s.a3)
    (if 4 < nl && (4 ≤ lim || 4 + 1 == nl) then s.a4 ^^^ ld d (o + 32) else s.a4) (if 5 < nl && (5 ≤ lim || 5 + 1 == nl) then s.a5 ^^^ ld d (o + 40) else s.a5)
    (if 6 < nl && (6 ≤ lim || 6 + 1 == nl) then s.a6 ^^^ ld d (o + 48) else s.a6) (if 7 < nl && (7 ≤ lim || 7 + 1 == nl) then s.a7 ^^^ ld d (o + 56) else s.a7)
    (if 8 < nl && (8 ≤ lim || 8 + 1 == nl) then s.a8 ^^^ ld d (o + 64) else s.a8) (if 9 < nl && (9 ≤ lim || 9 + 1 == nl) then s.a9 ^^^ ld d (o + 72) else s.a9)
    (if 10 < nl && (10 ≤ lim || 10 + 1 == nl) then s.a10 ^^^ ld d (o + 80) else s.a10) (if 11 < nl && (11 ≤ lim || 11 + 1 == nl) then s.a11 ^^^ ld d (o + 88) else s.a11)
    (if 12 < nl && (12 ≤ lim || 12 + 1 == nl) then s.a12 ^^^ ld d (o + 96) else s.a12) (if 13 < nl && (13 ≤ lim || 13 + 1 == nl) then s.a13 ^^^ ld d (o + 104) else s.a13)
    (if 14 < nl && (14 ≤ lim || 14 + 1 == nl) then s.a14 ^^^ ld d (o + 112) else s.a14) (if 15 < nl && (15 ≤ lim || 15 + 1 == nl) then s.a15 ^^^ ld d (o + 120) else s.a15)
    (if 16 < nl && (16 ≤ lim || 16 + 1 == nl) then s.a16 ^^^ ld d (o + 128) else s.a16) (if 17 < nl && (17 ≤ lim || 17 + 1 == nl) then s.a17 ^^^ ld d (o + 136) else s.a17)
    (if 18 < nl && (18 ≤ lim || 18 + 1 == nl) then s.a18 ^^^ ld d (o + 144) else s.a18) (if 19 < nl && (19 ≤ lim || 19 + 1 == nl) then s.a19 ^^^ ld d (o + 152) else s.a19)
    (if 20 < nl && (20 ≤ lim || 20 + 1 == nl) then s.a20 ^^^ ld d (o + 160) else s.a20) (if 21 < nl && (21 ≤ lim || 21 + 1 == nl) then s.a21 ^^^ ld d (o + 168) else s.a21)
    (if 22 < nl && (22 ≤ lim || 22 + 1 == nl) then s.a22 ^^^ ld d (o + 176) else s.a22) (if 23 < nl && (23 ≤ lim || 23 + 1 == nl) then s.a23 ^^^ ld d (o + 184) else s.a23)
    (if 24 < nl && (24 ≤ lim || 24 + 1 == nl) then s.a24 ^^^ ld d (o + 192) else s.a24)

def zeros : ByteArray := ByteArray.mk (Array.replicate 168 0)

/-- Write the eight bytes of `v` at `o`, least significant first. -/
@[inline] def set8 (b : ByteArray) (o : Nat) (v : UInt64) : ByteArray :=
  (((((((b.set! o v.toUInt8).set! (o+1) (v >>> 8).toUInt8).set! (o+2) (v >>> 16).toUInt8).set! (o+3) (v >>> 24).toUInt8).set! (o+4) (v >>> 32).toUInt8).set!
    (o+5) (v >>> 40).toUInt8).set! (o+6) (v >>> 48).toUInt8).set! (o+7) (v >>> 56).toUInt8

/-- Write the low `cnt` bytes of `v` (`0 < cnt < 8`) at `o`. -/
@[inline] def setLane (b : ByteArray) (o : Nat) (v : UInt64) (cnt : Nat) : ByteArray :=
  let b := b.set! o v.toUInt8
  if cnt = 1 then b else
  let b := b.set! (o+1) (v >>> 8).toUInt8
  if cnt = 2 then b else
  let b := b.set! (o+2) (v >>> 16).toUInt8
  if cnt = 3 then b else
  let b := b.set! (o+3) (v >>> 24).toUInt8
  if cnt = 4 then b else
  let b := b.set! (o+4) (v >>> 32).toUInt8
  if cnt = 5 then b else
  let b := b.set! (o+5) (v >>> 40).toUInt8
  if cnt = 6 then b else
  b.set! (o+6) (v >>> 48).toUInt8

/-- The first `k` bytes (`0 ≤ k ≤ 168`) of the state's rate part, as a fresh array. -/
def squeezeK (s : St) (k : Nat) : ByteArray :=
  let out := zeros.extract 0 k
  if k < 8 then (if k = 0 then out else setLane out 0 s.a0 (k - 0)) else
  let out := set8 out 0 s.a0
  if k = 8 then out else
  if k < 16 then (if k = 8 then out else setLane out 8 (s.a1 ^^^ ones) (k - 8)) else
  let out := set8 out 8 (s.a1 ^^^ ones)
  if k = 16 then out else
  if k < 24 then (if k = 16 then out else setLane out 16 (s.a2 ^^^ ones) (k - 16)) else
  let out := set8 out 16 (s.a2 ^^^ ones)
  if k = 24 then out else
  if k < 32 then (if k = 24 then out else setLane out 24 s.a3 (k - 24)) else
  let out := set8 out 24 s.a3
  if k = 32 then out else
  if k < 40 then (if k = 32 then out else setLane out 32 s.a4 (k - 32)) else
  let out := set8 out 32 s.a4
  if k = 40 then out else
  if k < 48 then (if k = 40 then out else setLane out 40 s.a5 (k - 40)) else
  let out := set8 out 40 s.a5
  if k = 48 then out else
  if k < 56 then (if k = 48 then out else setLane out 48 s.a6 (k - 48)) else
  let out := set8 out 48 s.a6
  if k = 56 then out else
  if k < 64 then (if k = 56 then out else setLane out 56 s.a7 (k - 56)) else
  let out := set8 out 56 s.a7
  if k = 64 then out else
  if k < 72 then (if k = 64 then out else setLane out 64 (s.a8 ^^^ ones) (k - 64)) else
  let out := set8 out 64 (s.a8 ^^^ ones)
  if k = 72 then out else
  if k < 80 then (if k = 72 then out else setLane out 72 s.a9 (k - 72)) else
  let out := set8 out 72 s.a9
  if k = 80 then out else
  if k < 88 then (if k = 80 then out else setLane out 80 s.a10 (k - 80)) else
  let out := set8 out 80 s.a10
  if k = 88 then out else
  if k < 96 then (if k = 88 then out else setLane out 88 s.a11 (k - 88)) else
  let out := set8 out 88 s.a11
  if k = 96 then out else
  if k < 104 then (if k = 96 then out else setLane out 96 (s.a12 ^^^ ones) (k - 96)) else
  let out := set8 out 96 (s.a12 ^^^ ones)
  if k = 104 then out else
  if k < 112 then (if k = 104 then out else setLane out 104 s.a13 (k - 104)) else
  let out := set8 out 104 s.a13
  if k = 112 then out else
  if k < 120 then (if k = 112 then out else setLane out 112 s.a14 (k - 112)) else
  let out := set8 out 112 s.a14
  if k = 120 then out else
  if k < 128 then (if k = 120 then out else setLane out 120 s.a15 (k - 120)) else
  let out := set8 out 120 s.a15
  if k = 128 then out else
  if k < 136 then (if k = 128 then out else setLane out 128 s.a16 (k - 128)) else
  let out := set8 out 128 s.a16
  if k = 136 then out else
  if k < 144 then (if k = 136 then out else setLane out 136 (s.a17 ^^^ ones) (k - 136)) else
  let out := set8 out 136 (s.a17 ^^^ ones)
  if k = 144 then out else
  if k < 152 then (if k = 144 then out else setLane out 144 s.a18 (k - 144)) else
  let out := set8 out 144 s.a18
  if k = 152 then out else
  if k < 160 then (if k = 152 then out else setLane out 152 s.a19 (k - 152)) else
  let out := set8 out 152 s.a19
  if k = 160 then out else
  if k < 168 then setLane out 160 (s.a20 ^^^ ones) (k - 160) else set8 out 160 (s.a20 ^^^ ones)

/-- The all-zero state in the stored (complemented) form. -/
def flipped : St := ⟨0, ones, ones, 0, 0, 0, 0, 0, ones, 0, 0, 0, ones, 0, 0, 0, 0, ones, 0, 0, ones, 0, 0, 0, 0⟩

def absorbAll (rate : Nat) (data : ByteArray) : (n : Nat) → (blk : Nat) → St → St
  | 0, _, s => s
  | n + 1, blk, s => absorbAll rate data n (blk + 1) (absorbF s data (blk * rate) (rate / 8) 25)

def sponge (rate : Nat) (suffix : UInt8) (data : ByteArray) (n : Nat) : ByteArray :=
  let full := data.size / rate
  let rem := data.size - full * rate
  let st := absorbAll rate data full 0 flipped
  let tail := data.copySlice (full * rate) zeros 0 rem
  let tail := tail.set! rem suffix
  let tail := tail.set! (rate - 1) (tail.get! (rate - 1) ||| 0x80)
  let st := absorbF st tail 0 (rate / 8) (rem / 8)
  let rec go (fuel : Nat) (st : St) (out : ByteArray) (left : Nat) : ByteArray :=
    match fuel with
    | 0 => out
    | f + 1 =>
      let k := if left < rate then left else rate
      let out := if out.size = 0 then squeezeK st k else out ++ squeezeK st k
      if left ≤ rate then out else go f (keccakF st) out (left - rate)
  go (n / rate + 1) st ByteArray.empty n

end Quick

def sha3_512Quick (data : ByteArray) : ByteArray := Quick.sponge 72 0x06 data 64
def sha3_256Quick (data : ByteArray) : ByteArray := Quick.sponge 136 0x06 data 32
def shake128Quick (data : ByteArray) (n : Nat) : ByteArray := Quick.sponge 168 0x1F data n
def shake256Quick (data : ByteArray) (n : Nat) : ByteArray := Quick.sponge 136 0x1F data n

end BlindLedger.Semantic
