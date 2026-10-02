/-! Fast twin of `Sha3.lean`: the same sponge over 25 unboxed `UInt64` fields instead of a boxed `Array UInt64`,
    pure Lean (no `@[extern]`, no `implemented_by`, no `partial`).  `sha3_512Fast`, `shake128Fast` and `shake256Fast`
    equal `sha3_512`, `shake128` and `shake256` for every input (`Sha3FastEq.lean`).  Not imported by the gate or any
    pinned executable; the twin runs about 30 times faster. -/
namespace BlindLedger.Semantic
namespace Fast

@[inline] def rl (v : UInt64) (n : UInt64) : UInt64 := (v <<< n) ||| (v >>> (64 - n))

def roundConstants : Array UInt64 := #[
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

def zero : St := {
  a0 := 0,
  a1 := 0,
  a2 := 0,
  a3 := 0,
  a4 := 0,
  a5 := 0,
  a6 := 0,
  a7 := 0,
  a8 := 0,
  a9 := 0,
  a10 := 0,
  a11 := 0,
  a12 := 0,
  a13 := 0,
  a14 := 0,
  a15 := 0,
  a16 := 0,
  a17 := 0,
  a18 := 0,
  a19 := 0,
  a20 := 0,
  a21 := 0,
  a22 := 0,
  a23 := 0,
  a24 := 0
}

def round (s : St) (rc : UInt64) : St :=
  let c0 := s.a0 ^^^ s.a5 ^^^ s.a10 ^^^ s.a15 ^^^ s.a20
  let c1 := s.a1 ^^^ s.a6 ^^^ s.a11 ^^^ s.a16 ^^^ s.a21
  let c2 := s.a2 ^^^ s.a7 ^^^ s.a12 ^^^ s.a17 ^^^ s.a22
  let c3 := s.a3 ^^^ s.a8 ^^^ s.a13 ^^^ s.a18 ^^^ s.a23
  let c4 := s.a4 ^^^ s.a9 ^^^ s.a14 ^^^ s.a19 ^^^ s.a24
  let d0 := c4 ^^^ rl c1 1
  let d1 := c0 ^^^ rl c2 1
  let d2 := c1 ^^^ rl c3 1
  let d3 := c2 ^^^ rl c4 1
  let d4 := c3 ^^^ rl c0 1
  let b0 := s.a0 ^^^ d0
  let b16 := rl (s.a5 ^^^ d0) 36
  let b7 := rl (s.a10 ^^^ d0) 3
  let b23 := rl (s.a15 ^^^ d0) 41
  let b14 := rl (s.a20 ^^^ d0) 18
  let b10 := rl (s.a1 ^^^ d1) 1
  let b1 := rl (s.a6 ^^^ d1) 44
  let b17 := rl (s.a11 ^^^ d1) 10
  let b8 := rl (s.a16 ^^^ d1) 45
  let b24 := rl (s.a21 ^^^ d1) 2
  let b20 := rl (s.a2 ^^^ d2) 62
  let b11 := rl (s.a7 ^^^ d2) 6
  let b2 := rl (s.a12 ^^^ d2) 43
  let b18 := rl (s.a17 ^^^ d2) 15
  let b9 := rl (s.a22 ^^^ d2) 61
  let b5 := rl (s.a3 ^^^ d3) 28
  let b21 := rl (s.a8 ^^^ d3) 55
  let b12 := rl (s.a13 ^^^ d3) 25
  let b3 := rl (s.a18 ^^^ d3) 21
  let b19 := rl (s.a23 ^^^ d3) 56
  let b15 := rl (s.a4 ^^^ d4) 27
  let b6 := rl (s.a9 ^^^ d4) 20
  let b22 := rl (s.a14 ^^^ d4) 39
  let b13 := rl (s.a19 ^^^ d4) 8
  let b4 := rl (s.a24 ^^^ d4) 14
  let o0 := b0 ^^^ ((~~~b1) &&& b2) ^^^ rc
  let o1 := b1 ^^^ ((~~~b2) &&& b3)
  let o2 := b2 ^^^ ((~~~b3) &&& b4)
  let o3 := b3 ^^^ ((~~~b4) &&& b0)
  let o4 := b4 ^^^ ((~~~b0) &&& b1)
  let o5 := b5 ^^^ ((~~~b6) &&& b7)
  let o6 := b6 ^^^ ((~~~b7) &&& b8)
  let o7 := b7 ^^^ ((~~~b8) &&& b9)
  let o8 := b8 ^^^ ((~~~b9) &&& b5)
  let o9 := b9 ^^^ ((~~~b5) &&& b6)
  let o10 := b10 ^^^ ((~~~b11) &&& b12)
  let o11 := b11 ^^^ ((~~~b12) &&& b13)
  let o12 := b12 ^^^ ((~~~b13) &&& b14)
  let o13 := b13 ^^^ ((~~~b14) &&& b10)
  let o14 := b14 ^^^ ((~~~b10) &&& b11)
  let o15 := b15 ^^^ ((~~~b16) &&& b17)
  let o16 := b16 ^^^ ((~~~b17) &&& b18)
  let o17 := b17 ^^^ ((~~~b18) &&& b19)
  let o18 := b18 ^^^ ((~~~b19) &&& b15)
  let o19 := b19 ^^^ ((~~~b15) &&& b16)
  let o20 := b20 ^^^ ((~~~b21) &&& b22)
  let o21 := b21 ^^^ ((~~~b22) &&& b23)
  let o22 := b22 ^^^ ((~~~b23) &&& b24)
  let o23 := b23 ^^^ ((~~~b24) &&& b20)
  let o24 := b24 ^^^ ((~~~b20) &&& b21)
  { a0 := o0, a1 := o1, a2 := o2, a3 := o3, a4 := o4, a5 := o5, a6 := o6, a7 := o7, a8 := o8, a9 := o9, a10 := o10, a11 := o11, a12 := o12, a13 := o13, a14 := o14, a15 := o15, a16 := o16, a17 := o17, a18 := o18, a19 := o19, a20 := o20, a21 := o21, a22 := o22, a23 := o23, a24 := o24 }

def keccakF (s : St) : St := Id.run do
  let mut st := s
  for r in [0:24] do st := round st (roundConstants[r]!)
  return st

def lane (s : St) (i : Nat) : UInt64 :=
  match i with
  | 0 => s.a0
  | 1 => s.a1
  | 2 => s.a2
  | 3 => s.a3
  | 4 => s.a4
  | 5 => s.a5
  | 6 => s.a6
  | 7 => s.a7
  | 8 => s.a8
  | 9 => s.a9
  | 10 => s.a10
  | 11 => s.a11
  | 12 => s.a12
  | 13 => s.a13
  | 14 => s.a14
  | 15 => s.a15
  | 16 => s.a16
  | 17 => s.a17
  | 18 => s.a18
  | 19 => s.a19
  | 20 => s.a20
  | 21 => s.a21
  | 22 => s.a22
  | 23 => s.a23
  | _ => s.a24

@[inline] def loadF (f : Nat → UInt8) (o : Nat) : UInt64 :=
  (f o).toUInt64 ||| ((f (o+1)).toUInt64 <<< 8) ||| ((f (o+2)).toUInt64 <<< 16) ||| ((f (o+3)).toUInt64 <<< 24) |||
  ((f (o+4)).toUInt64 <<< 32) ||| ((f (o+5)).toUInt64 <<< 40) ||| ((f (o+6)).toUInt64 <<< 48) ||| ((f (o+7)).toUInt64 <<< 56)

/-- XOR the first `nl` lanes of the block at `o` in `d` into `s`. -/
@[specialize] def absorb (s : St) (f : Nat → UInt8) (o nl : Nat) : St :=
  let v0 := if 0 < nl then s.a0 ^^^ loadF f (o + 0) else s.a0
  let v1 := if 1 < nl then s.a1 ^^^ loadF f (o + 8) else s.a1
  let v2 := if 2 < nl then s.a2 ^^^ loadF f (o + 16) else s.a2
  let v3 := if 3 < nl then s.a3 ^^^ loadF f (o + 24) else s.a3
  let v4 := if 4 < nl then s.a4 ^^^ loadF f (o + 32) else s.a4
  let v5 := if 5 < nl then s.a5 ^^^ loadF f (o + 40) else s.a5
  let v6 := if 6 < nl then s.a6 ^^^ loadF f (o + 48) else s.a6
  let v7 := if 7 < nl then s.a7 ^^^ loadF f (o + 56) else s.a7
  let v8 := if 8 < nl then s.a8 ^^^ loadF f (o + 64) else s.a8
  let v9 := if 9 < nl then s.a9 ^^^ loadF f (o + 72) else s.a9
  let v10 := if 10 < nl then s.a10 ^^^ loadF f (o + 80) else s.a10
  let v11 := if 11 < nl then s.a11 ^^^ loadF f (o + 88) else s.a11
  let v12 := if 12 < nl then s.a12 ^^^ loadF f (o + 96) else s.a12
  let v13 := if 13 < nl then s.a13 ^^^ loadF f (o + 104) else s.a13
  let v14 := if 14 < nl then s.a14 ^^^ loadF f (o + 112) else s.a14
  let v15 := if 15 < nl then s.a15 ^^^ loadF f (o + 120) else s.a15
  let v16 := if 16 < nl then s.a16 ^^^ loadF f (o + 128) else s.a16
  let v17 := if 17 < nl then s.a17 ^^^ loadF f (o + 136) else s.a17
  let v18 := if 18 < nl then s.a18 ^^^ loadF f (o + 144) else s.a18
  let v19 := if 19 < nl then s.a19 ^^^ loadF f (o + 152) else s.a19
  let v20 := if 20 < nl then s.a20 ^^^ loadF f (o + 160) else s.a20
  let v21 := if 21 < nl then s.a21 ^^^ loadF f (o + 168) else s.a21
  let v22 := if 22 < nl then s.a22 ^^^ loadF f (o + 176) else s.a22
  let v23 := if 23 < nl then s.a23 ^^^ loadF f (o + 184) else s.a23
  let v24 := if 24 < nl then s.a24 ^^^ loadF f (o + 192) else s.a24
  { a0 := v0, a1 := v1, a2 := v2, a3 := v3, a4 := v4, a5 := v5, a6 := v6, a7 := v7, a8 := v8, a9 := v9, a10 := v10, a11 := v11, a12 := v12, a13 := v13, a14 := v14, a15 := v15, a16 := v16, a17 := v17, a18 := v18, a19 := v19, a20 := v20, a21 := v21, a22 := v22, a23 := v23, a24 := v24 }

/-- Byte `j` of the padded message: `data`, then `suffix`, then zeros, with 0x80 or-ed into the last byte of `total`. -/
def padByte (data : ByteArray) (suffix : UInt8) (total j : Nat) : UInt8 :=
  (if j < data.size then data.get! j else if j = data.size then suffix else 0) ||| (if j = total - 1 then 0x80 else 0)

def sponge (rate : Nat) (suffix : UInt8) (data : ByteArray) (n : Nat) : ByteArray := Id.run do
  let full := data.size / rate
  let nl := rate / 8
  let mut st := zero
  for blk in [0:full] do
    st := keccakF (absorb st (data.get! ·) (blk * rate) nl)
  st := keccakF (absorb st (padByte data suffix ((full + 1) * rate)) (full * rate) nl)
  let mut out := ByteArray.empty
  for blk in [0:(n + rate - 1) / rate] do
    if blk > 0 then st := keccakF st
    for j in [0:rate] do
      if out.size < n then out := out.push (lane st (j / 8) >>> UInt64.ofNat (8 * (j % 8))).toUInt8
  return out

end Fast

def sha3_512Fast (data : ByteArray) : ByteArray := Fast.sponge 72 0x06 data 64
def shake128Fast (data : ByteArray) (n : Nat) : ByteArray := Fast.sponge 168 0x1F data n
def shake256Fast (data : ByteArray) (n : Nat) : ByteArray := Fast.sponge 136 0x1F data n

/-! Known answers: SHA3-512 of the empty string, of "abc" and of the 1600-bit message of 0xA3 bytes (FIPS 202 examples),
    and the first 32 bytes of SHAKE128("abc") and SHAKE256("abc"). -/
private def hex (b : ByteArray) : String :=
  String.join (b.toList.map fun x =>
    let h := Nat.toDigits 16 x.toNat
    String.ofList (if h.length < 2 then '0' :: h else h))

#guard hex (sha3_512Fast ByteArray.empty) ==
  "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
#guard hex (sha3_512Fast "abc".toUTF8) ==
  "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
#guard hex (sha3_512Fast ⟨Array.replicate 200 0xA3⟩) ==
  "e76dfad22084a8b1467fcf2ffa58361bec7628edf5f3fdc0e4805dc48caeeca81b7c13c30adf52a3659584739a2df46be589c51ca1a4a8416df6545a1ce8ba00"
#guard hex (shake128Fast "abc".toUTF8 32) == "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"
#guard hex (shake256Fast "abc".toUTF8 32) == "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"

end BlindLedger.Semantic
