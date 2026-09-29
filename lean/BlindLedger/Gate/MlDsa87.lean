import BlindLedger.Keccak

/-! ML-DSA-87 verification, written from FIPS 204 (Algorithm 8, `ML-DSA.Verify_internal`) and independent of the
    AWS-LC signer: nothing here is derived from that code.  Parameters: q = 8380417, d = 13, tau = 60,
    lambda = 256 (so c~ is 64 bytes), gamma1 = 2^19, gamma2 = (q-1)/32, (k, l) = (8, 7), beta = 120, omega = 75.
    Not proved, only checked: `tests/gate_vectors/mldsa87_acvp.vectors` (NIST ACVP sigVer) and the differential
    test against AWS-LC.  Callers pass M' whole (`00 00 ‖ message` for a pure signature with an empty context). -/
namespace BlindLedger.Gate.MlDsa87

open BlindLedger.Keccak

def q : Nat := 8380417
def gamma1 : Nat := 2 ^ 19
def gamma2 : Nat := 261888
def beta : Nat := 120
def tau : Nat := 60
def omega : Nat := 75
def k : Nat := 8
def l : Nat := 7

abbrev Poly := Array Nat

def bitrev8 (m : Nat) : Nat := (List.range 8).foldl (fun a i => a ||| (((m >>> i) &&& 1) <<< (7 - i))) 0
def zetas : Array Nat := (Array.range 256).map fun m => ((List.range (bitrev8 m)).foldl (fun a _ => a * 1753 % q) 1)

/-- FIPS 204 Algorithm 41. -/
def ntt (w : Poly) : Poly := Id.run do
  let mut w := w
  let mut m := 0
  let mut len := 128
  while len ≥ 1 do
    let mut start := 0
    while start < 256 do
      m := m + 1
      let z := zetas[m]!
      for j in [start:start + len] do
        let t := z * w[j + len]! % q
        w := w.set! (j + len) ((w[j]! + q - t) % q)
        w := w.set! j ((w[j]! + t) % q)
      start := start + 2 * len
    len := len / 2
  w

/-- FIPS 204 Algorithm 42; 8347681 = 256^-1 mod q. -/
def invNtt (w : Poly) : Poly := Id.run do
  let mut w := w
  let mut m := 256
  let mut len := 1
  while len < 256 do
    let mut start := 0
    while start < 256 do
      m := m - 1
      let z := q - zetas[m]!
      for j in [start:start + len] do
        let t := w[j]!
        w := w.set! j ((t + w[j + len]!) % q)
        w := w.set! (j + len) (z * ((t + q - w[j + len]!) % q) % q)
      start := start + 2 * len
    len := len * 2
  w.map fun x => x * 8347681 % q

/-- The little-endian bit string of `b`, bit `i`. -/
def bitAt (b : ByteArray) (i : Nat) : Nat := ((b.get! (i / 8)).toNat >>> (i % 8)) &&& 1

/-- 256 coefficients of `width` bits each, from byte offset `off` (SimpleBitUnpack). -/
def unpack (b : ByteArray) (off width : Nat) : Poly :=
  (Array.range 256).map fun j => (List.range width).foldl (fun a i => a ||| (bitAt b (8 * off + j * width + i) <<< i)) 0

/-- HintBitUnpack (Algorithm 21): none unless indices strictly increase within a polynomial, at most omega hints
    are named, and the padding is zero. -/
def hintUnpack (y : ByteArray) : Option (Array Poly) := Id.run do
  let mut h := Array.replicate k (Array.replicate 256 0)
  let mut idx := 0
  for i in [0:k] do
    let stop := (y.get! (omega + i)).toNat
    if stop < idx || stop > omega then return none
    let first := idx
    while idx < stop do
      if idx > first && (y.get! (idx - 1)).toNat ≥ (y.get! idx).toNat then return none
      h := h.modify i (·.set! (y.get! idx).toNat 1)
      idx := idx + 1
  for i in [idx:omega] do
    if y.get! i ≠ 0 then return none
  return some h

/-- RejNTTPoly (Algorithm 30) over SHAKE128; if the first `n` output bytes run out, ask for twice as many
    (SHAKE output extends its own prefix, so the result does not depend on `n`). -/
partial def rejNtt (seed : ByteArray) (n : Nat) : Poly :=
  let s := shake128 seed n
  let out := Id.run do
    let mut out : Array Nat := #[]
    let mut p := 0
    while out.size < 256 && p + 3 ≤ s.size do
      let z := (s.get! (p + 2)).toNat % 128 * 65536 + (s.get! (p + 1)).toNat * 256 + (s.get! p).toNat
      if z < q then out := out.push z
      p := p + 3
    out
  if out.size = 256 then out else rejNtt seed (2 * n)

/-- SampleInBall (Algorithm 29) over SHAKE256, with the same prefix extension. -/
partial def sampleInBall (seed : ByteArray) (n : Nat) : Poly :=
  let s := shake256 seed n
  let c : Option Poly := Id.run do
    let mut c := Array.replicate 256 0
    let mut p := 8
    for i in [256 - tau:256] do
      let mut j := 0
      repeat
        if p ≥ s.size then return none
        j := (s.get! p).toNat
        p := p + 1
        if j ≤ i then break
      c := c.set! i c[j]!
      c := c.set! j (if bitAt s (i + tau - 256) = 0 then 1 else q - 1)
    return some c
  c.getD (sampleInBall seed (2 * n))

/-- UseHint (Algorithm 40) with m = 16: the high bits of `r` (Decompose, Algorithm 36), moved by a hint. -/
def useHint (h r : Nat) : Nat :=
  let m : Int := if r % (2 * gamma2) > gamma2 then (r % (2 * gamma2) : Nat) - 2 * gamma2 else (r % (2 * gamma2) : Nat)
  let corner := (r : Int) - m == (q : Int) - 1
  let r1 := if corner then 0 else ((r : Int) - m).toNat / (2 * gamma2)
  let r0 := if corner then m - 1 else m
  if h = 0 then r1 else if r0 > 0 then (r1 + 1) % 16 else (r1 + 15) % 16

/-- Verify_internal for ML-DSA-87 (FIPS 204 Algorithm 8): `pk` 2592 bytes, `sig` 4627 bytes, `msg` is M'. -/
def verify (pk msg sig : ByteArray) : Bool :=
  if pk.size != 2592 || sig.size != 4627 then false else
  match hintUnpack (sig.extract (64 + 7 * 640) 4627) with
  | none => false
  | some h =>
    let v := (Array.range l).map fun s => unpack sig (64 + 640 * s) 20
    if !(v.all (·.all fun x => Int.natAbs ((gamma1 : Int) - x) < gamma1 - beta)) then false else
    let zh := v.map fun p => ntt (p.map fun x => (gamma1 + q - x) % q)
    let ch := ntt (sampleInBall (sig.extract 0 64) 136)
    let rho := pk.extract 0 32
    let w1 := (Array.range k).map fun r =>
      let a := (Array.range l).map fun s => rejNtt (rho ++ ByteArray.mk #[s.toUInt8, r.toUInt8]) 840
      let t := ntt ((unpack pk (32 + 320 * r) 10).map (· * 8192))
      let w := (Array.range 256).map fun j =>
        ((Array.range l).foldl (fun acc s => acc + a[s]![j]! * zh[s]![j]! % q) 0 + q - ch[j]! * t[j]! % q) % q
      (invNtt w).zipIdx.map fun (x, j) => useHint h[r]![j]! x
    let enc := w1.foldl (fun (out : ByteArray) p =>
      (Array.range 128).foldl (fun out i => out.push (UInt8.ofNat (p[2 * i]! + 16 * p[2 * i + 1]!))) out) ByteArray.empty
    let mu := shake256 (shake256 pk 64 ++ msg) 64
    (sig.extract 0 64).data == (shake256 (mu ++ enc) 64).data

end BlindLedger.Gate.MlDsa87
