import BlindLedger.Sha3Fast

/-! ML-DSA-87 verification, written from FIPS 204 (Algorithm 8, `ML-DSA.Verify_internal`) and independent of the
    AWS-LC signer: nothing here is derived from that code.  Parameters: q = 8380417, d = 13, tau = 60,
    lambda = 256 (so c~ is 64 bytes), gamma1 = 2^19, gamma2 = (q-1)/32, (k, l) = (8, 7), beta = 120, omega = 75.
    Not proved, only checked: `tests/gate_vectors/mldsa87_acvp.vectors` (NIST ACVP sigVer) and the differential
    test against AWS-LC.  Callers pass M' whole (`00 00 ‖ message` for a pure signature with an empty context).
    SHAKE runs as `Sha3Fast`; `Sha3FastEq.shake128_eq` and `shake256_eq` bridge it to FIPS 202. -/
namespace BlindLedger.Gate.MlDsa87

open BlindLedger.Semantic

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
  for layer in [0:8] do
    let len := 128 >>> layer
    for b in [0:1 <<< layer] do
      m := m + 1
      let z := zetas[m]!
      let start := 2 * len * b
      for j in [start:start + len] do
        let t := z * w[j + len]! % q
        w := w.set! (j + len) ((w[j]! + q - t) % q)
        w := w.set! j ((w[j]! + t) % q)
  w

/-- FIPS 204 Algorithm 42; 8347681 = 256^-1 mod q. -/
def invNtt (w : Poly) : Poly := Id.run do
  let mut w := w
  let mut m := 256
  for layer in [0:8] do
    let len := 1 <<< layer
    for b in [0:128 >>> layer] do
      m := m - 1
      let z := q - zetas[m]!
      let start := 2 * len * b
      for j in [start:start + len] do
        let t := w[j]!
        w := w.set! j ((t + w[j + len]!) % q)
        w := w.set! (j + len) (z * ((t + q - w[j + len]!) % q) % q)
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
    for t in [first:stop] do
      if t > first && (y.get! (t - 1)).toNat ≥ (y.get! t).toNat then return none
      h := h.modify i (·.set! (y.get! t).toNat 1)
    idx := stop
  for i in [idx:omega] do
    if y.get! i ≠ 0 then return none
  return some h

def rejNttBytes : Nat := 894        -- FIPS 204 Table 3, RejNTTPoly
def sampleInBallBytes : Nat := 221  -- FIPS 204 Table 3, SampleInBall

/-- Algorithm 30's scan: 23-bit little-endian candidates from byte triples, kept when below q, until 256. -/
def rejScan (s : ByteArray) (p : Nat) (out : Array Nat) : Array Nat :=
  if h : out.size < 256 ∧ p + 3 ≤ s.size then
    let z := (s.get! (p + 2)).toNat % 128 * 65536 + (s.get! (p + 1)).toNat * 256 + (s.get! p).toNat
    rejScan s (p + 3) (if z < q then out.push z else out)
  else out
termination_by s.size - p

def rejNttFrom (s : ByteArray) : Option Poly :=
  let out := rejScan s 0 #[]
  if out.size = 256 then some out else none

/-- RejNTTPoly (Algorithm 30) with FIPS 204 Table 3's XOF bound: none past 894 bytes of SHAKE128. -/
def rejNtt (seed : ByteArray) : Option Poly := rejNttFrom (shake128Fast seed rejNttBytes)

/-- The next byte at or after `p` that is at most `i`, and the position after it. -/
def drawAtMost (s : ByteArray) (i p : Nat) : Option (Nat × Nat) :=
  if h : p < s.size then
    if (s.get! p).toNat ≤ i then some ((s.get! p).toNat, p + 1) else drawAtMost s i (p + 1)
  else none
termination_by s.size - p

def sampleInBallFrom (s : ByteArray) : Option Poly := do
  let mut c := Array.replicate 256 0
  let mut p := 8
  for i in [256 - tau:256] do
    let (j, p') ← drawAtMost s i p
    c := c.set! i c[j]!
    c := c.set! j (if bitAt s (i + tau - 256) = 0 then 1 else q - 1)
    p := p'
  return c

/-- SampleInBall (Algorithm 29) with FIPS 204 Table 3's XOF bound: none past 221 bytes of SHAKE256. -/
def sampleInBall (seed : ByteArray) : Option Poly := sampleInBallFrom (shake256Fast seed sampleInBallBytes)

/-- ExpandA (Algorithm 32): none if any entry exceeds the Table 3 bound. -/
def expandA (rho : ByteArray) : Option (Array (Array Poly)) :=
  (Array.range k).mapM fun r => (Array.range l).mapM fun s => rejNtt (rho ++ ByteArray.mk #[s.toUInt8, r.toUInt8])

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
    match sampleInBall (sig.extract 0 64), expandA (pk.extract 0 32) with
    | some c, some aHat =>
    let ch := ntt c
    let w1 := (Array.range k).map fun r =>
      let a := aHat[r]!
      let t := ntt ((unpack pk (32 + 320 * r) 10).map (· * 8192))
      let w := (Array.range 256).map fun j =>
        ((Array.range l).foldl (fun acc s => acc + a[s]![j]! * zh[s]![j]! % q) 0 + q - ch[j]! * t[j]! % q) % q
      (invNtt w).zipIdx.map fun (x, j) => useHint h[r]![j]! x
    let enc := w1.foldl (fun (out : ByteArray) p =>
      (Array.range 128).foldl (fun out i => out.push (UInt8.ofNat (p[2 * i]! + 16 * p[2 * i + 1]!))) out) ByteArray.empty
    let mu := shake256Fast (shake256Fast pk 64 ++ msg) 64
    (sig.extract 0 64).data == (shake256Fast (mu ++ enc) 64).data
    | _, _ => false

end BlindLedger.Gate.MlDsa87
