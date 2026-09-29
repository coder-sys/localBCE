/-! Keccak-f[1600] with SHA3-512, SHAKE128 and SHAKE256, for the gate's ML-DSA-87 verifier.
    TEMPORARY DUPLICATE of the private Keccak-f in `BlindLedger.Sha3`, which stays untouched because it is in
    the engine pin's source manifest.  Delete this file, and use a public `Sha3.keccakF`, at the next engine
    re-pin.  `gate_vectors` checks both SHA3-512 implementations against Python `hashlib`. -/
namespace BlindLedger.Keccak

private def rotl (v : UInt64) (n : Nat) : UInt64 :=
  if n = 0 then v else (v <<< UInt64.ofNat n) ||| (v >>> UInt64.ofNat (64 - n))

private def roundConstants : Array UInt64 := #[
  0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
  0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
  0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
  0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
  0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
  0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]

private def rho : Array Nat := #[0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14]

private def round (a : Array UInt64) (r : Nat) : Array UInt64 := Id.run do
  let c := (Array.range 5).map fun x => a[x]! ^^^ a[x + 5]! ^^^ a[x + 10]! ^^^ a[x + 15]! ^^^ a[x + 20]!
  let d := (Array.range 5).map fun x => c[(x + 4) % 5]! ^^^ rotl (c[(x + 1) % 5]!) 1
  let mut b := Array.replicate 25 (0 : UInt64)
  for x in [0:5] do
    for y in [0:5] do
      b := b.set! (y + 5 * ((2 * x + 3 * y) % 5)) (rotl (a[x + 5 * y]! ^^^ d[x]!) (rho[x + 5 * y]!))
  let mut out := b
  for y in [0:5] do
    for x in [0:5] do
      out := out.set! (x + 5 * y) (b[x + 5 * y]! ^^^ ((~~~(b[(x + 1) % 5 + 5 * y]!)) &&& b[(x + 2) % 5 + 5 * y]!))
  out.set! 0 (out[0]! ^^^ (roundConstants[r]!))

def keccakF (a : Array UInt64) : Array UInt64 := (List.range 24).foldl round a

/-- Sponge: absorb `data` at `rate` bytes with domain-suffix byte `suffix`, then squeeze `n` bytes. -/
def sponge (rate : Nat) (suffix : UInt8) (data : ByteArray) (n : Nat) : ByteArray := Id.run do
  let total := (data.size / rate + 1) * rate
  let mut p := data ++ ByteArray.mk (Array.replicate (total - data.size) 0)
  p := p.set! data.size suffix
  p := p.set! (total - 1) (p.get! (total - 1) ||| 0x80)
  let mut st := Array.replicate 25 (0 : UInt64)
  for blk in [0:total / rate] do
    for i in [0:rate / 8] do
      let lane := (List.range 8).foldl (fun v j => v ||| (p.get! (blk * rate + 8 * i + j)).toUInt64 <<< UInt64.ofNat (8 * j)) 0
      st := st.set! i (st[i]! ^^^ lane)
    st := keccakF st
  let mut out := ByteArray.empty
  repeat
    for j in [0:rate] do
      if out.size < n then out := out.push (st[j / 8]! >>> UInt64.ofNat (8 * (j % 8))).toUInt8
    if out.size ≥ n then break
    st := keccakF st
  out

def sha3_512 (data : ByteArray) : ByteArray := sponge 72 0x06 data 64
def shake128 (data : ByteArray) (n : Nat) : ByteArray := sponge 168 0x1F data n
def shake256 (data : ByteArray) (n : Nat) : ByteArray := sponge 136 0x1F data n

end BlindLedger.Keccak
