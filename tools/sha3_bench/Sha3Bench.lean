import BlindLedger.Sha3
import BlindLedger.Sha3Fast
open BlindLedger.Semantic

/-! E1: `sha3_bench <file>` reads inputs as u32-BE length + bytes, prints per input `D <old> <fast>` (SHA3-512, SHAKE128 and
    SHAKE256 of 200 bytes, hex, concatenated), then times SHA3-512 of up to 4 MiB of the file with each (`H <digest>` twice, forced between the clocks), then
    `SPEED <old MB/s x100> <fast MB/s x100> <bytes>`.
    The Python test compares the two columns and hashlib. -/
def hex (b : ByteArray) : String :=
  String.join (b.toList.map fun x =>
    let h := Nat.toDigits 16 x.toNat
    String.ofList (if h.length < 2 then '0' :: h else h))

partial def items (b : ByteArray) (i : Nat) (acc : Array ByteArray) : Array ByteArray :=
  if i + 4 > b.size then acc else
    let n := ((b[i]!.toNat * 256 + b[i+1]!.toNat) * 256 + b[i+2]!.toNat) * 256 + b[i+3]!.toNat
    items b (i + 4 + n) (acc.push (b.extract (i + 4) (i + 4 + n)))

def old (d : ByteArray) : String := hex (sha3_512 d) ++ hex (shake128 d 200) ++ hex (shake256 d 200)
def fast (d : ByteArray) : String := hex (sha3_512Fast d) ++ hex (shake128Fast d 200) ++ hex (shake256Fast d 200)

def main (args : List String) : IO UInt32 := do
  let data ← IO.FS.readBinFile args[0]!
  for d in items data 0 #[] do
    IO.println s!"D {old d} {fast d}"
  let big := data.extract 0 (4 * 1048576)
  let t0 ← IO.monoNanosNow
  IO.println s!"H {hex (sha3_512 big)}"
  let t1 ← IO.monoNanosNow
  IO.println s!"H {hex (sha3_512Fast big)}"
  let t2 ← IO.monoNanosNow
  let mbps (ns : Nat) : Nat := big.size * 100000 / (ns + 1)  -- bytes/ns * 1e3 = MB/s; x100
  IO.println s!"SPEED {mbps (t1 - t0)} {mbps (t2 - t1)} {big.size}"
  return 0
