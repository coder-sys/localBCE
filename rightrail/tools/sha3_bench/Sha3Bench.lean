import BlindLedger.Sha3
import BlindLedger.Sha3Fast
import BlindLedger.Sha3Quick
import BlindLedger.Sha3Lanes
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
def quick (d : ByteArray) : String := hex (sha3_256Quick d) ++ hex (sha3_512Quick d) ++ hex (shake128Quick d 200) ++ hex (shake256Quick d 200) ++ hex (shake128Quick d 700)

/-- `sha3_bench --speed`: ns per hash and MB/s x10 of Fast and Quick per size, and ns per bare permutation (`PERM`); flags any
    digest disagreement.  Each figure is the least of many short timed runs, so a busy machine's clock swings average out. -/
def speed : IO UInt32 := do
  let mut bad := 0
  for len in [0:700] do
    let d := ByteArray.mk ((Array.range len).map fun i => (i * 7 + len).toUInt8)
    if sha3_256Quick d != sha3_256Fast d || sha3_512Quick d != sha3_512Fast d || shake128Quick d 200 != shake128Fast d 200 ||
       shake256Quick d 300 != shake256Fast d 300 then bad := bad + 1
  IO.println s!"MISMATCH {bad}"
  let sizes := [0, 32, 64, 71, 72, 73, 135, 136, 137, 200, 245, 500, 1024, 2048, 4096, 16384]
  let impls : List (String × (ByteArray → ByteArray)) :=
    [("256fast", sha3_256Fast), ("256quick", sha3_256Quick), ("512fast", sha3_512Fast), ("512quick", sha3_512Quick)]
  for sz in sizes do
    let mut line := s!"S {sz}"
    let mut bests : Array Nat := #[1000000000000, 1000000000000, 1000000000000, 1000000000000]
    let mut buf := ByteArray.mk (Array.replicate sz 7)
    let iters := 100000 / (sz + 64) + 1
    let mut acc : UInt8 := 0
    for _ in [0:80] do
      let mut k := 0
      for (_, h) in impls do
        let t0 ← IO.monoNanosNow
        for i in [0:iters] do
          if sz > 0 then buf := buf.set! 0 i.toUInt8
          acc := acc ^^^ (h buf)[0]!
        let t1 ← IO.monoNanosNow
        bests := bests.modify k (min · ((t1 - t0) / iters))
        k := k + 1
    let mut k := 0
    for (name, _) in impls do
      let ns := bests[k]!
      line := line ++ s!" {name}={ns}ns/{(sz * 10000 / (ns + 1))}"
      k := k + 1
    if acc == 255 then line := line ++ "!"
    IO.println line
  let mut st : BlindLedger.Semantic.Quick.St := ⟨1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25⟩
  let mut best := 1000000000000
  for _ in [0:200] do
    let t0 ← IO.monoNanosNow
    for _ in [0:2000] do st := BlindLedger.Semantic.Quick.keccakF st
    let t1 ← IO.monoNanosNow
    best := min best ((t1 - t0) / 2000)
  IO.println s!"PERM {best}ns {st.a0}"
  let mut sl : BlindLedger.Semantic.Quick.St := ⟨1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25⟩
  let mut bestL := 1000000000000
  for _ in [0:200] do
    let t0 ← IO.monoNanosNow
    for _ in [0:2000] do sl := BlindLedger.Semantic.Lanes.permA sl.a0 sl.a1 sl.a2 sl.a3 sl.a4 sl.a5 sl.a6 sl.a7 sl.a8 sl.a9 sl.a10 sl.a11 sl.a12 sl.a13 sl.a14 sl.a15 sl.a16 sl.a17 sl.a18 sl.a19 sl.a20 sl.a21 sl.a22 sl.a23 sl.a24
    let t1 ← IO.monoNanosNow
    bestL := min bestL ((t1 - t0) / 2000)
  IO.println s!"PERML {bestL}ns {sl.a0}"
  return 0

def main (args : List String) : IO UInt32 := do
  if args[0]? == some "--speed" then return ← speed
  let data ← IO.FS.readBinFile args[0]!
  for d in items data 0 #[] do
    IO.println s!"D {old d} {fast d} {quick d}"
  let big := data.extract 0 (4 * 1048576)
  let t0 ← IO.monoNanosNow
  IO.println s!"H {hex (sha3_512 big)}"
  let t1 ← IO.monoNanosNow
  IO.println s!"H {hex (sha3_512Fast big)}"
  let t2 ← IO.monoNanosNow
  let mbps (ns : Nat) : Nat := big.size * 100000 / (ns + 1)  -- bytes/ns * 1e3 = MB/s; x100
  IO.println s!"SPEED {mbps (t1 - t0)} {mbps (t2 - t1)} {big.size}"
  return 0
