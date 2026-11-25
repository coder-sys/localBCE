import BlindLedger.Gate.Obligations.Records
import BlindLedger.Gate.Engine3.Index
import BlindLedger.Gate.Engine3.Sha3Fused
import BlindLedger.Gate.MlDsa87
import BlindLedger.Financial.Evaluation
import BlindLedger.Financial.Payment.Cursor

open BlindLedger.Gate.Obligations
open BlindLedger.Gate.Engine3

/-! `obligations_cost`: step 0 of the combined store (design `one-store` section 16.3).  It measures what a command of the
    obligations shard costs before anything is built, and prints one line on standard output:

        COST perm_ns=... sha3_512_1k_ns=... record_dec_ns=... record_enc_ns=... probe_ns=... insert_ns=... evaluate_small_ns=... mldsa_verify_us=...

    Nothing passes or fails.  Each figure is the median of `reps` repeats of a loop of `iters` runs; the counts and every
    other note go to standard error.  Test-only, never pinned.

    `obligations_cost WIRE VECTORS`: WIRE is one obligation's BLFIN02 input (the hospital scenario's; the test writes
    it), VECTORS is `tests/gate_vectors/mldsa87_acvp.vectors`, whose first `accept` line is verified.

    * `perm_ns`: the marginal cost of one permutation in `sha3_512Into`, the SHA3-512 the engines run: a 2,300-byte
      message (32 permutations) less an empty one (1), over 31.
    * `sha3_512_1k_ns`: `sha3_512Into` of 1,024 bytes (15 permutations).
    * `record_dec_ns`: a hand-written `ByteArray` decode of a state row (`decRowB`, checked equal to the `List` codec
      on the sample first); the `List` codec's decode is reported on standard error.
    * `record_enc_ns`: the `List` codec's encode of a state row (`stateC.enc`).
    * `probe_ns`, `insert_ns`: `Idx.probe` of a key present in a table of 200,000 keys; `Idx.insert` of a new key into a
      table that already holds 200,000 (splits included).
    * `evaluate_small_ns`: `evaluate` on the wire's input, decoded once.
    * `mldsa_verify_us`: `MlDsa87.verify` of the vector. -/

def mix (x : UInt64) : UInt64 :=
  let z := x + 0x9E3779B97F4A7C15
  let z := (z ^^^ (z >>> 30)) * 0xBF58476D1CE4E5B9
  let z := (z ^^^ (z >>> 27)) * 0x94D049BB133111EB
  z ^^^ (z >>> 31)

/-- The pieces of `decRowB`, a `ByteArray` twin of `stateC.dec` written by hand from the layout `stateL`.
    The little-endian number of `w` bytes at `o`, read from its top byte down. -/
def rdN (b : ByteArray) (o : Nat) : Nat → Nat → Nat
  | 0, v => v
  | w + 1, v => rdN b o w (v * 256 + (b.get! (o + w)).toNat)

def zeroIn (b : ByteArray) (o : Nat) : Nat → Bool
  | 0 => true
  | w + 1 => b.get! (o + w) == 0 && zeroIn b o w

def decRowB (b : ByteArray) : Option StateRow :=
  let n := (b.get! 3).toNat
  if b.size == 245 && b.get! 0 == 0x60 && b.get! 1 == 5 && n < 32 && zeroIn b (4 + n) (31 - n) && zeroIn b 35 45 &&
      zeroIn b 88 9 && zeroIn b 118 12 && zeroIn b 239 6 then
    let r : StateRow := ⟨rdN b 2 1 0, (b.extract 3 35).toList, rdN b 80 8 0, rdN b 97 8 0, rdN b 105 3 0, rdN b 108 5 0, rdN b 113 5 0,
      rdN b 130 1 0, rdN b 131 8 0, rdN b 139 8 0, rdN b 147 8 0, rdN b 155 8 0, rdN b 163 8 0, rdN b 171 8 0, rdN b 179 5 0, rdN b 184 1 0,
      rdN b 185 1 0, rdN b 186 1 0, rdN b 187 5 0, rdN b 192 5 0, rdN b 197 5 0, rdN b 202 5 0, rdN b 207 8 0, rdN b 215 8 0, rdN b 223 5 0,
      rdN b 228 4 0, rdN b 232 5 0, rdN b 237 1 0, rdN b 238 1 0⟩
    if stateC.chk r then some r else none
  else none

def sampleRow : StateRow :=
  ⟨14, [10] ++ List.replicate 10 0x41 ++ List.replicate 21 0, 12345, 77, 3, 5, 9, 1, 150000, 100, 100, 100, 149900, 0, 2, 5, 2,
    1, 4, 6, 8, 9, 1700000000000, 1700000000005, 12, 3, 21, 1, 0⟩

@[noinline] def decL (l : List UInt8) (i : Nat) : UInt64 :=
  match stateC.dec l with
  | some r => r.rev.toUInt64 + i.toUInt64
  | none => 0

@[noinline] def decB (b : ByteArray) (i : Nat) : UInt64 :=
  match decRowB b with
  | some r => r.rev.toUInt64 + i.toUInt64
  | none => 0

@[noinline] def encL (r : StateRow) (i : Nat) : UInt64 :=
  (stateC.enc { r with rev := r.rev + i % 7 }).length.toUInt64 + i.toUInt64

@[noinline] def evalOnce (inp : BlindLedger.Financial.FinancialInput) (i : Nat) : UInt64 :=
  match BlindLedger.Financial.evaluate inp with
  | some r => r.afterRevision.toUInt64 + i.toUInt64
  | none => 0

/-- The median of `reps` repeats; each repeat starts from `mk`, runs `step` `iters` times and gives the picoseconds per
    step.  The sum of the steps' values is returned so that no step is dropped. -/
def bench {σ : Type} (reps iters : Nat) (mk : IO σ) (step : σ → Nat → σ × UInt64) : IO (Nat × UInt64) := do
  let mut ts : Array Nat := #[]
  let mut sink : UInt64 := 0
  for _ in [0:reps] do
    let mut s ← mk
    let mut acc : UInt64 := 0
    let t0 ← IO.monoNanosNow
    for i in [0:iters] do
      let (s', v) := step s i
      s := s'
      acc := acc + v
    let t1 ← IO.monoNanosNow
    sink := sink ^^^ acc
    ts := ts.push ((t1 - t0) * 1000 / iters)
  return ((ts.qsort (· < ·))[reps / 2]!, sink)

def fmtPs (ps : Nat) : String :=
  let f := ps % 1000
  s!"{ps / 1000}.{if f < 10 then "00" else if f < 100 then "0" else ""}{f}"

def hexVal (c : Char) : Nat := if c.toNat ≥ 97 then c.toNat - 87 else if c.toNat ≥ 65 then c.toNat - 55 else c.toNat - 48

def unhex (s : String) : ByteArray := Id.run do
  let cs := s.toList.toArray
  let mut out := ByteArray.empty
  for i in [0:cs.size / 2] do
    out := out.push (UInt8.ofNat (hexVal cs[2 * i]! * 16 + hexVal cs[2 * i + 1]!))
  return out

def main (args : List String) : IO UInt32 := do
  let [wirePath, vecPath] := args | do IO.eprintln "usage: obligations_cost WIRE VECTORS"; return 2
  let wire ← IO.FS.readBinFile wirePath
  let some inp := BlindLedger.Financial.Cursor.decodeFinancialInput wire | do IO.eprintln "the wire does not decode"; return 2
  let vec ← IO.FS.readFile vecPath
  let some line := (vec.splitOn "\n").find? (fun l => l.startsWith "mldsa87 accept ") | do IO.eprintln "no accept vector"; return 2
  let [_, _, pkH, msgH, sigH] := (line.trimAscii.toString.splitOn " ") | do IO.eprintln "bad vector line"; return 2
  let (pk, msg, sig) := (unhex pkH, unhex msgH, unhex sigH)
  -- the sample row and the twin
  let enc := (stateC.enc sampleRow)
  let encB := ByteArray.mk enc.toArray
  unless stateC.dec enc == some sampleRow && decRowB encB == some sampleRow do
    IO.eprintln "the sample row does not round trip, or the ByteArray twin differs from the List codec"
    return 1
  let reps := 9
  let data := ByteArray.mk ((Array.range 2400).map fun i => (mix i.toUInt64).toUInt8)
  let sha := fun (len : Nat) (_ : Unit) (i : Nat) => ((), ((sha3_512Into .empty .empty data (i % 8) len).get! 0).toUInt64)
  let (t32, s1) ← bench reps 20000 (pure ()) (sha 2300)
  let (t1, s2) ← bench reps 20000 (pure ()) (sha 0)
  let perm := (t32 - t1) / 31
  let (t1k, s3) ← bench reps 100000 (pure ()) (sha 1024)
  let (tdl, s4) ← bench reps 100000 (pure ()) (fun _ i => ((), decL enc i))
  let (tdb, s5) ← bench reps 100000 (pure ()) (fun _ i => ((), decB encB i))
  let (tenc, s6) ← bench reps 100000 (pure ()) (fun _ i => ((), encL sampleRow i))
  -- the index
  let nKeys := 200000
  let key (i : Nat) : UInt64 × UInt64 := (mix (2 * i).toUInt64, mix (2 * i + 1).toUInt64)
  let mut base := Index.Idx.new 10
  for i in [0:nKeys] do base := base.insert (key i).1 (key i).2 i
  let (tpr, s7) ← bench reps 1000000 (pure (ByteArray.mk (Array.replicate 400 0))) fun out i =>
    let out := Index.probe base (key (i * 7919 % nKeys)).1 (key (i * 7919 % nKeys)).2 out 0
    (out, Index.wAt out 0)
  let (tin, s8) ← bench reps 100000 (pure base) fun x i =>
    let x := x.insert (key (nKeys + i)).1 (key (nKeys + i)).2 (nKeys + i)
    (x, x.n.toUInt64)
  let (tev, s9) ← bench reps 20000 (pure ()) (fun _ i => ((), evalOnce inp i))
  let (tml, s10) ← bench 5 3 (pure ()) (fun _ i => ((), if BlindLedger.Gate.MlDsa87.verify pk msg sig then i.toUInt64 + 1 else 0))
  IO.eprintln s!"REPEATS reps={reps} perm_iters=20000 sha_iters=100000 codec_iters=100000 probe_iters=1000000 insert_iters=100000 evaluate_iters=20000 mldsa_reps=5 mldsa_iters=3 index_keys={nKeys} wire_bytes={wire.size}"
  IO.eprintln s!"EXTRA record_dec_list_ns={fmtPs tdl} sha3_512_2300_ns={fmtPs t32} sha3_512_0_ns={fmtPs t1} mldsa_verified={s10 != 0}"
  IO.eprintln s!"SINK {s1 ^^^ s2 ^^^ s3 ^^^ s4 ^^^ s5 ^^^ s6 ^^^ s7 ^^^ s8 ^^^ s9 ^^^ s10}"
  IO.println s!"COST perm_ns={fmtPs perm} sha3_512_1k_ns={fmtPs t1k} record_dec_ns={fmtPs tdb} record_enc_ns={fmtPs tenc} probe_ns={fmtPs tpr} insert_ns={fmtPs tin} evaluate_small_ns={fmtPs tev} mldsa_verify_us={fmtPs (tml / 1000)}"
  return 0
