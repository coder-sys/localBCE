import BlindLedger.Gate.Engine3.Step

/-! The frame helpers that the rows-file engine (`HStore`) and the checker share: a logged frame's parts and its own checks,
    the refusal frame, the logged answer's head and root, and the `RR_E3_CRASH` test hook (`before_append`, `after_append`),
    which ends the process at that point.  Synthetic, nonpayment, non-PHI, activation=false. -/

namespace BlindLedger.Gate.Engine3.Run

open BlindLedger.Gate BlindLedger.Gate.Rules BlindLedger.Gate.Flat BlindLedger.Gate.Flat.Worker
open BlindLedger.Gate.Frame (Word AnsFrame)
open Std (HashMap)

def crashAt(name : String) : IO Unit := do
  if (← IO.getEnv "RR_E3_CRASH") == some name then IO.Process.exit 99

def patchAns (a head root : ByteArray) : ByteArray :=
  let h := headAt a
  let o := a.copySlice 0 (ByteArray.emptyWithCapacity a.size) 0 h false
  let o := (o.append head).append root
  a.copySlice (h + 128) o o.size (a.size - h - 128) false

/-- The chain's genesis for shard `shard`, sets dated `asOf`, under the key-set pin `pin`. -/
def genesis (shard asOf : Nat) (pin : ByteArray) : ByteArray :=
  (chainStart ChunkIo.hl shard pin.toList ((⟨asOf, 0, []⟩ : Snapshot Rules.Line), (⟨asOf, 0, []⟩ : Snapshot Rules.Line))).toByteArray

/-- Frame `f`'s bytes `raw` as request bytes, answer bytes, trailer and the whole frame. -/
def splitFrame (f : FrameRef) (raw : ByteArray) : Option (ByteArray × ByteArray × Trailer × ByteArray) := do
  guard (raw.size == f.len)
  let t ← Trailer.decode (raw.extract (16 + f.rq + f.an) f.len)
  return (raw.extract 16 (16 + f.rq), raw.extract (16 + f.rq) (16 + f.rq + f.an), t, raw)

def readFrame (log : UInt32) (f : FrameRef) : IO (Option (ByteArray × ByteArray × Trailer × ByteArray)) :=
  return splitFrame f (← Io.pgRead log f.off.toUInt64 f.len.toUSize)

def refusal (bs : ByteArray) (wd : Word) : ByteArray :=
  ⟨(Frame.refusal wd ((Frame.decodeHdr (bs.extract 0 Frame.hdrBytes).toList).toOption.map (·.1))).toArray⟩

/-! ## Memory diagnostic (bench only)

`RR_E3_MEMDIAG=<file>`: after every 25th batch the engine appends to the file, per structure, its element count and the
bytes Lean's object layout gives it (an object header is 8 bytes, a byte array's header 24, an array's 24 and 8 a slot, a
boxed `UInt64` 16, a pair 24, a map node 32), then this process's private bytes, working set and the allocator's committed
bytes, before and after a forced collect of the allocator.  It changes no decision. -/


/-- Bench only (`RR_E3_MEMDIAG`): private bytes this process gained across each step of a batch, summed over the batches since
    the last print.  Slots: 0 step, 1 answer frame, 2 log write and sync, 3 seal file. -/
initialize memD : IO.Ref (Array Int) ← IO.mkRef (Array.replicate 4 0)

def memPriv : IO Nat := do
  if (← IO.getEnv "RR_E3_MEMDIAG").isNone then return 0
  return getN (← procMem 0) 0 8

def memMark (i : Nat) (m0 : Nat) : IO Nat := do
  let m ← memPriv
  if m0 != 0 then memD.modify (·.modify i (· + ((m : Int) - m0)))
  return m

/-- The rows an answer adds, its `adds` blobs one after the other (`Frame.decExt` on bytes, the fields before them
    skipped); none unless the walk ends at the answer's last byte. -/
def ansAdds (a : ByteArray) : Option ByteArray := Id.run do
  -- after the head, root, hold, grant id and authority record
  let mut p := headAt a + 128 + 16 + 64 + 208
  let blob (p : Nat) : Option Nat := if p + 2 ≤ a.size && p + 2 + getN a p 2 ≤ a.size then some (p + 2 + getN a p 2) else none
  if a.size < p + 4 then return none
  let nn := getN a p 4
  p := p + 4
  for _ in [0:nn] do
    let some q := blob p | return none
    p := q
  if a.size < p + 4 then return none
  let nl := getN a p 4
  p := p + 4
  -- a leaf: outcome, reasons and authority, the bypass flag (1: its id follows), the input
  for _ in [0:nl] do
    if a.size < p + 7 || a.get! (p + 6) > 1 then return none
    p := p + 7 + (if a.get! (p + 6) == 1 then 64 else 0) + 64
  if a.size < p + 4 then return none
  let na := getN a p 4
  p := p + 4
  let mut out := ByteArray.empty
  for _ in [0:na] do
    let some q := blob p | return none
    out := out ++ a.extract (p + 2) q
    p := q
  return if p == a.size then some out else none

/-- The refusal of a store written before commit 4b56a94c, whose logged `rq` is the request frame digest, not the batch
    identity.  Such a store is not migrated (synthetic stores only, ENGINE_V3.md section 24). -/
def staleFormat : String := "STORE_FORMAT logged before the batch identity (4b56a94c); no migration"

/-- A logged frame's own checks, which need no state: its request bytes have the identity `rq`, its answer hashes to `an`,
    the authority record and the rows the answer adds to `bd`; then those rows, released and unresolved.  The error names the check that failed. -/
def frameRows (rqb anb : ByteArray) (t : Trailer) : Except String (List Line × List Line) := do
  let .ok (q, dg) := Frame.Fast.decodeReqFast rqb | throw "LOG"
  let ib := (Frame.Fast.identFast rqb q).1
  if ib != t.rq && dg == t.rq then throw staleFormat
  if ib != t.rq || ansBind anb != t.an then throw s!"rq {ib != t.rq} an {ansBind anb != t.an}"
  let some (fr, fu) := (ansAdds anb).bind Rules.Run.parseAdds | throw "adds"
  if batchDigestFast t.au (fr, fu) != t.bd then throw "bd"
  pure (fr, fu)

end BlindLedger.Gate.Engine3.Run
