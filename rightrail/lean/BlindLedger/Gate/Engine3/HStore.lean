import BlindLedger.Gate.Engine3.Store
import BlindLedger.Gate.Engine3.StepH

/-! A store on rows files (`Hist`): a directory with the log (frames and trailers; the chunk
    fields of a trailer are zero and its root has no chunk tree), the key file, and one rows file per set.

    A batch is decided (`stepH`), its rows appended to the rows files and the tables, and its frame appended to the log and
    synced.  The log is the truth, and the rows files are not synced per batch: a clean stop syncs them and then writes the
    file `clean` (one byte, 1); a start writes 0 there and syncs it before any write.  A load that finds the marker 1 trusts
    the rows files (the cut to the last signed batch and the rows the files lack are put from the frames); any other
    start, whose process did not itself write the files, rebuilds both files from the log and swaps them in, so a power
    loss that left whole but hollow records cannot reach a decision.  Damage to the files while the marker says clean is
    outside the threat model (disk faults behind a completed sync).  Retry and pending frames are as in `Run.handle`.
    Synthetic, nonpayment, non-PHI, activation=false. -/

namespace BlindLedger.Gate.Engine3.Run

open BlindLedger.Gate BlindLedger.Gate.Rules BlindLedger.Gate.Flat BlindLedger.Gate.Flat.Worker
open BlindLedger.Gate.Frame (Word)

structure StoreH where
  /-- Taken out (`swap`) for the puts so that the tables are updated in place. -/
  h : IO.Ref (Option Hist.Hist)
  sec : ByteArray
  log : UInt32
  shard : Nat
  bt : Nat
  head : ByteArray
  root : ByteArray
  au : ByteArray
  logLen : Nat
  last : Option FrameRef
  pend : Option FrameRef
  dir : String
  /-- The head and root the answer just returned is to carry in place of its 128 placeholder bytes; the caller writes the answer in
      parts and clears this. -/
  patch : Option (ByteArray × ByteArray) := none

def closeRows (hv : Hist.Hist) : IO Unit := do
  hv.rel.close
  hv.unr.close

/-- Closes the log and the rows files of a store that is dropped. -/
def closeFds (s : StoreH) : IO Unit := do
  if let some hv ← s.h.get then closeRows hv
  let _ ← Io.pgClose s.log

/-- Directories this process has opened since it started: the rows files it wrote are in the file cache, so its own reopen
    needs no rebuild (only a start after a stop of another process does). -/
initialize ownDirs : IO.Ref (Array String) ← IO.mkRef #[]

/-- The clean-stop marker's byte was 1 (a missing file reads as not clean). -/
def markerClean (dir : String) : IO Bool := do
  try pure ((← IO.FS.readBinFile s!"{dir}/clean") == ByteArray.mk #[1]) catch _ => pure false

/-- The marker's byte set to `v` and synced (the one byte is a single sector write, so the directory need not be). -/
def markerSet (dir : String) (v : UInt8) : IO Bool := do
  let fd ← Io.pgOpen s!"{dir}/clean"
  if fd == 0xFFFFFFFF then return false
  let ok := (← Io.pgWrite fd 0 (ByteArray.mk #[v])) == 0 && (← Io.pgSync fd) == 0
  let _ ← Io.pgClose fd
  return ok

/-- A clean stop: the rows files synced, then the marker 1.  Without it the next start rebuilds the files. -/
def closeH (s : StoreH) : IO Unit := do
  if let some hv ← s.h.get then
    try
      hv.rel.f.sync
      hv.unr.f.sync
      let _ ← markerSet s.dir 1
    catch _ => pure ()
  closeFds s

/-- The parts of the frame of batch `s.bt + 1` for request bytes `bs` (digest `dg`) and the decided batch `d`, on a history whose heads
    are `hr` and `hu`; `replaced` is `Z` or the digest of the pending frame it replaces.  None when the answer is missing. -/
def freshH (s : StoreH) (hr hu : Head) (d : DoneH) (replaced : ByteArray) :
    IO (Option (Trailer × ByteArray × ByteArray)) := do
  let n := s.bt + 1
  let tw ← IO.monoNanosNow
  let some (ans, an, ib) := d.ans.get | return none
  let tf ← tick 4 tw
  let hr' : Head := ⟨hr.asOf, hr.count + d.fr.size, hr.n + d.fr.size⟩
  let hu' : Head := ⟨hu.asOf, hu.count + d.fu.size, hu.n + d.fu.size⟩
  let t0 : Trailer := ⟨s.shard, n, hr', hu', 1, 0, noSeal, none, none, none, d.au, ib, an, replaced, s.head, d.bd.get,
    zero64, zero64⟩
  let root := rootFour t0 zero64 (storeKs s.sec) none
  let t := { t0 with root, head := chainHead s.head t0.bd root }
  let trb ← evalNow t.encode
  let _ ← tick 7 tf
  return some (t, ans, trb)

/-- The process's CPU time at the last print of `memDiagH`. -/
initialize cpuPrev : IO.Ref UInt64 ← IO.mkRef 0

/-- Bench only (`RR_E3_MEMDIAG`): after every 25th batch the rows, the tables' bytes, this process's private bytes, working set
    and the allocator's committed bytes, and the time by phase since the last print. -/
def memDiagH (h : Hist.Hist) (n : Nat) : IO Unit := do
  let some path ← IO.getEnv "RR_E3_MEMDIAG" | return
  if n % 25 != 0 then return
  let u64 (b : ByteArray) (i : Nat) := getN b (8 * i) 8
  let before ← procMem 0
  let after ← procMem 2
  let mb (x : Nat) := x / 1048576
  let ph ← phases.swap (Array.replicate nPhases 0)
  let names := #["", "byte read path to decisions", "spawn", "puts", "answer wait", "admit+setup", "events", "frame",
    "log append+sync", "rows put", "", "", "", "", "", "", "whole batch", "  feeds (in byte read path)",
    "  probes, round 2, layout (in byte read path)", "  decideRows (in byte read path)",
    "  store lines and rows (in byte read path)", "  key digests (in byte read path)"]
  let mut pt := s!"  PHASES since last print: {ph[15]!} lines, ns per line:"
  for i in [0:22] do
    if names[i]! != "" then pt := pt ++ s!" [{names[i]!}] {ph[i]! / (ph[15]! + 1)}"
  -- the history engine's loop turn: where its time goes, per line (see `phases`); what no slot holds is the unattributed time
  let cpu ← procCpu
  let cpu0 ← cpuPrev.swap cpu
  let l := ph[15]! + 1
  let leaf := ph[22]! + ph[23]! + ph[5]! + ph[1]! + ph[19]! + ph[37]! + ph[9]! + ph[4]! + ph[7]! + ph[8]! + ph[39]! + ph[25]!
  let un : Int := (ph[26]! : Int) - leaf
  pt := pt ++ s!"
  LOOP ns per line: turn {ph[26]! / l} = pipe read {ph[22]! / l} decode {ph[23]! / l} admit {ph[5]! / l} read {ph[1]! / l} decide {ph[19]! / l} answer inputs {ph[37]! / l} rows put {ph[9]! / l} answer wait {ph[4]! / l} frame {ph[7]! / l} log {ph[8]! / l} patchAns {ph[39]! / l} answer write {ph[25]! / l} + unattributed {un / (l : Int)} (batch {ph[24]! / l}, whole batch tick {ph[16]! / l}, free and return {((ph[24]! : Int) - ph[16]!) / (l : Int)})"
  pt := pt ++ s!"
  ANSWER TASK ns per line: task {ph[28]! / l} = header {ph[35]! / l} lines root {ph[30]! / l} input hash {ph[31]! / l} leaf copy {ph[32]! / l} row push {ph[33]! / l} answer hash {ph[34]! / l}; leafIns {ph[38]! / l}; digest task {ph[29]! / l}"
  pt := pt ++ s!"
  ENGINE CPU ns per line {(cpu - cpu0).toNat * 100 / l} (process, all threads)"
  let md ← memD.swap (Array.replicate 4 0)
  let pp ← Hist.putPhases.swap (Array.replicate 5 0)
  let mut out := s!"MEMDIAG batch {n} rows released {h.hr.n} unresolved {h.hu.n}\n"
  out := out ++ s!"  PRIVATE BYTES gained per 25 batches, step {md[0]!}, answer frame {md[1]!}, log write {md[2]!}, rows put {md[3]!}\n"
  out := out ++ s!"  PUT ns per line: rows {pp[0]! / (ph[15]! + 1)} cores updated {pp[1]! / (ph[15]! + 1)} cores new {pp[2]! / (ph[15]! + 1)} ids {pp[3]! / (ph[15]! + 1)} file {pp[4]! / (ph[15]! + 1)}
"
  out := out ++ s!"  TABLE BYTES released ids {h.rel.ids.bytes} cores {h.rel.cores.bytes}, unresolved ids {h.unr.ids.bytes} cores {h.unr.cores.bytes}
"
  out := out ++ s!"  process MB before collect: private {mb (u64 before 0)} ws {mb (u64 before 1)} committed {mb (u64 before 2)} peak committed {mb (u64 before 3)}\n"
  out := out ++ s!"  process MB after collect: private {mb (u64 after 0)} ws {mb (u64 after 1)} committed {mb (u64 after 2)}\n"
  IO.FS.withFile path .append fun h => h.putStr (out ++ pt ++ "\n")

/-- One decoded request `q` (header digest `dg`, bytes `bs`) on the store: the store after it and the answer bytes.  A
    logged batch is matched by its identity (`Frame.ident`): computed here for a resent or pending batch, and on the
    answer task for a fresh one. -/
def handleH (s : StoreH) (bs : ByteArray) (q : Frame.Req) (dg : ByteArray) : IO (StoreH × ByteArray) := do
  let n := q.batch
  if n == s.bt then
    let some f := s.last | return (s, refusal bs .NOT_NEXT)
    let some (_, an, t, _) ← readFrame s.log f | return (s, refusal bs .CORRUPT)
    if t.rq != (Frame.Fast.identFast bs q).1 then return (s, refusal bs .CONFLICT)
    -- the stored answer is the one the trailer bound when the batch was sealed
    if ansBind an != t.an then return (s, refusal bs .CORRUPT)
    return (s, patchAns an t.head t.root)
  if n != s.bt + 1 then return (s, refusal bs .NOT_NEXT)
  if q.prev.toByteArray != s.head then return (s, refusal bs .HEAD)
  let pend ← match s.pend with
    | some f => readFrame s.log f
    | none => pure none
  if s.pend.isSome && pend.isNone then return (s, refusal bs .CORRUPT)
  if let some (_, _, t, _) := pend then
    if t.rq != (Frame.Fast.identFast bs q).1 then return (s, refusal bs .CONFLICT)
  let th ← IO.monoNanosNow
  let mm ← memPriv
  let some hv ← s.h.get | return (s, refusal bs .CORRUPT)
  let (hr, hu) := (hv.hr, hv.hu)
  let stepR ← stepH hv s.au q dg bs
  let mm ← memMark 0 mm
  match stepR with
  | .error w => return (s, refusal bs w)
  | .ok (.refused hold) =>
    return (s, Frame.Fast.encodeAnsFast ⟨.OK, q.shard, s.bt, dg, [], s.head, s.root, { noExt with hold }⟩)
  | .ok (.done d) =>
    -- the rows, while the answer is built; the history is taken out of its cell so its tables are updated in place.  If the
    -- log then fails, the cell is emptied and the next request opens the store again from disk (rows past the log are cut).
    let tp ← IO.monoNanosNow
    let some hv ← s.h.swap none | return (s, refusal bs .CORRUPT)
    let hv ← Hist.put hv d.lb d.idx d.keys d.fr d.fu
    let _ ← tick 9 tp
    s.h.set (some hv)
    let mm ← memMark 3 mm
    let fail (w : Word) : IO (StoreH × ByteArray) := do
      if let some hv ← s.h.get then closeRows hv
      s.h.set none
      return (s, refusal bs w)
    let some (t, ans, trb) ← freshH s hr hu d zero64 | fail .CORRUPT
    let mm ← memMark 1 mm
    let mut t := t
    let mut ans := ans
    let mut trb := trb
    let mut off := s.logLen
    let mut keep := false
    if let (some (_, _, _, pb), some pf) := (pend, s.pend) then
      off := pf.off
      if pb == encodeFrame bs ans trb then keep := true
      else
        let some (t2, a2, tr2) ← freshH s hr hu d (replacedDigest pb) | return ← fail .CORRUPT
        t := t2
        ans := a2
        trb := tr2
    if !keep then
      crashAt "before_append"
      if off < s.logLen then
        if (← Io.pgTrunc s.log off.toUInt64) != 0 then return ← fail .IO
      let ta ← IO.monoNanosNow
      -- the frame goes to the log in its four parts: no copy of the multi-megabyte whole
      let o := off.toUInt64
      if (← Io.pgWrite s.log o (frameHead bs.size ans.size trb.size)) != 0 || (← Io.pgWrite s.log (o + 16) bs) != 0 ||
          (← Io.pgWrite s.log (o + 16 + bs.size.toUInt64) ans) != 0 ||
          (← Io.pgWrite s.log (o + 16 + bs.size.toUInt64 + ans.size.toUInt64) trb) != 0 || (← Io.pgSync s.log) != 0 then
        return ← fail .IO
      let _ ← tick 8 ta
      crashAt "after_append"
    else if (← Io.pgSync s.log) != 0 then return ← fail .IO  -- the kept frame's own sync may have failed: sync before answering
    let mm ← memMark 2 mm
    let ref : FrameRef := ⟨off, bs.size, ans.size, trb.size⟩
    let _ ← tick 16 th
    return ({ s with bt := n, head := t.head, root := t.root, au := d.au, logLen := off + 16 + bs.size + ans.size + trb.size, last := some ref,
                     pend := none, patch := some (t.head, t.root) }, ans)

/-- Set `u` of a load, after the files were cut to the last signed batch: for each frame in order its lines `ls` and the set's size
    `n1` after it; the lines the file lacks are put as a live batch puts them (those it holds are skipped). -/
def refillSide (ctx : KeyCtx) (u : Bool) (st : Hist.Side) (items : Array (List Line × Nat)) : IO Hist.Side := do
  let mut st := st
  for (ls, n1) in items do
    if n1 ≤ st.f.n then continue
    let ls := ls.drop (st.f.n + ls.length - n1)
    let lb := ls.foldl (fun b l => putLine b l) (ByteArray.emptyWithCapacity (lineW2 * ls.length))
    st ← Hist.putAll ctx st u lb
  return st

/-- The frames of a refill that are decoded and put together. -/
def refillWindow : Nat := 16

/-- After a load cut each rows file to the last signed batch: the rows of frames `[0, bt)` that a file lacks (a crash lost its
    unsynced tail), put as the live batches put them.  `trs` are the frames' trailers, so the frames the files already hold
    are not read.  The frames of a window are checked and decoded at once, one task each, and the two sets, which share nothing,
    are put at once. -/
def refill (ctx : KeyCtx) (log : UInt32) (frames : Array FrameInfo) (trs : Array Trailer) (bt : Nat) (rel unr : Hist.Side) :
    IO (Except String (Hist.Side × Hist.Side)) := do
  let ns := trs.map fun t => (t.hr.n, t.hu.n)
  let mut a := 0
  while a < bt && ns[a]!.1 ≤ rel.f.n && ns[a]!.2 ≤ unr.f.n do a := a + 1
  let mut rel := rel
  let mut unr := unr
  while a < bt do
    let b := min bt (a + refillWindow)
    let mut jobs : Array (Nat × Task (Except String (List Line × List Line))) := #[]
    for j in [a:b] do
      let some (rqb, anb, t, _) ← readFrame log frames[j]!.ref | return .error "LOG"
      jobs := jobs.push (j, Task.spawn fun _ => frameRows rqb anb t)
    let mut ri : Array (List Line × Nat) := #[]
    let mut ui : Array (List Line × Nat) := #[]
    for (j, job) in jobs do
      match job.get with
      | .ok (fr, fu) =>
        ri := ri.push (fr, ns[j]!.1)
        ui := ui.push (fu, ns[j]!.2)
      | .error w => return .error s!"REPLAY:frame batch {j + 1} {w}"
    let tr ← IO.asTask (refillSide ctx false rel ri)
    let tu ← IO.asTask (refillSide ctx true unr ui)
    rel ← IO.ofExcept (← IO.wait tr)
    unr ← IO.ofExcept (← IO.wait tu)
    a := b
  return .ok (rel, unr)

/-- The chain of the first `bt` frames recomputed as the chunk engine's replay does: the first frame follows the genesis of
    its own shard and date (only batch 1 of a request carries a date), each
    frame's `prev` is the head before it, its root is the state root of its own fields (no chunk tree) and its head the
    chain head of `prev`, `bd` and root; the genesis is under the key-set pin of the first frame's authority record, and
    each frame's record follows the one before it (`ChunkIo.authFollows`).  A frame that fails is a corrupt log.  The trailers of the frames are returned. -/
def chainOk (sec : ByteArray) (log : UInt32) (frames : Array FrameInfo) (bt : Nat) : IO (Option (Array Trailer)) := do
  let mut prev := ByteArray.empty
  let mut au := ByteArray.empty
  let mut trs : Array Trailer := #[]
  for i in [0:bt] do
    let some t ← readTrailer log frames[i]! | return none
    if i == 0 then
      prev := genesis t.shard t.hr.asOf (t.au.extract 0 64)
      au := t.au
    if t.prev != prev || t.root != rootFour t zero64 (storeKs sec) none || t.head != chainHead t.prev t.bd t.root ||
        !Flat.ChunkIo.authFollows au.toList t.au.toList then
      return none
    prev := t.head
    au := t.au
    trs := trs.push t
  return some trs

/-- Both rows files again from the frames `[0, bt)`, into new files that replace the old ones once synced. -/
def rebuildRows (dir : String) (ctx : KeyCtx) (log : UInt32) (frames : Array FrameInfo) (trs : Array Trailer) (bt : Nat) (hr hu : Head) : IO Bool := do
  try
    let .ok rel ← Hist.Side.load ctx s!"{dir}/rows_rel.new" 0 false | return false
    let .ok unr ← Hist.Side.load ctx s!"{dir}/rows_unr.new" 0 true | rel.close; return false
    let r ← refill ctx log frames trs bt rel unr
    let good := match r with | .ok (a, b) => a.f.n == hr.n && b.f.n == hu.n | .error _ => false
    if let .ok (a, b) := r then
      a.f.sync
      b.f.sync
      a.close
      b.close
    else
      rel.close
      unr.close
    if !good then return false
    IO.FS.rename s!"{dir}/rows_rel.new" s!"{dir}/rows_rel"
    IO.FS.rename s!"{dir}/rows_unr.new" s!"{dir}/rows_unr"
    return true
  catch _ => return false

/-- The store of `dir` for request `q`: batch 1 of a directory with no log creates it; otherwise it loads at the head `q`
    follows (`q.batch - 1` batches), a whole frame after that being the pending one. -/
def openStoreH (dir : String) (q : Frame.Req) : IO (Except Word StoreH) := do
  if q.batch == 0 then return .error .NOT_NEXT
  if q.batch == 1 && q.prev.toByteArray != genesis q.shard q.asOf q.auth.pin.toByteArray then return .error .HEAD
  let logP := s!"{dir}/log"
  let h0 : Head := ⟨q.asOf, 0, 0⟩
  if q.batch == 1 && !(← System.FilePath.pathExists logP) then
    let sec ← initKey dir
    let fd ← Io.pgOpen logP
    if fd == 0xFFFFFFFF then return .error .INIT
    if !(← markerSet dir 0) then let _ ← Io.pgClose fd; return .error .INIT
    ownDirs.modify (·.push dir)
    let ctx := KeyCtx.ofSecret sec
    let .ok rel ← Hist.Side.load ctx s!"{dir}/rows_rel" 0 false | let _ ← Io.pgClose fd; return .error .INIT
    let .ok unr ← Hist.Side.load ctx s!"{dir}/rows_unr" 0 true | rel.close; let _ ← Io.pgClose fd; return .error .INIT
    let h ← IO.mkRef (some (⟨ctx, rel, unr, h0, h0⟩ : Hist.Hist))
    return .ok ⟨h, sec, fd, q.shard, 0, genesis q.shard q.asOf q.auth.pin.toByteArray, zero64, (encAuth (initAuth q)).toByteArray, 0, none, none, dir, none⟩
  let sec ← match ← readKey dir with
    | .ok s => pure s
    | .error _ => return .error .CORRUPT
  let (frames, torn, log) ← match ← scanLog logP with
    | .ok r => pure r
    | .error _ => return .error .CORRUPT
  let refuse (w : Word) : IO (Except Word StoreH) := do let _ ← Io.pgClose log; return .error w
  let n := frames.size
  let bt := q.batch - 1
  if !(bt == n || bt + 1 == n) then return ← refuse .HEAD
  let tr ← if bt == 0 then pure none else readTrailer log frames[bt - 1]!
  if bt != 0 && (tr.isNone || tr.map (·.head) != some q.prev.toByteArray) then return ← refuse .HEAD
  let some trs ← chainOk sec log frames bt | return ← refuse .CORRUPT
  -- a store begun under another key-set pin than the tenant's decides nothing (PIN)
  if tr.any (·.au.extract 0 64 != q.auth.pin.toByteArray) then return ← refuse .PIN
  let ctx := KeyCtx.ofSecret sec
  let (hr, hu) := match tr with | some t => (t.hr, t.hu) | none => (h0, h0)
  -- the marker 0 is durable before any write; a start that finds no marker 1 (and did not write the files itself) rebuilds
  let trusted := (← markerClean dir) || (← ownDirs.get).contains dir
  if !(← markerSet dir 0) then return ← refuse .IO
  if !trusted then
    if !(← rebuildRows dir ctx log frames trs bt hr hu) then return ← refuse .IO
  ownDirs.modify fun a => if a.contains dir then a else a.push dir
  let .ok rel ← Hist.Side.load ctx s!"{dir}/rows_rel" hr.n false | return ← refuse .CORRUPT
  let .ok unr ← Hist.Side.load ctx s!"{dir}/rows_unr" hu.n true | rel.close; return ← refuse .CORRUPT
  let .ok (rel, unr) ← refill ctx log frames trs bt rel unr | rel.close; unr.close; return ← refuse .CORRUPT
  if rel.f.n != hr.n || unr.f.n != hu.n then rel.close; unr.close; return ← refuse .CORRUPT
  if torn < (← System.FilePath.metadata logP).byteSize.toNat then
    if (← Io.pgTrunc log torn.toUInt64) != 0 || (← Io.pgSync log) != 0 then
      rel.close; unr.close; return ← refuse .IO
  let h ← IO.mkRef (some (⟨ctx, rel, unr, hr, hu⟩ : Hist.Hist))
  return .ok ⟨h, sec, log, q.shard, bt, q.prev.toByteArray, (tr.map (·.root)).getD zero64,
    (tr.map (·.au)).getD (encAuth (initAuth q)).toByteArray,
    (← System.FilePath.metadata logP).byteSize.toNat, if bt == 0 then none else some frames[bt - 1]!.ref,
    if bt < n then some frames[bt]!.ref else none, dir, none⟩

end BlindLedger.Gate.Engine3.Run
