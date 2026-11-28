import BlindLedger.Gate.Engine3.Store
import BlindLedger.Gate.Engine3.StepH
import BlindLedger.Gate.Engine3.HLinks
import BlindLedger.Gate.Engine3.HFacts

/-! A store on rows files (`Hist`): a directory with the log (frames and trailers; the chunk
    fields of a trailer are zero and its root has no chunk tree), the key file, and one rows file and one links file
    (`Links`) per set.

    A batch is decided (`stepH`), its rows appended to the rows files and the tables, and its frame appended to the log and
    synced.  The log is the truth, and the rows files are not synced per batch: a clean stop syncs them and then writes the
    file `clean` (one byte, 1); a start writes 0 there and syncs it before any write.  A load that finds the marker 1 trusts
    the rows files (the cut to the last signed batch and the rows the files lack are put from the frames) and the facts
    file (`Facts.load`: cut to the last fact frame's batch, which is admitted again with those after it); any other
    start, whose process has not completed an open of the store, rebuilds both files from the log and swaps them in, so a power
    loss that left whole but hollow records cannot reach a decision.  Damage to the files while the marker says clean is
    outside the threat model (disk faults behind a completed sync).  Retry and pending frames are as in `Run.handle`.
    Synthetic, nonpayment, non-PHI, activation=false. -/

namespace BlindLedger.Gate.Engine3.Run

open BlindLedger.Gate BlindLedger.Gate.Rules BlindLedger.Gate.Flat BlindLedger.Gate.Flat.Worker
open BlindLedger.Gate.Frame (Word)

structure StoreH where
  /-- Taken out (`swap`) for the puts so that the tables are updated in place. -/
  h : IO.Ref (Option Hist.Hist)
  /-- The links files, taken out the same way. -/
  lk : IO.Ref (Option Links.Two)
  /-- The `facts` file and its tables (`Facts`), taken out the same way. -/
  fx : IO.Ref (Option Facts.Facts)
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
  if let some lk ← s.lk.get then lk.close
  if let some fx ← s.fx.get then fx.close
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

/-- A clean stop: the rows, links and facts files synced, then the marker 1.  Without it the next start rebuilds the
    files. -/
def closeH (s : StoreH) : IO Unit := do
  if let (some hv, some lk, some fx) := (← s.h.get, ← s.lk.get, ← s.fx.get) then
    try
      hv.rel.f.sync
      hv.unr.f.sync
      lk.sync
      if (← Io.pgSync fx.fd) != 0 then throw (IO.userError "facts sync")
      let _ ← markerSet s.dir 1
    catch _ => pure ()
  closeFds s

/-- The trailer of batch `s.bt + 1` with heads `hr` and `hu`, authority record `au`, identity `rq`, answer digest `an`,
    `replaced` (`Z` or the digest of the pending frame it replaces) and batch digest `bd`, its root and chain head computed. -/
def trailerH (s : StoreH) (hr hu : Head) (au rq an replaced bd : ByteArray) : Trailer :=
  let t0 : Trailer := ⟨s.shard, s.bt + 1, hr, hu, 1, 0, noSeal, none, none, none, au, rq, an, replaced, s.head, bd, zero64, zero64⟩
  let root := rootFour t0 zero64 (storeKs s.sec) none
  { t0 with root, head := chainHead s.head t0.bd root }

/-- The parts of the frame of batch `s.bt + 1` for request bytes `bs` (digest `dg`) and the decided batch `d`, on a history whose heads
    are `hr` and `hu`; `replaced` is `Z` or the digest of the pending frame it replaces.  None when the answer is missing. -/
def freshH (s : StoreH) (hr hu : Head) (d : DoneH) (replaced : ByteArray) :
    IO (Option (Trailer × ByteArray × ByteArray)) := do
  let tw ← IO.monoNanosNow
  let some (ans, an, ib) := d.ans.get | return none
  let tf ← tick 4 tw
  let hr' : Head := ⟨hr.asOf, hr.count + d.fr.size, hr.n + d.fr.size⟩
  let hu' : Head := ⟨hu.asOf, hu.count + d.fu.size, hu.n + d.fu.size⟩
  let t := trailerH s hr' hu' d.au ib an replaced d.bd.get
  let trb ← evalNow t.encode
  let _ ← tick 7 tf
  return some (t, ans, trb)

/-- The frame of batch `s.bt + 1` (request `bs`, answer `ans`, trailer `t` encoded as `trb`) to the log, synced: in place of the
    pending frame `pend`, which is kept when its bytes are this frame's and else replaced by the frame `again` makes naming it,
    or after the log.  The trailer, the answer and the frame's place; `IO` when a write or the sync fails, `CORRUPT` when
    `again` gives nothing. -/
def appendH (s : StoreH) (bs : ByteArray) (pend : Option (ByteArray × ByteArray × Trailer × ByteArray)) (t : Trailer)
    (ans trb : ByteArray) (again : ByteArray → IO (Option (Trailer × ByteArray × ByteArray))) :
    IO (Except Word (Trailer × ByteArray × FrameRef)) := do
  let mut t := t
  let mut ans := ans
  let mut trb := trb
  let mut off := s.logLen
  let mut keep := false
  if let (some (_, _, _, pb), some pf) := (pend, s.pend) then
    off := pf.off
    if pb == encodeFrame bs ans trb then keep := true
    else
      let some (t2, a2, tr2) ← again (replacedDigest pb) | return .error .CORRUPT
      t := t2
      ans := a2
      trb := tr2
  if !keep then
    crashAt "before_append"
    if off < s.logLen then
      if (← Io.pgTrunc s.log off.toUInt64) != 0 then return .error .IO
    let ta ← IO.monoNanosNow
    -- the frame goes to the log in its four parts: no copy of the multi-megabyte whole
    let o := off.toUInt64
    if (← Io.pgWrite s.log o (frameHead bs.size ans.size trb.size)) != 0 || (← Io.pgWrite s.log (o + 16) bs) != 0 ||
        (← Io.pgWrite s.log (o + 16 + bs.size.toUInt64) ans) != 0 ||
        (← Io.pgWrite s.log (o + 16 + bs.size.toUInt64 + ans.size.toUInt64) trb) != 0 || (← Io.pgSync s.log) != 0 then
      return .error .IO
    let _ ← tick 8 ta
    crashAt "after_append"
  else if (← Io.pgSync s.log) != 0 then return .error .IO  -- the kept frame's own sync may have failed: sync before answering
  return .ok (t, ans, ⟨off, bs.size, ans.size, trb.size⟩)

/-- The store after batch `s.bt + 1`, logged at `ref` with trailer `t` and authority record `au`; its answer carries `t`'s head
    and root. -/
def sealedH (s : StoreH) (t : Trailer) (au : ByteArray) (ref : FrameRef) : StoreH :=
  { s with bt := s.bt + 1, head := t.head, root := t.root, au, logLen := ref.off + ref.len, last := some ref, pend := none,
           patch := some (t.head, t.root) }

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
  -- a pending frame of another request answers CONFLICT, unless it is a decision frame whose authority record this
  -- request's floors have passed (`RuleGate.passedBy`): then this batch is decided and its frame replaces the pending one,
  -- naming it (`appendH`).  A fact frame carries the record of the batch before it, so it is never cut
  if let some (prb, _, t, _) := pend then
    if t.rq != (Frame.Fast.identFast bs q).1 && (isFact prb || !((decAuth t.au.toList).any (RuleGate.passedBy · q.auth))) then
      return (s, refusal bs .CONFLICT)
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
      if let some lk ← s.lk.swap none then lk.close
      s.h.set none
      return (s, refusal bs w)
    let some (t, ans, trb) ← freshH s hr hu d zero64 | fail .CORRUPT
    -- the links records of the rows just put, from the answer's records and authority day
    let some (tr, tu) := Links.tailsOf ans | return ← fail .CORRUPT
    let some lk ← s.lk.swap none | return ← fail .CORRUPT
    if !lk.fits hv.rel hv.unr tr tu then
      lk.close
      return ← fail .CORRUPT
    let some lk' ← (try some <$> lk.put hv.ctx hv.rel hv.unr tr tu catch _ => pure none)
      | lk.close; return ← fail .IO
    s.lk.set (some lk')
    let mm ← memMark 1 mm
    match ← appendH s bs pend t ans trb (freshH s hr hu d) with
    | .error w => fail w
    | .ok (t, ans, ref) =>
      let _ ← memMark 2 mm
      let _ ← tick 16 th
      return (sealedH s t d.au ref, ans)

/-- One fact frame `q` (header digest `dg`, bytes `bs`) on the store, by `handleH`'s retry rule with `dg` as the batch identity
    (`FactFrame.retry`; batch 1 is refused before the store is opened): the logged answer to a resend of the last batch,
    `CONFLICT` for another digest there or at the pending frame.  Then the receipt and rows are admitted (`Facts.admit`), the
    records appended to `facts`, and the frame to the log.  The trailer is a zero-line batch's: row counts and authority
    record unchanged, `bd` the batch digest of no rows. -/
def handleF (s : StoreH) (bs : ByteArray) (q : FactFrame.Req) (dg : ByteArray) : IO (StoreH × ByteArray) := do
  let n := q.batch
  if n == s.bt then
    let some f := s.last | return (s, refusal bs .NOT_NEXT)
    let some (_, an, t, _) ← readFrame s.log f | return (s, refusal bs .CORRUPT)
    if t.rq != dg then return (s, refusal bs .CONFLICT)
    if ansBind an != t.an then return (s, refusal bs .CORRUPT)
    return (s, patchAns an t.head t.root)
  if n != s.bt + 1 then return (s, refusal bs .NOT_NEXT)
  if q.prev.toByteArray != s.head then return (s, refusal bs .HEAD)
  let pend ← match s.pend with
    | some f => readFrame s.log f
    | none => pure none
  if s.pend.isSome && pend.isNone then return (s, refusal bs .CORRUPT)
  if let some (_, _, t, _) := pend then
    if t.rq != dg then return (s, refusal bs .CONFLICT)
  let some hv ← s.h.get | return (s, refusal bs .CORRUPT)
  let some fx ← s.fx.swap none | return (s, refusal bs .CORRUPT)
  -- a failed write leaves the store to be opened again from disk, which cuts `facts` back to the log or rebuilds it
  let fd := fx.fd
  let fail (w : Word) : IO (StoreH × ByteArray) := do
    let _ ← Io.pgClose fd
    closeRows hv
    s.h.set none
    return (s, refusal bs w)
  -- the facts are out of the cell from here to `s.fx.set`: an exception in between closes their file, which no store holds
  try
    failOnceAt "facts_in_flight"
    let n0 := fx.bodies.size
    -- a refused frame leaves the facts as they were; any other verdict takes them
    let v := Facts.verdict fx n q.rcpt q.rows.length
    if let .refuse w := v then
      s.fx.set (some fx)
      return (s, refusal bs w)
    let .ok (ents, fx, rb) := Facts.apply v fx n q.rcpt q.rows | fail .CORRUPT
    if rb.size != 0 && (← Io.pgWrite fd (Obligations.recBytes * n0).toUInt64 rb) != 0 then return ← fail .IO
    let fresh (replaced : ByteArray) : IO (Option (Trailer × ByteArray × ByteArray)) := do
      let ans := Facts.answer q.shard n dg ents (Facts.rsOf fx.refs)
      let t := trailerH s hv.hr hv.hu s.au dg (ansBind ans) replaced (batchDigestFast s.au ([], []))
      return some (t, ans, t.encode)
    let some (t, ans, trb) ← fresh zero64 | return ← fail .CORRUPT
    match ← appendH s bs pend t ans trb fresh with
    | .error w => fail w
    | .ok (t, ans, ref) =>
      s.fx.set (some fx)
      return (sealedH s t s.au ref, ans)
  catch e =>
    let _ ← Io.pgClose fd
    throw e

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
    are put at once.  `IO` when a frame cannot be read, `CORRUPT` when one is read and does not replay (`frameRows`). -/
def refill (ctx : KeyCtx) (log : UInt32) (frames : Array FrameInfo) (trs : Array Trailer) (bt : Nat) (rel unr : Hist.Side) :
    IO (Except Word (Hist.Side × Hist.Side)) := do
  let ns := trs.map fun t => (t.hr.n, t.hu.n)
  let mut a := 0
  while a < bt && ns[a]!.1 ≤ rel.f.n && ns[a]!.2 ≤ unr.f.n do a := a + 1
  let mut rel := rel
  let mut unr := unr
  while a < bt do
    let b := min bt (a + refillWindow)
    let mut jobs : Array (Nat × Task (Except String (List Line × List Line))) := #[]
    for j in [a:b] do
      -- the test hook `refill_read` makes one read come back short
      let fr ← try failOnceAt "refill_read"; readFrame log frames[j]!.ref catch _ => pure none
      let some (rqb, anb, t, _) := fr | return .error .IO
      jobs := jobs.push (j, Task.spawn fun _ => frameRows rqb anb t)
    let mut ri : Array (List Line × Nat) := #[]
    let mut ui : Array (List Line × Nat) := #[]
    for (j, job) in jobs do
      match job.get with
      | .ok (fr, fu) =>
        ri := ri.push (fr, ns[j]!.1)
        ui := ui.push (fu, ns[j]!.2)
      | .error _ => return .error .CORRUPT
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

/-- Both rows files again from the frames `[0, bt)`, into new files that replace the old ones once synced.  None when
    done; `CORRUPT` when a frame does not replay (`refill`: its answer is not one the engine reads, or its rows do not
    reach the signed counts), `IO` when a file or a frame read fails. -/
def rebuildRows (dir : String) (ctx : KeyCtx) (log : UInt32) (frames : Array FrameInfo) (trs : Array Trailer) (bt : Nat) (hr hu : Head) :
    IO (Option Word) := do
  try
    let .ok rel ← Hist.Side.load ctx s!"{dir}/rows_rel.new" 0 false | return some .IO
    let .ok unr ← Hist.Side.load ctx s!"{dir}/rows_unr.new" 0 true | rel.close; return some .IO
    let r ← refill ctx log frames trs bt rel unr
    let bad : Option Word := match r with
      | .ok (a, b) => if a.f.n == hr.n && b.f.n == hu.n then none else some .CORRUPT
      | .error w => some w
    if let .ok (a, b) := r then
      a.f.sync
      b.f.sync
      a.close
      b.close
    else
      rel.close
      unr.close
    if let some w := bad then return some w
    IO.FS.rename s!"{dir}/rows_rel.new" s!"{dir}/rows_rel"
    IO.FS.rename s!"{dir}/rows_unr.new" s!"{dir}/rows_unr"
    return none
  catch _ => return some .IO

/-- Every logged answer is of the version this engine reads for its frame: `FactFrame.ansVersion` after a fact request
    (`isFact`, the request's magic), `Frame.version` after any other.  A store written before (`conformance/FRAME_V1.md`
    section 8) is not converted.  Two short reads per frame, the request's magic and the answer's first 6 bytes, so the
    work follows the number of batches, as `scanLog`'s.  `MAGIC` for another version, `IO` for a read that comes back
    short. -/
def versionsOk (log : UInt32) (frames : Array FrameInfo) : IO (Except Word Unit) := do
  for f in frames do
    let m ← Io.pgRead log (f.ref.off + 16).toUInt64 4
    let a ← Io.pgRead log (f.ref.off + 16 + f.ref.rq).toUInt64 6
    if m.size != 4 || a.size != 6 then return .error .IO
    if getN a 4 2 != (if isFact m then FactFrame.ansVersion else Frame.version) then return .error .MAGIC
  return .ok ()

/-- The store of `dir` for a request of shard `shard` and batch `batch` that follows head `prev` under key-set pin `pin`;
    `dq` is the decision request, none for a fact frame.  Batch 1 of a directory with no log creates the store, and only a
    decision frame opens the chain; otherwise it loads at the head the request follows (`batch - 1` batches), a whole frame
    after that being the pending one.  For a fact frame, a batch that is neither the next nor the last logged one is
    `NOT_NEXT`, and the last logged batch after another head is `CONFLICT` (its digest covers its `prev`), as
    `FactFrame.retry` says.  A log holding an answer of a version this engine does not read is refused first, on every
    path (`versionsOk`).  The `facts` file is kept or rebuilt from the log as the rows files are (`Facts.load`).  An open that fails, by a refusal or
    a throw, closes every file it opened.  Only an open that completes adds `dir` to `ownDirs`, so a retry after a failed
    open trusts the files only if the clean-stop marker says so. -/
def openStoreH (dir : String) (shard batch : Nat) (prev pin : ByteArray) (dq : Option Frame.Req) :
    IO (Except Word StoreH) := do
  if batch == 0 then return .error .NOT_NEXT
  let fact := dq.isNone
  if batch == 1 then
    let some q := dq | return .error .NOT_NEXT
    if prev != genesis shard q.asOf pin then return .error .HEAD
  let logP := s!"{dir}/log"
  let h0 : Head := ⟨(dq.map (·.asOf)).getD 0, 0, 0⟩
  let au0 := (dq.map fun q => (encAuth (initAuth q)).toByteArray).getD ByteArray.empty
  -- what to close if the open fails, newest first
  let held ← IO.mkRef (#[] : Array (IO Unit))
  let hold (c : IO Unit) : IO Unit := held.modify (·.push c)
  let refuse (w : Word) : IO (Except Word StoreH) := do
    for c in (← held.get).reverse do
      try c catch _ => pure ()
    return .error w
  if batch == 1 && !(← System.FilePath.pathExists logP) then
    try
      let sec ← initKey dir
      let fd ← Io.pgOpen logP
      if fd == 0xFFFFFFFF then return .error .INIT
      hold (do let _ ← Io.pgClose fd)
      if !(← markerSet dir 0) then return ← refuse .INIT
      let ctx := KeyCtx.ofSecret sec
      let .ok rel ← Hist.Side.load ctx s!"{dir}/rows_rel" 0 false | return ← refuse .INIT
      hold rel.close
      let .ok unr ← Hist.Side.load ctx s!"{dir}/rows_unr" 0 true | return ← refuse .INIT
      hold unr.close
      let lr ← Links.LSide.load ctx s!"{dir}/released.links" rel false false
      hold lr.close
      let lu ← Links.LSide.load ctx s!"{dir}/unresolved.links" unr true false
      hold lu.close
      let some fx ← Facts.create dir | return ← refuse .INIT
      let h ← IO.mkRef (some (⟨ctx, rel, unr, h0, h0⟩ : Hist.Hist))
      ownDirs.modify (·.push dir)
      return .ok ⟨h, ← IO.mkRef (some ⟨lr, lu⟩), ← IO.mkRef (some fx), sec, fd, shard, 0, genesis shard h0.asOf pin, zero64, au0, 0,
        none, none, dir, none⟩
    catch _ => return ← refuse .IO
  let sec ← match ← readKey dir with
    | .ok s => pure s
    | .error _ => return .error .CORRUPT
  let (frames, torn, log) ← match ← scanLog logP with
    | .ok r => pure r
    | .error _ => return .error .CORRUPT
  hold (do let _ ← Io.pgClose log)
  try
    -- a store of an older version decides nothing, whether it stopped cleanly or not (MAGIC: the version is wrong)
    if let .error w ← versionsOk log frames then return ← refuse w
    let n := frames.size
    let bt := batch - 1
    if !(bt == n || bt + 1 == n) then return ← refuse (if fact then .NOT_NEXT else .HEAD)
    let tr ← if bt == 0 then pure none else readTrailer log frames[bt - 1]!
    if bt != 0 && (tr.isNone || tr.map (·.head) != some prev) then
      return ← refuse (if fact && bt + 1 == n && tr.isSome then .CONFLICT else .HEAD)
    let some trs ← chainOk sec log frames bt | return ← refuse .CORRUPT
    -- a store begun under another key-set pin than the tenant's decides nothing (PIN)
    if tr.any (·.au.extract 0 64 != pin) then return ← refuse .PIN
    let ctx := KeyCtx.ofSecret sec
    let (hr, hu) := match tr with | some t => (t.hr, t.hu) | none => (h0, h0)
    -- the marker 0 is durable before any write; a start that finds no marker 1 (and whose process did not complete an
    -- open of this store) rebuilds
    let trusted := (← markerClean dir) || (← ownDirs.get).contains dir
    if !(← markerSet dir 0) then return ← refuse .IO
    if !trusted then
      if let some w ← rebuildRows dir ctx log frames trs bt hr hu then return ← refuse w
    let .ok rel ← Hist.Side.load ctx s!"{dir}/rows_rel" hr.n false | return ← refuse .CORRUPT
    hold rel.close
    let .ok unr ← Hist.Side.load ctx s!"{dir}/rows_unr" hu.n true | return ← refuse .CORRUPT
    hold unr.close
    let (rel, unr) ← match ← refill ctx log frames trs bt rel unr with
      | .ok r => pure r
      | .error w => return ← refuse w
    if rel.f.n != hr.n || unr.f.n != hu.n then return ← refuse .CORRUPT
    if torn < (← System.FilePath.metadata logP).byteSize.toNat then
      if (← Io.pgTrunc log torn.toUInt64) != 0 || (← Io.pgSync log) != 0 then return ← refuse .IO
    failOnceAt "open_before_links"
    -- the links files: kept up to their first record the rows do not give (none unless trusted), then the rest from the
    -- answers, each checked against its trailer
    let ansOf (j : Nat) : IO (Option ByteArray) := do
      let f := frames[j]!.ref
      let a ← Io.pgRead log (f.off + 16 + f.rq).toUInt64 f.an.toUSize
      return if a.size == f.an && trs[j]?.map (·.an) == some (ansBind a) then some a else none
    let lr ← Links.LSide.load ctx s!"{dir}/released.links" rel false trusted
    hold lr.close
    let lu ← Links.LSide.load ctx s!"{dir}/unresolved.links" unr true trusted
    hold lu.close
    let some lk ← (⟨lr, lu⟩ : Links.Two).extend ctx rel unr (trs.map fun t => (t.hr.n, t.hu.n)) ansOf
      | return ← refuse .CORRUPT
    let .ok fx ← Facts.load dir log frames trs bt trusted | return ← refuse .CORRUPT
    hold fx.close
    let h ← IO.mkRef (some (⟨ctx, rel, unr, hr, hu⟩ : Hist.Hist))
    let st : StoreH := ⟨h, ← IO.mkRef (some lk), ← IO.mkRef (some fx), sec, log, shard, bt, prev, (tr.map (·.root)).getD zero64,
      (tr.map (·.au)).getD au0,
      (← System.FilePath.metadata logP).byteSize.toNat, if bt == 0 then none else some frames[bt - 1]!.ref,
      if bt < n then some frames[bt]!.ref else none, dir, none⟩
    ownDirs.modify fun a => if a.contains dir then a else a.push dir
    return .ok st
  catch _ => return ← refuse .IO

end BlindLedger.Gate.Engine3.Run
