import BlindLedger.Gate.Engine3.Store
import BlindLedger.Gate.Engine3.VMirror
import BlindLedger.Gate.Engine3.AdmitB

/-! The checker of conformance/ENGINE_V3.md section 10, as running code.  It shares no memory with the engine: it reads
    `key` and the frames of `log`, builds its own history (`VMirror`: its own tagged rows files, tables, chain walk and
    reads; none of the engine's `Hist` or `StepH`) in a directory of its own (`vdir`) from batch 1, and checks a store
    of `gate_hist3` (rows files, HStore.lean) with `checkFrame`.
    Each frame's request is decoded by `decodeB` and admitted by `Run.admit` and `admB` (proved equal to the specification's
    decoder and `Run.admit`; the first frame and one in 64 are also decoded and admitted by the specification's code and
    must agree), and its kept lines decided by the proved `decideRows` over the checker's reads, POSTING_CAP counted
    per core; the answer bytes, `an`, the request, batch and authority digests, the heads, `Root4` and the head must be
    the frame's, and the trailer the one `freshH` writes (no chunk events, install number 1, no windows).  Shared with
    the engine and not yet proved: the answer encoder `ansW` (`encAnsW_eq` open), `batchDigestB` (`batchDigestB_eq`
    open), `leafIn`, the feed pins (`snapK`), the store lines and `assemble`.

    The next frame's decode, the answer, the batch digest and the answer and digest checks run on other cores, and a
    frame's mismatch is reported only after every earlier frame's checks passed, so it is the first in log order.

    `RR_V3_SKIP=answer` (a test hook, as `RR_E3_CRASH` is) turns the answer check off so the tests can show the check is
    what stops the tampering.
    Synthetic, nonpayment, non-PHI, activation=false. -/

namespace BlindLedger.Gate.Engine3.Verify

open BlindLedger.Gate BlindLedger.Gate.Rules BlindLedger.Gate.Flat BlindLedger.Gate.Flat.Worker
open BlindLedger.Gate.Engine3.Run
open BlindLedger.Gate.Frame (Rule)

def hexOf (b : ByteArray) : String :=
  let d := "0123456789abcdef".toList.toArray
  b.foldl (fun s x => s.push d[(x >>> 4).toNat]! |>.push d[(x &&& 15).toNat]!) ""

/-- `VERIFY_MISMATCH(shard)`: the batch, what differed, and both digests. -/
structure Mismatch where
  shard : Nat
  batch : Nat
  what : String
  engine : ByteArray
  mine : ByteArray

def Mismatch.show (m : Mismatch) : String :=
  s!"VERIFY_MISMATCH({m.shard}) batch {m.batch} {m.what}: engine {hexOf m.engine} verifier {hexOf m.mine}"

structure Ctx where
  vdir : String
  sec : ByteArray
  shard : Nat
  skip : List String
  /-- Nanoseconds.  On the frame path: 0 fetch, 1 decision, 11 puts, 4 heads and root, 12 waits for the other
      cores, 5 the whole frame.  On the other cores: 6 answer, 7 batch digest, 8 frame decode and digests, 9 answer
      check.  Slots 2, 3 and 10 are unused. -/
  prof : IO.Ref (Array Nat)

def Ctx.add (c : Ctx) (i t : Nat) : IO Unit := c.prof.modify fun a => a.modify i (· + t)

def headsDigest (hr hu : Head) (nx : Nat) : ByteArray :=
  hD "VERIFY/HEADS" [put64n (putHead (putHead ByteArray.empty hr) hu) nx]

/-- A frame decoded: the request bytes, the request and its digest, the answer bytes, the trailer. -/
structure Pre where
  rqb : ByteArray
  q : Frame.Req
  dg : ByteArray
  anb : ByteArray
  t : Trailer

def prep (f : FrameRef) (raw : ByteArray) : Except String Pre := do
  let some (rqb, anb, t, _) := splitFrame f raw | throw "frame unreadable"
  let dec := Frame.Fast.decodeB rqb
  -- the first batch and every `RR_E3_SPEC`-th (default 64) is also read by the list decoder, which must agree
  if (if rqb.size < 18 then 1 else getN rqb 10 8) % specEvery == 1 % specEvery then
    unless Frame.Fast.sameDec dec (Frame.Fast.decodeReqFast rqb) do throw "request decodes differ"
  let .ok (q, dg) := dec | throw "request undecodable"
  pure ⟨rqb, q, dg, anb, t⟩

/-- The checks of frame `n` that read nothing the next batch changes, in the order of section 10 step 1: the answer
    bytes and `an`, the batch's identity, the batch and authority digests.  The lines the frame records. -/
def late (c : Ctx) (n : Nat) (p : Pre) (ans : Option (ByteArray × ByteArray × ByteArray)) (bd au : ByteArray) :
    Except Mismatch Nat := do
  let bad (what : String) (a b : ByteArray) : Except Mismatch Nat := .error ⟨c.shard, n, what, a, b⟩
  let some (mine, an, ib) := ans | return ← bad "decision" zero64 zero64
  if !c.skip.contains "answer" then
    if mine != p.anb then return ← bad "answer" (hD "ANSWER" [p.anb]) (hD "ANSWER" [mine])
    if an != p.t.an then return ← bad "answer digest" p.t.an an
  if ib != p.t.rq then return ← bad "request digest" p.t.rq ib
  if bd != p.t.bd then return ← bad "batch digest" p.t.bd bd
  if au != p.t.au then return ← bad "authority record" (hD "AU" [p.t.au]) (hD "AU" [au])
  pure (getN mine 19 4)

/-- The late checks `ps`, oldest first, joined: the lines they record, or the first mismatch.  The wait is slot 12. -/
def join (c : Ctx) (ps : Array (Task (Except Mismatch Nat))) : IO (Except Mismatch Nat) := do
  let t0 ← IO.monoNanosNow
  let r := ps.foldlM (fun k x => (k + ·) <$> x.get) 0
  let t1 ← if r.isOk then IO.monoNanosNow else pure t0
  c.add 12 (t1 - t0)
  return r

/-- `late` on another core once the step's other cores are done.  A function of its own, so the task holds the step's
    answer parts and never its engine, whose open window must stay unshared for the next batch's puts. -/
@[noinline] def lateTask (c : Ctx) (n : Nat) (p : Pre) (ans : Task (Option (ByteArray × ByteArray × ByteArray)))
    (bd : Task ByteArray) (au : ByteArray) : BaseIO (Task (Except Mismatch Nat)) :=
  BaseIO.bindTask ans fun a => BaseIO.bindTask bd fun b =>
    spawnT (some c.prof) 9 (·.isOk) fun _ => late c n p a b au

/-! ## The checker on the history path -/

/-- The checker's state after `n` batches: its history, the heads of the two sets, the authority record and the head.
    Before batch 1 (`n = 0`) the heads, record and head are those batch 1's request starts from. -/
structure VC where
  m : VMirror.M
  hr : Head
  hu : Head
  au : ByteArray
  prev : ByteArray
  n : Nat

/-- A decided batch: the reads (for the puts), the lines the sets gain, the answer with its `an`, the authority record
    after it and the batch digest. -/
structure DoneC where
  g : VMirror.Got
  fr : Array Nat
  fu : Array Nat
  ans : Task (Option (ByteArray × ByteArray × ByteArray))
  au : ByteArray
  bd : Task ByteArray

/-- The batch of request `q` (digest `dg`, bytes `bs`) on the checker's history: admission (`Run.admit` on every batch, `admB`; the first batch and one in 64 also by `Run.admit` on the lines), the reads,
    `decideRows`, then the answer and the batch digest on other cores (slots 6 and 7).  None when the batch is not one
    the engine answers OK (admission refused, an authority record or a line that does not fit, a row number past 2^40). -/
def stepC (c : Ctx) (v : VC) (q : Frame.Req) (dg bs : ByteArray) : IO (Option DoneC) := do
  let au := q.auth
  if !au.reqs.isEmpty && au.release.isEmpty then return none
  let hsh (x : List UInt8) : List UInt8 := Run.hB ⟨x.toArray⟩
  let some au0 := decAuth v.au.toList | return none
  let opt (b : Bytes) : Option Bytes := if b.isEmpty then none else some b
  let st : Run.St :=
    { today := q.today, redo := q.redo, reqs := au.reqs.toArray, grant := opt au.grant, release := opt au.release
      byps := au.byps, floorIn := au.floor, kfloorIn := some au.kfloor, keyset := opt au.keyset, ksteps := au.ksteps }
  let adm : Except String Run.Admitted ←
    if st.reqs.isEmpty then pure (.error "") else pure (Run.admit mlDsaMemo au0.pin au0.rat au0.floor st)  -- every batch, uncached: the checker does not trust the engine's kept admission
  if let .error _ := adm then if !st.reqs.isEmpty then return none
  let reqs := st.reqs
  let ab := admB adm reqs
  let (covR, unfR, bPos) := (ab.cov, ab.unf, ab.bPos)
  let ens := entsB adm reqs
  -- the lines the rules decide are counted, not built: `VMirror.read` takes the number of them
  let b : Array Line := Array.replicate bPos.size Rows.nilLine
  -- a bypass or a HOLD-level entry names a payment by its number, built (from the payment key) only when the batch has one
  let reqsQ : Array Run.Req := match adm with
    | .ok a => if a.byps.isEmpty && !ens.any (·.any (·.authority == .HOLD)) then reqs else reqs.map fun x => { x with q := Frame.Fast.idNatA (Frame.Fast.payKeyOf x.ra) }
    | .error _ => reqs
  let (bps, byp, notes) := match adm with
    | .ok a => (a.byps, Run.bypOf hsh a.byps reqsQ.toList, a.notes)
    | .error _ => ([], [], [])
  let lim := limB reqsQ ens
  -- the first batch and every `RR_E3_SPEC`-th (default 64) is also admitted from the requests' lines, which must agree
  if ← specDue q.batch then
    let ok := match reqs.mapM (fun x => Frame.Fast.reqOfFast x.x) with
      | none => false
      | some rs =>
        let adm' : Except String Run.Admitted :=
          if rs.isEmpty then .error "" else Run.admit mlDsaMemo au0.pin au0.rat au0.floor { st with reqs := rs }
        let sa := specAdm adm' rs
        sameReqs reqs rs && sameAdm adm adm' && ab.cov == sa.cov && ab.fit == sa.fit && ab.unf == sa.unf && ab.bPos == sa.bPos &&
          (match adm' with
            | .ok a => Run.bypOf hsh a.byps rs.toList == byp && Run.limOf a.grant rs.toList == lim
            | .error _ => true)
    if !ok then
      IO.eprintln "SPEC_MISMATCH admission"
      return none
  let pins ← feedPins.get
  let kn : Array Bool := (Array.range 4).map fun k => feedKnown (pins.getD k .empty) bs k
  let dmf := snapK kn[0]! 1 Death.fields q.dmf
  let pd := snapK kn[1]! 2 Death.fields q.pdeath
  let ex := snapK kn[2]! 3 Exclusion.fields q.excl
  let sp := snapK kn[3]! 4 Span.fields q.span
  let ok := #[dmf.isSome, pd.isSome, ex.isSome, sp.isSome]
  if (Array.range 4).any (fun k => ok[k]! && !kn[k]!) then
    feedPins.set <| (Array.range 4).map fun k =>
      if ok[k]! && !kn[k]! then let (d, o, n) := feedAt bs k; bs.extract d (d + 77) ++ bs.extract o (o + n)
      else pins.getD k .empty
  if rowsFullF v.hr v.hu b.size then return none
  let kept := (reqs.zip (covR.zip unfR)).filterMap fun (x, c, u) => if c && !u then some x else none
  let t0 ← IO.monoNanosNow
  let some g ← VMirror.read v.m v.hr v.hu bs q kept b byp lim (dmf.isSome, pd.isSome, ex.isSome, sp.isSome) | return none
  let t1 ← IO.monoNanosNow
  let lay := g.lay
  let out := Rows.decideRows lay
  let t2 ← if out.ds.size == 0xFFFFFFFFFF then pure 0 else IO.monoNanosNow
  c.add 0 (t1 - t0)
  c.add 1 (t2 - t1)
  let (payIx, np) := Id.run do
    let mut ix : Array (Option Nat) := Array.mkEmpty reqs.size
    let mut n := 0
    for x in reqs, c in covR, u in unfR do
      if c && !u && x.ra.flow.ruled && !x.ra.lines.isEmpty then
        ix := ix.push (some n)
        n := n + 1
      else ix := ix.push none
    pure (ix, n)
  let nb := lay.lines.size
  let inRel : Array Bool := out.rel.foldl (fun a i => a.set! i true) (Array.replicate nb false)
  let inUnr : Array Bool := out.unr.foldl (fun a i => a.set! i true) (Array.replicate nb false)
  let (fl, msk) := Id.run do
    let mut fl : ByteArray := ⟨Array.replicate np 0⟩
    let mut msk : Array UInt32 := Array.replicate np 0
    for d in out.ds do
      let li := lay.lines[d.line]!
      let p := li.pay
      let sl := lay.slots[li.ki]!
      let own := lay.pRedo[p]! && Rows.anySame lay.relP sl.rs sl.rn li.row
      let mut f := fl[p]! ||| 4
      if d.out == 1 then f := f ||| 1
      if !(d.out == 0 && (!lay.pRedo[p]! || own)) then f := f ||| 2
      if inRel[d.line]! && d.out != 0 then f := f ||| 8
      if out.byd[p]! then f := f ||| 16
      if out.lft[d.line]! then f := f ||| 32
      fl := fl.set! p f
      msk := msk.set! p (msk[p]! ||| d.mask)
    pure (fl, msk)
  let flOf (pix : Option Nat) : UInt8 × UInt32 := match pix with
    | some p => (fl[p]!, msk[p]!)
    | none => (0, 0)
  let locOf (cp : Nat) : Option (Nat × Nat) :=
    if cp == 0 then none else if cp % 2 == 1 then ((g.relSeq[cp / 2]?).map (0, ·)) else ((g.unrSeq[cp / 2 - 1]?).map (1, ·))
  let (recs, nr) := Id.run do
    let mut r := ByteArray.emptyWithCapacity (20 * out.ds.size + 20)
    for d in out.ds do
      let rule : Rule := if fl[lay.lines[d.line]!.pay]! &&& 8 != 0 then .bypassed else if inRel[d.line]! then .released
        else if inUnr[d.line]! then .unresolved else .decided
      r := Frame.Fast.putRec r ⟨bPos.getD d.line 0, d.out.toNat, rule, d.mask.toNat, locOf d.cp⟩
    let mut nr := out.ds.size
    let mut n := 0
    for x in reqs, c in covR, u in unfR do
      if c then
        if u then
          let pk := (Frame.Fast.payKeyOf x.ra).size
          for ln in (if x.ra.flow.ruled then x.ra.lines else []) do
            r := Frame.Fast.putRec r ⟨n, 1, if Frame.Fast.lineFits ln 0 ln.size pk then .sibling else .wide, 0, none⟩
            n := n + 1
            nr := nr + 1
        else n := n + nLines x
    pure (r, nr)
  let leafIns (_ : Unit) : Array LeafIn := match adm with
    | .error _ => #[]
    | .ok a =>
      let gid := a.grant.id.toByteArray
      (reqs.zip (ens.zip (unfR.zip payIx))).map fun (x, en, u, pix) =>
        let (f, m) := flOf pix
        leafIn a gid x en u f m
  let bydQ (p : Nat) : Bool := match reqsQ.findIdx? (·.q == p) with
    | some i => (flOf payIx[i]!).1 &&& 16 != 0
    | none => false
  let bn := notes ++ (match adm with
    | .ok _ => Run.bypNotes hsh bps reqsQ.toList bydQ
    | .error _ => [])
  let notesB := bn.map (·.toUTF8)
  let (lb, rel1, unr1, shard, batch) := (g.lb, out.rel, out.unr, q.shard, q.batch)
  let au' : AuthRec := match adm with
    | .ok a => ⟨au0.pin, a.ratchet, a.grant.serial⟩
    | .error _ => au0
  let auB := (encAuth au').toByteArray
  let ans ← spawnT (some c.prof) 6 Option.isSome fun _ =>
    some (ansW false shard batch dg recs nr auB notesB (leafIns ()) (Frame.Fast.contextAt bs (Frame.Fast.ctxEnd bs q)) lb rel1
      unr1)
  let bd ← spawnT (some c.prof) 7 (·.size != 1) fun _ => batchDigestB lb auB rel1 unr1
  return some ⟨g, rel1, unr1, ans, auB, bd⟩

/-- Frame `v.n + 1` of a rows-file store decoded as `p`, on the checker's history: the batch (slot 0 reads, 1 the
    decision), its late checks on another core, the puts (slot 11), then the heads, the trailer of `freshH`, `Root4` and
    the head (slot 4).  A fault of the checker's store is an IO error (`VMirror.faultTag`). -/
def checkFrame (c : Ctx) (v : Option VC) (p : Except String Pre) : IO (Except Mismatch (VC × Task (Except Mismatch Nat))) := do
  let n := (v.map (·.n)).getD 0 + 1
  let bad {α : Type} (what : String) (a b : ByteArray) : IO (Except Mismatch α) := pure (.error ⟨c.shard, n, what, a, b⟩)
  let some v := v | bad "checker state" zero64 zero64
  let p ← match p with
    | .ok p => pure p
    | .error w => return ← bad w zero64 zero64
  let (q, t) := (p.q, p.t)
  if q.shard != c.shard || t.shard != c.shard || q.batch != n || t.batches != n then
    return ← bad "shard or batch number" (put64n ByteArray.empty t.batches) (put64n ByteArray.empty n)
  let h0 : Head := ⟨q.asOf, 0, 0⟩
  let v := if v.n == 0 then { v with hr := h0, hu := h0, au := (encAuth (initAuth q)).toByteArray, prev := genesis q.shard q.asOf q.auth.pin.toByteArray } else v
  if t.prev != v.prev || q.prev.toByteArray != v.prev then return ← bad "previous head" t.prev v.prev
  -- the logged authority record keeps the key-set pin and lowers neither the epoch nor the grant floor
  if !Flat.ChunkIo.authFollows v.au.toList t.au.toList then return ← bad "authority record" t.au v.au
  -- 1. the batch on the checker's history; the answer and the digests are checked on another core
  let some d ← stepC c v q p.dg p.rqb | bad "decision" zero64 zero64
  let chk ← lateTask c n p d.ans d.bd d.au
  let badL {α : Type} (what : String) (a b : ByteArray) : IO (Except Mismatch α) := do
    match ← join c #[chk] with
    | .error m => pure (.error m)
    | .ok _ => bad what a b
  -- 2. the puts: `v` is taken apart first, so the history is written in place
  let t1 ← IO.monoNanosNow
  let ⟨m, hr, hu, _, _, _⟩ := v
  let m ← VMirror.put m d.g d.fr d.fu
  let hr : Head := ⟨hr.asOf, hr.count + d.fr.size, hr.n + d.fr.size⟩
  let hu : Head := ⟨hu.asOf, hu.count + d.fu.size, hu.n + d.fu.size⟩
  let t2 ← IO.monoNanosNow
  -- 3. heads, no events and no windows, root and head
  if hr != t.hr || hu != t.hu || t.nx != 1 then
    return ← badL "heads or install number" (headsDigest t.hr t.hu t.nx) (headsDigest hr hu 1)
  if t.bOpen != 0 || t.bSeal != noSeal || t.sealEv.isSome || t.installEv.isSome || t.reclaimEv.isSome then
    return ← badL "window numbers or events" (put64n (put64n ByteArray.empty t.bOpen) t.bSeal) (put64n (put64n ByteArray.empty 0) noSeal)
  let root4 := rootFour t zero64 (storeKs c.sec) none
  if root4 != t.root then return ← badL "Root4" t.root root4
  let hd := chainHead t.prev t.bd root4
  if hd != t.head then return ← badL "head" t.head hd
  let t3 ← IO.monoNanosNow
  c.add 11 (t2 - t1)
  c.add 4 (t3 - t2)
  return .ok (⟨m, hr, hu, d.au, t.head, n⟩, chk)

/-! ## The checker's last state

    `vlast` in the checker's directory, rewritten after every run of whole frames it checked: shard u32 ‖ batches u64 ‖
    log position u64 ‖ lines u64 ‖ the two heads ‖ the head (64) ‖ the authority record, then
    `H512(dom VLAST ‖ k ‖ those bytes)`.  A start resumes from it only when its tag holds under the store's key, each
    set's file holds exactly the rows its head counts (so a file rolled back or cut is caught), and the log's bytes
    just before the position are the head; anything else rebuilds the store from the log.  Whether `vlast` itself is
    the newest is the TPM check of a later step. -/

structure Last where
  n : Nat
  pos : Nat
  lines : Nat
  hr : Head
  hu : Head
  prev : ByteArray
  au : ByteArray

def Last.body (shard : Nat) (l : Last) : ByteArray :=
  putHead (putHead (put64n (put64n (put64n (put32 ByteArray.empty shard) l.n) l.pos) l.lines) l.hr) l.hu ++ l.prev ++ l.au

def Last.enc (k : ByteArray) (shard : Nat) (l : Last) : ByteArray := let b := l.body shard; b ++ hD "VLAST" [k, b]

/-- The fixed part of the body: shard, batches, position, lines, two heads, head. -/
def lastFixed : Nat := 4 + 24 + 40 + 64

def Last.dec (k : ByteArray) (shard : Nat) (raw : ByteArray) : Option Last :=
  if raw.size < lastFixed + 64 then none else
  let b := raw.extract 0 (raw.size - 64)
  if hD "VLAST" [k, b] != raw.extract (raw.size - 64) raw.size || getN b 0 4 != shard then none else
  some ⟨getN b 4 8, getN b 12 8, getN b 20 8, getHead b 28, getHead b 48, b.extract 68 132, b.extract lastFixed b.size⟩

/-- The checker's state from `vdir` and the log (`log`, `size` bytes now), with the store's key and the position and
    lines it had checked; or why it cannot resume. -/
def resume (c : Ctx) (log : UInt32) (size : Nat) : IO (Except String (VC × ByteArray × Nat × Nat)) := do
  let some k ← VStore.loadKey s!"{c.vdir}/vkey" | return .error "no key opens"
  let lp := s!"{c.vdir}/vlast"
  if !(← System.FilePath.pathExists lp) then return .error "no last state"
  let some l := Last.dec k c.shard (← IO.FS.readBinFile lp) | return .error "the last state fails its tag"
  if l.n == 0 || l.pos < 64 || l.pos > size || (← Io.pgRead log (l.pos - 64).toUInt64 64) != l.prev then
    return .error s!"the log does not hold the checked head at offset {l.pos}"
  let .ok m ← VMirror.load c.vdir k c.shard | return .error "the store does not load"
  if m.rel.f.n != l.hr.n || m.unr.f.n != l.hu.n then
    VMirror.close m
    return .error s!"the store holds {m.rel.f.n} released and {m.unr.f.n} unresolved rows, the last state {l.hr.n} and {l.hu.n}"
  return .ok (⟨m, l.hr, l.hu, l.au, l.prev, l.n⟩, k, l.pos, l.lines)

/-- Writes `vlast` for `v`: the rows files first, then the new file, each synced, then renamed over it, so a power loss leaves a
    last state whose rows are on disk (a resume that finds otherwise rebuilds from the log). -/
def saveLast (c : Ctx) (k : ByteArray) (v : VC) (pos lines : Nat) : IO Unit := do
  let p := s!"{c.vdir}/vlast"
  let raw := Last.enc k c.shard ⟨v.n, pos, lines, v.hr, v.hu, v.prev, v.au⟩
  if (← Io.pgSync v.m.rel.f.fd) != 0 || (← Io.pgSync v.m.unr.f.fd) != 0 then throw (IO.userError "vlast: rows sync")
  let fd ← Io.pgOpen s!"{p}.new"
  if fd == 0xFFFFFFFF then throw (IO.userError "vlast: open")
  let ok := (← Io.pgWrite fd 0 raw) == 0 && (← Io.pgTrunc fd raw.size.toUInt64) == 0 && (← Io.pgSync fd) == 0
  let _ ← Io.pgClose fd
  unless ok do throw (IO.userError "vlast: write")
  IO.FS.rename s!"{p}.new" p

/-- The frame at `pos` if the file of `size` bytes holds it whole: its place, and its decode on another core; an
    unreadable header is the error. -/
def readAhead (c : Ctx) (log : UInt32) (size pos : Nat) : IO (Except Unit (Option (FrameRef × Task (Except String Pre)))) := do
  if pos + 16 > size then return .ok none
  let some f := parseHdr (← Io.pgRead log pos.toUInt64 16) pos | return .error ()
  if pos + f.len > size then return .ok none
  let raw ← Io.pgRead log f.off.toUInt64 f.len.toUSize
  return .ok (some (f, ← spawnT (some c.prof) 8 (·.isOk) fun _ => prep f raw))

/-- An earlier frame's mismatch, else `m`. -/
def firstOf (r : Except Mismatch Nat) (m : Mismatch) : Mismatch := match r with
  | .error m' => m'
  | .ok _ => m

/-- The whole frames of the log from `pos` on that the file holds now, each checked by `vf` (`num`: the batches a state
    has): the state after them, the log position and the lines they record.  Frame `n + 1` is read and decoded while
    frame `n` runs; at most two frames' late checks wait, and a mismatch is reported only once every earlier frame's late
    checks passed, so it is the first in log order.  The next frame's decode is waited for before `pump` returns or
    throws: that decode waits on a task of its own (`decodeB`'s digest), and a process that ends while it runs can hang
    in the runtime's exit, which waits for every worker. -/
def pump {σ : Type} (c : Ctx) (vf : Option σ → Except String Pre → IO (Except Mismatch (σ × Task (Except Mismatch Nat))))
    (num : σ → Nat) (log : UInt32) (path : String) (v0 : Option σ) (pos0 : Nat) : IO (Except Mismatch (Option σ × Nat × Nat)) := do
  let size := (← System.FilePath.metadata path).byteSize.toNat
  let ahead : IO.Ref (Option (Task (Except String Pre))) ← IO.mkRef none
  let decodeOf : Except Unit (Option (FrameRef × Task (Except String Pre))) → Option (Task (Except String Pre))
    | .ok (some (_, t)) => some t
    | _ => none
  try
    let mut v := v0
    let mut pos := pos0
    let mut lines := 0
    let mut pend : Array (Task (Except Mismatch Nat)) := #[]
    let mut cur ← readAhead c log size pos
    ahead.set (decodeOf cur)
    repeat
      let t0 ← IO.monoNanosNow
      let n := (v.map num).getD 0 + 1
      let x ← match cur with
        | .error () => return .error (firstOf (← join c pend) ⟨c.shard, n, "log header", zero64, zero64⟩)
        | .ok x => pure x
      let some (f, pre) := x | break
      let next ← readAhead c log size (pos + f.len)
      ahead.set (decodeOf next)
      let tw ← IO.monoNanosNow
      let p := pre.get
      let tw' ← if p.isOk then IO.monoNanosNow else pure tw
      c.add 12 (tw' - tw)
      -- the state moves into `vf`, so its history is updated in place, not copied
      let v0 := v
      v := none
      match ← vf v0 p with
      | .error m => return .error (firstOf (← join c pend) m)
      | .ok (v', chk) =>
        pend := pend.push chk
        if pend.size > 2 then
          match ← join c #[pend[0]!] with
          | .error m => return .error m
          | .ok k => lines := lines + k; pend := pend.extract 1 pend.size
        v := some v'
        pos := pos + f.len
        cur := next
      c.add 5 ((← IO.monoNanosNow) - t0)
    match ← join c pend with
    | .error m => return .error m
    | .ok k => return .ok (v, pos, lines + k)
  finally
    if let some t ← ahead.get then discard <| IO.wait t

end BlindLedger.Gate.Engine3.Verify
