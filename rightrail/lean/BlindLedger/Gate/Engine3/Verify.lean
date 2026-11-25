import BlindLedger.Gate.Engine3.Store
import BlindLedger.Gate.Engine3.VMirror
import BlindLedger.Gate.Engine3.AdmitB
import BlindLedger.Gate.Engine3.RuleGate
import BlindLedger.Gate.FactAdmit

/-! The checker of conformance/ENGINE_V3.md section 10, as running code.  It shares no memory with the engine: it reads
    `key` and the frames of `log`, builds its own history (`VMirror`: its own tagged rows files, tables, chain walk and
    reads; none of the engine's `Hist` or `StepH`) in a directory of its own (`vdir`) from batch 1, and checks a store
    of `gate_hist3` (rows files, HStore.lean) with `checkFrame`.
    Each frame's request is decoded by `decodeB` and admitted by `admitC` and `admB` (proved equal to the specification's
    decoder and `Run.admit`; the first frame and one in 64 are also decoded and admitted by the specification's code and
    must agree), and its kept lines decided by the proved `decideRows` over the checker's reads, POSTING_CAP counted
    per core; the answer bytes, `an`, the request, batch and authority digests, the heads, `Root4` and the head must be
    the frame's, and the trailer the one `freshH` writes (no chunk events, install number 1, no windows).  Shared with
    the engine and not yet proved: the answer encoder `ansW` (`encAnsW_eq` open), `batchDigestB` (`batchDigestB_eq`
    open), `leafIn`, the feed pins (`snapK`), the store lines and `assemble`.

    A fact frame (`RRDF`) is replayed by the specification (`checkF`, `FactFrame.checkFact`): its answer and the records
    it adds are derived again from its request and the checker's own facts (`FactFrame.admit`), sharing only the codecs
    with the engine; it adds no rows to either set.  After the last frame the store's `facts` file must be the file of
    those records, a byte prefix of it, or it and bytes past it (`factsDiff`; the engine cuts it back to the log or writes
    it again at open); the file itself is never read as input.  The checker keeps its own copy of its records (`vfacts`,
    bound by its last state) so that a start need not replay the fact frames already checked.

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

/-- A decision frame decoded: the request bytes, the request and its digest, the answer bytes, the trailer. -/
structure PreD where
  rqb : ByteArray
  q : Frame.Req
  dg : ByteArray
  anb : ByteArray
  t : Trailer

/-- A frame read from the log: a decision frame decoded, or a fact frame (`RRDF`) as its request and answer bytes and its
    trailer, which `checkF` replays. -/
inductive Pre where
  | dec (p : PreD)
  | fact (rqb anb : ByteArray) (t : Trailer)

def prep (f : FrameRef) (raw : ByteArray) : Except String Pre := do
  let some (rqb, anb, t, _) := splitFrame f raw | throw "frame unreadable"
  if isFact rqb then return .fact rqb anb t
  let dec := Frame.Fast.decodeB rqb
  -- the first batch and every `RR_E3_SPEC`-th (default 64) is also read by the list decoder, which must agree
  if (if rqb.size < 18 then 1 else getN rqb 10 8) % specEvery == 1 % specEvery then
    unless Frame.Fast.sameDec dec (Frame.Fast.decodeReqFast rqb) do throw "request decodes differ"
  let .ok (q, dg) := dec | throw "request undecodable"
  -- the engine carried the digest in the request's header; it must be the digest of the body logged
  unless Frame.Fast.frameDigestB rqb == dg do throw "frame digest"
  pure (.dec ⟨rqb, q, dg, anb, t⟩)

/-- The checks of frame `n` that read nothing the next batch changes, in the order of section 10 step 1: the answer
    bytes and `an`, the batch's identity, the batch and authority digests.  The lines the frame records. -/
def late (c : Ctx) (n : Nat) (p : PreD) (ans : Option (ByteArray × ByteArray × ByteArray)) (bd au : ByteArray) :
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
@[noinline] def lateTask (c : Ctx) (n : Nat) (p : PreD) (ans : Task (Option (ByteArray × ByteArray × ByteArray)))
    (bd : Task ByteArray) (au : ByteArray) : BaseIO (Task (Except Mismatch Nat)) :=
  BaseIO.bindTask ans fun a => BaseIO.bindTask bd fun b =>
    spawnT (some c.prof) 9 (·.isOk) fun _ => late c n p a b au

/-! ## The checker on the history path -/

/-- A store's record bodies, in order, as bytes. -/
def storeBytes (st : FactFrame.Store) : ByteArray := ⟨st.toList.flatten.toArray⟩

/-- The bytes `sb` of a store of `n0` records, and those of the records `new` has after them. -/
def extendSb (sb : ByteArray) (n0 : Nat) (new : FactFrame.Store) : ByteArray := sb ++ storeBytes (new.extract n0 new.size)

theorem storeBytes_append (a b : FactFrame.Store) : storeBytes (a ++ b) = storeBytes a ++ storeBytes b := by
  apply ByteArray.ext
  simp [storeBytes, List.flatten_append, ByteArray.data_append]

/-- Appending a frame's records to the bytes of the store before it gives the bytes of the store after it (`admit` only
    appends: `FactFrame.admit_st`). -/
theorem extendSb_eq {old xs : FactFrame.Store} {sb : ByteArray} (h : sb = storeBytes old) :
    extendSb sb old.size (old ++ xs) = storeBytes (old ++ xs) := by
  subst h
  have : (old ++ xs).extract old.size (old ++ xs).size = xs := by
    apply Array.ext'
    simp
  simp only [extendSb, this, storeBytes_append]

/-- The checker's state after `n` batches: its history, the heads of the two sets, the authority record, the head, the
    facts its replay of the fact frames derived (`FactFrame.admit`: the store and the checker's own tables) with the
    reference set's entries in byte order and their `rs` (`FactFrame.refsAfter`), and the digest of the checked fact
    frames' trailer digests (`ffStep`), the store's record bodies in order as bytes (`sb`, the file `vfacts`) and the
    digest `vlast` holds of them (`tg`) when it is known: a decision frame leaves the facts as they were, so the bytes and
    the digest are kept and `saveLast` neither flattens nor hashes them again (`VC.tag_eq`); a fact frame appends its
    records' bytes (`extendSb_eq`) and drops the digest.
    Before batch 1 (`n = 0`) the heads, record and head are those batch 1's request starts from. -/
structure VC where
  m : VMirror.M
  hr : Head
  hu : Head
  au : ByteArray
  prev : ByteArray
  n : Nat
  fs : FactFrame.Facts
  rf : FactFrame.Refs
  ft : ByteArray
  sb : ByteArray
  tg : Option ByteArray

/-- The digest of the fact frames checked so far after fact frame `n` with trailer `t`: its batch and its request and
    answer digests, so a fact frame changed after it was checked changes it. -/
def ffStep (ft : ByteArray) (n : Nat) (t : Trailer) : ByteArray := hD "VLAST/FFRAME" [ft, put64n ByteArray.empty n, t.rq, t.an]

/-- A decided batch: the reads (for the puts), the lines the sets gain, the answer with its `an`, the authority record
    after it and the batch digest. -/
structure DoneC where
  g : VMirror.Got
  fr : Array Nat
  fu : Array Nat
  ans : Task (Option (ByteArray × ByteArray × ByteArray))
  au : ByteArray
  bd : Task ByteArray

/-- The batch of request `q` (digest `dg`, bytes `bs`) on the checker's history: admission (`admitC`, `admB`; the first batch and one in 64 also by `Run.admit` on the lines), the reads,
    `decideRows`, then the answer and the batch digest on other cores (slots 6 and 7).  None when the batch is not one
    the engine answers OK (admission refused, an authority record or a line that does not fit, a row number past 2^40).

    Admission rule: the checker admits a frame in full with `Run.admit` unless every input of the admission (the stored
    pin, ratchet and floor, the day, the asserted floors, the tenant, and the bytes of the key set, grant and key-set
    steps) equals, byte for byte, those of the last frame without a bypass that this checker process admitted in full,
    and the frame itself has no bypass; then it reuses its own earlier result.  That result is the one `Run.admit` would give (`admit_of_key`:
    equal inputs, equal admission), so the verdict is the same as admitting every frame in full.  The kept result is
    made only by this process, from the frame bytes it decoded and its own stored authority record; nothing of it is
    taken from the engine's process or files. -/
def stepC (c : Ctx) (v : VC) (q : Frame.Req) (dg bs : ByteArray) : IO (Option DoneC) := do
  let au := q.auth
  if !au.reqs.isEmpty && au.release.isEmpty || au.reqs.isEmpty && !au.rsets.isEmpty then return none
  let hsh (x : List UInt8) : List UInt8 := Run.hB ⟨x.toArray⟩
  let some au0 := decAuth v.au.toList | return none
  let opt (b : Bytes) : Option Bytes := if b.isEmpty then none else some b
  let st : Run.St :=
    { today := q.today, redo := q.redo, reqs := au.reqs.toArray, grant := opt au.grant, release := opt au.release
      byps := au.byps, floorIn := au.floor, kfloorIn := some au.kfloor, keyset := opt au.keyset, ksteps := au.ksteps }
  -- the rule set (`RuleGate.after`) before the authority: a frame it holds is held whole
  let rg : Except String (Bytes × Nat) := if st.reqs.isEmpty then .ok (au0.rs, au0.rsv) else
    RuleGate.after mlDsaMemo
      (fun _ => st.keyset.bind fun ks => (SnapshotV2.admitBatchHead mlDsaMemo au0.pin q.today au0.rat ks au.ksteps).map (·.1))
      ((au.reqs.head?.map (·.r.tenantId)).getD []) q.batch au0 au
  let adm : Except String Run.Admitted ←
    if st.reqs.isEmpty then pure (.error "") else match rg with
      | .error why => pure (.error why)
      | .ok _ => admitC au0.pin au0.rat au0.floor st
  if let .error _ := adm then if !st.reqs.isEmpty then return none
  let reqs := st.reqs
  let ab := admB adm reqs
  let (covR, unfR, bPos) := (ab.cov, ab.unf, ab.bPos)
  let ens := entsB adm reqs
  -- the lines the rules decide are counted, not built: `VMirror.read` takes the number of them
  let b : Array Line := Array.replicate bPos.size Rows.nilLine
  -- a bypass, a cause record or a HOLD-level entry names a payment by its number, built (from the payment key) only
  -- when the batch has one
  let some (reqsQ, ap) := approvalsB hsh adm reqs ens st.redo | return none
  let (byp, notes) := match adm with
    | .ok a => (ap.byp, a.notes ++ ap.notes)
    | .error _ => ([], [])
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
            | .ok a => (Run.approvals hsh a.grant a.byps a.causes rs.toList st.redo).byp == byp && Run.limOf a.grant rs.toList == lim
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
  -- an exact repeat of a paid line, its sender not contesting, is answered at once and joins neither set
  let some (ax, pa) := answeringB q.today q.redo reqs lay out | return none
  let unr1 := if ax.pays.isEmpty then out.unr else out.unr.filter fun i => !pa[lay.lines[i]!.pay]!
  let nb := lay.lines.size
  let inRel : Array Bool := out.rel.foldl (fun a i => a.set! i true) (Array.replicate nb false)
  let inUnr : Array Bool := unr1.foldl (fun a i => a.set! i true) (Array.replicate nb false)
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
        leafIn ap ax gid x en u f m
  let bydQ (p : Nat) : Bool := match reqsQ.findIdx? (·.q == p) with
    | some i => (flOf payIx[i]!).1 &&& 16 != 0
    | none => false
  let bn := notes ++ (match adm with
    | .ok _ => Run.bypNotes hsh ap.byps reqsQ.toList bydQ ++ Run.causeNotes ap bydQ
    | .error _ => [])
  let notesB := bn.map (·.toUTF8)
  let (lb, rel1, shard, batch) := (g.lb, out.rel, q.shard, q.batch)
  let au' : AuthRec := match adm, rg with
    | .ok a, .ok (rs, rsv) => { au0 with rat := a.ratchet, floor := a.grant.serial, rs, rsv }
    | _, _ => au0
  let auB := (encAuth au').toByteArray
  let ans ← spawnT (some c.prof) 6 Option.isSome fun _ =>
    some (ansW false shard batch dg recs nr auB notesB (leafIns ()) (Frame.Fast.contextAt bs (Frame.Fast.ctxEnd bs q)) lb rel1
      unr1)
  let bd ← spawnT (some c.prof) 7 (·.size != 1) fun _ => batchDigestB lb auB rel1 unr1
  return some ⟨g, rel1, unr1, ans, auB, bd⟩

/-- The end of trailer `t` after a batch that leaves the sets with heads `hr` and `hu`: those heads, install number 1, no
    windows or events, `Root4` and the head; the first that differs, with the log's value and the checker's. -/
def sealDiff (c : Ctx) (t : Trailer) (hr hu : Head) : Option (String × ByteArray × ByteArray) :=
  if hr != t.hr || hu != t.hu || t.nx != 1 then
    some ("heads or install number", headsDigest t.hr t.hu t.nx, headsDigest hr hu 1)
  else if t.bOpen != 0 || t.bSeal != noSeal || t.sealEv.isSome || t.installEv.isSome || t.reclaimEv.isSome then
    some ("window numbers or events", put64n (put64n ByteArray.empty t.bOpen) t.bSeal, put64n (put64n ByteArray.empty 0) noSeal)
  else
    let root4 := rootFour t zero64 (storeKs c.sec) none
    if root4 != t.root then some ("Root4", t.root, root4)
    else
      let hd := chainHead t.prev t.bd root4
      if hd != t.head then some ("head", t.head, hd) else none

/-- Frame `n` of the log, a fact frame (`RRDF`: request bytes `rqb`, answer bytes `anb`, trailer `t`), on the checker's
    state `v`.  It is replayed by the specification, not by the engine's code (`FactFrame.checkFact`, `rrdf_log`): the
    request must decode with the trailer's digest, at this batch, after the checker's head and under the key-set pin of its
    authority record; `FactFrame.admit` admits it on the checker's own facts; the logged answer must be the fact answer of
    its entries carrying the `rs` of the checker's own reference entries after it (`RefSet.rs`), and the trailer's `an`
    that answer's digest.  The trailer is a zero-line batch's: the authority record and
    both heads unchanged, `bd` the checker's batch digest of no rows, then the end of the trailer as for a decision batch
    (`sealDiff`).  A fact frame never opens the chain.  `RR_V3_SKIP=answer` turns off the answer and `an` checks here too. -/
def checkF (c : Ctx) (v : VC) (n : Nat) (rqb anb : ByteArray) (t : Trailer) :
    IO (Except Mismatch (VC × Task (Except Mismatch Nat))) := do
  let bad {α : Type} (what : String) (a b : ByteArray) : IO (Except Mismatch α) := pure (.error ⟨c.shard, n, what, a, b⟩)
  if v.n == 0 then return ← bad "fact frame at batch 1" zero64 zero64
  if t.shard != c.shard || t.batches != n then
    return ← bad "shard or batch number" (put64n ByteArray.empty t.batches) (put64n ByteArray.empty n)
  if t.prev != v.prev then return ← bad "previous head" t.prev v.prev
  if t.au != v.au then return ← bad "authority record" (hD "AU" [t.au]) (hD "AU" [v.au])
  let some au0 := decAuth v.au.toList | bad "authority record" zero64 zero64
  let (prev, rq) := (v.prev.toList, t.rq.toList)
  -- `v` is taken apart first, so the facts are written in place
  let ⟨m, hr, hu, au, _, _, fs, rf, ft, sb, _⟩ := v
  let n0 := fs.st.size
  let r := if c.skip.contains "answer" then
      (FactFrame.replay FactFrame.sha fs c.shard n prev au0.pin rq rqb.toList).map fun (q, _, fs) =>
        (fs, FactFrame.refsAfter FactFrame.sha rf n0 fs q.rcpt q.rows)
    else FactFrame.checkFact FactFrame.sha fs rf c.shard n prev au0.pin rq rqb.toList anb.toList t.an.toList
  let (fs, rf) ← match r with
    | .ok x => pure x
    | .error f => return ← bad f.what f.logged.toByteArray f.mine.toByteArray
  let bd := batchDigestB ByteArray.empty au #[] #[]
  if bd != t.bd then return ← bad "batch digest" t.bd bd
  if let some (w, a, b) := sealDiff c t hr hu then return ← bad w a b
  return .ok (⟨m, hr, hu, au, t.head, n, fs, rf, ffStep ft n t, extendSb sb n0 fs.st, none⟩, Task.pure (.ok 0))

/-- Frame `v.n + 1` of a rows-file store decoded as `p`, on the checker's history: the batch (slot 0 reads, 1 the
    decision), its late checks on another core, the puts (slot 11), then the heads, the trailer of `freshH`, `Root4` and
    the head (slot 4).  A fact frame is `checkF`'s.  A fault of the checker's store is an IO error (`VMirror.faultTag`). -/
def checkFrame (c : Ctx) (v : Option VC) (p : Except String Pre) : IO (Except Mismatch (VC × Task (Except Mismatch Nat))) := do
  let n := (v.map (·.n)).getD 0 + 1
  let bad {α : Type} (what : String) (a b : ByteArray) : IO (Except Mismatch α) := pure (.error ⟨c.shard, n, what, a, b⟩)
  let some v := v | bad "checker state" zero64 zero64
  let p ← match p with
    | .ok (.dec p) => pure p
    | .ok (.fact rqb anb t) => return ← checkF c v n rqb anb t
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
  let ⟨m, hr, hu, _, _, _, fs, rf, ft, sb, tg⟩ := v
  let m ← VMirror.put m d.g d.fr d.fu
  let hr : Head := ⟨hr.asOf, hr.count + d.fr.size, hr.n + d.fr.size⟩
  let hu : Head := ⟨hu.asOf, hu.count + d.fu.size, hu.n + d.fu.size⟩
  let t2 ← IO.monoNanosNow
  -- 3. heads, no events and no windows, root and head
  if let some (w, a, b) := sealDiff c t hr hu then return ← badL w a b
  let t3 ← IO.monoNanosNow
  c.add 11 (t2 - t1)
  c.add 4 (t3 - t2)
  return .ok (⟨m, hr, hu, d.au, t.head, n, fs, rf, ft, sb, tg⟩, chk)

/-! ## The checker's last state

    `vlast` in the checker's directory, rewritten after every run of whole frames it checked: shard u32 ‖ batches u64 ‖
    log position u64 ‖ lines u64 ‖ the two heads ‖ the head (64) ‖ the digest of the facts, the reference entries and
    the checked fact frames' trailer digests (64, `factsTag`) ‖ the authority record, then `H512(dom VLAST ‖ k ‖ those
    bytes)`.  Before it, `vfacts` holds the checker's fact records (the bodies in order) when they changed.  A start
    resumes from it only when its tag holds under the store's key, each set's file holds exactly the rows its head counts
    (so a file rolled back or cut is caught), the log's bytes just before the position are the head, and the facts of
    `vfacts`, the reference entries its receipts give (`FactFrame.Refs.ofStore`) and the trailer digests of the log's
    fact frames before the position have the digest it holds (so a fact frame changed after it was checked is caught by
    its trailer).  When they do not (no `vfacts`, or one written after the last state), the fact frames before the
    position are replayed from the log, those must have the digest it holds, and `vfacts` is written again.  Anything
    else rebuilds the store from the log.  A `vlast` written before the trailer digests were bound fails that check and
    is rebuilt.  Whether `vlast` itself is
    the newest is the TPM check of a later step. -/

structure Last where
  n : Nat
  pos : Nat
  lines : Nat
  hr : Head
  hu : Head
  prev : ByteArray
  fd : ByteArray
  au : ByteArray

/-- The digest `vlast` holds of the checker's facts: their record bodies in order (`sb`), the number of reference set
    entries (u64), those entries in byte order (each 140 bytes), then the digest of the checked fact frames (`ffStep`). -/
def factsTag (sb : ByteArray) (rf : FactFrame.Refs) (ft : ByteArray) : ByteArray :=
  hD "VLAST/FACTS" [sb, put64n ByteArray.empty rf.es.length, ⟨rf.es.flatten.toArray⟩, ft]

/-- `sb` is the bytes of the store; a held digest is that of the facts. -/
def VC.Good (v : VC) : Prop := v.sb = storeBytes v.fs.st ∧ ∀ t, v.tg = some t → t = factsTag v.sb v.rf v.ft

/-- The digest `vlast` holds of `v`'s facts: the one held, else computed from the bytes kept. -/
def VC.tag (v : VC) : ByteArray := v.tg.getD (factsTag v.sb v.rf v.ft)

/-- The digest taken from the bytes and the held digest is `factsTag` of the store flattened afresh. -/
theorem VC.tag_eq {v : VC} (h : v.Good) : v.tag = factsTag (storeBytes v.fs.st) v.rf v.ft := by
  obtain ⟨h1, h2⟩ := h
  unfold VC.tag
  cases e : v.tg with
  | none => simp [h1]
  | some t => simp [h2 t e, h1]

def Last.body (shard : Nat) (l : Last) : ByteArray :=
  putHead (putHead (put64n (put64n (put64n (put32 ByteArray.empty shard) l.n) l.pos) l.lines) l.hr) l.hu ++ l.prev ++ l.fd ++
    l.au

def Last.enc (k : ByteArray) (shard : Nat) (l : Last) : ByteArray := let b := l.body shard; b ++ hD "VLAST" [k, b]

/-- The fixed part of the body: shard, batches, position, lines, two heads, head, facts digest. -/
def lastFixed : Nat := 4 + 24 + 40 + 64 + 64

def Last.dec (k : ByteArray) (shard : Nat) (raw : ByteArray) : Option Last :=
  if raw.size < lastFixed + 64 then none else
  let b := raw.extract 0 (raw.size - 64)
  if hD "VLAST" [k, b] != raw.extract (raw.size - 64) raw.size || getN b 0 4 != shard then none else
  some ⟨getN b 4 8, getN b 12 8, getN b 20 8, getHead b 28, getHead b 48, b.extract 68 132, b.extract 132 196,
    b.extract lastFixed b.size⟩

/-- The checker's facts after the frames before log position `pos`, which it checked before, with `ffStep`'s digest of
    them: each fact frame among them is replayed again by `FactFrame.checkFact` (at its batch, after its trailer's
    previous head, under its authority record's pin); or why not.  The rebuild path of `resume`. -/
def factsBefore (c : Ctx) (log : UInt32) (pos : Nat) :
    IO (Except String (FactFrame.Facts × FactFrame.Refs × ByteArray)) := do
  let mut fs : FactFrame.Facts := {}
  let mut rf := FactFrame.Refs.none FactFrame.sha
  let mut ft := ByteArray.empty
  let mut o := 0
  let mut n := 0
  while o < pos do
    let some f := parseHdr (← Io.pgRead log o.toUInt64 16) o | return .error s!"no frame at offset {o}"
    n := n + 1
    if o + f.len > pos then return .error s!"the frame of batch {n} runs past offset {pos}"
    if isFact (← Io.pgRead log (o + 16).toUInt64 4) then
      let some (rqb, anb, t, _) := splitFrame f (← Io.pgRead log o.toUInt64 f.len.toUSize)
        | return .error s!"the frame of batch {n} is unreadable"
      let some au0 := decAuth t.au.toList | return .error s!"batch {n} authority record"
      match FactFrame.checkFact FactFrame.sha fs rf c.shard n t.prev.toList au0.pin t.rq.toList rqb.toList anb.toList t.an.toList with
      | .ok x => fs := x.1; rf := x.2; ft := ffStep ft n t
      | .error e => return .error s!"batch {n} {e.what}"
    o := o + f.len
  return .ok (fs, rf, ft)

/-- `ffStep`'s digest of the fact frames before log position `pos`, read from their trailers alone (each frame's header,
    and a fact frame's trailer); none when a frame does not read. -/
def ftBefore (log : UInt32) (pos : Nat) : IO (Option ByteArray) := do
  let mut ft := ByteArray.empty
  let mut o := 0
  let mut n := 0
  while o < pos do
    let some f := parseHdr (← Io.pgRead log o.toUInt64 16) o | return none
    n := n + 1
    if o + f.len > pos then return none
    if isFact (← Io.pgRead log (o + 16).toUInt64 4) then
      let some t := Trailer.decode (← Io.pgRead log (o + 16 + f.rq + f.an).toUInt64 f.tr.toUSize) | return none
      ft := ffStep ft n t
    o := o + f.len
  return some ft

/-- `raw` written to `p`: a new file, synced, then renamed over it. -/
def putFile (p : String) (raw : ByteArray) : IO Unit := do
  let fd ← Io.pgOpen s!"{p}.new"
  if fd == 0xFFFFFFFF then throw (IO.userError s!"{p}: open")
  let ok := (← Io.pgWrite fd 0 raw) == 0 && (← Io.pgTrunc fd raw.size.toUInt64) == 0 && (← Io.pgSync fd) == 0
  let _ ← Io.pgClose fd
  unless ok do throw (IO.userError s!"{p}: write")
  IO.FS.rename s!"{p}.new" p

/-- The checker's fact records kept in `vdir` (`vfacts`, whole bodies), if it reads. -/
def loadFacts (vdir : String) : IO (Option ByteArray) := do
  let p := s!"{vdir}/vfacts"
  if !(← System.FilePath.pathExists p) then return none
  let b ← IO.FS.readBinFile p
  return if b.size % FactCodec.bodyBytes == 0 then some b else none

/-- The store's `facts` file in `dir` (absent reads as empty) against the file of the records the checker derived from the
    log's `n` batches (`FactFrame.Store.file`).  The file is a cache the engine writes again from the log at open (after
    a clean stop, from its last kept receipt on), and a live batch writes its records, unsynced, before its frame goes to
    the log; so the file may be a byte prefix of
    those records (not yet written again since a crash) or those records and bytes past them (a batch not yet logged).
    Either is a note, none when equal byte for byte.  Any other file is the first record that differs, named with the
    batch of its receipt (each record's bytes hashed). -/
def factsDiff (c : Ctx) (dir : String) (fx : FactFrame.Facts) : IO (Except Mismatch (Option String)) := do
  let fs := fx.st
  let p := s!"{dir}/facts"
  let got ← if ← System.FilePath.pathExists p then IO.FS.readBinFile p else pure ByteArray.empty
  let want : ByteArray := ⟨(FactFrame.Store.file fs).toArray⟩
  if got == want then return .ok none
  if got.size < want.size && got == want.extract 0 got.size then
    return .ok (some s!"FACTS_STALE({c.shard}) facts file holds {got.size} of the {want.size} bytes of the log's {fs.size} records; the engine writes it again at open")
  if want.size < got.size && got.extract 0 want.size == want then
    return .ok (some s!"FACTS_STALE({c.shard}) facts file holds {got.size - want.size} bytes past the {fs.size} records of the log (a batch not yet logged); the engine writes it again at open")
  -- each record is a body and its link (`FactStore.factsP`)
  let recOf (b : ByteArray) (i : Nat) : ByteArray := b.extract (Obligations.recBytes * i) (Obligations.recBytes * (i + 1))
  let recAt (b : ByteArray) (i : Nat) : ByteArray := hD "VERIFY/FACTS" [recOf b i]
  -- a byte differs inside both files, so some record of the log's differs
  let i := ((List.range fs.size).find? fun i => recOf got i != recOf want i).getD 0
  let kb := (((FactFrame.slotsFrom 0 fs.toList).filter (·.1 ≤ i)).getLast?.map (·.2.kb)).getD 0
  return .error ⟨c.shard, kb, s!"facts file record {i}", recAt got i, recAt want i⟩

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
  -- the facts kept in `vfacts`, when they and the log's fact frame trailers give the digest the last state holds
  let ft? ← ftBefore log l.pos
  let kept := match ← loadFacts c.vdir, ft? with
    | some sb, some ft =>
      let st : FactFrame.Store := (Array.range (sb.size / FactCodec.bodyBytes)).map fun i =>
        (sb.extract (FactCodec.bodyBytes * i) (FactCodec.bodyBytes * (i + 1))).toList
      let rf := FactFrame.Refs.ofStore FactFrame.sha st
      if factsTag sb rf ft == l.fd then some (⟨st, FactFrame.Ix.ofStore st⟩, rf, ft, sb) else none
    | _, _ => none
  if let some (fs, rf, ft, sb) := kept then
    return .ok (⟨m, l.hr, l.hu, l.au, l.prev, l.n, fs, rf, ft, sb, some l.fd⟩, k, l.pos, l.lines)
  match ← factsBefore c log l.pos with
  | .ok (fs, rf, ft) =>
    let sb := storeBytes fs.st
    if factsTag sb rf ft != l.fd then
      VMirror.close m
      return .error "the facts of the checked frames are not the ones the last state holds"
    IO.println s!"FACTS_REPLAYED({c.shard}) the checker's kept facts are not those of its last state: the fact frames before batch {l.n + 1} were replayed from the log"
    putFile s!"{c.vdir}/vfacts" sb
    return .ok (⟨m, l.hr, l.hu, l.au, l.prev, l.n, fs, rf, ft, sb, some l.fd⟩, k, l.pos, l.lines)
  | .error why =>
    VMirror.close m
    return .error s!"the facts of the checked frames: {why}"

/-- Writes `vlast` for `v`: the rows files synced first, and `vfacts` when its size is not that of the facts, then the
    new `vlast`, so a power loss leaves a last state whose rows are on disk (a resume that finds otherwise rebuilds from
    the log) and a `vfacts` that is its facts or that a resume replays past. -/
def saveLast (c : Ctx) (k : ByteArray) (v : VC) (pos lines : Nat) : IO VC := do
  let sb := v.sb
  let tag := v.tag
  let raw := Last.enc k c.shard ⟨v.n, pos, lines, v.hr, v.hu, v.prev, tag, v.au⟩
  if (← Io.pgSync v.m.rel.f.fd) != 0 || (← Io.pgSync v.m.unr.f.fd) != 0 then throw (IO.userError "vlast: rows sync")
  let fp := s!"{c.vdir}/vfacts"
  let held ← if ← System.FilePath.pathExists fp then pure (some (← System.FilePath.metadata fp).byteSize.toNat) else pure none
  if held != some sb.size then putFile fp sb
  putFile s!"{c.vdir}/vlast" raw
  return { v with tg := some tag }

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
    throws, so no worker is running when the process ends. -/
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
