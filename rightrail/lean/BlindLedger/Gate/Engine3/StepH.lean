import BlindLedger.Gate.Engine3.Step
import BlindLedger.Gate.Engine3.Hist
import BlindLedger.Gate.Engine3.AdmitB

/-! One batch on the rows-file history (`Hist`): the request frame's lines are read through the rows files and their
    tables (`Hist.read`), decided by the fixed-row decider (`decideRows`), and the answer and the batch digest are built
    from the decision.  Nothing is written here: the caller logs the batch, then puts the rows (`Hist.put`).  This is
    `Run.step` without the chunk store, the verifier's second decision and the model check.
    Synthetic, nonpayment, non-PHI, activation=false. -/

namespace BlindLedger.Gate.Engine3.Run

open BlindLedger.Gate BlindLedger.Gate.Rules BlindLedger.Gate.Flat BlindLedger.Gate.Flat.Worker
open BlindLedger.Gate.Frame (Word Rule)

/-- A decided batch: what the puts need, the answer (word OK, head and root zero) with its `an`, the authority record
    after the batch and the batch digest. -/
structure DoneH where
  lb : ByteArray
  idx : Array Nat
  keys : Array KeyQ
  fr : Array Nat
  fu : Array Nat
  ans : Task (Option (ByteArray × ByteArray × ByteArray))
  au : ByteArray
  bd : Task ByteArray

inductive SteppedH
  | refused (hold : ByteArray)
  | done (d : DoneH)

/-- Each request's payment number, or none, and the count: a covered request (`covR`) whose lines fit (`unfR` false)
    and are ruled and not empty gets the next number, in request order.  The loop `stepH` ran inline, moved here unchanged
    so a lemma can name it (`Flat.PayNum.payIdx_spec`). -/
def payIdx (reqs : Array Run.Req) (covR unfR : Array Bool) : Array (Option Nat) × Nat := Id.run do
  let mut ix : Array (Option Nat) := Array.mkEmpty reqs.size
  let mut n := 0
  for x in reqs, c in covR, u in unfR do
    if c && !u && x.ra.flow.ruled && !x.ra.lines.isEmpty then
      ix := ix.push (some n)
      n := n + 1
    else ix := ix.push none
  pure (ix, n)

/-- Per payment of the decided batch `out` on `lay` (`np` payments): its flags (1 a HOLD line, 2 a line that is not an
    own ALLOW, 4 any line, 8 a released line that was not ALLOW, 16 a bypass releases it, 32 it goes at HOLD authority)
    and the OR of its decided lines' reason masks, which `leafIn` turns into the leaf's reasons field.  The loop `stepH`
    ran inline, moved here unchanged so a lemma can name it (`Flat.Rows.payFlags_msk`).  `inRel`: per line, whether it
    joined the released set. -/
def payFlags (lay : Rows.Lay) (out : Rows.Out) (inRel : Array Bool) (np : Nat) : ByteArray × Array UInt32 := Id.run do
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

/-- The batch of request `q` (digest `dg`, bytes `bs`) on `h`, whose last authority record is `au0b`. -/
def stepH (h : Hist.Hist) (au0b : ByteArray) (q : Frame.Req) (dg bs : ByteArray) : IO (Except Word SteppedH) := do
  let ts ← IO.monoNanosNow
  let au := q.auth
  if !au.reqs.isEmpty && au.release.isEmpty then return .error .RECORD
  let hsh (x : List UInt8) : List UInt8 := Run.hB ⟨x.toArray⟩
  let some au0 := decAuth au0b.toList | return .error .CORRUPT
  let opt (b : Bytes) : Option Bytes := if b.isEmpty then none else some b
  let st : Run.St :=
    { today := q.today, redo := q.redo, reqs := au.reqs.toArray, grant := opt au.grant, release := opt au.release
      byps := au.byps, floorIn := au.floor, kfloorIn := some au.kfloor, keyset := opt au.keyset, ksteps := au.ksteps }
  let adm : Except String Run.Admitted ←
    if st.reqs.isEmpty then pure (.error "") else admitC au0.pin au0.rat au0.floor st
  if !st.reqs.isEmpty then
    if let .error why := adm then
      return .ok (.refused ((why.toUTF8.toList ++ List.replicate 16 0).take 16).toByteArray)
  let reqs := st.reqs
  let ab := admB adm reqs
  let (covR, unfR, bPos) := (ab.cov, ab.unf, ab.bPos)
  let ens := entsB adm reqs
  -- the lines the rules decide are counted, not built: `Hist.read` takes the number of them
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
  let ts ← if ← specDue q.batch then do
      let tc ← IO.monoNanosNow
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
      let td ← tick 41 tc
      if !ok then
        IO.eprintln "SPEC_MISMATCH admission"
        return .error .CORRUPT
      pure (ts + (td - tc))
    else pure ts
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
  -- a row number would pass 2^40: the batch is refused whole (the answer format has no cause for it)
  if rowsFullF h.hr h.hu b.size then return .error .FULL
  let t1 ← tick 5 ts
  let kept := (reqs.zip (covR.zip unfR)).filterMap fun (x, c, u) => if c && !u then some x else none
  let some g ← Hist.read h bs q kept b byp lim (dmf.isSome, pd.isSome, ex.isSome, sp.isSome) tick
    | return .error .CORRUPT
  let lay := g.lay
  let t1b ← tick 1 t1
  let out := Rows.decideRows lay
  let t2 ← if out.ds.size == 0xFFFFFFFFFF then pure 0 else tick 19 t1b
  let (payIx, np) := payIdx reqs covR unfR
  let nb := lay.lines.size
  let inRel : Array Bool := out.rel.foldl (fun a i => a.set! i true) (Array.replicate nb false)
  let inUnr : Array Bool := out.unr.foldl (fun a i => a.set! i true) (Array.replicate nb false)
  let (fl, msk) := payFlags lay out inRel np
  let flOf (pix : Option Nat) : UInt8 × UInt32 := match pix with
    | some p => (fl[p]!, msk[p]!)
    | none => (0, 0)
  let (relSeq, unrSeq) := (g.relSeq, g.unrSeq)
  let locOf (cp : Nat) : Option (Nat × Nat) :=
    if cp == 0 then none else if cp % 2 == 1 then ((relSeq[cp / 2]?).map (0, ·)) else ((unrSeq[cp / 2 - 1]?).map (1, ·))
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
  let (lb, rel1, unr1, shard, batch, ce) := (g.lb, out.rel, out.unr, q.shard, q.batch, Frame.Fast.ctxEnd bs q)
  -- the answer and the digest hold byte arrays, the leaves and index arrays only: not the layout or the reads
  -- bench (`RR_E3_MEMDIAG`): the two tasks and the stages of the answer are timed
  let tm := (← IO.getEnv "RR_E3_MEMDIAG").isSome
  let prof := if tm then some phases else none
  -- the record after the batch: a batch with admitted requests moves the ratchet and the floor, any other keeps it
  let au' : AuthRec := match adm with
    | .ok a => ⟨au0.pin, a.ratchet, a.grant.serial⟩
    | .error _ => au0
  let auB := (encAuth au').toByteArray
  let ans ← spawnT prof 28 Option.isSome fun _ =>
    let rel2 := if tm then stamp 36 rel1 else rel1
    let ls := if tm then stamp 38 (leafIns ()) else leafIns ()
    some (ansW tm shard batch dg recs nr auB notesB ls (Frame.Fast.contextAt bs ce) lb rel2 unr1)
  let bd ← spawnT prof 29 (·.size != 1) fun _ => batchDigestB lb auB rel1 unr1
  let _ ← tick 37 t2
  phases.modify (·.modify 15 (· + b.size))
  pure (.ok (.done ⟨lb, g.idx, g.keys, rel1, unr1, ans, auB, bd⟩))

end BlindLedger.Gate.Engine3.Run
