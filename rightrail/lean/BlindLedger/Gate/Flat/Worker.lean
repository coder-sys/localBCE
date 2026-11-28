import BlindLedger.Gate.Flat.ChunkIo
import BlindLedger.Gate.Flat.Io
import BlindLedger.Gate.Rules.Run
import BlindLedger.Gate.Verify
import BlindLedger.Gate.Frame.Fast

/-! The history store inside the resident gate engine (formats conformance/FLAT_V1.md, FRAME_V1.md).

    A request frame (`Frame.Fast.decodeReqFast`) names its batch and the signed chain head it follows.  Batch 1 creates the
    store (sets dated `asOf`, key-set genesis pin from the frame); a later batch opens it at that head and batch count, else
    the frame is refused.  The commit reads the batch's keys in two rounds (line keys, then id keys of fetched unresolved
    CAP_820 rows), decides with `decideFetched`, installs the batch (`ChunkIo.installBatch`: the chunk's frame appended to
    the log, its trailer last) and answers with one record per decided line, the new head and state root, and the extension.
    No row list is carried or kept.  A corrupt page or entry or an I/O error refuses the whole frame and decides nothing.
    The shard's authority record (genesis pin, key-set ratchet, grant serial floor) is in every frame's trailer and bound by
    its state root, so an open restores it.  A payment's lines come from its request bytes (`Run.reqOf`), the bypasses and cause
    releases from the signed approvals (`Run.admit`, `Run.approvals`).  Bench only: with `RR_FLAT_PROF` set the commit writes its
    counters and phase times to stderr.  Synthetic, nonpayment, non-PHI, activation=false. -/

namespace BlindLedger.Gate.Flat.Worker

open BlindLedger.Gate BlindLedger.Gate.Rules
open Std (HashMap HashSet)

/-- Bench only (`RR_FLAT_PROF` set): time spent per phase in this frame's commit, in ns; never read by a decision. -/
abbrev Prof := Option (IO.Ref (Array Nat))

/-- `f ()` timed into slot `i`; `sz` forces the result inside the timed span. -/
def tp {α : Type} (pf : Prof) (i : Nat) (f : Unit → α) (sz : α → Nat) : IO α := do
  let some prof := pf | return f ()
  let t0 ← IO.monoNanosNow
  let a ← IO.lazyPure f
  let n := sz a
  let t1 ← IO.monoNanosNow
  prof.modify fun p => (p.modify i (· + (t1 - t0))).modify 15 (· + n)
  pure a

def ti {α : Type} (pf : Prof) (i : Nat) (act : IO α) : IO α := do
  let some prof := pf | act
  let t0 ← IO.monoNanosNow
  let a ← act
  let t1 ← IO.monoNanosNow
  prof.modify fun p => p.modify i (· + (t1 - t0))
  pure a

def H (b : Bytes) : Bytes := (Bin.HB ⟨b.toArray⟩).toList

/-- The shard's authority record (`ChunkIo.CS.au`, in every frame's trailer): the key-set genesis pin, the ratchet of the
    head last admitted, the highest grant serial admitted, and the digest and version of the newest rule-set record
    admitted (`zeroDigest` and 0 for none).  A committed batch with requests moves it, forward only
    (`Run.floor_monotone`, `ChunkIo.authFollows`). -/
structure AuthRec where
  pin : Bytes
  rat : Keyset.Ratchet
  floor : Nat
  rs : Bytes
  rsv : Nat

/-- pin 64 ‖ epoch u32 ‖ head 64 ‖ day u32 ‖ cp 64 ‖ floor u64 ‖ rs 64 ‖ rsv u32 (`authLen` bytes). -/
def encAuth (a : AuthRec) : Bytes :=
  a.pin ++ natBE 4 a.rat.epoch ++ a.rat.head ++ natBE 4 a.rat.day ++ a.rat.cp ++ natBE 8 a.floor ++ a.rs ++ natBE 4 a.rsv

def decAuth (v : Bytes) : Option AuthRec :=
  if v.length != authLen then none else
  some ⟨v.take 64, ⟨beNat ((v.drop 64).take 4), (v.drop 68).take 64, beNat ((v.drop 132).take 4), (v.drop 136).take 64⟩,
    beNat ((v.drop 200).take 8), (v.drop 208).take 64, beNat ((v.drop 272).take 4)⟩

/-- `decAuth` reads exactly the `authLen`-byte records: every other length is refused. -/
theorem decAuth_isSome (v : Bytes) : (decAuth v).isSome = true ↔ v.length = authLen := by
  unfold decAuth
  by_cases h : v.length = authLen <;> simp [h]

/-- A record of fields that fit their widths reads back as itself. -/
theorem decAuth_encAuth (a : AuthRec) (hp : a.pin.length = 64) (hh : a.rat.head.length = 64)
    (hc : a.rat.cp.length = 64) (hs : a.rs.length = 64) (he : a.rat.epoch < 256 ^ 4) (hd : a.rat.day < 256 ^ 4)
    (hf : a.floor < 256 ^ 8) (hv : a.rsv < 256 ^ 4) : decAuth (encAuth a) = some a := by
  obtain ⟨pin, ⟨e, h, d, c⟩, f, rs, v⟩ := a
  simp only at hp hh hc hs he hd hf hv
  have l4 := Keyset.natBE_length 4
  have l8 := Keyset.natBE_length 8
  have hl : (encAuth ⟨pin, ⟨e, h, d, c⟩, f, rs, v⟩).length = authLen := by
    simp [encAuth, hp, hh, hc, hs, l4, l8, authLen]
  unfold decAuth
  simp only [hl, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte]
  simp only [encAuth, List.append_assoc]
  simp [List.drop_append, List.take_of_length_le, List.drop_of_length_le, hp, hh, hc, hs, l4, l8,
    beNat_natBE 4 e he, beNat_natBE 4 d hd, beNat_natBE 8 f hf, beNat_natBE 4 v hv]

/-- The hold of a frame with requests whose asserted rule-set floor (`a.rsv`, `a.rs`) a shard at version `rsv` under
    digest `rs` does not meet: a lower version is `RULESET_STALE`; the same version under another digest is
    `RULESET_FORK`. -/
def floorHold (rs : Bytes) (rsv : Nat) (a : Frame.Auth) : Option String :=
  if rsv < a.rsv then some "RULESET_STALE"
  else if rsv == a.rsv && rs != a.rs then some "RULESET_FORK"
  else none

/-- The rule-set hold of the engine that does not run signed rule sets (conformance/RULESET_V1.md section 9): the floor
    holds against the shard's record `r`; while a rule set is in force (`r.rsv > 0`) every frame is `RULESET_MISSING`;
    and a frame that presents rule-set records is `RULESET_NOT_RUN`, because this engine does not admit them.  It is
    taken beside the authority check, so the record is unchanged. -/
def rulesetHold (r : AuthRec) (a : Frame.Auth) : Option String :=
  match floorHold r.rs r.rsv a with
  | some w => some w
  | none =>
    if r.rsv != 0 then some "RULESET_MISSING"
    else if !a.rsets.isEmpty then some "RULESET_NOT_RUN"
    else none

theorem rulesetHold_stale (r : AuthRec) (a : Frame.Auth) (h : r.rsv < a.rsv) :
    rulesetHold r a = some "RULESET_STALE" := by
  simp [rulesetHold, floorHold, h]

theorem rulesetHold_fork (r : AuthRec) (a : Frame.Auth) (h : r.rsv = a.rsv) (hs : r.rs ≠ a.rs) :
    rulesetHold r a = some "RULESET_FORK" := by
  simp [rulesetHold, floorHold, h, hs]

/-- A floor hold passes only when the shard meets the asserted version, and at that version holds the asserted digest. -/
theorem floorHold_none {rs : Bytes} {rsv : Nat} {a : Frame.Auth} (h : floorHold rs rsv a = none) :
    a.rsv ≤ rsv ∧ (rsv = a.rsv → rs = a.rs) := by
  unfold floorHold at h
  split at h
  · cases h
  split at h
  · cases h
  rename_i h1 h2
  refine ⟨by omega, fun e => ?_⟩
  simpa [e] using h2

/-- A frame passes the rule-set holds only when neither the shard's record nor the frame names a rule set, and the frame
    presents no rule-set record. -/
theorem rulesetHold_none {r : AuthRec} {a : Frame.Auth} (h : rulesetHold r a = none) :
    r.rsv = 0 ∧ a.rsv = 0 ∧ r.rs = a.rs ∧ a.rsets = [] := by
  unfold rulesetHold at h
  split at h
  · cases h
  rename_i hf
  obtain ⟨h1, h2⟩ := floorHold_none hf
  split at h
  · cases h
  split at h
  · cases h
  rename_i h3 h4
  have hr : r.rsv = 0 := by simpa using h3
  have ha : a.rsv = 0 := by omega
  exact ⟨hr, ha, h2 (by omega), by simpa using h4⟩

structure FlatW where
  /-- Test only (the crash-test exe): where a commit kills the process; the pinned exes pass "none". -/
  crash : String := "none"
  /-- The exclusive lock on the open index's directory, held for the worker's life: a second writer is refused. -/
  lock : Option (String × IO.FS.Handle) := none
  /-- The open chunk store. -/
  cs : Option ChunkIo.CS := none
  /-- The identity of the frame being run (`Frame.ident`): its context and each request's `INPUT/v7`. -/
  rq : Bytes := []
  /-- The bytes hashed for `rq` (bench count). -/
  rqLen : Nat := 0
  /-- The batch count of the last open that succeeded, for each directory (`openLog`'s `seen`): a lower one is a rewound head. -/
  seen : HashMap String Nat := ∅

/-- The decider's view of the feeds in the pinned inputs (`FCtxInv`). -/
def feedsOf (c : Ctx) : Feeds :=
  let by_ {α : Type} (xs : List α) (k : α → Nat) : HashMap Nat (List α) :=
    xs.foldr (fun x m => m.insert (k x) (x :: m.getD (k x) [])) ∅
  let dmf := by_ (entries c.dmf) (·.id)
  let pd := by_ (entries c.providerDeaths) (·.id)
  let ex := by_ (entries c.exclusions) (·.id)
  let sp := by_ (entries c.enrollment) (·.member)
  { dmfSome := c.dmf.isSome, pdSome := c.providerDeaths.isSome, exclSome := c.exclusions.isSome, spanSome := c.enrollment.isSome,
    dmfOk := usable c.today 90 okDeath c.dmf, pdOk := usable c.today 90 okDeath c.providerDeaths,
    exclOk := usable c.today 31 okExclusion c.exclusions, spanOk := usable c.today 7 okSpan c.enrollment,
    dmf := fun i => dmf.getD i [], pdeath := fun i => pd.getD i [], excl := fun i => ex.getD i [], span := fun i => sp.getD i [] }

/-- The worker holding the exclusive lock on `dir` (file `lock`); `none`: another worker has it. -/
def lockDir (w : FlatW) (dir : String) : IO (Option FlatW) := do
  try
    IO.FS.createDirAll dir
    let key := (← IO.FS.realPath ⟨dir⟩).toString  -- one key for every spelling of the path
    if let some (d, _) := w.lock then
      if d == key then return some w
    let h ← IO.FS.Handle.mk ⟨s!"{key}/lock"⟩ .append
    pure (if ← h.tryLock then some { w with lock := some (key, h) } else none)
  catch _ => pure none

/-! ## The commit -/

structure Upd where
  ent : HashMap (UInt8 × Key) EntryA := ∅
  order : Array (UInt8 × Key) := #[]

/-- Rows `rows` appended to set `ns` from row number `n0`: a posting under each of their keys (`SetIdx.add`, on
    arrays: `EntryA.push_eq`).  A key's fetched entry is converted once, when the batch first touches it. -/
def Upd.rows (u : Upd) (look : UInt8 → Key → Entry) (ns : UInt8) (n0 : Nat) (rows : List Line) : Upd :=
  (rows.zipIdx n0).foldl (fun u (l, seq) => (keys l).foldl (fun (u : Upd) k =>
    match u.ent[(ns, k)]? with
    | some e => { u with ent := u.ent.insert (ns, k) (e.push H ⟨seq, l⟩) }
    | none => { ent := u.ent.insert (ns, k) ((look ns k).toA.push H ⟨seq, l⟩), order := u.order.push (ns, k) }) u) u

/-- The directory's starting bucket count (`RR_FLAT_NB`, bench only). -/
def nbOf : IO Nat := do pure (((← IO.getEnv "RR_FLAT_NB").bind String.toNat?).getD (2 ^ 19))

/-- The reads of a batch in two rounds (every key of its lines in both sets, then `round2`), each key looked up once
    through the directory and its window pages.  Also gives every looked-up key's live rows (the batch's kills). -/
def fetchChunk (pf : Prof) (pg : IO.Ref Nat) (cs : ChunkIo.CS) (fc : FCtx) (b : List Line) :
    IO (Option Fetched × HashMap ChunkIo.BK (Entry × List (Nat × Nat × Entry))) := do
  let ks ← tp pf 16 (fun _ => probeKeys b) (·.length)
  let memo ← IO.mkRef (∅ : HashMap ChunkIo.BK (Entry × List (Nat × Nat × Entry)))
  let bad ← IO.mkRef false
  let get (ns : UInt8) (k : Key) : IO Entry := do
    let bk := ChunkIo.mkBK (ChunkIo.skeyB (ns == 6) k)  -- encoded once per key and set
    match (← memo.get)[bk]? with
    | some (e, _) => pure e
    | none =>
      match ← ChunkIo.liveHits pf pg cs bk.b bk.h with
      | some hs =>
        let e := ChunkIo.lookupE cs bk.b hs
        memo.modify (·.insert bk (e, hs))
        pure e
      | none => bad.set true; pure Entry.empty
  let e5 ← ks.mapM (get 5)
  let e6 ← ks.mapM (get 6)
  let u := ks.zip e6
  let k2 ← tp pf 17 (fun _ => round2 fc.redo ks u) (·.length)
  let r2 ← k2.mapM fun k => do pure (k, ← get 5 k)
  let rel := ks.zip e5 ++ r2
  pure (if ← bad.get then none else some ⟨rel, u, fun _ => 0, fun _ => 0⟩, ← memo.get)

/-- `x`, or `none` when it throws (a failed read). -/
def guardIO {α : Type} (x : IO α) : IO (Option α) := do
  try pure (some (← x)) catch _ => pure none


/-! ## The commit -/

open BlindLedger.Gate.Frame (Word Rec Rule Leaf Ext AnsFrame)

def noExt : Ext := ⟨⟨Array.replicate 16 0⟩, Frame.Fast.zero64B, ⟨Array.replicate authLen 0⟩, [], [], []⟩

/-- A feed as a snapshot, when its rows hash to its declared pin (`Run.snapshot`, `Frame.snap`). -/
def snapF {α : Type} (kind : Nat) (fields : α → List (Nat × Nat)) (f : Frame.Feed α) : Option (Snapshot α × Bytes) :=
  if f.state != 1 then none else
  let s : Snapshot α := ⟨f.asOf, f.count, f.rows⟩
  match Fast.pinBytes "RR/GATE/SNAPSHOT/v1" kind fields s with
  | some b => let h := (BlindLedger.Semantic.sha3_512Quick b).toList; if h == f.pin then some (s, h) else none
  | none => none

/-- The word a store refusal names; any other text is an I/O failure. -/
def wordOf (why : String) : Word :=
  -- a pending frame the fresh decision does not equal is a replay mismatch
  let why := if why == "PENDING" then "REPLAY" else why
  (Frame.words.find? fun w => Run.name w == why).getD .IO

/-- Each reason's name and its bit in `Frame.maskOf` (names are distinct: `Run.name` sorts them strictly), built once. -/
def reasonBits : List (String × Nat) := Rules.reasons.map fun r => (Run.name r, 2 ^ r.idx)

/-- The reason mask of a leaf's reason text (`Run.leafReasons`): bits 62 and 63 are UNENCODABLE_PAYMENT and SCOPE. -/
def leafMask (s : String) : Nat :=
  (s.splitOn ",").foldl (fun m n =>
    if n == "UNENCODABLE_PAYMENT" then m ||| Frame.leafUnencodable else if n == "SCOPE" then m ||| Frame.leafScope
    else m ||| (reasonBits.lookup n).getD 0) 0

/-- A request's leaf: its pay line `m` and its input `rq` (`INPUT/v7`). -/
def leafOf (m : Run.Pay) (rq : ByteArray) : Frame.Leaf :=
  { outcome := Frame.outCode m.outcome, reasons := leafMask m.reasons,
    authority := [Gate.Authority.OBSERVE, .HOLD, .TRANSFER].idxOf m.authority, bypass := m.bypass.toByteArray, input := rq }

/-- `Frame.place`: each decided line takes the first position that holds it and no earlier line took. -/
def placeFast (pool : List (Nat × Line)) (ds : List Line) : List Nat := Id.run do
  let mut m : HashMap (Nat × Nat) (List (Nat × Line)) := ∅
  for p in pool.reverse do m := m.insert (p.2.id, p.2.pay) (p :: m.getD (p.2.id, p.2.pay) [])
  let mut out : Array Nat := #[]
  for l in ds do
    let k := (l.id, l.pay)
    let b := m.getD k []
    match b.find? (·.2 == l) with
    | some p => out := out.push p.1; m := m.insert k (b.erase p)
    | none => pure ()
  pure out.toList

/-- `Frame.firstRef`: the first key of the line with a live entry, released set first (`loc unresolved key`). -/
def firstRefFast (loc : Bool → Key → Option (Nat × Nat)) (x : Fast.Ix) (l : Line) : Option (Nat × Nat) :=
  match (keys l).find? fun k => !(Fast.hits x.rel x.relPost [k] fun _ => true).isEmpty with
  | some k => loc false k
  | none => ((keys l).find? fun k => !(Fast.hits x.unr x.unrPost [k] fun y => (keys l).any (x.claim y).contains).isEmpty).bind (loc true)

/-- The released rows `Run.answering` reads under exact key `k` from the entries fetched for a batch (`relM`): the
    entry's head rows, in row order; none when the key has more than `capN` postings, which cannot be read whole
    (`Flat.answer_eq`, `Flat.answer_cap`). -/
def relRows (relM : HashMap Key Entry) (k : Key) : Option (List Line) :=
  let e := relM.getD k Entry.empty
  if capN < e.count then none else some ((heads e).map (·.row))

/-- The payments whose senders contest an exact repeat (`Request.contest`): `Run.answering` decides them as before. -/
def contested (reqs : List Run.Req) : List Nat := reqs.filterMap fun e => if e.ra.contest then some e.q else none

/-- A batch's decisions by payment number, each payment's in decision order. -/
def byPay (ds : List Decision) : HashMap Nat (List Decision) :=
  ds.foldr (fun d m => m.insert d.line.pay (d :: m.getD d.line.pay [])) ∅

/-- The index a commit decides on (`commitBin`, `Flat.commit_leaves`, `Flat.leaf_capped`). -/
def leafIx (hr hu : Head) (fe : Fetched) (fc : FCtx) (b : List Line) : Fast.Ix :=
  localIx hr hu fe (localRows fe.rel) (localRows fe.unr) fc b

/-- A payment's decisions out of `byPay`, in decision order. -/
def leafGrp (bp : HashMap Nat (List Decision)) (p : Nat) : List Decision := bp.getD p []

/-- The worker's bypass test of payment `p`. -/
def leafByd (x : Fast.Ix) (bp : HashMap Nat (List Decision)) (p : Nat) : Bool := x.bypassed (leafGrp bp p) p

/-- Request `e`'s leaf before an exact-repeat answer: `Run.emitWith` over the payment's own decisions `grp e.q` with the
    payment outcome `out`, the bypass test `byd` and the re-decision test `rdo` (a request no grant entry covers is held
    alone, `Run.uncovered`), then `Run.causeLeaf` (`Flat.commit_leaves`). -/
def payOf (hsh : Bytes → Bytes) (g : Authority.Grant) (bps : List Authority.Bypass) (ap : Run.Approvals)
    (out : Nat → Outcome) (byd rdo : Nat → Bool) (grp : Nat → List Decision) (unf : Nat → Bool) (e : Run.Req) : Run.Pay :=
  Run.causeLeaf ap byd unf ((Run.emitWith hsh g (Run.bypsFor hsh bps e) out byd rdo (grp e.q) unf e).getD (Run.uncovered g e))

/-- Leaf `m` of request bytes `rq` as written: ANSWERED (3) with its earlier list when `ExactDuplicate.answerLeaf` over
    `c`, `k`, `ds` answers it and the list can be written (`Run.earlierBody`), else `m` as it is. -/
def leafAt (c : Ctx) (k : List Nat) (ds : List Decision) (unf : Nat → Bool) (m : Run.Pay) (rq : ByteArray) : Frame.Leaf :=
  match Rules.answerLeaf c k ds unf m.outcome m.q, Run.earlierBody c ds m.q with
  | .ANSWERED, some e => { leafOf m rq with outcome := 3, earlier := e.toByteArray }
  | _, _ => leafOf m rq

/-- The set a decided line's record names: released, released by an approval or at HOLD authority (bypassed),
    unresolved (a new held or reviewed line of a payment not answered, `ans`), or decided only. -/
def ruleOf (x : Fast.Ix) (grp : Nat → List Decision) (ans : Std.HashSet Nat) (e : Decision) : Rule :=
  if e.outcome == .ALLOW && !x.redo.contains e.line.pay && x.payOutcome (grp e.line.pay) e.line.pay == .ALLOW then .released
  else if x.bypassed (grp e.line.pay) e.line.pay || x.limitedPay (grp e.line.pay) e.line.pay && !x.own e.line then .bypassed
  else if e.outcome != .ALLOW && !e.reasons.contains .ALREADY_DECIDED && !x.own e.line && !x.ownU e.line &&
    !ans.contains e.line.pay then .unresolved
  else .decided

/-- One batch: `Frame.answerOf` for the request `q` (header digest `dg`, each request's input `rqs`) on the open store
    `cs0`, and the store after it.  A refusal leaves the store as it was. -/
def commitBin (pf : Prof) (w : FlatW) (cs0 : ChunkIo.CS) (q : Frame.Req) (dg : ByteArray) (rqs : Array ByteArray) :
    IO (FlatW × AnsFrame) := do
  let keep := { w with cs := some cs0 }
  let fail (wd : Word) : FlatW × AnsFrame := (keep, ⟨wd, q.shard, q.batch, dg, [], .empty, .empty, noExt⟩)
  let au := q.auth
  -- requests commit to the release, as the host's frame must carry it; rule-set records are presented for requests
  if !au.reqs.isEmpty && au.release.isEmpty || au.reqs.isEmpty && !au.rsets.isEmpty then return fail .RECORD
  -- an unsigned frame is already in the log (`retryOf`): only the request that made it may go on (CONFLICT), unless it
  -- was decided under authority floors this request's have passed (`right_rail_gate_chain.behind`): it can never be
  -- signed, so it is cut from the log
  let cs0 ← match cs0.pend with
    | some (prq, pau, _) =>
      if prq == w.rq then pure cs0 else
      let passed := match decAuth pau with
        | some p => !(au.floor.all (· ≤ p.floor)) || p.rat.epoch < au.kfloor || p.rsv < au.rsv ||
            (p.rsv == au.rsv && p.rs != au.rs)
        | none => false
      if !passed then return fail .CONFLICT
      if (← Io.pgTrunc cs0.log cs0.logLen.toUInt64) != 0 || (← Io.pgSync cs0.log) != 0 then return fail .IO
      pure { cs0 with pend := none }
    | none => pure cs0
  let keep := { w with cs := some cs0 }
  let fail (wd : Word) : FlatW × AnsFrame := (keep, ⟨wd, q.shard, q.batch, dg, [], .empty, .empty, noExt⟩)
  let check ← IO.getEnv "RR_FLAT_CHECK"
  let tc0 ← IO.monoNanosNow
  let hsh (x : List UInt8) : List UInt8 := Run.hB ⟨x.toArray⟩
  -- the record the store's last frame carries (its state root binds it); one that does not decode is a corrupt store
  let some au0 := decAuth cs0.au | return fail .CORRUPT
  let opt (b : Bytes) : Option Bytes := if b.isEmpty then none else some b
  let st : Run.St :=
    { today := q.today, redo := q.redo, reqs := au.reqs.toArray, grant := opt au.grant, release := opt au.release
      byps := au.byps, floorIn := au.floor, kfloorIn := some au.kfloor, keyset := opt au.keyset, ksteps := au.ksteps }
  let adm : Except String Run.Admitted :=
    if st.reqs.isEmpty then .error "" else match rulesetHold au0 au with
      | some why => .error why
      | none => Run.admit mlDsaOk au0.pin au0.rat au0.floor st
  -- a frame whose authority is not admitted decides nothing and writes nothing: it is refused visibly
  if !st.reqs.isEmpty then
    if let .error why := adm then
      return (keep, ⟨.OK, q.shard, cs0.batches, dg, [], cs0.head.toByteArray, (ChunkIo.stateRootOf cs0).toByteArray,
        { noExt with hold := ((why.toUTF8.toList ++ List.replicate 16 0).take 16).toByteArray }⟩)
  let all := st.lines fun e => match adm with
    | .ok a => (Authority.entryFor a.grant e.r.programId e.r.flow).isSome
    | .error _ => false
  let b := Run.keep all
  let ap : Run.Approvals := match adm with
    | .ok a => Run.approvals hsh a.grant a.byps a.causes st.reqs.toList st.redo
    | .error _ => ⟨[], [], [], []⟩
  let (bps, byp, lim, notes) := match adm with
    | .ok a => (ap.byps, ap.byp, Run.limOf a.grant st.reqs.toList, a.notes ++ ap.notes)
    | .error _ => ([], [], [], [])
  let dmf := snapF 1 Death.fields q.dmf
  let pd := snapF 2 Death.fields q.pdeath
  let ex := snapF 3 Exclusion.fields q.excl
  let sp := snapF 4 Span.fields q.span
  let c : Ctx :=
    { today := q.today, dmf := dmf.map (·.1), providerDeaths := pd.map (·.1), exclusions := ex.map (·.1)
      enrollment := sp.map (·.1), released := none, unresolved := none, releasedPrior := ⟨0, 0, []⟩, unresolvedPrior := ⟨0, 0, []⟩
      anchor := 0, redo := q.redo, byp := byp, lim := lim }
  let fc : FCtx := ⟨c.today, c.redo, feedsOf c, byp, lim⟩
  let pg ← IO.mkRef 0
  let some (fetched, kmemo) ← guardIO (ti pf 9 (fetchChunk pf pg cs0 fc b)) | return fail .IO
  let some fe := fetched | return fail .CORRUPT
  let hr := cs0.fs.hr
  let hu := cs0.fs.hu
  let ((ds, fr, fu), x) ← tp pf 3 (fun _ => (decideFetched hr hu fe fc [] b, leafIx hr hu fe fc b))
    fun ((d, a, c), _) => d.length + a.length + c.length
  let unf := Run.unfit all
  -- a payment's decisions, once: every per-payment question below looks only at its own
  let bp := byPay ds
  let grp := leafGrp bp
  let byd := leafByd x bp
  -- an exact repeat of a paid line, its sender not contesting, is answered at once and joins neither set
  -- (`Run.answering`) over the fetched rows (`relRows`)
  let relM : HashMap Key Entry := HashMap.ofList fe.rel
  let ax := Run.answering c (relRows relM) (contested st.reqs.toList) ds
  let fu := fu.filter fun l => !ax.pays.contains l.pay
  -- one leaf per request, the Spec's over `ExactDuplicate.decideBatchX`'s decisions (`Flat.commit_leaves`)
  let pays : List Run.Pay := match adm with
    | .ok a => st.reqs.toList.map (payOf hsh a.grant bps ap (fun p => x.payOutcome (grp p) p) byd x.redo.contains grp unf.contains)
    | .error _ => []
  let unrM : HashMap Key Entry := HashMap.ofList fe.unr
  let look (ns : UInt8) (k : Key) : Entry := ((if ns == 5 then relM else unrM).get? k).getD Entry.empty
  let u := (Upd.rows {} look 5 hr.n fr).rows look 6 hu.n fu
  let hr' : Head := ⟨hr.asOf, hr.n + fr.length, hr.n + fr.length⟩
  let hu' : Head := ⟨hu.asOf, hu.n + fu.length, hu.n + fu.length⟩
  let mut changed : Array (Bytes × Entry) := #[]
  let mut kills : HashMap Bytes (List (Nat × Nat × Entry)) := ∅
  for nk in u.order do
    let some e := u.ent[nk]? | continue
    let bk := ChunkIo.mkBK (ChunkIo.skeyB (nk.1 == 6) nk.2)
    let kb := bk.b.toList
    match kmemo[bk]? with
    | some (_, hs) => changed := changed.push (kb, e.toEntry); kills := kills.insert kb hs
    | none =>
      let some (some hs) ← guardIO (ChunkIo.liveHits pf pg cs0 bk.b bk.h) | return fail .CORRUPT
      changed := changed.push (kb, e.toEntry); kills := kills.insert kb hs
  -- the record after the batch: a batch with admitted requests moves the ratchet and the floor, any other keeps it
  let au' : AuthRec := match adm with
    | .ok a => { au0 with rat := a.ratchet, floor := a.grant.serial }
    | .error _ => au0
  let ti0 ← IO.monoNanosNow
  -- `cs0` is owned from here: the store is not in `w`, so the directory changes in place; a failure drops it (the next open reloads)
  let cs1 ← match ← ChunkIo.installBatch pf w.crash cs0 changed kills hr' hu' (encAuth au') (Chunk.batchDigest H (encAuth au') (fr, fu))
      w.rq check with
    | .ok c => pure c
    | .error why => return ({ w with cs := none }, ⟨wordOf why, q.shard, q.batch, dg, [], .empty, .empty, noExt⟩)
  let tc ← IO.monoNanosNow
  -- the answer: a record per decided line, then those held for width
  let kmemoLoc (u : Bool) (k : Key) : Option (Nat × Nat) :=
    (kmemo[ChunkIo.mkBK (ChunkIo.skeyB u k)]?).bind fun (_, hs) => hs.head?.map fun (ch, row, _) => (ch, row)
  let decided : List Rec ← tp pf 29 (fun _ =>
    let pos := placeFast (all.zipIdx.filterMap fun (l, i) => if unf.contains l.pay then none else some (i, l)) (ds.map (·.line))
    (pos.zip ds).map fun (i, e) => ⟨i, Frame.outCode e.outcome, ruleOf x grp ax.pays e, Frame.maskOf e.reasons, firstRefFast kmemoLoc x e.line⟩) (·.length)
  let held : List Rec ← tp pf 30 (fun _ => all.zipIdx.filterMap fun (l, i) =>
    if !Run.fits l then some ⟨i, 1, .wide, 0, none⟩
    else if unf.contains l.pay then some ⟨i, 1, .sibling, 0, none⟩ else none) (·.length)
  let rowsOf (tag : UInt8) (ls : List Line) : Option (List ByteArray) := ls.mapM (Run.rowBytesFast tag)
  let some (adds1, adds2) ← tp pf 31 (fun _ => (do pure (← rowsOf 1 fr, ← rowsOf 2 fu) : Option (List ByteArray × List ByteArray))) (fun r => (r.map fun (a, b) => a.length + b.length).getD 0)
    | return fail .CORRUPT
  let leaves ← tp pf 32 (fun _ => (pays.zip rqs.toList).map fun (m, rq) => leafAt ax.c ax.k ax.ds unf.contains m rq) (·.length)
  let bn ← tp pf 33 (fun _ => notes ++ (match adm with
    | .ok _ => Run.bypNotes hsh bps st.reqs.toList byd ++ Run.causeNotes ap byd
    | .error _ => [])) (·.length)
  let ans : AnsFrame := ⟨.OK, q.shard, cs1.batches, dg, decided ++ held, cs1.head.toByteArray, (ChunkIo.stateRootOf cs1).toByteArray,
    ⟨noExt.hold, (match adm with | .ok a => a.grant.id.toByteArray | .error _ => noExt.grant), (encAuth au').toByteArray,
      bn.map (·.toUTF8), leaves,
      adds1 ++ adds2⟩⟩
  let tc1 ← IO.monoNanosNow
  if let some r := pf then
    r.modify (·.set! 10 (tc1 - tc0) |>.set! 12 (tc - ti0) |>.set! 18 (tc1 - tc))
    IO.eprintln s!"RULES_FLAT_COUNTERS lines={all.length} work={Flat.work fe fc.feeds b} pages={← pg.get} hashed={cs1.stat.1 + (← pg.get) * (Chunk.pageSize + ChunkIo.domPageS.size) + w.rqLen} syncs={cs1.stat.2}"
  pure ({ w with cs := some cs1 }, ans)

/-! ## Frames -/

/-- The store of `dir` open for `q`: batch 1 creates it, a later batch opens it at the head the frame follows.  A resident
    store at that head, of the length this worker left it, is reused. -/
def openFor (w : FlatW) (dir : String) (q : Frame.Req) : IO (FlatW × Except Word ChunkIo.CS) := do
  let key := (w.lock.map (·.1)).getD dir
  -- a head older than one this process opened is a rewound store (NOT_NEXT)
  if q.batch - 1 < w.seen.getD key 0 then return (w, .error .NOT_NEXT)
  if let some cs := w.cs then
    let sz ← try pure (← System.FilePath.metadata (ChunkIo.logPath dir)).byteSize.toNat catch _ => pure 0
    if cs.head == q.prev && cs.batches + 1 == q.batch && sz == cs.logLen && cs.au.take 64 == q.auth.pin then
      return (w, .ok cs)
    ChunkIo.closeAll cs
  let w := { w with cs := none }
  if q.batch == 1 then
    let nb ← nbOf
    if nb == 0 then return (w, .error .INIT)
    let a : AuthRec := ⟨q.auth.pin, Keyset.Ratchet.init q.auth.pin, 0, zeroDigest, 0⟩
    match ← (try ChunkIo.initStore dir q.shard q.asOf nb (encAuth a) catch _ => pure none) with
    | some cs => pure (w, if cs.head == q.prev then .ok cs else .error .HEAD)
    | none => pure (w, .error .INIT)
  else
    match ← (try ChunkIo.openStore dir q.prev (q.batch - 1) (← IO.getEnv "RR_FLAT_CHECK") catch _ => pure (.error "IO")) with
    -- a store begun under another key-set pin than the tenant's decides nothing (PIN)
    | .ok cs => if cs.au.take 64 == q.auth.pin then pure (w, .ok cs) else do ChunkIo.closeAll cs; pure (w, .error .PIN)
    | .error why => pure (w, .error (wordOf why))

/-- One request frame (tag 4) on shard `shard`'s store in `dir`: the answer bytes. -/
def handle (w : FlatW) (dir : String) (shard : Nat) (bs : ByteArray) : IO (FlatW × ByteArray) := do
  let refuse (wd : Word) : ByteArray :=
    ⟨(Frame.refusal wd ((Frame.decodeHdr (bs.extract 0 Frame.hdrBytes).toList).toOption.map (·.1))).toArray⟩
  let pf : Prof ← if (← IO.getEnv "RR_FLAT_PROF").isSome then some <$> IO.mkRef (Array.replicate 48 0) else pure none
  match ← tp pf 19 (fun _ => Frame.Fast.decodeReqFast bs) (fun r => match r with | .ok _ => 0 | .error _ => 0) with
  | .error wd => pure (w, refuse wd)
  | .ok (q, dg) =>
    if q.shard != shard then return (w, refuse .SHARD)
    if pf.isSome then  -- bench only: the request parse alone, the lines the decider reads
      let _ ← tp pf 21 (fun _ => q.auth.reqs.foldl (fun n e => n + ((Frame.Fast.decodeRows e.x).map (·.rows.size)).getD 0) 0) id
      let _ ← tp pf 22 (fun _ => q.auth.reqs.foldl (fun n e => n + (e.ra.lines.map (Frame.Fast.lineOfBytes e.q)).length) 0) id
    let some w ← lockDir w dir | return ({ w with cs := none }, refuse .LOCK)
    let (ib, rqs) := Frame.Fast.identFast bs q
    let w := { w with rq := ib.toList, rqLen := bs.size }
    match ← ti pf 41 (openFor w dir q) with
    | (w, .error wd) => pure (w, refuse wd)
    | (w, .ok cs) =>
      let w := { w with seen := w.seen.insert ((w.lock.map (·.1)).getD dir) (q.batch - 1) }
      let r ← try some <$> commitBin pf w cs q dg rqs catch _ => pure none
      match r with
      | some (w, a) =>
        if pf.isSome then
          let _ ← tp pf 34 (fun _ => a.recs.foldl Frame.Fast.putRec ByteArray.empty) (·.size)
          let _ ← tp pf 35 (fun _ => a.ext.leaves.foldl Frame.Fast.putLeaf ByteArray.empty) (·.size)
          let _ ← tp pf 36 (fun _ => a.ext.adds.foldl Frame.Fast.putBlob2 ByteArray.empty) (·.size)
        let out ← tp pf 20 (fun _ => Frame.Fast.encodeAnsFast a) (·.size)
        if let some r := pf then IO.eprintln ("RULES_FLAT_PROF " ++ " ".intercalate ((← r.get).toList.map fun n => toString (n / 1000)))
        pure (w, out)
      | none => pure ({ w with cs := none }, refuse .IO)

end BlindLedger.Gate.Flat.Worker
