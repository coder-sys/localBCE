import BlindLedger.Gate.FactRegistry
import BlindLedger.Gate.FactStore
import BlindLedger.Gate.Engine3.Store
import BlindLedger.Gate.RefSet
import Std.Data.TreeMap

/-! The `facts` file of a rows-file store and the admission of fact frames (fact record design §2.2, §2.3, §2.10; phase 1,
    step 5).

    A fact frame (`RRDF`, `FactFrame.decodeReq`) is a batch of the shard's one chain.  Its receipt is admitted in the order
    of `FactRegistry.admit`, without the source registry, which is not wired yet:
    1. the same file as a stored receipt, unless a re-read, is `ALREADY` (rule 1);
    2. the receipt's own checks (cover 1 to 4, channel 1 to 3, a valid as-of date, no `reread` unless a re-read) and rule 6
       (a re-read names a stored receipt of the same file, source, `fseq`, as-of date, scope and sender with a lower
       reader), else `RECORD`;
    3. a re-read by a reader already stored for its source and `fseq` is `ALREADY`.
    `ALREADY` writes nothing and answers every row with disposition 4 and that receipt's record number.  Otherwise the
    receipt is written (`kb` the batch, `admitted` and `same` counted), then each row in order: disposition 2 when the
    statement in force for its (subject, kind, sid) has the same `op`, `vstart`, `vstop`, `until` and value and a rank at
    least the row's own; disposition 2 and a lift when it has them at a lower rank, the receipt is a full file (`cover`
    1) and the row in force is of the receipt's source (the statement's rank in force becomes the row's, so a file that
    arrives late never outranks it); else disposition 1 and a fact row with `until` from §3.2
    (`FactRegistry.lateUntil` over the source's stored receipts) and `receipt` the receipt's record number.  The
    frame's lifts follow its rows as lift records (`FactStore.liftRecs`).  The statement in force is the row of greatest
    rank in force (`fseq`, reader, `roff`; §3.2; its last lift's when lifted); of two of equal rank, the later record.
    Not in step 5: `FSEQ_REUSED`, the drop and gap checks, end rows, markers, summaries and money rows.

    The file holds 256-byte records in log order, each a body and its link (`FactStore.factsP`: the chains of
    `FactStore.chainKeys`, linked by `FactStore.run`), so it is `FactStore.factsFile` of the bodies.  A live batch appends
    its records before its frame goes to the log, and a clean stop syncs the file with the rows files.  An open after a
    clean stop (the store's marker, as for the rows files) keeps the file's records up to the last receipt of a logged
    batch, builds the tables and links from them (a file whose records do not decode or whose links differ is not kept),
    and admits that batch's frame and the fact frames after it again; any other open admits every fact frame of the log
    again.  Each frame admitted again has its derived answer checked against the one its trailer binds.  The tables are in memory:
    the chain table, the receipts by record, the first receipt of each file, the readings of each source and `fseq`, per
    source a `late` table of its full receipts, and per statement its row in force, so a row costs a few table reads
    whatever the store holds.  The design's `Index` tables are not built yet.

    The reference set (§2.9, step 6): a written receipt whose frame carries rows of the reference kinds (`RefSet.refKind`:
    3 EXCL, 4 PDEATH) adds its entry `src u16 ‖ fseq u64 ‖ reader u16 (big-endian) ‖ file ‖ rd`, with
    `rd = H(dom REFROWS ‖ those rows in wire order)`, which the stored receipt keeps (zero without such a row), so the
    entries are read again from the file's receipts.  The entries are kept sorted with each one's chain value
    `h = H(dom REFSRC ‖ h before it in its source, or H(dom REFSRC ‖ src) ‖ fseq ‖ file ‖ rd)`; a late receipt goes to its
    place and only the values from there to its source's last receipt are computed again.  Every fact answer carries
    `rs = H(dom REFSET ‖ per source ascending: src ‖ its last h)`.  This is the engine's own code: the checker computes
    `rs` by the specification (`RefSet.rs`) and refuses any difference.
    Synthetic, nonpayment, non-PHI, activation=false. -/

namespace BlindLedger.Gate.Engine3.Facts

open BlindLedger.Gate BlindLedger.Gate.FactCodec BlindLedger.Gate.Flat BlindLedger.Gate.Engine3.Run
open BlindLedger.Gate.Frame (Word)
open Std (HashMap TreeMap)

/-- A row's rank (§3.2): its receipt's `fseq` and reader, then its `roff`. -/
abbrev Rank := Nat × Nat × Nat

def rankLe (a b : Rank) : Bool :=
  a.1 < b.1 || (a.1 == b.1 && (a.2.1 < b.2.1 || (a.2.1 == b.2.1 && a.2.2 ≤ b.2.2)))

/-- The facts of a store: the open file, the bodies in record order, the chain table, the receipts by record number,
    the first receipt of each file, the receipts of each (`src`, `fseq`) in record order, per source its full receipts as
    `fseq ↦ cfrom` less each one a receipt of an `fseq` at least as high and a `cfrom` at most as low outdoes (`late`, so
    `cfrom` rises with `fseq`), per statement (subject, kind, sid) the record number, rank in force and source of the row
    in force, and the reference set's entries in byte order, each with its chain value. -/
structure Facts where
  fd : UInt32
  bodies : Array ByteArray
  tab : FactStore.Tab
  rcpt : HashMap Nat Receipt
  files : HashMap ByteArray Nat
  reads : HashMap (Nat × Nat) (Array Nat)
  late : HashMap Nat (TreeMap Nat Nat)
  force : HashMap ByteArray (Nat × Rank × Nat)
  refs : Array (ByteArray × ByteArray)

/-- No facts, on the open file `fd`. -/
def Facts.empty (fd : UInt32) : Facts := ⟨fd, #[], ∅, ∅, ∅, ∅, ∅, ∅, #[]⟩

def Facts.close (fx : Facts) : IO Unit := do
  let _ ← Io.pgClose fx.fd

/-- What a receipt says of itself (§2.10, phase 1): the parts of `FactRegistry.shapeOk` that need no registry entry. -/
def selfOk (r : Receipt) : Bool :=
  decide (1 ≤ r.cover ∧ r.cover ≤ 4) && decide (1 ≤ r.channel ∧ r.channel ≤ 3) && Rules.validDate r.asof &&
    (r.cover == 4 || r.reread == 0)

inductive Verdict where
  /-- `ALREADY`: the receipt that holds this file or reading. -/
  | held (seq : Nat)
  | refuse (w : Word)
  | write

/-- The receipt's fate, in `FactRegistry.admit`'s order; reads the facts only.  A batch or a record number past 40 bits
    is `FULL`. -/
def verdict (fx : Facts) (kb : Nat) (r : Receipt) (nrows : Nat) : Verdict :=
  match if r.cover == 4 then none else fx.files[(⟨r.file.toArray⟩ : ByteArray)]? with
  | some s => .held s
  | none =>
    -- rule 6: the receipt a re-read names
    let named := r.cover != 4 || (fx.rcpt[r.reread]?).any fun s => s.src == r.src && s.fseq == r.fseq &&
      s.file == r.file && s.asof == r.asof && s.scope == r.scope && s.sender == r.sender && s.reader < r.reader
    if !(selfOk r && named) then .refuse .RECORD
    else
      let same := if r.cover != 4 then none else
        (fx.reads.getD (r.src, r.fseq) #[]).find? fun j => (fx.rcpt[j]?).any (·.reader == r.reader)
      match same with
      | some s => .held s
      | none => if kb < 2 ^ 40 && fx.bodies.size + 1 + nrows < 2 ^ 40 then .write else .refuse .FULL

/-- A source's `late` table with its full receipt of `fseq` `f` and `cfrom` `c`: unchanged when an entry at or above `f`
    has a `cfrom` at most `c`; else the entries at or below `f` with a `cfrom` at least `c` (just below `f`) go and it is
    added. -/
def lateIn (t : TreeMap Nat Nat) (f c : Nat) : TreeMap Nat Nat := Id.run do
  if let some (_, c') := t.getEntryGE? f then
    if c' ≤ c then return t
  let mut t := t
  for _ in [0:t.size] do
    match t.getEntryLE? f with
    | some (k, c') => if c ≤ c' then t := t.erase k else break
    | none => break
  return t.insert f c

/-! ## The reference set -/

/-- `a` strictly before `b` in byte order. -/
def ltB (a b : ByteArray) : Bool := Id.run do
  for i in [0:min a.size b.size] do
    if a[i]! != b[i]! then return a[i]! < b[i]!
  return a.size < b.size

/-- An entry's source (its first two bytes, big-endian). -/
def srcOf (e : ByteArray) : Nat := e[0]!.toNat * 256 + e[1]!.toNat

def le2 (n : Nat) : ByteArray := ⟨#[(n % 256).toUInt8, (n / 256 % 256).toUInt8]⟩

/-- The entry of a written receipt `r` whose frame carried `rows`; none without a reference row. -/
def refEnt (r : Receipt) (rows : List FactFrame.Row) : Option ByteArray :=
  let rr := rows.filter fun w => RefSet.refKind w.value.kind
  if rr.isEmpty then none else
  let body := rr.foldl (fun b w => b ++ ⟨w.enc.toArray⟩) ByteArray.empty
  let be (w n : Nat) : ByteArray := ⟨(FactCodec.leBytes w n).reverse.toArray⟩
  some (be 2 r.src ++ be 8 r.fseq ++ be 2 r.reader ++ ⟨r.file.toArray⟩ ++ hD "REFROWS" [body])

/-- Entry `e` put in its place among `refs`; the chain values from there to the end of its source's run computed again. -/
def addRef (refs : Array (ByteArray × ByteArray)) (e : ByteArray) : Array (ByteArray × ByteArray) := Id.run do
  -- the first entry after `e`, by halving
  let mut lo := 0
  let mut hi := refs.size
  for _ in [0:64] do
    if hi ≤ lo then break
    let mid := (lo + hi) / 2
    if ltB e refs[mid]!.1 then hi := mid else lo := mid + 1
  let p := lo
  let src := srcOf e
  let mut a := refs.insertIdx! p (e, ByteArray.empty)
  for i in [p:a.size] do
    let x := a[i]!.1
    if srcOf x != src then break
    let h := if i > p || (i > 0 && srcOf a[i - 1]!.1 == src) then a[i - 1]!.2 else hD "REFSRC" [le2 src]
    -- fseq little-endian (bytes 2-9 reversed), then file and rd
    a := a.set! i (x, hD "REFSRC" [h, ⟨(x.extract 2 10).data.reverse⟩, x.extract 12 x.size])
  return a

/-- Entries `es`, in any order, sorted and each with its chain value, as `addRef` gives them one by one. -/
def refsOf (es : Array ByteArray) : Array (ByteArray × ByteArray) := Id.run do
  let es := (es.toList.mergeSort fun a b => !ltB b a).toArray
  let mut a : Array (ByteArray × ByteArray) := Array.mkEmpty es.size
  for i in [0:es.size] do
    let x := es[i]!
    let src := srcOf x
    let h := if i > 0 && srcOf es[i - 1]! == src then a[i - 1]!.2 else hD "REFSRC" [le2 src]
    a := a.push (x, hD "REFSRC" [h, ⟨(x.extract 2 10).data.reverse⟩, x.extract 12 x.size])
  return a

/-- `rs`: per source in ascending order (the entries' order), its number and its last chain value. -/
def rsOf (refs : Array (ByteArray × ByteArray)) : ByteArray := Id.run do
  let mut b := ByteArray.empty
  for i in [0:refs.size] do
    if i + 1 == refs.size || srcOf refs[i + 1]!.1 != srcOf refs[i]!.1 then
      b := b ++ le2 (srcOf refs[i]!.1) ++ refs[i]!.2
  return hD "REFSET" [b]

def keyOf (subject : Bytes) (kind : Nat) (sid : Bytes) : ByteArray := ⟨(subject ++ [UInt8.ofNat kind] ++ sid).toArray⟩

def stmtKey (w : FactFrame.Row) : ByteArray := keyOf w.subject w.value.kind w.sid

/-- The records of bodies `bs` appended at record `n` to a file whose chain table is `t` (`FactStore.factsP`): their bytes
    and the table after them. -/
def records (t : FactStore.Tab) (n : Nat) (bs : List Bytes) : ByteArray × FactStore.Tab :=
  let r := FactStore.run t n (bs.map FactStore.chainKeys)
  (⟨(FactStore.factsP.emit bs r.1).toArray⟩, r.2)

/-- A receipt that `verdict` lets write: the answer entries, the facts after it and the bytes of its new records (to go at
    record `fx.bodies.size`).  None when a stored row does not decode. -/
def write (fx : Facts) (kb : Nat) (r : Receipt) (rows : List FactFrame.Row) :
    Option (List FactFrame.Entry × Facts × ByteArray) := do
  let ⟨fd, bodies, tab, rcpt, files, reads, late, force, refs⟩ := fx
  let n0 := bodies.size
  let u := match (late[r.src]?).bind (·.getEntryGT? r.fseq) with
    | some (_, c) => FactRegistry.dayBefore c
    | none => FactRegistry.OPEN
  -- the receipt's place, filled once its counts are known
  let mut bodies := bodies.push .empty
  let mut force := force
  let mut ents : Array FactFrame.Entry := #[]
  let mut same := 0
  let mut lifts : Array FactStore.Lift := #[]
  for w in rows do
    let k := stmtKey w
    let rk : Rank := (r.fseq, r.reader, w.roff)
    let cur ← match force[k]? with
      | none => pure none
      | some (j, rk', s) => do
        let f ← Fact.dec bodies[j]!.toList
        pure (some (j, rk', s, f))
    match cur with
    | some (j, rk', s, f) =>
      if f.op == w.op && f.vstart == w.vstart && f.vstop == w.vstop && f.lineUntil == u && f.value.enc == w.value.enc then
        if rankLe rk rk' then
          ents := ents.push ⟨2, 0, j⟩
          same := same + 1
          continue
        if r.cover == 1 && s == r.src then
          ents := ents.push ⟨2, 0, j⟩
          same := same + 1
          lifts := lifts.push ⟨j, w.roff⟩
          force := force.insert k (j, rk, s)
          continue
    | none => pure ()
    let seq := bodies.size
    bodies := bodies.push ⟨(w.toFact u n0).enc.toArray⟩
    ents := ents.push ⟨1, 0, seq⟩
    if cur.all fun (_, rk', _, _) => rankLe rk' rk then force := force.insert k (seq, rk, r.src)
  let ent := refEnt r rows
  let rc := { r with kb := kb, admitted := bodies.size - n0 - 1, same := same,
                     rd := (ent.map fun e => (e.extract (e.size - 64) e.size).toList).getD (zeros 64) }
  bodies := bodies.set! n0 ⟨rc.enc.toArray⟩
  for l in FactStore.liftRecs n0 lifts.toList do
    bodies := bodies.push ⟨(FactStore.liftC.enc l).toArray⟩
  let (rb, tab) := records tab n0 ((bodies.extract n0 bodies.size).toList.map (·.toList))
  let refs := match ent with
    | some e => addRef refs e
    | none => refs
  let late := if rc.cover == 1 then late.insert rc.src (lateIn (late.getD rc.src {}) rc.fseq rc.cfrom) else late
  let reads := reads.insert (rc.src, rc.fseq) ((reads.getD (rc.src, rc.fseq) #[]).push n0)
  pure (ents.toList, ⟨fd, bodies, tab, rcpt.insert n0 rc, files.insertIfNew ⟨rc.file.toArray⟩ n0, reads, late, force, refs⟩,
    rb)

/-- What the verdict `v` on a fact frame's receipt `r` and rows, admitted as batch `kb`, gives: the answer entries, the facts
    after it and the bytes of the records it appends (none for `ALREADY`). -/
def apply (v : Verdict) (fx : Facts) (kb : Nat) (r : Receipt) (rows : List FactFrame.Row) :
    Except Word (List FactFrame.Entry × Facts × ByteArray) :=
  match v with
  | .held s => .ok (rows.map fun _ => ⟨4, 0, s⟩, fx, .empty)
  | .refuse w => .error w
  | .write => match write fx kb r rows with
    | some x => .ok x
    | none => .error .CORRUPT

def admit (fx : Facts) (kb : Nat) (r : Receipt) (rows : List FactFrame.Row) :
    Except Word (List FactFrame.Entry × Facts × ByteArray) :=
  apply (verdict fx kb r rows.length) fx kb r rows

/-- The fact answer before its head and root are known (both zero, as the engine patches them, `patchAns`), with the
    reference set's `rs` after the frame; no work items or money rows are written in steps 5 and 6. -/
def answer (shard batch : Nat) (dg : ByteArray) (ents : List FactFrame.Entry) (rs : ByteArray) : ByteArray :=
  ⟨(FactFrame.Ans.enc ⟨shard, batch, dg.toList, ents, zeros 64, zeros 64, rs.toList, 0, 0⟩).toArray⟩

/-- The facts of stored bodies `bodies` (on the open file `fd`), their tables built from the records alone: each receipt
    entered as `write` enters it (its reference entry from its `rd`), each fact row and each lift offered for its
    statement at its rank in force (the later record wins a tie, as in `write`).  None when a body is not a receipt, a
    fact row or a lift record, or names a record that is not there. -/
def ofBodies (fd : UInt32) (bodies : Array ByteArray) (tab : FactStore.Tab) : Option Facts := Id.run do
  let mut fx := Facts.empty fd
  let mut ents : Array ByteArray := #[]
  for i in [0:bodies.size] do
    let offer (fx : Facts) (k : ByteArray) (j : Nat) (rk : Rank) (s : Nat) : Facts :=
      if (fx.force[k]?).all fun (_, rk', _) => rankLe rk' rk then { fx with force := fx.force.insert k (j, rk, s) } else fx
    match FactStore.FRec.dec bodies[i]!.toList with
    | some (.receipt r) =>
      if r.rd != zeros 64 then
        let be (w n : Nat) : ByteArray := ⟨(FactCodec.leBytes w n).reverse.toArray⟩
        ents := ents.push (be 2 r.src ++ be 8 r.fseq ++ be 2 r.reader ++ ⟨r.file.toArray⟩ ++ ⟨r.rd.toArray⟩)
      fx := { fx with rcpt := fx.rcpt.insert i r, files := fx.files.insertIfNew ⟨r.file.toArray⟩ i,
                      reads := fx.reads.insert (r.src, r.fseq) ((fx.reads.getD (r.src, r.fseq) #[]).push i),
                      late := if r.cover == 1 then fx.late.insert r.src (lateIn (fx.late.getD r.src {}) r.fseq r.cfrom)
                        else fx.late }
    | some (.fact f) =>
      let some r := fx.rcpt[f.receipt]? | return none
      fx := offer fx (keyOf f.subject f.value.kind f.sid) i (r.fseq, r.reader, f.roff) r.src
    | some (.lift l) =>
      let some r := fx.rcpt[l.receipt]? | return none
      for x in l.list do
        let some f := (bodies[x.row]?).bind (Fact.dec ·.toList) | return none
        fx := offer fx (keyOf f.subject f.value.kind f.sid) x.row (r.fseq, r.reader, x.roff) r.src
    | _ => return none
  return some { fx with bodies, tab, refs := refsOf ents }

/-- The records of `facts` in `dir` that an open after a clean stop keeps for a log of `bt` batches: those before the last
    receipt of batch `bt` or lower, when the receipts' batches rise up to it, the records decode (`ofBodies`) and the
    file's links are those of the bodies.  Their facts and the batch from which the fact frames are admitted again (that
    receipt's: its records may be cut short); none to keep no part of the file. -/
def kept (dir : String) (bt : Nat) : IO (Option (Facts × Nat)) := do
  let p := s!"{dir}/facts"
  if !(← System.FilePath.pathExists p) then return none
  let file ← IO.FS.readBinFile p
  let rb := Obligations.recBytes
  let mut cut : Option (Nat × Nat) := none
  let mut kb := 0
  for i in [0:file.size / rb] do
    match Receipt.dec (file.extract (rb * i) (rb * i + bodyBytes)).toList with
    | some r =>
      if r.kb ≤ kb || r.kb > bt then break
      cut := some (i, r.kb)
      kb := r.kb
    | none => pure ()
  let some (c, kc) := cut | return none
  let bodies := (Array.range c).map fun i => file.extract (rb * i) (rb * i + bodyBytes)
  let (recs, tab) := records ∅ 0 (bodies.toList.map (·.toList))
  let some fx := ofBodies 0 bodies tab | return none
  if recs != file.extract 0 (rb * c) then return none
  return some (fx, kc)

/-- The facts of the first `bt` frames of the log, and the file `facts` written from them.  After a clean stop
    (`trusted`) the records `kept` stay and the fact frames from their batch on are admitted again; otherwise every fact
    frame is.  Each fact frame admitted (a frame that adds no rows and whose request is `RRDF`) must hash to its
    trailer's `rq`, its trailer must carry the previous authority record and the batch digest of no rows, and the answer
    derived again must be the one its trailer binds (`an`).  The error names the frame that failed. -/
def load (dir : String) (log : UInt32) (frames : Array FrameInfo) (trs : Array Trailer) (bt : Nat) (trusted : Bool) :
    IO (Except String Facts) := do
  let (fx0, j0) := match ← (if trusted then kept dir bt else pure none) with
    | some (fx, kc) => (fx, kc - 1)
    | none => (Facts.empty 0, 1)
  let at0 := Obligations.recBytes * fx0.bodies.size
  let mut fx := fx0
  let mut file := ByteArray.empty
  for j in [j0:bt] do
    let (some t, some t0) := (trs[j]?, trs[j - 1]?) | return .error s!"FACTS:frame batch {j + 1} trailer"
    if t.hr.n != t0.hr.n || t.hu.n != t0.hu.n then continue
    let f := frames[j]!.ref
    if !isFact (← Io.pgRead log (f.off + 16).toUInt64 4) then continue
    let some (rqb, _, _, _) ← readFrame log f | return .error s!"FACTS:frame batch {j + 1} LOG"
    let .ok (q, dg) := FactFrame.decodeReq FactFrame.sha rqb.toList | return .error s!"FACTS:frame batch {j + 1} request"
    if q.shard != t.shard || q.batch != j + 1 || dg.toByteArray != t.rq || t.au != t0.au ||
        batchDigestFast t.au ([], []) != t.bd then
      return .error s!"FACTS:frame batch {j + 1} trailer"
    let .ok (ents, fx', rb) := admit fx q.batch q.rcpt q.rows | return .error s!"FACTS:frame batch {j + 1} admit"
    if ansBind (answer q.shard q.batch t.rq ents (rsOf fx'.refs)) != t.an then return .error s!"FACTS:frame batch {j + 1} answer"
    fx := fx'
    file := file ++ rb
  let fd ← Io.pgOpen s!"{dir}/facts"
  if fd == 0xFFFFFFFF then return .error "FACTS:open"
  if (← Io.pgTrunc fd at0.toUInt64) != 0 || (← Io.pgWrite fd at0.toUInt64 file) != 0 then
    let _ ← Io.pgClose fd
    return .error "FACTS:write"
  return .ok { fx with fd }

/-- The empty facts of a new store, its file created empty. -/
def create (dir : String) : IO (Option Facts) := do
  let fd ← Io.pgOpen s!"{dir}/facts"
  if fd == 0xFFFFFFFF then return none
  if (← Io.pgTrunc fd 0) != 0 then
    let _ ← Io.pgClose fd
    return none
  return some (Facts.empty fd)

end BlindLedger.Gate.Engine3.Facts
