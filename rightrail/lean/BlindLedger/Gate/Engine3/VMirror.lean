import BlindLedger.Gate.Engine3.VStore
import BlindLedger.Gate.Engine3.ReadB
import BlindLedger.Gate.Engine3.RowsFile
import BlindLedger.Gate.Engine3.Index
import BlindLedger.Gate.Engine3.CoreSum

/-! The checker's history: per set (released, unresolved) its own tagged rows file (`VStore`), two tables of the
    proved `Index` and a long-core summary, sharing no state and no read code with the engine (`Hist.lean`).

    * `ids`: a slot per row under its id key.
    * `cores`: a slot per core under its core key, naming the core's newest row.  A core is the member and the month of
      a CAP row, the member, date and procedure of a fee-for-service row; POSTING_CAP counts the rows of a core.  A
      record links to the previous row of its core and holds the core's row count; past `capN` rows a core is frozen:
      its later rows link to its `capN`-th row.
    * `sum`: a core of more than `CoreSum.longMin` rows is summarised: each exact and near key among its first `capN`
      rows has an entry with its first row, its count and its first row not identical to the first (`CoreSum`), counted
      here (`sumAdd`) from the records this checker wrote or read with their tags held, under a digest word of its own
      (`keyWord`).  It holds nothing the file does not; `Side.load` counts it again.

    A key's read in a set is what the decider's history gives: an exact or near key's rows are its core's rows that
    have the key, ascending, the first `capN` of them, and its count is exact, or the core's count when the core is past
    the cap; an id key's rows are the rows with the id.  A key of a summarised core reads only what the decider uses of
    it (`Flat.DecideCut.decideRows_cut`): on the released side, when no line of a redone payment has the key, its first
    row; on the unresolved side, when it is a fee-for-service key, its first row and its first row not identical to the
    first; its count is the entry's.  Every other key walks its core's chain.  A slot only suggests: each row is read
    back with its leaf and tag computed again and compared whole.  A slot whose row fails, a link that does not go
    back, a row of another core or a count that does not agree with the walk is a fault of the store (`fault`), never
    an absence: the batch is not passed and the caller rebuilds the store from the log.  The tables are never stored:
    `Side.load` builds them from the rows whose tags held as the file is opened.

    Shared with the engine: the proved `Index` and decider, the summary's tables (`CoreSum`, not its counting), the
    request's store lines (`ReadB.storeLine`, `payField`), the feeds (`ReadB.feedsW`) and the assembly of the decider's
    layout (`assemble`).  Its own: the key list (`keysOf`, `round2Keys`), the core keys, the summary's digest and
    counting, the chain walk, the reads and the puts.  Synthetic, nonpayment, non-PHI. -/

namespace BlindLedger.Gate.Engine3.VMirror

open BlindLedger.Gate BlindLedger.Gate.Rules BlindLedger.Gate.Flat BlindLedger.Gate.Flat.Rows
open Std (HashMap)

/-- The error every store fault raises; the caller rebuilds the store from the log on it. -/
def faultTag : String := "VSTORE_FAULT"

def fault {α : Type} (what : String) : IO α := throw (IO.userError s!"{faultTag} {what}")

structure Side where
  f : VStore.T
  ids : Index.Idx
  cores : Index.Idx
  sum : CoreSum.Sum
  /-- 0 released, 1 unresolved. -/
  set : Nat

structure M where
  ctx : KeyCtx
  rel : Side
  unr : Side

/-! ## Cores and table words -/

def coreKey (r : RowX) : ByteArray :=
  let b := put64 (put64 (put64 (put64 ((ByteArray.emptyWithCapacity 72).push (if r.cap then 1 else 2)) r.m0) r.m1) r.m2) r.m3
  if r.cap then put32u b (r.date / 100) else put64 (put64 (put64 (put64 (put32u b r.date) r.q0) r.q1) r.q2) r.q3

def sameCore (a b : RowX) : Bool :=
  a.cap == b.cap && a.memEq b && (if a.cap then a.date / 100 == b.date / 100 else a.date == b.date && a.procEq b)

/-- The table words of key bytes `kb` in set `u`, as the batch's `KeyQ` of them has them. -/
def wordsOf (q : KeyQ) (u : Nat) : UInt64 × UInt64 := if u == 1 then (q.dh1, q.kh1) else (q.dh0, q.kh0)

def words (ctx : KeyCtx) (kb : ByteArray) (u : Nat) : UInt64 × UInt64 := wordsOf (keyQ ctx default kb) u

/-- The (row, table position) pairs the table's slots for `w` name, each row once. -/
def cands (ix : Index.Idx) (w : UInt64 × UInt64) : Array (Nat × Nat) := Id.run do
  let out := Index.probe ix w.1 w.2 ⟨Array.replicate (8 * Index.probeWords) 0⟩ 0
  let mut r : Array (Nat × Nat) := #[]
  for j in [0:(Index.wAt out 0).toNat] do
    let s := Index.seqOf (Index.wAt out (2 + 2 * j))
    if !r.any (·.1 == s) then r := r.push (s, (Index.wAt out (1 + 2 * j)).toNat)
  return r

/-- Record `q` of set `set` (file `f`), its tag checked; a fault when it is missing or fails. -/
def get (f : VStore.T) (set q : Nat) : IO ByteArray := do
  let some r ← VStore.fetch f q | fault s!"set {set} row {q}"
  return r

/-- The newest row of the core of `row` in set `set` (file `f`, core table `cores`), whose table words are `w`: its
    number, its table position and its record. -/
def newest (f : VStore.T) (cores : Index.Idx) (set : Nat) (row : RowX) (w : UInt64 × UInt64) :
    IO (Option (Nat × Nat × ByteArray)) := do
  for (q, pos) in cands cores w do
    let r ← get f set q
    if sameCore row (RowX.ofChunk r 0) then return some (q, pos, r)
  return none

/-! ## The summary's counting -/

@[inline] def fold (h w : UInt64) : UInt64 := mix64 (h ^^^ w)

/-- The summary's digest word of the exact key (`near` false) or the near key of `r`: a seeded fold of the very fields
    `RowX.exactEq` (`RowX.nearEq`) compares, so the rows of one key have one word. -/
def keyWord (seed : UInt64) (near : Bool) (r : RowX) : UInt64 :=
  let mem (h : UInt64) := fold (fold (fold (fold h r.m0) r.m1) r.m2) r.m3
  let proc (h : UInt64) := fold (fold (fold (fold h r.q0) r.q1) r.q2) r.q3
  if !near then
    let h := fold (fold (fold (mem (fold seed (if r.cap then 3 else 1))) r.a0) r.a1) r.a2
    fold (fold (proc (fold h r.date.toUInt64)) r.units.toUInt64) r.cents
  else if r.cap then fold (mem (fold seed 0)) (r.date / 100).toUInt64
  else proc (fold (fold (fold (fold (mem (fold seed 2)) r.r0) r.r1) r.r2) r.date.toUInt64)

/-- First rows of entries already read, by row number. -/
abbrev FirstRows := HashMap Nat RowX

/-- Row `q` (`y`) counted in the entry of its exact key and in that of its near key: a new entry when its word has
    none; else, unless the entry is mixed, compared with the entry's first row (read by `rd`, or from `fr`): the same key
    counts it, another key marks the entry mixed.  False when a table cannot take it or `q` is past the summary's cap. -/
def keyAdd (rd : Nat → IO ByteArray) (sm : CoreSum.Sum) (fr : FirstRows) (q : Nat) (y : RowX) :
    IO (CoreSum.Sum × FirstRows × Bool) := do
  if q ≥ sm.cap then return (sm, fr, false)
  let mut sm := sm
  let mut fr := fr
  for near in [false, true] do
    let h := keyWord sm.seed near y
    match sm.find near h with
    | none =>
      let (s2, ok) := sm.insert near h q
      sm := s2
      if !ok then return (sm, fr, false)
    | some (i, e) =>
      if !e.mixed then
        let x ← match fr.get? e.first with
          | some x => pure x
          | none => do
            let x := RowX.ofChunk (← rd e.first) 0
            fr := fr.insert e.first x
            pure x
        if (if near then x.nearEq y else x.exactEq y) then sm := sm.bump near i (if x.same y then none else some q) false
        else sm := sm.bump near i none true
  return (sm, fr, true)

/-- Row `seq` (the `k`-th of its core, `p` the row plus one it links to, `row` its contents) taken into the summary.
    Nothing while the core has `longMin` rows or fewer.  The row that makes it longer summarises the core: its earlier
    rows are read (`rd`, back through the links) and counted in ascending order, then the row, and the row is flagged.  A
    later row is flagged when the row it links to is, and counted while it is within the first `capN`.  A row that cannot
    be counted is not flagged, nor is any later row of its core: their reads walk the chain. -/
def sumAdd (rd : Nat → IO ByteArray) (sm : CoreSum.Sum) (fr : FirstRows) (seq k p : Nat) (row : RowX) :
    IO (CoreSum.Sum × FirstRows) := do
  if k ≤ CoreSum.longMin || p == 0 then return (sm, fr)
  if k == CoreSum.longMin + 1 then
    let mut prior : Array (Nat × RowX) := #[]
    let mut s := p - 1
    for _ in [0:CoreSum.longMin] do
      let rc ← rd s
      prior := prior.push (s, RowX.ofChunk rc 0)
      let pp := RowsFile.prevCoreAt rc 0
      if pp == 0 then break
      s := pp - 1
    if prior.size != CoreSum.longMin then return (sm, fr)
    let mut sm := sm
    let mut fr := fr
    for (q, y) in prior.reverse.push (seq, row) do
      let (s2, f2, ok) ← keyAdd rd sm fr q y
      sm := s2
      fr := f2
      if !ok then return (sm, fr)
    return (sm.setFlag seq, fr)
  if !sm.flagOf (p - 1) then return (sm, fr)
  if capN < k then return (sm.setFlag seq, fr)
  let (s2, f2, ok) ← keyAdd rd sm fr seq row
  return (if ok then s2.setFlag seq else s2, f2)

/-- A core as the batch's puts leave it: newest row, count, the `capN`-th row plus one (0 while it has fewer), its
    table position if it had a row before the batch, its table words. -/
structure Core where
  top : Nat
  cnt : Nat
  capAt : Nat
  pos : Option Nat
  w : UInt64 × UInt64
  deriving Inhabited

/-- The core whose newest row is `t` (table position `pos`, record `r`), table words `w`. -/
def coreOf (t pos : Nat) (r : ByteArray) (w : UInt64 × UInt64) : Core :=
  let n := RowsFile.countAt r 0
  ⟨t, n, if n < capN then 0 else if n == capN then t + 1 else RowsFile.prevCoreAt r 0, some pos, w⟩

/-- A core as one batch's read found it in a set: the core as the puts find it, its newest record (empty when it has no
    row), and its rows ascending (the first `capN`) once walked. -/
structure Found where
  core : Core
  top : ByteArray
  rows : Option (Array (Nat × RowX))

/-- A set's cores found in one batch, by core key. -/
abbrev Walk := HashMap ByteArray Found

/-! ## Reads -/

/-- The rows of the core of `row`, ascending (the first `capN` when the core is past the cap), from its newest row (`fd`)
    back through the links. -/
def chain (s : Side) (row : RowX) (fd : Found) : IO (Array (Nat × RowX)) := do
  let cnt := fd.core.cnt
  let frozen := capN < cnt
  let mut out : Array (Nat × RowX) := #[]
  let mut q := fd.core.top
  let mut rc := fd.top
  let mut c := cnt
  for _ in [0:capN + 2] do
    let y := RowX.ofChunk rc 0
    if !sameCore row y then fault s!"set {s.set} row {q} is not of the core it links to"
    out := out.push (q, y)
    let p := RowsFile.prevCoreAt rc 0
    if p == 0 then break
    if q < p then fault s!"set {s.set} row {q} links forward"
    q := p - 1
    rc ← get s.f s.set q
    -- each row back is one fewer, but the first past the cap links to the `capN`-th
    let c' := RowsFile.countAt rc 0
    if c' + 1 != c && !(c == cnt && frozen && c' == capN) then fault s!"set {s.set} row {q} count {c'} after {c}"
    c := c'
  let rows := (if frozen then out.extract 1 out.size else out).reverse
  if rows.size != min cnt capN then fault s!"set {s.set} core of {rows.size} rows counts {cnt}"
  return rows

/-- A read: the rows the decider reads (the first `capN`), their numbers, and the count. -/
structure Rd where
  rows : Array RowX
  seq : Array Nat
  cnt : Nat
  deriving Inhabited

/-- Key `q` in set `s`; `walked` holds this batch's cores.  `cut`: the decider uses only the key's first row (released)
    or its first two rows that differ (unresolved), so a key of a summarised core reads those from its entry. -/
def readKey (ctx : KeyCtx) (s : Side) (walked : IO.Ref Walk) (cut : Bool) (q : KeyQ) : IO Rd := do
  if s.f.n == 0 then return ⟨#[], #[], 0⟩
  let kind := q.kb[0]!
  if kind == 4 then
    let mut got : Array (Nat × RowX) := #[]
    for (c, _) in cands s.ids (wordsOf q s.set) do
      let y := RowX.ofChunk (← get s.f s.set c) 0
      if q.row.idEq y then got := got.push (c, y)
    let all := got.qsort (·.1 < ·.1)
    let g := all.extract 0 capN
    return ⟨g.map (·.2), g.map (·.1), all.size⟩
  let ck := coreKey q.row
  let fd ← match (← walked.get).get? ck with
    | some x => pure x
    | none => do
      let w := words ctx ck s.set
      let x : Found := match ← newest s.f s.cores s.set q.row w with
        | some (t, pos, r) => ⟨coreOf t pos r w, r, none⟩
        | none => ⟨⟨0, 0, 0, none, w⟩, .empty, none⟩
      walked.modify (·.insert ck x)
      pure x
  let cc := fd.core.cnt
  if cc == 0 then return ⟨#[], #[], 0⟩
  let exact := kind == 1 || kind == 3
  let has (y : RowX) : Bool := if exact then q.row.exactEq y else q.row.nearEq y
  if cut && s.sum.flagOf fd.core.top then
    -- every row of the core within the first `capN` is counted: a key with no entry, or whose entry's first row has
    -- another key, has no row; a mixed entry is walked
    let near := !exact
    match s.sum.find near (keyWord s.sum.seed near q.row) with
    | none => return ⟨#[], #[], if capN < cc then cc else 0⟩
    | some (_, e) =>
      if !e.mixed then
        let y := RowX.ofChunk (← get s.f s.set e.first) 0
        if !has y then return ⟨#[], #[], if capN < cc then cc else 0⟩
        let n := if capN < cc then cc else e.count
        match if s.set == 1 then e.diff else none with
        | some d => return ⟨#[y, RowX.ofChunk (← get s.f s.set d) 0], #[e.first, d], n⟩
        | none => return ⟨#[y], #[e.first], n⟩
  let all ← match fd.rows with
    | some r => pure r
    | none => do
      let r ← chain s q.row fd
      walked.modify (·.insert ck { fd with rows := some r })
      pure r
  let mut rows : Array RowX := #[]
  let mut seq : Array Nat := #[]
  let mut n := 0
  for (c, y) in all do
    if has y then
      n := n + 1
      if n ≤ capN then
        rows := rows.push y
        seq := seq.push c
  return ⟨rows, seq, if capN < cc then cc else n⟩

/-- The decider's layout of a batch and the place of every posting row it reads; for the puts, the store lines (`lb`,
    line `i` at `lineW2 * i`), the rows of the lines (`req`), the key of each line position (`idx`), the keys, and the cores the
    read found in the released and unresolved sets by core key (`Walk`). -/
structure Got where
  lay : Lay
  relSeq : Array Nat
  unrSeq : Array Nat
  lb : ByteArray
  req : Array RowX
  idx : Array Nat
  keys : Array KeyQ
  walkR : Walk
  walkU : Walk

def concat (rs : Array Rd) : Array RowX × Array Nat :=
  rs.foldl (fun (a, b) r => (a ++ r.rows, b ++ r.seq)) (#[], #[])

/-- The batch of request `q` (bytes `bs`; `reqs` the admitted requests whose lines the batch keeps, which are `b`; `byp`
    the admitted bypasses; `lim` the HOLD-level payments and their holds masks; `pres` the feeds' presence) on the sets with heads `hr`, `hu`: each key read in both sets,
    then the id keys of the unresolved CAP rows of redone payments in the released set, then the layout.  None when a
    kept line has no store line. -/
def read (m : M) (hr hu : Head) (bs : ByteArray) (q : Frame.Req) (reqs : Array Run.Req) (b : Array Line)
    (byp lim : List (Nat × Nat)) (pres : Bool × Bool × Bool × Bool) : IO (Option Got) := do
  let fx := ReadB.feedsW bs q pres (ld64 (← IO.getRandomBytes 8) 0)
  let mut lb := ByteArray.emptyWithCapacity (lineW2 * b.size)
  let mut pidx : Array Nat := Array.emptyWithCapacity b.size
  let mut np := 0
  for x in reqs do
    if x.ra.flow.ruled && !x.ra.lines.isEmpty then
      let some pf := ReadB.payField x.ra.programId x.ra.paymentId | return none
      for ln in x.ra.lines do
        lb := ReadB.storeLine lb ln pf
        pidx := pidx.push np
      np := np + 1
  if pidx.size != b.size || lb.size != lineW2 * b.size then return none
  let req := (Array.range b.size).map fun i => RowX.ofChunk lb (lineW2 * i)
  let ks := keysOf m.ctx req
  let redo := redoW q.redo
  -- the keys a line of a redone payment has (exact or near): their released reads are not cut
  let mut rk : Array Bool := Array.replicate ks.keys.size false
  if !q.redo.isEmpty then
    for l in [0:req.size] do
      if req[l]!.payIn redo then rk := (rk.set! ks.idx[3 * l]! true).set! ks.idx[3 * l + 1]! true
  let wu ← IO.mkRef {}
  let wr ← IO.mkRef {}
  let mut ur : Array Rd := Array.emptyWithCapacity ks.keys.size
  let mut rr : Array Rd := Array.emptyWithCapacity ks.keys.size
  for j in [0:ks.keys.size] do
    let k := ks.keys[j]!
    let kd := k.kb[0]!
    ur := ur.push (← readKey m.ctx m.unr wu (kd == 1 || kd == 2) k)
    rr := rr.push (← readKey m.ctx m.rel wr (!rk[j]!) k)
  let (unrP, unrSeq) := concat ur
  let (k2, smap) := round2Keys m.ctx redo ks unrP
  for k in k2 do rr := rr.push (← readKey m.ctx m.rel wr false k)
  let (relP, relSeq) := concat rr
  let keys := ks.keys ++ k2
  let hit (r : Rd) (k : KeyQ) : Hit := ⟨0, 0, r.cnt, k.kb[0]!.toNat, r.rows.size⟩
  let hu1 := (ur.zip ks.keys).map fun (r, k) => hit r k
  let hr1 := (rr.zip keys).map fun (r, k) => hit r k
  let lay := assemble hr hu q.today byp lim fx [] redo req pidx ks.idx (fun y => smap.getD (y.keyBytes 2) keys.size)
    hu1 hr1 relP relSeq unrP unrSeq
  return some ⟨{ lay with src := b }, relSeq, unrSeq, lb, req, ks.idx, keys, ← wr.get, ← wu.get⟩

/-! ## Puts -/

/-- Lines `sel` of the store lines `lb` (their rows `req`) appended to set `s`, each linked to the newest row of its core before
    it: the tagged records in one write, then the tables (the positions of cores that had rows set before any insert can
    move them), then the summary (`sumAdd`, reading back from the file just written).  `walk` holds the cores the batch's
    read found; a core it did not find is looked up.  `idW k` the id table words of line `k`. -/
def putSide (ctx : KeyCtx) (s : Side) (lb : @& ByteArray) (req : @& Array RowX) (walk : Walk) (sel : Array Nat)
    (idW : Nat → UInt64 × UInt64) : IO Side := do
  -- taken apart first, so the ring and the tables are updated in place
  let ⟨f, ids, cores, sum, set⟩ := s
  let n0 := f.n
  let mut recs := ByteArray.emptyWithCapacity (VStore.recLen * sel.size)
  let mut seen : HashMap ByteArray Core := {}
  let mut order : Array ByteArray := #[]
  -- rows that make or keep a core long, for the summary: row number, place in its core, link, row
  let mut late : Array (Nat × Nat × Nat × RowX) := #[]
  for i in [0:sel.size] do
    let o := lineW2 * sel[i]!
    let row := req[sel[i]!]!
    let ck := coreKey row
    let seq := n0 + i
    let c ← match seen.get? ck with
      | some c => pure c
      | none => do
        order := order.push ck
        match walk.get? ck with
        | some fd => pure fd.core
        | none =>
          let w := words ctx ck set
          match ← newest f cores set row w with
          | some (t, pos, r) => pure (coreOf t pos r w)
          | none => pure ⟨0, 0, 0, none, w⟩
    let prev := if c.cnt == 0 then 0 else if c.cnt ≤ capN then c.top + 1 else c.capAt
    if CoreSum.longMin < c.cnt + 1 then late := late.push (seq, c.cnt + 1, prev, row)
    -- the record: the row, the link, the count, the flags and three zero bytes, appended in place
    let cnt := min (c.cnt + 1) 65535
    recs := lb.copySlice o recs recs.size RowsFile.rowW
    for j in [0:5] do recs := recs.push ((prev >>> (8 * j)) % 256).toUInt8
    recs := ((recs.push (cnt % 256).toUInt8).push (cnt / 256).toUInt8).push (if row.cap then 2 else 0)
    recs := ((recs.push 0).push 0).push 0
    seen := seen.insert ck { c with top := seq, cnt := c.cnt + 1, capAt := if c.cnt + 1 == capN then seq + 1 else c.capAt }
  let f ← VStore.appendMany f recs
  let mut cores := cores
  for ck in order do
    let c := seen.get! ck
    if let some pos := c.pos then cores := cores.set pos (Index.withSeq (cores.get pos) c.top)
  for ck in order do
    let c := seen.get! ck
    if c.pos.isNone then cores := cores.insert c.w.1 c.w.2 c.top
  let mut ks := Index.zeros (16 * sel.size)
  for i in [0:sel.size] do
    let (h1, h2) := idW sel[i]!
    ks := Index.wSet (Index.wSet ks (2 * i) h1) (2 * i + 1) h2
  let mut sum := sum
  let mut fr : FirstRows := {}
  for (seq, k, p, row) in late do
    let (s2, f2) ← sumAdd (get f set) sum fr seq k p row
    sum := s2
    fr := f2
  return ⟨f, ids.insertMany ks 8 sel.size n0, cores, sum, set⟩

/-- The batch's lines `fr` (released) and `fu` (unresolved) put; `keys`, `idx` as `read` gave them. -/
def put (m : M) (g : Got) (fr fu : Array Nat) : IO M := do
  let ⟨ctx, rel, unr⟩ := m
  let idW (u : Nat) (k : Nat) : UInt64 × UInt64 := wordsOf g.keys[g.idx[3 * k + 2]!]! u
  let rel ← putSide ctx rel g.lb g.req g.walkR fr (idW 0)
  let unr ← putSide ctx unr g.lb g.req g.walkU fu (idW 1)
  return ⟨ctx, rel, unr⟩

/-! ## Opening -/

/-- What a set's load builds as its records are checked: the two tables, the summary and its first rows read, or the
    first error. -/
abbrev LoadAcc := Index.Idx × Index.Idx × CoreSum.Sum × FirstRows × Option String

/-- Set `set` of shard `shard` from `path` under `k`: the file cut back to its good records, and the tables and the
    summary built from them as they are checked.  An error when a row links to a row that is not its core's newest, or
    when a record the summary reads back no longer holds. -/
def Side.load (ctx : KeyCtx) (path : String) (k : ByteArray) (shard set : Nat) : IO (Except String Side) := do
  let each (get : Nat → IO (Option ByteArray)) (x : LoadAcc) (blk : ByteArray) (i seq : Nat) : IO LoadAcc := do
    let (ids, cores, sum, fr, err) := x
    if err.isSome then return x
    let o := VStore.sealedLen * i
    let row := RowX.ofChunk blk o
    let (a, b) := words ctx (row.keyBytes 2) set
    let ids := ids.insert a b seq
    let w := words ctx (coreKey row) set
    let rec_ := blk.extract o (o + VStore.recLen)
    let p := RowsFile.prevCoreAt rec_ 0
    let cnt := RowsFile.countAt rec_ 0
    let rd (q : Nat) : IO ByteArray := do
      let some r ← get q | fault s!"set {set} row {q}"
      pure r
    -- `sum` moves into `sumAdd`, so its tables are updated in place
    let (sum, fr, bad) ← match ← (sumAdd rd sum fr seq cnt p row).toBaseIO with
      | .ok (s2, f2) => pure (s2, f2, none)
      | .error e => pure (⟨0, 0, 0, #[], .empty, .empty, 0, 0⟩, {}, some (toString e))
    if bad.isSome then return (ids, cores, sum, fr, bad)
    -- the first rows read stay for the next rows, a bounded number
    let fr := if fr.size > 4096 then {} else fr
    if p == 0 then return (ids, cores.insert w.1 w.2 seq, sum, fr, none)
    -- the core's newest row so far is the row linked to, or (past the cap) the row that links where this one does
    let cs := cands cores w
    let hit ← if cnt ≤ capN + 1 then pure (cs.find? (·.1 == p - 1))
      else cs.findM? fun (q, _) => do
        let some r ← get q | return false
        pure (sameCore row (RowX.ofChunk r 0) && RowsFile.prevCoreAt r 0 == p)
    match hit with
    | some (_, pos) => return (ids, cores.set pos (Index.withSeq (cores.get pos) seq), sum, fr, none)
    | none => return (ids, cores, sum, fr, some s!"row {seq} of set {set} follows a row that is not the newest of its core")
  match ← VStore.openAt path k shard set (Index.Idx.new 10, Index.Idx.new 10, ← CoreSum.Sum.new, {}, none) each with
  | .error e => return .error e
  | .ok (_, _, _, _, _, some e) => return .error e
  | .ok (f, ids, cores, sum, _, none) => return .ok ⟨f, ids, cores, sum, set⟩

/-- Both sets of shard `shard` in `dir` under `k` (the tables keyed by a key derived from `k`). -/
def load (dir : String) (k : ByteArray) (shard : Nat) : IO (Except String M) := do
  let ctx := KeyCtx.ofSecret ((hD "VINDEX" [k]).extract 0 32)
  let .ok rel ← Side.load ctx s!"{dir}/vrows_rel" k shard 0 | return .error "released set"
  let .ok unr ← Side.load ctx s!"{dir}/vrows_unr" k shard 1 | return .error "unresolved set"
  return .ok ⟨ctx, rel, unr⟩

def close (m : M) : IO Unit := do VStore.close m.rel.f; VStore.close m.unr.f

end BlindLedger.Gate.Engine3.VMirror
