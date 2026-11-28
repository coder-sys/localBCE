import BlindLedger.Gate.Engine3.ReadB
import BlindLedger.Gate.Engine3.Index
import BlindLedger.Gate.Engine3.RowsFile
import BlindLedger.Gate.Engine3.CoreSum

/-! # History on rows files (gate path design sections 3.1 to 3.3)

Each of the two row sets (released, unresolved) is a rows file plus two RAM tables of `Index`:

* `ids`: one slot per row under its id key, holding the row's number.
* `cores`: one slot per core, holding the number of the core's newest row; the record of a row names the previous row of
  its core (`prevCore`, plus one; 0 none) and the core's row count, so a core's rows are a chain through the file.

A core is the member and the date and procedure of a fee-for-service row, and the member and the month of a CAP row.  The
exact key and the near key of a row are each a filter of its core: every row with the same exact (near) key has the same
core.  A key's entry is its core's chain filtered by the key's equality (`exactEq`, `nearEq`), in ascending row number; its
count is exact and the decider reads its first `capN` rows, as the entries of the chunk store give them.  An id key's entry
is the rows the id table's hints name that have the id.  A hint only suggests: every row is read from the file and compared.

A batch is read and put in one pass.  `read` digests each distinct core and each distinct id of the batch once, probes the
tables of both sets for them eight keys ahead, reads the rows the hints name, and keeps in the batch's plan what the put
needs (each core's newest row, table place, count and link).  `put` writes the records from the plan and inserts at once:
no second probe, no second digest.  Exact and near keys are not digested: only ids and cores are stored under a digest.

The tables hold nothing the rows files do not; `Side.load` builds them again from the file.  A core of more than 32 rows is
also summarised (`CoreSum`): each of its keys has an entry with its first row, its count and its first row not identical
to the first, which is all the decider reads of a key where no line of the batch can be its own payment's released row
(released side) or where the key is a fee-for-service one (unresolved side) (`Flat.DecideCut.decideRows_cut`); such a
key reads one or two rows, not its chain.  Rows are appended to the file in one write per batch, after the log has the
batch.  Nothing in here is on the trusted path of a decision: a wrong hint costs a
read, and the rows read are compared whole.  Synthetic, nonpayment, non-PHI, activation=false. -/

namespace BlindLedger.Gate.Engine3.Hist

open BlindLedger.Gate BlindLedger.Gate.Rules BlindLedger.Gate.Flat BlindLedger.Gate.Flat.Rows
open Std (HashMap)

/-- Records of a rows file kept in RAM: `cacheSlots` of them, row `s` in slot `s % cacheSlots`, `tag` holding each slot's row
    number plus one (0 empty).  A row's bytes never change while its set is open (rows are only appended; a reopen loads a
    new set with a new cache), so a slot holds what the file holds.  Filled with every row put or loaded and every row a read
    fetched from the file.  The records are kept in pages of `pageRecs`, each allocated at its first write, so a cache
    holds only the pages its rows were written to. -/
structure Cache where
  tag : ByteArray
  pages : Array ByteArray

/-- Slots of a cache (16 MB of records). -/
def cacheSlots : Nat := 65536

/-- Records of a page (32 KB). -/
def pageRecs : Nat := 128

/-- `n` zero bytes in a buffer of exactly that capacity (`Index.zeros` passes through an array of `n` boxed bytes). -/
def zeroBytes (n : Nat) : ByteArray := Id.run do
  let mut b := ByteArray.emptyWithCapacity n
  for _ in [0:n] do b := b.push 0
  return b

/-- An empty cache of `m` slots (not inlined: with `m` known its tag table would be built once, at the program's start, and
    shared by every cache). -/
@[noinline] def Cache.new (m : Nat) : IO (IO.Ref Cache) :=
  IO.mkRef ⟨zeroBytes (8 * m), Array.replicate (m / pageRecs) .empty⟩

/-- Row `s` when its slot holds it (none from a cache taken out of its cell by `putSide`). -/
@[inline] def Cache.get? (c : @& Cache) (s : Nat) : Option ByteArray :=
  let i := s % cacheSlots
  if c.tag.size == 8 * cacheSlots && Index.wAt c.tag i == (s + 1).toUInt64 then
    let o := RowsFile.recW * (i % pageRecs)
    some (c.pages[i / pageRecs]!.extract o (o + RowsFile.recW))
  else none

/-- Rows `s0 .. s0 + cnt - 1` kept, from `buf` (whole records from its start). -/
def Cache.putRun (c : Cache) (s0 : Nat) (buf : @& ByteArray) (cnt : Nat) : Cache := Id.run do
  let ⟨tag, pages⟩ := c
  let mut tag := tag
  let mut pages := pages
  for j in [0:cnt] do
    let i := (s0 + j) % cacheSlots
    tag := Index.wSet tag i (s0 + j + 1).toUInt64
    pages := pages.modify (i / pageRecs) fun pg =>
      let pg := if pg.isEmpty then zeroBytes (RowsFile.recW * pageRecs) else pg
      buf.copySlice (RowsFile.recW * j) pg (RowsFile.recW * (i % pageRecs)) RowsFile.recW
  return ⟨tag, pages⟩

/-- One row set.  `rd`: further descriptors of the rows file, for reading many rows at once (`fetchEach`). -/
structure Side where
  f : RowsFile.Rows
  ids : Index.Idx
  cores : Index.Idx
  rd : Array UInt32
  /-- The long-core summary of the set (`CoreSum`). -/
  sum : CoreSum.Sum
  /-- Rows of the file in RAM (`Cache`), read and written on the thread that owns the set, never by a task.  A cell shared
      across threads makes every value set in it shared, so that an update copies it: the reads of a batch update it a few
      times only, and each put moves the cache to a new cell. -/
  mem : IO.Ref Cache

/-- Closes the rows file and its further descriptors (an open one keeps a rename of the file from succeeding). -/
def Side.close (s : Side) : IO Unit := do
  s.f.close
  for fd in s.rd do
    let _ ← Io.pgClose fd

structure Hist where
  ctx : KeyCtx
  rel : Side
  unr : Side
  hr : Head
  hu : Head

/-! ## Cores and hints -/

/-- The core of a row, as bytes to hash. -/
def coreBytes (r : RowX) : ByteArray :=
  let b := ByteArray.emptyWithCapacity 72
  let mem := put64 (put64 (put64 (put64 (b.push (if r.cap then 5 else 6)) r.m3) r.m2) r.m1) r.m0
  if r.cap then put32u mem (r.date / 100)
  else put64 (put64 (put64 (put64 (put32u mem r.date) r.q0) r.q1) r.q2) r.q3

@[inline] def coreEq (a b : RowX) : Bool :=
  a.cap == b.cap && a.memEq b && (if a.cap then a.date / 100 == b.date / 100 else a.date == b.date && a.procEq b)

/-- The table words of a key's bytes in a set (`keyQ` digests a key longer than `shortMax` bytes the long way). -/
def hashOf (ctx : KeyCtx) (kb : ByteArray) (u : Bool) : UInt64 × UInt64 :=
  let q := keyQ ctx default kb
  if u then (q.dh1, q.kh1) else (q.dh0, q.kh0)

/-- The (row number, table position) pairs a probe's output names, a row once. -/
def hintsFrom (out : ByteArray) : Array (Nat × Nat) := Id.run do
  let c := (Index.wAt out 0).toNat
  let mut r : Array (Nat × Nat) := #[]
  for j in [0:c] do
    let s := Index.seqOf (Index.wAt out (2 + 2 * j))
    if !r.any (·.1 == s) then r := r.push (s, (Index.wAt out (1 + 2 * j)).toNat)
  return r

/-- The (row number, table position) pairs the table's hints for `(h1, h2)` name, a row once. -/
def hintsOf (ix : Index.Idx) (h1 h2 : UInt64) : Array (Nat × Nat) :=
  hintsFrom (Index.probe ix h1 h2 (Index.zeros (8 * Index.probeWords)) 0)

/-- The table words of keys `q` in set `u`: key `i` at words `2 i` and `2 i + 1`. -/
def wordsOf (q : Array KeyQ) (u : Bool) : ByteArray := Id.run do
  let mut ks := Index.zeros (16 * q.size)
  for i in [0:q.size] do
    let k := q[i]!
    ks := Index.wSet (Index.wSet ks (2 * i) (if u then k.dh1 else k.dh0)) (2 * i + 1) (if u then k.kh1 else k.kh0)
  return ks

/-- Each key of `q` that has hints in `ix`, with its hints; the keys are probed eight ahead. -/
def probeHints (ix : Index.Idx) (q : Array KeyQ) (u : Bool) : Array (Nat × Array (Nat × Nat)) :=
  Index.probeEach ix (wordsOf q u) (fun acc i out => if Index.wAt out 0 == 0 then acc else acc.push (i, hintsFrom out)) 8
    q.size #[]

/-- Records `seqs` of `f`, read at once: each of the further descriptors `rd` reads every k-th, so the reads wait on the disk
    together (a read of a row not in the system's cache takes far longer than the work on it).  The tasks are handed the
    file and the descriptors only: a set they reached would be shared across threads, and its tables then copied at every
    update. -/
def fetchEach (f : RowsFile.Rows) (rd : Array UInt32) (seqs : Array Nat) : IO (Array ByteArray) := do
  let k := rd.size
  if k == 0 || seqs.size < 4 then return (← seqs.mapM f.fetch)
  let ts ← (Array.range k).mapM fun w => IO.asTask do
    let f := { f with fd := rd[w]! }
    let mut out : Array ByteArray := Array.emptyWithCapacity (seqs.size / k + 1)
    for j in [0:(seqs.size + k - 1 - w) / k] do
      out := out.push (← f.fetch seqs[w + k * j]!)
    return out
  let mut res : Array ByteArray := Array.replicate seqs.size ByteArray.empty
  for w in [0:k] do
    match ts[w]!.get with
    | .ok out => for j in [0:out.size] do res := res.set! (w + k * j) out[j]!
    | .error e => throw e
  return res

/-- Records `seqs` (ascending, distinct) of `f`.  Rows close together are read with one call (a run of at most 2048 records
    with gaps of at most 16), and the runs are read by the further descriptors `rd` at once. -/
def fetchRuns (f : RowsFile.Rows) (rd : Array UInt32) (seqs : Array Nat) : IO (Array ByteArray) := do
  let mut runs : Array (Nat × Nat) := #[]
  let mut a := 0
  while a < seqs.size do
    let mut b := a + 1
    while b < seqs.size && seqs[b]! - seqs[b - 1]! ≤ 16 && seqs[b]! - seqs[a]! < 2048 do b := b + 1
    runs := runs.push (a, b)
    a := b
  let read (f : RowsFile.Rows) (r : Nat × Nat) : IO (Array ByteArray) := do
    let s0 := seqs[r.1]!
    let buf ← f.fetch s0 (seqs[r.2 - 1]! - s0 + 1)
    return (Array.range (r.2 - r.1)).map fun i =>
      let o := RowsFile.recW * (seqs[r.1 + i]! - s0)
      buf.extract o (o + RowsFile.recW)
  let k := rd.size
  if k == 0 || runs.size < 4 then
    let mut out : Array ByteArray := Array.emptyWithCapacity seqs.size
    for r in runs do out := out ++ (← read f r)
    return out
  let ts ← (Array.range k).mapM fun w => IO.asTask do
    let f := { f with fd := rd[w]! }
    let mut out : Array (Array ByteArray) := #[]
    for j in [0:(runs.size + k - 1 - w) / k] do out := out.push (← read f runs[w + k * j]!)
    return out
  let mut got : Array (Array (Array ByteArray)) := #[]
  for t in ts do
    match t.get with
    | .ok o => got := got.push o
    | .error e => throw e
  let mut out : Array ByteArray := Array.emptyWithCapacity seqs.size
  for i in [0:runs.size] do out := out ++ got[i % k]![i / k]!
  return out

/-- Records `seqs` of a set (file `f`, further descriptors `rd`, cache `mem`): from the cache where it holds them, the rest
    from the file at once (`fetchRuns` when `seqs` ascend and are distinct, else `fetchEach`) and then kept in the cache.  A
    row past the file's end is not looked up in the cache, so its read fails as a file read does. -/
def recsOf (f : RowsFile.Rows) (rd : Array UInt32) (mem : IO.Ref Cache) (seqs : Array Nat) (runs : Bool) :
    IO (Array ByteArray) := do
  let c ← mem.get
  let mut out : Array ByteArray := Array.emptyWithCapacity seqs.size
  let mut miss : Array Nat := #[]
  for i in [0:seqs.size] do
    let s := seqs[i]!
    match if s < f.n then c.get? s else none with
    | some r => out := out.push r
    | none =>
      out := out.push .empty
      miss := miss.push i
  if miss.isEmpty then return out
  let ms := miss.map (seqs[·]!)
  let got ← if runs then fetchRuns f rd ms else fetchEach f rd ms
  mem.modify fun c => (Array.range ms.size).foldl (fun c j => c.putRun ms[j]! got[j]! 1) c
  for j in [0:miss.size] do out := out.set! miss[j]! got[j]!
  return out

/-- Record `s` of a set (`recsOf`). -/
def recOf (f : RowsFile.Rows) (mem : IO.Ref Cache) (s : Nat) : IO ByteArray := do
  if s < f.n then
    if let some r := (← mem.get).get? s then return r
  let r ← f.fetch s
  mem.modify (·.putRun s r 1)
  return r

/-- The distinct values of `xs`, ascending (a bitmap over their range). -/
def distinctSorted (xs : Array Nat) : Array Nat := Id.run do
  if xs.isEmpty then return #[]
  let lo := xs.foldl min xs[0]!
  let hi := xs.foldl max xs[0]!
  let mut bm := Index.zeros ((hi - lo) / 8 + 1)
  for x in xs do
    let d := x - lo
    bm := bm.set! (d >>> 3) (bm[d >>> 3]! ||| ((1 : UInt8) <<< (d &&& 7).toUInt8))
  let mut out : Array Nat := Array.emptyWithCapacity xs.size
  for b in [0:bm.size] do
    let v := bm[b]!
    if v != 0 then
      for i in [0:8] do
        if (v >>> i.toUInt8) &&& 1 == 1 then out := out.push (lo + 8 * b + i)
  return out

/-- The newest row of each core of `gq` in set `st`: its number, its table position and its record. -/
def findCores (st : Side) (gq : Array KeyQ) (u : Bool) : IO (Array (Option (Nat × Nat × ByteArray))) := do
  let mut out : Array (Option (Nat × Nat × ByteArray)) := Array.replicate gq.size none
  if st.f.n == 0 then return out
  let phs := probeHints st.cores gq u
  -- the first hint of every core is read at once; a core whose first hint is not it reads the others in turn
  let first ← recsOf st.f st.rd st.mem (phs.map fun (_, hs) => hs[0]!.1) false
  for j in [0:phs.size] do
    let (g, hs) := phs[j]!
    if coreEq gq[g]!.row (RowX.ofChunk first[j]! 0) then out := out.set! g (some (hs[0]!.1, hs[0]!.2, first[j]!))
    else
      for (s, pos) in hs.extract 1 hs.size do
        let rc ← recOf st.f st.mem s
        if coreEq gq[g]!.row (RowX.ofChunk rc 0) then
          out := out.set! g (some (s, pos, rc))
          break
  return out

/-- The rows of set `st` with the id of each key of `iq`, ascending by number. -/
def findIds (st : Side) (iq : Array KeyQ) (u : Bool) : IO (Array (Array (Nat × RowX))) := do
  let mut out : Array (Array (Nat × RowX)) := Array.replicate iq.size #[]
  if st.f.n == 0 then return out
  let phs := probeHints st.ids iq u
  let recs ← recsOf st.f st.rd st.mem (phs.foldl (fun a (_, hs) => hs.foldl (fun a (s, _) => a.push s) a) #[]) false
  let mut o := 0
  for (i, hs) in phs do
    let mut got : Array (Nat × RowX) := #[]
    for (s, _) in hs do
      let y := RowX.ofChunk recs[o]! 0
      o := o + 1
      if iq[i]!.row.idEq y then got := got.push (s, y)
    out := out.set! i (got.qsort (·.1 < ·.1))
  return out

/-! ## Reads -/

/-- The first rows of a core, ascending, from the core's newest row `s0` (record `rc0`), by walking its chain, and the
    records the walk read from the file rather than the cache (row number, bytes; `rs` with them added).  A core with more
    than `capN` rows is frozen: its rows past the `capN`-th link back to the `capN`-th, so the walk reads at most `capN + 1`
    records and drops the newest of them, which is past the cap. -/
def coreChain (st : Side) (s0 : Nat) (rc0 : ByteArray) (rs : Array (Nat × ByteArray)) :
    IO (Array (Nat × RowX) × Array (Nat × ByteArray)) := do
  let cnt := RowsFile.countAt rc0 0
  let c ← st.mem.get
  let mut out : Array (Nat × RowX) := #[]
  let mut rs := rs
  let mut s := s0
  let mut rc := rc0
  for _ in [0:st.f.n] do
    out := out.push (s, RowX.ofChunk rc 0)
    let p := RowsFile.prevCoreAt rc 0
    if p == 0 then break
    s := p - 1
    match if s < st.f.n then c.get? s else none with
    | some r => rc := r
    | none =>
      rc ← st.f.fetch s
      rs := rs.push (s, rc)
  return ((if capN < cnt then out.extract 1 out.size else out).reverse, rs)

/-! ## The batch's cores, ids and keys

Each distinct core and each distinct id of a batch is digested once, when first met.  The tables that find repeats hash the
words of the rows, seeded afresh for each batch so no input can crowd them, and confirm a hit by comparing the rows. -/

/-- `w` folded into `h`. -/
@[inline] def fw (h w : UInt64) : UInt64 :=
  let x := (h ^^^ w) * 0x9E3779B97F4A7C15
  x ^^^ (x >>> 32)

def idHashR (seed : UInt64) (r : RowX) : UInt64 :=
  mix64 (fw (fw (fw (fw (fw (fw (fw seed r.i0) r.i1) r.i2) r.i3) r.i4) r.i5) r.i6)

def coreHashR (seed : UInt64) (r : RowX) : UInt64 :=
  let h := fw seed (if r.cap then 5 else 6)
  let h := fw (fw (fw (fw h r.m0) r.m1) r.m2) r.m3
  mix64 (if r.cap then fw h (r.date / 100).toUInt64
         else fw (fw (fw (fw (fw h r.date.toUInt64) r.q0) r.q1) r.q2) r.q3)

def exactHashR (seed : UInt64) (r : RowX) : UInt64 :=
  let h := fw seed (if r.cap then 3 else 1)
  let h := fw (fw (fw (fw h r.m0) r.m1) r.m2) r.m3
  let h := fw (fw (fw h r.a0) r.a1) r.a2
  let h := fw (fw (fw (fw (fw h r.date.toUInt64) r.q0) r.q1) r.q2) r.q3
  mix64 (fw (fw h r.units.toUInt64) r.cents)

def nearHashR (seed : UInt64) (r : RowX) : UInt64 :=
  let h := fw seed (if r.cap then 0 else 2)
  let h := fw (fw (fw (fw h r.m0) r.m1) r.m2) r.m3
  mix64 (if r.cap then fw h (r.date / 100).toUInt64
         else fw (fw (fw (fw (fw (fw (fw (fw h r.r0) r.r1) r.r2) r.date.toUInt64) r.q0) r.q1) r.q2) r.q3)

/-- First rows of entries already read, by row number (one map per put or per block of a load). -/
abbrev FirstRows := HashMap Nat RowX

/-- Row `q` (`y`) counted in the entry of its exact key and in that of its near key (`CoreSum`): a new entry when its key
    has none; else, unless the entry is mixed, compared with the entry's first row (read by `get`, or from `fr`): the same
    key counts it, another key marks the entry mixed.  False when a table cannot take it or `q` is past the summary's cap. -/
def keyAdd (get : Nat → IO ByteArray) (sm : CoreSum.Sum) (fr : FirstRows) (q : Nat) (y : RowX) :
    IO (CoreSum.Sum × FirstRows × Bool) := do
  if q ≥ sm.cap then return (sm, fr, false)
  let mut sm := sm
  let mut fr := fr
  for near in [false, true] do
    let h := if near then nearHashR sm.seed y else exactHashR sm.seed y
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
            let x := RowX.ofChunk (← get e.first) 0
            fr := fr.insert e.first x
            pure x
        if (if near then x.nearEq y else x.exactEq y) then sm := sm.bump near i (if x.same y then none else some q) false
        else sm := sm.bump near i none true
  return (sm, fr, true)

/-- Row `seq` (the `k`-th of its core, `p` the row plus one before it in the core's chain, `row` its contents) taken into the
    summary.  Nothing to do while the core has `longMin` rows or fewer.  The row that makes it longer summarises the core:
    its earlier rows are read (`get`) and counted in ascending order, then the row.  A later row follows the flag of
    the row before it, and is counted while it is within the first `capN`.  When a row cannot be counted the flag stays off
    and readers walk the core's chain. -/
def sumAdd (get : Nat → IO ByteArray) (sm : CoreSum.Sum) (fr : FirstRows) (seq k p : Nat) (row : RowX) :
    IO (CoreSum.Sum × FirstRows) := do
  if k ≤ CoreSum.longMin || p == 0 then return (sm, fr)
  if k == CoreSum.longMin + 1 then
    let mut prior : Array (Nat × RowX) := #[]
    let mut s := p - 1
    for _ in [0:CoreSum.longMin] do
      let rc ← get s
      prior := prior.push (s, RowX.ofChunk rc 0)
      let pp := RowsFile.prevCoreAt rc 0
      if pp == 0 then break
      s := pp - 1
    if prior.size != CoreSum.longMin then return (sm, fr)
    let mut sm := sm
    let mut fr := fr
    for (q, y) in prior.reverse.push (seq, row) do
      let (s2, f2, ok) ← keyAdd get sm fr q y
      sm := s2
      fr := f2
      if !ok then return (sm, fr)
    return (sm.setFlag seq, fr)
  if !sm.flagOf (p - 1) then return (sm, fr)
  if capN < k then return (sm.setFlag seq, fr)
  let (s2, f2, ok) ← keyAdd get sm fr seq row
  return (if ok then s2.setFlag seq else s2, f2)

/-- Where `h` falls in the open table `t` (entry plus one, 0 empty; a power of two, at most half full): the entry whose `eq`
    holds (`.inl`), or the empty slot it would take (`.inr`). -/
@[inline] def tabFind (t : @& Array Nat) (h : UInt64) (eq : Nat → Bool) : Nat ⊕ Nat := Id.run do
  let m := t.size - 1
  let mut i := (h &&& m.toUInt64).toNat
  for _ in [0:t.size] do
    let s := t[i]!
    if s == 0 then return .inr i
    if eq (s - 1) then return .inl (s - 1)
    i := (i + 1) &&& m
  return .inr t.size

/-- The table of `s` slots (a power of two) over the ids `iq`. -/
def idTable (seed : UInt64) (iq : Array KeyQ) (s : Nat) : Array Nat := Id.run do
  let mut t := Array.replicate s 0
  for j in [0:iq.size] do
    let mut p := (idHashR seed iq[j]!.row &&& (s - 1).toUInt64).toNat
    while t[p]! != 0 do p := (p + 1) &&& (s - 1)
    t := t.set! p (j + 1)
  return t

/-- The key of `r` with the digests of its bytes `kb` (the bytes themselves are not kept). -/
def hqOf (ctx : KeyCtx) (r : RowX) (kb : ByteArray) : KeyQ :=
  { keyQ ctx r kb with kb := ByteArray.empty }

/-- The batch's distinct cores `gq` and distinct ids `iq` (each with the first row that has it and its digests), the core and
    the id of each line, and the id table (for the second round). -/
structure Grp where
  gq : Array KeyQ
  iq : Array KeyQ
  lg : Array Nat
  li : Array Nat
  it : Array Nat

def grpsOf (ctx : KeyCtx) (seed : UInt64) (req : Array RowX) : Grp := Id.run do
  let n := req.size
  let mut gq : Array KeyQ := Array.emptyWithCapacity n
  let mut iq : Array KeyQ := Array.emptyWithCapacity n
  let mut lg : Array Nat := Array.emptyWithCapacity n
  let mut li : Array Nat := Array.emptyWithCapacity n
  let mut ct : Array Nat := Array.replicate (ReadB.tabSize n) 0
  let mut it : Array Nat := Array.replicate (ReadB.tabSize n) 0
  for r in req do
    match tabFind ct (coreHashR seed r) (fun g => coreEq r gq[g]!.row) with
    | .inl g => lg := lg.push g
    | .inr s =>
      ct := ct.set! s (gq.size + 1)
      lg := lg.push gq.size
      gq := gq.push (hqOf ctx r (coreBytes r))
    match tabFind it (idHashR seed r) (fun i => r.idEq iq[i]!.row) with
    | .inl i => li := li.push i
    | .inr s =>
      it := it.set! s (iq.size + 1)
      li := li.push iq.size
      iq := iq.push (hqOf ctx r (r.keyBytes 2))
  return ⟨gq, iq, lg, li, it⟩

/-- The batch's distinct keys in first-occurrence order (exact, near, id of each line), as the decider's layout numbers them:
    a row that has the key, its kind (`keyBytes`' first byte), and its core (exact, near) or its id (`aux`); `idx` the key
    of each line position (`3 * i + j`); `idNum` the number plus one of each id's key. -/
structure Kset where
  krow : Array RowX
  kind : ByteArray
  aux : Array Nat
  idx : Array Nat
  idNum : Array Nat

def ksetOf (seed : UInt64) (req : Array RowX) (g : Grp) : Kset := Id.run do
  let n := req.size
  let mut krow : Array RowX := Array.emptyWithCapacity (3 * n)
  let mut kind := ByteArray.emptyWithCapacity (3 * n)
  let mut aux : Array Nat := Array.emptyWithCapacity (3 * n)
  let mut idx : Array Nat := Array.emptyWithCapacity (3 * n)
  let mut kt : Array Nat := Array.replicate (ReadB.tabSize (2 * n)) 0
  let mut idNum : Array Nat := Array.replicate g.iq.size 0
  for l in [0:n] do
    let r := req[l]!
    let ke : UInt8 := if r.cap then 3 else 1
    match tabFind kt (exactHashR seed r) (fun j => kind[j]! == ke && r.exactEq krow[j]!) with
    | .inl j => idx := idx.push j
    | .inr s =>
      kt := kt.set! s (krow.size + 1)
      idx := idx.push krow.size
      krow := krow.push r
      kind := kind.push ke
      aux := aux.push g.lg[l]!
    let kn : UInt8 := if r.cap then 0 else 2
    match tabFind kt (nearHashR seed r) (fun j => kind[j]! == kn && r.nearEq krow[j]!) with
    | .inl j => idx := idx.push j
    | .inr s =>
      kt := kt.set! s (krow.size + 1)
      idx := idx.push krow.size
      krow := krow.push r
      kind := kind.push kn
      aux := aux.push g.lg[l]!
    let i := g.li[l]!
    if idNum[i]! == 0 then
      idNum := idNum.set! i (krow.size + 1)
      krow := krow.push r
      kind := kind.push 4
      aux := aux.push i
    idx := idx.push (idNum[i]! - 1)
  return ⟨krow, kind, aux, idx, idNum⟩

/-- The plan the put needs: `[nI, G, n]`, then per line `[id, core]` (indexes into the id and core digests), then per core
    and per set (released, unresolved) `[place + 1 (0: a new core), newest row, count, link]`. -/
def planOf (nI n : Nat) (lg li : Array Nat) (fr fu : Array (Option (Nat × Nat × ByteArray))) : Array Nat := Id.run do
  let gn := lg.foldl (fun m g => max m (g + 1)) 0
  let mut pl : Array Nat := Array.emptyWithCapacity (3 + 2 * n + 8 * gn)
  pl := (pl.push nI).push gn |>.push n
  for l in [0:n] do
    pl := (pl.push li[l]!).push lg[l]!
  for g in [0:gn] do
    for fs in [fr, fu] do
      match fs[g]! with
      | none => pl := (((pl.push 0).push 0).push 0).push 0
      | some (s, pos, rc) =>
        pl := (((pl.push (pos + 1)).push s).push (RowsFile.countAt rc 0)).push (RowsFile.prevCoreAt rc 0)
  return pl

/-- A set's reads: the decider's hits for the batch's keys, the rows it reads and their numbers, and the cores found.  `rk`:
    the keys a line of a redone payment has (exact or near).  A key of a summarised core reads from its entry what the
    decider uses (`Flat.DecideCut.decideRows_cut`): on the released side, when no line of a redone payment has it, its
    first row; on the unresolved side, when it is a fee-for-service key, its first row and its first row not identical to
    the first.  Its count is the entry's.  A released exact key of more than one row reads its chain instead, since an
    exact repeat is answered against all of its rows (`answeringB`).  Every other key reads its core's chain, filtered
    by the key. -/
def readSet (st : Side) (u : Bool) (gq iq : Array KeyQ) (ks : Kset) (rk : Array Bool) :
    IO (Array Hit × Array RowX × Array Nat × Array (Option (Nat × Nat × ByteArray))) := do
  let found ← findCores st gq u
  let ids ← findIds st iq u
  let nk := ks.krow.size
  -- per key: 0 no rows, 1 the chain, 2 the entry `ents[j]`; the entries' rows are read at once
  let mut via : ByteArray := Index.zeros nk
  let mut ents : Array CoreSum.Ent := Array.replicate nk default
  let mut walk : Array Bool := Array.replicate gq.size false
  let mut want : Array Nat := #[]
  for j in [0:nk] do
    let kd := ks.kind[j]!
    if kd != 4 then
      let g := ks.aux[j]!
      if let some (s0, _, _) := found[g]! then
        if st.sum.flagOf s0 && (if u then kd == 1 || kd == 2 else !rk[j]!) then
          let near := kd == 0 || kd == 2
          let row := ks.krow[j]!
          match st.sum.find near (if near then nearHashR st.sum.seed row else exactHashR st.sum.seed row) with
          | none => pure ()
          | some (_, e) =>
            if e.mixed || (!u && (kd == 1 || kd == 3) && 1 < e.count) then
              via := via.set! j 1
              walk := walk.set! g true
            else
              via := via.set! j 2
              ents := ents.set! j e
              want := want.push e.first
              if u then if let some d := e.diff then want := want.push d
        else
          via := via.set! j 1
          walk := walk.set! g true
  let mut chains : Array (Array (Nat × RowX)) := Array.replicate gq.size #[]
  let mut rs : Array (Nat × ByteArray) := #[]
  for g in [0:gq.size] do
    if walk[g]! then
      if let some (s0, _, rc0) := found[g]! then
        let (ch, r2) ← coreChain st s0 rc0 rs
        chains := chains.set! g ch
        rs := r2
  unless rs.isEmpty do st.mem.modify fun c => rs.foldl (fun c (s, r) => c.putRun s r 1) c
  let useq := distinctSorted want
  let urows := (← recsOf st.f st.rd st.mem useq true).map (RowX.ofChunk · 0)
  let mut pos : HashMap Nat Nat := {}
  for i in [0:useq.size] do pos := pos.insert useq[i]! i
  let mut hits : Array Hit := Array.emptyWithCapacity nk
  let mut rows : Array RowX := #[]
  let mut seq : Array Nat := #[]
  for j in [0:nk] do
    let kd := ks.kind[j]!
    if kd == 4 then
      let r := ids[ks.aux[j]!]!
      hits := hits.push ⟨0, 0, r.size, 4, min r.size capN⟩
      for (s, y) in r.extract 0 capN do
        rows := rows.push y
        seq := seq.push s
    else
      -- the cap is per core: a core over `capN` rows reads as that count for each of its keys
      let cc := match found[ks.aux[j]!]! with
        | some (_, _, rc0) => RowsFile.countAt rc0 0
        | none => 0
      let row := ks.krow[j]!
      let ex := kd == 1 || kd == 3
      let mut n := 0
      let mut m := 0
      if via[j]! == 2 then
        -- an entry whose first row has another key shares its digest word only: the key has no rows
        let e := ents[j]!
        let y := urows[pos[e.first]!]!
        if (if ex then row.exactEq y else row.nearEq y) then
          n := e.count
          m := 1
          rows := rows.push y
          seq := seq.push e.first
          if u then
            if let some d := e.diff then
              m := 2
              rows := rows.push urows[pos[d]!]!
              seq := seq.push d
      else if via[j]! == 1 then
        for (s, y) in chains[ks.aux[j]!]! do
          if (if ex then row.exactEq y else row.nearEq y) then
            n := n + 1
            if n ≤ capN then
              rows := rows.push y
              seq := seq.push s
        m := min n capN
      hits := hits.push ⟨0, 0, if capN < cc then cc else n, kd.toNat, m⟩
  return (hits, rows, seq, found)

/-- The decider's layout of a batch and the place of every posting row it reads; for the puts, the batch's store lines
    (`lb`, line `i` at `lineW2 * i`), the plan (`planOf`) and the digests it indexes (the ids, then the cores). -/
structure Got where
  lay : Lay
  relSeq : Array Nat
  unrSeq : Array Nat
  lb : ByteArray
  idx : Array Nat
  keys : Array KeyQ

/-- `ReadB.read` on the rows files: same arguments, same layout.  None when a kept line has no store line.  Reads that fail
    to complete raise an IO error (the batch is not answered). -/
def read (h : Hist) (bs : ByteArray) (q : Frame.Req) (reqs : Array Run.Req) (b : Array Line) (byp lim : List (Nat × Nat))
    (pres : Bool × Bool × Bool × Bool) (tk : Nat → Nat → IO Nat) : IO (Option Got) := do
  let t0 ← IO.monoNanosNow
  let seed := ld64 (← IO.getRandomBytes 8) 0
  let fx ← evalNow (ReadB.feedsW bs q pres seed)
  let t0 ← tk 17 t0
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
  let req ← evalNow ((Array.range b.size).map fun i => RowX.ofChunk lb (lineW2 * i))
  let t0 ← tk 20 t0
  let g ← evalNow (grpsOf h.ctx seed req)
  let ks ← evalNow (ksetOf seed req g)
  let t1 ← tk 21 t0
  let nk := ks.krow.size
  let redo := redoW q.redo
  let mut rk : Array Bool := Array.replicate nk false
  if !q.redo.isEmpty then
    for l in [0:req.size] do
      if req[l]!.payIn redo then rk := (rk.set! ks.idx[3 * l]! true).set! ks.idx[3 * l + 1]! true
  let (hu1, unrP, unrSeq, fu) ← readSet h.unr true g.gq g.iq ks rk
  let (hr0, relP0, relSeq0, fr) ← readSet h.rel false g.gq g.iq ks rk
  -- round 2: the id key of each unresolved CAP row of a redone payment that is not yet a key, once
  let nI := g.iq.size
  let mut iq := g.iq
  let mut it := g.it
  for y in unrP do
    if y.cap && y.payIn redo then
      match tabFind it (idHashR seed y) (fun i => y.idEq iq[i]!.row) with
      | .inl _ => pure ()
      | .inr s =>
        it := it.set! s (iq.size + 1)
        iq := iq.push (hqOf h.ctx y (y.keyBytes 2))
        if it.size < 2 * iq.size then it := idTable seed iq (2 * it.size)
  let more ← findIds h.rel (iq.extract nI iq.size) false
  let mut hr1 := hr0
  let mut relP := relP0
  let mut relSeq := relSeq0
  for r in more do
    hr1 := hr1.push ⟨0, 0, r.size, 4, min r.size capN⟩
    for (s, y) in r.extract 0 capN do
      relP := relP.push y
      relSeq := relSeq.push s
  let nr := hr1.size
  let uIdOf (y : RowX) : Nat :=
    match tabFind it (idHashR seed y) (fun i => y.idEq iq[i]!.row) with
    | .inl i => if i < nI then ks.idNum[i]! - 1 else nk + (i - nI)
    | .inr _ => nr
  let lay ← evalNow (assemble h.hr h.hu q.today byp lim fx [] redo req pidx ks.idx uIdOf hu1 hr1 relP relSeq unrP unrSeq)
  let _ ← tk 18 t1
  return some ⟨{ lay with src := b }, relSeq, unrSeq, lb, planOf nI req.size g.lg g.li fr fu, g.iq ++ g.gq⟩

/-! ## Puts -/

/-- Bench diagnostic (`RR_E3_MEMDIAG`): nanoseconds of `putSide` by part, summed: 0 the rows (records), 1 updates of existing
    cores, 2 new cores, 3 ids, 4 file write. -/
initialize putPhases : IO.Ref (Array Nat) ← IO.mkRef (Array.replicate 5 0)

def putTick (i t0 : Nat) : IO Nat := do
  let t ← IO.monoNanosNow
  putPhases.modify (·.modify i (· + (t - t0)))
  pure t

/-- The rows `sel` (line numbers of `lb`, the store lines at `lineW2` bytes) appended to set `u`, from the plan `pl` and the
    digests `keys` the read made.  The records go to the file in one write, written in place into one buffer; the tables
    follow.  `st` is taken apart first so that the tables are updated in place. -/
def putSide (st : Side) (u : Bool) (lb : @& ByteArray) (sel : Array Nat) (keys : @& Array KeyQ) (pl : @& Array Nat) :
    IO Side := do
  let ⟨f, ids, cores, rd, sum, mem⟩ := st
  let mem ← IO.mkRef (← mem.swap ⟨.empty, .empty⟩)
  let t0 ← IO.monoNanosNow
  let n0 := f.n
  let nI := pl[0]!
  let gn := pl[1]!
  let fo := 3 + 2 * pl[2]! + (if u then 4 else 0)
  let mut recs := ByteArray.emptyWithCapacity (RowsFile.recW * sel.size)
  -- per core touched: newest row plus one (0 untouched), count, and the link of a frozen chain
  let mut tn : Array Nat := Array.replicate gn 0
  let mut tc : Array Nat := Array.replicate gn 0
  let mut tf : Array Nat := Array.replicate gn 0
  let mut order : Array Nat := #[]
  -- rows that make or keep a core long, for the summary: line, row number, place in the core, and the row before it plus one
  let mut late : Array (Nat × Nat × Nat × Nat) := #[]
  for i in [0:sel.size] do
    let l := sel[i]!
    let o := lineW2 * l
    let g := pl[4 + 2 * l]!
    let seq := n0 + i
    let mut prev := 0
    let mut cnt := 1
    if tn[g]! != 0 then
      let c := tc[g]!
      prev := if capN < c then tf[g]! else tn[g]!
      cnt := c + 1
      tf := tf.set! g (if capN ≤ c then prev else 0)
    else
      order := order.push g
      let b := fo + 8 * g
      if pl[b]! != 0 then
        let c0 := pl[b + 2]!
        prev := if capN < c0 then pl[b + 3]! else pl[b + 1]! + 1
        cnt := c0 + 1
        tf := tf.set! g (if capN ≤ c0 then prev else 0)
    if CoreSum.longMin < cnt then late := late.push (l, seq, cnt, prev)
    tn := tn.set! g (seq + 1)
    tc := tc.set! g cnt
    recs := lb.copySlice o recs recs.size lineW2 false
    for k in [0:5] do recs := recs.push ((prev >>> (8 * k)) % 256).toUInt8
    let c := min cnt 65535
    recs := ((recs.push (c % 256).toUInt8).push (c / 256).toUInt8).push (if lb[o + 123]! == 3 then 2 else 0)
    recs := ((recs.push 0).push 0).push 0
  let t0 ← putTick 0 t0
  -- updates of existing cores first: table positions hold until the first insert
  let mut cores := cores
  for g in order do
    let p := pl[fo + 8 * g]!
    if p != 0 then cores := cores.set (p - 1) (Index.withSeq (cores.get (p - 1)) (tn[g]! - 1))
  let t0 ← putTick 1 t0
  for g in order do
    if pl[fo + 8 * g]! == 0 then
      let k := keys[nI + g]!
      cores := cores.insert (if u then k.dh1 else k.dh0) (if u then k.kh1 else k.kh0) (tn[g]! - 1)
  let t0 ← putTick 2 t0
  -- the ids' table words, then one batch insert: the table fetches the buckets of keys ahead while it inserts
  let mut ks := Index.zeros (16 * sel.size)
  for i in [0:sel.size] do
    let k := keys[pl[3 + 2 * sel[i]!]!]!
    ks := Index.wSet (Index.wSet ks (2 * i) (if u then k.dh1 else k.dh0)) (2 * i + 1) (if u then k.kh1 else k.kh0)
  let ids := ids.insertMany ks 8 sel.size n0
  let t0 ← putTick 3 t0
  let f ← f.append recs
  mem.modify (·.putRun n0 recs sel.size)
  let mut sum := sum
  let mut fr : FirstRows := {}
  for (l, seq, k, p) in late do
    let (s2, f2) ← sumAdd (recOf f mem) sum fr seq k p (RowX.ofChunk lb (lineW2 * l))
    sum := s2
    fr := f2
  let _ ← putTick 4 t0
  return ⟨f, ids, cores, rd, sum, mem⟩

/-- The batch's rows `fr` (released) and `fu` (unresolved) put from the read's plan `idx` and digests `keys`. -/
def put (h : Hist) (lb : ByteArray) (idx : Array Nat) (keys : Array KeyQ) (fr fu : Array Nat) : IO Hist := do
  let ⟨ctx, rel, unr, hr, hu⟩ := h
  let rel ← putSide rel false lb fr keys idx
  let unr ← putSide unr true lb fu keys idx
  return ⟨ctx, rel, unr, ⟨hr.asOf, hr.count + fr.size, hr.n + fr.size⟩, ⟨hu.asOf, hu.count + fu.size, hu.n + fu.size⟩⟩

/-- All the store lines `lb` put to set `u` (a refill from the log), its own cores and ids found as a read would. -/
def putAll (ctx : KeyCtx) (st : Side) (u : Bool) (lb : ByteArray) : IO Side := do
  let n := lb.size / lineW2
  let seed := ld64 (← IO.getRandomBytes 8) 0
  let req := (Array.range n).map fun i => RowX.ofChunk lb (lineW2 * i)
  let g := grpsOf ctx seed req
  let fs ← findCores st g.gq u
  putSide st u lb (Array.range n) (g.iq ++ g.gq) (planOf g.iq.size n g.lg g.li fs fs)

/-! ## Opening -/

/-- A set from its rows file (`keep`: only the first rows the log confirms), the tables built by one pass over the file. -/
def Side.load (ctx : KeyCtx) (path : String) (keep : Nat) (u : Bool) : IO (Except String Side) := do
  let f ← RowsFile.«open» path (some keep)
  let mut ids := Index.Idx.new 10
  let mut cores := Index.Idx.new 10
  let mut sum ← CoreSum.Sum.new
  let mem ← Cache.new cacheSlots
  let blk := 4096
  for bi in [0:(f.n + blk - 1) / blk] do
    let s0 := bi * blk
    let m := min blk (f.n - s0)
    let buf ← f.fetch s0 m
    mem.modify (·.putRun s0 buf m)
    let mut fr : FirstRows := {}
    for j in [0:m] do
      let row := RowX.ofChunk buf (RowsFile.recW * j)
      let seq := s0 + j
      let (i1, i2) := hashOf ctx (row.keyBytes 2) u
      ids := ids.insert i1 i2 seq
      let (h1, h2) := hashOf ctx (coreBytes row) u
      let p := RowsFile.prevCoreAt buf j
      let k := RowsFile.countAt buf j
      if CoreSum.longMin < k then
        let (s2, f2) ← sumAdd (recOf f mem) sum fr seq k p row
        sum := s2
        fr := f2
      if p == 0 then cores := cores.insert h1 h2 seq
      else
        -- past `capN + 1` rows a row links to the core's `capN`-th row, and the slot names the row before it
        let hs := hintsOf cores h1 h2
        let hit ← if RowsFile.countAt buf j ≤ capN + 1 then pure (hs.find? (·.1 == p - 1))
          else hs.findM? fun (q, _) => do pure (RowsFile.prevCoreAt (← recOf f mem q) 0 == p)
        match hit with
        | some (_, pos) => cores := cores.set pos (Index.withSeq (cores.get pos) seq)
        | none => return .error s!"rows file {path}: row {seq} follows a row that is not the newest of its core"
  -- descriptors for reading many rows at once; none if the system refuses them (reads then go one by one)
  let mut rd : Array UInt32 := #[]
  for _ in [0:4] do
    let fd ← Io.pgOpen path
    if fd != 0xFFFFFFFF then rd := rd.push fd
  return .ok ⟨f, ids, cores, rd, sum, mem⟩

/-- The engine's core test agrees with the model's core (`Flat.coreKey`) on lines that fit: two lines are in one core
    exactly when their core keys are equal. -/
theorem rowX_coreEq_iff (x y : Line) (hx : fitsLine2 x = true) (hy : fitsLine2 y = true) :
    coreEq (RowX.of x) (RowX.of y) = true ↔ coreKey x = coreKey y := by
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10⟩ := of_eqs x y hx hy
  obtain ⟨_, _, _, _, _, hda, _⟩ := fits2 hx
  obtain ⟨_, _, _, _, _, hda', _⟩ := fits2 hy
  have hd : (RowX.of x).date / 100 = (RowX.of y).date / 100 ↔ x.date / 100 = y.date / 100 := date100 hda hda'
  simp only [coreEq, coreKey, cap_of]
  cases isCap x <;> cases isCap y <;> simp [h3, h6, h7, hd, and_assoc]

end BlindLedger.Gate.Engine3.Hist
