import BlindLedger.Gate.Flat.DecideRows
import BlindLedger.Gate.Engine3.RowsStore
import BlindLedger.Gate.Flat.Worker

/-! Test-only bench of the decision step alone: `decideFetched`, which `decideBatchIdx` runs on the fetched entries, with
    no store, codec, host or I/O.  The history is generated row by row from its index and streamed once per set; only
    the entries of the keys the batches read (round 1 and round 2) are kept, so memory does not grow with the history.
    The batches are 2,000 lines: fresh payments, exact and near duplicates of released rows, resent lines, duplicates of
    unresolved rows, re-decisions of released payments and bypasses of held ones.  Identifiers and members are 33-byte
    numbers, as the store holds them.

    `decide_bench time <corpus>` times `fetch` (the in-memory probes) and `decideFetched` per batch;
    `decide_bench split <corpus>` times each stage `decideFetched` runs and checks the staged result equals it.
    Corpora: `mixed300k`, `mixed3m` (100,000 members, so 3 and 30 history rows per member), `hot300k`, `hot3m` (every
    batch line on one member, which holds 1 % of the history on 8 FFS near keys and 10 CAP months).  Not part of the
    engine.

    Measured 2026-10-31 on the 8-core laptop, one thread, 10 batches of 2,000 lines, µs per line (best batch):

    | Corpus | `decideFetched` | `fetch` | Entry work per line | Lines capped |
    |---|---|---|---|---|
    | mixed, 300k | 38.9 (32.0) | 8.1 | 6.5 | 0 |
    | mixed, 3M | 43.5 (34.7) | 10.1 | 6.6 | 0 |
    | hot, 300k | 171.9 (136.5) | 7.5 | 12.7 | 3,069 of 20,015 |
    | hot, 3M | 518.9 (464.0) | 8.9 | 26.4 | 18,761 of 20,015 |

    On mixed members the cost barely moves with the history (entries stay near one row); on one member it grows with the
    rows per key up to the 1,024-posting cap, and past the cap the lines still pay for the full heads.

    Split (`split`, µs per line, mixed 300k / hot 300k / hot 3M; stages timed alone, so they sum above the whole):
    counterparts 4.0 / 146.8 / 473.1 (every line lists every row sharing a key); rule checks and claims 11.8 / 12.2 /
    12.8; released lines 12.5 / 0.9 / 0.8 (`payOutcome` and `bypassed` scan the batch once per line); post maps 5.5 /
    7.1 / 12.5; feed maps 5.3 / 5.9 / 15.8; order 5.1 / 6.2 / 9.2; cap map 4.1 / 3.4 / 3.7; hot keys 1.3 / 3.0 / 12.2;
    local rows 0.5 / 4.5 / 13.0; batch and redo sets 1.7; unresolved lines 1.1 / 1.6 / 2.7.  Fetch: probe keys 4.9,
    round 2 3.0, the two gets 3.8.

    The fixed-row decider (`Rows.decideRows`, `time`): 1.82 / 1.79 / 1.66 / 2.42 µs per line on mixed 300k / mixed 3M
    / hot 300k / hot 3M, every batch equal to the reference.  Its `layout` from today's list entries costs 34 to 161
    µs per line (it refetches, hashes list keys and splits 33-byte numbers into words); that is a bridge for this
    bench, not the engine's read path, which hands over fixed rows.  `check 2500` (four small corpora with stale and
    missing feeds, feeds past `capN`, unchained sets, ids seen elsewhere, capped hot keys; 1 to 200 lines a batch):
    10,000 batches, 0 mismatches. -/

namespace BlindLedger.Gate.Flat.DecideBench

open BlindLedger.Gate.Rules BlindLedger.Gate.Rules.Fast BlindLedger.Gate.Flat
open BlindLedger.Gate.OnepIndex (capD)
open Std (HashMap HashSet)

@[inline] def mix (x : UInt64) : UInt64 :=
  let z := x + 0x9E3779B97F4A7C15
  let z := (z ^^^ (z >>> 30)) * 0xBF58476D1CE4E5B9
  let z := (z ^^^ (z >>> 27)) * 0x94D049BB133111EB
  z ^^^ (z >>> 31)

def hh (salt i : Nat) : Nat := (mix (mix salt.toUInt64 ^^^ i.toUInt64)).toNat

def top : Nat := 2 ^ 256

/-- A 33-byte number (`0x01 ‖ 32 bytes`), as the store holds identifiers and members. -/
def n33 (salt i : Nat) : Nat :=
  top + hh salt i * 2 ^ 192 + hh (salt + 1) i * 2 ^ 128 + hh (salt + 2) i * 2 ^ 64 + hh (salt + 3) i

structure Corpus where
  name : String
  nRel : Nat
  members : Nat
  hot : Bool
  batches : Nat := 10
  size : Nat := 2000
  /-- In a hot corpus, every `hotEvery`-th history row is on the hot member. -/
  hotEvery : Nat := 100

def Corpus.nUnr (c : Corpus) : Nat := c.nRel / 20

def planOf (m : Nat) : Nat := m % 5 + 1

def hotMember : Nat := n33 10 0

/-- Row `i` from salt `s`; `hotRow` puts it on the hot member's few near keys. -/
def genRow (c : Corpus) (s : Nat) (hotRow : Bool) (i pay : Nat) : Line :=
  let m := if hotRow then hotMember else n33 10 (hh s i % c.members)
  let r := hh (s + 1) i % 100
  let month := 1 + hh (s + 2) i % 10
  let id := n33 (s + 10) i
  if r < 15 then
    ⟨id, pay, .CAP_820, m, planOf m, planOf m, 20260001 + month * 100, 0, 1, 50000 + hh (s + 9) i % 1000⟩
  else
    let day := if hotRow then 5 + hh (s + 3) i % 2 else 1 + hh (s + 3) i % 28
    let rend := if hotRow then 7 + hh (s + 4) i % 2 else 1 + hh (s + 4) i % 5000
    let proc := if hotRow then 10 + hh (s + 5) i % 2 else 1 + hh (s + 5) i % 300
    let date := if hotRow then 20260100 + day else 20260000 + month * 100 + day
    ⟨id, pay, if r < 90 then .FFS_CLAIM else .FFS_CYCLE, m, 1 + hh (s + 7) i % 2000, rend, date, proc,
      1 + hh (s + 8) i % 3, 1000 + hh (s + 9) i % 99000⟩

/-- Row `i` of a set (0 released, 1 unresolved); 1 % of rows are on the hot member in a hot corpus. -/
def histRow (c : Corpus) (set i : Nat) : Line :=
  genRow c (100 * (set + 1)) (c.hot && i % c.hotEvery == 0) i ((set + 1) * 1000000000 + i / 3)

def pickRow (c : Corpus) (n x : Nat) : Nat := if c.hot then x % (n / c.hotEvery) * c.hotEvery else x % n

structure BatchIn where
  lines : List Line
  redo : List Nat
  byp : List (Nat × Nat)
  lim : List (Nat × Nat)

def genBatch (c : Corpus) (t : Nat) : BatchIn := Id.run do
  let mut ls : Array Line := #[]
  let mut redo : Array Nat := #[]
  let mut byp : Array (Nat × Nat) := #[]
  let mut lim : Array (Nat × Nat) := #[]
  let mut p := 0
  while ls.size < c.size do
    let pay := 5000000000 + t * 100000 + p
    let kind := hh (900 + t) p % 100
    let x := hh (901 + t) p
    let nid := n33 (2000 + t) p
    if kind < 70 then
      for j in [0:1 + x % 4] do ls := ls.push (genRow c (1000 + 20 * t) c.hot (8 * p + j) pay)
      -- some new payments go at HOLD authority, with no holds or with some
      if x % 7 == 0 then lim := lim.push (pay, if x % 2 == 0 then 0 else x / 7 % 2 ^ Rules.reasons.length)
    else if kind < 78 then
      ls := ls.push { histRow c 0 (pickRow c c.nRel x) with id := nid, pay := pay }
    else if kind < 83 then
      ls := ls.push (histRow c 0 (pickRow c c.nRel x))
    else if kind < 88 then
      let r := histRow c 0 (pickRow c c.nRel x)
      ls := ls.push { r with id := nid, pay := pay, units := r.units + 7, cents := r.cents + 1 }
    else if kind < 92 then
      ls := ls.push { histRow c 1 (pickRow c c.nUnr x) with id := nid, pay := pay }
    else if kind < 96 then
      let i := pickRow c c.nRel x
      let r := histRow c 0 i
      redo := redo.push r.pay
      for j in [i / 3 * 3 : min (i / 3 * 3 + 3) c.nRel] do
        let y := histRow c 0 j
        if !c.hot || y.member == r.member then ls := ls.push y
    else
      let i := pickRow c c.nUnr x
      let r := histRow c 1 i
      byp := byp.push (r.pay, if x % 2 == 0 then 2 ^ Rules.reasons.length - 1 else x % 2 ^ Rules.reasons.length)
      for j in [i / 3 * 3 : min (i / 3 * 3 + 3) c.nUnr] do
        let y := histRow c 1 j
        if !c.hot || y.member == r.member then ls := ls.push y
    p := p + 1
  return ⟨ls.toList, redo.toList, byp.toList, lim.toList⟩

def spanOf (m : Nat) : List Span :=
  if m % 97 < 3 then [] else
  let base : List Span := [⟨m, planOf m, 20250101, 20271231⟩]
  if m % 101 == 0 then base ++ [⟨m, planOf m % 5 + 1, 20260101, 20260630⟩] else base

/-- Eligibility rows of member `m` (G2): most members one row with an allowed aid code and a benefit level; one in 13
    no level (BENEFIT_LEVEL_MISSING), one in 17 an aid code not allowed (PROGRAM_NOT_ELIGIBLE), two in 89 no row, one in
    103 a second, shorter row. -/
def eligOf (m : Nat) : List Elig :=
  if m % 89 < 2 then [] else
  let aid := if m % 17 == 0 then 12345 else allowedAid.getD (m % 5) 78131
  let base : List Elig := [⟨m, aid, if m % 13 == 0 then 0 else 1, 20250101, 20271231⟩]
  if m % 103 == 0 then base ++ [⟨m, 78131, 1, 20260101, 20260630⟩] else base

def feeds : Feeds :=
  { dmfSome := true, pdSome := true, exclSome := true, spanSome := true, eligSome := true,
    dmfOk := true, pdOk := true, exclOk := true, spanOk := true, eligOk := true,
    dmf := fun i => if i % 199 == 0 then [⟨i, 20260301⟩] else [],
    pdeath := fun i => if i % 499 == 0 then [⟨i, 20260201⟩] else [],
    excl := fun i => if i % 307 == 0 then [⟨i, 20260101, 99991231⟩] else [],
    span := spanOf, elig := eligOf }

def today : Nat := 20261031

def emptyA : EntryA := ⟨0, #[], zeroDigest⟩

/-- `EntryA.push` with a hash that always gives `zeroDigest`: past `capN` only the count moves (the decision never reads the
    tail). -/
def pushA (e : EntryA) (p : Posting) : EntryA :=
  if e.head.size < capN then { e with count := e.count + 1, head := e.head.push p } else { e with count := e.count + 1 }

/-- Streams `n` rows of a set into the entries of the wanted keys. -/
def streamSet (row : Nat → Line) (n : Nat) (want : HashSet Key) : HashMap Key Entry := Id.run do
  let mut slot : HashMap Key Nat := ∅
  let mut es : Array EntryA := #[]
  for i in [0:n] do
    let l := row i
    for k in keys l do
      if want.contains k then
        match slot.get? k with
        | some j => es := es.modify j fun e => pushA e ⟨i, l⟩
        | none =>
          slot := slot.insert k es.size
          es := es.push (pushA emptyA ⟨i, l⟩)
  return slot.fold (fun acc k j => acc.insert k (es.getD j emptyA).toEntry) ∅

def fcOf (bi : BatchIn) : FCtx := ⟨today, bi.redo, feeds, bi.byp, bi.lim⟩

/-- Each line's payment as its first position among the batch's payments (the request position of a decoded frame). -/
def payIdx (ls : List Line) : Array Nat := Id.run do
  let mut m : HashMap Nat Nat := ∅
  let mut out : Array Nat := #[]
  for l in ls do
    match m.get? l.pay with
    | some j => out := out.push j
    | none =>
      out := out.push m.size
      m := m.insert l.pay m.size
  return out

/-- The two sets as indexes over the streamed history, holding exactly the entries the batches read; no core
    counts (per key). -/
def buildSt (c : Corpus) (bs : Array BatchIn) : St :=
  let want := HashSet.ofList (bs.toList.flatMap fun bi => probeKeys bi.lines)
  let um := streamSet (histRow c 1) c.nUnr want
  let unr : SetIdx := ⟨⟨20261030, c.nUnr, c.nUnr⟩, fun k => um.getD k Entry.empty, fun _ => 0⟩
  let r2 := bs.toList.flatMap fun bi =>
    let ks := probeKeys bi.lines
    round2 bi.redo ks (ks.map fun k => (k, unr.get k))
  let rm := streamSet (histRow c 0) c.nRel (want.insertMany r2)
  ⟨⟨⟨20261030, c.nRel, c.nRel⟩, fun k => rm.getD k Entry.empty, fun _ => 0⟩, unr⟩

def corpora : List Corpus :=
  [⟨"mixed50k", 50000, 16667, false, 10, 2000, 100⟩, ⟨"mixed300k", 300000, 100000, false, 10, 2000, 100⟩, ⟨"mixed3m", 3000000, 100000, false, 10, 2000, 100⟩,
   ⟨"hot300k", 300000, 1, true, 10, 2000, 100⟩, ⟨"hot3m", 3000000, 1, true, 10, 2000, 100⟩]

def fmt (x : Float) : String := toString ((x * 100).round / 100)

def us (a b n : Nat) : Float := (b - a).toFloat / n.toFloat / 1000

@[noinline] def runFetch (s : St) (bi : BatchIn) : IO Fetched := pure (fetch s bi.redo bi.lines)

@[noinline] def runLayout (s : St) (bi : BatchIn) : IO Rows.Lay := pure (Rows.layout s (fcOf bi) [] bi.lines)

@[noinline] def runRows (x : Rows.Lay) : IO Rows.Out := pure (Rows.decideRows x)

@[noinline] def runDecide (s : St) (fe : Fetched) (bi : BatchIn) : IO (List Decision × List Line × List Line) :=
  pure (decideFetched s.rel.head s.unr.head fe (fcOf bi) [] bi.lines)

def setup (c : Corpus) : IO (Array BatchIn × St) := do
  let t0 ← IO.monoNanosNow
  let bs := (Array.range c.batches).map (genBatch c)
  let s := buildSt c bs
  let n := (bs.map fun bi => (fetch s bi.redo bi.lines).rel.length).foldl (· + ·) 0
  let t1 ← IO.monoNanosNow
  IO.println s!"{c.name}: history {c.nRel} released, {c.nUnr} unresolved; {c.batches} batches; setup s {fmt ((t1 - t0).toFloat / 1e9)} ({n} keys)"
  return (bs, s)

def timeCorpus (c : Corpus) : IO Unit := do
  let (bs, s) ← setup c
  let mut tf := 0
  let mut td := 0
  let mut lines := 0
  let mut allow := 0
  let mut hold := 0
  let mut review := 0
  let mut cap := 0
  let mut postings := 0
  let mut rel := 0
  let mut unr := 0
  let mut best : Float := 1e9
  let mut tl := 0
  let mut tr := 0
  let mut bestR : Float := 1e9
  let mut bad := 0
  for bi in bs do
    let a ← IO.monoNanosNow
    let fe ← runFetch s bi
    let b ← IO.monoNanosNow
    let r ← runDecide s fe bi
    let d ← IO.monoNanosNow
    let x ← runLayout s bi
    let e ← IO.monoNanosNow
    let o ← runRows x
    let g ← IO.monoNanosNow
    let n := bi.lines.length
    tl := tl + (e - d)
    tr := tr + (g - e)
    bestR := min bestR (us e g n)
    if o.toRef x != Rows.project r then bad := bad + 1
    tf := tf + (b - a)
    td := td + (d - b)
    best := min best (us b d n)
    lines := lines + n
    postings := postings + entryWork fe.rel + entryWork fe.unr
    rel := rel + r.2.1.length
    unr := unr + r.2.2.length
    for x in r.1 do
      match x.outcome with
      | .ALLOW => allow := allow + 1
      | .HOLD => hold := hold + 1
      | .HUMAN_REVIEW => review := review + 1
      if x.reasons.contains .POSTING_CAP then cap := cap + 1
  IO.println s!"  lines {lines}: allow {allow} hold {hold} review {review} (posting cap {cap}); released {rel} unresolved {unr}; entry work/line {fmt (postings.toFloat / lines.toFloat)}"
  IO.println s!"  fetch us/line {fmt (us 0 tf lines)}; decide us/line {fmt (us 0 td lines)} (best batch {fmt best})"
  IO.println s!"  fixed rows: layout us/line {fmt (us 0 tl lines)}; decide us/line {fmt (us 0 tr lines)} (best batch {fmt bestR}); batches unequal to the reference {bad}"

/-! ## Stages of `decideFetched`, each timed alone -/

@[noinline] def sProbe (b : List Line) : IO (List Key) := pure (probeKeys b)
@[noinline] def sGet (x : SetIdx) (ks : List Key) : IO (List (Key × Entry)) := pure (ks.map fun k => (k, x.get k))
@[noinline] def sRound2 (redo : List Nat) (ks : List Key) (u : List (Key × Entry)) : IO (List Key) :=
  pure (round2 redo ks u)
@[noinline] def sLocal (es : List (Key × Entry)) : IO (List Posting) := pure (localRows es)
@[noinline] def sPost (ps : List Posting) (es : List (Key × Entry)) : IO (HashMap Key (List Nat)) := pure (postMap ps es)
@[noinline] def sFeeds (fd : Feeds) (b : List Line) (ur : List Posting) :
    IO (HashMap Nat (List Death) × HashMap Nat (List Death) × HashMap Nat (List Exclusion) × HashMap Nat (List Span) ×
      HashMap Nat (List Elig)) :=
  pure (idMap fd.dmf (members b), idMap fd.pdeath (parties b), idMap fd.excl (parties b), idMap fd.span (spanIds b ur),
    idMap fd.elig (members b))
@[noinline] def sSets (fc : FCtx) (b : List Line) : IO (HashSet Nat × HashSet Line) :=
  pure (HashSet.ofList fc.redo, HashSet.ofList b)
@[noinline] def sCaps (fe : Fetched) (fd : Feeds) (b : List Line) : IO (HashSet Key × Bool) :=
  pure (hotKeys fe fd b, idCapped fe)
@[noinline] def sOrder (x : Ix) (b : List Line) : IO (List Line) := pure (x.order b)
@[noinline] def sDecideAll (x : Ix) (f : List Nat) (o : List Line) : IO (List Decision) :=
  pure (x.decideAll (HashSet.ofList (idSeen f)) o)

/-- `decideAll` without counterparts: the rule checks and the claims the batch carries forward. -/
def firesAll (x : Ix) : HashSet Key → List Line → List (List Reason)
  | _, [] => []
  | s, l :: ls => reasons.filter (x.fires s l) :: firesAll x (s.insertMany (x.claim l)) ls

@[noinline] def sFires (x : Ix) (f : List Nat) (o : List Line) : IO (List (List Reason)) :=
  pure (firesAll x (HashSet.ofList (idSeen f)) o)
@[noinline] def sCounter (x : Ix) (o : List Line) : IO (List (List Nat)) := pure (o.map x.counterparts)
@[noinline] def sCap (ic : Bool) (hot : HashSet Key) (fd : Feeds) (ds : List Decision) : IO (List Decision) :=
  pure (ds.map fun d => if cappedWith ic hot fd d.line then capD d else d)
@[noinline] def sReleased (x : Ix) (ds : List Decision) : IO (List Line) := pure (x.releasedLines ds)
@[noinline] def sUnresolved (x : Ix) (ds : List Decision) : IO (List Line) := pure (x.unresolvedLines ds)

def stageNames : List String :=
  ["probe keys", "unresolved get", "round 2", "released get", "local rows (sort, dedup)", "post maps", "feed maps",
   "batch and redo sets", "hot keys, id cap", "order (own, canonical)", "decideAll", "  of which rule checks and claims",
   "  of which counterparts", "cap map", "released lines (payOutcome, bypassed)", "unresolved lines"]

def splitCorpus (c : Corpus) : IO Bool := do
  let (bs, s) ← setup c
  let mut acc : Array Nat := Array.replicate stageNames.length 0
  let mut lines := 0
  let mut ok := true
  for bi in bs do
    let b := bi.lines
    let fc := fcOf bi
    let fd := fc.feeds
    let t0 ← IO.monoNanosNow
    let ks ← sProbe b
    let t1 ← IO.monoNanosNow
    let u ← sGet s.unr ks
    let t2 ← IO.monoNanosNow
    let r2 ← sRound2 bi.redo ks u
    let t3 ← IO.monoNanosNow
    let rl ← sGet s.rel (ks ++ r2)
    let t4 ← IO.monoNanosNow
    let fe : Fetched := ⟨rl, u, s.rel.core, s.unr.core⟩
    let rr ← sLocal fe.rel
    let ur ← sLocal fe.unr
    let t5 ← IO.monoNanosNow
    let rp ← sPost rr fe.rel
    let up ← sPost ur fe.unr
    let t6 ← IO.monoNanosNow
    let (dm, pd, ex, sp, el) ← sFeeds fd b ur
    let t7 ← IO.monoNanosNow
    let (rd, bt) ← sSets fc b
    let t8 ← IO.monoNanosNow
    let (hot, ic) ← sCaps fe fd b
    let t9 ← IO.monoNanosNow
    let hr := s.rel.head
    let hu := s.unr.head
    let x : Ix :=
      { today := fc.today, redo := rd, byp := fc.byp, lim := fc.lim, batch := bt,
        relChained := hr.chained fc.today, unrChained := hu.chained fc.today,
        relV := ⟨hr.asOf, hr.count, []⟩, unrV := ⟨hu.asOf, hu.count, []⟩,
        relN := rr.length, unrN := ur.length, rel := (rr.map (·.row)).toArray, unr := (ur.map (·.row)).toArray,
        relPost := rp, unrPost := up, looseKeys := ∅,
        dmfSome := fd.dmfSome, pdSome := fd.pdSome, exclSome := fd.exclSome, spanSome := fd.spanSome,
        eligSome := fd.eligSome,
        dmfOk := fd.dmfOk, pdOk := fd.pdOk, exclOk := fd.exclOk, spanOk := fd.spanOk, eligOk := fd.eligOk,
        dmf := dm, pdeath := pd, excl := ex, span := sp, elig := el }
    let o ← sOrder x b
    let t10 ← IO.monoNanosNow
    let ds0 ← sDecideAll x [] o
    let t11 ← IO.monoNanosNow
    let fs ← sFires x [] o
    let t12 ← IO.monoNanosNow
    let cs ← sCounter x o
    let t13 ← IO.monoNanosNow
    let ds ← sCap ic hot fd ds0
    let t14 ← IO.monoNanosNow
    let ra ← sReleased x ds
    let t15 ← IO.monoNanosNow
    let ua ← sUnresolved x ds
    let t16 ← IO.monoNanosNow
    let ref := decideFetched hr hu (fetch s bi.redo b) fc [] b
    if ref != (ds, ra, ua) || fs.length != cs.length then ok := false
    let d := [t1 - t0, t2 - t1, t3 - t2, t4 - t3, t5 - t4, t6 - t5, t7 - t6, t8 - t7, t9 - t8, t10 - t9, t11 - t10,
      t12 - t11, t13 - t12, t14 - t13, t15 - t14, t16 - t15]
    acc := (acc.zip d.toArray).map fun (a, b) => a + b
    lines := lines + b.length
  IO.println s!"  staged result equals decideFetched: {ok}"
  for (nm, v) in stageNames.zip acc.toList do
    IO.println s!"  {nm}: us/line {fmt (us 0 v lines)}"
  return ok

def find (n : String) : Option Corpus := corpora.find? (·.name == n)

/-! ## Randomized check of the fixed-row decider -/

/-- Feed variant `v`: each feed present 90 %, usable 75 % of those; one member in 7 (variant 0 mod 3) has more spans
    than `capN`, one in 11 (variant 0 mod 5) more deaths, one in 13 (variant 0 mod 7) more eligibility rows. -/
def feedsV (v : Nat) : Feeds :=
  let on (k p : Nat) := hh 7000 (16 * v + k) % 100 < p
  let ds := on 0 90
  let ps := on 1 90
  let es := on 2 90
  let ss := on 3 90
  let gs := on 8 90
  { dmfSome := ds, pdSome := ps, exclSome := es, spanSome := ss, eligSome := gs,
    dmfOk := ds && on 4 75, pdOk := ps && on 5 75, exclOk := es && on 6 75, spanOk := ss && on 7 75,
    eligOk := gs && on 9 75,
    dmf := fun i => if v % 5 == 0 && i % 11 == 0 then List.replicate (capN + 1) ⟨i, 20270101⟩ else feeds.dmf i,
    pdeath := feeds.pdeath, excl := feeds.excl,
    span := fun i => if v % 3 == 0 && i % 7 == 0 then List.replicate (capN + 1) ⟨i, planOf i, 20250101, 20271231⟩
      else spanOf i,
    elig := fun i => if v % 7 == 0 && i % 13 == 0 then List.replicate (capN + 1) ⟨i, 78131, 1, 20250101, 20271231⟩
      else eligOf i }

def checkCorpora : List Corpus :=
  [⟨"mixed, dense", 20000, 2000, false, 0, 200, 100⟩, ⟨"mixed, 40 rows a member", 20000, 500, false, 0, 200, 100⟩,
   ⟨"hot", 20000, 1, true, 0, 200, 100⟩, ⟨"hot, capped", 40000, 1, true, 0, 100, 2⟩]

structure Tally where
  batches : Nat := 0
  lines : Nat := 0
  bad : Nat := 0
  hold : Nat := 0
  review : Nat := 0
  cap : Nat := 0
  already : Nat := 0
  rel : Nat := 0
  unr : Nat := 0

def checkChunk (c : Corpus) (t0 n : Nat) (ty : Tally) : IO Tally := do
  let bs := (Array.range n).map fun j =>
    let t := t0 + j
    genBatch { c with size := 1 + hh 5000 t % c.size } t
  let s := buildSt c bs
  let mut ty := ty
  for j in [0:n] do
    let t := t0 + j
    let bi := bs.getD j ⟨[], [], [], []⟩
    let fc : FCtx := ⟨today, bi.redo, feedsV t, bi.byp, bi.lim⟩
    let f := if hh 5001 t % 5 == 0 then (bi.lines.take 3).map (·.id) else []
    let s := if hh 5002 t % 10 == 0 then { s with rel := { s.rel with head := { s.rel.head with count := c.nRel + 1 } } }
      else if hh 5002 t % 10 == 1 then { s with unr := { s.unr with head := { s.unr.head with asOf := today + 1 } } }
      else s
    let r := decideBatchIdx s fc f bi.lines
    let x := Rows.layout s fc f bi.lines
    let o := Rows.decideRows x
    if o.toRef x != Rows.project r then
      if ty.bad == 0 then
        let a := (o.toRef x).1
        let p := (Rows.project r).1
        let k := ((a.zip p).findIdx? fun (u, v) => u != v).getD (min a.length p.length)
        IO.println s!"  first mismatch: {c.name} batch {t}, decision {k} of {p.length}: rows {repr (a[k]?.map fun q => (q.2.1, q.2.2.1, q.2.2.2))} reference {repr (p[k]?.map fun q => (q.2.1, q.2.2.1, q.2.2.2))}; released {(o.toRef x).2.1.length} vs {r.2.1.length}, unresolved {(o.toRef x).2.2.length} vs {r.2.2.length}"
      ty := { ty with bad := ty.bad + 1 }
    ty := { ty with batches := ty.batches + 1, lines := ty.lines + bi.lines.length }
    ty := { ty with rel := ty.rel + r.snd.fst.length, unr := ty.unr + r.snd.snd.length }
    for d in r.1 do
      if d.outcome == .HOLD then ty := { ty with hold := ty.hold + 1 }
      if d.outcome == .HUMAN_REVIEW then ty := { ty with review := ty.review + 1 }
      if d.reasons.contains .POSTING_CAP then ty := { ty with cap := ty.cap + 1 }
      if d.reasons.contains .ALREADY_DECIDED then ty := { ty with already := ty.already + 1 }
  return ty

/-- One core over the cap with every key under it: a member's released rows on one date and procedure, split between
    two rendering providers, `capN / 2 + 1` rows each.  A new claim on that core is HOLD with `POSTING_CAP` from
    `decideBatchIdx` and from `decideRows`, the two agree, and the per-key state (`St.perKey`) does not cap it. -/
def coreCapCheck : IO Bool := do
  let m := n33 20 0
  let row (i : Nat) : Line :=
    ⟨n33 21 i, n33 22 i, .FFS_CLAIM, m, 1 + i % 2000, 7 + i % 2, 20260105, 10, 1 + i % 3, 1000 + i⟩
  let e0 : SetIdx := ⟨⟨20261030, 0, 0⟩, fun _ => Entry.empty, fun _ => 0⟩
  let s : St := ⟨e0.addRows (fun _ => zeroDigest) ((List.range (capN + 2)).map row), e0⟩
  let l : Line := ⟨n33 23 0, n33 24 0, .FFS_CLAIM, m, 5, 7, 20260105, 10, 2, 777⟩
  let fc : FCtx := ⟨today, [], feeds, [], []⟩
  let r := decideBatchIdx s fc [] [l]
  let x := Rows.layout s fc [] [l]
  let o := Rows.decideRows x
  let core := s.rel.core (coreKey l)
  let keyMax := (keys l).foldl (fun a k => max a (s.rel.get k).count) 0
  let held := r.1.length == 1 && r.1.all fun d => d.outcome == .HOLD && d.reasons.contains .POSTING_CAP
  let perKey := (decideBatchIdx s.perKey fc [] [l]).1.any (·.reasons.contains .POSTING_CAP)
  let same := o.toRef x == Rows.project r
  let ok := capN < core && keyMax ≤ capN && held && !perKey && same
  IO.println s!"one core over the cap: core {core} rows, largest key {keyMax}; reference HOLD POSTING_CAP {held}, per key POSTING_CAP {perKey}, fixed-row decider equal {same}"
  return ok

def checkAll (per : Nat) : IO Bool := do
  let mut ok ← coreCapCheck
  let mut total := 0
  for c in checkCorpora do
    let mut ty : Tally := {}
    let mut t0 := 0
    while t0 < per do
      ty ← checkChunk c t0 (min 125 (per - t0)) ty
      t0 := t0 + 125
    IO.println s!"{c.name}: batches {ty.batches} lines {ty.lines} mismatches {ty.bad}; hold {ty.hold} (posting cap {ty.cap}, already decided {ty.already}) review {ty.review}; released {ty.rel} unresolved {ty.unr}"
    total := total + ty.batches
    if ty.bad != 0 then ok := false
  IO.println s!"check: {total} batches, {if ok then "0 mismatches" else "MISMATCHES"}"
  return ok

/-! ## The layout from a chunk store

    `rows <corpus> <passes>` builds a store of installed chunks (the entries the batches read, and filler entries so the
    store holds about two entries per history row, spread over chunks of 150,000 entries), then times, per batch of
    request rows, the stages of `Engine3.layoutStore` and `decideRows`, and checks each batch's `Lay` and decisions equal
    `Rows.layout`'s and `decideRows`'s over the index.  `rowscheck <batches>` does that on the small randomized corpora of
    `check`.  Both first check `RowX.ofChunk` against `RowX.of (getLine ..)` on every row of the store. -/

open BlindLedger.Gate.Engine3 (HistStore Img Ks KeyQ Hit KeyCtx FDirs FDir keysOf round2Keys assemble layoutStore RowX W9 redoW
  keyState khSt dhSt khAt dhAt keyDigest shortMax sk encodeChunk parseChunk slotOff flagTail getLine FeedSrc FeedsX putN getN
  W3 W4 W7 payW idW)

/-! ### Feeds on the wire (conformance/ENGINE_V3.md §19)

    The host's side: `encFeeds` writes the rows of `fd` for the members `ms` and providers `ps` in the §19 order, and
    gives each feed's descriptor; a feed with a row it cannot encode is sent missing (state 2).  The engine's side is
    `FeedsX.decode`.  `viewOf` is the model's view of the same bytes: each feed's rows decoded one by one into a
    snapshot and read through `Worker.feedsOf`, so a check compares the engine with the feeds of the request's context. -/

/-- Lexicographic order of two equal-length lists of numbers. -/
def lexLeN : List Nat → List Nat → Bool
  | a :: as, b :: bs => a < b || a == b && lexLeN as bs
  | _, _ => true

/-- One feed's rows in §19 order, or none when a row does not fit its width. -/
def encRows {α : Type} (xs : List α) (fits : α → Bool) (fields : α → List Nat) (put : ByteArray → α → ByteArray) :
    Option ByteArray :=
  if xs.all fits then some ((xs.mergeSort fun a b => lexLeN (fields a) (fields b)).foldl put ByteArray.empty) else none

/-- The descriptor and rows of one feed: absent, missing (unencodable), or present dated `asOf` with every row sent. -/
def srcOf (present : Bool) (asOf stride : Nat) : Option ByteArray → FeedSrc
  | some b => if present then ⟨true, asOf, b.size / stride, b⟩ else ⟨false, 0, 0, ByteArray.empty⟩
  | none => ⟨false, 0, 0, ByteArray.empty⟩

/-- The four feeds of `fd` for `ms` and `ps` (each id once), dated so that a usable feed is fresh and an unusable one is
    stale. -/
def encFeeds (fd : Feeds) (ms ps : List Nat) : FeedSrc × FeedSrc × FeedSrc × FeedSrc :=
  let once := fun (xs : List Nat) => (xs.mergeSort fun a b => decide (a ≤ b)).foldr
    (fun x acc => if acc.head? == some x then acc else x :: acc) []
  let ms := once ms
  let ps := once ps
  let mem := fun (m : Nat) => m >>> 256 == 1
  let prov := fun (p : Nat) => p < 2 ^ 168
  let d32 := fun (d : Nat) => d < 2 ^ 32
  let putM := fun (b : ByteArray) (m : Nat) => putN b m 32
  let putP := fun (b : ByteArray) (p : Nat) => putN b p 21
  let at_ := fun (ok : Bool) => if ok then today - 1 else 20250101
  (srcOf fd.dmfSome (at_ fd.dmfOk) 36 (encRows (ms.flatMap fd.dmf) (fun x => mem x.id && d32 x.date)
      (fun x => [x.id, x.date]) fun b x => putN (putM b x.id) x.date 4),
   srcOf fd.pdSome (at_ fd.pdOk) 25 (encRows (ps.flatMap fd.pdeath) (fun x => prov x.id && d32 x.date)
      (fun x => [x.id, x.date]) fun b x => putN (putP b x.id) x.date 4),
   srcOf fd.exclSome (at_ fd.exclOk) 29 (encRows (ps.flatMap fd.excl) (fun x => prov x.id && d32 x.start && d32 x.stop)
      (fun x => [x.id, x.start, x.stop]) fun b x => putN (putN (putP b x.id) x.start 4) x.stop 4),
   srcOf fd.spanSome (at_ fd.spanOk) 61 (encRows (ms.flatMap fd.span)
      (fun x => mem x.member && prov x.plan && d32 x.start && d32 x.stop) (fun x => [x.member, x.plan, x.start, x.stop])
      fun b x => putN (putN (putP (putM b x.member) x.plan) x.start 4) x.stop 4))

/-- The seed of the feed tables in the bench (the engine takes it from its store secret). -/
def feedSeed : UInt64 := 0x5eed0f0f

def decodeFeeds (r : FeedSrc × FeedSrc × FeedSrc × FeedSrc) : Option FeedsX :=
  FeedsX.decode today feedSeed r.1 r.2.1 r.2.2.1 r.2.2.2

/-- The rows of `src`, each read alone from its bytes, as the model's snapshot (none when absent). -/
def snapOf {α : Type} (src : FeedSrc) (stride : Nat) (row : Nat → α) : Option (Snapshot α) :=
  if src.present then some ⟨src.asOf, src.count, (List.range (src.rows.size / stride)).map fun j => row (stride * j)⟩
  else none

/-- The model's feeds of the same bytes: `Worker.feedsOf` of a context holding the four snapshots. -/
def viewOf (r : FeedSrc × FeedSrc × FeedSrc × FeedSrc) : Feeds :=
  let (d, p, e, s) := r
  let g := fun (b : ByteArray) (o w : Nat) => getN b o w
  let none_ : Snapshot Line := ⟨0, 0, []⟩
  Worker.feedsOf
    { today, released := none, unresolved := none, releasedPrior := none_, unresolvedPrior := none_, anchor := 0,
      redo := [], eligibility := none,
      dmf := snapOf d 36 fun o => (⟨2 ^ 256 + g d.rows o 32, g d.rows (o + 32) 4⟩ : Death),
      providerDeaths := snapOf p 25 fun o => (⟨g p.rows o 21, g p.rows (o + 21) 4⟩ : Death),
      exclusions := snapOf e 29 fun o => (⟨g e.rows o 21, g e.rows (o + 21) 4, g e.rows (o + 25) 4⟩ : Exclusion),
      enrollment := snapOf s 61 fun o =>
        (⟨2 ^ 256 + g s.rows o 32, g s.rows (o + 32) 21, g s.rows (o + 53) 4, g s.rows (o + 57) 4⟩ : Span) }

/-- The feeds a check sends and the engine decodes, and the model's view of them; a frame the engine refuses is a
    failed check. -/
def feedsFor (fd : Feeds) (ms ps : List Nat) : IO (FeedsX × Feeds) := do
  let r := encFeeds fd ms ps
  match decodeFeeds r with
  | some fx => pure (fx, viewOf r)
  | none => throw (IO.userError "feeds: the engine refused the rows the host sent")

/-- The members and providers whose feed rows a corpus sends: every member it draws from and providers 1 to 5,000
    (`genRow`). -/
def corpusIds (c : Corpus) : List Nat × List Nat := ((List.range c.members).map (n33 10), List.range' 1 5000)

/-- The members and providers a batch reads feeds for: its lines', and the members of the unresolved rows it fetches. -/
def feedIds (s : St) (bi : BatchIn) : List Nat × List Nat :=
  (bi.lines.map (·.member) ++ (fetch s bi.redo bi.lines).unr.flatMap (fun (_, e) => (heads e).map (·.row.member)),
   bi.lines.flatMap fun l => [l.payee, l.rendering])

/-- Every entry the batches read, as stored bytes (set tag first) and entry. -/
def wantedOf (s : St) (bs : Array BatchIn) : Array (BlindLedger.Gate.Bytes × Entry) := Id.run do
  let mut seen : HashSet (Bool × Key) := ∅
  let mut out : Array (BlindLedger.Gate.Bytes × Entry) := #[]
  for bi in bs do
    let fe := fetch s bi.redo bi.lines
    for (u, es) in [(false, fe.rel), (true, fe.unr)] do
      for (k, e) in es do
        if e.count != 0 && !seen.contains (u, k) then
          seen := seen.insert (u, k)
          out := out.push (sk u k, e)
  return out

/-- A filler entry of one row, under one of the row's keys, in either set. -/
def fillEnt (i : Nat) : BlindLedger.Gate.Bytes × Entry :=
  let r := (i * 16 + 5).toUInt64
  let l : Line := ⟨top + (mix r).toNat, (mix (r + 1)).toNat % 2 ^ 40, if i % 4 == 0 then .CAP_820 else .FFS_CLAIM,
    top + (mix (r + 2)).toNat, (mix (r + 3)).toNat % 2 ^ 20, (mix (r + 4)).toNat % 2 ^ 20, (mix (r + 5)).toNat % 2 ^ 30,
    (mix (r + 6)).toNat % 2 ^ 30, (mix (r + 7)).toNat % 2 ^ 20, (mix (r + 8)).toNat⟩
  (sk (i % 2 == 0) ([exactKey l, nearKey l, idKey l][i % 3]!), ⟨1, [⟨i, l⟩], zeroDigest⟩)

/-- Chunks of the wanted and `fill` filler entries, written as the engine writes them, and the directory over them. -/
def buildStore (wanted : Array (BlindLedger.Gate.Bytes × Entry)) (fill : Nat) : IO HistStore := do
  let sec := ByteArray.mk ((Array.range 32).map fun i => (mix (i.toUInt64 + 5)).toUInt8)
  let ctx := KeyCtx.ofSecret sec
  let hashes := fun (kb : BlindLedger.Gate.Bytes) =>
    let u := kb.headD 0 == 1
    let k : ByteArray := ⟨kb.tail.toArray⟩
    if k.size ≤ shortMax then
      let s := keyState ctx k
      (khSt s u, dhSt s u)
    else
      let d := keyDigest ctx.sec k
      (khAt d u, dhAt d u)
  let total := wanted.size + fill
  let nc := total / 150000 + 1
  let nb := total / 64 * 10 / 7 / 4 + 2
  let mut dirs : FDirs := (Array.range 64).map fun j => FDir.empty nb (mix (j.toUInt64 + 1000))
  let mut chunks : Array Img := #[]
  for c in [0:nc] do
    let mut items : Array (UInt64 × UInt64 × BlindLedger.Gate.Bytes × Entry) := #[]
    for k in [0:(wanted.size + nc - 1 - c) / nc] do
      let x := wanted.getD (c + k * nc) (([] : BlindLedger.Gate.Bytes), Entry.empty)
      items := items.push ((hashes x.1).1, (hashes x.1).2, x.1, x.2)
    for k in [0:(fill + nc - 1 - c) / nc] do
      let x := fillEnt (c + k * nc + 10000000000)
      items := items.push ((hashes x.1).1, (hashes x.1).2, x.1, x.2)
    items := items.qsort fun a b => a.1 < b.1 || (a.1 == b.1 && BlindLedger.Gate.Flat.Chunk.bytesLt a.2.2.1 b.2.2.1)
    let (file, _) := encodeChunk (fun kb => (hashes kb).1) (fun kb => (hashes kb).2)
      (items.toList.map fun x => (x.2.2.1, x.2.2.2)) c 0 #[]
    let some (m, img) := parseChunk file | throw (IO.userError "store: chunk does not parse")
    for x in items do
      dirs := dirs.insert x.2.1 c
      if !dirs.kept x.2.1 then throw (IO.userError "store: directory refused an insert")
    chunks := chunks.push ⟨m, img, ByteArray.empty⟩
  IO.println s!"  store: {wanted.size} wanted + {fill} filler entries, {nc} chunks, {chunks.foldl (fun a ch => a + ch.img.size) 0} image bytes, {nb} buckets a segment"
  return ⟨ctx, dirs, chunks⟩

/-- Rows checked and rows where `RowX.ofChunk` differs from `RowX.of (getLine ..)`, over every posting row of the store. -/
def rowDecodeCheck (st : HistStore) : IO (Nat × Nat) := do
  let mut n := 0
  let mut bad := 0
  for ch in st.chunks do
    for i in [0:ch.m.rows] do
      let o := slotOff i
      if ch.img[o + 8]! &&& flagTail == 0 then
        n := n + 1
        match getLine ch.img (o + 19) with
        | some l => if !(RowX.ofChunk ch.img (o + 19)).same (RowX.of l) then bad := bad + 1
        | none => bad := bad + 1
  return (n, bad)

def arrEq {α : Type} [Inhabited α] (f : α → α → Bool) (a b : Array α) : Bool :=
  a.size == b.size && (List.range a.size).all fun i => f a[i]! b[i]!

/-- Two runs of feed facts, each in its own layout's array: the same length, cap flag and facts in order. -/
def runEq {α : Type} [Inhabited α] (f : α → α → Bool) (xa ya : Array α) (a b : Rows.Rg) : Bool :=
  a.n == b.n && a.over == b.over && (List.range a.n).all fun k => f xa[a.s + k]! ya[b.s + k]!

def deathEq (x y : Death) : Bool := x.id == y.id && x.date == y.date

def exclEq (x y : Exclusion) : Bool := x.id == y.id && x.start == y.start && x.stop == y.stop

def spanEq (x y : Rows.SpanF) : Bool :=
  x.plan == y.plan && x.small == y.small && x.p0 == y.p0 && x.p1 == y.p1 && x.p2 == y.p2 && x.start == y.start &&
    x.stop == y.stop && x.mOk == y.mOk

def eligEq (x y : Rows.EligF) : Bool :=
  x.mOk == y.mOk && x.aidOk == y.aidOk && x.level == y.level && x.start == y.start && x.stop == y.stop

/-- Every field of two layouts but the sources `toRef` reads; the feed facts of each line and unresolved row compared
    through their runs, since the engine's fact arrays are the whole feeds. -/
def sameLay (a b : Rows.Lay) : Bool :=
  a.today == b.today && a.relCh == b.relCh && a.unrCh == b.unrCh && a.dmfSome == b.dmfSome && a.pdSome == b.pdSome &&
  a.exclSome == b.exclSome && a.spanSome == b.spanSome && a.eligSome == b.eligSome && a.dmfOk == b.dmfOk &&
  a.pdOk == b.pdOk && a.exclOk == b.exclOk && a.spanOk == b.spanOk && a.eligOk == b.eligOk &&
  arrEq (fun x y => x.row.same y.row && x.ke == y.ke && x.kn == y.kn && x.ki == y.ki && x.pay == y.pay &&
    runEq deathEq a.dmf b.dmf x.dmf y.dmf && runEq spanEq a.spans b.spans x.span y.span &&
    runEq eligEq a.eligs b.eligs x.elig y.elig &&
    runEq deathEq a.pdeath b.pdeath x.pdP y.pdP && runEq deathEq a.pdeath b.pdeath x.pdR y.pdR &&
    runEq exclEq a.excl b.excl x.exP y.exP && runEq exclEq a.excl b.excl x.exR y.exR && x.fseen == y.fseen)
    a.lines b.lines &&
  arrEq (fun x y => x.kind == y.kind && x.rs == y.rs && x.rn == y.rn && x.rc == y.rc && x.us == y.us && x.un == y.un &&
    x.uc == y.uc) a.slots b.slots &&
  arrEq RowX.same a.relP b.relP && a.relSeq == b.relSeq && arrEq RowX.same a.unrP b.unrP && a.unrSeq == b.unrSeq &&
  arrEq (runEq spanEq a.spans b.spans) a.uSpan b.uSpan && a.uId == b.uId &&
  a.redo.size == b.redo.size && a.redo.toList.all b.redo.contains && a.pRedo == b.pRedo && a.pByp == b.pByp && a.lLim == b.lLim

def sameOut (a b : Rows.Out) : Bool :=
  arrEq (fun x y => x.line == y.line && x.mask == y.mask && x.out == y.out && x.cp == y.cp) a.ds b.ds &&
  a.rel == b.rel && a.unr == b.unr && a.byd == b.byd && a.lft == b.lft

@[noinline] def rKeys (st : HistStore) (req : Array RowX) : IO Ks := pure (keysOf st.ctx req)

@[noinline] def rProbe (st : HistStore) (ks : Array KeyQ) (u : Bool) : IO (Array Hit) := pure (ks.map (st.probe · u))

@[noinline] def rDecode (st : HistStore) (hs : Array Hit) : IO (Array RowX × Array Nat) := pure (st.decode hs)

@[noinline] def rRound2 (st : HistStore) (redo : HashSet W9) (ks : Ks) (ur : Array RowX) :
    IO (Array KeyQ × HashMap ByteArray Nat) := pure (round2Keys st.ctx redo ks ur)

@[noinline] def rAssemble (hr hu : Head) (fc : FCtx) (fx : FeedsX) (redo : HashSet W9) (req : Array RowX)
    (pidx : Array Nat) (ks : Ks) (k2 : Array KeyQ) (smap : HashMap ByteArray Nat) (hu1 hr1 : Array Hit)
    (rr : Array RowX × Array Nat) (ur : Array RowX × Array Nat) : IO Rows.Lay :=
  pure (assemble hr hu fc.today fc.byp fc.lim fx [] redo req pidx ks.idx (fun y => smap.getD (y.keyBytes 2) (ks.keys.size + k2.size))
    hu1 hr1 rr.1 rr.2 ur.1 ur.2)

/-- One batch through the stages, with the time of each in ns (keys, probe, decode, layout assembly, decide), its `Lay`
    and its decisions. -/
def stagedBatch (st : HistStore) (fx : FeedsX) (s : St) (bi : BatchIn) (req : Array RowX) :
    IO (Array Nat × Rows.Lay × Rows.Out) := do
  let fc := fcOf bi
  let pidx := payIdx bi.lines
  let a0 ← IO.monoNanosNow
  let redo := redoW fc.redo
  let ks ← rKeys st req
  let a1 ← IO.monoNanosNow
  let hu1 ← rProbe st ks.keys true
  let hr1a ← rProbe st ks.keys false
  let a2 ← IO.monoNanosNow
  let ur ← rDecode st hu1
  let a3 ← IO.monoNanosNow
  let (k2, smap) ← rRound2 st redo ks ur.1
  let a4 ← IO.monoNanosNow
  let hr2 ← rProbe st k2 false
  let hr1 := hr1a ++ hr2
  let a5 ← IO.monoNanosNow
  let rr ← rDecode st hr1
  let a6 ← IO.monoNanosNow
  let lay ← rAssemble s.rel.head s.unr.head fc fx redo req pidx ks k2 smap hu1 hr1 rr ur
  let a7 ← IO.monoNanosNow
  let o ← runRows lay
  let a8 ← IO.monoNanosNow
  return (#[(a1 - a0) + (a4 - a3), (a2 - a1) + (a5 - a4), (a3 - a2) + (a6 - a5), a7 - a6, a8 - a7], lay, o)

def rowsCorpus (c : Corpus) (passes : Nat) : IO Bool := do
  let (bs, s) ← setup c
  let t0 ← IO.monoNanosNow
  let st ← buildStore (wantedOf s bs) (2 * (c.nRel + c.nUnr))
  let t1 ← IO.monoNanosNow
  let (nrows, rbad) ← rowDecodeCheck st
  IO.println s!"  store built in {fmt ((t1 - t0).toFloat / 1e9)} s; RowX.ofChunk vs RowX.of (getLine ..): {nrows} rows, {rbad} mismatches"
  let (ms, ps) := corpusIds c
  let t2 ← IO.monoNanosNow
  let src ← IO.lazyPure fun _ => encFeeds feeds ms ps
  let t3 ← IO.monoNanosNow
  let some fx ← IO.lazyPure fun _ => decodeFeeds src | throw (IO.userError "feeds: the engine refused the rows the host sent")
  let t4 ← IO.monoNanosNow
  let view := viewOf src
  let per := (t4 - t3).toFloat / 1e3 / (bs.foldl (fun a bi => a + bi.lines.length) 0 / bs.size).toFloat
  IO.println s!"  feeds: dmf {fx.dmf.facts.size}, death {fx.pd.facts.size}, exclusion {fx.ex.facts.size}, span {fx.sp.facts.size} rows; host encode {fmt ((t3 - t2).toFloat / 1e6)} ms; engine decode {fmt ((t4 - t3).toFloat / 1e6)} ms a frame, {fmt per} us/line if sent with every batch"
  let mut bad := 0
  for p in [0:passes] do
    let mut acc : Array Nat := Array.replicate 5 0
    let mut lines := 0
    for bi in bs do
      let req := bi.lines.toArray.map RowX.of
      let (d, lay, o) ← stagedBatch st fx s bi req
      acc := (acc.zip d).map fun (a, b) => a + b
      lines := lines + req.size
      if p == 0 then
        let old := Rows.layout s { fcOf bi with feeds := view } [] bi.lines
        if !sameLay lay old || !sameOut o (Rows.decideRows old) then bad := bad + 1
    let u := fun (i : Nat) => fmt (us 0 acc[i]! lines)
    IO.println s!"  pass {p}: us/line keys {u 0}, probe {u 1}, decode {u 2}, layout {u 3}, decide {u 4} ({lines} lines)"
  IO.println s!"{c.name}: batches unequal to Rows.layout/decideRows {bad}"
  return rbad == 0 && bad == 0

/-! Timers only (`rowsprof`): the sub-steps of the key stage and of the layout assembly, each timed alone. -/

@[noinline] def pKb (req : Array RowX) : IO Nat := do
  let mut n := 0
  for r in req do
    for j in [0:3] do n := n + (r.keyBytes j).size
  pure n

@[noinline] def pKbMap (req : Array RowX) : IO Nat := do
  let mut map : HashMap ByteArray Nat := {}
  for r in req do
    for j in [0:3] do
      let kb := r.keyBytes j
      if !map.contains kb then map := map.insert kb map.size
  pure map.size

@[noinline] def pSlots (nk : Nat) (hu1 hr1 : Array Hit) : IO Nat := do
  let mut slots : Array Rows.Slot := Array.emptyWithCapacity hr1.size
  let mut rs := 0
  let mut us := 0
  for j in [0:hr1.size] do
    let h := hr1[j]!
    let rn := min h.cnt capN
    if j < nk then
      let g := hu1[j]!
      let un := min g.cnt capN
      slots := slots.push { kind := h.kind, rs, rn, rc := h.cnt, us, un, uc := g.cnt }
      us := us + un
    else slots := slots.push { kind := h.kind, rs, rn, rc := h.cnt }
    rs := rs + rn
  pure slots.size

@[noinline] def pUnr (fx : FeedsX) (smap : HashMap ByteArray Nat) (unrP : Array RowX) : IO Nat := do
  let mut n := 0
  for y in unrP do
    n := n + (fx.sp.find y.w4.key).n + smap.getD (y.keyBytes 2) 0
  pure n

@[noinline] def pFeeds (fx : FeedsX) (req : Array RowX) : IO Nat := do
  let mut n := 0
  for r in req do
    n := n + (fx.dmf.find r.w4.key).n + (fx.pd.find r.payee.key).n + (fx.pd.find r.rend.key).n +
      (fx.ex.find r.payee.key).n + (fx.ex.find r.rend.key).n + (fx.sp.find r.w4.key).n
  pure n

@[noinline] def pRest (fc : FCtx) (redo : HashSet W9) (req : Array RowX) (pidx : Array Nat) (ks : Ks) : IO Nat := do
  let np := pidx.foldl (fun m p => max m (p + 1)) 0
  let mut pDone : Array Bool := Array.replicate np false
  let mut pRedo : Array Bool := Array.replicate np false
  let mut pByp : Array (Option UInt32) := Array.replicate np none
  let byp : HashMap W9 UInt32 := fc.byp.foldl (fun m x =>
    if x.1 < 256 ^ payW && !m.contains (W9.ofNat x.1) then m.insert (W9.ofNat x.1) (x.2 % 2 ^ 32).toUInt32 else m) ∅
  let fs : HashSet W7 := ([] : List Nat).foldl (fun s n => if n < 256 ^ idW then s.insert (W7.ofNat n) else s) ∅
  let mut lines : Array Rows.LineIn := Array.emptyWithCapacity req.size
  for i in [0:req.size] do
    let r := req[i]!
    let pj := pidx[i]!
    if !pDone[pj]! then
      pDone := pDone.set! pj true
      pRedo := pRedo.set! pj (r.payIn redo)
      pByp := pByp.set! pj (byp.get? r.w9)
    lines := lines.push
      { row := r, ke := ks.idx[3 * i]!, kn := ks.idx[3 * i + 1]!, ki := ks.idx[3 * i + 2]!, pay := pj, dmf := default,
        span := default, pdP := default, pdR := default, exP := default, exR := default, elig := default,
        fseen := fs.contains r.w7 }
  pure lines.size

def rowsProf (c : Corpus) (passes : Nat) : IO Bool := do
  let (bs, s) ← setup c
  let st ← buildStore (wantedOf s bs) (2 * (c.nRel + c.nUnr))
  let some fx := decodeFeeds (encFeeds feeds (corpusIds c).1 (corpusIds c).2)
    | throw (IO.userError "feeds: the engine refused the rows the host sent")
  for p in [0:passes] do
    let mut acc : Array Nat := Array.replicate 9 0
    let mut lines := 0
    for bi in bs do
      let req := bi.lines.toArray.map RowX.of
      let fc := fcOf bi
      let pidx := payIdx bi.lines
      let redo := redoW fc.redo
      let ks := keysOf st.ctx req
      let hu1 := ks.keys.map (st.probe · true)
      let ur := st.decode hu1
      let (k2, smap) := round2Keys st.ctx redo ks ur.1
      let hr1 := (ks.keys ++ k2).map (st.probe · false)
      let t0 ← IO.monoNanosNow
      let _ ← pKb req
      let t1 ← IO.monoNanosNow
      let _ ← pKbMap req
      let t2 ← IO.monoNanosNow
      let _ ← rKeys st req
      let t3 ← IO.monoNanosNow
      let _ ← pSlots ks.keys.size hu1 hr1
      let t4 ← IO.monoNanosNow
      let _ ← pUnr fx smap ur.1
      let t5 ← IO.monoNanosNow
      let _ ← pFeeds fx req
      let t6 ← IO.monoNanosNow
      let _ ← pRest fc redo req pidx ks
      let t7 ← IO.monoNanosNow
      acc := (acc.zip #[t1 - t0, t2 - t1, t3 - t2, t4 - t3, t5 - t4, t6 - t5, t7 - t6, 0, 0]).map fun (a, b) => a + b
      lines := lines + req.size
    let u := fun (i : Nat) => fmt (us 0 acc[i]! lines)
    IO.println s!"  pass {p}: us/line keyBytes {u 0}, keyBytes+map {u 1}, keysOf {u 2}; slots {u 3}, unrSpans+uId {u 4}, feeds {u 5}, rest {u 6} ({lines} lines)"
  return true

/-- The fields of each fact of an id, sorted: what a feed says about it whatever its row order. -/
def factSet {α : Type} (f : α → List Nat) (xs : List α) : List (List Nat) := (xs.map f).mergeSort lexLeN

def deathF (x : Death) : List Nat := [x.id, x.date]
def exclF (x : Exclusion) : List Nat := [x.id, x.start, x.stop]
def spanFs (x : Span) : List Nat := [x.member, x.plan, x.start, x.stop]

/-- The model's view of the sent bytes holds what `fd` says about the members `ms` and providers `ps`, for every feed
    that is present. -/
def viewSame (fd v : Feeds) (ms ps : List Nat) : Bool :=
  v.dmfSome == fd.dmfSome && v.pdSome == fd.pdSome && v.exclSome == fd.exclSome && v.spanSome == fd.spanSome &&
  (!fd.dmfSome || ms.all fun m => factSet deathF (fd.dmf m) == factSet deathF (v.dmf m)) &&
  (!fd.spanSome || ms.all fun m => factSet spanFs (fd.span m) == factSet spanFs (v.span m)) &&
  (!fd.pdSome || ps.all fun p => factSet deathF (fd.pdeath p) == factSet deathF (v.pdeath p)) &&
  (!fd.exclSome || ps.all fun p => factSet exclF (fd.excl p) == factSet exclF (v.excl p))

/-- A date of 2025 or of January to October 2026 from `x`. -/
def dateOf (x : Nat) : Nat :=
  let y := 2025 + x % 2
  (y * 100 + 1 + x / 2 % (if y == 2026 then 10 else 12)) * 100 + 1 + x / 24 % 28

/-- Heavy feeds: one member in 50 has 100 to 399 deaths and as many spans of mixed plans and dates, one in 997 more
    spans than `capN`; one provider in 100 has 100 to 399 deaths, and another as many exclusion windows.  Usable. -/
def feedsHeavy : Feeds :=
  let many := fun (salt i : Nat) => (List.range (100 + hh salt i % 300)).map fun k => hh (salt + 1) (1000 * i + k)
  { feeds with
    dmf := fun i => if hh 7100 i % 50 == 0 then (many 7101 i).map fun x => ⟨i, dateOf x⟩ else feeds.dmf i,
    pdeath := fun i => if i % 100 == 0 then (many 7103 i).map fun x => ⟨i, dateOf x⟩ else feeds.pdeath i,
    excl := fun i => if i % 100 == 1 then
        (many 7105 i).map fun x => ⟨i, dateOf x, if x % 3 == 0 then 99991231 else 20261231⟩
      else feeds.excl i,
    span := fun i =>
      if hh 7107 i % 997 == 0 then
        (List.range (capN + 76)).map fun k => ⟨i, 1 + k % 7, dateOf (hh 7108 (1000 * i + k)), 20271231⟩
      else if hh 7100 i % 50 == 0 then (many 7109 i).map fun x => ⟨i, 1 + x % 7, dateOf x, dateOf x + (if x % 5 == 0 then 0 else 10000)⟩
      else spanOf i }

/-- A copy of `b` with the `n` bytes at `o` and at `o'` swapped (`o + n ≤ o'`). -/
def swapRows (b : ByteArray) (o o' n : Nat) : ByteArray :=
  b.extract 0 o ++ b.extract o' (o' + n) ++ b.extract (o + n) o' ++ b.extract o (o + n) ++ b.extract (o' + n) b.size

/-- The first of two neighbouring span rows of one member that differ. -/
def runPair (b : ByteArray) : Option Nat :=
  (List.range (b.size / 61 - 1)).find? fun j =>
    (BlindLedger.Gate.Engine3.memAt b (61 * j)).key == (BlindLedger.Gate.Engine3.memAt b (61 * j + 61)).key &&
      (b.extract (61 * j) (61 * j + 61)).data != (b.extract (61 * j + 61) (61 * j + 122)).data

/-- The decoder refuses rows out of order, a cut row and rows on an absent feed, and takes a repeated row as one more
    row of its run; a feed with a row the host cannot encode is sent missing. -/
def refusalCheck : IO Bool := do
  let ms := (List.range 400).map (n33 10)
  let ps := List.range' 1 5000
  let r := encFeeds feeds ms ps
  let (d, p, e, s) := r
  let some fx := decodeFeeds r | return false
  let k0 := (BlindLedger.Gate.Engine3.memAt s.rows 0).key
  let swapped := { s with rows := swapRows s.rows 0 (61 * (s.count - 1)) 61 }
  let cut := { s with rows := s.rows.extract 0 (s.rows.size - 1) }
  let twice := { s with rows := s.rows.extract 0 61 ++ s.rows, count := s.count + 1 }
  let wide : Feeds := { feeds with dmf := fun i => if i == ms[3]! then [⟨i + 2 ^ 257, 20260101⟩] else feeds.dmf i }
  let checks := [
    ("rows out of order are refused", s.count > 1 && (decodeFeeds (d, p, e, swapped)).isNone),
    ("rows of one member out of order are refused",
      match runPair s.rows with
      | some j => (decodeFeeds (d, p, e, { s with rows := swapRows s.rows (61 * j) (61 * j + 61) 61 })).isNone
      | none => false),
    ("a cut row is refused", (decodeFeeds (d, p, e, cut)).isNone),
    ("rows on an absent feed are refused", (decodeFeeds (d, p, e, { s with present := false })).isNone),
    ("a repeated row is one more row of its run",
      match decodeFeeds (d, p, e, twice) with
      | some y => (y.sp.find k0).n == (fx.sp.find k0).n + 1 && y.sp.ok
      | none => false),
    ("a row the host cannot encode sends its feed missing",
      match decodeFeeds (encFeeds wide ms ps) with
      | some y => !y.dmf.present && !y.dmf.ok && y.dmf.facts.isEmpty && y.sp.ok
      | none => false)]
  let mut ok := true
  for (n, v) in checks do
    IO.println s!"  {n}: {if v then "yes" else "NO"}"
    if !v then ok := false
  return ok

/-- The small randomized corpora of `checkAll`, and two of them with heavy feeds (20,000 members and providers,
    hundreds of rows of mixed dates for some): the store layout and decisions against `Rows.layout` and `decideRows`
    over the model's view of the feed bytes sent, and that view against the feeds the host encoded. -/
def rowsCheckAll (per : Nat) : IO Bool := do
  let h0 ← IO.monoMsNow
  let mut ok ← refusalCheck
  let mut total := 0
  let fillM := ((List.range 4000).map (n33 10)).filter (· % 199 == 0)
  let fillP := (List.range' 1 5000).filter fun p => p % 499 == 0 || p % 307 == 0
  let heavyM := (List.range 20000).map (n33 10)
  let heavyP := List.range' 1 20000
  let heavy := encFeeds feedsHeavy heavyM heavyP
  let some hx := decodeFeeds heavy | throw (IO.userError "feeds: the engine refused the heavy rows")
  let hv := viewOf heavy
  let hSame := viewSame feedsHeavy hv heavyM heavyP
  let hOk := hx.dmf.ok && hx.pd.ok && hx.ex.ok && hx.sp.ok && hSame
  IO.println s!"heavy feeds: dmf {hx.dmf.facts.size}, death {hx.pd.facts.size}, exclusion {hx.ex.facts.size}, span {hx.sp.facts.size} rows; usable {[hx.dmf.ok, hx.pd.ok, hx.ex.ok, hx.sp.ok]}, equal to the view {hSame} ({(← IO.monoMsNow) - h0} ms with the refusal tests)"
  if !hOk then ok := false
  let runs := checkCorpora.map (·, false) ++ (checkCorpora.take 2).map fun c => ({ c with name := c.name ++ ", heavy feeds" }, true)
  for (c, isHeavy) in runs do
    let c0 ← IO.monoMsNow
    let mut bad := 0
    let mut rowsN := 0
    let mut t0 := 0
    while t0 < per do
      let n := min 125 (per - t0)
      let bs := (Array.range n).map fun j => genBatch { c with size := 1 + hh 5000 (t0 + j) % c.size } (t0 + j)
      let s := buildSt c bs
      let st ← buildStore (wantedOf s bs) 0
      let (nr, rb) ← rowDecodeCheck st
      rowsN := rowsN + nr
      bad := bad + rb
      for j in [0:n] do
        let t := t0 + j
        let bi := bs.getD j ⟨[], [], [], []⟩
        let fd := if isHeavy then feedsHeavy else feedsV t
        let f := if hh 5001 t % 5 == 0 then (bi.lines.take 3).map (·.id) else []
        let s := if hh 5002 t % 10 == 0 then { s with rel := { s.rel with head := { s.rel.head with count := c.nRel + 1 } } }
          else if hh 5002 t % 10 == 1 then { s with unr := { s.unr with head := { s.unr.head with asOf := today + 1 } } }
          else s
        let (ms, ps) := feedIds s bi
        let (fx, view) ← if isHeavy then pure (hx, hv) else feedsFor fd (ms ++ fillM) (ps ++ fillP)
        let x := layoutStore st s.rel.head s.unr.head today bi.redo bi.byp bi.lim fx f (bi.lines.toArray.map RowX.of)
          (payIdx bi.lines)
        let old := Rows.layout s ⟨today, bi.redo, view, bi.byp, bi.lim⟩ f bi.lines
        if !sameLay x old || !sameOut (Rows.decideRows x) (Rows.decideRows old) || !viewSame fd view ms ps then
          bad := bad + 1
        total := total + 1
      t0 := t0 + n
    IO.println s!"{c.name}: {rowsN} store rows, mismatches {bad} ({(← IO.monoMsNow) - c0} ms)"
    if bad != 0 then ok := false
  IO.println s!"rowscheck: {total} batches, {if ok then "0 mismatches" else "MISMATCHES"}"
  return ok

/-! ## Wide numbers

    Payments and providers that agree in their low 64 bits: no two of them merge in a row compare, the redo set, the
    layout or the decision.  The history holds a line whose id, payee, rendering and procedure are far above 2^64 (the id
    not an `n33`); it is stored, read back and decided exactly.  `wide` runs the case and prints what it checked. -/

def wideCheck : IO Bool := do
  let c : Corpus := ⟨"wide", 1000, 100, false, 1, 10, 100⟩
  let p := 7 * 2 ^ 64 + 5
  let a := genRow c 900 false 1 p
  let b := genRow c 900 false 2 (p + 2 ^ 64)
  let d := genRow c 900 false 3 5
  let e := genRow c 901 false 4 6
  let g := { e with id := n33 902 4, payee := e.payee + 2 ^ 64, rendering := e.rendering + 2 ^ 70, proc := e.proc + 2 ^ 80 }
  -- A stored line whose id, payee and procedure are wide, and a batch line with the same keys.
  let h := { g with id := 2 ^ 300 + 12345, pay := p + 2 ^ 200 }
  let h2 := { h with id := 2 ^ 300 + 12346, pay := 9 }
  let bi : BatchIn := ⟨[a, b, d, e, g, h2], [p], [], []⟩
  let s0 := buildSt c #[bi]
  let ent : Entry := ⟨1, [⟨7, h⟩], zeroDigest⟩
  let hk := [exactKey h, nearKey h, idKey h]
  let s : St := { s0 with rel := { s0.rel with get := fun k => if hk.contains k then ent else s0.rel.get k } }
  let fc0 := fcOf bi
  let st ← buildStore (wantedOf s #[bi]) 0
  let (ms, ps) := feedIds s bi
  let (fx, view) ← feedsFor fc0.feeds ms ps
  let fc := { fc0 with feeds := view }
  let x := Rows.layout s fc [] bi.lines
  let y := layoutStore st s.rel.head s.unr.head today bi.redo bi.byp bi.lim fx [] (bi.lines.toArray.map RowX.of)
    (payIdx bi.lines)
  let rd ← rowDecodeCheck st
  let ra := RowX.of a
  IO.println s!"  rows read {rd.1}, undecodable {rd.2}, history rows in layout {y.relP.size}"
  let ok := [
    ("payments of one low word are three rows", !ra.same (RowX.of b) && !ra.payEq (RowX.of b) && !ra.payEq (RowX.of d)),
    ("payments are four positions", x.lines.map (·.pay) == #[0, 1, 2, 3, 3, 4] && (payIdx bi.lines) == #[0, 1, 2, 3, 3, 4]),
    ("only the redone payment is redone", x.pRedo == #[true, false, false, false, false] && sameLay x y),
    ("the redo words name one payment", ra.payIn (redoW [p]) && !(RowX.of b).payIn (redoW [p]) && !(RowX.of d).payIn (redoW [p])),
    ("a redone payment of 2^576 or more matches nothing", !ra.payIn (redoW [p + 2 ^ 576])),
    ("providers and procedures that differ high are different keys", !(RowX.of e).exactEq (RowX.of g) && !(RowX.of e).nearEq (RowX.of g)),
    ("a wide line is stored and read back exactly", rd.1 == 2 && rd.2 == 0 && y.relP.size == 2 && y.relP.all (·.same (RowX.of h))),
    ("decisions equal the reference", (Rows.decideRows x).toRef x == Rows.project (decideBatchIdx s fc [] bi.lines) &&
      sameOut (Rows.decideRows y) (Rows.decideRows x))]
  let mut all := true
  for (n, v) in ok do
    IO.println s!"  {n}: {if v then "yes" else "NO"}"
    if !v then all := false
  return all

/-! ## Memory of the rows check

    `rowsmem <corpus> <batches>` runs the rows check's work on batches of one check corpus and prints, per batch, the
    committed megabytes after each stage (feeds, engine layout, model layout, compare), after the allocator returns
    what it can, and the resident megabytes.  Flat numbers mean the check keeps nothing from one batch to the next. -/

/-- Committed bytes (resident bytes when `rss`) of this process, as the allocator reports them. -/
@[extern c inline "({ size_t e_, u_, s_, r_, pr_, c_, pc_, f_; mi_process_info(&e_, &u_, &s_, &r_, &pr_, &c_, &pc_, &f_); lean_io_result_mk_ok(lean_box_usize(#1 ? r_ : c_)); })"]
opaque memNow (rss : Bool) : IO USize

/-- The allocator returns its free memory to the system. -/
@[extern c inline "(mi_collect(true), lean_io_result_mk_ok(lean_box(0)))"]
opaque memCollect : IO Unit

def rowsMem (nm : String) (n : Nat) : IO Bool := do
  let some c := checkCorpora.find? (·.name == nm) | throw (IO.userError s!"unknown check corpus {nm}")
  let mb := fun (x : USize) => x.toNat / 1048576
  let fillM := ((List.range 4000).map (n33 10)).filter (· % 199 == 0)
  let fillP := (List.range' 1 5000).filter fun p => p % 499 == 0 || p % 307 == 0
  let bs := (Array.range n).map fun t => genBatch { c with size := 1 + hh 5000 t % c.size } t
  let s := buildSt c bs
  let st ← buildStore (wantedOf s bs) 0
  memCollect
  let c0 ← memNow false
  IO.println s!"{nm}: {n} batches; committed MB after the store {mb c0}"
  let mut bad := 0
  for t in [0:n] do
    let bi := bs.getD t ⟨[], [], [], []⟩
    let fd := feedsV t
    let f := if hh 5001 t % 5 == 0 then (bi.lines.take 3).map (·.id) else []
    let s := if hh 5002 t % 10 == 0 then { s with rel := { s.rel with head := { s.rel.head with count := c.nRel + 1 } } }
      else if hh 5002 t % 10 == 1 then { s with unr := { s.unr with head := { s.unr.head with asOf := today + 1 } } }
      else s
    let (ms, ps) := feedIds s bi
    let m0 ← memNow false
    let (fx, view) ← feedsFor fd (ms ++ fillM) (ps ++ fillP)
    if fx.sp.facts.size == 1000000007 then IO.println "."
    let m1 ← memNow false
    let x := layoutStore st s.rel.head s.unr.head today bi.redo bi.byp bi.lim fx f (bi.lines.toArray.map RowX.of)
      (payIdx bi.lines)
    if x.lines.size == 1000000007 then IO.println "."
    let m2 ← memNow false
    let old := Rows.layout s ⟨today, bi.redo, view, bi.byp, bi.lim⟩ f bi.lines
    if old.lines.size == 1000000007 then IO.println "."
    let m3 ← memNow false
    if !sameLay x old || !sameOut (Rows.decideRows x) (Rows.decideRows old) || !viewSame fd view ms ps then
      bad := bad + 1
    let m4 ← memNow false
    memCollect
    let m5 ← memNow false
    let r ← memNow true
    IO.println s!"  batch {t}: {bi.lines.length} lines, {ms.length} member ids; committed MB {mb m0} feeds {mb m1} engine {mb m2} model {mb m3} compare {mb m4} collected {mb m5}; resident {mb r}"
  IO.println s!"rowsmem: {n} batches, mismatches {bad}"
  return bad == 0

end BlindLedger.Gate.Flat.DecideBench

open BlindLedger.Gate.Flat.DecideBench in
def main (args : List String) : IO UInt32 := do
  match args with
  | ["time", n] => match find n with
    | some c => timeCorpus c; return 0
    | none => IO.eprintln s!"unknown corpus {n}"; return 2
  | ["check", n] => return if (← checkAll n.toNat!) then 0 else 1
  | ["setup", n] => match find n with
    | some c => let _ ← setup c; return 0
    | none => IO.eprintln s!"unknown corpus {n}"; return 2
  | ["split", n] => match find n with
    | some c => return if (← splitCorpus c) then 0 else 1
    | none => IO.eprintln s!"unknown corpus {n}"; return 2
  | ["rows", n, p] => match find n with
    | some c => return if (← rowsCorpus c p.toNat!) then 0 else 1
    | none => IO.eprintln s!"unknown corpus {n}"; return 2
  | ["rowsprof", n, p] => match find n with
    | some c => return if (← rowsProf c p.toNat!) then 0 else 1
    | none => IO.eprintln s!"unknown corpus {n}"; return 2
  | ["wide"] => return if (← wideCheck) then 0 else 1
  | ["rowscheck", n] => return if (← rowsCheckAll n.toNat!) then 0 else 1
  | ["rowsmem", c, n] => return if (← rowsMem c n.toNat!) then 0 else 1
  | _ => IO.eprintln "usage: decide_bench time|split|setup|rows <corpus> | check|rowscheck <batches per corpus> | rowsmem <check corpus> <batches> | wide"; return 2
