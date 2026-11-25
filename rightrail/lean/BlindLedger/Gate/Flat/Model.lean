import BlindLedger.Gate.OnepIndex

/-! The history-flat gate as a pure model (design rrb/designs/flat-r1.md; formats conformance/FLAT_V1.md).

    Each set (released, unresolved) is a key index `SetIdx`: a map from a rule key (`keys`: exact, near, id) to an
    `Entry` (row count, the first `capN` postings `(seq, row)` in row order, a running hash of the rest), the set's
    rows per core (`coreKey`), and the set's head (date, declared count, rows held).  A batch reads history only
    through `fetch`: the entries of its lines' keys in both sets (round 1) and, for each fetched unresolved CAP_820 row
    of a redone payment, that row's id key in the released set (round 2, for `own`), with the row counts of their
    cores.  The reference feeds are read by member and provider id, at most `capN` facts each.  `decideFetched` runs
    the unchanged indexed rules (`Rules.Fast.Ix`) on an index built from those reads alone.  A line that reads anything
    cut short is HOLD with `POSTING_CAP` (fail closed, row by row; `capped`); the cap counts per core (`capCount`), so a
    line whose core holds more than `capN` rows in either set is HOLD.  The state is
    carried (`Spec.carried`): the sets read are the gate's own checkpoints, so `loose` is empty and `chained` is
    `Head.chained`.

    The set history is bound by a hash chain (CHAIN/v1): `D' = H (dom ‖ 0x01 ‖ D ‖ auth ‖ delta)`, auth the shard's
    authority record after the batch and delta the rows the batch appends to each set (`Spec.addsOf`), over a genesis
    `H (dom ‖ 0x00 ‖ shard ‖ pin ‖ sets)`.  `H` is SHA3-512 at runtime;
    statements take it as a parameter and name the two colliding inputs where they need one.  The
    statements are in `Flat/Theorems.lean`.  Synthetic, nonpayment, non-PHI, activation=false. -/

namespace BlindLedger.Gate.Flat

open BlindLedger.Gate.Rules BlindLedger.Gate.Rules.Fast
open BlindLedger.Gate.OnepIndex (leb unleb capD)
open Std (HashMap HashSet)

/-- The width of the shard's authority record (`Worker.encAuth`): pin 64, epoch 4, ratchet head 64, day 4,
    checkpoint 64, floor 8, rule-set digest 64, rule-set version 4.  The only definition of it: both engines, the answer
    format and the store log use this. -/
def authLen : Nat := 276

/-! ## Codec: minimal LEB128 (`OnepIndex.leb`) -/

def unlebN : Nat → Bytes → Option (List Nat × Bytes)
  | 0, r => some ([], r)
  | n + 1, r => do
    let (a, r) ← unleb r
    let (as, r) ← unlebN n r
    pure (a :: as, r)

/-- Exactly `n` bytes. -/
def takeN (n : Nat) (bs : Bytes) : Option (Bytes × Bytes) :=
  if n ≤ bs.length then some (bs.take n, bs.drop n) else none

/-- `takeN` in one walk of the `n` bytes (`takeN` measures the whole remainder at every call, so decoding a file with it
    costs the square of the file's length).  The long-remainder decoders call it; `takeN_fast` says it is `takeN`. -/
def takeNFast (n : Nat) (bs : Bytes) : Option (Bytes × Bytes) :=
  go n bs []
where
  go : Nat → Bytes → Bytes → Option (Bytes × Bytes)
    | 0, r, acc => some (acc.reverse, r)
    | _ + 1, [], _ => none
    | n + 1, b :: r, acc => go n r (b :: acc)

theorem takeNFast_go (n : Nat) : ∀ (bs acc : Bytes),
    takeNFast.go n bs acc = if n ≤ bs.length then some (acc.reverse ++ bs.take n, bs.drop n) else none := by
  induction n with
  | zero => intro bs acc; simp [takeNFast.go]
  | succ n ih =>
    intro bs acc
    cases bs with
    | nil => simp [takeNFast.go]
    | cons b r => simp [takeNFast.go, ih]

theorem takeN_fast : @takeN = @takeNFast := by
  funext n bs
  simp [takeN, takeNFast, takeNFast_go]

/-- The decoders that loop over a long remainder call `takeNFast`; every proof about them reads it as `takeN`. -/
@[simp] theorem takeNFast_eq (n : Nat) (bs : Bytes) : takeNFast n bs = takeN n bs := by
  simp [takeN, takeNFast, takeNFast_go]

/-- A key (a number list): its length, then each number. -/
def encKey (k : Key) : Bytes := leb k.length ++ k.flatMap leb

def flowOf : Nat → Option Flow
  | 1 => some .FFS_CYCLE
  | 2 => some .FFS_CLAIM
  | 3 => some .CAP_820
  | _ => none

/-- A row: the ten numbers of `Spec.enc` (flow tag, member, payee, rendering, date, proc, units, cents, id, pay). -/
def encLine (l : Line) : Bytes := (enc l).flatMap leb

def decLine (bs : Bytes) : Option (Line × Bytes) := do
  let (xs, r) ← unlebN 10 bs
  match xs with
  | [t, m, py, rd, dt, pr, u, ct, i, p] =>
    let fl ← flowOf t
    pure (⟨i, p, fl, m, py, rd, dt, pr, u, ct⟩, r)
  | _ => none

/-! ## Entries -/

/-- Postings an entry holds in full, and facts read per feed id.  Past it a line is HOLD with `POSTING_CAP`. -/
def capN : Nat := 1024

/-- A row of a set under one of its keys: its position in the set (`seq`, from 0) and the row (the decider reads its
    fields: `claim`, `own`, counterparts). -/
structure Posting where
  seq : Nat
  row : Line
  deriving DecidableEq, Repr

/-- A key's entry: how many rows hold the key, the first `min count capN` of them in row order, and the running hash of
    the postings past `capN` (`zeroDigest` while there are none). -/
structure Entry where
  count : Nat
  head : List Posting
  tail : Bytes
  deriving DecidableEq, Repr

def encPosting (p : Posting) : Bytes := leb p.seq ++ encLine p.row

def Entry.empty : Entry := ⟨0, [], zeroDigest⟩

/-- Appends one posting: into `head` below `capN`, else into `tail`. -/
def Entry.push (H : Bytes → Bytes) (e : Entry) (p : Posting) : Entry :=
  if e.head.length < capN then { e with count := e.count + 1, head := e.head ++ [p] }
  else { e with count := e.count + 1, tail := H (domain "INDEX/TAIL" ++ e.tail ++ encPosting p) }

/-- An `Entry` with its postings in an array, so a posting appends in constant time (`Entry.push`'s list append costs
    the entry's length).  `EntryA.push_eq` states it equal to `Entry.push`. -/
structure EntryA where
  count : Nat
  head : Array Posting
  tail : Bytes

def EntryA.toEntry (e : EntryA) : Entry := ⟨e.count, e.head.toList, e.tail⟩

def Entry.toA (e : Entry) : EntryA := ⟨e.count, e.head.toArray, e.tail⟩

def EntryA.push (H : Bytes → Bytes) (e : EntryA) (p : Posting) : EntryA :=
  if e.head.size < capN then { e with count := e.count + 1, head := e.head.push p }
  else { e with count := e.count + 1, tail := H (domain "INDEX/TAIL" ++ e.tail ++ encPosting p) }

def encEntry (e : Entry) : Bytes :=
  leb e.count ++ leb e.head.length ++ e.head.flatMap encPosting ++ leb e.tail.length ++ e.tail

def decPostings : Nat → Bytes → Option (List Posting × Bytes)
  | 0, r => some ([], r)
  | n + 1, r => do
    let (s, r) ← unleb r
    let (l, r) ← decLine r
    let (ps, r) ← decPostings n r
    pure (⟨s, l⟩ :: ps, r)

/-- Strictly rising `seq`. -/
def rising (ps : List Posting) : Bool := (ps.zip (ps.drop 1)).all fun (p, q) => p.seq < q.seq

/-- What `decEntry` accepts: `head` is `min count capN` postings with rising `seq`, `tail` a digest. -/
def Entry.Wf (e : Entry) : Prop :=
  e.head.length = min e.count capN ∧ e.tail.length = digestBytes ∧ rising e.head = true

/-- Canonical bytes only (all used, `Entry.Wf`); anything else is corruption (`none`: the batch HOLDs). -/
def decEntry (bs : Bytes) : Option Entry := do
  let (c, r) ← unleb bs
  let (n, r) ← unleb r
  let (ps, r) ← decPostings n r
  let (tl, r) ← unleb r
  let (t, r) ← takeN tl r
  if r.isEmpty && n == min c capN && t.length == digestBytes && rising ps then pure ⟨c, ps, t⟩ else none

/-- Row `i` onward of `rows`, under key `k`. -/
def postingsFrom (k : Key) : Nat → List Line → List Posting
  | _, [] => []
  | i, l :: ls => if (keys l).contains k then ⟨i, l⟩ :: postingsFrom k (i + 1) ls else postingsFrom k (i + 1) ls

/-- The entry of `k` over a set's rows (the index invariant's right side). -/
def entryOf (H : Bytes → Bytes) (rows : List Line) (k : Key) : Entry :=
  (postingsFrom k 0 rows).foldl (Entry.push H) Entry.empty

/-! ## Set index -/

/-- A line's core: tag 5, member and month for a CAP_820 line; tag 6, member, date and procedure for any other.  Every
    exact and near key of the line lies inside it.  It agrees with the engine's core bytes (`Engine3.Hist.coreBytes`)
    for lines that pass `fitsLine2` (`Engine3.Hist.rowX_coreEq_iff`, on the core test). -/
def coreKey (l : Line) : Key := if isCap l then [5, l.member, l.date / 100] else [6, l.member, l.date, l.proc]

/-- The core of an exact or near key (`keys`); an id key has none. -/
def keyCore : Key → Option Key
  | [1, m, _, d, p, _, _] => some [6, m, d, p]
  | [3, m, _, d, _, _, _] => some [5, m, d / 100]
  | [2, m, _, d, p] => some [6, m, d, p]
  | [0, m, mo] => some [5, m, mo]
  | _ => none

theorem keyCore_exact (l : Line) : keyCore (exactKey l) = some (coreKey l) := by
  cases h : isCap l <;> simp [exactKey, coreKey, keyCore, h]

theorem keyCore_near (l : Line) : keyCore (nearKey l) = some (coreKey l) := by
  cases h : isCap l <;> simp [nearKey, coreKey, keyCore, h]

theorem keyCore_id (l : Line) : keyCore (idKey l) = none := rfl

/-- A set's date, declared count, and rows held (`n`, the next `seq`). -/
structure Head where
  asOf : Nat
  count : Nat
  n : Nat
  deriving DecidableEq, Repr

/-- `Spec.chained` of a carried set (the set read is the prior, so the containment and date order hold). -/
def Head.chained (h : Head) (today : Nat) : Bool := h.n == h.count && validDate h.asOf && h.asOf ≤ today

structure SetIdx where
  head : Head
  get : Key → Entry
  /-- Rows per core (`coreKey`). -/
  core : Key → Nat

/-- `x` indexes exactly `s`: its head is `s`'s, and every key maps to its rows' entry. -/
def IdxInv (H : Bytes → Bytes) (x : SetIdx) (s : Snapshot Line) : Prop :=
  x.head = ⟨s.asOf, s.count, s.entries.length⟩ ∧ ∀ k, x.get k = entryOf H s.entries k

/-- `x` counts the rows of `s` per core. -/
def CoreInv (x : SetIdx) (s : Snapshot Line) : Prop := ∀ c, x.core c = (s.entries.filter (coreKey · == c)).length

/-- One appended row: a posting under each of its three keys (pairwise distinct: kinds 1/3, 0/2, 4), one more row
    of its core. -/
def SetIdx.add (H : Bytes → Bytes) (x : SetIdx) (l : Line) : SetIdx :=
  let p : Posting := ⟨x.head.n, l⟩
  { head := { x.head with n := x.head.n + 1 },
    get := fun k => if (keys l).contains k then (x.get k).push H p else x.get k,
    core := fun c => if c == coreKey l then x.core c + 1 else x.core c }

/-- `Spec.advance` on the index: rows appended, count = rows (as `advance` sets it). -/
def SetIdx.addRows (H : Bytes → Bytes) (x : SetIdx) (adds : List Line) : SetIdx :=
  let y := adds.foldl (SetIdx.add H) x
  { y with head := { y.head with count := x.head.n + adds.length } }

/-! ## Feeds (not history: fixed per snapshot, read by id) -/

/-- The four reference snapshots by id, with their presence and usability fixed when the snapshot is installed. -/
structure Feeds where
  dmfSome : Bool
  pdSome : Bool
  exclSome : Bool
  spanSome : Bool
  dmfOk : Bool
  pdOk : Bool
  exclOk : Bool
  spanOk : Bool
  dmf : Nat → List Death
  pdeath : Nat → List Death
  excl : Nat → List Exclusion
  span : Nat → List Span

/-- What a frame carries besides the lines: today, the redone payments, the feeds. -/
structure FCtx where
  today : Nat
  redo : List Nat
  feeds : Feeds
  /-- The admitted bypasses of the batch (`Ctx.byp`). -/
  byp : List (Nat × Nat)
  /-- The HOLD-level payments and their holds masks (`Ctx.lim`). -/
  lim : List (Nat × Nat)

def FCtxInv (fc : FCtx) (c : Ctx) : Prop :=
  fc.today = c.today ∧ fc.redo = c.redo ∧
  fc.feeds.dmfSome = c.dmf.isSome ∧ fc.feeds.pdSome = c.providerDeaths.isSome ∧
  fc.feeds.exclSome = c.exclusions.isSome ∧ fc.feeds.spanSome = c.enrollment.isSome ∧
  fc.feeds.dmfOk = usable c.today 90 okDeath c.dmf ∧ fc.feeds.pdOk = usable c.today 90 okDeath c.providerDeaths ∧
  fc.feeds.exclOk = usable c.today 31 okExclusion c.exclusions ∧ fc.feeds.spanOk = usable c.today 7 okSpan c.enrollment ∧
  (∀ i, fc.feeds.dmf i = (entries c.dmf).filter (·.id == i)) ∧
  (∀ i, fc.feeds.pdeath i = (entries c.providerDeaths).filter (·.id == i)) ∧
  (∀ i, fc.feeds.excl i = (entries c.exclusions).filter (·.id == i)) ∧
  (∀ i, fc.feeds.span i = (entries c.enrollment).filter (·.member == i)) ∧ fc.byp = c.byp ∧ fc.lim = c.lim

/-- The facts the decider may use of one id. -/
def facts {α : Type} (xs : List α) : List α := xs.take capN

def feedOver {α : Type} (xs : List α) : Bool := capN < xs.length

structure St where
  rel : SetIdx
  unr : SetIdx

/-- `s` without its core counts: the state a store that keeps none decides on, which caps per key. -/
def St.perKey (s : St) : St := ⟨{ s.rel with core := fun _ => 0 }, { s.unr with core := fun _ => 0 }⟩

/-! ## Fetch: every history read of a batch -/

def uniqStep (acc : HashSet Key × List Key) (k : Key) : HashSet Key × List Key :=
  if acc.1.contains k then acc else (acc.1.insert k, k :: acc.2)

/-- First occurrences, in order. -/
def uniq (ks : List Key) : List Key := (ks.foldl uniqStep (∅, [])).2.reverse

def probeKeys (b : List Line) : List Key := uniq (b.flatMap keys)

/-- The postings the decider may use (at most `capN`, whatever the entry claims). -/
def heads (e : Entry) : List Posting := e.head.take capN

/-- Round 2: id keys of unresolved CAP_820 rows of redone payments, whose `claim` reads `own`. -/
def round2 (redo : List Nat) (ks : List Key) (u : List (Key × Entry)) : List Key :=
  let known := HashSet.ofList ks
  uniq ((u.flatMap fun ke => (heads ke.2).filterMap fun p =>
    if isCap p.row && redo.contains p.row.pay then some (idKey p.row) else none).filter fun k => !known.contains k)

structure Fetched where
  rel : List (Key × Entry)
  unr : List (Key × Entry)
  /-- Rows per core in each set; the decision reads the cores of the fetched keys (`capCount`). -/
  relCore : Key → Nat
  unrCore : Key → Nat

/-- All keys of the batch are read together (one prefetch, design §2.3), then round 2. -/
def fetch (s : St) (redo : List Nat) (b : List Line) : Fetched :=
  let ks := probeKeys b
  let u := ks.map fun k => (k, s.unr.get k)
  ⟨(ks ++ round2 redo ks u).map fun k => (k, s.rel.get k), u, s.rel.core, s.unr.core⟩

/-! ## Decide from the fetched entries -/

def dedupSeq : List Posting → List Posting
  | p :: t@(q :: _) => if p.seq == q.seq then dedupSeq t else p :: dedupSeq t
  | t => t

/-- The fetched rows of a set, each once, in row order. -/
def localRows (es : List (Key × Entry)) : List Posting :=
  dedupSeq ((es.flatMap fun ke => heads ke.2).mergeSort fun p q => decide (p.seq ≤ q.seq))

/-- Each key's postings as positions in `localRows` (an order-preserving renumbering of `seq`). -/
def postMap (ps : List Posting) (es : List (Key × Entry)) : HashMap Key (List Nat) :=
  let pos := (ps.foldl (fun (acc : HashMap Nat Nat × Nat) p => (acc.1.insert p.seq acc.2, acc.2 + 1)) (∅, 0)).1
  es.foldl (fun m ke => m.insert ke.1 ((heads ke.2).filterMap fun p => pos.get? p.seq)) ∅

def idMap {α : Type} (g : Nat → List α) (ids : List Nat) : HashMap Nat (List α) :=
  ids.foldl (fun m i => m.insert i (facts (g i))) ∅

def members (b : List Line) : List Nat := b.map (·.member)

def parties (b : List Line) : List Nat := b.flatMap fun l => [l.payee, l.rendering]

/-- Spans are read for the batch's members and for the fetched unresolved rows' members (their `claim`). -/
def spanIds (b : List Line) (ur : List Posting) : List Nat := members b ++ ur.map (·.row.member)

/-- `Rules.Fast.Ix` over the fetched rows `rr`, `ur` only.  `relV`/`unrV` carry no rows: the decisions never read
    them. -/
def localIx (hr hu : Head) (fe : Fetched) (rr ur : List Posting) (fc : FCtx) (b : List Line) : Ix :=
  let fd := fc.feeds
  { today := fc.today, redo := HashSet.ofList fc.redo, byp := fc.byp, lim := fc.lim, batch := HashSet.ofList b,
    relChained := hr.chained fc.today, unrChained := hu.chained fc.today,
    relV := ⟨hr.asOf, hr.count, []⟩, unrV := ⟨hu.asOf, hu.count, []⟩,
    relN := rr.length, unrN := ur.length, rel := (rr.map (·.row)).toArray, unr := (ur.map (·.row)).toArray,
    relPost := postMap rr fe.rel, unrPost := postMap ur fe.unr, looseKeys := ∅,
    dmfSome := fd.dmfSome, pdSome := fd.pdSome, exclSome := fd.exclSome, spanSome := fd.spanSome,
    dmfOk := fd.dmfOk, pdOk := fd.pdOk, exclOk := fd.exclOk, spanOk := fd.spanOk,
    dmf := idMap fd.dmf (members b), pdeath := idMap fd.pdeath (parties b), excl := idMap fd.excl (parties b),
    span := idMap fd.span (spanIds b ur) }

/-! ## Caps: what a line may not decide on -/

/-- A released id-key entry cut short: `own` (and so the decision order of the whole batch) may be wrong. -/
def idCapped (fe : Fetched) : Bool := fe.rel.any fun ke => ke.1.head? == some 4 && capN < ke.2.count

/-- One of the line's own feed reads is cut short. -/
def feedCapped (fd : Feeds) (l : Line) : Bool :=
  feedOver (fd.dmf l.member) || feedOver (fd.span l.member) ||
    [l.payee, l.rendering].any fun i => feedOver (fd.pdeath i) || feedOver (fd.excl i)

/-- The row count a read of key `k` (entry `e`) gives the cap: its core's (`core`) when the core holds more than
    `capN` rows, else the key's own.  The cap counts per core (engine `Hist.readKey`); an id key has no core. -/
def capCount (core : Key → Nat) (k : Key) (e : Entry) : Nat :=
  match keyCore k with
  | some c => if capN < core c then core c else e.count
  | none => e.count

/-- Keys whose readers may see a wrong answer: an entry cut short or in a core of more than `capN` rows
    (`capCount`), a key of a fetched unresolved CAP_820 row or of a CAP_820 line of the batch whose member's spans are
    cut short (its `claim` reads them). -/
def hotKeys (fe : Fetched) (fd : Feeds) (b : List Line) : HashSet Key :=
  HashSet.ofList ((fe.rel.filter fun ke => capN < capCount fe.relCore ke.1 ke.2).map (·.1) ++
    (fe.unr.filter fun ke => capN < capCount fe.unrCore ke.1 ke.2).map (·.1) ++
    (fe.unr.filter fun ke => (heads ke.2).any fun p => isCap p.row && feedOver (fd.span p.row.member)).map (·.1) ++
    (b.filter fun m => isCap m && feedOver (fd.span m.member)).flatMap keys)

/-- The line HOLDs with `POSTING_CAP`. -/
def capped (hot : HashSet Key) (fe : Fetched) (fd : Feeds) (l : Line) : Bool :=
  idCapped fe || (keys l).any hot.contains || feedCapped fd l

/-- `capped` with `idCapped fe` given: `decideFetched` computes it once per batch, not once per line. -/
def cappedWith (ic : Bool) (hot : HashSet Key) (fd : Feeds) (l : Line) : Bool :=
  ic || (keys l).any hot.contains || feedCapped fd l

theorem cappedWith_eq (hot : HashSet Key) (fe : Fetched) (fd : Feeds) (l : Line) :
    cappedWith (idCapped fe) hot fd l = capped hot fe fd l := rfl

/-- No line of the batch is capped: the case `decideBatchIdx_eq` covers. -/
def Uncapped (fe : Fetched) (fd : Feeds) (b : List Line) : Prop := ∀ l ∈ b, capped (hotKeys fe fd b) fe fd l = false

/-- Decisions, then the rows appended to the released and unresolved sets. -/
def decideFetched (hr hu : Head) (fe : Fetched) (fc : FCtx) (f : List Nat) (b : List Line) :
    List Decision × List Line × List Line :=
  let ur := localRows fe.unr
  let x := localIx hr hu fe (localRows fe.rel) ur fc b
  let hot := hotKeys fe fc.feeds b
  let ic := idCapped fe
  let ds := (x.decideAll (HashSet.ofList (idSeen f)) (x.order b)).map fun d =>
    if cappedWith ic hot fc.feeds d.line then capD d else d
  (ds, x.releasedLines ds, x.unresolvedLines ds)

def decideBatchIdx (s : St) (fc : FCtx) (f : List Nat) (b : List Line) : List Decision × List Line × List Line :=
  decideFetched s.rel.head s.unr.head (fetch s fc.redo b) fc f b

def St.apply (H : Bytes → Bytes) (s : St) (r : List Decision × List Line × List Line) : St :=
  ⟨s.rel.addRows H r.2.1, s.unr.addRows H r.2.2⟩

/-! ## Work: every history and feed read of a batch, counted -/

/-- One unit per entry read, one per posting handed to the decider. -/
def entryWork (es : List (Key × Entry)) : Nat := (es.map fun ke => 1 + (heads ke.2).length).sum

/-- One unit per feed id read, one per fact handed to the decider. -/
def factWork {α : Type} (g : Nat → List α) (ids : List Nat) : Nat := (ids.map fun i => 1 + (facts (g i)).length).sum

def work (fe : Fetched) (fd : Feeds) (b : List Line) : Nat :=
  entryWork fe.rel + entryWork fe.unr + factWork fd.dmf (members b) + factWork fd.span (spanIds b (localRows fe.unr)) +
    factWork fd.pdeath (parties b) + factWork fd.excl (parties b)

/-- Per line: 3 keys in each set, at most one round-2 id key and one span read per fetched unresolved posting, 6 feed
    ids; each read at most `1 + capN` units.  No term depends on the history. -/
def workC : Nat := (12 + 6 * capN) * (1 + capN)

/-! ## CHAIN/v1 -/

def encSet (s : Snapshot Line) : Bytes := leb s.asOf ++ leb s.count ++ leb s.entries.length ++ s.entries.flatMap encLine

/-- What one batch appends: released rows, unresolved rows (`Spec.batchFresh`). -/
def encDelta (d : List Line × List Line) : Bytes :=
  leb d.1.length ++ d.1.flatMap encLine ++ leb d.2.length ++ d.2.flatMap encLine

/-- The genesis of shard `k` under key-set genesis pin `pin`, its sets `g`. -/
def chainStart (H : Bytes → Bytes) (k : Nat) (pin : Bytes) (g : Snapshot Line × Snapshot Line) : Bytes :=
  H (domain "CHAIN" ++ [0x00] ++ leb k ++ leb pin.length ++ pin ++ encSet g.1 ++ encSet g.2)

/-- One batch: `s.1` the shard's authority record after it (`Worker.encAuth`), `s.2` the rows it appends. -/
def chainStep (H : Bytes → Bytes) (D : Bytes) (s : Bytes × (List Line × List Line)) : Bytes :=
  H (domain "CHAIN" ++ [0x01] ++ D ++ leb s.1.length ++ s.1 ++ encDelta s.2)

/-- The head after the batches `ds` (authority record, `Spec.addsOf` delta) of shard `k` from genesis `g` under `pin`; its
    sets are `Spec.replay g (ds.map (·.2))`. -/
def chainHead (H : Bytes → Bytes) (k : Nat) (pin : Bytes) (g : Snapshot Line × Snapshot Line)
    (ds : List (Bytes × (List Line × List Line))) : Bytes :=
  ds.foldl (chainStep H) (chainStart H k pin g)

end BlindLedger.Gate.Flat
