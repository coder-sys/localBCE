import Std.Data.HashMap
import Std.Data.HashSet
import BlindLedger.Gate.Spec
import BlindLedger.Gate.Rules.Spec

/-! Indexed twin of `Spec.decideBatch` and `pinInput` (design rrb/designs/gate-rules-fast-v1.md); `FastEq.lean` proves it equal. -/

namespace BlindLedger.Gate.Rules.Fast

open BlindLedger.Gate.Rules
open Std (HashMap HashSet)

/-! Indexed twin of `decideBatch` and `pinInput`.  Each list scan of the Spec is answered from an
    index built once per batch; `FastEq.lean` proves `decideBatchF c b = decideBatch c b` and
    `pinBytes_eq` for all inputs.  Indexes are only probed (`contains`, `getD`), never iterated, so no
    output depends on hash order.  Synthetic, nonpayment, activation=false. -/

instance : Hashable Line where
  hash l := mixHash (hash l.id) <| mixHash (hash l.pay) <| mixHash (hash l.flow.tag) <|
    mixHash (hash l.member) <| mixHash (hash l.payee) <| mixHash (hash l.rendering) <|
    mixHash (hash l.date) <| mixHash (hash l.proc) <| mixHash (hash l.units) (hash l.cents)

/-! ## Index primitives -/

/-- Rows by an identifier: `getD k []` holds exactly the rows whose `key` is `k` (`mem_group`). -/
def group {α : Type} (key : α → Nat) (xs : List α) : HashMap Nat (List α) :=
  xs.foldl (fun m x => m.insert (key x) (x :: m.getD (key x) [])) ∅

/-- One row of `posts`: each of row `n`'s keys lists `n`. -/
def postStep (acc : HashMap Key (List Nat) × Nat) (x : Line) : HashMap Key (List Nat) × Nat :=
  ((keys x).foldl (fun m k => m.insert k (acc.2 :: m.getD k [])) acc.1, acc.2 + 1)

/-- Each key's row positions in `xs` (`mem_posts`), and the row count.  A fold, so a writer that
    keeps it extends it by the appended rows alone (`posts_append`). -/
def posts (xs : List Line) : HashMap Key (List Nat) × Nat := xs.foldl postStep (∅, 0)

/-- Drops adjacent repeats. -/
def dedup : List Nat → List Nat
  | a :: t@(b :: _) => if a == b then dedup t else a :: dedup t
  | t => t

/-- The ids, in row order and each once, of the rows of `xs` that share a key of `ks` and pass `p`. -/
def hits (xs : Array Line) (post : HashMap Key (List Nat)) (ks : List Key) (p : Line → Bool) : List Nat :=
  (dedup ((ks.flatMap (post.getD · [])).mergeSort fun i j => decide (i ≤ j))).filterMap fun i =>
    xs[i]?.bind fun y => if p y then some y.id else none

/-- `chained`, with the containment test on a hash set of the set read. -/
def chainedF (today : Nat) (prior : Snapshot Line) : Option (Snapshot Line) → Bool
  | none => false
  | some s => s.entries.length == s.count && validDate s.asOf && s.asOf ≤ today && prior.asOf ≤ s.asOf &&
      prior.entries.all (HashSet.ofList s.entries).contains

def viewF (ch : Bool) (prior : Snapshot Line) (o : Option (Snapshot Line)) : Snapshot Line :=
  if ch then o.getD prior else prior

def looseF (ch : Bool) (prior : Snapshot Line) (o : Option (Snapshot Line)) : List Line :=
  if ch then [] else
    let p := HashSet.ofList prior.entries
    (entries o).filter fun x => !p.contains x

/-! ## The per-batch index -/

structure Ix where
  today : Nat
  redo : HashSet Nat
  batch : HashSet Line
  relChained : Bool
  unrChained : Bool
  /-- The views (`view`), their lengths, and view-then-`loose` rows with their key positions. -/
  relV : Snapshot Line
  unrV : Snapshot Line
  relN : Nat
  unrN : Nat
  rel : Array Line
  unr : Array Line
  relPost : HashMap Key (List Nat)
  unrPost : HashMap Key (List Nat)
  looseKeys : HashSet Key
  dmfSome : Bool
  pdSome : Bool
  exclSome : Bool
  spanSome : Bool
  dmfOk : Bool
  pdOk : Bool
  exclOk : Bool
  spanOk : Bool
  dmf : HashMap Nat (List Death)
  pdeath : HashMap Nat (List Death)
  excl : HashMap Nat (List Exclusion)
  span : HashMap Nat (List Span)

/-- One pass over each set and snapshot: O(n) expected, n the rows read. -/
def Ix.build (c : Ctx) (b : List Line) : Ix :=
  let rc := chainedF c.today c.releasedPrior c.released
  let uc := chainedF c.today c.unresolvedPrior c.unresolved
  let rv := viewF rc c.releasedPrior c.released
  let uv := viewF uc c.unresolvedPrior c.unresolved
  let ra := rv.entries ++ looseF rc c.releasedPrior c.released
  let ua := uv.entries ++ looseF uc c.unresolvedPrior c.unresolved
  { today := c.today, redo := HashSet.ofList c.redo, batch := HashSet.ofList b,
    relChained := rc, unrChained := uc, relV := rv, unrV := uv,
    relN := rv.entries.length, unrN := uv.entries.length, rel := ra.toArray, unr := ua.toArray,
    relPost := (posts ra).1, unrPost := (posts ua).1,
    looseKeys := HashSet.ofList ((ra.drop rv.entries.length ++ ua.drop uv.entries.length).map exactKey),
    dmfSome := c.dmf.isSome, pdSome := c.providerDeaths.isSome, exclSome := c.exclusions.isSome,
    spanSome := c.enrollment.isSome,
    dmfOk := usable c.today 90 okDeath c.dmf, pdOk := usable c.today 90 okDeath c.providerDeaths,
    exclOk := usable c.today 31 okExclusion c.exclusions, spanOk := usable c.today 7 okSpan c.enrollment,
    dmf := group (·.id) (entries c.dmf), pdeath := group (·.id) (entries c.providerDeaths),
    excl := group (·.id) (entries c.exclusions), span := group (·.member) (entries c.enrollment) }

/-! ## Queries: each equals the Spec function of the same name (`FastEq`). -/

def Ix.own (x : Ix) (l : Line) : Bool :=
  x.redo.contains l.pay && (x.relPost.getD (idKey l) []).any fun i => i < x.relN && x.rel[i]?.any (· == l)

def Ix.enrolled (x : Ix) (l : Line) : Bool := (x.span.getD l.member []).any (covers l)

def Ix.notEnrolled (x : Ix) (l : Line) : Bool := x.spanOk && validDate l.date && !x.enrolled l

def Ix.claim (x : Ix) (l : Line) : List Key :=
  if isCap l && x.notEnrolled l && !x.own l then [exactKey l, idKey l] else keys l

def Ix.memberDead (x : Ix) (l : Line) : Bool := (x.dmf.getD l.member []).any (·.date < l.date)

def Ix.providerDead (x : Ix) (l : Line) : Bool :=
  (x.pdeath.getD l.payee []).any (·.date < l.date) || (x.pdeath.getD l.rendering []).any (·.date < l.date)

def Ix.excluded (x : Ix) (l : Line) : Bool :=
  let inForce (e : Exclusion) := e.start ≤ l.date && l.date ≤ e.stop
  (x.excl.getD l.payee []).any inForce || (x.excl.getD l.rendering []).any inForce

def Ix.overlap (x : Ix) (l : Line) : Bool :=
  let first := l.date / 100 * 100 + 1
  let last := l.date / 100 * 100 + monthDays (l.date / 10000) (l.date / 100 % 100)
  let ss := x.span.getD l.member []
  ss.any fun s => ss.any fun t =>
    s.plan != t.plan && max first (max s.start t.start) ≤ min last (min s.stop t.stop)

/-- `(seen0 c b).contains k`: a key of a released view row the batch does not decide again. -/
def Ix.seen0 (x : Ix) (k : Key) : Bool :=
  (x.relPost.getD k []).any fun i => i < x.relN && x.rel[i]?.any fun y => !(x.own y && x.batch.contains y)

/-- `(pending c).contains k`: a key an unresolved view row claims (`claim` ⊆ `keys`). -/
def Ix.pending (x : Ix) (k : Key) : Bool :=
  (x.unrPost.getD k []).any fun i => i < x.unrN && x.unr[i]?.any fun y => (x.claim y).contains k

/-- The Spec's `seen` list: the batch's own claims so far (`s`), then `seen0`. -/
def Ix.seen (x : Ix) (s : HashSet Key) (k : Key) : Bool := s.contains k || x.seen0 k

/-- `fires`, row for row. -/
def Ix.fires (x : Ix) (s : HashSet Key) (l : Line) : Reason → Bool
  | .ALREADY_DECIDED => x.seen s (idKey l) || x.pending (idKey l)
  | .CAP_MEMBER_MONTH_DUPLICATE => isCap l &&
      (x.seen s (exactKey l) || x.seen s (nearKey l) || x.spanOk && validDate l.date && x.overlap l)
  | .COLLIDES_WITH_UNRESOLVED_NEAR => !isCap l && x.pending (nearKey l) && !x.pending (exactKey l)
  | .DUPLICATE_OF_UNRESOLVED => x.pending (exactKey l) || isCap l && x.pending (nearKey l)
  | .FFS_DUPLICATE_LINE => !isCap l && x.seen s (exactKey l)
  | .FFS_DUPLICATE_UNVERIFIED => !isCap l && x.looseKeys.contains (exactKey l)
  | .FFS_NEAR_DUPLICATE => !isCap l && x.seen s (nearKey l) && !x.seen s (exactKey l)
  | .MEMBER_DECEASED => x.dmfOk && validDate l.date && x.memberDead l
  | .MEMBER_DECEASED_UNVERIFIED => x.dmfSome && !x.dmfOk && validDate l.date && x.memberDead l
  | .MEMBER_NOT_ENROLLED => x.notEnrolled l
  | .MEMBER_NOT_ENROLLED_UNVERIFIED => x.spanSome && !x.spanOk && validDate l.date && !x.enrolled l
  | .PROVIDER_DECEASED => x.pdOk && validDate l.date && x.providerDead l
  | .PROVIDER_DECEASED_UNVERIFIED => x.pdSome && !x.pdOk && validDate l.date && x.providerDead l
  | .PROVIDER_EXCLUDED => x.exclOk && validDate l.date && x.excluded l
  | .PROVIDER_EXCLUDED_UNVERIFIED => x.exclSome && !x.exclOk && validDate l.date && x.excluded l
  | .SERVICE_DATE_FUTURE => x.today < l.date
  | .SERVICE_DATE_INVALID => !validDate l.date
  | .STALE_DMF => !x.dmfOk
  | .STALE_ENROLLMENT => !x.spanOk
  | .STALE_EXCLUSION => !x.exclOk
  | .STALE_PROVIDER_DEATH => !x.pdOk
  | .STALE_RELEASED => !x.relChained
  | .STALE_UNRESOLVED => !x.unrChained

def Ix.counterparts (x : Ix) (l : Line) : List Nat :=
  hits x.rel x.relPost (keys l) (fun _ => true) ++
    hits x.unr x.unrPost (keys l) fun y => (keys l).any (x.claim y).contains

def Ix.decideLine (x : Ix) (s : HashSet Key) (l : Line) : Decision :=
  let rs := reasons.filter (x.fires s l)
  { line := l, outcome := outcomeOf rs, reasons := rs, counterparts := x.counterparts l }

def Ix.decideAll (x : Ix) : HashSet Key → List Line → List Decision
  | _, [] => []
  | s, l :: ls => x.decideLine s l :: x.decideAll (s.insertMany (x.claim l)) ls

def Ix.order (x : Ix) (b : List Line) : List Line :=
  canonical (b.filter x.own) ++ canonical (b.filter fun y => !x.own y)

/-- O(|ds|) per call, as in the Spec: O(b²) per batch (b ≤ 1,000; about 5 µs a line is estimated from the design, not measured). -/
def Ix.payOutcome (x : Ix) (ds : List Decision) (p : Nat) : Outcome :=
  let ls := ds.filter (·.line.pay == p)
  if ls.any (·.outcome == .HOLD) then .HOLD
  else if !ls.isEmpty && ls.all fun d => d.outcome == .ALLOW && (!x.redo.contains p || x.own d.line) then .ALLOW
  else .HUMAN_REVIEW

def Ix.releasedLines (x : Ix) (ds : List Decision) : List Line :=
  (allowedLines ds).filter fun l => !x.redo.contains l.pay && x.payOutcome ds l.pay == .ALLOW

def Ix.unresolvedLines (x : Ix) (ds : List Decision) : List Line :=
  (ds.filter fun d => d.outcome != .ALLOW && !d.reasons.contains .ALREADY_DECIDED && !x.own d.line).map (·.line)

/-- The batch run with the ids `f` that the tenant's id registry gives another shard already seen. -/
def Ix.runIn (x : Ix) (f : List Nat) (b : List Line) : Result :=
  let ds := x.decideAll (HashSet.ofList (idSeen f)) (x.order b)
  let ra := x.releasedLines ds
  let ua := x.unresolvedLines ds
  { decisions := ds, released := ⟨x.relV.asOf, x.relN + ra.length, x.relV.entries ++ ra⟩,
    unresolved := ⟨x.unrV.asOf, x.unrN + ua.length, x.unrV.entries ++ ua⟩ }

def decideBatchFIn (c : Ctx) (f : List Nat) (b : List Line) : Result := (Ix.build c b).runIn f b

def decideBatchF (c : Ctx) (b : List Line) : Result := decideBatchFIn c [] b

/-! Twins of the multi-shard defs: one hash set per answer kind, built once per batch (`ShardRun.lean`). -/

def readyF (k : Nat) (os : List Owner) (b : List Line) : List Line :=
  let ok := HashSet.ofList ((os.filter fun o => o.shard == k || o.settled).map (·.id))
  let wait := HashSet.ofList ((b.filter fun m => !ok.contains m.id).map (·.pay))
  b.filter fun l => !wait.contains l.pay

def foreignOfF (k : Nat) (os : List Owner) (b : List Line) : List Nat :=
  let t := HashSet.ofList ((os.filter fun o => o.shard != k && o.settled).map (·.id))
  (b.map (·.id)).filter fun i => t.contains i

def settleFreeF (rel unr : List Line) (p : List Nat) : List Nat :=
  let s := HashSet.ofList ((rel ++ unr).map (·.id))
  p.filter fun i => !s.contains i

def decideRegF (c : Ctx) (k : Nat) (os : List Owner) (b : List Line) : Result :=
  let r := readyF k os b
  decideBatchFIn c (foreignOfF k os r) r

/-! ## Pins: `pinInput` as one ByteArray (about 0.93 KB a released row, not 22 KB of list cells). -/

/-- `be w n` appended to `acc`: one shift per byte, not a power and a division. -/
def pushBe (acc : ByteArray) (w n : Nat) : Option ByteArray :=
  if n < 256 ^ w then some ((List.range w).reverse.foldl (fun a i => a.push ((n >>> (8 * i)) % 256).toUInt8) acc)
  else none

def pushRow (acc : ByteArray) : List (Nat × Nat) → Option ByteArray
  | [] => some acc
  | (w, n) :: fs => do pushRow (← pushBe acc w n) fs

/-- List byte order (`List.le`) from byte `i` on: first differing byte, a proper prefix first. -/
def leFrom (a b : ByteArray) (i : Nat) : Bool :=
  if h : i < a.size then
    if h' : i < b.size then
      if a[i] < b[i] then true else if a[i] == b[i] then leFrom a b (i + 1) else false
    else false
  else true
termination_by a.size - i

def baLe (a b : ByteArray) : Bool := leFrom a b 0

def pinBytes {α : Type} (domain : String) (kind : Nat) (fields : α → List (Nat × Nat)) (s : Snapshot α) :
    Option ByteArray := do
  let head ← pushRow (domain.toUTF8.push 0) [(4, kind), (4, s.asOf), (4, s.count)]
  let rows ← s.entries.mapM fun x => pushRow .empty (fields x)
  let out := ByteArray.emptyWithCapacity (rows.foldl (· + ·.size) head.size) ++ head
  pure ((rows.mergeSort baLe).foldl (· ++ ·) out)

/-- `Gate.setsDigest` over `pinBytes` (`setsDigestF_eq`): the checkpoint state digest, without the spec's list sort. -/
def setsDigestF (H : ByteArray → List UInt8) (r u : Snapshot Line) : Option (List UInt8) := do
  let a ← pinBytes "RR/GATE/RELEASED/v1" 5 Line.fields r
  let b ← pinBytes "RR/GATE/UNRESOLVED/v1" 6 Line.fields u
  pure (BlindLedger.Gate.stateDigest (fun x => H ⟨x.toArray⟩) (H a) (H b))

end BlindLedger.Gate.Rules.Fast
