import BlindLedger.Financial.Partition

/-! Shard split laws (OWNER-SCALE-3; rrb/state/owner-scale-3-design-20261007.md §1-§7, statement list §9).

    One partition `cx.p` = one spine database + `K = pk.k cx.p` shard databases.  The spine holds the cell
    directory (the only dedup authority), the clock, pool/budget/link totals, spine-homed rows, shard heads and the
    records `R_n`; a shard holds its cells' MOVE charges, gross and machine-charge totals, its chain head and its
    `APPLIED(n)` list.  The judge is sequential over a file's rows and reads only the spine; Lean is a pure
    function of a shard's input `I_k`; `finRows` is the shard transaction (guarded: a cell moves at most once).
    The single-store reference `Single` holds the same rows in one database; `merge` is the design's
    `pi(spine) ∪ pi(shard_k)` and `Single` carries no DROP field, so `pi` is the identity here.  The hashes are
    parameters (`Ctx.hsh`, `Ctx.hs`), assumed only to advance a shard head (`Ctx.advances`).  Not imported by any
    pinned executable. -/

namespace BlindLedger.Financial.ShardSplit

open BlindLedger.Financial.Partition (PartId)

abbrev Cell := String
abbrev Item := String
abbrev Dg := Nat

def kOf : List (PartId × Nat) → PartId → Nat
  | [], _ => 1
  | (q, n) :: t, p => if p = q then n else kOf t p

/-- The shard pack: `K_p` per partition; a partition it does not name opens as `K = 1` (migration, §1). -/
structure Pack where
  ks : List (PartId × Nat)

def Pack.k (pk : Pack) (p : PartId) : Nat := kOf pk.ks p

def packOk (pk : Pack) : Bool := pk.ks.all fun x => 0 < x.2

/-- A pack change is refused once a partition has history and its `K` would change. -/
def packUpdateOk (hist : List PartId) (pk pk' : Pack) : Bool :=
  packOk pk' && hist.all fun p => pk'.k p == pk.k p

inductive Home where
  | spine
  | shard (k : Nat)
deriving DecidableEq

structure Row where
  cell : Cell
  item : Option Item   -- none: itemless row
  raw : Dg
  gross : Int
  positive : Bool      -- CLP / cash cell (false: REV / PLB / RAW)

structure DirRow where
  home : Home
  raw : Dg
  gross : Int

abbrev Dir := Cell → Option DirRow

structure Input where
  t : Nat              -- the one clock reading t_f
  rows : List Row

structure Ctx where
  p : PartId
  hsh : PartId → Item → Nat                     -- H("RR/SHARD/v1", p, item_id)
  lean : List Row → List Bool                   -- Lean batchFast on I_k (pure); true = MOVE
  hs : Dg → Nat → List Row → List Bool → Dg     -- shard chain: post_head = hs pre_head n I_k V_k
  advances : ∀ d n I V, hs d n I V ≠ d

def shardOf (pk : Pack) (cx : Ctx) (i : Item) : Nat := cx.hsh cx.p i % pk.k cx.p

/-- Home of a new cell: a positive cell with an item goes to its item's shard, everything else to the spine. -/
def routeNew (pk : Pack) (cx : Ctx) (r : Row) : Home :=
  match r.positive, r.item with
  | true, some i => .shard (shardOf pk cx i)
  | _, _ => .spine

inductive Verdict where
  | admit (h : Home)
  | duplicate
  | conflict
deriving DecidableEq

def setDir (d : Dir) (c : Cell) (x : DirRow) : Dir := fun c' => if c' = c then some x else d c'

/-- One row: a known cell routes by its directory row (equal raw: DUPLICATE, other raw: CONFLICT); a new cell is
    written to the directory in the same judgment, so a later row of the same file routes by it. -/
def judgeRow (pk : Pack) (cx : Ctx) (d : Dir) (r : Row) : Dir × Verdict :=
  match d r.cell with
  | some x => (d, if x.raw = r.raw then .duplicate else .conflict)
  | none => (setDir d r.cell ⟨routeNew pk cx r, r.raw, r.gross⟩, .admit (routeNew pk cx r))

def judgeRows (pk : Pack) (cx : Ctx) : Dir → List Row → Dir × List (Row × Verdict)
  | d, [] => (d, [])
  | d, r :: rs =>
    let a := judgeRow pk cx d r
    let b := judgeRows pk cx a.1 rs
    (b.1, (r, a.2) :: b.2)

structure SpineView where
  dir : Dir
  t : Nat

structure Judgment where
  dir : Dir
  out : List (Row × Verdict)
  t : Nat
  ok : Bool            -- clock not below the previous record's

def judge (pk : Pack) (cx : Ctx) (sv : SpineView) (inp : Input) : Judgment :=
  let a := judgeRows pk cx sv.dir inp.rows
  ⟨a.1, a.2, inp.t, decide (sv.t ≤ inp.t)⟩

/-- `I_h`: the admitted rows homed at `h`. -/
def part (J : Judgment) (h : Home) : List Row := (J.out.filter fun x => x.2 == .admit h).map (·.1)

def touched (pk : Pack) (cx : Ctx) (J : Judgment) : List Nat :=
  (List.range (pk.k cx.p)).filter fun k => !(part J (.shard k)).isEmpty

def verdicts (cx : Ctx) (J : Judgment) (k : Nat) : List Bool := cx.lean (part J (.shard k))

def gsum (rs : List Row) : Int := (rs.map (·.gross)).sum

def bump (chg : Cell → Nat) (c : Cell) : Cell → Nat := fun c' => if c' = c then chg c' + 1 else chg c'

/-- The shard transaction on `I_k` with verdicts `V_k`: a row moves iff Lean says MOVE and its cell has no MOVE
    charge yet; returns the charges and the machine charge added. -/
def finRows (chg : Cell → Nat) : List Row → List Bool → (Cell → Nat) × Int
  | [], _ => (chg, 0)
  | r :: rs, vs =>
    let mv := vs.headD false && chg r.cell == 0
    let a := finRows (if mv then bump chg r.cell else chg) rs vs.tail
    (a.1, (if mv then r.gross else 0) + a.2)

/-- `finalize_k(I_k, V_k)` at the spine (stateless): the machine charge of the rows Lean moves. -/
def vsum : List Row → List Bool → Int
  | [], _ => 0
  | r :: rs, vs => (if vs.headD false then r.gross else 0) + vsum rs vs.tail

/-! ## The single-store reference -/

/-- One database: the merged view's rows by natural key (no DROP field). -/
structure View where
  dir : Dir
  t : Nat
  used : Int           -- pool used (spine)
  budget : Int         -- budget charged (spine)
  lc : Int             -- LINK charges (spine)
  spineRows : List Row
  chg : Cell → Nat     -- MOVE charges per cell
  gross : Int          -- gross of admitted shard cells
  mc : Int             -- machine charges
abbrev Single := View

def spineOf (s : Single) : SpineView := ⟨s.dir, s.t⟩

def judgeSingle (pk : Pack) (cx : Ctx) (s : Single) (inp : Input) : Judgment := judge pk cx (spineOf s) inp

def finAll (J : Judgment) (V : Nat → List Bool) : (Cell → Nat) → List Nat → (Cell → Nat) × Int
  | chg, [] => (chg, 0)
  | chg, k :: ks =>
    let a := finRows chg (part J (.shard k)) (V k)
    let b := finAll J V a.1 ks
    (b.1, a.2 + b.2)

def applySingle (pk : Pack) (cx : Ctx) (s : Single) (J : Judgment) (V : Nat → List Bool) : Single :=
  let ks := touched pk cx J
  let f := finAll J V s.chg ks
  let g := (ks.map fun k => gsum (part J (.shard k))).sum
  let l := gsum (part J .spine)
  { dir := J.dir, t := J.t, used := s.used + g, budget := s.budget + f.2 + l, lc := s.lc + l,
    spineRows := s.spineRows ++ part J .spine, chg := f.1, gross := s.gross + g, mc := s.mc + f.2 }

def stepSingle (pk : Pack) (cx : Ctx) (s : Single) (inp : Input) : Single :=
  let J := judgeSingle pk cx s inp
  if J.ok then applySingle pk cx s J (verdicts cx J) else s

def runSingle (pk : Pack) (cx : Ctx) : Single → List Input → Single
  | s, [] => s
  | s, r :: rs => runSingle pk cx (stepSingle pk cx s r) rs

def initSingle : Single := ⟨fun _ => none, 0, 0, 0, 0, [], fun _ => 0, 0, 0⟩

/-! ## The sharded store -/

structure ShardDB where
  chg : Cell → Nat
  gross : Int
  mc : Int
  head : Dg
  applied : List Nat   -- APPLIED(n), oldest first

/-- Spine record `R_n`. -/
structure Rec where
  n : Nat
  t : Nat
  I : Nat → List Row
  V : Nat → List Bool
  pre : Nat → Dg
  post : Nat → Dg
  touched : List Nat

structure SpineDB where
  dir : Dir
  t : Nat
  used : Int
  budget : Int
  lc : Int
  spineRows : List Row
  heads : Nat → Dg
  recs : List Rec      -- newest first

abbrev SS := SpineDB × (Nat → ShardDB)

def SpineDB.view (sp : SpineDB) : SpineView := ⟨sp.dir, sp.t⟩

/-- Shard `k`'s part of `R`: the transaction, then head := post_head_k and APPLIED(n) last. -/
def applyPart (R : Rec) (k : Nat) (sh : ShardDB) : ShardDB :=
  let f := finRows sh.chg (R.I k) (R.V k)
  { chg := f.1, gross := sh.gross + gsum (R.I k), mc := sh.mc + f.2, head := R.post k,
    applied := sh.applied ++ [R.n] }

def mkRec (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) : Judgment × Rec :=
  let J := judge pk cx ss.1.view inp
  let n := ss.1.recs.length + 1
  (J, { n := n, t := inp.t, I := fun k => part J (.shard k), V := verdicts cx J,
        pre := fun k => (ss.2 k).head,
        post := fun k => cx.hs (ss.2 k).head n (part J (.shard k)) (verdicts cx J k),
        touched := touched pk cx J })

def headsOk (pk : Pack) (cx : Ctx) (ss : SS) : Bool :=
  (List.range (pk.k cx.p)).all fun k => (ss.2 k).head == ss.1.heads k

def checkAll (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) : Bool :=
  (judge pk cx ss.1.view inp).ok && headsOk pk cx ss

def commitSpine (sp : SpineDB) (J : Judgment) (R : Rec) : SpineDB :=
  let l := gsum (part J .spine)
  { dir := J.dir, t := J.t, used := sp.used + (R.touched.map fun k => gsum (R.I k)).sum,
    budget := sp.budget + (R.touched.map fun k => vsum (R.I k) (R.V k)).sum + l, lc := sp.lc + l,
    spineRows := sp.spineRows ++ part J .spine,
    heads := fun k => if k ∈ R.touched then R.post k else sp.heads k, recs := R :: sp.recs }

def commitShards (R : Rec) (C : List Nat) (sh : Nat → ShardDB) : Nat → ShardDB :=
  fun k => if k ∈ C then applyPart R k (sh k) else sh k

/-- One record: judge, check heads and clock, spine COMMIT, then every touched shard; `none` = refused. -/
def stepS (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) : Option SS :=
  if checkAll pk cx ss inp then
    let a := mkRec pk cx ss inp
    some (commitSpine ss.1 a.1 a.2, commitShards a.2 a.2.touched ss.2)
  else none

def stepT (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) : SS := (stepS pk cx ss inp).getD ss

/-- A crash after the spine COMMIT: only the shards in `C` committed their part. -/
def afterSpine (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) (C : List Nat) : SS :=
  if checkAll pk cx ss inp then
    let a := mkRec pk cx ss inp
    (commitSpine ss.1 a.1 a.2, commitShards a.2 C ss.2)
  else ss

def runS (pk : Pack) (cx : Ctx) : SS → List Input → SS
  | ss, [] => ss
  | ss, r :: rs => runS pk cx (stepT pk cx ss r) rs

def initShard : ShardDB := ⟨fun _ => 0, 0, 0, 0, []⟩
def initS : SS := (⟨fun _ => none, 0, 0, 0, 0, [], fun _ => 0, []⟩, fun _ => initShard)

def reachS (pk : Pack) (cx : Ctx) (ss : SS) : Prop := ∃ rs, ss = runS pk cx initS rs

/-- Replay of `R` on shard `k`: only from `pre_head_k` when it differs from `post_head_k`; any other head is left
    as is (`shard_diverged` halts). -/
def replay (R : Rec) (k : Nat) (sh : ShardDB) : ShardDB :=
  if k ∈ R.touched ∧ sh.head = R.pre k ∧ sh.head ≠ R.post k then applyPart R k sh else sh

def recover (sp : SpineDB) (k : Nat) (sh : ShardDB) : ShardDB :=
  match sp.recs with
  | [] => sh
  | R :: _ => replay R k sh

def recoverAll (ss : SS) : SS := (ss.1, fun k => recover ss.1 k (ss.2 k))

/-- `pi(spine) ∪ pi(shard_k)`, shards `0 .. K-1`. -/
def merge (pk : Pack) (cx : Ctx) (ss : SS) : View :=
  let ks := List.range (pk.k cx.p)
  { dir := ss.1.dir, t := ss.1.t, used := ss.1.used, budget := ss.1.budget, lc := ss.1.lc,
    spineRows := ss.1.spineRows, chg := fun c => (ks.map fun k => (ss.2 k).chg c).sum,
    gross := (ks.map fun k => (ss.2 k).gross).sum, mc := (ks.map fun k => (ss.2 k).mc).sum }

def moves (c : Cell) (v : View) : Nat := v.chg c

/-- Shard `k`'s rows of a cell-keyed table under directory `d`. -/
def restrict (d : Dir) (k : Nat) (chg : Cell → Nat) : Cell → Nat :=
  fun c => if (d c).map (·.home) = some (.shard k) then chg c else 0

def checkSingle (pk : Pack) (cx : Ctx) (s : Single) (inp : Input) (s' : Single) : Prop :=
  (judgeSingle pk cx s inp).ok = true ∧
    s' = applySingle pk cx s (judgeSingle pk cx s inp) (verdicts cx (judgeSingle pk cx s inp))

def checkSpine (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) (sp' : SpineDB) : Prop :=
  checkAll pk cx ss inp = true ∧ sp' = commitSpine ss.1 (mkRec pk cx ss inp).1 (mkRec pk cx ss inp).2

def checkShard (R : Rec) (k : Nat) (sh sh' : ShardDB) : Prop :=
  sh' = if k ∈ R.touched then applyPart R k sh else sh

/-- Each shard's APPLIED list is exactly the records touching it, in spine order. -/
def appliedOk (pk : Pack) (cx : Ctx) (ss : SS) : Prop :=
  ∀ k < pk.k cx.p, (ss.2 k).applied = (ss.1.recs.reverse.filter fun R => k ∈ R.touched).map (·.n)

/-! ## §9 statements -/

/-- K_p is positive under a well-formed pack. -/
theorem k_pos (pk : Pack) (p : PartId) (h : packOk pk = true) : 0 < pk.k p := by
  sorry

/-- A new cell's home is the spine or exactly one shard below K. -/
theorem route_total (pk : Pack) (cx : Ctx) (r : Row) (h : packOk pk = true) :
    routeNew pk cx r = .spine ∨ ∃ k, k < pk.k cx.p ∧ routeNew pk cx r = .shard k := by
  sorry

/-- K is fixed once the partition has history. -/
theorem shard_stable (hist : List PartId) (pk pk' : Pack) (p : PartId) (hu : packUpdateOk hist pk pk' = true)
    (hp : p ∈ hist) : pk'.k p = pk.k p := by
  sorry

/-- Routes never move: a directory row survives every step unchanged. -/
theorem dir_route_stable (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) (c : Cell) (x : DirRow)
    (h : ss.1.dir c = some x) : (stepT pk cx ss inp).1.dir c = some x := by
  sorry

/-- Admitted rows of different homes in one judgment name different cells. -/
theorem parts_disjoint (pk : Pack) (cx : Ctx) (sv : SpineView) (inp : Input) {h h' : Home} (hh : h ≠ h')
    {r r' : Row} (hr : r ∈ part (judge pk cx sv inp) h) (hr' : r' ∈ part (judge pk cx sv inp) h') :
    r.cell ≠ r'.cell := by
  sorry

/-- Shard-local: shard k's transaction reads and writes only shard k's rows. -/
theorem part_local (pk : Pack) (cx : Ctx) (sv : SpineView) (inp : Input) (k : Nat) (V : List Bool)
    (chg chg' : Cell → Nat) (h : restrict (judge pk cx sv inp).dir k chg = restrict (judge pk cx sv inp).dir k chg') :
    restrict (judge pk cx sv inp).dir k (finRows chg (part (judge pk cx sv inp) (.shard k)) V).1 =
      restrict (judge pk cx sv inp).dir k (finRows chg' (part (judge pk cx sv inp) (.shard k)) V).1 ∧
    (finRows chg (part (judge pk cx sv inp) (.shard k)) V).2 =
      (finRows chg' (part (judge pk cx sv inp) (.shard k)) V).2 := by
  sorry

/-- A refusal changes no database. -/
theorem refusal_atomic (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) (h : checkAll pk cx ss inp = false) :
    stepT pk cx ss inp = ss := by
  sorry

/-- No commit on a stale head. -/
theorem commit_requires_heads (pk : Pack) (cx : Ctx) (ss ss' : SS) (inp : Input)
    (h : stepS pk cx ss inp = some ss') : ∀ k < pk.k cx.p, (ss.2 k).head = ss.1.heads k := by
  sorry

/-- Recovery reads only the last committed spine record and shard k. -/
theorem recover_pure (sp : SpineDB) (R : Rec) (rs : List Rec) (h : sp.recs = R :: rs) (k : Nat) (sh : ShardDB) :
    recover sp k sh = replay R k sh := by
  sorry

/-- Recovery is idempotent. -/
theorem recover_idem (sp : SpineDB) (k : Nat) (sh : ShardDB) :
    recover sp k (recover sp k sh) = recover sp k sh := by
  sorry

/-- The spine judge is the single-store judge: the spine alone is the dedup authority. -/
theorem dir_dedup (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) :
    judge pk cx ss.1.view inp = judgeSingle pk cx (merge pk cx ss) inp := by
  sorry

/-- No double move: across all shards a cell carries at most one MOVE charge. -/
theorem no_cross_shard_duplicate (pk : Pack) (cx : Ctx) (ss : SS) (h : reachS pk cx ss) (c : Cell) :
    moves c (merge pk cx ss) ≤ 1 := by
  sorry

/-- Not weakened: whatever the spine and shard checks accept, the single-store check accepts. -/
theorem check_split (pk : Pack) (cx : Ctx) (ss : SS) (hr : reachS pk cx ss) (inp : Input) (sp' : SpineDB)
    (sh' : Nat → ShardDB) (hsp : checkSpine pk cx ss inp sp')
    (hsh : ∀ k < pk.k cx.p, checkShard (mkRec pk cx ss inp).2 k (ss.2 k) (sh' k)) :
    checkSingle pk cx (merge pk cx ss) inp (merge pk cx (sp', sh')) := by
  sorry

/-- The single step factors as judge, Lean, finalize. -/
theorem step_factor (pk : Pack) (cx : Ctx) (s : Single) (inp : Input) (h : (judgeSingle pk cx s inp).ok = true) :
    stepSingle pk cx s inp =
      applySingle pk cx s (judgeSingle pk cx s inp) (verdicts cx (judgeSingle pk cx s inp)) := by
  sorry

/-- Sharded = single: the merged sharded run is the single-store run. -/
theorem shard_run_eq (pk : Pack) (cx : Ctx) (rs : List Input) :
    merge pk cx (runS pk cx initS rs) = runSingle pk cx initSingle rs := by
  sorry

/-- A crash after the spine COMMIT converges: recovery yields the committed step. -/
theorem rollforward_eq (pk : Pack) (cx : Ctx) (ss ss' : SS) (inp : Input) (C : List Nat)
    (h : stepS pk cx ss inp = some ss') (hC : ∀ k ∈ C, k ∈ (mkRec pk cx ss inp).2.touched) :
    recoverAll (afterSpine pk cx ss inp C) = ss' := by
  sorry

/-- A crash before the spine COMMIT leaves a reachable state, and recovery changes nothing in it. -/
theorem crash_before_spine (pk : Pack) (cx : Ctx) (ss : SS) (h : reachS pk cx ss) : recoverAll ss = ss := by
  sorry

/-- The reader cut is real: a crash state whose shard heads all equal the spine's is the committed step. -/
theorem reader_cut (pk : Pack) (cx : Ctx) (ss ss' : SS) (inp : Input) (C : List Nat)
    (h : stepS pk cx ss inp = some ss') (hC : ∀ k ∈ C, k ∈ (mkRec pk cx ss inp).2.touched)
    (hh : ∀ k < pk.k cx.p, ((afterSpine pk cx ss inp C).2 k).head = (afterSpine pk cx ss inp C).1.heads k) :
    afterSpine pk cx ss inp C = ss' := by
  sorry

/-- Pool used is the shards' gross; the budget is the shards' machine charges plus the spine's LINK charges. -/
theorem pool_budget_merge (pk : Pack) (cx : Ctx) (ss : SS) (h : reachS pk cx ss) :
    ss.1.used = ((List.range (pk.k cx.p)).map fun k => (ss.2 k).gross).sum ∧
    ss.1.budget = ((List.range (pk.k cx.p)).map fun k => (ss.2 k).mc).sum + ss.1.lc := by
  sorry

/-- The spine binds the shard chains: heads match and each shard's APPLIED list is its records, in order. -/
theorem spine_chain_binds (pk : Pack) (cx : Ctx) (ss : SS) (h : reachS pk cx ss) :
    headsOk pk cx ss = true ∧ appliedOk pk cx ss := by
  sorry

end BlindLedger.Financial.ShardSplit
