import BlindLedger.Financial.Partition

/-! Shard split laws (OWNER-SCALE-3; rrb/state/owner-scale-3-design-20261007.md §1-§7, statement list §9).

    One partition `cx.p` = one spine database + `K = pk.k cx.p` shard databases.  The spine holds the cell
    directory (the only dedup authority), the clock, pool/budget/link totals, spine-homed rows, shard heads and the
    records `R_n`; a shard holds its cells' MOVE charges, gross and machine-charge totals, its chain head and its
    `APPLIED(n)` list.  The judge is sequential over a file's rows and reads only the spine; Lean is a pure
    function of a shard's input `I_k`; `finRows` is the shard transaction (guarded: a cell moves at most once).
    The single-store reference `Single` holds the same rows in one database; `merge` is the design's
    `pi(spine) ∪ pi(shard_k)` and `Single` carries no DROP field, so `pi` is the identity here.  The hashes are
    parameters (`Ctx.hsh`, `Ctx.hs`) with no assumption.  The writer never stores a touched shard head that does not
    move: `post_head_k = adv (hs ..) pre_head_k` (`post_ne_pre`), so a fixed point of `hs` (which no real hash rules
    out) cannot leave one record's shard part the writer accepts unapplied (`accepted_applied`).  Records commit in
    groups (`stepG`: one spine COMMIT, one transaction per shard), and a group can return a head to its old value,
    so the writer also checks APPLIED: it accepts only if every shard `fits` the spine (head = `heads k`, APPLIED =
    the `n` of every spine record touching `k`).  Then no group part is left unapplied while writes go on
    (`accepted_applied_group`, `group_crash_refused`).  Recovery replays, oldest first and head-guarded, every record
    above a shard's APPLIED entries and commits only a result that `fits`, so a crash leaving any set of records
    unapplied converges (`rollforward_group`, `rollforward_any`), and a pre-head mismatch, a final head the spine
    disagrees with, or an APPLIED gap writes nothing (`recover_diverged`, `recover_diverged_tail`, `recover_gap`).
    Not imported by any pinned executable. -/

namespace BlindLedger.Financial.ShardSplit

open BlindLedger.Financial.Partition (PartId)

abbrev Cell := String
abbrev Item := String
abbrev Dg := Nat

def kOf : List (PartId × Nat) → PartId → Nat
  | [], _ => 1
  | (q, n) :: t, p => if p = q then n else kOf t p

/-- The shard pack: `K_p` per partition, set when the store opens; a partition it does not name has `K = 1`. -/
structure Pack where
  ks : List (PartId × Nat)

def Pack.k (pk : Pack) (p : PartId) : Nat := kOf pk.ks p

def packOk (pk : Pack) : Bool := pk.ks.all fun x => 0 < x.2

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
  item : Option Item   -- the item of the row that first admitted the cell; RESHARD homes by it

abbrev Dir := Cell → Option DirRow

structure Input where
  t : Nat              -- the one clock reading t_f
  rows : List Row

structure Ctx where
  p : PartId
  hsh : PartId → Item → Nat                     -- H("RR/SHARD/v1", p, item_id)
  lean : List Row → List Bool                   -- Lean batchFast on I_k (pure); true = MOVE
  hs : Dg → Nat → List Row → List Bool → Dg     -- shard chain: post_head = adv (hs pre_head n I_k V_k) pre_head
  hi : Dg → Nat → (Cell → Nat) × Int × Int → Dg  -- RESHARD part: post_head = adv (hi pre_head n image) pre_head

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
  | none => (setDir d r.cell ⟨routeNew pk cx r, r.raw, r.gross, r.item⟩, .admit (routeNew pk cx r))

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
  ok : Bool            -- pack well-formed (every K ≥ 1) and clock not below the previous record's

def judge (pk : Pack) (cx : Ctx) (sv : SpineView) (inp : Input) : Judgment :=
  let a := judgeRows pk cx sv.dir inp.rows
  ⟨a.1, a.2, inp.t, packOk pk && decide (sv.t ≤ inp.t)⟩

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

/-! ## The whole-file reference: Lean runs once on every shard-admitted row of the file -/

/-- The shard index an item hashes to (an itemless row is never shard-admitted; `0` is a placeholder). -/
def sidx (pk : Pack) (cx : Ctx) : Option Item → Nat
  | some i => shardOf pk cx i
  | none => 0

def isSh : Verdict → Bool
  | .admit (.shard _) => true
  | _ => false

/-- The file's shard-admitted rows, in file order. -/
def wrows (o : List (Row × Verdict)) : List Row := (o.filter fun x => isSh x.2).map (·.1)

/-- The verdicts of the rows `q` selects, read off a verdict list for all of `rs`. -/
def sel (q : Row → Bool) : List Row → List Bool → List Bool
  | [], _ => []
  | r :: rs, W => if q r then W.headD false :: sel q rs W.tail else sel q rs W.tail

/-- Locality of Lean (the stated hypothesis of the whole-file reference): for every item predicate, the verdicts
    Lean gives the selected rows inside a batch equal the verdicts it gives those rows alone. -/
def Local (cx : Ctx) : Prop := ∀ (q : Option Item → Bool) (rows : List Row),
  sel (fun r => q r.item) rows (cx.lean rows) = cx.lean (rows.filter fun r => q r.item)

/-- Lean run once per group, the shape of the product judge (`batchFast` per obligation ledger, B:416): `κ` names a
    row's group, `g a G` is the verdict list Lean gives group `a`'s rows `G` in file order (any function, so it may
    thread state inside the group as `batchFast` does), and each row reads its verdict at its position inside its
    group (`pre` = the rows before it). -/
def groupAux {α : Type} [DecidableEq α] (κ : Row → α) (g : α → List Row → List Bool) (all : List Row) :
    List Row → List Row → List Bool
  | _, [] => []
  | pre, r :: rs => (g (κ r) (all.filter fun x => decide (κ x = κ r))).getD
      (pre.filter fun x => decide (κ x = κ r)).length false :: groupAux κ g all (pre ++ [r]) rs

/-- The grouped judge on a file: every row's verdict from its group's one Lean batch. -/
def grouped {α : Type} [DecidableEq α] (κ : Row → α) (g : α → List Row → List Bool) (rows : List Row) :
    List Bool := groupAux κ g rows [] rows

/-- Filtering by `q` first changes nothing when every row `p` keeps is one `q` keeps. -/
theorem filter_sub (p q : Row → Bool) (h : ∀ x, p x = true → q x = true) :
    ∀ l : List Row, (l.filter q).filter p = l.filter p
  | [] => rfl
  | x :: l => by
    by_cases hp : p x = true
    · simp [hp, h x hp, filter_sub p q h l]
    · by_cases hq : q x = true
      · simp [hp, hq, filter_sub p q h l]
      · simp [hp, hq, filter_sub p q h l]

/-- When every group lies inside one item, the grouped judge's verdicts for the rows of any set of items, read off
    the whole batch, equal its verdicts on those rows alone (from any prefix `pre`). -/
theorem group_sel {α : Type} [DecidableEq α] (κ : Row → α) (g : α → List Row → List Bool)
    (q : Option Item → Bool) (hκ : ∀ x y, κ x = κ y → x.item = y.item) (all : List Row) :
    ∀ (rs pre : List Row), sel (fun r => q r.item) rs (groupAux κ g all pre rs) =
      groupAux κ g (all.filter fun r => q r.item) (pre.filter fun r => q r.item) (rs.filter fun r => q r.item)
  | [], _ => rfl
  | r :: rs, pre => by
    have ih := group_sel κ g q hκ all rs (pre ++ [r])
    by_cases hr : q r.item = true
    · have hs : ∀ l : List Row, (l.filter fun r => q r.item).filter (fun x => decide (κ x = κ r)) =
          l.filter fun x => decide (κ x = κ r) :=
        filter_sub _ _ fun x hx => (by rw [hκ x r (of_decide_eq_true hx)]; exact hr)
      rw [List.filter_cons_of_pos (p := fun r : Row => q r.item) hr]
      simp only [groupAux, sel, hr, ↓reduceIte, List.headD_cons, List.tail_cons]
      rw [ih, List.filter_append, List.filter_cons_of_pos (p := fun r : Row => q r.item) hr, List.filter_nil, hs, hs]
    · rw [List.filter_cons_of_neg (p := fun r : Row => q r.item) hr]
      simp only [groupAux, sel, hr, Bool.false_eq_true, ↓reduceIte, List.tail_cons]
      rw [ih, List.filter_append, List.filter_cons_of_neg (p := fun r : Row => q r.item) hr, List.filter_nil,
        List.append_nil]

/-- Goal 4, `Local` on the real judge's shape: if Lean is run once per group (`cx.lean = grouped κ g`, any `g`) and
    every group lies inside one item (`κ x = κ y → x.item = y.item`, true of obligation ledgers: one
    `FinancialInput` has one obligation of one item), then `Local cx` holds. -/
theorem local_grouped {α : Type} [DecidableEq α] (cx : Ctx) (κ : Row → α) (g : α → List Row → List Bool)
    (hκ : ∀ x y, κ x = κ y → x.item = y.item) (hl : cx.lean = grouped κ g) : Local cx := by
  intro q rows
  rw [hl]
  exact group_sel κ g q hκ rows rows []

def applyWhole (cx : Ctx) (s : Single) (J : Judgment) : Single :=
  let w := wrows J.out
  let f := finRows s.chg w (cx.lean w)
  let l := gsum (part J .spine)
  { dir := J.dir, t := J.t, used := s.used + gsum w, budget := s.budget + f.2 + l, lc := s.lc + l,
    spineRows := s.spineRows ++ part J .spine, chg := f.1, gross := s.gross + gsum w, mc := s.mc + f.2 }

def stepWhole (pk : Pack) (cx : Ctx) (s : Single) (inp : Input) : Single :=
  let J := judgeSingle pk cx s inp
  if J.ok then applyWhole cx s J else s

def runWhole (pk : Pack) (cx : Ctx) : Single → List Input → Single
  | s, [] => s
  | s, r :: rs => runWhole pk cx (stepWhole pk cx s r) rs

/-- Per-row MOVE receipts from one whole-file verdict list `W` (false for a row not shard-admitted). -/
def rcptW : List (Row × Verdict) → List Bool → List Bool
  | [], _ => []
  | x :: o, W => if isSh x.2 then W.headD false :: rcptW o W.tail else false :: rcptW o W

/-- Per-row MOVE receipts from per-shard verdict lists `V` (each shard's list read in its own order). -/
def rcptS : List (Row × Verdict) → (Nat → List Bool) → List Bool
  | [], _ => []
  | x :: o, V => match x.2 with
    | .admit (.shard k) => (V k).headD false :: rcptS o fun j => if j = k then (V k).tail else V j
    | _ => false :: rcptS o V

/-- A pre-shard store (§1 migration): one database with its cells (raw digest, gross), MOVE charges, totals and
    chain head.  The last four fields are the well-formedness the single store keeps: at most one MOVE charge per
    cell, charges only on known cells, pool used = gross, budget = machine charges + LINK charges.  A store born
    empty is the legacy store with no cells. -/
structure Legacy where
  cells : Cell → Option (Dg × Int)
  item : Cell → Option Item
  t : Nat
  used : Int
  budget : Int
  lc : Int
  spineRows : List Row
  chg : Cell → Nat
  gross : Int
  mc : Int
  head : Dg
  chg_le : ∀ c, chg c ≤ 1
  chg_cell : ∀ c, 0 < chg c → cells c ≠ none
  used_eq : used = gross
  budget_eq : budget = mc + lc

/-- The backfilled directory: every legacy cell, home shard 0, its legacy raw digest and gross. -/
def backfill (L : Legacy) : Dir := fun c => (L.cells c).map fun x => ⟨.shard 0, x.1, x.2, L.item c⟩

/-- The migrated single store: the legacy rows with the backfilled directory. -/
def initSingle (L : Legacy) : Single :=
  ⟨backfill L, L.t, L.used, L.budget, L.lc, L.spineRows, L.chg, L.gross, L.mc⟩

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
  /-- RESHARD only: each touched shard's charges, gross and machine charge after the record, written as is.
      `none` (every other record): the part is the transaction on `I k`, `V k`. -/
  img : Option (Nat → (Cell → Nat) × Int × Int) := none

structure SpineDB where
  dir : Dir
  t : Nat
  used : Int
  budget : Int
  lc : Int
  spineRows : List Row
  heads : Nat → Dg
  recs : List Rec      -- newest first
  k : Nat              -- the store's K: set at open, changed only by RESHARD; a pack with another K is refused

abbrev SS := SpineDB × (Nat → ShardDB)

def SpineDB.view (sp : SpineDB) : SpineView := ⟨sp.dir, sp.t⟩

/-- Shard `k`'s part of `R`: the transaction (or, for RESHARD, the image `R.img`, an overwrite, so a replay
    yields the same state), then head := post_head_k and APPLIED(n) last. -/
def applyPart (R : Rec) (k : Nat) (sh : ShardDB) : ShardDB :=
  let f := finRows sh.chg (R.I k) (R.V k)
  let v := R.img.elim (f.1, sh.gross + gsum (R.I k), sh.mc + f.2) (· k)
  { chg := v.1, gross := v.2.1, mc := v.2.2, head := R.post k, applied := sh.applied ++ [R.n] }

/-- A chain step that would return its own pre head `d` moves it to `d + 1` instead, so a touched shard head always
    moves. Port: Python does not port `adv`; it must refuse a part whose post head equals its pre head, which
    differs from this model only at a hash fixed point. -/
def adv (h d : Dg) : Dg := if h = d then d + 1 else h

theorem adv_ne (h d : Dg) : adv h d ≠ d := by
  unfold adv
  split
  · exact Nat.succ_ne_self d
  · assumption

def mkRec (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) : Judgment × Rec :=
  let J := judge pk cx ss.1.view inp
  let n := ss.1.recs.length
  (J, { n := n, t := inp.t, I := fun k => part J (.shard k), V := verdicts cx J,
        pre := fun k => (ss.2 k).head,
        post := fun k => adv (cx.hs (ss.2 k).head n (part J (.shard k)) (verdicts cx J k)) (ss.2 k).head,
        touched := touched pk cx J })

@[simp] theorem mkRec_img (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) : (mkRec pk cx ss inp).2.img = none := rfl

/-- Every record's post head differs from its pre head, under any `hs`. -/
theorem post_ne_pre (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) (k : Nat) :
    (mkRec pk cx ss inp).2.post k ≠ (mkRec pk cx ss inp).2.pre k := adv_ne _ _

def headsOk (pk : Pack) (cx : Ctx) (ss : SS) : Bool :=
  (List.range (pk.k cx.p)).all fun k => (ss.2 k).head == ss.1.heads k

/-- The pack's `K` for the partition is the store's: a pack saved before a RESHARD, or not saved after one, is
    refused. -/
def kOk (pk : Pack) (cx : Ctx) (ss : SS) : Bool := ss.1.k == pk.k cx.p

/-- Saving a pack: accepted iff it is well formed and its `K` for the partition is the stored one, so a pack
    written after a RESHARD carries the new `K` and one carrying the old `K` is refused (`Reshard.packSave_ok`). -/
def packSaveOk (pk' : Pack) (cx : Ctx) (ss : SS) : Bool := packOk pk' && kOk pk' cx ss

/-- A stored RESHARD image is the one each touched shard's post head commits to under `hi`; true of every record
    without an image. -/
def imgOk (cx : Ctx) (R : Rec) : Bool :=
  R.img.elim true fun f => R.touched.all fun k => R.post k == adv (cx.hi (R.pre k) R.n (f k)) (R.pre k)

/-- Shard `k` agrees with the spine: its head is `heads k` and its APPLIED list is the `n` of every spine record
    touching `k`, oldest first.  So no record is missing and none is skipped (no gap below the newest entry); a
    head alone cannot show this, since a group can move a head `h0 -> h1 -> h0`.  `Inv3` is this for every `k`. -/
abbrev fits (sp : SpineDB) (k : Nat) (sh : ShardDB) : Prop :=
  sh.head = sp.heads k ∧ sh.applied = (sp.recs.reverse.filter fun R => k ∈ R.touched).map (·.n)

/-- The shards held under `K`: `0 .. K-1`, then every shard a spine record touches (a shard retired by a RESHARD
    to a smaller `K` stays held while a record touching it may be owed). -/
def held (K : Nat) (ss : SS) : List Nat := List.range K ++ ss.1.recs.flatMap (·.touched)

/-- STMT-CHANGE-1 (trunk `fitsOk` ranged over `range K`): every held shard fits the spine, so a crash inside a
    RESHARD to a smaller `K` blocks every record until recovery finishes the retired shards (replaces the
    branch's `lastOk`). -/
def fitsOk (pk : Pack) (cx : Ctx) (ss : SS) : Bool :=
  (held (pk.k cx.p) ss).all fun k => decide (fits ss.1 k (ss.2 k))

/-- Spine records are numbered `0, 1, 2, ...` in commit order (`R_0` = GENESIS, next = last + 1). -/
abbrev chainsOk (ss : SS) : Prop := ss.1.recs.reverse.map (·.n) = List.range' 0 ss.1.recs.length

/-- STMT-CHANGE-2 (trunk `checkAll`, branch old L401-412): the writer accepts only if the spine records are
    numbered in order (`chainsOk`; a duplicate `n` is refused, `dup_n_refused`), every held shard fits the spine
    (head and APPLIED, `fitsOk`), and the pack's `K` is the stored one (`kOk`). -/
def checkAll (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) : Bool :=
  decide (chainsOk ss) && (judge pk cx ss.1.view inp).ok && fitsOk pk cx ss && kOk pk cx ss

def commitSpine (sp : SpineDB) (J : Judgment) (R : Rec) : SpineDB :=
  let l := gsum (part J .spine)
  { dir := J.dir, t := J.t, used := sp.used + (R.touched.map fun k => gsum (R.I k)).sum,
    budget := sp.budget + (R.touched.map fun k => vsum (R.I k) (R.V k)).sum + l, lc := sp.lc + l,
    spineRows := sp.spineRows ++ part J .spine,
    heads := fun k => if k ∈ R.touched then R.post k else sp.heads k, recs := R :: sp.recs, k := sp.k }

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

/-- One commit group (osbench `r9_shard_bench` `attempt`): each input is judged on the state the earlier ones left
    and gets the next `n`; one spine COMMIT covers the group and each shard commits its parts in one transaction.
    `none` = some input refused (the whole group rolls back).  One record is the length-1 group (`stepG_single`). -/
def stepG (pk : Pack) (cx : Ctx) : SS → List Input → Option SS
  | ss, [] => some ss
  | ss, i :: is => (stepS pk cx ss i).bind fun s => stepG pk cx s is

/-- A crash after a group's spine COMMIT: the shards in `C` committed the whole group, the others none of it. -/
def afterSpineG (pk : Pack) (cx : Ctx) (ss : SS) (inps : List Input) (C : List Nat) : SS :=
  match stepG pk cx ss inps with
  | some ss' => (ss'.1, fun k => if k ∈ C then ss'.2 k else ss.2 k)
  | none => ss

def runS (pk : Pack) (cx : Ctx) : SS → List Input → SS
  | ss, [] => ss
  | ss, r :: rs => runS pk cx (stepT pk cx ss r) rs

def initShard : ShardDB := ⟨fun _ => 0, 0, 0, 0, []⟩

/-- Shards after migration: shard 0 is the legacy store (its charges, totals and head; APPLIED empty). -/
def initShards (L : Legacy) : Nat → ShardDB :=
  fun k => if k = 0 then ⟨L.chg, L.gross, L.mc, L.head, []⟩ else initShard

/-- GENESIS `R_0`: touches no shard; its pre and post heads are every shard's opening head (shard 0: the legacy
    head). -/
def genesis (L : Legacy) : Rec :=
  { n := 0, t := L.t, I := fun _ => [], V := fun _ => [], pre := fun k => (initShards L k).head,
    post := fun k => (initShards L k).head, touched := [] }

/-- The migrated store (§1 as amended 2026-10-07, lead decision on K): the legacy store opens at `K`, stored in
    the spine (`SpineDB.k`); a reachable store opens at the pack's `K = pk.k cx.p` (`reachS`).  Every step keeps
    `K`; only a RESHARD changes it (`Reshard.reshard_k`), and a pack whose `K` differs from the stored one is
    refused (`kOk`).  `K = 1` (an unnamed partition) is the special case.  The legacy store becomes shard 0; the
    directory is backfilled from every legacy cell with home shard 0; the spine holds the legacy totals,
    `heads(k)` = each shard's opening head, and the one record GENESIS `R_0`. -/
def initS (K : Nat) (L : Legacy) : SS :=
  (⟨backfill L, L.t, L.used, L.budget, L.lc, L.spineRows, fun k => (initShards L k).head, [genesis L], K⟩,
    initShards L)

def reachS (pk : Pack) (cx : Ctx) (ss : SS) : Prop := ∃ L rs, ss = runS pk cx (initS (pk.k cx.p) L) rs

/-- The merge sums shards `0..K-1`, so it accounts for the migrated store when K ≥ 1, or when the legacy store
    holds no MOVE charge and no totals (a store born empty, any K).  At K = 0 nothing is admitted
    (`k_zero_refused`). -/
def openOk (pk : Pack) (cx : Ctx) (L : Legacy) : Prop :=
  0 < pk.k cx.p ∨ ((∀ c, L.chg c = 0) ∧ L.gross = 0 ∧ L.mc = 0)

/-- Reachable from a migrated store with `openOk`. -/
def reachOk (pk : Pack) (cx : Ctx) (ss : SS) : Prop := ∃ L rs, openOk pk cx L ∧ ss = runS pk cx (initS (pk.k cx.p) L) rs

/-- Replay of `R` on shard `k`, only from `pre_head_k`; any other head stops recovery (`ShardDiverged`). -/
def replay (R : Rec) (k : Nat) (sh : ShardDB) : Option ShardDB :=
  if sh.head = R.pre k then some (applyPart R k sh) else none

def replays (k : Nat) : List Rec → ShardDB → Option ShardDB
  | [], sh => some sh
  | R :: rs, sh => (replay R k sh).bind (replays k rs)

/-- The spine records shard `k` still owes, oldest first: touching `k`, `n` above every APPLIED entry. -/
def pending (sp : SpineDB) (k : Nat) (sh : ShardDB) : List Rec :=
  sp.recs.reverse.filter fun R => decide (k ∈ R.touched) && sh.applied.all fun m => decide (m < R.n)

/-- Replays every pending record in order, in one transaction, and commits only if the result fits the spine
    (`fits`: head = `heads k`, APPLIED = every record touching `k`).  Otherwise it writes nothing and refuses
    (`none`, osbench `ShardDiverged`): a pre-head mismatch (`recover_diverged`), a final head the spine disagrees
    with (`recover_diverged_tail`), or a record APPLIED skipped (`recover_gap`).  APPLIED, not the head, decides
    what is owed, so a part never applies twice. -/
def recover (sp : SpineDB) (k : Nat) (sh : ShardDB) : Option ShardDB :=
  match replays k (pending sp k sh) sh with
  | some s => if fits sp k s then some s else none
  | none => none

/-- STMT-CHANGE-3 (trunk `recoverAll` ranged over `range (pk.k cx.p)`; branch old L513 was total): recovers every
    shard the store holds (`held` under the stored `K`, so a shard retired by a RESHARD is finished too), and only
    if every spine record's image, if any, is the one its post heads commit to (`imgOk`).  A refusal on any of
    them refuses the store (`recoverAll_refused`, `replay_forged`).  Readers must go through `readS` or `recoverAll`;
    raw `merge` over an unrecovered shard may over-read.  The pack argument is unused (a stale pack cannot narrow
    recovery). -/
def recoverAll (_pk : Pack) (cx : Ctx) (ss : SS) : Option SS :=
  if ss.1.recs.all (imgOk cx) && (held ss.1.k ss).all fun k => (recover ss.1 k (ss.2 k)).isSome then
    some (ss.1, fun k => (recover ss.1 k (ss.2 k)).getD (ss.2 k))
  else none

/-- STMT-CHANGE-4 (branch old L547: replay left the shard as is): an image the record's post heads do not commit
    to is never installed; recovery refuses the whole store. -/
theorem replay_forged (pk : Pack) (cx : Ctx) (ss : SS) (R : Rec) (hR : R ∈ ss.1.recs) (h : imgOk cx R = false) :
    recoverAll pk cx ss = none := by
  have : ss.1.recs.all (imgOk cx) = false := List.all_eq_false.2 ⟨R, hR, by simp [h]⟩
  simp [recoverAll, this]

/-- `pi(spine) ∪ pi(shard_k)`, shards `0 .. K-1` of the stored `K` (`SpineDB.k`), never the pack's: a stale
    pack cannot misread the store.  The pack argument is unused. -/
def merge (_pk : Pack) (_cx : Ctx) (ss : SS) : View :=
  let ks := List.range ss.1.k
  { dir := ss.1.dir, t := ss.1.t, used := ss.1.used, budget := ss.1.budget, lc := ss.1.lc,
    spineRows := ss.1.spineRows, chg := fun c => (ks.map fun k => (ss.2 k).chg c).sum,
    gross := (ks.map fun k => (ss.2 k).gross).sum, mc := (ks.map fun k => (ss.2 k).mc).sum }

/-- The guarded reader: `merge` only when every held shard fits the spine (`fitsOk`) and the pack's `K` is the
    stored one (`kOk`); an unrecovered RESHARD (a committed shard beside an uncommitted one) reads `none`, never an
    over-read.  Readers go through `readS` or `recoverAll`. -/
def readS (pk : Pack) (cx : Ctx) (ss : SS) : Option View :=
  if fitsOk pk cx ss && kOk pk cx ss then some (merge pk cx ss) else none

theorem readS_some {pk : Pack} {cx : Ctx} {ss : SS} {m : View} (h : readS pk cx ss = some m) :
    fitsOk pk cx ss = true ∧ kOk pk cx ss = true ∧ m = merge pk cx ss := by
  unfold readS at h
  split at h
  · rename_i hc
    simp only [Bool.and_eq_true] at hc
    exact ⟨hc.1, hc.2, (Option.some.inj h).symm⟩
  · exact absurd h (by simp)

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

/-- Each shard's APPLIED list is exactly the records touching it, in spine order; shards `0 .. K-1` of the stored `K`
    (STMT-CHANGE-34: not the pack's `K`, as `merge`).  The pack arguments are unused. -/
def appliedOk (_pk : Pack) (_cx : Ctx) (ss : SS) : Prop :=
  ∀ k < ss.1.k, (ss.2 k).applied = (ss.1.recs.reverse.filter fun R => k ∈ R.touched).map (·.n)

/-- One event of the merged history: a shard's tip (its head and the spine's `heads(k)`), a spine record with the
    shards whose next APPLIED entry is its number, ascending, or a shard's APPLIED entries no record claims. -/
inductive Ev where
  | tip (k : Nat) (shard spine : Dg)
  | record (R : Rec) (parts : List Nat)
  | orphan (k : Nat) (left : List Nat)

/-- Shard `k`'s next pending APPLIED entry is `n`. -/
def nextIs (pend : Nat → List Nat) (n k : Nat) : Bool := decide ((pend k).head? = some n)

/-- Interleave the spine records (oldest first) with the shards' pending APPLIED lists. -/
def mergeGo (K : Nat) : List Rec → (Nat → List Nat) → List Ev
  | [], pend => ((List.range K).filter fun k => !(pend k).isEmpty).map fun k => .orphan k (pend k)
  | R :: rs, pend => .record R ((List.range K).filter (nextIs pend R.n)) ::
      mergeGo K rs fun k => if nextIs pend R.n k then (pend k).tail else pend k

/-- `mergeHist`: every shard's tip (`k < K`), then per record, oldest first, the record and the shards `k < K` whose
    next pending APPLIED entry is its number, ascending `k`; then one orphan per shard with APPLIED entries left. -/
def mergeHist (_pk : Pack) (_cx : Ctx) (ss : SS) : List Ev :=
  ((List.range ss.1.k).map fun k => Ev.tip k (ss.2 k).head (ss.1.heads k)) ++
    mergeGo ss.1.k ss.1.recs.reverse fun k => (ss.2 k).applied

/-- One pass over a merged history from record number `i`: each tip's heads agree, record numbers run `i, i+1, ...`,
    each record's parts are exactly the shards below `K` it touches, and no APPLIED entry is left over. -/
def evOk (K : Nat) : Nat → List Ev → Bool
  | _, [] => true
  | i, .tip _ a b :: t => (a == b) && evOk K i t
  | i, .record R ks :: t =>
      decide (R.n = i) && decide (ks = (List.range K).filter fun k => decide (k ∈ R.touched)) && evOk K (i + 1) t
  | _, .orphan _ _ :: _ => false

/-- `evOk` from record number 0 with the stored `K = ss.1.k` (STMT-CHANGE-34: not the pack's; the history is read
    from the store `ss`): tips agree, records run `0, 1, ...`, each record's parts are exactly the shards below `K`
    it touches, and there is no orphan. -/
def historyOk (ss : SS) (h : List Ev) : Bool := evOk ss.1.k 0 h

/-! ## Helpers -/

theorem kOf_pos : ∀ (l : List (PartId × Nat)) (p : PartId), (l.all fun x => 0 < x.2) = true → 0 < kOf l p
  | [], _, _ => Nat.one_pos
  | (q, n) :: t, p, h => by
    simp only [List.all_cons, Bool.and_eq_true, decide_eq_true_eq] at h
    simp only [kOf]
    split
    · exact h.1
    · exact kOf_pos t p h.2

theorem judgeRows_keep (pk : Pack) (cx : Ctx) : ∀ (d : Dir) (rs : List Row) (c : Cell) (x : DirRow),
    d c = some x → (judgeRows pk cx d rs).1 c = some x
  | d, [], c, x, h => h
  | d, r :: rs, c, x, h => by
    show (judgeRows pk cx (judgeRow pk cx d r).1 rs).1 c = some x
    apply judgeRows_keep pk cx _ rs c x
    unfold judgeRow
    split
    · exact h
    · next hn =>
      simp only [setDir]
      split
      · next he => subst he; rw [hn] at h; cases h
      · exact h

theorem judgeRows_admit (pk : Pack) (cx : Ctx) (h : Home) : ∀ (d : Dir) (rs : List Row) (a : Row × Verdict),
    a ∈ (judgeRows pk cx d rs).2 → a.2 = .admit h → ∃ x, (judgeRows pk cx d rs).1 a.1.cell = some x ∧ x.home = h
  | d, [], a, hm, _ => by simp [judgeRows] at hm
  | d, r :: rs, a, hm, hv => by
    simp only [judgeRows, List.mem_cons] at hm
    rcases hm with rfl | ht
    · change (judgeRow pk cx d r).2 = _ at hv
      have key : ∃ x, (judgeRow pk cx d r).1 r.cell = some x ∧ x.home = h := by
        revert hv
        unfold judgeRow
        cases hd : d r.cell with
        | some y => intro hv; dsimp only at hv; split at hv <;> cases hv
        | none =>
          intro hv; dsimp only at hv ⊢; cases hv
          exact ⟨⟨routeNew pk cx r, r.raw, r.gross, r.item⟩, by simp [setDir], rfl⟩
      obtain ⟨x, hx, hh⟩ := key
      exact ⟨x, judgeRows_keep pk cx _ rs r.cell x hx, hh⟩
    · exact judgeRows_admit pk cx h _ rs a ht hv

theorem part_home (pk : Pack) (cx : Ctx) (sv : SpineView) (inp : Input) (h : Home) {r : Row}
    (hr : r ∈ part (judge pk cx sv inp) h) : ∃ x, (judge pk cx sv inp).dir r.cell = some x ∧ x.home = h := by
  simp only [part, List.mem_map, List.mem_filter, beq_iff_eq] at hr
  obtain ⟨a, ⟨hm, hv⟩, rfl⟩ := hr
  exact judgeRows_admit pk cx h sv.dir inp.rows a hm hv

theorem finRows_local (S : Cell → Prop) : ∀ (rs : List Row) (vs : List Bool) (chg chg' : Cell → Nat),
    (∀ r ∈ rs, S r.cell) → (∀ c, S c → chg c = chg' c) →
    (∀ c, S c → (finRows chg rs vs).1 c = (finRows chg' rs vs).1 c) ∧ (finRows chg rs vs).2 = (finRows chg' rs vs).2
  | [], _, _, _, _, h => ⟨h, rfl⟩
  | r :: rs, vs, chg, chg', hS, h => by
    have hr : chg r.cell = chg' r.cell := h _ (hS r (List.mem_cons_self ..))
    have h1 : ∀ c, S c → (if (vs.headD false && chg r.cell == 0) = true then bump chg r.cell else chg) c =
        (if (vs.headD false && chg' r.cell == 0) = true then bump chg' r.cell else chg') c := by
      intro c hc; rw [hr]; split <;> simp only [bump, h c hc]
    obtain ⟨ih1, ih2⟩ := finRows_local S rs vs.tail _ _ (fun r' hr' => hS r' (List.mem_cons_of_mem _ hr')) h1
    simp only [finRows]
    exact ⟨ih1, by rw [ih2, hr]⟩

theorem finRows_le1 : ∀ (rs : List Row) (vs : List Bool) (chg : Cell → Nat), (∀ c, chg c ≤ 1) →
    ∀ c, (finRows chg rs vs).1 c ≤ 1
  | [], _, _, h, c => h c
  | r :: rs, vs, chg, h, c => by
    simp only [finRows]
    apply finRows_le1 rs vs.tail _ _ c
    intro c'
    split
    · next hm =>
      simp only [Bool.and_eq_true, beq_iff_eq] at hm
      simp only [bump]
      split
      · next he => subst he; have := hm.2; omega
      · exact h c'
    · exact h c'

theorem finRows_supp : ∀ (rs : List Row) (vs : List Bool) (chg : Cell → Nat) (c : Cell),
    0 < (finRows chg rs vs).1 c → 0 < chg c ∨ ∃ r ∈ rs, r.cell = c
  | [], _, _, _, h => .inl h
  | r :: rs, vs, chg, c, h => by
    simp only [finRows] at h
    rcases finRows_supp rs vs.tail _ c h with h1 | ⟨r', hr', he⟩
    · split at h1
      · simp only [bump] at h1
        split at h1
        · next he => exact .inr ⟨r, List.mem_cons_self .., he.symm⟩
        · exact .inl h1
      · exact .inl h1
    · exact .inr ⟨r', List.mem_cons_of_mem _ hr', he⟩

theorem sum_zeroN (f : Nat → Nat) : ∀ l : List Nat, (∀ x ∈ l, f x = 0) → (l.map f).sum = 0
  | [], _ => rfl
  | x :: l, h => by
    rw [List.map_cons, List.sum_cons, h x (List.mem_cons_self ..),
      sum_zeroN f l fun y hy => h y (List.mem_cons_of_mem _ hy)]

theorem sum_le_one (f : Nat → Nat) (hf : ∀ k, f k ≤ 1) (hu : ∀ k k', 0 < f k → 0 < f k' → k = k') :
    ∀ l : List Nat, l.Nodup → (l.map f).sum ≤ 1
  | [], _ => Nat.zero_le 1
  | k :: l, hn => by
    rw [List.nodup_cons] at hn
    simp only [List.map_cons, List.sum_cons]
    by_cases hk : f k = 0
    · have := sum_le_one f hf hu l hn.2; omega
    · have h0 := sum_zeroN f l fun x hx => by
        cases hx0 : f x with
        | zero => rfl
        | succ m =>
          obtain rfl := hu k x (Nat.pos_of_ne_zero hk) (by omega)
          exact absurd hx hn.1
      have := hf k; omega

theorem sum_range_zeroI (f : Nat → Int) : ∀ K : Nat, 0 < K → (∀ k, k ≠ 0 → f k = 0) →
    ((List.range K).map f).sum = f 0
  | 0, h, _ => absurd h (Nat.lt_irrefl 0)
  | n + 1, _, hf => by
    rw [List.range_succ_eq_map, List.map_cons, List.sum_cons, List.map_map,
      Partition.sum_zero (f ∘ Nat.succ) (List.range n) fun k _ => hf _ (Nat.succ_ne_zero k), Int.add_zero]

theorem sum_range_zeroN (f : Nat → Nat) : ∀ K : Nat, 0 < K → (∀ k, k ≠ 0 → f k = 0) →
    ((List.range K).map f).sum = f 0
  | 0, h, _ => absurd h (Nat.lt_irrefl 0)
  | n + 1, _, hf => by
    rw [List.range_succ_eq_map, List.map_cons, List.sum_cons, List.map_map,
      sum_zeroN (f ∘ Nat.succ) (List.range n) fun k _ => hf _ (Nat.succ_ne_zero k), Nat.add_zero]

theorem initShards_ne (L : Legacy) {k : Nat} (hk : k ≠ 0) : initShards L k = initShard := if_neg hk

/-- Summing a shard field over `0..K-1` right after migration gives shard 0's value, when K ≥ 1 or that value
    is 0. -/
theorem init_sumI (f : ShardDB → Int) (L : Legacy) (K : Nat) (hf : f initShard = 0)
    (h : 0 < K ∨ f (initShards L 0) = 0) :
    ((List.range K).map fun k => f (initShards L k)).sum = f (initShards L 0) := by
  cases h with
  | inl hK =>
    exact sum_range_zeroI (fun k => f (initShards L k)) K hK fun k hk => by
      show f (initShards L k) = 0; rw [initShards_ne L hk]; exact hf
  | inr h0 =>
    rw [h0]
    exact Partition.sum_zero (fun k => f (initShards L k)) _ fun k _ => by
      by_cases hk : k = 0
      · subst hk; exact h0
      · show f (initShards L k) = 0; rw [initShards_ne L hk]; exact hf

theorem init_sumN (f : ShardDB → Nat) (L : Legacy) (K : Nat) (hf : f initShard = 0)
    (h : 0 < K ∨ f (initShards L 0) = 0) :
    ((List.range K).map fun k => f (initShards L k)).sum = f (initShards L 0) := by
  cases h with
  | inl hK =>
    exact sum_range_zeroN (fun k => f (initShards L k)) K hK fun k hk => by
      show f (initShards L k) = 0; rw [initShards_ne L hk]; exact hf
  | inr h0 =>
    rw [h0]
    exact sum_zeroN (fun k => f (initShards L k)) _ fun k _ => by
      by_cases hk : k = 0
      · subst hk; exact h0
      · show f (initShards L k) = 0; rw [initShards_ne L hk]; exact hf

/-- The gate invariant: a shard holds at most one MOVE charge per cell, and only for cells the directory homes
    at that shard. -/
def Inv (ss : SS) : Prop :=
  ∀ c, (∀ k, (ss.2 k).chg c ≤ 1) ∧ (∀ k, 0 < (ss.2 k).chg c → ∃ x, ss.1.dir c = some x ∧ x.home = .shard k)

theorem inv_step (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) (hI : Inv ss) : Inv (stepT pk cx ss inp) := by
  unfold stepT stepS
  split
  · intro c
    obtain ⟨hle, hdir⟩ := hI c
    refine ⟨fun k => ?_, fun k hk => ?_⟩
    · show (commitShards (mkRec pk cx ss inp).2 (mkRec pk cx ss inp).2.touched ss.2 k).chg c ≤ 1
      unfold commitShards
      split
      · exact finRows_le1 _ _ _ (fun c' => (hI c').1 k) c
      · exact hle k
    · change 0 < (commitShards (mkRec pk cx ss inp).2 (mkRec pk cx ss inp).2.touched ss.2 k).chg c at hk
      change ∃ x, (judge pk cx ss.1.view inp).dir c = some x ∧ x.home = .shard k
      unfold commitShards at hk
      split at hk
      · rcases finRows_supp _ _ _ c hk with h0 | ⟨r, hr, rfl⟩
        · obtain ⟨x, hx, hh⟩ := hdir k h0
          exact ⟨x, judgeRows_keep pk cx _ _ _ x hx, hh⟩
        · exact part_home pk cx ss.1.view inp (.shard k) hr
      · obtain ⟨x, hx, hh⟩ := hdir k hk
        exact ⟨x, judgeRows_keep pk cx _ _ c x hx, hh⟩
  · exact hI

theorem inv_run (pk : Pack) (cx : Ctx) : ∀ (ss : SS) (rs : List Input), Inv ss → Inv (runS pk cx ss rs)
  | _, [], h => h
  | ss, r :: rs, h => inv_run pk cx _ rs (inv_step pk cx ss r h)

theorem inv_init {K : Nat} (L : Legacy) : Inv (initS K L) := fun c => by
  refine ⟨fun k => ?_, fun k hk => ?_⟩
  · show (initShards L k).chg c ≤ 1
    by_cases h0 : k = 0
    · subst h0; exact L.chg_le c
    · rw [initShards_ne L h0]; exact Nat.zero_le 1
  · change 0 < (initShards L k).chg c at hk
    change ∃ x, backfill L c = some x ∧ x.home = .shard k
    by_cases h0 : k = 0
    · subst h0
      cases hc : L.cells c with
      | none => exact absurd hc (L.chg_cell c hk)
      | some y => exact ⟨⟨.shard 0, y.1, y.2, L.item c⟩, by simp [backfill, hc], rfl⟩
    · rw [initShards_ne L h0] at hk; exact absurd hk (Nat.lt_irrefl 0)

/-- Every shard head equals the spine's head, and APPLIED lists the records touching the shard, in order. -/
def Inv3 (ss : SS) : Prop := ∀ k, (ss.2 k).head = ss.1.heads k ∧
  (ss.2 k).applied = (ss.1.recs.reverse.filter fun R => k ∈ R.touched).map (·.n)

theorem inv3_step (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) (h : Inv3 ss) : Inv3 (stepT pk cx ss inp) := by
  unfold stepT stepS
  split
  · intro k
    obtain ⟨h1, h2⟩ := h k
    by_cases hk : k ∈ (mkRec pk cx ss inp).2.touched
    · simp [commitShards, commitSpine, applyPart, hk, h2]
    · simp [commitShards, commitSpine, hk, h1, h2]
  · exact h

theorem inv3_run (pk : Pack) (cx : Ctx) : ∀ (ss : SS) (rs : List Input), Inv3 ss → Inv3 (runS pk cx ss rs)
  | _, [], h => h
  | ss, r :: rs, h => inv3_run pk cx _ rs (inv3_step pk cx ss r h)

theorem inv3_init {K : Nat} (L : Legacy) : Inv3 (initS K L) := fun k => by
  refine ⟨rfl, ?_⟩
  show (initShards L k).applied = _
  have ha : (initShards L k).applied = [] := by
    by_cases h0 : k = 0
    · subst h0; rfl
    · rw [initShards_ne L h0]; rfl
  rw [ha]
  simp [initS, genesis]

/-- STMT-CHANGE-5 (branch old L893-895 checked only the newest record's image): the stored `K` is the pack's, and
    every record's image, if any, is the one its post heads commit to. -/
def InvK (pk : Pack) (cx : Ctx) (ss : SS) : Prop :=
  ss.1.k = pk.k cx.p ∧ ss.1.recs.all (imgOk cx) = true

/-- A step adds a record without an image, so every image stays the one its post heads commit to. -/
theorem imgs_step (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) (h : ss.1.recs.all (imgOk cx) = true) :
    (stepT pk cx ss inp).1.recs.all (imgOk cx) = true := by
  unfold stepT stepS
  split
  · show ((mkRec pk cx ss inp).2 :: ss.1.recs).all (imgOk cx) = true
    rw [List.all_cons, h]; rfl
  · exact h

theorem imgs_run (pk : Pack) (cx : Ctx) : ∀ (ss : SS) (rs : List Input), ss.1.recs.all (imgOk cx) = true →
    (runS pk cx ss rs).1.recs.all (imgOk cx) = true
  | _, [], h => h
  | ss, r :: rs, h => imgs_run pk cx _ rs (imgs_step pk cx ss r h)

theorem invK_step (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) (h : InvK pk cx ss) :
    InvK pk cx (stepT pk cx ss inp) := by
  refine ⟨?_, imgs_step pk cx ss inp h.2⟩
  unfold stepT stepS
  split
  · exact h.1
  · exact h.1

theorem invK_run (pk : Pack) (cx : Ctx) : ∀ (ss : SS) (rs : List Input), InvK pk cx ss → InvK pk cx (runS pk cx ss rs)
  | _, [], h => h
  | ss, r :: rs, h => invK_run pk cx _ rs (invK_step pk cx ss r h)

theorem invK_init (pk : Pack) (cx : Ctx) (L : Legacy) : InvK pk cx (initS (pk.k cx.p) L) := ⟨rfl, rfl⟩

theorem reach_invK (pk : Pack) (cx : Ctx) (ss : SS) (h : reachS pk cx ss) : InvK pk cx ss := by
  obtain ⟨L, rs, rfl⟩ := h; exact invK_run pk cx _ rs (invK_init pk cx L)

theorem chain_step (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) (h : chainsOk ss) :
    chainsOk (stepT pk cx ss inp) := by
  unfold stepT stepS
  split
  · show ((mkRec pk cx ss inp).2 :: ss.1.recs).reverse.map (·.n) = List.range' 0 (ss.1.recs.length + 1)
    rw [List.reverse_cons, List.map_append, h, List.range'_concat]
    simp [mkRec]
  · exact h

theorem chain_run (pk : Pack) (cx : Ctx) : ∀ (ss : SS) (rs : List Input), chainsOk ss → chainsOk (runS pk cx ss rs)
  | _, [], h => h
  | ss, r :: rs, h => chain_run pk cx _ rs (chain_step pk cx ss r h)

theorem chain_init {K : Nat} (L : Legacy) : chainsOk (initS K L) := rfl

/-- On an `Inv3`, `chainsOk` state (every reachable one) the shard and numbering checks pass, so the writer decides
    by the judgement alone.  CHANGED (2026-10-09, RGL-FIX2 L-2): gains `chainsOk ss`, since `checkAll` checks it.
    STMT-CHANGE-6 (trunk L930): gains `hK : ss.1.k = pk.k cx.p`, since `checkAll` checks `kOk`. -/
theorem checkAll_of_inv3 (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) (h3 : Inv3 ss) (hn : chainsOk ss)
    (hK : ss.1.k = pk.k cx.p) : checkAll pk cx ss inp = (judge pk cx ss.1.view inp).ok := by
  have hf : fitsOk pk cx ss = true := List.all_eq_true.2 fun k _ => decide_eq_true (h3 k)
  have hk : kOk pk cx ss = true := by simp [kOk, hK]
  rw [checkAll, hf, hk, decide_eq_true hn, Bool.true_and, Bool.and_true, Bool.and_true]

/-- A tampered spine holding two records with the same `n` is refused, whatever the shards hold (osbench refuses it
    by the `applied.n` PRIMARY KEY). -/
theorem dup_n_refused (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) (hd : ¬ (ss.1.recs.map (·.n)).Nodup) :
    checkAll pk cx ss inp = false := by
  cases hc : checkAll pk cx ss inp
  · rfl
  · simp only [checkAll, Bool.and_eq_true, decide_eq_true_eq] at hc
    have hnd : ((ss.1.recs.map (·.n)).reverse).Nodup := by
        rw [← List.map_reverse, show ss.1.recs.reverse.map (·.n) = _ from hc.1.1.1]; exact List.nodup_range'
    exact absurd ((List.pairwise_reverse.1 hnd).imp fun h e => h e.symm) hd

theorem judgeRow_new (pk : Pack) (cx : Ctx) (d : Dir) (r : Row) (h : Home)
    (hv : (judgeRow pk cx d r).2 = .admit h) : d r.cell = none ∧ ∃ x, (judgeRow pk cx d r).1 r.cell = some x := by
  revert hv
  unfold judgeRow
  cases hd : d r.cell with
  | some y => intro hv; dsimp only at hv; split at hv <;> cases hv
  | none => intro _; exact ⟨rfl, ⟨routeNew pk cx r, r.raw, r.gross, r.item⟩, by simp [setDir]⟩

/-- Rows whose verdict `p` selects (every selected verdict an admit) were new to the directory the judgment
    started from, and their cells are distinct. -/
theorem judgeRows_freshP (pk : Pack) (cx : Ctx) (p : Verdict → Bool) (hp : ∀ v, p v = true → ∃ h, v = .admit h) :
    ∀ (d : Dir) (rs : List Row),
    (∀ a ∈ (judgeRows pk cx d rs).2, p a.2 = true → d a.1.cell = none) ∧
    ((judgeRows pk cx d rs).2.filter fun x => p x.2).Pairwise (fun a b => a.1.cell ≠ b.1.cell)
  | d, [] => ⟨fun _ hm => by simp [judgeRows] at hm, by simp [judgeRows]⟩
  | d, r :: rs => by
    obtain ⟨ih1, ih2⟩ := judgeRows_freshP pk cx p hp (judgeRow pk cx d r).1 rs
    have hmono : ∀ c, (judgeRow pk cx d r).1 c = none → d c = none := fun c hc => by
      cases hd : d c with
      | none => rfl
      | some x =>
        have hk := judgeRows_keep pk cx d [r] c x hd
        change (judgeRow pk cx d r).1 c = some x at hk
        rw [hc] at hk; cases hk
    show (∀ a ∈ (r, (judgeRow pk cx d r).2) :: (judgeRows pk cx (judgeRow pk cx d r).1 rs).2,
        p a.2 = true → d a.1.cell = none) ∧
      (((r, (judgeRow pk cx d r).2) :: (judgeRows pk cx (judgeRow pk cx d r).1 rs).2).filter
        fun x => p x.2).Pairwise (fun a b => a.1.cell ≠ b.1.cell)
    refine ⟨fun a hm hv => ?_, ?_⟩
    · rcases List.mem_cons.1 hm with rfl | ht
      · obtain ⟨h, e⟩ := hp _ hv
        exact (judgeRow_new pk cx d r h e).1
      · exact hmono _ (ih1 a ht hv)
    · rw [List.filter_cons]
      split
      · next hv =>
        obtain ⟨h, hv'⟩ := hp _ hv
        obtain ⟨_, x, hx⟩ := judgeRow_new pk cx d r h hv'
        refine List.Pairwise.cons (fun b hb => ?_) ih2
        have hb' := List.mem_filter.1 hb
        have h0 := ih1 b hb'.1 (by simpa using hb'.2)
        intro he
        have he' : r.cell = b.1.cell := he
        rw [← he', hx] at h0
        cases h0
      · exact ih2

/-- Rows admitted at `h` were new to the directory the judgment started from, and their cells are distinct. -/
theorem judgeRows_fresh (pk : Pack) (cx : Ctx) (h : Home) (d : Dir) (rs : List Row) :
    (∀ a ∈ (judgeRows pk cx d rs).2, a.2 = .admit h → d a.1.cell = none) ∧
    ((judgeRows pk cx d rs).2.filter fun x => x.2 == .admit h).Pairwise (fun a b => a.1.cell ≠ b.1.cell) :=
  let e := judgeRows_freshP pk cx (· == .admit h) (fun _ hv => ⟨h, beq_iff_eq.1 hv⟩) d rs
  ⟨fun a ha hv => e.1 a ha (beq_iff_eq.2 hv), e.2⟩

theorem isSh_admit (v : Verdict) (hv : isSh v = true) : ∃ h, v = .admit h := by
  cases v with
  | admit h => exact ⟨h, rfl⟩
  | duplicate => cases hv
  | conflict => cases hv

/-- An admitted row's home is its route. -/
theorem judgeRows_route (pk : Pack) (cx : Ctx) : ∀ (d : Dir) (rs : List Row),
    ∀ a ∈ (judgeRows pk cx d rs).2, ∀ h, a.2 = .admit h → h = routeNew pk cx a.1
  | _, [] => fun _ hm => by simp [judgeRows] at hm
  | d, r :: rs => fun a hm h hv => by
    have hm' : a ∈ (r, (judgeRow pk cx d r).2) :: (judgeRows pk cx (judgeRow pk cx d r).1 rs).2 := hm
    rcases List.mem_cons.1 hm' with rfl | ht
    · revert hv
      show (judgeRow pk cx d r).2 = .admit h → h = routeNew pk cx r
      unfold judgeRow
      cases d r.cell with
      | some y => intro hv; dsimp only at hv; split at hv <;> cases hv
      | none => intro hv; dsimp only at hv; exact (Verdict.admit.inj hv).symm
    · exact judgeRows_route pk cx _ rs a ht h hv

theorem route_sidx (pk : Pack) (cx : Ctx) (r : Row) (j : Nat) (h : routeNew pk cx r = .shard j) :
    sidx pk cx r.item = j ∧ (0 < pk.k cx.p → j < pk.k cx.p) := by
  unfold routeNew at h
  cases hp : r.positive <;> cases hi : r.item <;> simp only [hp, hi] at h <;>
    first | exact ⟨Home.shard.inj h, fun hk => by rw [← Home.shard.inj h]; exact Nat.mod_lt _ hk⟩ | cases h

theorem part_fresh (pk : Pack) (cx : Ctx) (sv : SpineView) (inp : Input) (h : Home) :
    (part (judge pk cx sv inp) h).Pairwise (fun a b => a.cell ≠ b.cell) ∧
      ∀ r ∈ part (judge pk cx sv inp) h, sv.dir r.cell = none := by
  obtain ⟨h1, h2⟩ := judgeRows_fresh pk cx h sv.dir inp.rows
  refine ⟨by unfold part; exact List.pairwise_map.2 h2, fun r hr => ?_⟩
  simp only [part, List.mem_map, List.mem_filter, beq_iff_eq] at hr
  obtain ⟨a, ⟨hm, hv⟩, rfl⟩ := hr
  exact h1 a hm hv

/-- On distinct cells with no charge, the shard transaction charges exactly the stateless `vsum`. -/
theorem finRows_vsum : ∀ (rs : List Row) (vs : List Bool) (chg : Cell → Nat),
    rs.Pairwise (fun a b => a.cell ≠ b.cell) → (∀ r ∈ rs, chg r.cell = 0) → (finRows chg rs vs).2 = vsum rs vs
  | [], _, _, _, _ => rfl
  | r :: rs, vs, chg, hp, hz => by
    rw [List.pairwise_cons] at hp
    have h0 := hz r (List.mem_cons_self ..)
    have ih : ∀ chg' : Cell → Nat, (∀ r' ∈ rs, chg' r'.cell = chg r'.cell) →
        (finRows chg' rs vs.tail).2 = vsum rs vs.tail := fun chg' h =>
      finRows_vsum rs vs.tail chg' hp.2 fun r' hr' => (h r' hr').trans (hz r' (List.mem_cons_of_mem _ hr'))
    simp only [finRows, vsum]
    rw [ih]
    · rw [h0]; simp
    · intro r' hr'
      split
      · simp only [bump]; rw [if_neg (Ne.symm (hp.1 r' hr'))]
      · rfl

theorem inv_zero {ss : SS} (hI : Inv ss) (c : Cell) (hc : ss.1.dir c = none) (k : Nat) : (ss.2 k).chg c = 0 := by
  cases h : (ss.2 k).chg c with
  | zero => rfl
  | succ m =>
    obtain ⟨x, hx, _⟩ := (hI c).2 k (by omega)
    rw [hc] at hx; cases hx

theorem sum_filter (p : Nat → Bool) (f : Nat → Int) : ∀ l : List Nat,
    ((l.filter p).map f).sum = (l.map fun k => if p k then f k else 0).sum
  | [] => rfl
  | k :: l => by
    rw [List.filter_cons, List.map_cons, List.sum_cons, ← sum_filter p f l]
    cases p k <;> simp

theorem commit_mem (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) {k : Nat} (hk : k ∈ List.range (pk.k cx.p)) :
    k ∈ (mkRec pk cx ss inp).2.touched ↔ (!(part (judge pk cx ss.1.view inp) (.shard k)).isEmpty) = true := by
  simp only [mkRec, touched, List.mem_filter, hk, true_and]

theorem commit_gross (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) {k : Nat} (hk : k ∈ List.range (pk.k cx.p)) :
    (commitShards (mkRec pk cx ss inp).2 (mkRec pk cx ss inp).2.touched ss.2 k).gross = (ss.2 k).gross +
      if (!(part (judge pk cx ss.1.view inp) (.shard k)).isEmpty) = true then
        gsum (part (judge pk cx ss.1.view inp) (.shard k)) else 0 := by
  unfold commitShards
  by_cases ht : k ∈ (mkRec pk cx ss inp).2.touched
  · rw [if_pos ht, if_pos ((commit_mem pk cx ss inp hk).1 ht)]; rfl
  · rw [if_neg ht, if_neg fun h => ht ((commit_mem pk cx ss inp hk).2 h), Int.add_zero]

theorem commit_mc (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) (hI : Inv ss) {k : Nat}
    (hk : k ∈ List.range (pk.k cx.p)) :
    (commitShards (mkRec pk cx ss inp).2 (mkRec pk cx ss inp).2.touched ss.2 k).mc = (ss.2 k).mc +
      if (!(part (judge pk cx ss.1.view inp) (.shard k)).isEmpty) = true then
        vsum (part (judge pk cx ss.1.view inp) (.shard k)) (verdicts cx (judge pk cx ss.1.view inp) k) else 0 := by
  unfold commitShards
  by_cases ht : k ∈ (mkRec pk cx ss inp).2.touched
  · rw [if_pos ht, if_pos ((commit_mem pk cx ss inp hk).1 ht)]
    obtain ⟨hp, hf⟩ := part_fresh pk cx ss.1.view inp (.shard k)
    show (ss.2 k).mc + (finRows (ss.2 k).chg (part (judge pk cx ss.1.view inp) (.shard k))
      (verdicts cx (judge pk cx ss.1.view inp) k)).2 = _
    rw [finRows_vsum _ _ _ hp fun r hr => inv_zero hI r.cell (hf r hr) k]
  · rw [if_neg ht, if_neg fun h => ht ((commit_mem pk cx ss inp hk).2 h), Int.add_zero]

/-- Pool used is the shards' gross; budget is the shards' machine charges plus LINK charges. -/
def Inv4 (pk : Pack) (cx : Ctx) (ss : SS) : Prop :=
  ss.1.used = ((List.range (pk.k cx.p)).map fun k => (ss.2 k).gross).sum ∧
    ss.1.budget = ((List.range (pk.k cx.p)).map fun k => (ss.2 k).mc).sum + ss.1.lc

theorem inv4_step (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) (hI : Inv ss) (h4 : Inv4 pk cx ss) :
    Inv4 pk cx (stepT pk cx ss inp) := by
  unfold stepT stepS
  split
  · obtain ⟨hu, hb⟩ := h4
    refine ⟨?_, ?_⟩
    · show ss.1.used + ((mkRec pk cx ss inp).2.touched.map fun k => gsum ((mkRec pk cx ss inp).2.I k)).sum =
        ((List.range (pk.k cx.p)).map fun k =>
          (commitShards (mkRec pk cx ss inp).2 (mkRec pk cx ss inp).2.touched ss.2 k).gross).sum
      have hT : ((mkRec pk cx ss inp).2.touched.map fun k => gsum ((mkRec pk cx ss inp).2.I k)).sum =
          ((List.range (pk.k cx.p)).map fun k =>
            if (!(part (judge pk cx ss.1.view inp) (.shard k)).isEmpty) = true then
              gsum (part (judge pk cx ss.1.view inp) (.shard k)) else 0).sum :=
        sum_filter (fun k => !(part (judge pk cx ss.1.view inp) (.shard k)).isEmpty)
          (fun k => gsum (part (judge pk cx ss.1.view inp) (.shard k))) (List.range (pk.k cx.p))
      rw [List.map_congr_left fun k hk => commit_gross pk cx ss inp hk, Partition.sum_map_add, ← hu, hT]
    · show ss.1.budget + ((mkRec pk cx ss inp).2.touched.map fun k =>
          vsum ((mkRec pk cx ss inp).2.I k) ((mkRec pk cx ss inp).2.V k)).sum +
          gsum (part (mkRec pk cx ss inp).1 .spine) =
        ((List.range (pk.k cx.p)).map fun k =>
          (commitShards (mkRec pk cx ss inp).2 (mkRec pk cx ss inp).2.touched ss.2 k).mc).sum +
          (ss.1.lc + gsum (part (mkRec pk cx ss inp).1 .spine))
      have hT : ((mkRec pk cx ss inp).2.touched.map fun k =>
            vsum ((mkRec pk cx ss inp).2.I k) ((mkRec pk cx ss inp).2.V k)).sum =
          ((List.range (pk.k cx.p)).map fun k =>
            if (!(part (judge pk cx ss.1.view inp) (.shard k)).isEmpty) = true then
              vsum (part (judge pk cx ss.1.view inp) (.shard k)) (verdicts cx (judge pk cx ss.1.view inp) k)
            else 0).sum :=
        sum_filter (fun k => !(part (judge pk cx ss.1.view inp) (.shard k)).isEmpty)
          (fun k => vsum (part (judge pk cx ss.1.view inp) (.shard k)) (verdicts cx (judge pk cx ss.1.view inp) k))
          (List.range (pk.k cx.p))
      rw [List.map_congr_left fun k hk => commit_mc pk cx ss inp hI hk, Partition.sum_map_add, hb, hT]
      omega
  · exact h4

theorem inv4_run (pk : Pack) (cx : Ctx) :
    ∀ (ss : SS) (rs : List Input), Inv ss → Inv4 pk cx ss → Inv4 pk cx (runS pk cx ss rs)
  | _, [], _, h => h
  | ss, r :: rs, hI, h => inv4_run pk cx _ rs (inv_step pk cx ss r hI) (inv4_step pk cx ss r hI h)

theorem inv4_init (pk : Pack) (cx : Ctx) (L : Legacy) (hL : openOk pk cx L) : Inv4 pk cx (initS (pk.k cx.p) L) := by
  refine ⟨?_, ?_⟩
  · show L.used = ((List.range (pk.k cx.p)).map fun k => (initShards L k).gross).sum
    rw [init_sumI (·.gross) L _ rfl (hL.imp_right fun e => e.2.1)]
    exact L.used_eq
  · show L.budget = ((List.range (pk.k cx.p)).map fun k => (initShards L k).mc).sum + L.lc
    rw [init_sumI (·.mc) L _ rfl (hL.imp_right fun e => e.2.2)]
    exact L.budget_eq

theorem view_eq {a b : View} (h1 : a.dir = b.dir) (h2 : a.t = b.t) (h3 : a.used = b.used)
    (h4 : a.budget = b.budget) (h5 : a.lc = b.lc) (h6 : a.spineRows = b.spineRows) (h7 : a.chg = b.chg)
    (h8 : a.gross = b.gross) (h9 : a.mc = b.mc) : a = b := by
  cases a; cases b; simp only [View.mk.injEq]; exact ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9⟩

/-- MOVE charges `finalize` puts on cell `c` (stateless). -/
def vchg (c : Cell) : List Row → List Bool → Nat
  | [], _ => 0
  | r :: rs, vs => (if vs.headD false = true ∧ r.cell = c then 1 else 0) + vchg c rs vs.tail

theorem finRows_vchg (c : Cell) : ∀ (rs : List Row) (vs : List Bool) (chg : Cell → Nat),
    rs.Pairwise (fun a b => a.cell ≠ b.cell) → (∀ r ∈ rs, chg r.cell = 0) →
    (finRows chg rs vs).1 c = chg c + vchg c rs vs
  | [], _, _, _, _ => rfl
  | r :: rs, vs, chg, hp, hz => by
    rw [List.pairwise_cons] at hp
    have h0 := hz r (List.mem_cons_self ..)
    simp only [finRows, vchg]
    rw [finRows_vchg c rs vs.tail _ hp.2]
    · by_cases hc : r.cell = c
      · subst hc
        cases vs.headD false <;> simp [bump, h0]
      · cases vs.headD false <;> simp [bump, h0, hc, Ne.symm hc]
    · intro r' hr'
      split
      · simp only [bump]; rw [if_neg (Ne.symm (hp.1 r' hr'))]; exact hz r' (List.mem_cons_of_mem _ hr')
      · exact hz r' (List.mem_cons_of_mem _ hr')

theorem vchg_zero (c : Cell) : ∀ (rs : List Row) (vs : List Bool), (∀ r ∈ rs, r.cell ≠ c) → vchg c rs vs = 0
  | [], _, _ => rfl
  | r :: rs, vs, h => by
    simp [vchg, vchg_zero c rs vs.tail fun r' hr' => h r' (List.mem_cons_of_mem _ hr'),
      h r (List.mem_cons_self ..)]

theorem sum_filterN (p : Nat → Bool) (f : Nat → Nat) : ∀ l : List Nat,
    ((l.filter p).map f).sum = (l.map fun k => if p k then f k else 0).sum
  | [] => rfl
  | k :: l => by
    rw [List.filter_cons, List.map_cons, List.sum_cons, ← sum_filterN p f l]
    cases p k <;> simp

theorem sum_map_addN {α} (f g : α → Nat) : ∀ l : List α,
    (l.map fun x => f x + g x).sum = (l.map f).sum + (l.map g).sum
  | [] => rfl
  | x :: l => by simp only [List.map_cons, List.sum_cons, sum_map_addN f g l]; omega

theorem sum_touched (pk : Pack) (cx : Ctx) (J : Judgment) (f : Nat → Int) : ((touched pk cx J).map f).sum =
    ((List.range (pk.k cx.p)).map fun k => if (!(part J (.shard k)).isEmpty) = true then f k else 0).sum :=
  sum_filter _ f _

theorem sum_touchedN (pk : Pack) (cx : Ctx) (J : Judgment) (f : Nat → Nat) : ((touched pk cx J).map f).sum =
    ((List.range (pk.k cx.p)).map fun k => if (!(part J (.shard k)).isEmpty) = true then f k else 0).sum :=
  sum_filterN _ f _

/-- The single store's `finAll` over distinct shards whose parts are fresh, distinct and pairwise disjoint charges
    exactly `vsum` and adds exactly `vchg`. -/
theorem finAll_eq (J : Judgment) (V : Nat → List Bool) : ∀ (ks : List Nat) (chg : Cell → Nat), ks.Nodup →
    (∀ k ∈ ks, (part J (.shard k)).Pairwise (fun a b => a.cell ≠ b.cell)) →
    (∀ k ∈ ks, ∀ r ∈ part J (.shard k), chg r.cell = 0) →
    (∀ k ∈ ks, ∀ k' ∈ ks, k ≠ k' → ∀ r ∈ part J (.shard k), ∀ r' ∈ part J (.shard k'), r.cell ≠ r'.cell) →
    (finAll J V chg ks).2 = (ks.map fun k => vsum (part J (.shard k)) (V k)).sum ∧
    ∀ c, (finAll J V chg ks).1 c = chg c + (ks.map fun k => vchg c (part J (.shard k)) (V k)).sum
  | [], _, _, _, _, _ => ⟨rfl, fun _ => rfl⟩
  | k :: ks, chg, hn, hp, hz, hd => by
    rw [List.nodup_cons] at hn
    have hk : k ∈ k :: ks := List.mem_cons_self ..
    have ih := finAll_eq J V ks (finRows chg (part J (.shard k)) (V k)).1 hn.2
      (fun k' h' => hp k' (List.mem_cons_of_mem _ h'))
      (fun k' h' r hr => by
        have e1 := finRows_vchg r.cell _ (V k) _ (hp k hk) (hz k hk)
        have e2 := hz k' (List.mem_cons_of_mem _ h') r hr
        have e3 := vchg_zero r.cell (part J (.shard k)) (V k) fun r0 h0 =>
          hd k hk k' (List.mem_cons_of_mem _ h') (fun e => hn.1 (by rw [e]; exact h')) r0 h0 r hr
        omega)
      (fun a ha b hb => hd a (List.mem_cons_of_mem _ ha) b (List.mem_cons_of_mem _ hb))
    refine ⟨?_, fun c => ?_⟩
    · show (finRows chg (part J (.shard k)) (V k)).2 +
          (finAll J V (finRows chg (part J (.shard k)) (V k)).1 ks).2 = _
      rw [ih.1, finRows_vsum _ _ _ (hp k hk) (hz k hk), List.map_cons, List.sum_cons]
    · show (finAll J V (finRows chg (part J (.shard k)) (V k)).1 ks).1 c = _
      rw [ih.2 c, finRows_vchg c _ _ _ (hp k hk) (hz k hk), List.map_cons, List.sum_cons]
      omega

theorem commit_chg (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) (hI : Inv ss) (c : Cell) {k : Nat}
    (hk : k ∈ List.range (pk.k cx.p)) :
    (commitShards (mkRec pk cx ss inp).2 (mkRec pk cx ss inp).2.touched ss.2 k).chg c = (ss.2 k).chg c +
      if (!(part (judge pk cx ss.1.view inp) (.shard k)).isEmpty) = true then
        vchg c (part (judge pk cx ss.1.view inp) (.shard k)) (verdicts cx (judge pk cx ss.1.view inp) k) else 0 := by
  unfold commitShards
  by_cases ht : k ∈ (mkRec pk cx ss inp).2.touched
  · rw [if_pos ht, if_pos ((commit_mem pk cx ss inp hk).1 ht)]
    obtain ⟨hp, hf⟩ := part_fresh pk cx ss.1.view inp (.shard k)
    exact finRows_vchg c _ _ _ hp fun r hr => inv_zero hI r.cell (hf r hr) k
  · rw [if_neg ht, if_neg fun h => ht ((commit_mem pk cx ss inp hk).2 h), Nat.add_zero]

/-- A spine commit plus every touched shard's part merges to the single store's apply. -/
theorem merge_commit (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) (hI : Inv ss) (hK : ss.1.k = pk.k cx.p) :
    merge pk cx (commitSpine ss.1 (mkRec pk cx ss inp).1 (mkRec pk cx ss inp).2,
      commitShards (mkRec pk cx ss inp).2 (mkRec pk cx ss inp).2.touched ss.2) =
    applySingle pk cx (merge pk cx ss) (judge pk cx ss.1.view inp) (verdicts cx (judge pk cx ss.1.view inp)) := by
  have hF := finAll_eq (judge pk cx ss.1.view inp) (verdicts cx (judge pk cx ss.1.view inp))
    (touched pk cx (judge pk cx ss.1.view inp)) (merge pk cx ss).chg
    (List.Pairwise.filter _ List.nodup_range)
    (fun k _ => (part_fresh pk cx ss.1.view inp (.shard k)).1)
    (fun k _ r hr => sum_zeroN (fun k' => (ss.2 k').chg r.cell) (List.range ss.1.k) fun k' _ =>
      inv_zero hI r.cell ((part_fresh pk cx ss.1.view inp (.shard k)).2 r hr) k')
    (fun a _ b _ hab r hr r' hr' he => by
      obtain ⟨x, hx, hxh⟩ := part_home pk cx ss.1.view inp (.shard a) hr
      obtain ⟨y, hy, hyh⟩ := part_home pk cx ss.1.view inp (.shard b) hr'
      rw [he, hy] at hx
      cases hx
      exact hab (Home.shard.inj (hxh.symm.trans hyh)))
  refine view_eq rfl rfl rfl ?_ rfl rfl (funext fun c => ?_) ?_ ?_
  · show ss.1.budget + ((touched pk cx (judge pk cx ss.1.view inp)).map fun k =>
        vsum (part (judge pk cx ss.1.view inp) (.shard k)) (verdicts cx (judge pk cx ss.1.view inp) k)).sum +
        gsum (part (judge pk cx ss.1.view inp) .spine) =
      ss.1.budget + (finAll (judge pk cx ss.1.view inp) (verdicts cx (judge pk cx ss.1.view inp))
        (merge pk cx ss).chg (touched pk cx (judge pk cx ss.1.view inp))).2 +
        gsum (part (judge pk cx ss.1.view inp) .spine)
    rw [hF.1]
  · show ((List.range ss.1.k).map fun k =>
        (commitShards (mkRec pk cx ss inp).2 (mkRec pk cx ss inp).2.touched ss.2 k).chg c).sum =
      (finAll (judge pk cx ss.1.view inp) (verdicts cx (judge pk cx ss.1.view inp))
        (merge pk cx ss).chg (touched pk cx (judge pk cx ss.1.view inp))).1 c
    rw [hF.2 c]
    show _ = ((List.range ss.1.k).map fun k => (ss.2 k).chg c).sum +
      ((touched pk cx (judge pk cx ss.1.view inp)).map fun k =>
        vchg c (part (judge pk cx ss.1.view inp) (.shard k)) (verdicts cx (judge pk cx ss.1.view inp) k)).sum
    rw [hK, List.map_congr_left fun k hk => commit_chg pk cx ss inp hI c hk, sum_map_addN, sum_touchedN]
  · show ((List.range ss.1.k).map fun k =>
        (commitShards (mkRec pk cx ss inp).2 (mkRec pk cx ss inp).2.touched ss.2 k).gross).sum =
      ((List.range ss.1.k).map fun k => (ss.2 k).gross).sum +
        ((touched pk cx (judge pk cx ss.1.view inp)).map fun k =>
          gsum (part (judge pk cx ss.1.view inp) (.shard k))).sum
    rw [hK, List.map_congr_left fun k hk => commit_gross pk cx ss inp hk, Partition.sum_map_add, sum_touched]
  · show ((List.range ss.1.k).map fun k =>
        (commitShards (mkRec pk cx ss inp).2 (mkRec pk cx ss inp).2.touched ss.2 k).mc).sum =
      ((List.range ss.1.k).map fun k => (ss.2 k).mc).sum +
        (finAll (judge pk cx ss.1.view inp) (verdicts cx (judge pk cx ss.1.view inp))
          (merge pk cx ss).chg (touched pk cx (judge pk cx ss.1.view inp))).2
    rw [hF.1, hK, List.map_congr_left fun k hk => commit_mc pk cx ss inp hI hk, Partition.sum_map_add, sum_touched]

/-- CHANGED (2026-10-09, RGL-FIX2 L-2): `merge_step` and the `_run` theorems below gain `chainsOk ss`, as
    `checkAll_of_inv3`; `shard_run_eq` (from the migrated store) is unchanged.  STMT-CHANGE-7 (trunk L1256-1294,
    branch old L1245-1282): `merge_step`/`merge_run` take both `chainsOk ss` and `InvK pk cx ss`, since `merge`
    sums the stored `K` and `checkAll` checks `kOk`. -/
theorem merge_step (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) (hI : Inv ss) (h3 : Inv3 ss) (hn : chainsOk ss)
    (hK : InvK pk cx ss) : merge pk cx (stepT pk cx ss inp) = stepSingle pk cx (merge pk cx ss) inp := by
  show merge pk cx ((stepS pk cx ss inp).getD ss) =
    if (judge pk cx ss.1.view inp).ok = true then
      applySingle pk cx (merge pk cx ss) (judge pk cx ss.1.view inp) (verdicts cx (judge pk cx ss.1.view inp))
    else merge pk cx ss
  unfold stepS
  rw [checkAll_of_inv3 pk cx ss inp h3 hn hK.1]
  by_cases hok : (judge pk cx ss.1.view inp).ok = true
  · rw [if_pos hok, if_pos hok]
    exact merge_commit pk cx ss inp hI hK.1
  · rw [if_neg hok, if_neg hok, Option.getD_none]

theorem merge_run (pk : Pack) (cx : Ctx) : ∀ (ss : SS) (rs : List Input), Inv ss → Inv3 ss → chainsOk ss →
    InvK pk cx ss → merge pk cx (runS pk cx ss rs) = runSingle pk cx (merge pk cx ss) rs
  | _, [], _, _, _, _ => rfl
  | ss, r :: rs, hI, h3, hn, hK => by
    show merge pk cx (runS pk cx (stepT pk cx ss r) rs) = runSingle pk cx (stepSingle pk cx (merge pk cx ss) r) rs
    rw [← merge_step pk cx ss r hI h3 hn hK]
    exact merge_run pk cx _ rs (inv_step pk cx ss r hI) (inv3_step pk cx ss r h3) (chain_step pk cx ss r hn)
      (invK_step pk cx ss r hK)

theorem merge_congr (pk : Pack) (cx : Ctx) (sp : SpineDB) (sh sh2 : Nat → ShardDB)
    (h : ∀ k ∈ List.range sp.k, sh k = sh2 k) : merge pk cx (sp, sh) = merge pk cx (sp, sh2) := by
  refine view_eq rfl rfl rfl rfl rfl rfl (funext fun c => ?_) ?_ ?_
  · show ((List.range sp.k).map fun k => (sh k).chg c).sum =
      ((List.range sp.k).map fun k => (sh2 k).chg c).sum
    rw [List.map_congr_left fun k hk => congrArg (fun s => ShardDB.chg s c) (h k hk)]
  · show ((List.range sp.k).map fun k => (sh k).gross).sum =
      ((List.range sp.k).map fun k => (sh2 k).gross).sum
    rw [List.map_congr_left fun k hk => congrArg ShardDB.gross (h k hk)]
  · show ((List.range sp.k).map fun k => (sh k).mc).sum =
      ((List.range sp.k).map fun k => (sh2 k).mc).sum
    rw [List.map_congr_left fun k hk => congrArg ShardDB.mc (h k hk)]

/-! ## §9 statements -/

/-- K_p is positive under a well-formed pack. -/
theorem k_pos (pk : Pack) (p : PartId) (h : packOk pk = true) : 0 < pk.k p := by
  exact kOf_pos pk.ks p h

/-- K = 0 is refused: when `pk.k cx.p = 0`, the sharded step refuses every input on every state (`none`) and the
    single step leaves every store unchanged. -/
theorem k_zero_refused (pk : Pack) (cx : Ctx) (hK : pk.k cx.p = 0) (ss : SS) (s : Single) (inp : Input) :
    stepS pk cx ss inp = none ∧ stepSingle pk cx s inp = s := by
  have hp : packOk pk = false := by
    cases h : packOk pk with
    | false => rfl
    | true => have := k_pos pk cx.p h; omega
  simp [stepS, checkAll, stepSingle, judgeSingle, judge, hp]

/-- A new cell's home is the spine or exactly one shard below K. -/
theorem route_total (pk : Pack) (cx : Ctx) (r : Row) (h : packOk pk = true) :
    routeNew pk cx r = .spine ∨ ∃ k, k < pk.k cx.p ∧ routeNew pk cx r = .shard k := by
  unfold routeNew
  split
  · exact .inr ⟨_, Nat.mod_lt _ (k_pos pk cx.p h), rfl⟩
  · exact .inl rfl

/-- Ordinary steps keep `K` (review fix 8, lead 2026-10-07): on a store reachable by ordinary steps, a pack save
    that `packSaveOk` accepts keeps `K` of the store's partition.  `K` is set when the store opens and stored in the
    spine; only a RESHARD changes it (`Reshard.reshard_k`), after which only a pack with the new `K` saves
    (`Reshard.packSave_ok`).  A stale pack cannot step or RESHARD (`kOk`, `Reshard.stale_pack`), and `merge` sums
    the stored `K`, so it cannot misread the store either. -/
theorem shard_stable_run (pk pk' : Pack) (cx : Ctx) (ss : SS) (hr : reachS pk cx ss)
    (hu : packSaveOk pk' cx ss = true) : pk'.k cx.p = pk.k cx.p := by
  simp only [packSaveOk, kOk, Bool.and_eq_true, beq_iff_eq] at hu
  exact hu.2.symm.trans (reach_invK pk cx ss hr).1

/-- Routes never move: a directory row survives every step unchanged. -/
theorem dir_route_stable (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) (c : Cell) (x : DirRow)
    (h : ss.1.dir c = some x) : (stepT pk cx ss inp).1.dir c = some x := by
  unfold stepT stepS
  split
  · exact judgeRows_keep pk cx ss.1.dir inp.rows c x h
  · exact h

theorem dir_run (pk : Pack) (cx : Ctx) (c : Cell) (x : DirRow) :
    ∀ (ss : SS) (rs : List Input), ss.1.dir c = some x → (runS pk cx ss rs).1.dir c = some x
  | _, [], h => h
  | ss, r :: rs, h => dir_run pk cx c x _ rs (dir_route_stable pk cx ss r c x h)

/-- A row on a cell the directory already holds is DUPLICATE (equal raw) or CONFLICT, never ADMITTED. -/
theorem judgeRows_known (pk : Pack) (cx : Ctx) (c : Cell) (x : DirRow) :
    ∀ (d : Dir) (rs : List Row) (a : Row × Verdict), d c = some x → a ∈ (judgeRows pk cx d rs).2 →
      a.1.cell = c → a.2 = if x.raw = a.1.raw then .duplicate else .conflict
  | _, [], _, _, ha, _ => by simp [judgeRows] at ha
  | d, r :: rs, a, hd, ha, hc => by
    change a ∈ (r, (judgeRow pk cx d r).2) :: (judgeRows pk cx (judgeRow pk cx d r).1 rs).2 at ha
    cases List.mem_cons.1 ha with
    | inl h =>
      subst h
      change r.cell = c at hc
      show (judgeRow pk cx d r).2 = if x.raw = r.raw then .duplicate else .conflict
      simp only [judgeRow, hc, hd]
    | inr h => exact judgeRows_known pk cx c x _ rs a (judgeRows_keep pk cx d [r] c x hd) h hc

/-- Migration gate: judging any input on any state run from the migrated store, every row naming a legacy cell is
    DUPLICATE when its raw digest equals the legacy one and CONFLICT otherwise; it is never ADMITTED. -/
theorem legacy_resend (pk : Pack) (cx : Ctx) (L : Legacy) (rs : List Input) (inp : Input) {c : Cell} {raw : Dg}
    {g : Int} (hc : L.cells c = some (raw, g)) {a : Row × Verdict}
    (ha : a ∈ (judge pk cx (runS pk cx (initS (pk.k cx.p) L) rs).1.view inp).out) (hac : a.1.cell = c) :
    a.2 = if raw = a.1.raw then .duplicate else .conflict :=
  judgeRows_known pk cx c ⟨.shard 0, raw, g, L.item c⟩ (runS pk cx (initS (pk.k cx.p) L) rs).1.dir inp.rows a
    (dir_run pk cx c _ (initS (pk.k cx.p) L) rs (by simp [initS, backfill, hc])) ha hac

/-- Admitted rows of different homes in one judgment name different cells. -/
theorem parts_disjoint (pk : Pack) (cx : Ctx) (sv : SpineView) (inp : Input) {h h' : Home} (hh : h ≠ h')
    {r r' : Row} (hr : r ∈ part (judge pk cx sv inp) h) (hr' : r' ∈ part (judge pk cx sv inp) h') :
    r.cell ≠ r'.cell := by
  intro he
  obtain ⟨x, hx, hxh⟩ := part_home pk cx sv inp h hr
  obtain ⟨y, hy, hyh⟩ := part_home pk cx sv inp h' hr'
  rw [he, hy] at hx
  have hxy : y = x := Option.some.inj hx
  subst hxy
  exact hh (hxh.symm.trans hyh)

/-- Shard-local: shard k's transaction reads and writes only shard k's rows. -/
theorem part_local (pk : Pack) (cx : Ctx) (sv : SpineView) (inp : Input) (k : Nat) (V : List Bool)
    (chg chg' : Cell → Nat) (h : restrict (judge pk cx sv inp).dir k chg = restrict (judge pk cx sv inp).dir k chg') :
    restrict (judge pk cx sv inp).dir k (finRows chg (part (judge pk cx sv inp) (.shard k)) V).1 =
      restrict (judge pk cx sv inp).dir k (finRows chg' (part (judge pk cx sv inp) (.shard k)) V).1 ∧
    (finRows chg (part (judge pk cx sv inp) (.shard k)) V).2 =
      (finRows chg' (part (judge pk cx sv inp) (.shard k)) V).2 := by
  have hS : ∀ r ∈ part (judge pk cx sv inp) (.shard k),
      ((judge pk cx sv inp).dir r.cell).map (·.home) = some (.shard k) := fun r hr => by
    obtain ⟨x, hx, hh⟩ := part_home pk cx sv inp _ hr
    simp [hx, hh]
  have hE : ∀ c, ((judge pk cx sv inp).dir c).map (·.home) = some (.shard k) → chg c = chg' c := fun c hc => by
    have := congrFun h c
    simp only [restrict, if_pos hc] at this
    exact this
  obtain ⟨h1, h2⟩ := finRows_local (fun c => ((judge pk cx sv inp).dir c).map (·.home) = some (.shard k))
    (part (judge pk cx sv inp) (.shard k)) V chg chg' hS hE
  refine ⟨funext fun c => ?_, h2⟩
  by_cases hc : ((judge pk cx sv inp).dir c).map (·.home) = some (.shard k)
  · simp only [restrict, if_pos hc]
    exact h1 c hc
  · simp only [restrict, if_neg hc]

/-- A refusal changes no database. -/
theorem refusal_atomic (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) (h : checkAll pk cx ss inp = false) :
    stepT pk cx ss inp = ss := by
  simp [stepT, stepS, h]

/-- No commit on a stale head. -/
theorem commit_requires_heads (pk : Pack) (cx : Ctx) (ss ss' : SS) (inp : Input)
    (h : stepS pk cx ss inp = some ss') : ∀ k < pk.k cx.p, (ss.2 k).head = ss.1.heads k := by
  intro k hk
  unfold stepS at h
  split at h
  · next hc =>
    simp only [checkAll, fitsOk, Bool.and_eq_true, List.all_eq_true, decide_eq_true_eq] at hc
    exact (hc.1.2 k (List.mem_append_left _ (List.mem_range.2 hk))).1
  · cases h

/-- Definitional: `judgeSingle` is the spine judge, so judging on the spine view equals judging on the merged view
    (`rfl`).  Dedup authority is the model's choice, not proved here. -/
theorem dir_dedup (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) :
    judge pk cx ss.1.view inp = judgeSingle pk cx (merge pk cx ss) inp := by
  rfl

/-- No double move: across all shards a cell carries at most one MOVE charge. -/
theorem no_cross_shard_duplicate (pk : Pack) (cx : Ctx) (ss : SS) (h : reachS pk cx ss) (c : Cell) :
    moves c (merge pk cx ss) ≤ 1 := by
  obtain ⟨L, rs, rfl⟩ := h
  have hI := inv_run pk cx (initS (pk.k cx.p) L) rs (inv_init L)
  show ((List.range (runS pk cx (initS (pk.k cx.p) L) rs).1.k).map fun k =>
    ((runS pk cx (initS (pk.k cx.p) L) rs).2 k).chg c).sum ≤ 1
  refine sum_le_one (fun k => ((runS pk cx (initS (pk.k cx.p) L) rs).2 k).chg c) (fun k => (hI c).1 k) ?_ _
    (List.nodup_range ..)
  intro k k' hk hk'
  obtain ⟨x, hx, hh⟩ := (hI c).2 k hk
  obtain ⟨y, hy, hh'⟩ := (hI c).2 k' hk'
  have hxy : x = y := Option.some.inj (hx.symm.trans hy)
  subst hxy
  exact Home.shard.inj (hh.symm.trans hh')

/-- Sound direction: on a reachable state, a spine state and shard states that `checkSpine` (against the honest
    `mkRec`, not a stored record) and `checkShard` (shards below `K`) accept merge to a state `checkSingle` accepts.
    `checkSingle` alone does not imply the converse, because `merge` forgets heads, APPLIED and charge placement;
    `check_split_iff` proves the two directions against `os3Bar`, which adds those per-DB checks. -/
theorem check_split (pk : Pack) (cx : Ctx) (ss : SS) (hr : reachS pk cx ss) (inp : Input) (sp' : SpineDB)
    (sh' : Nat → ShardDB) (hsp : checkSpine pk cx ss inp sp')
    (hsh : ∀ k < pk.k cx.p, checkShard (mkRec pk cx ss inp).2 k (ss.2 k) (sh' k)) :
    checkSingle pk cx (merge pk cx ss) inp (merge pk cx (sp', sh')) := by
  have hK := (reach_invK pk cx ss hr).1
  obtain ⟨L, rs, hrs⟩ := hr
  have hI : Inv ss := by rw [hrs]; exact inv_run pk cx (initS (pk.k cx.p) L) rs (inv_init L)
  obtain ⟨hc, rfl⟩ := hsp
  refine ⟨?_, ?_⟩
  · simp only [checkAll, Bool.and_eq_true] at hc; exact hc.1.1.2
  · rw [merge_congr pk cx (commitSpine ss.1 (mkRec pk cx ss inp).1 (mkRec pk cx ss inp).2) sh' _
      fun k hk => hsh k (Nat.lt_of_lt_of_eq (List.mem_range.1 hk) hK)]
    exact merge_commit pk cx ss inp hI hK

/-- Over a duplicate-free list holding `k`, a function zero on every other member sums to its value at `k`. -/
theorem sum_one (f : Nat → Nat) (k : Nat) : ∀ l : List Nat, l.Nodup → k ∈ l → (∀ k' ∈ l, k' ≠ k → f k' = 0) →
    (l.map f).sum = f k
  | [], _, hk, _ => absurd hk List.not_mem_nil
  | a :: l, hn, hk, h0 => by
    rw [List.map_cons, List.sum_cons]
    have ha := (List.nodup_cons.1 hn).1
    by_cases hak : a = k
    · subst hak
      rw [sum_zeroN f l fun k' hk' => h0 k' (List.mem_cons_of_mem _ hk') fun e => ha (e ▸ hk'), Nat.add_zero]
    · rw [h0 a (List.mem_cons_self ..) hak, Nat.zero_add]
      exact sum_one f k l (List.nodup_cons.1 hn).2 ((List.mem_cons.1 hk).resolve_left fun e => hak e.symm)
        fun k' hk' => h0 k' (List.mem_cons_of_mem _ hk')

/-- Two charge counts over shards `0..K-1` that are positive only where `P` holds, with `P` true of at most one
    shard, and that have equal sums, agree on every shard below `K`. -/
theorem pin_one (K k : Nat) (hk : k < K) (P : Nat → Prop) (hP : ∀ a b, P a → P b → a = b) (f g : Nat → Nat)
    (hf : ∀ k' < K, 0 < f k' → P k') (hg : ∀ k' < K, 0 < g k' → P k')
    (hs : ((List.range K).map f).sum = ((List.range K).map g).sum) : f k = g k := by
  by_cases hp : P k
  · have zf : ∀ k' ∈ List.range K, k' ≠ k → f k' = 0 := fun k' hk' hne =>
      Nat.eq_zero_of_not_pos fun h => hne (hP _ _ (hf k' (List.mem_range.1 hk') h) hp)
    have zg : ∀ k' ∈ List.range K, k' ≠ k → g k' = 0 := fun k' hk' hne =>
      Nat.eq_zero_of_not_pos fun h => hne (hP _ _ (hg k' (List.mem_range.1 hk') h) hp)
    rwa [sum_one f k _ List.nodup_range (List.mem_range.2 hk) zf,
      sum_one g k _ List.nodup_range (List.mem_range.2 hk) zg] at hs
  · rw [Nat.eq_zero_of_not_pos fun h => hp (hf k hk h), Nat.eq_zero_of_not_pos fun h => hp (hg k hk h)]

/-- Two shard databases with equal charges, gross, machine charges, head and APPLIED list are equal. -/
theorem shard_eq {a b : ShardDB} (h1 : a.chg = b.chg) (h2 : a.gross = b.gross) (h3 : a.mc = b.mc)
    (h4 : a.head = b.head) (h5 : a.applied = b.applied) : a = b := by
  cases a; cases b; simp only [ShardDB.mk.injEq]; exact ⟨h1, h2, h3, h4, h5⟩

/-- Two spine databases equal field by field (directory, clock, used, budget, LINK charges, spine rows, heads,
    records, K) are equal. -/
theorem spine_eq {a b : SpineDB} (h1 : a.dir = b.dir) (h2 : a.t = b.t) (h3 : a.used = b.used)
    (h4 : a.budget = b.budget) (h5 : a.lc = b.lc) (h6 : a.spineRows = b.spineRows) (h7 : a.heads = b.heads)
    (h8 : a.recs = b.recs) (h9 : a.k = b.k) : a = b := by
  cases a; cases b; simp only [SpineDB.mk.injEq]; exact ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9⟩

/-- The OS3 bar for one record `R` = `(mkRec pk cx ss inp).2`: `checkSingle` on the merge, plus the per-DB checks
    the merge forgets.  The spine stores `R` on top of its records, keeps `K`, and sets `heads(k)` to `post_head_k` exactly for
    touched `k`; every shard below `K` has head `heads(k)` (`headsOk`) and APPLIED = the records touching it
    (`appliedOk`), holds MOVE charges only on cells the new directory homes at it, and moves its gross by `gsum` of its
    part and its machine charges by `finalize`'s total for its part (both zero when untouched). -/
def os3Bar (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) (sp' : SpineDB) (sh' : Nat → ShardDB) : Prop :=
  checkSingle pk cx (merge pk cx ss) inp (merge pk cx (sp', sh')) ∧
  sp'.recs = (mkRec pk cx ss inp).2 :: ss.1.recs ∧ sp'.k = ss.1.k ∧
  (∀ k, sp'.heads k =
    if k ∈ (mkRec pk cx ss inp).2.touched then (mkRec pk cx ss inp).2.post k else ss.1.heads k) ∧
  headsOk pk cx (sp', sh') = true ∧ appliedOk pk cx (sp', sh') ∧
  ∀ k < pk.k cx.p, (∀ c, 0 < (sh' k).chg c → ∃ x, sp'.dir c = some x ∧ x.home = .shard k) ∧
    (sh' k).gross = (ss.2 k).gross +
      (if k ∈ (mkRec pk cx ss inp).2.touched then gsum ((mkRec pk cx ss inp).2.I k) else 0) ∧
    (sh' k).mc = (ss.2 k).mc + (if k ∈ (mkRec pk cx ss inp).2.touched then
      (finRows (ss.2 k).chg ((mkRec pk cx ss inp).2.I k) ((mkRec pk cx ss inp).2.V k)).2 else 0)

/-- Check split, both directions (review fix 6): on a reachable state, the spine check plus the shard checks for
    every shard below `K` hold exactly when the OS3 bar `os3Bar` holds.  So the split checks are neither weaker nor
    stronger than the single-store check on the merge together with per-DB heads, APPLIED, home-charge and
    per-shard total checks. -/
theorem check_split_iff (pk : Pack) (cx : Ctx) (ss : SS) (hr : reachS pk cx ss) (inp : Input) (sp' : SpineDB)
    (sh' : Nat → ShardDB) :
    (checkSpine pk cx ss inp sp' ∧ ∀ k < pk.k cx.p, checkShard (mkRec pk cx ss inp).2 k (ss.2 k) (sh' k)) ↔
      os3Bar pk cx ss inp sp' sh' := by
  have hI : Inv ss := by obtain ⟨L, rs, rfl⟩ := hr; exact inv_run pk cx (initS (pk.k cx.p) L) rs (inv_init L)
  have h3 : Inv3 ss := by obtain ⟨L, rs, rfl⟩ := hr; exact inv3_run pk cx (initS (pk.k cx.p) L) rs (inv3_init L)
  have hK := reach_invK pk cx ss hr
  have hst : checkAll pk cx ss inp = true → stepT pk cx ss inp =
      (commitSpine ss.1 (mkRec pk cx ss inp).1 (mkRec pk cx ss inp).2,
        commitShards (mkRec pk cx ss inp).2 (mkRec pk cx ss inp).2.touched ss.2) := fun hc => by
    unfold stepT stepS; rw [if_pos hc]; rfl
  have hI1 := inv_step pk cx ss inp hI
  have h31 := inv3_step pk cx ss inp h3
  constructor
  · rintro ⟨⟨hc, rfl⟩, hsh⟩
    rw [hst hc] at hI1 h31
    have he : ∀ k < pk.k cx.p,
        sh' k = commitShards (mkRec pk cx ss inp).2 (mkRec pk cx ss inp).2.touched ss.2 k := hsh
    refine ⟨check_split pk cx ss hr inp _ sh' ⟨hc, rfl⟩ hsh, rfl, rfl, fun k => rfl, ?_, fun k hk => ?_,
      fun k hk => ⟨fun c hp => ?_, ?_, ?_⟩⟩
    · simp only [headsOk, List.all_eq_true, beq_iff_eq]
      intro k hk
      exact (congrArg ShardDB.head (he k (List.mem_range.1 hk))).trans (h31 k).1
    · exact (congrArg ShardDB.applied (he k (lt_of_lt_of_eq hk hK.1))).trans (h31 k).2
    · rw [he k hk] at hp; exact (hI1 c).2 k hp
    · rw [he k hk]
      by_cases ht : k ∈ (mkRec pk cx ss inp).2.touched
      · simp [commitShards, applyPart, ht]
      · simp [commitShards, ht]
    · rw [he k hk]
      by_cases ht : k ∈ (mkRec pk cx ss inp).2.touched
      · simp [commitShards, applyPart, ht]
      · simp [commitShards, ht]
  · rintro ⟨⟨hok, hm⟩, hrec, hk', hhd, hH, hA, hsh⟩
    have hc : checkAll pk cx ss inp = true := (checkAll_of_inv3 pk cx ss inp h3
      (by obtain ⟨L, rs, rfl⟩ := hr; exact chain_run pk cx (initS (pk.k cx.p) L) rs (chain_init L)) hK.1).trans hok
    rw [hst hc] at hI1 h31
    have hm' := hm.trans (merge_commit pk cx ss inp hI hK.1).symm
    have hsp : sp' = commitSpine ss.1 (mkRec pk cx ss inp).1 (mkRec pk cx ss inp).2 :=
      spine_eq (congrArg View.dir hm') (congrArg View.t hm') (congrArg View.used hm') (congrArg View.budget hm')
        (congrArg View.lc hm') (congrArg View.spineRows hm') (funext hhd) hrec hk'
    subst hsp
    refine ⟨⟨hc, rfl⟩, fun k hk => ?_⟩
    obtain ⟨hhome, hg, hmc⟩ := hsh k hk
    show sh' k = commitShards (mkRec pk cx ss inp).2 (mkRec pk cx ss inp).2.touched ss.2 k
    have hH' : (sh' k).head = (commitSpine ss.1 (mkRec pk cx ss inp).1 (mkRec pk cx ss inp).2).heads k := by
      simp only [headsOk, List.all_eq_true, beq_iff_eq] at hH; exact hH k (List.mem_range.2 hk)
    have hA' : (sh' k).applied = ((commitSpine ss.1 (mkRec pk cx ss inp).1 (mkRec pk cx ss inp).2).recs.reverse.filter
        fun R => k ∈ R.touched).map (·.n) := hA k (lt_of_lt_of_eq hk hK.1.symm)
    refine shard_eq (funext fun c => ?_) ?_ ?_ (hH'.trans (h31 k).1.symm) (hA'.trans (h31 k).2.symm)
    · exact pin_one (pk.k cx.p) k hk
        (fun k' => ∃ x, (judge pk cx ss.1.view inp).dir c = some x ∧ x.home = .shard k')
        (fun a b ⟨x, hx, ha⟩ ⟨y, hy, hb⟩ => by
          rw [hx] at hy; cases hy; exact Home.shard.inj (ha.symm.trans hb))
        (fun k' => (sh' k').chg c)
        (fun k' => (commitShards (mkRec pk cx ss inp).2 (mkRec pk cx ss inp).2.touched ss.2 k').chg c)
        (fun k' hk' h => ((hsh k' hk').1 c h)) (fun k' _ h => (hI1 c).2 k' h)
        (by rw [← hK.1]; exact congrArg (fun v => View.chg v c) hm')
    · rw [hg]
      by_cases ht : k ∈ (mkRec pk cx ss inp).2.touched
      · simp [commitShards, applyPart, ht]
      · simp [commitShards, ht]
    · rw [hmc]
      by_cases ht : k ∈ (mkRec pk cx ss inp).2.touched
      · simp [commitShards, applyPart, ht]
      · simp [commitShards, ht]

/-- Definitional unfolding: when the judgment is ok, `stepSingle` is `applySingle` with Lean's verdicts. -/
theorem step_factor (pk : Pack) (cx : Ctx) (s : Single) (inp : Input) (h : (judgeSingle pk cx s inp).ok = true) :
    stepSingle pk cx s inp =
      applySingle pk cx s (judgeSingle pk cx s inp) (verdicts cx (judgeSingle pk cx s inp)) := by
  simp [stepSingle, h]

/-! ### The whole-file reference agrees with the per-shard runs under `Local` -/

/-- A per-row sum over rows and their verdicts. -/
def lsum (φ : Row → Bool → Int) : List Row → List Bool → Int
  | [], _ => 0
  | r :: rs, W => φ r (W.headD false) + lsum φ rs W.tail

theorem gsum_lsum : ∀ (rs : List Row) (W : List Bool), gsum rs = lsum (fun r _ => r.gross) rs W
  | [], _ => rfl
  | r :: rs, W => by
    show r.gross + gsum rs = r.gross + lsum (fun r _ => r.gross) rs W.tail
    rw [gsum_lsum rs W.tail]

theorem vsum_lsum : ∀ (rs : List Row) (W : List Bool), vsum rs W = lsum (fun r b => if b then r.gross else 0) rs W
  | [], _ => rfl
  | r :: rs, W => by
    show (if W.headD false then r.gross else 0) + vsum rs W.tail =
      (if W.headD false then r.gross else 0) + lsum (fun r b => if b then r.gross else 0) rs W.tail
    rw [vsum_lsum rs W.tail]

theorem vchg_lsum (c : Cell) : ∀ (rs : List Row) (W : List Bool),
    ((vchg c rs W : Nat) : Int) = lsum (fun r b => if b = true ∧ r.cell = c then 1 else 0) rs W
  | [], _ => rfl
  | r :: rs, W => by
    show (((if W.headD false = true ∧ r.cell = c then 1 else 0) + vchg c rs W.tail : Nat) : Int) =
      (if W.headD false = true ∧ r.cell = c then 1 else 0) +
        lsum (fun r b => if b = true ∧ r.cell = c then 1 else 0) rs W.tail
    rw [← vchg_lsum c rs W.tail]
    by_cases h : W.headD false = true ∧ r.cell = c
    · rw [if_pos h, if_pos h]; omega
    · rw [if_neg h, if_neg h]; omega

theorem cast_sum {α} (f : α → Nat) : ∀ l : List α, (((l.map f).sum : Nat) : Int) = (l.map fun x => (f x : Int)).sum
  | [] => rfl
  | x :: l => by
    simp only [List.map_cons, List.sum_cons]
    rw [← cast_sum f l]
    omega

theorem sum_zeroI : ∀ l : List Nat, (l.map fun _ => (0 : Int)).sum = 0
  | [] => rfl
  | _ :: l => by rw [List.map_cons, List.sum_cons, sum_zeroI l, Int.add_zero]

theorem sum_ite (j : Nat) (a : Int) : ∀ K : Nat,
    ((List.range K).map fun k => if (j == k) = true then a else 0).sum = if j < K then a else 0
  | 0 => by rw [if_neg (Nat.not_lt_zero j)]; rfl
  | K + 1 => by
    rw [List.range_succ, List.map_append, List.sum_append, sum_ite j a K]
    simp only [List.map_cons, List.map_nil, List.sum_cons, List.sum_nil]
    by_cases h1 : j < K
    · rw [if_pos h1, if_pos (show j < K + 1 by omega), if_neg (fun e => Nat.ne_of_lt h1 (beq_iff_eq.1 e))]
      omega
    · by_cases h2 : j = K
      · subst h2
        rw [if_neg h1, if_pos (beq_self_eq_true j), if_pos (show j < j + 1 by omega)]
        omega
      · rw [if_neg h1, if_neg (fun e => h2 (beq_iff_eq.1 e)), if_neg (show ¬j < K + 1 by omega)]
        omega

theorem lsum_cons_sel (φ : Row → Bool → Int) (q : Row → Bool) (r : Row) (rs : List Row) (W : List Bool) :
    lsum φ ((r :: rs).filter q) (sel q (r :: rs) W) =
      (if q r = true then φ r (W.headD false) else 0) + lsum φ (rs.filter q) (sel q rs W.tail) := by
  by_cases hq : q r = true
  · rw [List.filter_cons_of_pos hq]
    show lsum φ (r :: rs.filter q) (if q r = true then W.headD false :: sel q rs W.tail else sel q rs W.tail) = _
    rw [if_pos hq, if_pos hq]
    rfl
  · rw [List.filter_cons_of_neg hq]
    show lsum φ (rs.filter q) (if q r = true then W.headD false :: sel q rs W.tail else sel q rs W.tail) = _
    rw [if_neg hq, if_neg hq, Int.zero_add]

/-- Splitting a per-row sum by shard index: the whole list's sum is the sum over shards of each part's sum, each
    part read with the verdicts `sel` picks for it. -/
theorem lsum_split (φ : Row → Bool → Int) (σ : Row → Nat) (K : Nat) : ∀ (rs : List Row) (W : List Bool),
    (∀ r ∈ rs, σ r < K) →
    lsum φ rs W = ((List.range K).map fun k => lsum φ (rs.filter fun r => σ r == k) (sel (fun r => σ r == k) rs W)).sum
  | [], _, _ => (sum_zeroI (List.range K)).symm
  | r :: rs, W, h => by
    show φ r (W.headD false) + lsum φ rs W.tail = _
    rw [List.map_congr_left fun k _ => lsum_cons_sel φ (fun r => σ r == k) r rs W, Partition.sum_map_add,
      sum_ite (σ r) _ K, if_pos (h r (List.mem_cons_self ..)),
      ← lsum_split φ σ K rs W.tail fun r' hr' => h r' (List.mem_cons_of_mem _ hr')]

theorem ite_lsum (φ : Row → Bool → Int) (l : List Row) (W : List Bool) :
    (if (!l.isEmpty) = true then lsum φ l W else 0) = lsum φ l W := by
  cases l <;> rfl

/-- A shard part is the file's shard-admitted rows with that shard index. -/
theorem part_wrows (pk : Pack) (cx : Ctx) (sv : SpineView) (inp : Input) (k : Nat) :
    part (judge pk cx sv inp) (.shard k) = (wrows (judge pk cx sv inp).out).filter fun r => sidx pk cx r.item == k := by
  unfold part wrows
  rw [List.filter_map, List.filter_filter]
  congr 1
  apply List.filter_congr
  intro ⟨r, v⟩ hx
  have hroute := judgeRows_route pk cx sv.dir inp.rows (r, v) hx
  cases v with
  | admit h =>
    cases h with
    | spine => simp [isSh]
    | shard j =>
      have hs := (route_sidx pk cx r j (hroute _ rfl).symm).1
      by_cases hjk : j = k
      · subst hjk; simp [isSh, hs]
      · simp [isSh, hs]
        rw [Bool.eq_false_iff.2 fun e => hjk (Home.shard.inj (Verdict.admit.inj (beq_iff_eq.1 e))),
          Bool.eq_false_iff.2 fun e => hjk (beq_iff_eq.1 e)]
  | duplicate => simp [isSh]
  | conflict => simp [isSh]

theorem wrows_lt (pk : Pack) (cx : Ctx) (sv : SpineView) (inp : Input) (hk : 0 < pk.k cx.p) :
    ∀ r ∈ wrows (judge pk cx sv inp).out, sidx pk cx r.item < pk.k cx.p := fun r hr => by
  obtain ⟨⟨r', v⟩, ha, rfl⟩ := List.mem_map.1 hr
  have ha' := List.mem_filter.1 ha
  obtain ⟨h, rfl⟩ := isSh_admit v ha'.2
  cases h with
  | spine => have e := ha'.2; simp [isSh] at e
  | shard j =>
    have e := route_sidx pk cx r' j (judgeRows_route pk cx sv.dir inp.rows _ ha'.1 _ rfl).symm
    show sidx pk cx r'.item < _
    rw [e.1]; exact e.2 hk

theorem verdicts_sel (pk : Pack) (cx : Ctx) (sv : SpineView) (inp : Input) (hLoc : Local cx) :
    verdicts cx (judge pk cx sv inp) = fun k =>
      sel (fun r => sidx pk cx r.item == k) (wrows (judge pk cx sv inp).out) (cx.lean (wrows (judge pk cx sv inp).out)) :=
  funext fun k => by
    show cx.lean (part (judge pk cx sv inp) (.shard k)) = _
    rw [part_wrows, hLoc (fun o => sidx pk cx o == k)]

theorem touched_lsum (pk : Pack) (cx : Ctx) (sv : SpineView) (inp : Input) (hok : (judge pk cx sv inp).ok = true)
    (hLoc : Local cx) (φ : Row → Bool → Int) :
    ((touched pk cx (judge pk cx sv inp)).map fun k =>
      lsum φ (part (judge pk cx sv inp) (.shard k)) (verdicts cx (judge pk cx sv inp) k)).sum =
    lsum φ (wrows (judge pk cx sv inp).out) (cx.lean (wrows (judge pk cx sv inp).out)) := by
  have hp : packOk pk = true := by simp only [judge, Bool.and_eq_true] at hok; exact hok.1
  rw [sum_touched, List.map_congr_left fun k _ => ite_lsum φ _ _, verdicts_sel pk cx sv inp hLoc,
    List.map_congr_left fun k _ => congrArg (lsum φ · _) (part_wrows pk cx sv inp k)]
  exact (lsum_split φ (fun r => sidx pk cx r.item) _ _ _ (wrows_lt pk cx sv inp (k_pos pk cx.p hp))).symm

/-- One ok judgment: the whole-file apply equals the per-shard apply, on a store with no charge on a new cell. -/
theorem whole_apply (pk : Pack) (cx : Ctx) (sv : SpineView) (inp : Input) (s : Single)
    (hok : (judge pk cx sv inp).ok = true) (hz : ∀ c, sv.dir c = none → s.chg c = 0) (hLoc : Local cx) :
    applyWhole cx s (judge pk cx sv inp) = applySingle pk cx s (judge pk cx sv inp) (verdicts cx (judge pk cx sv inp)) := by
  obtain ⟨hw1, hw2⟩ := judgeRows_freshP pk cx isSh isSh_admit sv.dir inp.rows
  have hpw : (wrows (judge pk cx sv inp).out).Pairwise (fun a b => a.cell ≠ b.cell) := List.pairwise_map.2 hw2
  have hzw : ∀ r ∈ wrows (judge pk cx sv inp).out, s.chg r.cell = 0 := fun r hr => by
    obtain ⟨a, ha, rfl⟩ := List.mem_map.1 hr
    exact hz _ (hw1 a (List.mem_filter.1 ha).1 (List.mem_filter.1 ha).2)
  have hF := finAll_eq (judge pk cx sv inp) (verdicts cx (judge pk cx sv inp)) (touched pk cx (judge pk cx sv inp))
    s.chg (List.Pairwise.filter _ List.nodup_range)
    (fun k _ => (part_fresh pk cx sv inp (.shard k)).1)
    (fun k _ r hr => hz r.cell ((part_fresh pk cx sv inp (.shard k)).2 r hr))
    (fun a _ b _ hab r hr r' hr' he => by
      obtain ⟨x, hx, hxh⟩ := part_home pk cx sv inp (.shard a) hr
      obtain ⟨y, hy, hyh⟩ := part_home pk cx sv inp (.shard b) hr'
      rw [he, hy] at hx
      cases hx
      exact hab (Home.shard.inj (hxh.symm.trans hyh)))
  have hg : gsum (wrows (judge pk cx sv inp).out) = ((touched pk cx (judge pk cx sv inp)).map fun k =>
      gsum (part (judge pk cx sv inp) (.shard k))).sum := by
    rw [List.map_congr_left fun k _ => gsum_lsum _ (verdicts cx (judge pk cx sv inp) k),
      touched_lsum pk cx sv inp hok hLoc, gsum_lsum _ (cx.lean (wrows (judge pk cx sv inp).out))]
  have hv : vsum (wrows (judge pk cx sv inp).out) (cx.lean (wrows (judge pk cx sv inp).out)) =
      ((touched pk cx (judge pk cx sv inp)).map fun k =>
        vsum (part (judge pk cx sv inp) (.shard k)) (verdicts cx (judge pk cx sv inp) k)).sum := by
    rw [List.map_congr_left fun k _ => vsum_lsum _ _, touched_lsum pk cx sv inp hok hLoc, vsum_lsum]
  have hc : ∀ c, ((vchg c (wrows (judge pk cx sv inp).out) (cx.lean (wrows (judge pk cx sv inp).out)) : Nat) : Int) =
      (((touched pk cx (judge pk cx sv inp)).map fun k =>
        vchg c (part (judge pk cx sv inp) (.shard k)) (verdicts cx (judge pk cx sv inp) k)).sum : Nat) := fun c => by
    rw [cast_sum, List.map_congr_left fun k _ => vchg_lsum c _ _, touched_lsum pk cx sv inp hok hLoc, vchg_lsum]
  generalize judge pk cx sv inp = J at hpw hzw hF hg hv hc ⊢
  refine view_eq rfl rfl ?_ ?_ rfl rfl (funext fun c => ?_) ?_ ?_
  · show s.used + gsum (wrows J.out) = s.used + ((touched pk cx J).map fun k => gsum (part J (.shard k))).sum
    rw [hg]
  · show s.budget + (finRows s.chg (wrows J.out) (cx.lean (wrows J.out))).2 + gsum (part J .spine) =
      s.budget + (finAll J (verdicts cx J) s.chg (touched pk cx J)).2 + gsum (part J .spine)
    rw [hF.1, finRows_vsum _ _ _ hpw hzw, hv]
  · show (finRows s.chg (wrows J.out) (cx.lean (wrows J.out))).1 c = (finAll J (verdicts cx J) s.chg (touched pk cx J)).1 c
    rw [hF.2 c, finRows_vchg c _ _ _ hpw hzw]
    have := hc c
    omega
  · show s.gross + gsum (wrows J.out) = s.gross + ((touched pk cx J).map fun k => gsum (part J (.shard k))).sum
    rw [hg]
  · show s.mc + (finRows s.chg (wrows J.out) (cx.lean (wrows J.out))).2 =
      s.mc + (finAll J (verdicts cx J) s.chg (touched pk cx J)).2
    rw [hF.1, finRows_vsum _ _ _ hpw hzw, hv]

theorem whole_step (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) (hI : Inv ss) (hLoc : Local cx) :
    stepWhole pk cx (merge pk cx ss) inp = stepSingle pk cx (merge pk cx ss) inp := by
  show (if (judge pk cx ss.1.view inp).ok = true then applyWhole cx (merge pk cx ss) (judge pk cx ss.1.view inp)
      else merge pk cx ss) =
    if (judge pk cx ss.1.view inp).ok = true then
      applySingle pk cx (merge pk cx ss) (judge pk cx ss.1.view inp) (verdicts cx (judge pk cx ss.1.view inp))
    else merge pk cx ss
  by_cases hok : (judge pk cx ss.1.view inp).ok = true
  · rw [if_pos hok, if_pos hok]
    exact whole_apply pk cx ss.1.view inp _ hok (fun c hc => sum_zeroN (fun k => (ss.2 k).chg c)
      (List.range ss.1.k) fun k _ => inv_zero hI c hc k) hLoc
  · rw [if_neg hok, if_neg hok]

theorem whole_run (pk : Pack) (cx : Ctx) (hLoc : Local cx) : ∀ (ss : SS) (rs : List Input), Inv ss → Inv3 ss →
    chainsOk ss → InvK pk cx ss → merge pk cx (runS pk cx ss rs) = runWhole pk cx (merge pk cx ss) rs
  | _, [], _, _, _, _ => rfl
  | ss, r :: rs, hI, h3, hn, hK => by
    show merge pk cx (runS pk cx (stepT pk cx ss r) rs) = runWhole pk cx (stepWhole pk cx (merge pk cx ss) r) rs
    rw [whole_step pk cx ss r hI hLoc, ← merge_step pk cx ss r hI h3 hn hK]
    exact whole_run pk cx hLoc _ rs (inv_step pk cx ss r hI) (inv3_step pk cx ss r h3) (chain_step pk cx ss r hn)
      (invK_step pk cx ss r hK)

/-- Per-shard receipts read back in file order equal the whole-file receipts. -/
theorem rcpt_eq (pk : Pack) (cx : Ctx) : ∀ (o : List (Row × Verdict)) (W : List Bool),
    (∀ a ∈ o, ∀ h, a.2 = .admit h → h = routeNew pk cx a.1) →
    rcptS o (fun k => sel (fun r => sidx pk cx r.item == k) (wrows o) W) = rcptW o W
  | [], _, _ => rfl
  | (r, v) :: o, W, hr => by
    have ih := fun W' => rcpt_eq pk cx o W' fun a ha => hr a (List.mem_cons_of_mem _ ha)
    cases v with
    | duplicate => exact congrArg (false :: ·) (ih W)
    | conflict => exact congrArg (false :: ·) (ih W)
    | admit h =>
      cases h with
      | spine => exact congrArg (false :: ·) (ih W)
      | shard j =>
        have hj := (route_sidx pk cx r j (hr _ (List.mem_cons_self ..) _ rfl).symm).1
        have hV : ∀ k, sel (fun r' => sidx pk cx r'.item == k) (r :: wrows o) W =
            if k = j then W.headD false :: sel (fun r' => sidx pk cx r'.item == k) (wrows o) W.tail
            else sel (fun r' => sidx pk cx r'.item == k) (wrows o) W.tail := fun k => by
          show (if (sidx pk cx r.item == k) = true then _ else _) = _
          rw [hj]
          by_cases hk : k = j
          · rw [if_pos (beq_iff_eq.2 hk.symm), if_pos hk]
          · rw [if_neg (fun e => hk (beq_iff_eq.1 e).symm), if_neg hk]
        show (sel (fun r' => sidx pk cx r'.item == j) (r :: wrows o) W).headD false ::
            rcptS o (fun k => if k = j then (sel (fun r' => sidx pk cx r'.item == j) (r :: wrows o) W).tail
              else sel (fun r' => sidx pk cx r'.item == k) (r :: wrows o) W) = W.headD false :: rcptW o W.tail
        rw [← ih W.tail]
        refine congr (congrArg List.cons ?_) (congrArg (rcptS o) (funext fun k => ?_))
        · rw [hV j, if_pos rfl, List.headD_cons]
        · by_cases hk : k = j
          · rw [if_pos hk, hk, hV j, if_pos rfl, List.tail_cons]
          · rw [if_neg hk, hV k, if_neg hk]

/-- Receipts of a sharded run: per input, none if refused, else per-row MOVE flags from the per-shard verdicts. -/
def rcptsS (pk : Pack) (cx : Ctx) : SS → List Input → List (Option (List Bool))
  | _, [] => []
  | ss, i :: is => (if checkAll pk cx ss i then some (rcptS (judge pk cx ss.1.view i).out
      (verdicts cx (judge pk cx ss.1.view i))) else none) :: rcptsS pk cx (stepT pk cx ss i) is

/-- Receipts of the whole-file reference run. -/
def rcptsW (pk : Pack) (cx : Ctx) : Single → List Input → List (Option (List Bool))
  | _, [] => []
  | s, i :: is => (if (judgeSingle pk cx s i).ok then some (rcptW (judgeSingle pk cx s i).out
      (cx.lean (wrows (judgeSingle pk cx s i).out))) else none) :: rcptsW pk cx (stepWhole pk cx s i) is

theorem rcpts_run (pk : Pack) (cx : Ctx) (hLoc : Local cx) : ∀ (ss : SS) (rs : List Input), Inv ss → Inv3 ss →
    chainsOk ss → InvK pk cx ss → rcptsS pk cx ss rs = rcptsW pk cx (merge pk cx ss) rs
  | _, [], _, _, _, _ => rfl
  | ss, i :: is, hI, h3, hn, hK => by
    show (if checkAll pk cx ss i = true then some (rcptS (judge pk cx ss.1.view i).out
        (verdicts cx (judge pk cx ss.1.view i))) else none) :: rcptsS pk cx (stepT pk cx ss i) is =
      (if (judge pk cx ss.1.view i).ok = true then some (rcptW (judge pk cx ss.1.view i).out
        (cx.lean (wrows (judge pk cx ss.1.view i).out))) else none) :: rcptsW pk cx (stepWhole pk cx (merge pk cx ss) i) is
    rw [whole_step pk cx ss i hI hLoc, ← merge_step pk cx ss i hI h3 hn hK,
      ← rcpts_run pk cx hLoc _ is (inv_step pk cx ss i hI) (inv3_step pk cx ss i h3) (chain_step pk cx ss i hn)
        (invK_step pk cx ss i hK),
      verdicts_sel pk cx ss.1.view i hLoc,
      rcpt_eq pk cx (judge pk cx ss.1.view i).out _ (judgeRows_route pk cx ss.1.view.dir i.rows),
      checkAll_of_inv3 pk cx ss i h3 hn hK.1]

/-- From a migrated store with `openOk`, the merged sharded run equals the single-store run (Lean per shard part).
    Under `Local` (restricting a file to any set of items leaves Lean's verdicts on the kept rows unchanged), the merged run also
    equals the whole-file reference (Lean once on all the file's shard-admitted rows), and the sharded run's per-row
    MOVE receipts equal the whole-file receipts.  The first half needs no assumption on Lean; the whole-file half
    ASSUMES `Local cx`, a hypothesis on Lean that this module does not prove. -/
theorem shard_run_eq (pk : Pack) (cx : Ctx) (L : Legacy) (hL : openOk pk cx L) (rs : List Input) :
    merge pk cx (runS pk cx (initS (pk.k cx.p) L) rs) = runSingle pk cx (initSingle L) rs ∧
    (Local cx → merge pk cx (runS pk cx (initS (pk.k cx.p) L) rs) = runWhole pk cx (initSingle L) rs ∧
      rcptsS pk cx (initS (pk.k cx.p) L) rs = rcptsW pk cx (initSingle L) rs) := by
  have h0 : merge pk cx (initS (pk.k cx.p) L) = initSingle L := view_eq rfl rfl rfl rfl rfl rfl
    (funext fun c => init_sumN (·.chg c) L _ rfl (hL.imp_right fun e => e.1 c))
    (init_sumI (·.gross) L _ rfl (hL.imp_right fun e => e.2.1))
    (init_sumI (·.mc) L _ rfl (hL.imp_right fun e => e.2.2))
  refine ⟨?_, fun hLoc => ⟨?_, ?_⟩⟩
  · rw [merge_run pk cx (initS (pk.k cx.p) L) rs (inv_init L) (inv3_init L) (chain_init L) (invK_init pk cx L), h0]
  · rw [whole_run pk cx hLoc (initS (pk.k cx.p) L) rs (inv_init L) (inv3_init L) (chain_init L) (invK_init pk cx L), h0]
  · rw [rcpts_run pk cx hLoc (initS (pk.k cx.p) L) rs (inv_init L) (inv3_init L) (chain_init L) (invK_init pk cx L),
      h0]

/-- One `afterSpine` step: a crash after the spine COMMIT of an accepted step, with only shards `C ⊆ touched`
    committed, whose shard heads below `K` all equal the spine's, is the committed step, under any `hs`. -/
theorem reader_cut (pk : Pack) (cx : Ctx) (ss ss' : SS) (inp : Input) (C : List Nat)
    (h : stepS pk cx ss inp = some ss') (hC : ∀ k ∈ C, k ∈ (mkRec pk cx ss inp).2.touched)
    (hh : ∀ k < pk.k cx.p, ((afterSpine pk cx ss inp C).2 k).head = (afterSpine pk cx ss inp C).1.heads k) :
    afterSpine pk cx ss inp C = ss' := by
  unfold stepS at h
  split at h
  · next hc =>
    obtain rfl := Option.some.inj h
    unfold afterSpine at hh ⊢
    rw [if_pos hc] at hh ⊢
    refine Prod.ext rfl (funext fun k => ?_)
    show commitShards (mkRec pk cx ss inp).2 C ss.2 k =
      commitShards (mkRec pk cx ss inp).2 (mkRec pk cx ss inp).2.touched ss.2 k
    unfold commitShards
    by_cases hk : k ∈ C
    · rw [if_pos hk, if_pos (hC k hk)]
    · rw [if_neg hk]
      by_cases ht : k ∈ (mkRec pk cx ss inp).2.touched
      · exfalso
        have hK : k < pk.k cx.p := by
          have h' := ht
          simp only [mkRec, touched, List.mem_filter, List.mem_range] at h'
          exact h'.1
        have e := hh k hK
        simp only [commitShards, if_neg hk, commitSpine, if_pos ht] at e
        exact post_ne_pre pk cx ss inp k e.symm
      · rw [if_neg ht]
  · cases h

/-- Running `a ++ b` is running `a`, then `b` from where `a` ended. -/
theorem runS_append (pk : Pack) (cx : Ctx) : ∀ (ss : SS) (a b : List Input),
    runS pk cx ss (a ++ b) = runS pk cx (runS pk cx ss a) b
  | _, [], _ => rfl
  | ss, r :: a, b => runS_append pk cx (stepT pk cx ss r) a b

/-- One step leaves shard `k` unchanged or appends exactly one APPLIED entry to it. -/
theorem step_shard (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) (k : Nat) :
    (stepT pk cx ss inp).2 k = ss.2 k ∨
      ((stepT pk cx ss inp).2 k).applied.length = (ss.2 k).applied.length + 1 := by
  unfold stepT stepS
  split
  · by_cases ht : k ∈ (mkRec pk cx ss inp).2.touched
    · right; simp [commitShards, applyPart, ht]
    · left; simp [commitShards, ht]
  · exact .inl rfl

/-- A shard at or above `K` is never changed by a step. -/
theorem step_high (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) (k : Nat) (hk : pk.k cx.p ≤ k) :
    (stepT pk cx ss inp).2 k = ss.2 k := by
  unfold stepT stepS
  split
  · have hn : k ∉ (mkRec pk cx ss inp).2.touched := fun ht => by
      have ht' : k ∈ touched pk cx (judge pk cx ss.1.view inp) := ht
      unfold touched at ht'
      rw [List.mem_filter, List.mem_range] at ht'
      exact absurd ht'.1 (Nat.not_lt.2 hk)
    simp [commitShards, hn]
  · rfl

/-- Over any run, shard `k` is unchanged or its APPLIED list is strictly longer. -/
theorem run_shard (pk : Pack) (cx : Ctx) (k : Nat) : ∀ (ss : SS) (rs : List Input),
    (runS pk cx ss rs).2 k = ss.2 k ∨ (ss.2 k).applied.length < ((runS pk cx ss rs).2 k).applied.length
  | _, [] => .inl rfl
  | ss, r :: rs => by
    show (runS pk cx (stepT pk cx ss r) rs).2 k = ss.2 k ∨
      (ss.2 k).applied.length < ((runS pk cx (stepT pk cx ss r) rs).2 k).applied.length
    rcases run_shard pk cx k (stepT pk cx ss r) rs with h | h <;> rcases step_shard pk cx ss r k with h' | h'
    · exact .inl (h.trans h')
    · right; rw [h, h']; omega
    · rw [h'] at h; exact .inr h
    · right; omega

/-- A shard at or above `K` is never changed by a run. -/
theorem run_high (pk : Pack) (cx : Ctx) (k : Nat) (hk : pk.k cx.p ≤ k) : ∀ (ss : SS) (rs : List Input),
    (runS pk cx ss rs).2 k = ss.2 k
  | _, [] => rfl
  | ss, r :: rs => (run_high pk cx k hk (stepT pk cx ss r) rs).trans (step_high pk cx ss r k hk)

/-- Reader cut over prefixes (review fix 7): a reader that takes the spine after the first `i` inputs of a run
    from a migrated store and each shard `k` after any number `j k` of them, and whose APPLIED check
    (`appliedOk`: each shard below `K` lists exactly the spine records touching it) passes, holds exactly the
    store after the first `i` inputs, every shard included.  The check needed is APPLIED, not heads: `Ctx.hs` is
    arbitrary and `adv` only stops one step from returning its own pre head, so a shard two touching records ahead
    can show the spine's head again (heads going `h0 → h1 → h0`) while its charges differ. -/
theorem reader_cut_prefix (pk : Pack) (cx : Ctx) (L : Legacy) (rs : List Input) (i : Nat) (j : Nat → Nat)
    (sp : SpineDB) (sh : Nat → ShardDB) (hsp : sp = (runS pk cx (initS (pk.k cx.p) L) (rs.take i)).1)
    (hsh : ∀ k, sh k = (runS pk cx (initS (pk.k cx.p) L) (rs.take (j k))).2 k) (hA : appliedOk pk cx (sp, sh)) :
    (sp, sh) = runS pk cx (initS (pk.k cx.p) L) (rs.take i) := by
  subst hsp
  refine Prod.ext rfl (funext fun k => ?_)
  show sh k = (runS pk cx (initS (pk.k cx.p) L) (rs.take i)).2 k
  have ext : ∀ m n, m ≤ n → ∃ ys, runS pk cx (initS (pk.k cx.p) L) (rs.take n) =
      runS pk cx (runS pk cx (initS (pk.k cx.p) L) (rs.take m)) ys :=
    fun m n h => ⟨(rs.drop m).take (n - m), by rw [← runS_append, ← List.take_add, Nat.add_sub_of_le h]⟩
  rw [hsh k]
  by_cases hK : k < pk.k cx.p
  · have e : (sh k).applied =
        ((runS pk cx (initS (pk.k cx.p) L) (rs.take i)).1.recs.reverse.filter fun R => k ∈ R.touched).map (·.n) :=
      hA k (lt_of_lt_of_eq hK (invK_run pk cx _ (rs.take i) (invK_init pk cx L)).1.symm)
    have hl := congrArg List.length
      (e.trans ((inv3_run pk cx (initS (pk.k cx.p) L) (rs.take i) (inv3_init L)) k).2.symm)
    rw [hsh k] at hl
    rcases Nat.le_total (j k) i with h | h
    · obtain ⟨ys, hy⟩ := ext _ _ h
      rw [hy] at hl ⊢
      rcases run_shard pk cx k (runS pk cx (initS (pk.k cx.p) L) (rs.take (j k))) ys with e' | e'
      · exact e'.symm
      · omega
    · obtain ⟨ys, hy⟩ := ext _ _ h
      rw [hy] at hl ⊢
      rcases run_shard pk cx k (runS pk cx (initS (pk.k cx.p) L) (rs.take i)) ys with e' | e'
      · exact e'
      · omega
  · have hk := Nat.le_of_not_lt hK
    rw [run_high pk cx k hk, run_high pk cx k hk]

/-- Pool used is the shards' gross; the budget is the shards' machine charges plus the spine's LINK charges. -/
theorem pool_budget_merge (pk : Pack) (cx : Ctx) (ss : SS) (h : reachOk pk cx ss) :
    ss.1.used = ((List.range (pk.k cx.p)).map fun k => (ss.2 k).gross).sum ∧
    ss.1.budget = ((List.range (pk.k cx.p)).map fun k => (ss.2 k).mc).sum + ss.1.lc := by
  obtain ⟨L, rs, hL, rfl⟩ := h
  exact inv4_run pk cx (initS (pk.k cx.p) L) rs (inv_init L) (inv4_init pk cx L hL)

/-! ## Group commit and recovery -/

theorem stepG_single (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) : stepG pk cx ss [inp] = stepS pk cx ss inp := by
  cases h : stepS pk cx ss inp <;> simp [stepG, h]

theorem stepG_append (pk : Pack) (cx : Ctx) : ∀ (ss : SS) (a b : List Input),
    stepG pk cx ss (a ++ b) = (stepG pk cx ss a).bind fun s => stepG pk cx s b
  | ss, [], b => by simp [stepG]
  | ss, i :: a, b => by
    simp only [List.cons_append, stepG]
    cases stepS pk cx ss i with
    | none => rfl
    | some s => exact stepG_append pk cx s a b

/-- An accepted group is the run of its inputs, so every `runS` invariant holds after it. -/
theorem stepG_run (pk : Pack) (cx : Ctx) : ∀ (ss ss' : SS) (inps : List Input),
    stepG pk cx ss inps = some ss' → runS pk cx ss inps = ss'
  | ss, ss', [], h => by simp only [stepG, Option.some.injEq] at h; subst h; rfl
  | ss, ss', i :: is, h => by
    cases hs : stepS pk cx ss i with
    | none => simp [stepG, hs] at h
    | some s =>
      have h' : stepG pk cx s is = some ss' := by simpa [stepG, hs] using h
      show runS pk cx (stepT pk cx ss i) is = ss'
      rw [show stepT pk cx ss i = s by simp [stepT, hs]]
      exact stepG_run pk cx s ss' is h'

/-- An accepted group puts its records `G` on the spine, numbered from the spine's length, and replaying them in
    order on each shard's pre-group state yields its post-group state. -/
theorem replay_commit (pk : Pack) (cx : Ctx) : ∀ (ss ss' : SS) (inps : List Input), stepG pk cx ss inps = some ss' →
    ∃ G : List Rec, ss'.1.recs = G ++ ss.1.recs ∧ (∀ R ∈ G, ss.1.recs.length ≤ R.n) ∧
      ∀ k, replays k (G.reverse.filter fun R => decide (k ∈ R.touched)) (ss.2 k) = some (ss'.2 k)
  | ss, ss', [], h => by
    simp only [stepG, Option.some.injEq] at h
    subst h
    exact ⟨[], rfl, by simp, fun k => rfl⟩
  | ss, ss', i :: is, h => by
    cases hs : stepS pk cx ss i with
    | none => simp [stepG, hs] at h
    | some s =>
      have h' : stepG pk cx s is = some ss' := by simpa [stepG, hs] using h
      obtain ⟨G, hG, hb, hr⟩ := replay_commit pk cx s ss' is h'
      unfold stepS at hs
      split at hs
      · obtain rfl := Option.some.inj hs
        refine ⟨G ++ [(mkRec pk cx ss i).2], ?_, ?_, fun k => ?_⟩
        · rw [hG, List.append_assoc]
          rfl
        · intro R hR
          rcases List.mem_append.1 hR with hR | hR
          · have := hb R hR
            simp only [commitSpine, List.length_cons] at this
            omega
          · rw [List.mem_singleton.1 hR]
            exact Nat.le_refl _
        · have hk' := hr k
          rw [List.reverse_append, List.reverse_singleton, List.singleton_append]
          by_cases hk : k ∈ (mkRec pk cx ss i).2.touched
          · rw [List.filter_cons_of_pos (by simpa using hk)]
            simp only [commitShards, if_pos hk] at hk'
            have hp : replay (mkRec pk cx ss i).2 k (ss.2 k) = some (applyPart (mkRec pk cx ss i).2 k (ss.2 k)) :=
              if_pos rfl
            show (replay _ k (ss.2 k)).bind (replays k _) = _
            rw [hp]
            exact hk'
          · rw [List.filter_cons_of_neg (by simpa using hk)]
            simpa only [commitShards, if_neg hk] using hk'
      · cases hs

private theorem replays_append (k : Nat) : ∀ (a b : List Rec) (sh : ShardDB),
    replays k (a ++ b) sh = (replays k a sh).bind (replays k b)
  | [], b, sh => rfl
  | R :: a, b, sh => by
    show (replay R k sh).bind (replays k (a ++ b)) = ((replay R k sh).bind (replays k a)).bind (replays k b)
    cases replay R k sh with
    | none => rfl
    | some t => exact replays_append k a b t

private theorem replays_applied (k : Nat) : ∀ (l : List Rec) (sh s : ShardDB),
    replays k l sh = some s → s.applied = sh.applied ++ l.map (·.n)
  | [], sh, s, h => by simp only [replays, Option.some.injEq] at h; subst h; simp
  | R :: l, sh, s, h => by
    simp only [replays, replay] at h
    split at h
    · rw [replays_applied k l _ s h]
      simp [applyPart]
    · cases h

/-- A shard whose APPLIED lists every spine record touching it owes nothing. -/
theorem pending_nil (sp : SpineDB) (k : Nat) (sh : ShardDB)
    (ha : sh.applied = (sp.recs.reverse.filter fun R => k ∈ R.touched).map (·.n)) : pending sp k sh = [] := by
  unfold pending
  rw [List.filter_eq_nil_iff]
  intro R hR hp
  simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true] at hp
  have hm : R.n ∈ sh.applied := by
    rw [ha]
    exact List.mem_map.2 ⟨R, List.mem_filter.2 ⟨hR, decide_eq_true hp.1⟩, rfl⟩
  exact Nat.lt_irrefl _ (hp.2 _ hm)

theorem recover_some (sp : SpineDB) (k : Nat) (sh s : ShardDB)
    (hs : replays k (pending sp k sh) sh = some s) : recover sp k sh = if fits sp k s then some s else none := by
  simp only [recover, hs]

private theorem recover_none (sp : SpineDB) (k : Nat) (sh : ShardDB)
    (hs : replays k (pending sp k sh) sh = none) : recover sp k sh = none := by
  simp only [recover, hs]

/-- If every shard recovers to `ss'`'s, the store recovers to `ss'`. -/
theorem recoverAll_some (pk : Pack) (cx : Ctx) (ss ss' : SS) (h1 : ss.1 = ss'.1)
    (hg : ss.1.recs.all (imgOk cx) = true)
    (h : ∀ k, recover ss.1 k (ss.2 k) = some (ss'.2 k)) : recoverAll pk cx ss = some ss' := by
  unfold recoverAll
  rw [if_pos (by rw [hg, Bool.true_and]; exact List.all_eq_true.2 fun k _ => by simp only [h k, Option.isSome_some])]
  exact congrArg some (Prod.ext h1 (funext fun k => by simp only [h k, Option.getD_some]))

/-- CHANGED (2026-10-09, RGL-FIX2 L-1): `recover` and `recoverAll` return `Option`; the theorems below state `some`
    for a recovery and `none` for a refusal.  A refusal on any shard below `K` refuses the whole store.
    STMT-CHANGE-8 (trunk L2111): `hk : k < ss.1.k` (the stored `K`), not the pack's; `recoverAll_retired` covers a
    retired shard. -/
theorem recoverAll_refused (pk : Pack) (cx : Ctx) (ss : SS) (k : Nat) (hk : k < ss.1.k)
    (h : recover ss.1 k (ss.2 k) = none) : recoverAll pk cx ss = none := by
  unfold recoverAll
  rw [if_neg]
  intro ha
  simp only [Bool.and_eq_true] at ha
  simpa [h] using List.all_eq_true.1 ha.2 k (List.mem_append_left _ (List.mem_range.2 hk))

/-- A shard some spine record touches is recovered too, at or above the stored `K` (one retired by a RESHARD to a
    smaller `K`): a refusal on it refuses the store. -/
theorem recoverAll_retired (pk : Pack) (cx : Ctx) (ss : SS) (k : Nat) (R : Rec) (hR : R ∈ ss.1.recs)
    (hk : k ∈ R.touched) (h : recover ss.1 k (ss.2 k) = none) : recoverAll pk cx ss = none := by
  unfold recoverAll
  rw [if_neg]
  intro ha
  simp only [Bool.and_eq_true] at ha
  simpa [h] using List.all_eq_true.1 ha.2 k (List.mem_append_right _ (List.mem_flatMap.2 ⟨R, hR, hk⟩))

/-- A shard that fits the spine owes nothing, and recovery returns it as is. -/
theorem recover_fits (sp : SpineDB) (k : Nat) (sh : ShardDB) (hf : fits sp k sh) : recover sp k sh = some sh := by
  rw [recover_some sp k sh sh (by rw [pending_nil sp k sh hf.2]; rfl), if_pos hf]

theorem recover_done (ss : SS) (h3 : Inv3 ss) (k : Nat) : recover ss.1 k (ss.2 k) = some (ss.2 k) :=
  recover_fits ss.1 k (ss.2 k) (h3 k)

/-- On the pre-group shard state, recovery replays exactly the group's records and reaches the post-group state. -/
theorem recover_group (pk : Pack) (cx : Ctx) (ss ss' : SS) (inps : List Input) (h3 : Inv3 ss) (hn : chainsOk ss)
    (h : stepG pk cx ss inps = some ss') (k : Nat) : recover ss'.1 k (ss.2 k) = some (ss'.2 k) := by
  obtain ⟨G, hG, hb, hr⟩ := replay_commit pk cx ss ss' inps h
  have h3' : Inv3 ss' := by
    rw [← stepG_run pk cx ss ss' inps h]
    exact inv3_run pk cx ss inps h3
  have h0 := pending_nil ss.1 k (ss.2 k) (h3 k).2
  unfold pending at h0
  rw [recover_some ss'.1 k (ss.2 k) (ss'.2 k) ?_, if_pos (show fits ss'.1 k (ss'.2 k) from h3' k)]
  unfold pending
  rw [hG, List.reverse_append, List.filter_append, h0, List.nil_append]
  have hc : (G.reverse.filter fun R => decide (k ∈ R.touched) && (ss.2 k).applied.all fun m => decide (m < R.n)) =
      G.reverse.filter fun R => decide (k ∈ R.touched) := by
    apply List.filter_congr
    intro R hR
    have hall : ((ss.2 k).applied.all fun m => decide (m < R.n)) = true := by
      simp only [List.all_eq_true, decide_eq_true_eq]
      intro m hm
      rw [(h3 k).2] at hm
      obtain ⟨R', hR', rfl⟩ := List.mem_map.1 hm
      have h1 : R'.n ∈ List.range' 0 ss.1.recs.length := by
        rw [← hn]
        exact List.mem_map.2 ⟨R', (List.mem_filter.1 hR').1, rfl⟩
      have h2 := hb R (List.mem_reverse.1 hR)
      simp only [List.mem_range'_1] at h1
      omega
    rw [hall, Bool.and_true]
  rw [hc, hr]

/-- A crash after a group's spine COMMIT, whichever shards `C` committed, converges: recovery yields the committed
    group, under any `hs`.  No bound on what is pending is needed (`rollforward_any`).  STMT-CHANGE-9 (trunk
    L2157): gains `hg` (every stored image is the one its post heads commit to), since `recoverAll` refuses a
    forged image (`replay_forged`); every reachable state has it (`reach_invK`). -/
theorem rollforward_group (pk : Pack) (cx : Ctx) (ss ss' : SS) (inps : List Input) (C : List Nat) (h3 : Inv3 ss)
    (hn : chainsOk ss) (hg : ss.1.recs.all (imgOk cx) = true) (h : stepG pk cx ss inps = some ss') :
    recoverAll pk cx (afterSpineG pk cx ss inps C) = some ss' := by
  have h3' : Inv3 ss' := by
    rw [← stepG_run pk cx ss ss' inps h]
    exact inv3_run pk cx ss inps h3
  have hg' : ss'.1.recs.all (imgOk cx) = true := by
    rw [← stepG_run pk cx ss ss' inps h]
    exact imgs_run pk cx ss inps hg
  unfold afterSpineG
  rw [h]
  refine recoverAll_some pk cx _ ss' rfl hg' fun k => ?_
  show recover ss'.1 k (if k ∈ C then ss'.2 k else ss.2 k) = some (ss'.2 k)
  by_cases hk : k ∈ C
  · rw [if_pos hk]
    exact recover_done ss' h3' k
  · rw [if_neg hk]
    exact recover_group pk cx ss ss' inps h3 hn h k

/-- Any pending set converges: if the spine committed the inputs `inps` (one group or many) and shard `k` stopped
    after any prefix `j k` of them, recovery brings every shard to the committed state. -/
theorem rollforward_any (pk : Pack) (cx : Ctx) (ss ss' : SS) (inps : List Input) (h3 : Inv3 ss) (hn : chainsOk ss)
    (h : stepG pk cx ss inps = some ss') (j : Nat → Nat) (k : Nat) :
    recover ss'.1 k (((stepG pk cx ss (inps.take (j k))).getD ss).2 k) = some (ss'.2 k) := by
  have e := stepG_append pk cx ss (inps.take (j k)) (inps.drop (j k))
  rw [List.take_append_drop, h] at e
  cases ht : stepG pk cx ss (inps.take (j k)) with
  | none => rw [ht] at e; cases e
  | some t =>
    rw [ht] at e
    have e' : stepG pk cx t (inps.drop (j k)) = some ss' := e.symm
    have hr := stepG_run pk cx ss t _ ht
    have h3t : Inv3 t := by rw [← hr]; exact inv3_run pk cx ss _ h3
    have hnt : chainsOk t := by rw [← hr]; exact chain_run pk cx ss _ hn
    exact recover_group pk cx t ss' _ h3t hnt e' k

/-- CHANGED (2026-10-08, group recovery): gains `Inv3 ss` and `chainsOk ss`.  Recovery now replays every record
    above the shard's APPLIED entries, so on an arbitrary `ss` an old unapplied record would be replayed first; the
    single-record case of `rollforward_group`.  STMT-CHANGE-10 (trunk L2193): gains `hg`, as `rollforward_group`. -/
theorem rollforward_eq (pk : Pack) (cx : Ctx) (ss ss' : SS) (inp : Input) (C : List Nat) (h3 : Inv3 ss)
    (hn : chainsOk ss) (hg : ss.1.recs.all (imgOk cx) = true) (h : stepS pk cx ss inp = some ss') (hC : ∀ k ∈ C, k ∈ (mkRec pk cx ss inp).2.touched) :
    recoverAll pk cx (afterSpine pk cx ss inp C) = some ss' := by
  have hG : stepG pk cx ss [inp] = some ss' := (stepG_single pk cx ss inp).trans h
  have hA : afterSpine pk cx ss inp C = afterSpineG pk cx ss [inp] C := by
    unfold afterSpineG
    rw [hG]
    unfold stepS at h
    split at h
    · next hc =>
      obtain rfl := Option.some.inj h
      unfold afterSpine
      rw [if_pos hc]
      refine Prod.ext rfl (funext fun k => ?_)
      show commitShards _ C ss.2 k = if k ∈ C then commitShards _ _ ss.2 k else ss.2 k
      unfold commitShards
      by_cases hk : k ∈ C
      · rw [if_pos hk, if_pos hk, if_pos (hC k hk)]
      · rw [if_neg hk, if_neg hk]
    · cases h
  rw [hA]
  exact rollforward_group pk cx ss ss' [inp] C h3 hn hg hG

/-- A crash before the spine COMMIT leaves a reachable state, and recovery changes nothing in it. -/
theorem crash_before_spine (pk : Pack) (cx : Ctx) (ss : SS) (h : reachS pk cx ss) : recoverAll pk cx ss = some ss := by
  have hg := (reach_invK pk cx ss h).2
  obtain ⟨L, rs, rfl⟩ := h
  exact recoverAll_some pk cx _ _ rfl hg (recover_done _ (inv3_run pk cx (initS (pk.k cx.p) L) rs (inv3_init L)))

/-- Recovery is idempotent: recovering a recovered shard returns it; a refusal stays a refusal. -/
theorem recover_idem (sp : SpineDB) (k : Nat) (sh : ShardDB) :
    (recover sp k sh).bind (recover sp k) = recover sp k sh := by
  cases hr : replays k (pending sp k sh) sh with
  | none => rw [recover_none sp k sh hr]; rfl
  | some s =>
    rw [recover_some sp k sh s hr]
    by_cases hf : fits sp k s
    · rw [if_pos hf]; exact recover_fits sp k s hf
    · rw [if_neg hf]; rfl

/-- The old last-record recovery is the one-record case: a single pending record replays from its pre head and
    commits if the result fits the spine; anything else is refused.  CHANGED (2026-10-08, RGL-FIX): the
    condition gains `∧ fits sp k (applyPart R k sh)`, since `recover` now checks the final head and APPLIED. -/
theorem recover_one (sp : SpineDB) (k : Nat) (sh : ShardDB) (R : Rec) (h : pending sp k sh = [R]) :
    recover sp k sh = if sh.head = R.pre k ∧ fits sp k (applyPart R k sh) then some (applyPart R k sh) else none := by
  by_cases hh : sh.head = R.pre k
  · rw [recover_some sp k sh (applyPart R k sh) (by rw [h]; simp [replays, replay, hh])]
    by_cases hf : fits sp k (applyPart R k sh)
    · rw [if_pos hf, if_pos (And.intro hh hf)]
    · rw [if_neg hf, if_neg (fun c : sh.head = R.pre k ∧ fits sp k (applyPart R k sh) => hf c.2)]
  · rw [recover_none sp k sh (by rw [h]; simp [replays, replay, hh]),
      if_neg (fun c : sh.head = R.pre k ∧ fits sp k (applyPart R k sh) => hh c.1)]

/-- Fail closed: if a pending record's `pre_head_k` differs from the head reached by replaying the records before
    it, recovery refuses shard `k` (osbench: any mismatch writes nothing and raises `ShardDiverged`). -/
theorem recover_diverged (sp : SpineDB) (k : Nat) (sh s : ShardDB) (a b : List Rec) (R : Rec)
    (hp : pending sp k sh = a ++ R :: b) (ha : replays k a sh = some s) (hne : s.head ≠ R.pre k) :
    recover sp k sh = none :=
  recover_none sp k sh (by rw [hp, replays_append, ha]; simp [replays, replay, hne])

/-- Fail closed on the tail: if every pending record replays but the final head is not the spine's `heads k` (a
    torn or tampered heads row), recovery refuses shard `k`. -/
theorem recover_diverged_tail (sp : SpineDB) (k : Nat) (sh s : ShardDB)
    (hs : replays k (pending sp k sh) sh = some s) (hne : s.head ≠ sp.heads k) : recover sp k sh = none := by
  rw [recover_some sp k sh s hs, if_neg (fun hf : fits sp k s => hne hf.1)]

/-- Fail closed on a gap: if APPLIED skips a spine record touching `k` (its `n` lies below an APPLIED entry `m` but
    is not in APPLIED), that record is never pending again, so recovery refuses shard `k`. -/
theorem recover_gap (sp : SpineDB) (k : Nat) (sh : ShardDB) (R : Rec) (m : Nat) (hR : R ∈ sp.recs)
    (hk : k ∈ R.touched) (hm : m ∈ sh.applied) (hlt : R.n < m) (hnot : R.n ∉ sh.applied) :
    recover sp k sh = none := by
  cases hs : replays k (pending sp k sh) sh with
  | none => exact recover_none sp k sh hs
  | some s =>
    rw [recover_some sp k sh s hs, if_neg]
    intro hf
    have hin : R.n ∈ s.applied := by
      rw [hf.2]
      exact List.mem_map.2 ⟨R, List.mem_filter.2 ⟨List.mem_reverse.2 hR, decide_eq_true hk⟩, rfl⟩
    rw [replays_applied k _ sh s hs] at hin
    rcases List.mem_append.1 hin with h | h
    · exact hnot h
    · obtain ⟨R', hR', he⟩ := List.mem_map.1 h
      have he' : R'.n = R.n := he
      unfold pending at hR'
      have hp := (List.mem_filter.1 hR').2
      simp only [Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true] at hp
      have := hp.2 m hm
      omega

theorem evOk_tips (K i : Nat) (a b : Nat → Dg) (t : List Ev) : ∀ l : List Nat,
    evOk K i ((l.map fun k => Ev.tip k (a k) (b k)) ++ t) = ((l.all fun k => a k == b k) && evOk K i t)
  | [] => by simp
  | k :: l => by
    simp only [List.map_cons, List.cons_append, evOk, List.all_cons, evOk_tips K i a b t l, Bool.and_assoc]

theorem filter_eq_at {p q : Nat → Bool} {K k : Nat} (h : (List.range K).filter p = (List.range K).filter q)
    (hk : k < K) : p k = q k := by
  have e : k ∈ (List.range K).filter p ↔ k ∈ (List.range K).filter q := by rw [h]
  simp only [List.mem_filter, List.mem_range, hk, true_and] at e
  cases hp : p k <;> cases hq : q k <;> simp_all

/-- Under consecutive numbering after `i`, no later record's number is `i`. -/
theorem filt_ge (rs : List Rec) (i k : Nat) (hr : rs.map (·.n) = List.range' (i + 1) rs.length) :
    ((rs.filter fun R => decide (k ∈ R.touched)).map (·.n)).head? ≠ some i := by
  intro h
  have hm : i ∈ (rs.filter fun R => decide (k ∈ R.touched)).map (·.n) := List.mem_of_mem_head? h
  have hm2 : i ∈ rs.map (·.n) := by
    obtain ⟨R, hR, he⟩ := List.mem_map.1 hm
    exact List.mem_map.2 ⟨R, (List.mem_filter.1 hR).1, he⟩
  rw [hr, List.mem_range'_1] at hm2
  omega

theorem filt_cons (k : Nat) (R : Rec) (rs : List Rec) :
    ((R :: rs).filter fun R => decide (k ∈ R.touched)).map (·.n) =
      if decide (k ∈ R.touched) then R.n :: (rs.filter fun R => decide (k ∈ R.touched)).map (·.n)
      else (rs.filter fun R => decide (k ∈ R.touched)).map (·.n) := by
  by_cases h : k ∈ R.touched <;> simp [h]

/-- One shard at one record: its pending list is the record's number (iff touched) before the rest, exactly when the
    merge step claims it iff touched and leaves the rest. -/
theorem step_k (n : Nat) (b : Bool) (l F : List Nat) (hne : F.head? ≠ some n) :
    l = (if b then n :: F else F) ↔
      decide (l.head? = some n) = b ∧ (if decide (l.head? = some n) = true then l.tail else l) = F := by
  cases b
  · simp only [Bool.false_eq_true, ↓reduceIte]
    constructor
    · intro h; subst h; simp [hne]
    · intro ⟨h1, h2⟩
      rw [h1] at h2
      simpa using h2
  · simp only [↓reduceIte]
    constructor
    · intro h; subst h; simp
    · intro ⟨h1, h2⟩
      rw [h1] at h2
      simp only [↓reduceIte] at h2
      cases l with
      | nil => simp at h1
      | cons a t => simp at h1 h2; simp [h1, h2]

/-- The merge pass accepts exactly consecutive numbering from `i` and pending lists equal to each shard's records. -/
theorem evOk_go (K : Nat) : ∀ (rs : List Rec) (i : Nat) (pend : Nat → List Nat),
    evOk K i (mergeGo K rs pend) = true ↔
      rs.map (·.n) = List.range' i rs.length ∧
        ∀ k < K, pend k = (rs.filter fun R => decide (k ∈ R.touched)).map (·.n) := by
  intro rs
  induction rs with
  | nil =>
    intro i pend
    have e : ∀ l : List Nat, evOk K i (l.map fun k => Ev.orphan k (pend k)) = true ↔ l = [] := by
      intro l; cases l <;> simp [evOk]
    show evOk K i (((List.range K).filter fun k => !(pend k).isEmpty).map fun k => Ev.orphan k (pend k)) = true ↔ _
    rw [e]
    simp [List.filter_eq_nil_iff]
  | cons R rs ih =>
    intro i pend
    simp only [mergeGo, evOk, Bool.and_eq_true, decide_eq_true_eq, ih, List.map_cons, List.length_cons,
      List.range'_succ, List.cons.injEq]
    constructor
    · rintro ⟨⟨hn, hks⟩, hr, hp⟩
      subst hn
      refine ⟨⟨rfl, hr⟩, fun k hk => ?_⟩
      rw [filt_cons]
      exact (step_k R.n _ (pend k) _ (filt_ge rs R.n k hr)).2 ⟨filter_eq_at hks hk, hp k hk⟩
    · rintro ⟨⟨hn, hr⟩, hp⟩
      subst hn
      have hs : ∀ k, k < K → nextIs pend R.n k = decide (k ∈ R.touched) ∧
          (if nextIs pend R.n k = true then (pend k).tail else pend k) =
            (rs.filter fun R => decide (k ∈ R.touched)).map (·.n) := fun k hk =>
        (step_k R.n _ (pend k) _ (filt_ge rs R.n k hr)).1 (by have := hp k hk; rwa [filt_cons] at this)
      exact ⟨⟨rfl, List.filter_congr fun k hk => (hs k (List.mem_range.1 hk)).1⟩, hr, fun k hk => (hs k hk).2⟩

/-- On any state: `historyOk (mergeHist ss)` holds iff records are numbered `0 .. n-1` oldest first (`chainsOk`),
    every shard `k < K` has head = the spine's `heads k` (`headsOk`), and every shard `k < K` has APPLIED = the
    numbers of the records touching it, oldest first (`appliedOk`).  Shard hash chains stay abstract (`cx.hs`).
    STMT-CHANGE-34: `historyOk`, `mergeHist` and `appliedOk` range over the stored `K`, so the pack's `headsOk` needs
    `hK : ss.1.k = pk.k cx.p` (gained). -/
theorem spine_chain_binds_iff (pk : Pack) (cx : Ctx) (ss : SS) (hK : ss.1.k = pk.k cx.p) :
    chainsOk ss ∧ headsOk pk cx ss = true ∧ appliedOk pk cx ss ↔ historyOk ss (mergeHist pk cx ss) = true := by
  unfold historyOk mergeHist
  rw [evOk_tips ss.1.k 0 (fun k => (ss.2 k).head) ss.1.heads, Bool.and_eq_true, evOk_go]
  unfold chainsOk headsOk appliedOk
  rw [List.length_reverse, hK]
  exact ⟨fun ⟨a, b, c⟩ => ⟨b, a, c⟩, fun ⟨b, a, c⟩ => ⟨a, b, c⟩⟩

/-- The spine binds the shard chains: on every reachable state heads match, each shard's APPLIED list is its
    records in order, records are numbered in order, and the merged history passes `historyOk`. -/
theorem spine_chain_binds (pk : Pack) (cx : Ctx) (ss : SS) (h : reachS pk cx ss) :
    headsOk pk cx ss = true ∧ appliedOk pk cx ss ∧ chainsOk ss ∧ historyOk ss (mergeHist pk cx ss) = true := by
  have hK := (reach_invK pk cx ss h).1
  obtain ⟨L, rs, rfl⟩ := h
  have h3 := inv3_run pk cx (initS (pk.k cx.p) L) rs (inv3_init L)
  have hc := chain_run pk cx (initS (pk.k cx.p) L) rs (chain_init L)
  have hh : headsOk pk cx (runS pk cx (initS (pk.k cx.p) L) rs) = true := by
    simp only [headsOk, List.all_eq_true, beq_iff_eq]
    exact fun k _ => (h3 k).1
  have ha : appliedOk pk cx (runS pk cx (initS (pk.k cx.p) L) rs) := fun k _ => (h3 k).2
  exact ⟨hh, ha, hc, (spine_chain_binds_iff pk cx _ hK).1 ⟨hc, hh, ha⟩⟩

/-! ## A shard COMMIT that fails after the spine COMMIT -/

/-- A state with the spine COMMIT of the step on `ss` whose shard `k` (touched) still has its APPLIED list from
    `ss` fails `historyOk`: the spine lists the record for `k` and the shard does not. -/
theorem applied_missing (pk : Pack) (cx : Ctx) (ss X : SS) (inp : Input) (h3 : Inv3 ss) (hKs : ss.1.k = pk.k cx.p)
    (hX : X.1 = commitSpine ss.1 (mkRec pk cx ss inp).1 (mkRec pk cx ss inp).2) (k : Nat)
    (ht : k ∈ (mkRec pk cx ss inp).2.touched) (ha : (X.2 k).applied = (ss.2 k).applied) :
    historyOk X (mergeHist pk cx X) = false := by
  have hKX : X.1.k = pk.k cx.p := by rw [hX]; exact hKs
  cases e : historyOk X (mergeHist pk cx X)
  · rfl
  obtain ⟨-, -, hA⟩ := (spine_chain_binds_iff pk cx X hKX).2 e
  have hK : k < pk.k cx.p := by
    have h' := ht
    simp only [mkRec, touched, List.mem_filter, List.mem_range] at h'
    exact h'.1
  have hl := congrArg List.length ((hA k (by rw [hKX]; exact hK)).symm.trans (ha.trans (h3 k).2))
  rw [hX] at hl
  simp [commitSpine, ht] at hl

/-- Spine COMMIT succeeds, then a touched shard's COMMIT fails (only shards `C ⊆ touched` committed): `historyOk`
    refuses the state, the writer refuses any next step on it (`accepted_applied`), and recovery yields the
    committed step.  No assumption on `hs`.  CHANGED (2026-10-08): gains `chainsOk ss`, as `rollforward_eq`.
    STMT-CHANGE-11 (trunk L2411): gains `hg`, as `rollforward_eq`. -/
theorem rollforward_closed (pk : Pack) (cx : Ctx) (ss ss' : SS) (inp : Input) (C : List Nat) (h3 : Inv3 ss)
    (hn : chainsOk ss) (hg : ss.1.recs.all (imgOk cx) = true) (h : stepS pk cx ss inp = some ss') (hC : ∀ k ∈ C, k ∈ (mkRec pk cx ss inp).2.touched)
    (hm : ∃ k ∈ (mkRec pk cx ss inp).2.touched, k ∉ C) :
    historyOk (afterSpine pk cx ss inp C) (mergeHist pk cx (afterSpine pk cx ss inp C)) = false ∧
      recoverAll pk cx (afterSpine pk cx ss inp C) = some ss' := by
  obtain ⟨k, ht, hk⟩ := hm
  have hc : checkAll pk cx ss inp = true := by
    unfold stepS at h
    split at h
    · assumption
    · cases h
  have hKs : ss.1.k = pk.k cx.p := by
    simp only [checkAll, kOk, Bool.and_eq_true, beq_iff_eq] at hc
    exact hc.2
  have hA : afterSpine pk cx ss inp C = (commitSpine ss.1 (mkRec pk cx ss inp).1 (mkRec pk cx ss inp).2,
      commitShards (mkRec pk cx ss inp).2 C ss.2) := by
    unfold afterSpine
    rw [if_pos hc]
  exact ⟨applied_missing pk cx ss _ inp h3 hKs (by rw [hA]) k ht (by rw [hA]; simp [commitShards, hk]),
    rollforward_eq pk cx ss ss' inp C h3 hn hg h hC⟩

/-- One record, any `hs` (the identity included): if the writer's check accepts a next input on the state a crash
    after the spine COMMIT left, every touched shard has applied the record, so an unapplied part stops all later
    writes until recovery replays it.  This uses only the head half of `fitsOk` and `post_ne_pre`.  For a group,
    where a head can return to its old value, see `accepted_applied_group` (it uses the APPLIED half). -/
theorem accepted_applied (pk : Pack) (cx : Ctx) (ss ss' : SS) (inp inp' : Input) (C : List Nat)
    (h : stepS pk cx ss inp = some ss') (hC : ∀ k ∈ C, k ∈ (mkRec pk cx ss inp).2.touched)
    (hc : checkAll pk cx (afterSpine pk cx ss inp C) inp' = true) :
    ∀ k ∈ (mkRec pk cx ss inp).2.touched,
      (mkRec pk cx ss inp).2.n ∈ ((afterSpine pk cx ss inp C).2 k).applied := by
  have hh : ∀ k < pk.k cx.p, ((afterSpine pk cx ss inp C).2 k).head = (afterSpine pk cx ss inp C).1.heads k := by
    simp only [checkAll, fitsOk, Bool.and_eq_true, List.all_eq_true, List.mem_range, decide_eq_true_eq] at hc
    exact fun k hk => (hc.1.2 k (List.mem_append_left _ (List.mem_range.2 hk))).1
  rw [reader_cut pk cx ss ss' inp C h hC hh]
  intro k hk
  unfold stepS at h
  split at h
  · obtain rfl := Option.some.inj h
    show (mkRec pk cx ss inp).2.n ∈ (if k ∈ (mkRec pk cx ss inp).2.touched then
      applyPart (mkRec pk cx ss inp).2 k (ss.2 k) else ss.2 k).applied
    rw [if_pos hk]
    exact List.mem_append_right _ (List.mem_singleton_self _)
  · cases h

/-- If the writer accepts on a group crash state, a shard `k < K` that did not commit owes nothing of the group. -/
private theorem group_check_owes (pk : Pack) (cx : Ctx) (ss ss' : SS) (inps : List Input) (C : List Nat)
    (inp' : Input) (h3 : Inv3 ss) (h : stepG pk cx ss inps = some ss')
    (hc : checkAll pk cx (afterSpineG pk cx ss inps C) inp' = true) (G : List Rec)
    (hG : ss'.1.recs = G ++ ss.1.recs) (k : Nat) (hk : k < pk.k cx.p) (hkC : k ∉ C) :
    (G.reverse.filter fun R => decide (k ∈ R.touched)) = [] := by
  simp only [afterSpineG, h, checkAll, fitsOk, Bool.and_eq_true, List.all_eq_true, List.mem_range,
    decide_eq_true_eq] at hc
  have hf : (ss.2 k).applied = (ss'.1.recs.reverse.filter fun R => k ∈ R.touched).map (·.n) := by
    have h1 := (hc.1.2 k (List.mem_append_left _ (List.mem_range.2 hk))).2
    simp only [if_neg hkC] at h1
    exact h1
  rw [(h3 k).2, hG, List.reverse_append, List.filter_append, List.map_append] at hf
  have hl := congrArg List.length hf
  rw [List.length_append, List.length_map, List.length_map] at hl
  exact List.length_eq_zero_iff.1 (by omega)

/-- A group, any `hs` and any heads (a group may move a head `h0 -> h1 -> h0`): if the writer's check accepts a next
    input on the state a crash after the group's spine COMMIT left (shards in `C` committed), every shard `k < K`
    holds the committed state, so no part of the group is left unapplied while writes go on.  The APPLIED half of
    `fitsOk` decides this, not the head. -/
theorem accepted_applied_group (pk : Pack) (cx : Ctx) (ss ss' : SS) (inps : List Input) (C : List Nat)
    (inp' : Input) (h3 : Inv3 ss) (h : stepG pk cx ss inps = some ss')
    (hc : checkAll pk cx (afterSpineG pk cx ss inps C) inp' = true) :
    ∀ k < pk.k cx.p, (afterSpineG pk cx ss inps C).2 k = ss'.2 k := by
  intro k hk
  obtain ⟨G, hG, -, hr⟩ := replay_commit pk cx ss ss' inps h
  have hA : (afterSpineG pk cx ss inps C).2 k = if k ∈ C then ss'.2 k else ss.2 k := by
    simp only [afterSpineG, h]
  rw [hA]
  by_cases hkC : k ∈ C
  · rw [if_pos hkC]
  · rw [if_neg hkC]
    have hr := hr k
    rw [group_check_owes pk cx ss ss' inps C inp' h3 h hc G hG k hk hkC] at hr
    simp only [replays, Option.some.injEq] at hr
    exact hr

/-- The RGL review's MED-1 crash is refused: a group committed on the spine with a record touching shard `k < K`,
    and shard `k` did not commit it.  Whatever `hs` does to the head (back to `h0` included), the writer refuses
    every next input until recovery replays the group. -/
theorem group_crash_refused (pk : Pack) (cx : Ctx) (ss ss' : SS) (inps : List Input) (C : List Nat)
    (inp' : Input) (h3 : Inv3 ss) (h : stepG pk cx ss inps = some ss') (k : Nat) (hk : k < pk.k cx.p)
    (hkC : k ∉ C) (R : Rec) (hR : R ∈ ss'.1.recs) (hR' : R ∉ ss.1.recs) (hRk : k ∈ R.touched) :
    checkAll pk cx (afterSpineG pk cx ss inps C) inp' = false := by
  cases hc : checkAll pk cx (afterSpineG pk cx ss inps C) inp'
  · rfl
  · obtain ⟨G, hG, -, -⟩ := replay_commit pk cx ss ss' inps h
    have he := group_check_owes pk cx ss ss' inps C inp' h3 h hc G hG k hk hkC
    rw [hG, List.mem_append] at hR
    have hm : R ∈ G.reverse.filter fun R => decide (k ∈ R.touched) :=
      List.mem_filter.2 ⟨List.mem_reverse.2 (hR.resolve_right hR'), decide_eq_true hRk⟩
    rw [he] at hm
    cases hm

end BlindLedger.Financial.ShardSplit
