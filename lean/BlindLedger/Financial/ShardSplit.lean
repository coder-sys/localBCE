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
          exact ⟨⟨routeNew pk cx r, r.raw, r.gross⟩, by simp [setDir], rfl⟩
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

theorem inv_init : Inv initS := fun _ => ⟨fun _ => Nat.zero_le 1, fun _ h => (Nat.lt_irrefl 0 h).elim⟩

/-- After a committed step, shard `k`'s head is the last record's `post_head_k` for every touched `k`. -/
def Inv2 (ss : SS) : Prop := ∀ R rs, ss.1.recs = R :: rs → ∀ k ∈ R.touched, (ss.2 k).head = R.post k

theorem inv2_step (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) (h : Inv2 ss) : Inv2 (stepT pk cx ss inp) := by
  unfold stepT stepS
  split
  · intro R rs hR k hk
    have hR' : (mkRec pk cx ss inp).2 = R := (List.cons.inj hR).1
    subst hR'
    show (commitShards (mkRec pk cx ss inp).2 (mkRec pk cx ss inp).2.touched ss.2 k).head = _
    unfold commitShards
    rw [if_pos hk]
    rfl
  · exact h

theorem inv2_run (pk : Pack) (cx : Ctx) : ∀ (ss : SS) (rs : List Input), Inv2 ss → Inv2 (runS pk cx ss rs)
  | _, [], h => h
  | ss, r :: rs, h => inv2_run pk cx _ rs (inv2_step pk cx ss r h)

theorem replay_commit (R : Rec) (sh : Nat → ShardDB) (C : List Nat) (hC : ∀ k ∈ C, k ∈ R.touched)
    (hpre : ∀ k, R.pre k = (sh k).head) (hadv : ∀ k, R.post k ≠ R.pre k) (k : Nat) :
    replay R k (commitShards R C sh k) = commitShards R R.touched sh k := by
  unfold commitShards replay
  by_cases hk : k ∈ C
  · have ht := hC k hk
    rw [if_pos hk, if_pos ht]
    have hn : ¬(k ∈ R.touched ∧ (applyPart R k (sh k)).head = R.pre k ∧ (applyPart R k (sh k)).head ≠ R.post k) :=
      fun h' => h'.2.2 rfl
    rw [if_neg hn]
  · rw [if_neg hk]
    by_cases ht : k ∈ R.touched
    · have hy : k ∈ R.touched ∧ (sh k).head = R.pre k ∧ (sh k).head ≠ R.post k :=
        ⟨ht, (hpre k).symm, fun h' => hadv k (h'.symm.trans (hpre k).symm)⟩
      rw [if_pos ht, if_pos hy]
    · have hn : ¬(k ∈ R.touched ∧ (sh k).head = R.pre k ∧ (sh k).head ≠ R.post k) := fun h' => ht h'.1
      rw [if_neg ht, if_neg hn]

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

theorem judgeRow_new (pk : Pack) (cx : Ctx) (d : Dir) (r : Row) (h : Home)
    (hv : (judgeRow pk cx d r).2 = .admit h) : d r.cell = none ∧ ∃ x, (judgeRow pk cx d r).1 r.cell = some x := by
  revert hv
  unfold judgeRow
  cases hd : d r.cell with
  | some y => intro hv; dsimp only at hv; split at hv <;> cases hv
  | none => intro _; exact ⟨rfl, ⟨routeNew pk cx r, r.raw, r.gross⟩, by simp [setDir]⟩

/-- Rows admitted at `h` were new to the directory the judgment started from, and their cells are distinct. -/
theorem judgeRows_fresh (pk : Pack) (cx : Ctx) (h : Home) : ∀ (d : Dir) (rs : List Row),
    (∀ a ∈ (judgeRows pk cx d rs).2, a.2 = .admit h → d a.1.cell = none) ∧
    ((judgeRows pk cx d rs).2.filter fun x => x.2 == .admit h).Pairwise (fun a b => a.1.cell ≠ b.1.cell)
  | d, [] => ⟨fun _ hm => by simp [judgeRows] at hm, by simp [judgeRows]⟩
  | d, r :: rs => by
    obtain ⟨ih1, ih2⟩ := judgeRows_fresh pk cx h (judgeRow pk cx d r).1 rs
    have hmono : ∀ c, (judgeRow pk cx d r).1 c = none → d c = none := fun c hc => by
      cases hd : d c with
      | none => rfl
      | some x =>
        have hk := judgeRows_keep pk cx d [r] c x hd
        change (judgeRow pk cx d r).1 c = some x at hk
        rw [hc] at hk; cases hk
    show (∀ a ∈ (r, (judgeRow pk cx d r).2) :: (judgeRows pk cx (judgeRow pk cx d r).1 rs).2,
        a.2 = .admit h → d a.1.cell = none) ∧
      (((r, (judgeRow pk cx d r).2) :: (judgeRows pk cx (judgeRow pk cx d r).1 rs).2).filter
        fun x => x.2 == .admit h).Pairwise (fun a b => a.1.cell ≠ b.1.cell)
    refine ⟨fun a hm hv => ?_, ?_⟩
    · rcases List.mem_cons.1 hm with rfl | ht
      · exact (judgeRow_new pk cx d r h hv).1
      · exact hmono _ (ih1 a ht hv)
    · rw [List.filter_cons]
      split
      · next hv =>
        have hv' : (judgeRow pk cx d r).2 = .admit h := by simpa using hv
        obtain ⟨_, x, hx⟩ := judgeRow_new pk cx d r h hv'
        refine List.Pairwise.cons (fun b hb => ?_) ih2
        have hb' := List.mem_filter.1 hb
        have h0 := ih1 b hb'.1 (by simpa using hb'.2)
        intro he
        have he' : r.cell = b.1.cell := he
        rw [← he', hx] at h0
        cases h0
      · exact ih2

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

theorem inv4_init (pk : Pack) (cx : Ctx) : Inv4 pk cx initS :=
  ⟨(Partition.sum_zero (fun k => (initS.2 k).gross) _ fun _ _ => rfl).symm,
    by rw [Partition.sum_zero (fun k => (initS.2 k).mc) _ fun _ _ => rfl]; rfl⟩

/-! ## §9 statements -/

/-- K_p is positive under a well-formed pack. -/
theorem k_pos (pk : Pack) (p : PartId) (h : packOk pk = true) : 0 < pk.k p := by
  exact kOf_pos pk.ks p h

/-- A new cell's home is the spine or exactly one shard below K. -/
theorem route_total (pk : Pack) (cx : Ctx) (r : Row) (h : packOk pk = true) :
    routeNew pk cx r = .spine ∨ ∃ k, k < pk.k cx.p ∧ routeNew pk cx r = .shard k := by
  unfold routeNew
  split
  · exact .inr ⟨_, Nat.mod_lt _ (k_pos pk cx.p h), rfl⟩
  · exact .inl rfl

/-- K is fixed once the partition has history. -/
theorem shard_stable (hist : List PartId) (pk pk' : Pack) (p : PartId) (hu : packUpdateOk hist pk pk' = true)
    (hp : p ∈ hist) : pk'.k p = pk.k p := by
  simp only [packUpdateOk, Bool.and_eq_true, List.all_eq_true, beq_iff_eq] at hu
  exact hu.2 p hp

/-- Routes never move: a directory row survives every step unchanged. -/
theorem dir_route_stable (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) (c : Cell) (x : DirRow)
    (h : ss.1.dir c = some x) : (stepT pk cx ss inp).1.dir c = some x := by
  unfold stepT stepS
  split
  · exact judgeRows_keep pk cx ss.1.dir inp.rows c x h
  · exact h

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
    simp only [checkAll, headsOk, Bool.and_eq_true, List.all_eq_true, List.mem_range, beq_iff_eq] at hc
    exact hc.2 k hk
  · cases h

/-- Recovery reads only the last committed spine record and shard k. -/
theorem recover_pure (sp : SpineDB) (R : Rec) (rs : List Rec) (h : sp.recs = R :: rs) (k : Nat) (sh : ShardDB) :
    recover sp k sh = replay R k sh := by
  unfold recover
  rw [h]

/-- Recovery is idempotent. -/
theorem recover_idem (sp : SpineDB) (k : Nat) (sh : ShardDB) :
    recover sp k (recover sp k sh) = recover sp k sh := by
  cases hr : sp.recs with
  | nil => simp only [recover, hr]
  | cons R rs =>
    rw [recover_pure sp R rs hr, recover_pure sp R rs hr]
    unfold replay
    by_cases hc : k ∈ R.touched ∧ sh.head = R.pre k ∧ sh.head ≠ R.post k
    · have hn : ¬(k ∈ R.touched ∧ (applyPart R k sh).head = R.pre k ∧ (applyPart R k sh).head ≠ R.post k) :=
        fun h' => h'.2.2 rfl
      rw [if_pos hc, if_neg hn]
    · simp only [if_neg hc]

/-- The spine judge is the single-store judge: the spine alone is the dedup authority. -/
theorem dir_dedup (pk : Pack) (cx : Ctx) (ss : SS) (inp : Input) :
    judge pk cx ss.1.view inp = judgeSingle pk cx (merge pk cx ss) inp := by
  rfl

/-- No double move: across all shards a cell carries at most one MOVE charge. -/
theorem no_cross_shard_duplicate (pk : Pack) (cx : Ctx) (ss : SS) (h : reachS pk cx ss) (c : Cell) :
    moves c (merge pk cx ss) ≤ 1 := by
  obtain ⟨rs, rfl⟩ := h
  have hI := inv_run pk cx initS rs inv_init
  show ((List.range (pk.k cx.p)).map fun k => ((runS pk cx initS rs).2 k).chg c).sum ≤ 1
  refine sum_le_one (fun k => ((runS pk cx initS rs).2 k).chg c) (fun k => (hI c).1 k) ?_ _ (List.nodup_range ..)
  intro k k' hk hk'
  obtain ⟨x, hx, hh⟩ := (hI c).2 k hk
  obtain ⟨y, hy, hh'⟩ := (hI c).2 k' hk'
  have hxy : x = y := Option.some.inj (hx.symm.trans hy)
  subst hxy
  exact Home.shard.inj (hh.symm.trans hh')

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
  simp [stepSingle, h]

/-- Sharded = single: the merged sharded run is the single-store run. -/
theorem shard_run_eq (pk : Pack) (cx : Ctx) (rs : List Input) :
    merge pk cx (runS pk cx initS rs) = runSingle pk cx initSingle rs := by
  sorry

/-- A crash after the spine COMMIT converges: recovery yields the committed step. -/
theorem rollforward_eq (pk : Pack) (cx : Ctx) (ss ss' : SS) (inp : Input) (C : List Nat)
    (h : stepS pk cx ss inp = some ss') (hC : ∀ k ∈ C, k ∈ (mkRec pk cx ss inp).2.touched) :
    recoverAll (afterSpine pk cx ss inp C) = ss' := by
  unfold stepS at h
  split at h
  · next hc =>
    obtain rfl := Option.some.inj h
    unfold afterSpine
    rw [if_pos hc]
    refine Prod.ext rfl (funext fun k => ?_)
    exact replay_commit _ ss.2 C hC (fun _ => rfl) (fun k => cx.advances _ _ _ _) k
  · cases h

/-- A crash before the spine COMMIT leaves a reachable state, and recovery changes nothing in it. -/
theorem crash_before_spine (pk : Pack) (cx : Ctx) (ss : SS) (h : reachS pk cx ss) : recoverAll ss = ss := by
  obtain ⟨rs, rfl⟩ := h
  have h2 := inv2_run pk cx initS rs (fun _ _ h => by cases h)
  refine Prod.ext rfl (funext fun k => ?_)
  show recover _ k _ = _
  cases hr : (runS pk cx initS rs).1.recs with
  | nil => simp only [recover, hr]
  | cons R rs' =>
    rw [recover_pure _ R rs' hr]
    have hn : ¬(k ∈ R.touched ∧ ((runS pk cx initS rs).2 k).head = R.pre k ∧
        ((runS pk cx initS rs).2 k).head ≠ R.post k) := fun ⟨hk, _, hne⟩ => hne (h2 R rs' hr k hk)
    unfold replay
    rw [if_neg hn]

/-- The reader cut is real: a crash state whose shard heads all equal the spine's is the committed step. -/
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
        exact cx.advances _ _ _ _ e.symm
      · rw [if_neg ht]
  · cases h

/-- Pool used is the shards' gross; the budget is the shards' machine charges plus the spine's LINK charges. -/
theorem pool_budget_merge (pk : Pack) (cx : Ctx) (ss : SS) (h : reachS pk cx ss) :
    ss.1.used = ((List.range (pk.k cx.p)).map fun k => (ss.2 k).gross).sum ∧
    ss.1.budget = ((List.range (pk.k cx.p)).map fun k => (ss.2 k).mc).sum + ss.1.lc := by
  obtain ⟨rs, rfl⟩ := h
  exact inv4_run pk cx initS rs inv_init (inv4_init pk cx)

/-- The spine binds the shard chains: heads match and each shard's APPLIED list is its records, in order. -/
theorem spine_chain_binds (pk : Pack) (cx : Ctx) (ss : SS) (h : reachS pk cx ss) :
    headsOk pk cx ss = true ∧ appliedOk pk cx ss := by
  obtain ⟨rs, rfl⟩ := h
  have h3 := inv3_run pk cx initS rs (fun _ => ⟨rfl, rfl⟩)
  refine ⟨?_, fun k _ => (h3 k).2⟩
  simp only [headsOk, List.all_eq_true, beq_iff_eq]
  exact fun k _ => (h3 k).1

end BlindLedger.Financial.ShardSplit
