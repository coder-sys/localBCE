import BlindLedger.Financial.ShardSplit

/-!
# RESHARD: change `K` for the record partition at a quiescent boundary

`reshard hist pk pk' cx key ss` moves a sharded store from pack `pk` to pack `pk'` (which may change `K` for `cx.p`
only; every other partition in `hist` keeps its `K`, `packUpdateOk`).  It applies only when every shard
`k < max K K'` has committed the spine's last record (`quiet`); otherwise it returns `none` and nothing is applied.

The directory keeps every row's raw digest and gross; a shard-homed row is rehomed to `sidx pk' cx (key c)`, i.e.
`shardOf pk' cx i` for its item `i` (`key` is the cell's item, which `DirRow` does not carry).  Shard rows are not
copied but derived: shard `j` holds `restrict dir' j` of the merged charges, so a row can sit only where the new
directory homes it.  Totals (gross, machine charges) consolidate at shard 0.  One spine record (no rows) touches
every shard `< max K K'` and advances its head and APPLIED list as any record does.

* (a) `reshard_row`, `reshard_row_src`, `reshard_dir`, `reach_high`: each charged row is present exactly once, at
  `tgt` (`shardOf pk'` of its item); no row appears from nowhere; old shards `≥ K` hold none on a reachable store.
* (b) `reshard_merge_run` (lifts `merge_run`), `reshard_whole_run` (lifts `whole_run`, `merge_run`),
  `reshard_rcpts_run` (lifts `rcpts_run`): the resharded store runs as the un-resharded single store; `norm` erases
  only the shard index of directory homes, so verdicts, receipts and every total agree exactly.
* (c) `inv_reshard` .. `history_reshard`: `Inv`..`Inv4`, `chainsOk`, `headsOk`, `historyOk` hold after.
* (d) `reshard_none`, `reshard_refuse`, `reshard_open`: refusal is `none`, never a partial application.
-/

namespace BlindLedger.Financial.Reshard

open BlindLedger.Financial.ShardSplit
open BlindLedger.Financial.Partition (PartId)

/-- The new shard of cell `c` under `pk'`. -/
def tgt (pk' : Pack) (cx : Ctx) (key : Cell → Option Item) (c : Cell) : Nat := sidx pk' cx (key c)

def rh (t : Nat) : Home → Home
  | .spine => .spine
  | .shard _ => .shard t

def rehome (pk' : Pack) (cx : Ctx) (key : Cell → Option Item) (c : Cell) (x : DirRow) : DirRow :=
  { x with home := rh (tgt pk' cx key c) x.home }

def rdir (pk' : Pack) (cx : Ctx) (key : Cell → Option Item) (d : Dir) : Dir := fun c => (d c).map (rehome pk' cx key c)

/-- Shards touched by the RESHARD record. -/
def rT (pk pk' : Pack) (cx : Ctx) : List Nat := List.range (max (pk.k cx.p) (pk'.k cx.p))

/-- Quiescent boundary: every shard has committed the spine's last record. -/
def quiet (pk pk' : Pack) (cx : Ctx) (ss : SS) : Bool := (rT pk pk' cx).all fun k => (ss.2 k).head == ss.1.heads k

def reshardOk (hist : List PartId) (pk pk' : Pack) (cx : Ctx) (ss : SS) : Bool :=
  quiet pk pk' cx ss && packOk pk && packUpdateOk (hist.filter (· != cx.p)) pk pk'

def rRec (pk pk' : Pack) (cx : Ctx) (ss : SS) : Rec :=
  { n := ss.1.recs.length, t := ss.1.t, I := fun _ => [], V := fun _ => [], pre := fun k => (ss.2 k).head,
    post := fun k => cx.hs (ss.2 k).head ss.1.recs.length [] [], touched := rT pk pk' cx }

def rShard (pk pk' : Pack) (cx : Ctx) (key : Cell → Option Item) (ss : SS) (j : Nat) : ShardDB :=
  { chg := restrict (rdir pk' cx key ss.1.dir) j (merge pk cx ss).chg,
    gross := if j = 0 then (merge pk cx ss).gross else 0,
    mc := if j = 0 then (merge pk cx ss).mc else 0,
    head := if j ∈ rT pk pk' cx then (rRec pk pk' cx ss).post j else (ss.2 j).head,
    applied := if j ∈ rT pk pk' cx then (ss.2 j).applied ++ [ss.1.recs.length] else (ss.2 j).applied }

def rSpine (pk pk' : Pack) (cx : Ctx) (key : Cell → Option Item) (ss : SS) : SpineDB :=
  { ss.1 with
    dir := rdir pk' cx key ss.1.dir,
    heads := fun k => if k ∈ rT pk pk' cx then (rRec pk pk' cx ss).post k else ss.1.heads k,
    recs := rRec pk pk' cx ss :: ss.1.recs }

def reshard (hist : List PartId) (pk pk' : Pack) (cx : Ctx) (key : Cell → Option Item) (ss : SS) : Option SS :=
  if reshardOk hist pk pk' cx ss then some (rSpine pk pk' cx key ss, rShard pk pk' cx key ss) else none

variable {hist : List PartId} {pk pk' : Pack} {cx : Ctx} {key : Cell → Option Item} {ss ss' : SS}

/-! ## (d) Refusal -/

theorem reshard_eq (h : reshard hist pk pk' cx key ss = some ss') :
    reshardOk hist pk pk' cx ss = true ∧ ss' = (rSpine pk pk' cx key ss, rShard pk pk' cx key ss) := by
  by_cases hc : reshardOk hist pk pk' cx ss = true
  · simp only [reshard, hc, ↓reduceIte, Option.some.injEq] at h
    exact ⟨hc, h.symm⟩
  · simp [reshard, hc] at h

theorem reshard_none (h : reshardOk hist pk pk' cx ss = false) : reshard hist pk pk' cx key ss = none := by
  simp [reshard, h]

theorem reshard_refuse
    (h : quiet pk pk' cx ss = false ∨ packOk pk = false ∨ packUpdateOk (hist.filter (· != cx.p)) pk pk' = false) :
    reshard hist pk pk' cx key ss = none := by
  apply reshard_none
  unfold reshardOk
  rcases h with h | h | h <;> simp [h]

/-- A crash after a spine COMMIT that left a touched shard `k` uncommitted is not quiescent: RESHARD refuses. -/
theorem reshard_open (inp : Input) (C : List Nat) (k : Nat) (hc : checkAll pk cx ss inp = true)
    (hk : k ∈ (mkRec pk cx ss inp).2.touched) (hC : k ∉ C) :
    reshard hist pk pk' cx key (afterSpine pk cx ss inp C) = none := by
  simp only [mkRec] at hk
  have hK : k < pk.k cx.p := by
    have h0 := hk; simp only [touched, List.mem_filter, List.mem_range] at h0; exact h0.1
  apply reshard_refuse
  left
  rw [Bool.eq_false_iff]
  intro hq
  simp only [quiet, rT, List.all_eq_true, beq_iff_eq] at hq
  have h1 := hq k (List.mem_range.2 (Nat.lt_of_lt_of_le hK (Nat.le_max_left _ _)))
  simp only [afterSpine, hc, ↓reduceIte, commitShards, hC, commitSpine, mkRec, hk] at h1
  exact cx.advances _ _ _ _ h1.symm

theorem ok_parts (h : reshardOk hist pk pk' cx ss = true) :
    quiet pk pk' cx ss = true ∧ packOk pk = true ∧ packOk pk' = true := by
  simp only [reshardOk, packUpdateOk, Bool.and_eq_true] at h
  exact ⟨h.1.1, h.1.2, h.2.1⟩

/-! ## Charges under the new directory -/

theorem tgt_lt (hK : 0 < pk'.k cx.p) (c : Cell) : tgt pk' cx key c < pk'.k cx.p := by
  unfold tgt
  cases key c with
  | none => exact hK
  | some i => exact Nat.mod_lt _ hK

theorem restrict_le {d : Dir} {k : Nat} {chg : Cell → Nat} {c : Cell} : restrict d k chg c ≤ chg c := by
  simp only [restrict]; split <;> omega

theorem restrict_pos {d : Dir} {k : Nat} {chg : Cell → Nat} {c : Cell} (h : 0 < restrict d k chg c) :
    ∃ x, d c = some x ∧ x.home = .shard k := by
  simp only [restrict] at h
  by_cases hx : (d c).map (·.home) = some (.shard k)
  · revert hx
    cases d c with
    | none => intro hx; cases hx
    | some x => intro hx; exact ⟨x, rfl, by simpa using hx⟩
  · rw [if_neg hx] at h; exact absurd h (Nat.lt_irrefl 0)

theorem inv_off (hI : Inv ss) (c : Cell) (k : Nat) (h : ∀ x, ss.1.dir c = some x → x.home ≠ .shard k) :
    (ss.2 k).chg c = 0 := by
  rcases Nat.eq_zero_or_pos ((ss.2 k).chg c) with h0 | h0
  · exact h0
  · obtain ⟨x, hx, hh⟩ := (hI c).2 k h0; exact absurd hh (h x hx)

theorem merge_le1 (hI : Inv ss) (c : Cell) : (merge pk cx ss).chg c ≤ 1 := by
  show ((List.range (pk.k cx.p)).map fun k => (ss.2 k).chg c).sum ≤ 1
  refine sum_le_one (fun k => (ss.2 k).chg c) (fun k => (hI c).1 k) ?_ _ (List.nodup_range ..)
  intro k k' hk hk'
  obtain ⟨x, hx, hh⟩ := (hI c).2 k hk
  obtain ⟨y, hy, hh'⟩ := (hI c).2 k' hk'
  have hxy : x = y := Option.some.inj (hx.symm.trans hy)
  subst hxy
  exact Home.shard.inj (hh.symm.trans hh')

/-- The merged charge of a cell homed at shard `k0` is shard `k0`'s charge. -/
theorem merge_at (hI : Inv ss) (c : Cell) (x : DirRow) (hx : ss.1.dir c = some x) (k0 : Nat) (hh : x.home = .shard k0)
    (hk : k0 < pk.k cx.p) : (merge pk cx ss).chg c = (ss.2 k0).chg c := by
  show ((List.range (pk.k cx.p)).map fun k => (ss.2 k).chg c).sum = _
  refine sum_one (fun k => (ss.2 k).chg c) k0 _ List.nodup_range (List.mem_range.2 hk) ?_
  intro k _ hne
  refine inv_off hI c k fun y hy => ?_
  have hxy : x = y := Option.some.inj (hx.symm.trans hy)
  subst hxy
  rw [hh]; intro he; exact hne (Home.shard.inj he).symm

theorem rchg_sum (hI : Inv ss) (hK' : 0 < pk'.k cx.p) (c : Cell) :
    ((List.range (pk'.k cx.p)).map fun j => restrict (rdir pk' cx key ss.1.dir) j (merge pk cx ss).chg c).sum
      = (merge pk cx ss).chg c := by
  cases hx : ss.1.dir c with
  | none =>
    have h0 : (merge pk cx ss).chg c = 0 := sum_zeroN _ _ fun k _ => inv_zero hI c hx k
    rw [h0]; exact sum_zeroN _ _ fun j _ => by simp [restrict, rdir, hx]
  | some x =>
    cases hh : x.home with
    | spine =>
      have h0 : (merge pk cx ss).chg c = 0 := sum_zeroN _ _ fun k _ => inv_off hI c k fun y hy => by
        have hxy : x = y := Option.some.inj (hx.symm.trans hy)
        subst hxy; rw [hh]; intro he; cases he
      rw [h0]; exact sum_zeroN _ _ fun j _ => by simp [restrict, rdir, hx, rehome, hh, rh]
    | shard k0 =>
      refine (sum_one (fun j => restrict (rdir pk' cx key ss.1.dir) j (merge pk cx ss).chg c) (tgt pk' cx key c) _
        List.nodup_range (List.mem_range.2 (tgt_lt hK' c)) ?_).trans ?_
      · intro j _ hj
        simp [restrict, rdir, hx, rehome, hh, rh, Ne.symm hj]
      · simp [restrict, rdir, hx, rehome, hh, rh]

/-- The merged view after RESHARD is the merged view before, with the rehomed directory. -/
theorem merge_reshard (hI : Inv ss) (hK' : 0 < pk'.k cx.p) :
    merge pk' cx (rSpine pk pk' cx key ss, rShard pk pk' cx key ss)
      = { merge pk cx ss with dir := rdir pk' cx key ss.1.dir } := by
  apply view_eq <;> try rfl
  · funext c; exact rchg_sum hI hK' c
  · refine (sum_range_zeroI (fun j => (rShard pk pk' cx key ss j).gross) _ hK' fun j hj => ?_).trans ?_
    · simp [rShard, hj]
    · simp [rShard]
  · refine (sum_range_zeroI (fun j => (rShard pk pk' cx key ss j).mc) _ hK' fun j hj => ?_).trans ?_
    · simp [rShard, hj]
    · simp [rShard]

/-! ## (c) Invariants that hold before still hold after -/

theorem inv_reshard (hI : Inv ss) (h : reshard hist pk pk' cx key ss = some ss') : Inv ss' := by
  obtain ⟨_, rfl⟩ := reshard_eq h
  intro c
  exact ⟨fun k => Nat.le_trans restrict_le (merge_le1 hI c), fun k hk => restrict_pos hk⟩

theorem inv2_reshard (h : reshard hist pk pk' cx key ss = some ss') : Inv2 ss' := by
  obtain ⟨_, rfl⟩ := reshard_eq h
  intro R rs hR k hk
  simp only [rSpine, List.cons.injEq] at hR
  obtain ⟨rfl, rfl⟩ := hR
  have hk' : k ∈ rT pk pk' cx := hk
  simp [rShard, hk']

theorem inv3_reshard (h3 : Inv3 ss) (h : reshard hist pk pk' cx key ss = some ss') : Inv3 ss' := by
  obtain ⟨_, rfl⟩ := reshard_eq h
  intro k
  obtain ⟨h1, h2⟩ := h3 k
  by_cases hk : k ∈ rT pk pk' cx
  · simp [rShard, rSpine, rRec, hk, h2]
  · simp [rShard, rSpine, rRec, hk, h1, h2]

theorem inv4_reshard (hI : Inv ss) (h4 : Inv4 pk cx ss) (h : reshard hist pk pk' cx key ss = some ss') :
    Inv4 pk' cx ss' := by
  obtain ⟨hok, rfl⟩ := reshard_eq h
  have hm := merge_reshard (pk := pk) (key := key) hI (k_pos pk' cx.p (ok_parts hok).2.2)
  have hg : (merge pk' cx (rSpine pk pk' cx key ss, rShard pk pk' cx key ss)).gross = (merge pk cx ss).gross := by
    rw [hm]
  have hc : (merge pk' cx (rSpine pk pk' cx key ss, rShard pk pk' cx key ss)).mc = (merge pk cx ss).mc := by
    rw [hm]
  exact ⟨h4.1.trans hg.symm, h4.2.trans (congrArg (· + ss.1.lc) hc.symm)⟩

theorem chain_reshard (hc : chainsOk ss) (h : reshard hist pk pk' cx key ss = some ss') : chainsOk ss' := by
  obtain ⟨_, rfl⟩ := reshard_eq h
  show (rRec pk pk' cx ss :: ss.1.recs).reverse.map (·.n) = List.range' 0 (ss.1.recs.length + 1)
  rw [List.reverse_cons, List.map_append, hc, List.range'_concat]
  simp [rRec]

theorem heads_reshard (h : reshard hist pk pk' cx key ss = some ss') : headsOk pk' cx ss' = true := by
  obtain ⟨_, rfl⟩ := reshard_eq h
  simp only [headsOk, List.all_eq_true, List.mem_range, beq_iff_eq]
  intro k hk
  have hk' : k ∈ rT pk pk' cx := List.mem_range.2 (Nat.lt_of_lt_of_le hk (Nat.le_max_right _ _))
  simp [rShard, rSpine, hk']

theorem history_reshard (hc : chainsOk ss) (h3 : Inv3 ss) (h : reshard hist pk pk' cx key ss = some ss') :
    historyOk pk' cx (mergeHist pk' cx ss') = true :=
  (spine_chain_binds_iff pk' cx ss').1 ⟨chain_reshard hc h, heads_reshard h, fun k _ => (inv3_reshard h3 h k).2⟩

/-! ## (a) Every row present exactly once, at its new home -/

theorem tgt_some {c : Cell} {i : Item} (h : key c = some i) : tgt pk' cx key c = shardOf pk' cx i := by
  simp [tgt, h, sidx]

theorem reshard_dir (h : reshard hist pk pk' cx key ss = some ss') (c : Cell) :
    ss'.1.dir c = (ss.1.dir c).map (rehome pk' cx key c) := by
  obtain ⟨_, rfl⟩ := reshard_eq h; rfl

/-- A row charged at old shard `k < K` is, after RESHARD, at `tgt < K'` with the same charge, and nowhere else. -/
theorem reshard_row (hI : Inv ss) (h : reshard hist pk pk' cx key ss = some ss') (c : Cell) (k : Nat)
    (hk : k < pk.k cx.p) (hpos : 0 < (ss.2 k).chg c) :
    tgt pk' cx key c < pk'.k cx.p ∧ (ss'.2 (tgt pk' cx key c)).chg c = (ss.2 k).chg c ∧
      ∀ j, j ≠ tgt pk' cx key c → (ss'.2 j).chg c = 0 := by
  obtain ⟨hok, rfl⟩ := reshard_eq h
  obtain ⟨x, hx, hh⟩ := (hI c).2 k hpos
  have hm := merge_at hI c x hx k hh hk
  refine ⟨tgt_lt (k_pos pk' cx.p (ok_parts hok).2.2) c, ?_, fun j hj => ?_⟩
  · show restrict (rdir pk' cx key ss.1.dir) _ (merge pk cx ss).chg c = _
    simp [restrict, rdir, hx, rehome, hh, rh, hm]
  · show restrict (rdir pk' cx key ss.1.dir) j (merge pk cx ss).chg c = 0
    simp [restrict, rdir, hx, rehome, hh, rh, Ne.symm hj]

/-- No row appears from nowhere: a charge at new shard `j` sits at the cell's `tgt` and came from an old shard. -/
theorem reshard_row_src (hI : Inv ss) (h : reshard hist pk pk' cx key ss = some ss') (c : Cell) (j : Nat)
    (hpos : 0 < (ss'.2 j).chg c) :
    j = tgt pk' cx key c ∧ ∃ k < pk.k cx.p, (ss.2 k).chg c = (ss'.2 j).chg c := by
  obtain ⟨hok, rfl⟩ := reshard_eq h
  obtain ⟨y, hy, hyh⟩ := restrict_pos hpos
  cases hx : ss.1.dir c with
  | none => simp [rdir, hx] at hy
  | some x =>
    simp only [rdir, hx, Option.map_some, Option.some.injEq] at hy
    subst hy
    cases hh : x.home with
    | spine => simp [rehome, hh, rh] at hyh
    | shard k0 =>
      have hj : j = tgt pk' cx key c := by simp [rehome, hh, rh] at hyh; exact hyh.symm
      have hpos' := Nat.lt_of_lt_of_le hpos restrict_le
      rcases Nat.lt_or_ge k0 (pk.k cx.p) with hk | hk
      · refine ⟨hj, k0, hk, ?_⟩
        show _ = restrict (rdir pk' cx key ss.1.dir) j (merge pk cx ss).chg c
        subst hj
        simp [restrict, rdir, hx, rehome, hh, rh, merge_at hI c x hx k0 hh hk]
      · exfalso
        have h0 : (merge pk cx ss).chg c = 0 := sum_zeroN _ _ fun k hk' => inv_off hI c k fun z hz => by
          have hxz : x = z := Option.some.inj (hx.symm.trans hz)
          subst hxz; rw [hh]; intro he
          have := List.mem_range.1 hk'; rw [Home.shard.inj he] at hk; omega
        exact absurd (h0 ▸ hpos') (Nat.lt_irrefl 0)

/-- On a reachable store with `packOk pk`, old shards `≥ K` hold no charge, so `reshard_row` covers every row. -/
theorem reach_high (hp : packOk pk = true) (hr : reachS pk cx ss) (k : Nat) (hk : pk.k cx.p ≤ k) (c : Cell) :
    (ss.2 k).chg c = 0 := by
  obtain ⟨L, rs, rfl⟩ := hr
  rw [run_high pk cx k hk]
  have : k ≠ 0 := by have := k_pos pk cx.p hp; omega
  simp [initS, initShards, this, initShard]

/-! ## (b) Observational equivalence -/

def cls : Home → Home
  | .spine => .spine
  | .shard _ => .shard 0

def nrow (x : DirRow) : DirRow := { x with home := cls x.home }

def ndir (d : Dir) : Dir := fun c => (d c).map nrow

def clsV : Verdict → Verdict
  | .admit h => .admit (cls h)
  | v => v

def nv (x : Row × Verdict) : Row × Verdict := (x.1, clsV x.2)

/-- A view with the shard index of every directory home erased; every other field is kept. -/
def norm (v : View) : View := { v with dir := ndir v.dir }

theorem cls_route (pk pk' : Pack) (cx : Ctx) (r : Row) : cls (routeNew pk cx r) = cls (routeNew pk' cx r) := by
  obtain ⟨c, it, raw, g, pos⟩ := r
  cases pos <;> cases it <;> rfl

theorem ndir_set (d : Dir) (c : Cell) (x : DirRow) : ndir (setDir d c x) = setDir (ndir d) c (nrow x) := by
  funext c'; by_cases h : c' = c <;> simp [ndir, setDir, h]

theorem nrow_rehome (c : Cell) (x : DirRow) : nrow (rehome pk' cx key c x) = nrow x := by
  obtain ⟨h, r, g⟩ := x; cases h <;> rfl

theorem ndir_rdir (d : Dir) : ndir (rdir pk' cx key d) = ndir d := by
  funext c
  show ((d c).map (rehome pk' cx key c)).map nrow = (d c).map nrow
  cases d c with
  | none => rfl
  | some x => exact congrArg some (nrow_rehome c x)

theorem jrow_sim (pk pk' : Pack) (cx : Ctx) {d1 d2 : Dir} (h : ndir d1 = ndir d2) (r : Row) :
    ndir (judgeRow pk cx d1 r).1 = ndir (judgeRow pk' cx d2 r).1 ∧
      clsV (judgeRow pk cx d1 r).2 = clsV (judgeRow pk' cx d2 r).2 := by
  have hc : (d1 r.cell).map nrow = (d2 r.cell).map nrow := congrFun h r.cell
  rcases h1 : d1 r.cell with _ | x <;> rcases h2 : d2 r.cell with _ | y <;> rw [h1, h2] at hc
  · simp only [judgeRow, h1, h2]
    refine ⟨?_, by simp [clsV, cls_route pk pk' cx r]⟩
    rw [ndir_set, ndir_set, h]; simp only [nrow, cls_route pk pk' cx r]
  · simp at hc
  · simp at hc
  · have hn : nrow x = nrow y := by simpa using hc
    have hr0 := congrArg DirRow.raw hn
    have hr : x.raw = y.raw := hr0
    simp only [judgeRow, h1, h2, hr]
    exact ⟨h, by trivial⟩

theorem jrows_sim (pk pk' : Pack) (cx : Ctx) : ∀ (rows : List Row) {d1 d2 : Dir}, ndir d1 = ndir d2 →
    ndir (judgeRows pk cx d1 rows).1 = ndir (judgeRows pk' cx d2 rows).1 ∧
      (judgeRows pk cx d1 rows).2.map nv = (judgeRows pk' cx d2 rows).2.map nv
  | [], _, _, h => ⟨h, rfl⟩
  | r :: rs, d1, d2, h => by
    obtain ⟨ha, hv⟩ := jrow_sim pk pk' cx h r
    obtain ⟨hb, hw⟩ := jrows_sim pk pk' cx rs ha
    refine ⟨hb, ?_⟩
    show nv (r, (judgeRow pk cx d1 r).2) :: (judgeRows pk cx (judgeRow pk cx d1 r).1 rs).2.map nv
      = nv (r, (judgeRow pk' cx d2 r).2) :: (judgeRows pk' cx (judgeRow pk' cx d2 r).1 rs).2.map nv
    rw [hw]; simp only [nv, hv]

theorem jsingle_sim (pk pk' : Pack) (cx : Ctx) (hp : packOk pk = packOk pk') {s1 s2 : View}
    (h : norm s1 = norm s2) (inp : Input) :
    (judgeSingle pk cx s1 inp).ok = (judgeSingle pk' cx s2 inp).ok ∧
      ndir (judgeSingle pk cx s1 inp).dir = ndir (judgeSingle pk' cx s2 inp).dir ∧
      (judgeSingle pk cx s1 inp).t = (judgeSingle pk' cx s2 inp).t ∧
      (judgeSingle pk cx s1 inp).out.map nv = (judgeSingle pk' cx s2 inp).out.map nv := by
  have hd0 := congrArg View.dir h
  have ht0 := congrArg View.t h
  have hd : ndir s1.dir = ndir s2.dir := hd0
  have ht : s1.t = s2.t := ht0
  obtain ⟨h1, h2⟩ := jrows_sim pk pk' cx inp.rows hd
  refine ⟨?_, h1, rfl, h2⟩
  show (packOk pk && decide (s1.t ≤ inp.t)) = (packOk pk' && decide (s2.t ≤ inp.t))
  rw [hp, ht]

/-- Filtering on a verdict property that ignores the shard index commutes with `nv`. -/
theorem fil_nv (p : Verdict → Bool) (hp : ∀ v, p (clsV v) = p v) :
    ∀ o : List (Row × Verdict), ((o.map nv).filter fun x => p x.2).map (·.1) = (o.filter fun x => p x.2).map (·.1)
  | [] => rfl
  | x :: o => by
    have ih := fil_nv p hp o
    by_cases hx : p x.2 = true
    · simp only [List.map_cons, List.filter_cons, nv, hp, hx, ↓reduceIte, ih]
    · simp only [List.map_cons, List.filter_cons, nv, hp, hx, ↓reduceIte, ih, Bool.false_eq_true]

theorem isSh_clsV (v : Verdict) : isSh (clsV v) = isSh v := by
  rcases v with ⟨_ | _⟩ | _ | _ <;> rfl

theorem spine_clsV (v : Verdict) : (clsV v == .admit .spine) = (v == .admit .spine) := by
  rcases v with ⟨_ | _⟩ | _ | _ <;> rfl

theorem rcptW_nv : ∀ (o : List (Row × Verdict)) (W : List Bool), rcptW (o.map nv) W = rcptW o W
  | [], _ => rfl
  | x :: o, W => by simp only [List.map_cons, rcptW, nv, isSh_clsV, rcptW_nv o]

theorem norm_applyW (cx : Ctx) {s1 s2 : View} {J1 J2 : Judgment} (hs : norm s1 = norm s2)
    (hd : ndir J1.dir = ndir J2.dir) (ht : J1.t = J2.t) (ho : J1.out.map nv = J2.out.map nv) :
    norm (applyWhole cx s1 J1) = norm (applyWhole cx s2 J2) := by
  have hw : wrows J1.out = wrows J2.out :=
    (fil_nv isSh isSh_clsV J1.out).symm.trans
      ((congrArg (fun o : List (Row × Verdict) => (o.filter fun x => isSh x.2).map (·.1)) ho).trans
        (fil_nv isSh isSh_clsV J2.out))
  have hp : part J1 .spine = part J2 .spine :=
    (fil_nv (· == .admit .spine) spine_clsV J1.out).symm.trans
      ((congrArg (fun o : List (Row × Verdict) => (o.filter fun x => x.2 == Verdict.admit .spine).map (·.1)) ho).trans
        (fil_nv (· == .admit .spine) spine_clsV J2.out))
  obtain ⟨d1, t1, u1, b1, l1, sr1, c1, g1, m1⟩ := s1
  obtain ⟨d2, t2, u2, b2, l2, sr2, c2, g2, m2⟩ := s2
  simp only [norm, View.mk.injEq] at hs
  obtain ⟨_, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩ := hs
  simp only [norm, applyWhole, hw, hp, hd, ht]

/-- The whole-file run, and its receipts, from views equal up to `norm`, under packs with the same `packOk`. -/
theorem runW_sim (pk pk' : Pack) (cx : Ctx) (hp : packOk pk = packOk pk') :
    ∀ (rs : List Input) {s1 s2 : View}, norm s1 = norm s2 →
      norm (runWhole pk cx s1 rs) = norm (runWhole pk' cx s2 rs) ∧ rcptsW pk cx s1 rs = rcptsW pk' cx s2 rs
  | [], _, _, h => ⟨h, rfl⟩
  | i :: is, s1, s2, h => by
    obtain ⟨ho, hd, ht, hv⟩ := jsingle_sim pk pk' cx hp h i
    have hstep : norm (stepWhole pk cx s1 i) = norm (stepWhole pk' cx s2 i) := by
      cases hb : (judgeSingle pk cx s1 i).ok
      · have hb' := ho.symm.trans hb
        simp [stepWhole, hb, hb']; exact h
      · have hb' := ho.symm.trans hb
        simp [stepWhole, hb, hb']; exact norm_applyW cx h hd ht hv
    obtain ⟨ih1, ih2⟩ := runW_sim pk pk' cx hp is hstep
    refine ⟨ih1, ?_⟩
    have hw : wrows (judgeSingle pk cx s1 i).out = wrows (judgeSingle pk' cx s2 i).out :=
      (fil_nv isSh isSh_clsV _).symm.trans
        ((congrArg (fun o : List (Row × Verdict) => (o.filter fun x => isSh x.2).map (·.1)) hv).trans
          (fil_nv isSh isSh_clsV _))
    have hr : ∀ W, rcptW (judgeSingle pk cx s1 i).out W = rcptW (judgeSingle pk' cx s2 i).out W := fun W => by
      rw [← rcptW_nv _ W, hv, rcptW_nv]
    simp only [rcptsW, ho, hw, hr, ih2]

theorem norm_reshard (hI : Inv ss) (hK' : 0 < pk'.k cx.p) :
    norm (merge pk' cx (rSpine pk pk' cx key ss, rShard pk pk' cx key ss)) = norm (merge pk cx ss) := by
  rw [merge_reshard hI hK']
  show ({ merge pk cx ss with dir := ndir (rdir pk' cx key ss.1.dir) } : View) = { merge pk cx ss with dir := ndir ss.1.dir }
  rw [ndir_rdir]

/-- Lifts `merge_run`: the resharded store runs as the single store on the merged view with the rehomed directory. -/
theorem reshard_merge_run (hI : Inv ss) (h3 : Inv3 ss) (h : reshard hist pk pk' cx key ss = some ss')
    (rs : List Input) :
    merge pk' cx (runS pk' cx ss' rs) = runSingle pk' cx { merge pk cx ss with dir := rdir pk' cx key ss.1.dir } rs := by
  have hI' := inv_reshard hI h
  have h3' := inv3_reshard h3 h
  obtain ⟨hok, rfl⟩ := reshard_eq h
  rw [merge_run pk' cx _ rs hI' h3', merge_reshard hI (k_pos pk' cx.p (ok_parts hok).2.2)]

/-- Lifts `whole_run` and `merge_run`: after RESHARD the store's merged view equals, up to the shard index of
    directory homes, the un-resharded single-store and whole-file runs (verdicts, dir, clock, every total). -/
theorem reshard_whole_run (hLoc : Local cx) (hI : Inv ss) (h3 : Inv3 ss)
    (h : reshard hist pk pk' cx key ss = some ss') (rs : List Input) :
    norm (merge pk' cx (runS pk' cx ss' rs)) = norm (runWhole pk cx (merge pk cx ss) rs) ∧
      norm (merge pk' cx (runS pk' cx ss' rs)) = norm (runSingle pk cx (merge pk cx ss) rs) := by
  have hI' := inv_reshard hI h
  have h3' := inv3_reshard h3 h
  obtain ⟨hok, rfl⟩ := reshard_eq h
  have hp : packOk pk' = packOk pk := by rw [(ok_parts hok).2.1, (ok_parts hok).2.2]
  have hw : norm (merge pk' cx (runS pk' cx (rSpine pk pk' cx key ss, rShard pk pk' cx key ss) rs))
      = norm (runWhole pk cx (merge pk cx ss) rs) := by
    rw [whole_run pk' cx hLoc _ rs hI' h3']
    exact (runW_sim pk' pk cx hp rs (norm_reshard (pk := pk) (key := key) hI (k_pos pk' cx.p (ok_parts hok).2.2))).1
  refine ⟨hw, ?_⟩
  rw [hw, ← whole_run pk cx hLoc ss rs hI h3, merge_run pk cx ss rs hI h3]

/-- Lifts `rcpts_run`: per-row receipts after RESHARD are the un-resharded store's and the whole-file run's. -/
theorem reshard_rcpts_run (hLoc : Local cx) (hI : Inv ss) (h3 : Inv3 ss)
    (h : reshard hist pk pk' cx key ss = some ss') (rs : List Input) :
    rcptsS pk' cx ss' rs = rcptsW pk cx (merge pk cx ss) rs ∧ rcptsS pk' cx ss' rs = rcptsS pk cx ss rs := by
  have hI' := inv_reshard hI h
  have h3' := inv3_reshard h3 h
  obtain ⟨hok, rfl⟩ := reshard_eq h
  have hp : packOk pk' = packOk pk := by rw [(ok_parts hok).2.1, (ok_parts hok).2.2]
  have hw : rcptsS pk' cx (rSpine pk pk' cx key ss, rShard pk pk' cx key ss) rs = rcptsW pk cx (merge pk cx ss) rs := by
    rw [rcpts_run pk' cx hLoc _ rs hI' h3']
    exact (runW_sim pk' pk cx hp rs (norm_reshard (pk := pk) (key := key) hI (k_pos pk' cx.p (ok_parts hok).2.2))).2
  exact ⟨hw, hw.trans (rcpts_run pk cx hLoc ss rs hI h3).symm⟩

/-! ## Witness -/

def cxW : Ctx :=
  { p := 0, hsh := fun _ _ => 1, lean := fun rs => rs.map fun _ => true, hs := fun d _ _ _ => d + 1,
    advances := fun d _ _ _ => Nat.succ_ne_self d }

def LW : Legacy :=
  { cells := fun _ => some (5, 10), t := 0, used := 10, budget := 3, lc := 0, spineRows := [], chg := fun _ => 1,
    gross := 10, mc := 3, head := 0, chg_le := fun _ => Nat.le_refl 1, chg_cell := fun _ _ => by simp,
    used_eq := rfl, budget_eq := rfl }

/-- K = 1 to K = 2: the one charged row moves from shard 0 to shard 1 (`1 % 2`), with its directory home. -/
example : (reshard [0] ⟨[]⟩ ⟨[(0, 2)]⟩ cxW (fun _ => some "i") (initS LW)).map
    (fun ss => ((ss.2 1).chg "a", (ss.2 0).chg "a", (ss.1.dir "a").map (·.home))) = some (1, 0, some (.shard 1)) := by
  decide

/-- Changing `K` of another partition with history is refused. -/
example : reshard [1] ⟨[]⟩ ⟨[(1, 2)]⟩ cxW (fun _ => some "i") (initS LW) = none := by
  apply reshard_none; decide

/-! ## Axiom pins -/

/-- info: 'BlindLedger.Financial.Reshard.reshard_row' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms reshard_row
/-- info: 'BlindLedger.Financial.Reshard.reshard_row_src' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms reshard_row_src
/-- info: 'BlindLedger.Financial.Reshard.reshard_merge_run' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms reshard_merge_run
/-- info: 'BlindLedger.Financial.Reshard.reshard_whole_run' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms reshard_whole_run
/-- info: 'BlindLedger.Financial.Reshard.reshard_rcpts_run' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms reshard_rcpts_run
/-- info: 'BlindLedger.Financial.Reshard.inv_reshard' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms inv_reshard
/-- info: 'BlindLedger.Financial.Reshard.history_reshard' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms history_reshard
/-- info: 'BlindLedger.Financial.Reshard.reshard_refuse' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms reshard_refuse
/-- info: 'BlindLedger.Financial.Reshard.reshard_open' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms reshard_open

end BlindLedger.Financial.Reshard
