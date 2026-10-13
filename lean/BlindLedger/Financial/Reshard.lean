import BlindLedger.Financial.ShardSplit

/-!
# RESHARD: change `K` for the record partition at a quiescent boundary

`reshard pk K' cx ss` moves a sharded store from pack `pk` to `setK pk cx.p K'`: only `cx.p`'s `K` changes, by
construction (`setK_k_ne`).  It applies only when every shard `k < max K K'` has committed the spine's last record
(`quiet`), `packOk pk`, `0 < K'` and the store's stored `K` is the pack's (`kOk`); otherwise it returns `none` and
nothing is applied.  The spine stores `K` (`SpineDB.k`); RESHARD sets it to `K'` (`reshard_k`), and every step and
every RESHARD under a pack whose `K` is not the stored one is refused (`stale_pack`): a pack not saved after a
RESHARD, or saved before one, cannot step or RESHARD the store.  `merge` sums the stored `K`, whatever the pack, so
a stale pack cannot misread it either; and a pack saves only with the stored `K` (`packSaveOk`, `packSave_ok`).

RESHARD is one spine record like any other.  Its part for shard `j` is an IMAGE (`Rec.img`): `j`'s charges, gross
and machine charge after the record, written as is.  `applyPart` overwrites from the image, so applying a part is
idempotent and independent of the order in which shards commit; the existing `replay`/`recoverAll` finishes a
RESHARD interrupted after the spine COMMIT at any set `C` of committed shards (`reshard_rollforward`).  Until it is
finished every later RESHARD and every step is refused under any pack, retired shards included (`lastOk`,
`reshard_crash_open`); once recovered the store accepts both again (`reshard_live`): a crash never wedges it.  Every
store a crash can leave recovers to a reachable store (`Crash`, `crash_recover`); recovery of any shard set `S`
interrupted part-way leaves again such a store (`crash_recoverOn`), for a RESHARD crash exactly the one with the
touched shards of `S` committed (`crash_partial`).  Each touched shard's post head is `cx.hi pre n image`, a chain
separate from the step chain `cx.hs` (`reshard_head_img`).  Replay installs a stored image only when the record's
post heads are `hi` of it (`imgOk`); that is the guard.  `img_bind` adds only injectivity of `hi` at the true image,
assumed explicitly (`Ctx` does not provide it).  A coordinated rewrite of image, post heads and spine heads on
uncommitted shards is not ruled out (open, not a regression).

The directory keeps every row's raw digest, gross and admitting item; a shard-homed row is rehomed to
`sidx pk' cx x.item`, `shardOf pk'` of the item the directory row itself carries (no caller-supplied key).  Shard
`j`'s image holds `restrict dir' j` of the merged charges, so a row can sit only where the new directory homes it.
The record touches every shard `< max K K'`; retired shards (`K' ≤ j < K`) are imaged to zero.

Limits, stated: gross and machine charge consolidate at shard 0 (a per-shard total is not a function of the
model's directory, which has no finite support); per-shard reconciliation must sum directory rows.

* (a) `reshard_row`, `reshard_row_src`, `reshard_dir`, `reshard_local`: each charged row is present exactly once,
  at `tgt`; no row appears from nowhere; every shard row sits at its item's shard under the new pack.
* (b) `reshard_merge_run`, `reshard_whole_run`, `reshard_rcpts_run`: the resharded store runs as the un-resharded
  single store up to `norm` (the shard index of directory homes).
* (c) `inv_reshard` .. `history_reshard`, `inv2_reshard`, `ReachR`, `reachS_reachR`, `reachR_ok`, `reachR_recover`:
  invariants, the stored `K`, the home bound and recovery hold on every store reachable by steps and RESHARDs.
* (d) `reshard_none`, `reshard_refuse`, `stale_pack`, `reshard_k`, `packSave_ok`, `reshard_open`,
  `reshard_rollforward`, `reshard_crash_open`, `Crash`, `crash_recover`, `crash_partial`, `crash_recoverOn`,
  `live_inv3`, `reshard_live`, `reshard_head_img`, `img_bind`.
-/

namespace BlindLedger.Financial.Reshard

open BlindLedger.Financial.ShardSplit
open BlindLedger.Financial.Partition (PartId)

/-- The pack with `K = K'` for partition `p`, every other partition unchanged. -/
def setK (pk : Pack) (p : PartId) (K' : Nat) : Pack := ⟨(p, K') :: pk.ks⟩

/-- The shard of directory row `x` under pack `pk`: its item's shard. -/
def tgt (pk : Pack) (cx : Ctx) (x : DirRow) : Nat := sidx pk cx x.item

def rh (t : Nat) : Home → Home
  | .spine => .spine
  | .shard _ => .shard t

def rehome (pk : Pack) (cx : Ctx) (x : DirRow) : DirRow := { x with home := rh (tgt pk cx x) x.home }

def rdir (pk : Pack) (cx : Ctx) (d : Dir) : Dir := fun c => (d c).map (rehome pk cx)

/-- Shards touched by the RESHARD record. -/
def rT (pk : Pack) (K' : Nat) (cx : Ctx) : List Nat := List.range (max (pk.k cx.p) K')

/-- Quiescent boundary: every shard the record reads or writes, and every shard the spine's last record touched,
    has committed that record, and its image, if any, is the one its post heads commit to. -/
def quiet (pk : Pack) (K' : Nat) (cx : Ctx) (ss : SS) : Bool :=
  ((rT pk K' cx).all fun k => (ss.2 k).head == ss.1.heads k) && lastOk cx ss

def reshardOk (pk : Pack) (K' : Nat) (cx : Ctx) (ss : SS) : Bool :=
  quiet pk K' cx ss && packOk pk && decide (0 < K') && kOk pk cx ss

/-- Shard `j`'s image: its rows of the merged charges under the new directory; totals at shard 0. -/
def rImg (pk : Pack) (K' : Nat) (cx : Ctx) (ss : SS) (j : Nat) : (Cell → Nat) × Int × Int :=
  (restrict (rdir (setK pk cx.p K') cx ss.1.dir) j (merge pk cx ss).chg,
    if j = 0 then (merge pk cx ss).gross else 0, if j = 0 then (merge pk cx ss).mc else 0)

def rRec (pk : Pack) (K' : Nat) (cx : Ctx) (ss : SS) : Rec :=
  { n := ss.1.recs.length, t := ss.1.t, I := fun _ => [], V := fun _ => [], pre := fun k => (ss.2 k).head,
    post := fun k => cx.hi (ss.2 k).head ss.1.recs.length (rImg pk K' cx ss k), touched := rT pk K' cx,
    img := some (rImg pk K' cx ss) }

def rSpine (pk : Pack) (K' : Nat) (cx : Ctx) (ss : SS) : SpineDB :=
  { ss.1 with
    dir := rdir (setK pk cx.p K') cx ss.1.dir,
    heads := fun k => if k ∈ rT pk K' cx then (rRec pk K' cx ss).post k else ss.1.heads k,
    recs := rRec pk K' cx ss :: ss.1.recs,
    k := K' }

def reshard (pk : Pack) (K' : Nat) (cx : Ctx) (ss : SS) : Option SS :=
  if reshardOk pk K' cx ss then some (rSpine pk K' cx ss, commitShards (rRec pk K' cx ss) (rT pk K' cx) ss.2)
  else none

/-- A crash after the RESHARD spine COMMIT: only the shards in `C` committed their part. -/
def afterReshard (pk : Pack) (K' : Nat) (cx : Ctx) (ss : SS) (C : List Nat) : SS :=
  if reshardOk pk K' cx ss then (rSpine pk K' cx ss, commitShards (rRec pk K' cx ss) C ss.2) else ss

/-- Every shard-homed directory row sits below `K`. -/
def homesLt (pk : Pack) (cx : Ctx) (d : Dir) : Prop :=
  ∀ c x j, d c = some x → x.home = .shard j → j < pk.k cx.p

/-- Every shard-homed directory row sits at its item's shard. -/
def locDir (pk : Pack) (cx : Ctx) (d : Dir) : Prop :=
  ∀ c x j, d c = some x → x.home = .shard j → j = sidx pk cx x.item

/-- Stores reachable by steps and RESHARDs from a migrated store (the pack is the store's current pack). -/
inductive ReachR (cx : Ctx) : Pack → SS → Prop
  | init (pk : Pack) (L : Legacy) : packOk pk = true → ReachR cx pk (initS (pk.k cx.p) L)
  | step {pk : Pack} {ss : SS} (inp : Input) : ReachR cx pk ss → ReachR cx pk (stepT pk cx ss inp)
  | resh {pk : Pack} {ss ss' : SS} (K' : Nat) :
      ReachR cx pk ss → reshard pk K' cx ss = some ss' → ReachR cx (setK pk cx.p K') ss'

/-- Recovery interrupted part-way: only the shards in `S` were recovered. -/
def recoverOn (cx : Ctx) (S : List Nat) (ss : SS) : SS :=
  (ss.1, fun k => if k ∈ S then recover cx ss.1 k (ss.2 k) else ss.2 k)

/-- Every store a crash can leave: a reachable store, or one interrupted after the spine COMMIT of a step or of a
    RESHARD with any set `C` of touched shards committed.  A recovery interrupted part-way is again a `Crash` store
    (`crash_recoverOn`; for `resh`, `crash_partial`). -/
inductive Crash (cx : Ctx) : Pack → SS → Prop
  | ok {pk : Pack} {ss : SS} : ReachR cx pk ss → Crash cx pk ss
  | spine {pk : Pack} {ss : SS} (inp : Input) (C : List Nat) : ReachR cx pk ss →
      (∀ k ∈ C, k ∈ (mkRec pk cx ss inp).2.touched) → Crash cx pk (afterSpine pk cx ss inp C)
  | resh {pk : Pack} {ss : SS} (K' : Nat) (C : List Nat) : ReachR cx pk ss → reshardOk pk K' cx ss = true →
      (∀ k ∈ C, k ∈ rT pk K' cx) → Crash cx (setK pk cx.p K') (afterReshard pk K' cx ss C)

variable {pk : Pack} {K' : Nat} {cx : Ctx} {ss ss' : SS}

/-! ## The pack -/

theorem setK_k_self (pk : Pack) (p : PartId) (K' : Nat) : (setK pk p K').k p = K' := by
  simp [setK, Pack.k, kOf]

theorem setK_k_ne (pk : Pack) {p q : PartId} (K' : Nat) (h : q ≠ p) : (setK pk p K').k q = pk.k q := by
  simp [setK, Pack.k, kOf, h]

/-! ## (d) Refusal and crash -/

theorem reshard_eq (h : reshard pk K' cx ss = some ss') :
    reshardOk pk K' cx ss = true ∧
      ss' = (rSpine pk K' cx ss, commitShards (rRec pk K' cx ss) (rT pk K' cx) ss.2) := by
  unfold reshard at h
  split at h
  · rename_i hh; cases h; exact ⟨hh, rfl⟩
  · cases h

theorem reshard_none (h : reshardOk pk K' cx ss = false) : reshard pk K' cx ss = none := by
  simp [reshard, h]

theorem ok_parts (h : reshardOk pk K' cx ss = true) :
    quiet pk K' cx ss = true ∧ packOk pk = true ∧ 0 < K' ∧ ss.1.k = pk.k cx.p := by
  simp only [reshardOk, kOk, Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] at h
  obtain ⟨⟨⟨hq, hp⟩, hK⟩, hk⟩ := h
  exact ⟨hq, hp, hK, hk⟩

theorem reshard_refuse (h : quiet pk K' cx ss = false ∨ packOk pk = false ∨ K' = 0 ∨ ss.1.k ≠ pk.k cx.p) :
    reshard pk K' cx ss = none := by
  apply reshard_none
  cases hh : reshardOk pk K' cx ss
  · rfl
  · obtain ⟨hq, hp, hK, hk⟩ := ok_parts hh
    rcases h with h | h | h | h
    · rw [hq] at h; cases h
    · rw [hp] at h; cases h
    · omega
    · exact absurd hk h

/-- HIGH-1: a pack whose `K` is not the store's (one saved before a RESHARD, or not saved after one) can neither
    RESHARD nor step the store. -/
theorem stale_pack (h : ss.1.k ≠ pk.k cx.p) :
    (∀ K'', reshard pk K'' cx ss = none) ∧ ∀ inp, stepS pk cx ss inp = none := by
  refine ⟨fun K'' => reshard_refuse (Or.inr (Or.inr (Or.inr h))), fun inp => ?_⟩
  have hk : kOk pk cx ss = false := beq_eq_false_iff_ne.2 h
  simp [stepS, checkAll, hk]

/-- RESHARD stores its `K'`. -/
theorem reshard_k (h : reshard pk K' cx ss = some ss') : ss'.1.k = K' := by
  unfold reshard at h
  split at h
  · cases h; rfl
  · cases h

/-- After a RESHARD to `K'`, a pack saves iff it is well formed and its `K` is `K'`: the old `K` is refused. -/
theorem packSave_ok (h : reshard pk K' cx ss = some ss') (pk' : Pack) :
    packSaveOk pk' cx ss' = (packOk pk' && K' == pk'.k cx.p) := by
  unfold packSaveOk kOk; rw [reshard_k h]

theorem rRec_imgOk : imgOk cx (rRec pk K' cx ss) = true :=
  List.all_eq_true.2 fun _ _ => beq_self_eq_true _

/-- A newest record touching a shard whose head is not the spine's head blocks RESHARD and every step. -/
theorem lastOk_false {s : SS} {R : Rec} {rs : List Rec} (hr : s.1.recs = R :: rs) {k : Nat} (hk : k ∈ R.touched)
    (hne : (s.2 k).head ≠ s.1.heads k) : lastOk cx s = false := by
  have h : (R.touched.all fun k => (s.2 k).head == s.1.heads k) = false :=
    Bool.eq_false_iff.2 fun h => hne (beq_iff_eq.1 (List.all_eq_true.1 h k hk))
  simp [lastOk, hr, h]

theorem blocked {s : SS} (hl : lastOk cx s = false) :
    (∀ pk'' K'', reshard pk'' K'' cx s = none) ∧ ∀ pk'' inp, stepS pk'' cx s inp = none := by
  refine ⟨fun pk'' K'' => reshard_refuse (Or.inl ?_), fun pk'' inp => ?_⟩
  · simp [quiet, hl]
  · simp [stepS, checkAll, hl]

/-- A crash after a step's spine COMMIT that left a touched shard `k` uncommitted is not quiescent: under any
    pack, RESHARD and every step refuse. -/
theorem reshard_open (inp : Input) (C : List Nat) (k : Nat) (hc : checkAll pk cx ss inp = true)
    (hk : k ∈ (mkRec pk cx ss inp).2.touched) (hC : k ∉ C) :
    (∀ pk'' K'', reshard pk'' K'' cx (afterSpine pk cx ss inp C) = none) ∧
      ∀ pk'' inp', stepS pk'' cx (afterSpine pk cx ss inp C) inp' = none := by
  have hA : afterSpine pk cx ss inp C =
      (commitSpine ss.1 (mkRec pk cx ss inp).1 (mkRec pk cx ss inp).2,
        commitShards (mkRec pk cx ss inp).2 C ss.2) := by
    unfold afterSpine; rw [if_pos hc]
  rw [hA]
  apply blocked
  refine lastOk_false (R := (mkRec pk cx ss inp).2) (rs := ss.1.recs) rfl hk ?_
  have e1 : (commitShards (mkRec pk cx ss inp).2 C ss.2 k).head = (ss.2 k).head := by simp [commitShards, hC]
  have e2 : (commitSpine ss.1 (mkRec pk cx ss inp).1 (mkRec pk cx ss inp).2).heads k =
      cx.hs (ss.2 k).head ss.1.recs.length (part (judge pk cx ss.1.view inp) (.shard k))
        (verdicts cx (judge pk cx ss.1.view inp) k) := by
    show (if k ∈ (mkRec pk cx ss inp).2.touched then _ else _) = _
    rw [if_pos hk]; rfl
  show (commitShards (mkRec pk cx ss inp).2 C ss.2 k).head ≠
    (commitSpine ss.1 (mkRec pk cx ss inp).1 (mkRec pk cx ss inp).2).heads k
  rw [e1, e2]
  exact fun h => cx.advances _ _ _ _ h.symm

/-- H1: a RESHARD interrupted after its spine COMMIT, with any set `C` of shards committed, recovers to exactly
    the completed RESHARD. -/
theorem reshard_rollforward (C : List Nat) (h : reshard pk K' cx ss = some ss') (hC : ∀ k ∈ C, k ∈ rT pk K' cx) :
    recoverAll cx (afterReshard pk K' cx ss C) = ss' := by
  obtain ⟨hok, rfl⟩ := reshard_eq h
  have hA : afterReshard pk K' cx ss C = (rSpine pk K' cx ss, commitShards (rRec pk K' cx ss) C ss.2) := by
    unfold afterReshard; rw [if_pos hok]
  rw [hA]
  refine Prod.ext rfl (funext fun k => ?_)
  exact replay_commit cx (rRec pk K' cx ss) ss.2 C hC (fun _ => rfl) (fun _ => cx.advancesI _ _ _) rRec_imgOk k

/-- Before recovery, an interrupted RESHARD with any touched shard `j` uncommitted (a retired `j ≥ K'` included)
    blocks every later RESHARD and every step, under any pack. -/
theorem reshard_crash_open (C : List Nat) (j : Nat) (hok : reshardOk pk K' cx ss = true) (hj : j ∈ rT pk K' cx)
    (hC : j ∉ C) :
    (∀ pk'' K'', reshard pk'' K'' cx (afterReshard pk K' cx ss C) = none) ∧
      ∀ pk'' inp, stepS pk'' cx (afterReshard pk K' cx ss C) inp = none := by
  have hA : afterReshard pk K' cx ss C = (rSpine pk K' cx ss, commitShards (rRec pk K' cx ss) C ss.2) := by
    unfold afterReshard; rw [if_pos hok]
  rw [hA]
  apply blocked
  refine lastOk_false (R := rRec pk K' cx ss) (rs := ss.1.recs) rfl hj ?_
  have e1 : (commitShards (rRec pk K' cx ss) C ss.2 j).head = (ss.2 j).head := by simp [commitShards, hC]
  show (commitShards (rRec pk K' cx ss) C ss.2 j).head ≠ (rSpine pk K' cx ss).heads j
  rw [e1]
  show _ ≠ (if j ∈ rT pk K' cx then _ else _)
  rw [if_pos hj]
  exact fun h => cx.advancesI _ _ _ h.symm

/-- M1: recovery of every store a crash can leave is a reachable store. -/
theorem crash_recover (h : Crash cx pk ss) : ReachR cx pk (recoverAll cx ss) := sorry

/-- M1: a RESHARD recovery interrupted after recovering any shards `S` leaves the RESHARD crash with `C` and the
    touched shards of `S` committed; recovery may be interrupted and resumed any number of times. -/
theorem crash_partial (C S : List Nat) (hok : reshardOk pk K' cx ss = true) (hC : ∀ k ∈ C, k ∈ rT pk K' cx) :
    recoverOn cx S (afterReshard pk K' cx ss C) =
      afterReshard pk K' cx ss (C ++ S.filter fun k => decide (k ∈ rT pk K' cx)) := sorry

/-- M1: recovery of any shard set `S` interrupted part-way, from any store a crash can leave (a step's crash
    included), leaves a store a crash can leave. -/
theorem crash_recoverOn (h : Crash cx pk ss) (S : List Nat) : Crash cx pk (recoverOn cx S ss) := sorry

/-- Never wedged: with every shard head at the spine's, the stored `K` the pack's and the newest image bound
    (`InvK`), RESHARD to any `K'' > 0` applies and every step the judgment accepts commits. -/
theorem live_inv3 (h3 : Inv3 ss) (hk : InvK pk cx ss) (hp : packOk pk = true) (K'' : Nat) (hK : 0 < K'') :
    (reshard pk K'' cx ss).isSome = true ∧
      ∀ inp, (judge pk cx ss.1.view inp).ok = true → (stepS pk cx ss inp).isSome = true := sorry

/-- After a crash inside any RESHARD (a `K` decrease included), recovery leaves a store that accepts RESHARD to any
    `K'' > 0` and every step the judgment accepts. -/
theorem reshard_live (C : List Nat) (h3 : Inv3 ss) (h : reshard pk K' cx ss = some ss')
    (hC : ∀ k ∈ C, k ∈ rT pk K' cx) (K'' : Nat) (hK : 0 < K'') :
    (reshard (setK pk cx.p K') K'' cx (recoverAll cx (afterReshard pk K' cx ss C))).isSome = true ∧
      ∀ inp, (judge (setK pk cx.p K') cx ss'.1.view inp).ok = true →
        (stepS (setK pk cx.p K') cx (recoverAll cx (afterReshard pk K' cx ss C)) inp).isSome = true := sorry

/-- The transition's head equation: each touched shard's head after RESHARD is the image chain `cx.hi` over its
    pre head, the record number and its charges, gross and machine charge after RESHARD.  This alone does not
    bind the head to the state (`hi` need not be injective); see `img_bind`. -/
theorem reshard_head_img (h : reshard pk K' cx ss = some ss') (j : Nat) (hj : j ∈ rT pk K' cx) :
    (ss'.2 j).head = cx.hi (ss.2 j).head ss.1.recs.length ((ss'.2 j).chg, (ss'.2 j).gross, (ss'.2 j).mc) := by
  obtain ⟨_, rfl⟩ := reshard_eq h
  show (commitShards (rRec pk K' cx ss) (rT pk K' cx) ss.2 j).head = cx.hi (ss.2 j).head ss.1.recs.length
    ((commitShards (rRec pk K' cx ss) (rT pk K' cx) ss.2 j).chg, (commitShards (rRec pk K' cx ss) (rT pk K' cx) ss.2 j).gross,
      (commitShards (rRec pk K' cx ss) (rT pk K' cx) ss.2 j).mc)
  unfold commitShards
  rw [if_pos hj]
  rfl

/-- M2: if `hi` at shard `j`'s pre head and record number has no collision with the true image (`hInj`, a
    collision-resistance assumption stated pointwise: no `Ctx` hash into `Dg = Nat` is injective on all images),
    every image whose `hi` gives `j`'s head after RESHARD is the true one.  This adds only head injectivity; the
    real guard is `imgOk` in `replay`.  A coordinated rewrite of image, post heads and spine heads on uncommitted
    shards is not ruled out (open, not a regression). -/
theorem img_bind (j : Nat) (v : (Cell → Nat) × Int × Int)
    (hInj : ∀ w, cx.hi (ss.2 j).head ss.1.recs.length w = cx.hi (ss.2 j).head ss.1.recs.length (rImg pk K' cx ss j) →
      w = rImg pk K' cx ss j)
    (h : reshard pk K' cx ss = some ss') (hj : j ∈ rT pk K' cx)
    (hv : (ss'.2 j).head = cx.hi (ss.2 j).head ss.1.recs.length v) : v = rImg pk K' cx ss j := by
  have hh : (ss'.2 j).head = cx.hi (ss.2 j).head ss.1.recs.length (rImg pk K' cx ss j) := by
    obtain ⟨_, rfl⟩ := reshard_eq h
    show (commitShards (rRec pk K' cx ss) (rT pk K' cx) ss.2 j).head = _
    unfold commitShards
    rw [if_pos hj]
    rfl
  exact hInj v (hv.symm.trans hh)

/-! ## Charges under the new directory -/

theorem tgt_lt (hK : 0 < pk.k cx.p) (x : DirRow) : tgt pk cx x < pk.k cx.p := by
  unfold tgt sidx
  cases x.item with
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

/-- With the home bound, shards `≥ K` hold no charge, so `reshard_row` covers every charged row. -/
theorem high_zero (hI : Inv ss) (hB : homesLt pk cx ss.1.dir) (k : Nat) (hk : pk.k cx.p ≤ k) (c : Cell) :
    (ss.2 k).chg c = 0 :=
  inv_off hI c k fun x hx hh => by have := hB c x k hx hh; omega

theorem merge_le1 (hI : Inv ss) (c : Cell) : (merge pk cx ss).chg c ≤ 1 := by
  show ((List.range ss.1.k).map fun k => (ss.2 k).chg c).sum ≤ 1
  refine sum_le_one (fun k => (ss.2 k).chg c) (fun k => (hI c).1 k) ?_ _ (List.nodup_range ..)
  intro k k' hk hk'
  obtain ⟨x, hx, hh⟩ := (hI c).2 k hk
  obtain ⟨y, hy, hh'⟩ := (hI c).2 k' hk'
  have hxy : x = y := Option.some.inj (hx.symm.trans hy)
  subst hxy
  exact Home.shard.inj (hh.symm.trans hh')

/-- The merged charge of a cell homed at shard `k0` is shard `k0`'s charge. -/
theorem merge_at (hI : Inv ss) (c : Cell) (x : DirRow) (hx : ss.1.dir c = some x) (k0 : Nat) (hh : x.home = .shard k0)
    (hk : k0 < ss.1.k) : (merge pk cx ss).chg c = (ss.2 k0).chg c := by
  show ((List.range ss.1.k).map fun k => (ss.2 k).chg c).sum = _
  refine sum_one (fun k => (ss.2 k).chg c) k0 _ List.nodup_range (List.mem_range.2 hk) ?_
  intro k _ hne
  refine inv_off hI c k fun y hy => ?_
  have hxy : x = y := Option.some.inj (hx.symm.trans hy)
  subst hxy
  rw [hh]; intro he; exact hne (Home.shard.inj he).symm

theorem mem_rT {k : Nat} (hk : k < K') : k ∈ rT pk K' cx :=
  List.mem_range.2 (Nat.lt_of_lt_of_le hk (Nat.le_max_right _ _))

theorem new_chg {k : Nat} (hk : k ∈ rT pk K' cx) (c : Cell) :
    (commitShards (rRec pk K' cx ss) (rT pk K' cx) ss.2 k).chg c =
      restrict (rdir (setK pk cx.p K') cx ss.1.dir) k (merge pk cx ss).chg c := by
  unfold commitShards; rw [if_pos hk]; rfl

theorem new_gross {k : Nat} (hk : k ∈ rT pk K' cx) :
    (commitShards (rRec pk K' cx ss) (rT pk K' cx) ss.2 k).gross =
      if k = 0 then (merge pk cx ss).gross else 0 := by
  unfold commitShards; rw [if_pos hk]; rfl

theorem new_mc {k : Nat} (hk : k ∈ rT pk K' cx) :
    (commitShards (rRec pk K' cx ss) (rT pk K' cx) ss.2 k).mc = if k = 0 then (merge pk cx ss).mc else 0 := by
  unfold commitShards; rw [if_pos hk]; rfl

theorem sum_range_zeroI' (f : Nat → Int) (K : Nat) (hK : 0 < K) (hf : ∀ k, k ≠ 0 → k < K → f k = 0) :
    ((List.range K).map f).sum = f 0 := by
  have e : (List.range K).map f = (List.range K).map (fun k => if k < K then f k else 0) :=
    List.map_congr_left fun k hk => (if_pos (List.mem_range.1 hk)).symm
  rw [e, sum_range_zeroI _ K hK fun k hk => by
    by_cases h : k < K
    · simp only [if_pos h]; exact hf k hk h
    · simp only [if_neg h]]
  simp only [if_pos hK]

theorem gross_sum (hK' : 0 < K') :
    ((List.range K').map fun k => (commitShards (rRec pk K' cx ss) (rT pk K' cx) ss.2 k).gross).sum =
      (merge pk cx ss).gross := by
  rw [sum_range_zeroI' _ K' hK' fun k hk hl => by rw [new_gross (mem_rT hl)]; exact if_neg hk,
    new_gross (mem_rT hK')]
  exact if_pos rfl

theorem mc_sum (hK' : 0 < K') :
    ((List.range K').map fun k => (commitShards (rRec pk K' cx ss) (rT pk K' cx) ss.2 k).mc).sum =
      (merge pk cx ss).mc := by
  rw [sum_range_zeroI' _ K' hK' fun k hk hl => by rw [new_mc (mem_rT hl)]; exact if_neg hk,
    new_mc (mem_rT hK')]
  exact if_pos rfl

/-- The new images, summed over the new shards, give back the merged charge of every cell. -/
theorem rimg_sum (hI : Inv ss) (hK' : 0 < K') (c : Cell) :
    ((List.range K').map fun k => restrict (rdir (setK pk cx.p K') cx ss.1.dir) k (merge pk cx ss).chg c).sum =
      (merge pk cx ss).chg c := by
  by_cases hz : ∀ k ∈ List.range ss.1.k, (ss.2 k).chg c = 0
  · have h0 : (merge pk cx ss).chg c = 0 := sum_zeroN (fun k => (ss.2 k).chg c) _ hz
    rw [h0]
    exact sum_zeroN _ _ fun k _ => by
      have := @restrict_le (rdir (setK pk cx.p K') cx ss.1.dir) k (merge pk cx ss).chg c
      omega
  · have hex : ∃ k0 ∈ List.range ss.1.k, (ss.2 k0).chg c ≠ 0 :=
      Classical.byContradiction fun hcon =>
        hz fun k hk => Classical.byContradiction fun hh => hcon ⟨k, hk, hh⟩
    obtain ⟨k0, _, hne⟩ := hex
    obtain ⟨x, hx, hh⟩ := (hI c).2 k0 (Nat.pos_of_ne_zero hne)
    have hK2 : 0 < (setK pk cx.p K').k cx.p := by rw [setK_k_self]; exact hK'
    have ht := tgt_lt hK2 x
    rw [setK_k_self] at ht
    have hnd : rdir (setK pk cx.p K') cx ss.1.dir c = some (rehome (setK pk cx.p K') cx x) := by
      simp [rdir, hx]
    have hhome : (rehome (setK pk cx.p K') cx x).home = .shard (tgt (setK pk cx.p K') cx x) := by
      simp [rehome, rh, hh]
    generalize tgt (setK pk cx.p K') cx x = t at ht hhome
    refine (sum_one (fun k => restrict (rdir (setK pk cx.p K') cx ss.1.dir) k (merge pk cx ss).chg c) t _
      List.nodup_range (List.mem_range.2 ht) ?_).trans ?_
    · intro k _ hne'
      simp [restrict, hnd, hhome, Ne.symm hne']
    · simp [restrict, hnd, hhome]

/-- The merged view after RESHARD is the merged view before, with the rehomed directory. -/
theorem merge_reshard (hI : Inv ss) (hK' : 0 < K') :
    merge (setK pk cx.p K') cx (rSpine pk K' cx ss, commitShards (rRec pk K' cx ss) (rT pk K' cx) ss.2)
      = { merge pk cx ss with dir := rdir (setK pk cx.p K') cx ss.1.dir } := by
  refine view_eq rfl rfl rfl rfl rfl rfl (funext fun c => ?_) ?_ ?_
  · show ((List.range K').map fun k => (commitShards (rRec pk K' cx ss) (rT pk K' cx) ss.2 k).chg c).sum =
      (merge pk cx ss).chg c
    rw [List.map_congr_left fun k hk => new_chg (mem_rT (List.mem_range.1 hk)) c]
    exact rimg_sum hI hK' c
  · exact gross_sum hK'
  · exact mc_sum hK'

/-! ## (c) Invariants -/

theorem inv_reshard (hI : Inv ss) (hB : homesLt pk cx ss.1.dir) (h : reshard pk K' cx ss = some ss') : Inv ss' := by
  obtain ⟨_, rfl⟩ := reshard_eq h
  intro c
  refine ⟨fun k => ?_, fun k hk => ?_⟩
  · show (commitShards (rRec pk K' cx ss) (rT pk K' cx) ss.2 k).chg c ≤ 1
    by_cases hkT : k ∈ rT pk K' cx
    · rw [new_chg hkT]; exact Nat.le_trans restrict_le (merge_le1 hI c)
    · unfold commitShards; rw [if_neg hkT]; exact (hI c).1 k
  · change 0 < (commitShards (rRec pk K' cx ss) (rT pk K' cx) ss.2 k).chg c at hk
    change ∃ x, rdir (setK pk cx.p K') cx ss.1.dir c = some x ∧ x.home = .shard k
    by_cases hkT : k ∈ rT pk K' cx
    · rw [new_chg hkT] at hk; exact restrict_pos hk
    · unfold commitShards at hk; rw [if_neg hkT] at hk
      have h2 : ¬ k < max (pk.k cx.p) K' := fun hh => hkT (List.mem_range.2 hh)
      have h0 := high_zero hI hB k (by omega) c
      omega

theorem inv2_reshard (h : reshard pk K' cx ss = some ss') : Inv2 ss' := by
  obtain ⟨_, rfl⟩ := reshard_eq h
  intro R rs hR k hk
  have hR' : rRec pk K' cx ss = R := (List.cons.inj hR).1
  subst hR'
  show (commitShards (rRec pk K' cx ss) (rT pk K' cx) ss.2 k).head = _
  unfold commitShards
  have hk' : k ∈ rT pk K' cx := hk
  rw [if_pos hk']
  rfl

theorem inv3_reshard (h3 : Inv3 ss) (h : reshard pk K' cx ss = some ss') : Inv3 ss' := by
  obtain ⟨_, rfl⟩ := reshard_eq h
  intro k
  obtain ⟨h1, h2⟩ := h3 k
  by_cases hk : k ∈ rT pk K' cx
  · simp [commitShards, rSpine, applyPart, rRec, hk, h2]
  · simp [commitShards, rSpine, rRec, hk, h1, h2]

theorem inv4_reshard (hI : Inv ss) (h4 : Inv4 pk cx ss) (h : reshard pk K' cx ss = some ss') :
    Inv4 (setK pk cx.p K') cx ss' := by
  obtain ⟨hok, rfl⟩ := reshard_eq h
  obtain ⟨_, _, hK', hk⟩ := ok_parts hok
  refine ⟨?_, ?_⟩
  · show ss.1.used = ((List.range ((setK pk cx.p K').k cx.p)).map fun k =>
      (commitShards (rRec pk K' cx ss) (rT pk K' cx) ss.2 k).gross).sum
    rw [setK_k_self, gross_sum hK']
    show _ = ((List.range ss.1.k).map fun k => (ss.2 k).gross).sum
    rw [hk]; exact h4.1
  · show ss.1.budget = ((List.range ((setK pk cx.p K').k cx.p)).map fun k =>
      (commitShards (rRec pk K' cx ss) (rT pk K' cx) ss.2 k).mc).sum + ss.1.lc
    rw [setK_k_self, mc_sum hK']
    show _ = ((List.range ss.1.k).map fun k => (ss.2 k).mc).sum + ss.1.lc
    rw [hk]; exact h4.2

theorem chain_reshard (hc : chainsOk ss) (h : reshard pk K' cx ss = some ss') : chainsOk ss' := by
  obtain ⟨_, rfl⟩ := reshard_eq h
  show ((rRec pk K' cx ss :: ss.1.recs).reverse.map (·.n)) = List.range' 0 (ss.1.recs.length + 1)
  rw [List.reverse_cons, List.map_append, hc, List.range'_concat]
  simp [rRec]

theorem heads_reshard (h : reshard pk K' cx ss = some ss') : headsOk (setK pk cx.p K') cx ss' = true := by
  obtain ⟨_, rfl⟩ := reshard_eq h
  unfold headsOk
  rw [setK_k_self]
  refine List.all_eq_true.2 fun k hk => beq_iff_eq.2 ?_
  have hkT : k ∈ rT pk K' cx := List.mem_range.2 (Nat.lt_of_lt_of_le (List.mem_range.1 hk) (Nat.le_max_right _ _))
  show (commitShards (rRec pk K' cx ss) (rT pk K' cx) ss.2 k).head = (rSpine pk K' cx ss).heads k
  show _ = (if k ∈ rT pk K' cx then _ else _)
  unfold commitShards
  rw [if_pos hkT, if_pos hkT]
  rfl

theorem history_reshard (hc : chainsOk ss) (h3 : Inv3 ss) (h : reshard pk K' cx ss = some ss') :
    historyOk (setK pk cx.p K') cx (mergeHist (setK pk cx.p K') cx ss') = true :=
  (spine_chain_binds_iff (setK pk cx.p K') cx ss').1
    ⟨chain_reshard hc h, heads_reshard h, fun k _ => (inv3_reshard h3 h k).2⟩

theorem reachR_run : ∀ (rs : List Input) {ss : SS}, ReachR cx pk ss → ReachR cx pk (runS pk cx ss rs)
  | [], _, h => h
  | r :: rs, _, h => reachR_run rs (ReachR.step r h)

/-- Every store a step run reaches from a migrated store is `ReachR`. -/
theorem reachS_reachR (hp : packOk pk = true) (h : reachS pk cx ss) : ReachR cx pk ss := by
  obtain ⟨L, rs, rfl⟩ := h
  exact reachR_run rs (ReachR.init pk L hp)

theorem packOk_setK (hp : packOk pk = true) (hK : 0 < K') (p : PartId) : packOk (setK pk p K') = true := by
  simp only [packOk, setK, List.all_cons, Bool.and_eq_true, decide_eq_true_eq] at hp ⊢
  exact ⟨hK, hp⟩

theorem invK_reshard (h : reshard pk K' cx ss = some ss') : InvK (setK pk cx.p K') cx ss' := by
  have hk := reshard_k h
  obtain ⟨_, rfl⟩ := reshard_eq h
  exact ⟨by rw [setK_k_self]; exact hk, rRec_imgOk⟩

/-- A property of directory rows kept by every step: it holds of each new row (a `routeNew` row) and the old rows
    are kept. -/
theorem judgeRows_pres (pk : Pack) (cx : Ctx) (P : DirRow → Prop)
    (hn : ∀ r, P ⟨routeNew pk cx r, r.raw, r.gross, r.item⟩) :
    ∀ (d : Dir) (rs : List Row), (∀ c x, d c = some x → P x) →
      ∀ c x, (judgeRows pk cx d rs).1 c = some x → P x
  | d, [], h => h
  | d, r :: rs, h => by
    show ∀ c x, (judgeRows pk cx (judgeRow pk cx d r).1 rs).1 c = some x → P x
    apply judgeRows_pres pk cx P hn _ rs
    unfold judgeRow
    split
    · exact h
    · intro c x hx
      simp only [setDir] at hx
      split at hx
      · rw [← Option.some.inj hx]; exact hn r
      · exact h c x hx

theorem stepT_pres (pk : Pack) (cx : Ctx) (P : DirRow → Prop)
    (hn : ∀ r, P ⟨routeNew pk cx r, r.raw, r.gross, r.item⟩) (ss : SS) (inp : Input)
    (h : ∀ c x, ss.1.dir c = some x → P x) : ∀ c x, (stepT pk cx ss inp).1.dir c = some x → P x := by
  unfold stepT stepS
  split
  · exact judgeRows_pres pk cx P hn ss.1.dir inp.rows h
  · exact h

theorem homesLt_step (hK : 0 < pk.k cx.p) (inp : Input) (h : homesLt pk cx ss.1.dir) :
    homesLt pk cx (stepT pk cx ss inp).1.dir :=
  fun c x j hx hj =>
    stepT_pres pk cx (fun x => ∀ j, x.home = .shard j → j < pk.k cx.p)
      (fun r j hj => (route_sidx pk cx r j hj).2 hK) ss inp (fun c x hx j hj => h c x j hx hj) c x hx j hj

theorem homesLt_init (hK : 0 < pk.k cx.p) (L : Legacy) : homesLt pk cx (initS (pk.k cx.p) L).1.dir := by
  intro c x j hx hj
  change backfill L c = some x at hx
  unfold backfill at hx
  cases hc : L.cells c with
  | none => rw [hc] at hx; cases hx
  | some y =>
    rw [hc] at hx
    have e := Option.some.inj hx
    subst e
    have hj0 : Home.shard 0 = Home.shard j := hj
    rw [← Home.shard.inj hj0]; exact hK

theorem homesLt_reshard (hK : 0 < K') (h : reshard pk K' cx ss = some ss') :
    homesLt (setK pk cx.p K') cx ss'.1.dir := by
  intro c x j hx hj
  have hd : ss'.1.dir c = (ss.1.dir c).map (rehome (setK pk cx.p K') cx) := by
    obtain ⟨_, rfl⟩ := reshard_eq h
    rfl
  rw [hd] at hx
  cases hy : ss.1.dir c with
  | none => rw [hy] at hx; cases hx
  | some y =>
    rw [hy] at hx
    have e : rehome (setK pk cx.p K') cx y = x := Option.some.inj hx
    subst e
    cases hh : y.home with
    | spine =>
      have hj' : rh (tgt (setK pk cx.p K') cx y) y.home = .shard j := hj
      rw [hh] at hj'
      simp [rh] at hj'
    | shard m =>
      have hj' : rh (tgt (setK pk cx.p K') cx y) y.home = .shard j := hj
      rw [hh] at hj'
      have hj'' : Home.shard (tgt (setK pk cx.p K') cx y) = Home.shard j := hj'
      have hl := tgt_lt (pk := setK pk cx.p K') (cx := cx) (by rw [setK_k_self]; exact hK) y
      rw [← Home.shard.inj hj'']; exact hl

/-- M3: on every store reachable by steps and RESHARDs the invariants and the home bound hold, and the stored `K`
    is the pack's (`InvK`: `ss.1.k = pk.k cx.p`, and the newest image is bound). -/
theorem reachR_ok (h : ReachR cx pk ss) :
    packOk pk = true ∧ Inv ss ∧ Inv2 ss ∧ Inv3 ss ∧ Inv4 pk cx ss ∧ chainsOk ss ∧ homesLt pk cx ss.1.dir ∧
      InvK pk cx ss := by
  induction h with
  | init pk L hp =>
    exact ⟨hp, inv_init L, inv2_init L, inv3_init L, inv4_init pk cx L (Or.inl (k_pos pk cx.p hp)),
      chain_init L, homesLt_init (k_pos pk cx.p hp) L, invK_init pk cx L⟩
  | step inp _ ih =>
    obtain ⟨hp, hI, h2, h3, h4, hc, hB, hk⟩ := ih
    exact ⟨hp, inv_step _ _ _ inp hI, inv2_step _ _ _ inp h2, inv3_step _ _ _ inp h3,
      inv4_step _ _ _ inp hI h4, chain_step _ _ _ inp hc, homesLt_step (k_pos _ cx.p hp) inp hB,
      invK_step _ _ _ inp hk⟩
  | resh K' _ hr ih =>
    obtain ⟨hp, hI, h2, h3, h4, hc, hB, hk⟩ := ih
    obtain ⟨hok, _⟩ := reshard_eq hr
    obtain ⟨_, _, hK', _⟩ := ok_parts hok
    exact ⟨packOk_setK hp hK' cx.p, inv_reshard hI hB hr, inv2_reshard hr, inv3_reshard h3 hr,
      inv4_reshard hI h4 hr, chain_reshard hc hr, homesLt_reshard hK' hr, invK_reshard hr⟩

/-- A crash before any spine COMMIT leaves a `ReachR` store; recovery changes nothing in it. -/
theorem reachR_recover (h : ReachR cx pk ss) : recoverAll cx ss = ss := by
  have h2 := (reachR_ok h).2.2.1
  show (ss.1, fun k => recover cx ss.1 k (ss.2 k)) = (ss.1, ss.2)
  congr 1
  funext k
  unfold recover
  split
  · rfl
  · next R rs hR =>
    unfold replay
    rw [if_neg]
    rintro ⟨hk, _, hne, _⟩
    exact hne (h2 R rs hR k hk)

/-! ## (a) Every row present exactly once, at its new home -/

theorem reshard_dir (h : reshard pk K' cx ss = some ss') (c : Cell) :
    ss'.1.dir c = (ss.1.dir c).map (rehome (setK pk cx.p K') cx) := by
  obtain ⟨_, rfl⟩ := reshard_eq h
  rfl

/-- M2: after RESHARD every shard row sits at its own item's shard under the new pack. -/
theorem reshard_local (h : reshard pk K' cx ss = some ss') : locDir (setK pk cx.p K') cx ss'.1.dir := by
  intro c x j hx hj
  rw [reshard_dir h c] at hx
  cases hy : ss.1.dir c with
  | none => rw [hy] at hx; cases hx
  | some y =>
    rw [hy] at hx
    have e : rehome (setK pk cx.p K') cx y = x := Option.some.inj hx
    subst e
    cases hh : y.home with
    | spine =>
      have hj' : rh (tgt (setK pk cx.p K') cx y) y.home = .shard j := hj
      rw [hh] at hj'
      simp [rh] at hj'
    | shard m =>
      have hj' : rh (tgt (setK pk cx.p K') cx y) y.home = .shard j := hj
      rw [hh] at hj'
      have hj'' : Home.shard (tgt (setK pk cx.p K') cx y) = Home.shard j := hj'
      exact (Home.shard.inj hj'').symm

/-- Steps keep item locality: a new shard row is routed to its item's shard. -/
theorem locDir_step (inp : Input) (h : locDir pk cx ss.1.dir) : locDir pk cx (stepT pk cx ss inp).1.dir :=
  fun c x j hx hj =>
    stepT_pres pk cx (fun x => ∀ j, x.home = .shard j → j = sidx pk cx x.item)
      (fun r j hj => (route_sidx pk cx r j hj).1.symm) ss inp (fun c x hx j hj => h c x j hx hj) c x hx j hj

/-- A row charged at old shard `k < K` is, after RESHARD, at its `tgt < K'` with the same charge, and nowhere
    else. -/
theorem reshard_row (hI : Inv ss) (hB : homesLt pk cx ss.1.dir) (h : reshard pk K' cx ss = some ss') (c : Cell)
    (k : Nat) (hk : k < pk.k cx.p) (hpos : 0 < (ss.2 k).chg c) :
    ∃ x, ss.1.dir c = some x ∧ tgt (setK pk cx.p K') cx x < K' ∧
      (ss'.2 (tgt (setK pk cx.p K') cx x)).chg c = (ss.2 k).chg c ∧
      ∀ j, j ≠ tgt (setK pk cx.p K') cx x → (ss'.2 j).chg c = 0 := by
  obtain ⟨hok, e⟩ := reshard_eq h
  obtain ⟨_, _, hK', hkk⟩ := ok_parts hok
  obtain ⟨x, hx, hh⟩ := (hI c).2 k hpos
  have hK2 : 0 < (setK pk cx.p K').k cx.p := by rw [setK_k_self]; exact hK'
  have ht := tgt_lt hK2 x
  rw [setK_k_self] at ht
  have hnd : rdir (setK pk cx.p K') cx ss.1.dir c = some (rehome (setK pk cx.p K') cx x) := by
    simp [rdir, hx]
  have hhome : (rehome (setK pk cx.p K') cx x).home = .shard (tgt (setK pk cx.p K') cx x) := by
    simp [rehome, rh, hh]
  have hmerge : (merge pk cx ss).chg c = (ss.2 k).chg c := merge_at hI c x hx k hh (by rw [hkk]; exact hk)
  subst e
  refine ⟨x, hx, ht, ?_, fun j hj => ?_⟩
  · show (commitShards (rRec pk K' cx ss) (rT pk K' cx) ss.2 _).chg c = _
    rw [new_chg (mem_rT ht)]
    simp [restrict, hnd, hhome, hmerge]
  · show (commitShards (rRec pk K' cx ss) (rT pk K' cx) ss.2 j).chg c = 0
    by_cases hj' : j ∈ rT pk K' cx
    · rw [new_chg hj']; simp [restrict, hnd, hhome, Ne.symm hj]
    · unfold commitShards; rw [if_neg hj']
      have : ¬ j < max (pk.k cx.p) K' := fun hh => hj' (List.mem_range.2 hh)
      exact high_zero hI hB j (by omega) c

/-- No row appears from nowhere: a charge at new shard `j` sits at the row's `tgt` and came from an old shard. -/
theorem reshard_row_src (hI : Inv ss) (hB : homesLt pk cx ss.1.dir) (h : reshard pk K' cx ss = some ss')
    (c : Cell) (j : Nat) (hpos : 0 < (ss'.2 j).chg c) :
    ∃ x, ss.1.dir c = some x ∧ j = tgt (setK pk cx.p K') cx x ∧
      ∃ k < pk.k cx.p, (ss.2 k).chg c = (ss'.2 j).chg c := by
  obtain ⟨hok, e⟩ := reshard_eq h
  obtain ⟨_, _, hK', hkk⟩ := ok_parts hok
  subst e
  change 0 < (commitShards (rRec pk K' cx ss) (rT pk K' cx) ss.2 j).chg c at hpos
  have hj : j ∈ rT pk K' cx := Classical.byContradiction fun hj' => by
    unfold commitShards at hpos; rw [if_neg hj'] at hpos
    have : ¬ j < max (pk.k cx.p) K' := fun hh => hj' (List.mem_range.2 hh)
    have := high_zero hI hB j (by omega) c
    omega
  rw [new_chg hj] at hpos
  obtain ⟨x', hx', hhj⟩ := restrict_pos hpos
  have hM : 0 < (merge pk cx ss).chg c := Nat.lt_of_lt_of_le hpos restrict_le
  have hex : ∃ k0 ∈ List.range ss.1.k, (ss.2 k0).chg c ≠ 0 :=
    Classical.byContradiction fun hcon => by
      have : (merge pk cx ss).chg c = 0 :=
        sum_zeroN (fun k => (ss.2 k).chg c) _ fun k hk => Classical.byContradiction fun hh => hcon ⟨k, hk, hh⟩
      omega
  obtain ⟨k0, hk0, hne⟩ := hex
  obtain ⟨x, hx, hh⟩ := (hI c).2 k0 (Nat.pos_of_ne_zero hne)
  have hmerge : (merge pk cx ss).chg c = (ss.2 k0).chg c := merge_at hI c x hx k0 hh (List.mem_range.1 hk0)
  have hnd : rdir (setK pk cx.p K') cx ss.1.dir c = some (rehome (setK pk cx.p K') cx x) := by
    simp [rdir, hx]
  rw [hnd] at hx'
  have hx2 : rehome (setK pk cx.p K') cx x = x' := Option.some.inj hx'
  have hhome : (rehome (setK pk cx.p K') cx x).home = .shard (tgt (setK pk cx.p K') cx x) := by
    simp [rehome, rh, hh]
  have hhome2 : (rehome (setK pk cx.p K') cx x).home = .shard j := by rw [hx2]; exact hhj
  have hjt := Home.shard.inj (hhome2.symm.trans hhome)
  refine ⟨x, hx, hjt, k0, ?_, ?_⟩
  · have := List.mem_range.1 hk0; omega
  · show _ = (commitShards (rRec pk K' cx ss) (rT pk K' cx) ss.2 j).chg c
    rw [new_chg hj]
    simp [restrict, hnd, hhome2, hmerge]

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

theorem nrow_rehome (x : DirRow) : nrow (rehome pk cx x) = nrow x := by
  have : ∀ (t : Nat) (h : Home), cls (rh t h) = cls h := by intro t h; cases h <;> rfl
  simp only [nrow, rehome, this]

theorem ndir_rdir (d : Dir) : ndir (rdir pk cx d) = ndir d := by
  funext c
  rcases h : d c with _ | x
  · simp [ndir, rdir, h]
  · simp [ndir, rdir, h, nrow_rehome]

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

theorem norm_reshard (hI : Inv ss) (hK' : 0 < K') :
    norm (merge (setK pk cx.p K') cx (rSpine pk K' cx ss, commitShards (rRec pk K' cx ss) (rT pk K' cx) ss.2))
      = norm (merge pk cx ss) := by
  rw [merge_reshard hI hK']
  simp only [norm, ndir_rdir] <;> rfl

theorem invK_of_ok (hok : reshardOk pk K' cx ss = true) : InvK pk cx ss := by
  obtain ⟨hq, _, _, hk⟩ := ok_parts hok
  simp only [quiet, Bool.and_eq_true] at hq
  have hl := hq.2
  unfold lastOk at hl
  simp only [Bool.and_eq_true] at hl
  exact ⟨hk, hl.2⟩

/-- What the three run lemmas need: invariants of the new store, the old store's `InvK`, and equal norms. -/
theorem reshard_pre (hI : Inv ss) (hB : homesLt pk cx ss.1.dir) (h3 : Inv3 ss)
    (h : reshard pk K' cx ss = some ss') :
    Inv ss' ∧ Inv3 ss' ∧ InvK (setK pk cx.p K') cx ss' ∧ InvK pk cx ss ∧
      norm (merge (setK pk cx.p K') cx ss') = norm (merge pk cx ss) ∧
      packOk (setK pk cx.p K') = packOk pk := by
  obtain ⟨hok, e⟩ := reshard_eq h
  obtain ⟨_, hp, hK', _⟩ := ok_parts hok
  refine ⟨inv_reshard hI hB h, inv3_reshard h3 h, invK_reshard h, invK_of_ok hok, ?_, ?_⟩
  · rw [e]; exact norm_reshard hI hK'
  · rw [hp, packOk_setK hp hK']

/-- Lifts `merge_run`: the resharded store runs as the single store on the merged view with the rehomed directory. -/
theorem reshard_merge_run (hI : Inv ss) (hB : homesLt pk cx ss.1.dir) (h3 : Inv3 ss)
    (h : reshard pk K' cx ss = some ss') (rs : List Input) :
    merge (setK pk cx.p K') cx (runS (setK pk cx.p K') cx ss' rs)
      = runSingle (setK pk cx.p K') cx { merge pk cx ss with dir := rdir (setK pk cx.p K') cx ss.1.dir } rs := by
  obtain ⟨hI', h3', hK'', _⟩ := reshard_pre hI hB h3 h
  obtain ⟨hok, e⟩ := reshard_eq h
  obtain ⟨_, _, hK', _⟩ := ok_parts hok
  rw [merge_run (setK pk cx.p K') cx ss' rs hI' h3' hK'', e, merge_reshard hI hK']

/-- Lifts `whole_run` and `merge_run`: after RESHARD the store's merged view equals, up to the shard index of
    directory homes, the un-resharded single-store and whole-file runs (verdicts, dir, clock, every total). -/
theorem reshard_whole_run (hLoc : Local cx) (hI : Inv ss) (hB : homesLt pk cx ss.1.dir) (h3 : Inv3 ss)
    (h : reshard pk K' cx ss = some ss') (rs : List Input) :
    norm (merge (setK pk cx.p K') cx (runS (setK pk cx.p K') cx ss' rs)) = norm (runWhole pk cx (merge pk cx ss) rs) ∧
      norm (merge (setK pk cx.p K') cx (runS (setK pk cx.p K') cx ss' rs))
        = norm (runSingle pk cx (merge pk cx ss) rs) := by
  obtain ⟨hI', h3', hK'', hKss, hs, hp⟩ := reshard_pre hI hB h3 h
  have hw : norm (merge (setK pk cx.p K') cx (runS (setK pk cx.p K') cx ss' rs)) =
      norm (runWhole pk cx (merge pk cx ss) rs) := by
    rw [whole_run (setK pk cx.p K') cx hLoc ss' rs hI' h3' hK'']
    exact (runW_sim (setK pk cx.p K') pk cx hp rs hs).1
  refine ⟨hw, hw.trans ?_⟩
  rw [← whole_run pk cx hLoc ss rs hI h3 hKss, merge_run pk cx ss rs hI h3 hKss]

/-- Lifts `rcpts_run`: per-row receipts after RESHARD are the un-resharded store's and the whole-file run's. -/
theorem reshard_rcpts_run (hLoc : Local cx) (hI : Inv ss) (hB : homesLt pk cx ss.1.dir) (h3 : Inv3 ss)
    (h : reshard pk K' cx ss = some ss') (rs : List Input) :
    rcptsS (setK pk cx.p K') cx ss' rs = rcptsW pk cx (merge pk cx ss) rs ∧
      rcptsS (setK pk cx.p K') cx ss' rs = rcptsS pk cx ss rs := by
  obtain ⟨hI', h3', hK'', hKss, hs, hp⟩ := reshard_pre hI hB h3 h
  have h1 : rcptsS (setK pk cx.p K') cx ss' rs = rcptsW pk cx (merge pk cx ss) rs :=
    (rcpts_run (setK pk cx.p K') cx hLoc ss' rs hI' h3' hK'').trans
      (runW_sim (setK pk cx.p K') pk cx hp rs hs).2
  exact ⟨h1, h1.trans (rcpts_run pk cx hLoc ss rs hI h3 hKss).symm⟩

/-! ## Witnesses (kernel `decide`) -/

def cxW : Ctx :=
  { p := 0, hsh := fun _ _ => 1, lean := fun rs => rs.map fun _ => true, hs := fun d _ _ _ => d + 1,
    advances := fun d _ _ _ => Nat.succ_ne_self d, hi := fun d _ _ => d + 1, advancesI := fun d _ _ => Nat.succ_ne_self d }

def LW : Legacy :=
  { cells := fun _ => some (5, 10), item := fun _ => some "i", t := 0, used := 10, budget := 3, lc := 0,
    spineRows := [], chg := fun _ => 1, gross := 10, mc := 3, head := 0, chg_le := fun _ => Nat.le_refl 1,
    chg_cell := fun _ _ => by simp, used_eq := rfl, budget_eq := rfl }

/-- K = 1 to K = 2: the one charged row moves from shard 0 to shard 1 (`1 % 2`), with its directory home. -/
example : (reshard ⟨[]⟩ 2 cxW (initS 1 LW)).map
    (fun ss => ((ss.2 1).chg "a", (ss.2 0).chg "a", (ss.1.dir "a").map (·.home))) = some (1, 0, some (.shard 1)) := by
  decide

/-- H1, the review's scenario and its mirror: a crash after the RESHARD spine COMMIT with shard 1 only, shard 0
    only, or no shard committed; after recovery "a" is charged once, at shard 1, and the merged charge is 1. -/
example : [[1], [0], []].map (fun C =>
      let ss := recoverAll cxW (afterReshard ⟨[]⟩ 2 cxW (initS 1 LW) C)
      ((ss.2 0).chg "a", (ss.2 1).chg "a", (merge ⟨[(0, 2)]⟩ cxW ss).chg "a"))
    = [(0, 1, 1), (0, 1, 1), (0, 1, 1)] := by
  decide

/-- Before recovery, shard 0 uncommitted: a later RESHARD and a step are both refused. -/
example : (reshard ⟨[(0, 2)]⟩ 3 cxW (afterReshard ⟨[]⟩ 2 cxW (initS 1 LW) [1])).isNone = true ∧
    (stepS ⟨[(0, 2)]⟩ cxW (afterReshard ⟨[]⟩ 2 cxW (initS 1 LW) [1]) ⟨0, []⟩).isNone = true := by
  decide

/-- K = 2 to K = 1 with retired shard 1 uncommitted: a step and a RESHARD to K = 1 are refused before recovery and
    accepted after it. -/
example : let ss := afterReshard ⟨[(0, 2)]⟩ 1 cxW (initS 2 LW) [0]
    ((stepS ⟨[(0, 1), (0, 2)]⟩ cxW ss ⟨0, []⟩).isNone && (reshard ⟨[(0, 1), (0, 2)]⟩ 1 cxW ss).isNone &&
      (stepS ⟨[(0, 1), (0, 2)]⟩ cxW (recoverAll cxW ss) ⟨0, []⟩).isSome &&
      (reshard ⟨[(0, 1), (0, 2)]⟩ 1 cxW (recoverAll cxW ss)).isSome) = true := by
  decide

/-- `K' = 0` is refused. -/
example : (reshard ⟨[]⟩ 0 cxW (initS 1 LW)).isNone = true := by
  decide

/-- HIGH-1, the review's scenario: after RESHARD K = 1 to K = 2, the unsaved pack (K = 1) can neither RESHARD
    back to K = 1 nor step; the saved pack steps. -/
example : (reshard ⟨[]⟩ 2 cxW (initS 1 LW)).map (fun ss =>
      ((reshard ⟨[]⟩ 1 cxW ss).isNone, (stepS ⟨[]⟩ cxW ss ⟨0, []⟩).isNone, (stepS ⟨[(0, 2)]⟩ cxW ss ⟨0, []⟩).isSome))
    = some (true, true, true) := by
  decide

/-- The r2 stale-merge scenario: after RESHARD K = 1 to K = 2, `merge` under the old pack (K = 1) still reads the
    charge at shard 1; summing the pack's `K`, as `merge` did before, reads 0. -/
example : (reshard ⟨[]⟩ 2 cxW (initS 1 LW)).map (fun ss =>
      ((merge ⟨[]⟩ cxW ss).chg "a", ((List.range (Pack.k ⟨[]⟩ cxW.p)).map fun k => (ss.2 k).chg "a").sum))
    = some (1, 0) := by
  decide

/-- After RESHARD K = 1 to K = 2, a pack with K = 2 saves and the old pack (K = 1) is refused. -/
example : (reshard ⟨[]⟩ 2 cxW (initS 1 LW)).map (fun ss =>
      (packSaveOk ⟨[(0, 2)]⟩ cxW ss, packSaveOk ⟨[]⟩ cxW ss)) = some (true, false) := by
  decide

end BlindLedger.Financial.Reshard
