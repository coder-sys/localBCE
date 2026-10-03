import BlindLedger.Gate.Rules.Shards
import BlindLedger.Gate.Rules.FastEq
import BlindLedger.Gate.AnchorTheorems

/-! Multi-shard runtime (rrb/designs/multi-shard-runtime-v1.md §5): the id registry protocol as reserve,
    seal and settle events of any shards in any order, and its safety; the `Fast` twins proved equal.
    A crash is an absent event; a restored registry is refused at boot (design §4), so a run never steps
    back.  Synthetic, nonpayment, activation=false. -/

namespace BlindLedger.Gate.Rules

/-! ### The answers -/

theorem contains_filter_map {α : Type} (p : α → Bool) (f : α → Nat) (os : List α) (i : Nat) :
    ((os.filter p).map f).contains i = os.any fun o => f o == i && p o := by
  apply Bool.eq_iff_iff.mpr
  rw [List.contains_iff_mem, List.any_eq_true]
  constructor
  · intro h
    obtain ⟨o, ho, rfl⟩ := List.mem_map.mp h
    obtain ⟨ho, hp⟩ := List.mem_filter.mp ho
    exact ⟨o, ho, by simp [hp]⟩
  · rintro ⟨o, ho, h⟩
    simp only [Bool.and_eq_true, beq_iff_eq] at h
    exact List.mem_map.mpr ⟨o, List.mem_filter.mpr ⟨ho, h.2⟩, h.1⟩

/-- If every answer naming shard `k` is true, a line `k` decides that the registry does not give `k` is
    recorded elsewhere: it is in `foreignOf`, so it is `ALREADY_DECIDED` (`fresh_owner`). -/
theorem ready_hf {reg : Nat → Option Nat} {k : Nat} {os : List Owner} {b : List Line}
    (hos : ∀ o ∈ os, o.shard = k → reg o.id = some k) :
    ∀ l ∈ ready k os b, reg l.id ≠ some k → l.id ∈ foreignOf k os (ready k os b) := by
  intro l hl hne
  have hb : l ∈ b := (List.mem_filter.mp hl).1
  have hw : (!b.any fun m => m.pay == l.pay && !okId k os m.id) = true := (List.mem_filter.mp hl).2
  have hok : okId k os l.id = true := by
    cases h : okId k os l.id
    · have : (b.any fun m => m.pay == l.pay && !okId k os m.id) = true :=
        List.any_eq_true.mpr ⟨l, hb, by simp [h]⟩
      rw [this] at hw
      cases hw
    · rfl
  obtain ⟨o, ho, he⟩ := List.any_eq_true.mp hok
  simp only [Bool.and_eq_true, Bool.or_eq_true, beq_iff_eq] at he
  by_cases hk : o.shard = k
  · exact (hne (by rw [← he.1]; exact hos o ho hk)).elim
  · have hs : o.settled = true := he.2.resolve_left hk
    refine List.mem_filter.mpr ⟨List.mem_map.mpr ⟨l, hl, rfl⟩, List.any_eq_true.mpr ⟨o, ho, ?_⟩⟩
    simp [he.1, hk, hs]

/-- A freed id is in neither of the shard's sealed sets. -/
theorem settleFree_out {rel unr : List Line} {p : List Nat} {i : Nat}
    (h : i ∈ settleFree rel unr p) : ∀ x ∈ rel ++ unr, x.id ≠ i := by
  intro x hx he
  have h2 : (!((rel ++ unr).map (·.id)).contains i) = true := (List.mem_filter.mp h).2
  rw [List.contains_iff_mem.mpr (List.mem_map.mpr ⟨x, hx, he⟩)] at h2
  cases h2

/-! ### The protocol model -/

/-- The registry (`reg i`: the shard holding id `i`), each shard's sealed sets, and every ALLOW line sealed
    with its shard. -/
structure World where
  reg : Nat → Option Nat
  rel : Nat → List Line
  unr : Nat → List Line
  paid : List (Nat × Line)

inductive Ev
  | reserve (k : Nat) (ids : List Nat)
  | sealB (k : Nat) (c : Ctx) (os : List Owner) (b : List Line)
  | settle (k : Nat) (pending : List Nat)

/-- `reserve` gives each free id to `k`; `settle` frees those of `k`'s ids its sets do not hold; `seal`
    decides `decideReg` on `k`'s own sets, refused unless every answer naming `k` is the registry's. -/
def World.step (w : World) : Ev → Option World
  | .reserve k ids => some { w with reg := fun i => if w.reg i = none ∧ i ∈ ids then some k else w.reg i }
  | .settle k p => some { w with
      reg := fun i => if i ∈ settleFree (w.rel k) (w.unr k) p ∧ w.reg i = some k then none else w.reg i }
  | .sealB k c os b =>
    if releasedSet c = w.rel k ∧ unresolvedSet c = w.unr k ∧ ∀ o ∈ os, o.shard = k → w.reg o.id = some k then
      let r := decideReg c k os b
      some { w with rel := fun j => if j = k then r.released.entries else w.rel j,
                    unr := fun j => if j = k then r.unresolved.entries else w.unr j,
                    paid := w.paid ++ ((r.decisions.filter fun d =>
                      payOutcome c r.decisions d.line.pay == .ALLOW).map fun d => (k, d.line)) }
    else none

def World.run (w : World) : List Ev → Option World
  | [] => some w
  | e :: es => (w.step e).bind (·.run es)

/-- Every set row is its shard's in the registry, released ids are unique per shard, and every ALLOW line
    sealed is in its shard's released set. -/
def World.Ok (w : World) : Prop :=
  (∀ k, ∀ x ∈ w.rel k ++ w.unr k, w.reg x.id = some k) ∧ (∀ k, ((w.rel k).map (·.id)).Nodup) ∧
    ∀ p ∈ w.paid, p.2 ∈ w.rel p.1

theorem World.step_ok {w w' : World} {e : Ev} (h : w.Ok) (hs : w.step e = some w') : w'.Ok := by
  obtain ⟨ho, hn, hp⟩ := h
  cases e with
  | reserve k ids =>
    simp only [World.step, Option.some.injEq] at hs
    subst hs
    refine ⟨fun j x hx => ?_, hn, hp⟩
    have hj := ho j x hx
    show (if w.reg x.id = none ∧ x.id ∈ ids then some k else w.reg x.id) = some j
    rw [if_neg (by rw [hj]; simp), hj]
  | settle k p =>
    simp only [World.step, Option.some.injEq] at hs
    subst hs
    refine ⟨fun j x hx => ?_, hn, hp⟩
    have hj := ho j x hx
    show (if x.id ∈ settleFree (w.rel k) (w.unr k) p ∧ w.reg x.id = some k then none else w.reg x.id) = some j
    rw [if_neg, hj]
    rintro ⟨h1, h2⟩
    rw [hj] at h2
    obtain rfl := Option.some.inj h2
    exact settleFree_out h1 x hx rfl
  | sealB k c os b =>
    simp only [World.step] at hs
    split at hs
    · rename_i hg
      obtain ⟨hrel, hunr, hos⟩ := hg
      simp only [Option.some.injEq] at hs
      subst hs
      have hf := ready_hf (b := b) hos
      refine ⟨fun j x hx => ?_, fun j => ?_, fun p hp' => ?_⟩
      · show w.reg x.id = some j
        by_cases hj : j = k
        · have hx : x ∈ (decideReg c k os b).released.entries ++ (decideReg c k os b).unresolved.entries := by
            simpa only [if_pos hj] using hx
          rw [hj]
          rcases List.mem_append.mp hx with hx | hx
          · exact (released_owner hf hx).elim
              (fun h => ho k x (List.mem_append_left _ (by rw [← hrel]; exact h))) id
          · exact (unresolved_owner hf hx).elim
              (fun h => ho k x (List.mem_append_right _ (by rw [← hunr]; exact h))) id
        · have hx : x ∈ w.rel j ++ w.unr j := by simpa only [if_neg hj] using hx
          exact ho j x hx
      · show ((if j = k then (decideReg c k os b).released.entries else w.rel j).map (·.id)).Nodup
        by_cases hj : j = k
        · rw [if_pos hj]
          exact released_nodup (by rw [hrel]; exact hn k)
        · rw [if_neg hj]
          exact hn j
      · show p.2 ∈ (if p.1 = k then (decideReg c k os b).released.entries else w.rel p.1)
        have hp' : p ∈ w.paid ++ (((decideReg c k os b).decisions.filter fun d =>
            payOutcome c (decideReg c k os b).decisions d.line.pay == .ALLOW).map fun d => (k, d.line)) := hp'
        rcases List.mem_append.mp hp' with hp' | hp'
        · by_cases hj : p.1 = k
          · rw [if_pos hj]
            exact row_next (Or.inl (by rw [hrel, ← hj]; exact hp p hp'))
          · rw [if_neg hj]
            exact hp p hp'
        · obtain ⟨d, hd, rfl⟩ := List.mem_map.mp hp'
          obtain ⟨hd, ha⟩ := List.mem_filter.mp hd
          rw [if_pos rfl]
          exact row_next (Or.inr ⟨d, hd, rfl, beq_iff_eq.mp ha⟩)
    · cases hs

theorem World.run_ok {w w' : World} {es : List Ev} (h : w.Ok) (hr : w.run es = some w') : w'.Ok := by
  induction es generalizing w with
  | nil =>
    simp only [World.run, Option.some.injEq] at hr
    exact hr ▸ h
  | cons e es ih =>
    simp only [World.run] at hr
    cases hs : w.step e with
    | none => rw [hs] at hr; cases hr
    | some w1 => rw [hs] at hr; exact ih (World.step_ok h hs) hr

/-- Headline (runtime): over any interleaving of reserve, seal and settle events of any shards, two ALLOW
    lines sealed anywhere with one id are one line of one shard. -/
theorem run_one_payment_per_line {w w' : World} {es : List Ev} (h : w.Ok) (hr : w.run es = some w')
    {k k' : Nat} {x y : Line} (hx : (k, x) ∈ w'.paid) (hy : (k', y) ∈ w'.paid) (hid : x.id = y.id) :
    k = k' ∧ x = y := by
  obtain ⟨ho, hn, hp⟩ := World.run_ok h hr
  have hx' : x ∈ w'.rel k := hp _ hx
  have hy' : y ∈ w'.rel k' := hp _ hy
  have h1 := ho k x (List.mem_append_left _ hx')
  have h2 := ho k' y (List.mem_append_left _ hy')
  rw [hid, h2] at h1
  obtain rfl := Option.some.inj h1
  exact ⟨rfl, map_nodup_inj (hn k') hx' hy' hid⟩

/-- No line id is in two shards' sets, after any run. -/
theorem run_no_id_two_shards {w w' : World} {es : List Ev} (h : w.Ok) (hr : w.run es = some w')
    {k k' : Nat} {x y : Line} (hx : x ∈ w'.rel k ++ w'.unr k) (hy : y ∈ w'.rel k' ++ w'.unr k')
    (hid : x.id = y.id) : k = k' := by
  obtain ⟨ho, -, -⟩ := World.run_ok h hr
  have h1 := ho k x hx
  rw [hid, ho k' y hy] at h1
  exact (Option.some.inj h1).symm

/-! ### The registry's rows and answers: no wrongful refusal -/

/-- A registry row `(kind, id, shard)`: 0 RESERVE, 1 FREE, 2 SETTLE, 3 BOOT (`Gate.idRegStep`). -/
abbrev Row := Nat × Nat × Nat

/-- The holder of id `i` after rows `l` (newest first), and whether a SETTLE row of the holder is newer
    (the id is recorded); `none`: free (§2 derived state). -/
def holder (i : Nat) : List Row → Option (Nat × Bool)
  | [] => none
  | (kd, j, k) :: l =>
    if kd = 2 then (holder i l).map fun p => (p.1, p.2 || p.1 == k)
    else if j = i ∧ kd = 0 then some (k, false)
    else if j = i ∧ kd = 1 then none
    else holder i l

/-- The registry's answer for id `i`: the raw `Owner` (§2). -/
def answer (l : List Row) (i : Nat) : Option Owner := (holder i l).map fun p => ⟨i, p.1, p.2⟩

/-- Reserve: in request order, each id free at its turn gets a RESERVE row of `k`. -/
def reserveRows (k : Nat) (l : List Row) (ids : List Nat) : List Row :=
  ids.foldl (fun l j => if holder j l = none then (0, j, k) :: l else l) l

/-- Settle: a FREE row for each id of `free` in flight of `k`, then a SETTLE row of `k` unless no id of
    `k` is left in flight. -/
def settleRows (k : Nat) (l : List Row) (free : List Nat) : List Row :=
  let l := free.foldl (fun l j => if holder j l = some (k, false) then (1, j, k) :: l else l) l
  if l.any fun r => holder r.2.1 l = some (k, false) then (2, 0, k) :: l else l

/-- The rows the registry appends for an event; a settle frees what `settleFree` gives. -/
def World.rows (w : World) (l : List Row) : Ev → List Row
  | .reserve k ids => reserveRows k l ids
  | .settle k p => settleRows k l (settleFree (w.rel k) (w.unr k) p)
  | .sealB _ _ _ _ => l

def World.runL (w : World) (l : List Row) : List Ev → Option (World × List Row)
  | [] => some (w, l)
  | e :: es => (w.step e).bind fun w' => w'.runL (w.rows l e) es

/-- Every settle names each id its shard has in flight (`pendingOf_fair`).  Needed: after `reserve 1 [5]`,
    `settle 1 []`, id 5 is recorded for shard 1 in no set of shard 1, and shard 0 answers it
    `ALREADY_DECIDED`. -/
def World.Fair (w : World) (l : List Row) : List Ev → Prop
  | [] => True
  | e :: es => (∀ k p, e = .settle k p → ∀ i, holder i l = some (k, false) → i ∈ p) ∧
      ∀ w', w.step e = some w' → w'.Fair (w.rows l e) es

/-- The rows give the world's `reg`, and a recorded id is in its holder's sets. -/
def World.Inv (w : World) (l : List Row) : Prop :=
  (∀ i, (holder i l).map (·.1) = w.reg i) ∧
    ∀ i k, holder i l = some (k, true) → ∃ x ∈ w.rel k ++ w.unr k, x.id = i

example : World.Inv ⟨fun _ => none, fun _ => [], fun _ => [], []⟩ [] :=
  ⟨fun _ => rfl, fun _ _ h => by simp [holder] at h⟩

theorem holder_reserveRows (i k : Nat) (ids : List Nat) : ∀ l : List Row, holder i (reserveRows k l ids) =
    if holder i l = none ∧ i ∈ ids then some (k, false) else holder i l := by
  induction ids with
  | nil => intro l; simp [reserveRows]
  | cons j ids ih =>
    intro l
    have h1 : holder i (if holder j l = none then (0, j, k) :: l else l) =
        if j = i ∧ holder i l = none then some (k, false) else holder i l := by
      by_cases hj : holder j l = none <;> by_cases hji : j = i
      · subst hji; simp [holder, hj]
      · simp [holder, hj, hji]
      · subst hji; simp [hj]
      · simp [hj, hji]
    simp only [reserveRows, List.foldl_cons] at ih ⊢
    rw [ih, h1]
    by_cases hji : j = i
    · subst hji; by_cases hn : holder j l = none <;> simp [hn]
    · simp [hji, Ne.symm hji]

theorem holder_freeRows (i k : Nat) (fr : List Nat) : ∀ l : List Row,
    holder i (fr.foldl (fun l j => if holder j l = some (k, false) then (1, j, k) :: l else l) l) =
      if i ∈ fr ∧ holder i l = some (k, false) then none else holder i l := by
  induction fr with
  | nil => intro l; simp
  | cons j fr ih =>
    intro l
    have h1 : holder i (if holder j l = some (k, false) then (1, j, k) :: l else l) =
        if j = i ∧ holder i l = some (k, false) then none else holder i l := by
      by_cases hj : holder j l = some (k, false) <;> by_cases hji : j = i
      · subst hji; simp [holder, hj]
      · simp [holder, hj, hji]
      · subst hji; simp [hj]
      · simp [hj, hji]
    simp only [List.foldl_cons]
    rw [ih, h1]
    by_cases hji : j = i
    · subst hji; by_cases hn : holder j l = some (k, false) <;> simp [hn]
    · simp [hji, Ne.symm hji]

theorem holder_mem (i : Nat) (l : List Row) : ∀ x, holder i l = some x → ∃ r ∈ l, r.2.1 = i := by
  induction l with
  | nil => intro x h; simp [holder] at h
  | cons r l ih =>
    obtain ⟨kd, j, k⟩ := r
    intro x h
    by_cases hj : j = i
    · exact ⟨_, by simp, hj⟩
    · cases hy : holder i l with
      | none => simp [holder, hj, hy] at h
      | some y =>
        obtain ⟨r, hr, e⟩ := ih y hy
        exact ⟨r, List.mem_cons_of_mem _ hr, e⟩

theorem holder_settleRows (i k : Nat) (l : List Row) (fr : List Nat) :
    holder i (settleRows k l fr) = (if i ∈ fr ∧ holder i l = some (k, false) then none else holder i l).map
      fun p => (p.1, p.2 || p.1 == k) := by
  rw [← holder_freeRows i k fr l]
  simp only [settleRows]
  generalize fr.foldl (fun l j => if holder j l = some (k, false) then (1, j, k) :: l else l) l = l1
  split
  · simp [holder]
  · rename_i hn
    cases h : holder i l1 with
    | none => rfl
    | some p =>
      obtain ⟨h1, b⟩ := p
      by_cases hk : h1 = k
      · subst hk
        cases b
        · obtain ⟨r, hr, e⟩ := holder_mem i l1 _ h
          exact (hn (List.any_eq_true.mpr ⟨r, hr, by simp [e, h]⟩)).elim
        · simp
      · simp [hk]

theorem World.step_inv {w w' : World} {l : List Row} {e : Ev} (h : w.Inv l)
    (hf : ∀ k p, e = .settle k p → ∀ i, holder i l = some (k, false) → i ∈ p) (hs : w.step e = some w') :
    w'.Inv (w.rows l e) := by
  obtain ⟨hr, hx⟩ := h
  cases e with
  | reserve k ids =>
    simp only [World.step, Option.some.injEq] at hs
    subst hs
    refine ⟨fun i => ?_, fun i j h' => ?_⟩
    · show (holder i (reserveRows k l ids)).map (·.1) = if w.reg i = none ∧ i ∈ ids then some k else w.reg i
      rw [holder_reserveRows, ← hr i]
      by_cases hn : holder i l = none <;> by_cases hi : i ∈ ids <;> simp [hn, hi]
    · rw [World.rows, holder_reserveRows] at h'
      split at h'
      · simp at h'
      · exact hx i j h'
  | settle k p =>
    simp only [World.step, Option.some.injEq] at hs
    subst hs
    have key : ∀ i, i ∈ settleFree (w.rel k) (w.unr k) p → (w.reg i = some k ↔ holder i l = some (k, false)) := by
      intro i hi
      refine ⟨fun hk => ?_, fun hk => by rw [← hr i, hk]; rfl⟩
      rw [← hr i] at hk
      cases hh : holder i l with
      | none => rw [hh] at hk; cases hk
      | some q =>
        obtain ⟨q1, b⟩ := q
        rw [hh] at hk
        obtain rfl : q1 = k := Option.some.inj hk
        cases b
        · rfl
        · obtain ⟨x, hxm, hxi⟩ := hx i q1 hh
          exact (settleFree_out hi x hxm hxi).elim
    refine ⟨fun i => ?_, fun i j h' => ?_⟩
    · show (holder i (settleRows k l (settleFree (w.rel k) (w.unr k) p))).map (·.1) =
        if i ∈ settleFree (w.rel k) (w.unr k) p ∧ w.reg i = some k then none else w.reg i
      rw [holder_settleRows, Option.map_map]
      by_cases hc : i ∈ settleFree (w.rel k) (w.unr k) p ∧ holder i l = some (k, false)
      · rw [if_pos hc, if_pos ⟨hc.1, (key i hc.1).mpr hc.2⟩]; rfl
      · rw [if_neg hc, if_neg (fun h => hc ⟨h.1, (key i h.1).mp h.2⟩), ← hr i]
        cases holder i l <;> rfl
    · rw [World.rows, holder_settleRows] at h'
      obtain ⟨q, hq, he⟩ := Option.map_eq_some_iff.mp h'
      split at hq
      · cases hq
      · rename_i hc
        obtain ⟨q1, b⟩ := q
        simp only [Prod.mk.injEq] at he
        obtain rfl := he.1
        cases b
        · obtain rfl : q1 = k := by simpa using he.2
          have hp := hf _ _ rfl i hq
          cases hm : ((w.rel q1 ++ w.unr q1).map (·.id)).contains i
          · exact (hc ⟨List.mem_filter.mpr ⟨hp, by simp [hm]⟩, hq⟩).elim
          · obtain ⟨x, hxm, hxi⟩ := List.mem_map.mp (List.contains_iff_mem.mp hm)
            exact ⟨x, hxm, hxi⟩
        · exact hx i q1 hq
  | sealB k c os b =>
    simp only [World.step] at hs
    split at hs
    · rename_i hg
      obtain ⟨hrel, hunr, -⟩ := hg
      simp only [Option.some.injEq] at hs
      subst hs
      refine ⟨hr, fun i j h' => ?_⟩
      obtain ⟨x, hxm, hxi⟩ := hx i j h'
      refine ⟨x, ?_, hxi⟩
      show x ∈ (if j = k then (decideReg c k os b).released.entries else w.rel j) ++
        (if j = k then (decideReg c k os b).unresolved.entries else w.unr j)
      by_cases hj : j = k
      · rw [if_pos hj, if_pos hj]
        subst hj
        rcases List.mem_append.mp hxm with h | h
        · exact List.mem_append_left _ (row_next (Or.inl (by rw [hrel]; exact h)))
        · exact List.mem_append_right _ (List.mem_append_left _ (by rw [hunr]; exact h) :
            x ∈ unresolvedSet c ++ unresolvedLines c (decideReg c j os b).decisions)
      · rw [if_neg hj, if_neg hj]; exact hxm
    · cases hs

theorem World.runL_inv {w w' : World} {l l' : List Row} {es : List Ev} (h : w.Inv l) (hf : w.Fair l es)
    (hr : w.runL l es = some (w', l')) : w'.Inv l' := by
  induction es generalizing w l with
  | nil =>
    simp only [World.runL, Option.some.injEq, Prod.mk.injEq] at hr
    obtain ⟨rfl, rfl⟩ := hr
    exact h
  | cons e es ih =>
    rw [World.Fair] at hf
    simp only [World.runL] at hr
    cases hs : w.step e with
    | none => rw [hs] at hr; cases hr
    | some w1 => rw [hs] at hr; exact ih (World.step_inv h hf.1 hs) (hf.2 w1 hs) hr

/-- The logged run is the run: `run_ok` and the headlines above hold of it. -/
theorem World.runL_run {w w' : World} {l l' : List Row} {es : List Ev} (hr : w.runL l es = some (w', l')) :
    w.run es = some w' := by
  induction es generalizing w l with
  | nil =>
    simp only [World.runL, Option.some.injEq, Prod.mk.injEq] at hr
    rw [← hr.1]; rfl
  | cons e es ih =>
    simp only [World.runL] at hr
    cases hs : w.step e with
    | none => rw [hs] at hr; cases hr
    | some w1 => rw [hs] at hr; simp only [World.run, hs, Option.bind_some]; exact ih hr

/-- A settle naming `pendingOf` of an answer that covers each id its shard has in flight is fair. -/
theorem pendingOf_fair {l : List Row} {k : Nat} {os : List Owner} (hos : ∀ o ∈ os, answer l o.id = some o)
    (hc : ∀ i, holder i l = some (k, false) → ∃ o ∈ os, o.id = i) :
    ∀ i, holder i l = some (k, false) → i ∈ pendingOf k os := by
  intro i hi
  obtain ⟨o, ho, rfl⟩ := hc i hi
  have e := hos o ho
  rw [answer, hi] at e
  have e1 : k = o.shard := congrArg Owner.shard (Option.some.inj e)
  have e2 : false = o.settled := congrArg Owner.settled (Option.some.inj e)
  refine List.mem_map.mpr ⟨o, List.mem_filter.mpr ⟨ho, ?_⟩, rfl⟩
  simp [← e1, ← e2]

/-- The registry head after rows `l` (newest first) from `g`. -/
def chainHead (H : List UInt8 → List UInt8) (g : List UInt8) : List Row → List UInt8
  | [] => g
  | (kd, i, s) :: l => idRegStep H (chainHead H g l) kd i s

/-- A row whose fields fit their widths in `idRegStep`. -/
def rowFits (r : Row) : Prop := r.1 < 256 ^ 1 ∧ r.2.1 < 256 ^ 129 ∧ r.2.2 < 256 ^ 4

/-- With an injective `H`, the row count and head fix the rows. -/
theorem chainHead_inj {H : List UInt8 → List UInt8} (hH : ∀ a b, H a = H b → a = b) (g : List UInt8) :
    ∀ l l' : List Row, l.length = l'.length → (∀ r ∈ l ++ l', rowFits r) →
      chainHead H g l = chainHead H g l' → l = l'
  | [], [], _, _, _ => rfl
  | [], _ :: _, hn, _, _ => by simp at hn
  | _ :: _, [], hn, _, _ => by simp at hn
  | (kd, i, s) :: l, (kd', i', s') :: l', hn, hf, he => by
    simp only [chainHead, idRegStep] at he
    have hlen : ∀ w v v', (Gate.natBE w v).length = (Gate.natBE w v').length := by simp [Gate.natBE]
    have bk : ∀ w v v', v < 256 ^ w → v' < 256 ^ w → Gate.natBE w v = Gate.natBE w v' → v = v' :=
      fun w v v' hv hv' e => (Gate.beNat_natBE w v hv).symm.trans ((congrArg Gate.beNat e).trans
        (Gate.beNat_natBE w v' hv'))
    obtain ⟨e, e3⟩ := List.append_inj' (hH _ _ he) (hlen 4 s s')
    obtain ⟨e, e2⟩ := List.append_inj' e (hlen 129 i i')
    obtain ⟨e, e1⟩ := List.append_inj' e (hlen 1 kd kd')
    have f : rowFits (kd, i, s) := hf _ (by simp)
    have f' : rowFits (kd', i', s') := hf _ (by simp)
    have := chainHead_inj hH g l l' (by simpa using hn) (fun r hr => hf r (by
      rcases List.mem_append.mp hr with h | h
      · exact List.mem_append_left _ (List.mem_cons_of_mem _ h)
      · exact List.mem_append_right _ (List.mem_cons_of_mem _ h))) (List.append_cancel_left e)
    rw [bk 1 kd kd' f.1 f'.1 e1, bk 129 i i' f.2.1 f'.2.1 e2, bk 4 s s' f.2.2 f'.2.2 e3, this]

/-- Accuracy headline (no wrongful refusal): over a fair run of any interleaving from rows that give the
    world, if the registry's rows have the run's count and head (its chain matches), an id its answers
    give another shard as recorded (`taken`, so `ALREADY_DECIDED`) is held by that shard, whose sets hold
    a line with that id. -/
theorem run_taken_recorded {H : List UInt8 → List UInt8} (hH : ∀ a b, H a = H b → a = b) {g : List UInt8}
    {w w' : World} {l l' reg : List Row} {es : List Ev} (h : w.Inv l) (hf : w.Fair l es)
    (hr : w.runL l es = some (w', l')) (hfit : ∀ r ∈ reg ++ l', rowFits r) (hn : reg.length = l'.length)
    (hh : chainHead H g reg = chainHead H g l') {k i : Nat} {os : List Owner}
    (hos : ∀ o ∈ os, answer reg o.id = some o) (ht : taken k os i = true) :
    ∃ k', k' ≠ k ∧ w'.reg i = some k' ∧ ∃ x ∈ w'.rel k' ++ w'.unr k', x.id = i := by
  have e := chainHead_inj hH g reg l' hn hfit hh
  have hos : ∀ o ∈ os, answer l' o.id = some o := e ▸ hos
  obtain ⟨hreg, hx⟩ := World.runL_inv h hf hr
  obtain ⟨o, ho, he⟩ := List.any_eq_true.mp ht
  simp only [Bool.and_eq_true, beq_iff_eq, bne_iff_ne, ne_eq] at he
  obtain ⟨hoi, hok, hos'⟩ := he
  obtain ⟨⟨q1, q2⟩, hq, hqo⟩ := Option.map_eq_some_iff.mp (hos o ho)
  have h1 : q1 = o.shard := congrArg Owner.shard hqo
  have h2 : q2 = o.settled := congrArg Owner.settled hqo
  have hq' : holder i l' = some (o.shard, true) := by rw [← hoi, hq, h1, h2, hos']
  refine ⟨o.shard, hok, ?_, hx i o.shard hq'⟩
  rw [← hreg i, hq']
  rfl

/-! ### The twins -/

namespace Fast

open Std (HashSet)

theorem readyF_eq (k : Nat) (os : List Owner) (b : List Line) : readyF k os b = ready k os b := by
  simp only [readyF, ready]
  congr 1
  funext l
  simp only [HashSet.contains_ofList, contains_filter_map, okId]

theorem foreignOfF_eq (k : Nat) (os : List Owner) (b : List Line) : foreignOfF k os b = foreignOf k os b := by
  simp only [foreignOfF, foreignOf]
  congr 1
  funext i
  simp only [HashSet.contains_ofList, contains_filter_map, taken]

theorem settleFreeF_eq (rel unr : List Line) (p : List Nat) : settleFreeF rel unr p = settleFree rel unr p := by
  simp only [settleFreeF, settleFree, HashSet.contains_ofList]

theorem decideRegF_eq (c : Ctx) (k : Nat) (os : List Owner) (b : List Line) :
    decideRegF c k os b = decideReg c k os b := by
  simp only [decideRegF, decideReg, readyF_eq, foreignOfF_eq, decideBatchFIn_eq]

end Fast

/-! Axiom pins. -/
/-- info: 'BlindLedger.Gate.Rules.run_one_payment_per_line' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms run_one_payment_per_line
/-- info: 'BlindLedger.Gate.Rules.run_no_id_two_shards' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms run_no_id_two_shards
/-- info: 'BlindLedger.Gate.Rules.Fast.decideRegF_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Fast.decideRegF_eq
/-- info: 'BlindLedger.Gate.Rules.Fast.settleFreeF_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Fast.settleFreeF_eq
/-- info: 'BlindLedger.Gate.Rules.run_taken_recorded' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms run_taken_recorded
/-- info: 'BlindLedger.Gate.Rules.World.runL_run' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms World.runL_run
/-- info: 'BlindLedger.Gate.Rules.pendingOf_fair' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms pendingOf_fair

end BlindLedger.Gate.Rules
