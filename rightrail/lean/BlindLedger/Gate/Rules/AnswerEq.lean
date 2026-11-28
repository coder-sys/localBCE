import BlindLedger.Gate.Rules.Run
import BlindLedger.Gate.Rules.FastEq

namespace BlindLedger.Gate.Rules.Run

open BlindLedger.Gate.Rules

/-! The engine's exact-duplicate answer and approval reading against their specifications.

    `decideBatchX_run`: the vector runner's batch (`commit`: `Fast.Ix.runIn`, then `answering` over the released set)
    is `ExactDuplicate.decideBatchX` at the payments `answering` decides as contested.
    `answering_pays`: for any rows reading that returns a decided line's exact key's released rows in set order or
    none, the answered set and the leaf's reading are `ExactDuplicate.answered` at those payments.  `answering_eq`:
    when every such key is read (none past the worker's `capN` postings), the answered set is
    `ExactDuplicate.answered` at the sender's contested payments, less a payment with an already decided line and one
    whose earlier list cannot be written, and the earlier list written is the Spec's (`answering_earlierBody`).  `unread_contested`, `answering_unread`: a payment with a held line under a
    key that cannot be read is decided contested (never answered, leaf and waiting lines as before) and is held by the
    rules with no approval and no release.  `Flat.answer_eq` and `Flat.answer_cap` state both for the worker's reading.
    `isCause_of_decode`, `isCause_of_bypass`, `admit_kinds`: the kind-byte pick and `admit`'s reading of approvals,
    with every approval past the first `maxBypasses` refused. -/

/-- The reasons `answering` reads. -/
private abbrev dupR (d : Decision) : Bool :=
  d.reasons.contains .FFS_DUPLICATE_LINE || d.reasons.contains .CAP_MEMBER_MONTH_DUPLICATE

private theorem any_congr_of {α : Type} {L : List α} {f g : α → Bool} (h : ∀ x ∈ L, f x = g x) :
    L.any f = L.any g := by
  induction L with
  | nil => rfl
  | cons a L ih => simp only [List.any_cons, h a (by simp), ih fun x hx => h x (by simp [hx])]

private theorem filterMap_congr_of {α β : Type} {L : List α} {f g : α → Option β} (h : ∀ x ∈ L, f x = g x) :
    L.filterMap f = L.filterMap g := by
  induction L with
  | nil => rfl
  | cons a L ih => rw [List.filterMap_cons, List.filterMap_cons, h a (by simp), ih fun x hx => h x (by simp [hx])]

private theorem filter_contains {l : List Nat} {f : Nat → Bool} {a : Nat} (h : a ∈ l) :
    (l.filter f).contains a = f a := by
  cases hf : f a <;> simp [List.mem_filter, h, hf]

/-- A line's exact repeat lies under its exact key. -/
private theorem find_sameLine_key (L : List Line) (l : Line) :
    L.find? (sameLine · l) = (L.filter (exactKey · == exactKey l)).find? (sameLine · l) := by
  induction L with
  | nil => rfl
  | cons x L ih =>
    by_cases hs : sameLine x l = true
    · simp [hs, sameLine_exactKey hs]
    · by_cases he : exactKey x = exactKey l
      · simp [hs, he, ih]
      · simp [hs, he, ih]

private theorem find_rows {block : Key → List Line} {l : Line} :
    ∀ K : List Key, (∀ key ∈ K, ∀ x ∈ block key, exactKey x = key) → (K.flatMap block).find? (sameLine · l) =
      if exactKey l ∈ K then (block (exactKey l)).find? (sameLine · l) else none
  | [], _ => by simp
  | key :: K, hb => by
    rw [List.flatMap_cons, List.find?_append, find_rows K fun key' hk => hb key' (List.mem_cons_of_mem _ hk)]
    by_cases hk : key = exactKey l
    · subst hk
      cases (block (exactKey l)).find? (sameLine · l) <;> simp
    · have hn : (block key).find? (sameLine · l) = none := by
        rw [List.find?_eq_none]
        intro x hx hs
        exact hk ((hb key (by simp) x hx).symm.trans (sameLine_exactKey hs))
      simp [hn, Ne.symm hk]

private theorem rows_key {R : List Line} {rowsFor : Key → Option (List Line)} {ds : List Decision}
    (hrows : ∀ d ∈ ds, ∀ rs, rowsFor (exactKey d.line) = some rs → rs = R.filter (exactKey · == exactKey d.line)) :
    ∀ key ∈ ((ds.filter dupR).map (exactKey ·.line)).eraseDups, ∀ x ∈ (rowsFor key).getD [], exactKey x = key := by
  intro key hK x hx
  obtain ⟨d, hd, rfl⟩ := List.mem_map.mp (List.mem_eraseDups.mp hK)
  cases h : rowsFor (exactKey d.line) with
  | none => simp [h] at hx
  | some rs =>
    rw [h, Option.getD_some, hrows d (List.mem_filter.mp hd).1 rs h] at hx
    simpa using (List.mem_filter.mp hx).2

private theorem rows_contains {block : Key → List Line} {K : List Key}
    (hb : ∀ key ∈ K, ∀ x ∈ block key, exactKey x = key) {l : Line} (hK : exactKey l ∈ K) :
    (K.flatMap block).contains l = (block (exactKey l)).contains l := by
  apply Bool.eq_iff_iff.mpr
  rw [List.contains_iff_mem, List.contains_iff_mem, List.mem_flatMap]
  exact ⟨fun ⟨key, hk, hx⟩ => by rw [hb key hk l hx]; exact hx, fun hx => ⟨_, hK, hx⟩⟩

private theorem answering_released (c' : Ctx) (rowsFor : Key → Option (List Line)) (k : List Nat)
    (ds : List Decision) :
    releasedSet (answering c' rowsFor k ds).c =
      (((ds.filter dupR).map (exactKey ·.line)).eraseDups).flatMap fun key => (rowsFor key).getD [] :=
  List.flatMap_map _ _ _

/-- Over the rows `answering` reads, a held line's twin is the Spec's when its key is read, else none. -/
private theorem twin_answering {c c' : Ctx} {rowsFor : Key → Option (List Line)} {k : List Nat}
    {ds : List Decision} (hredo : c'.redo = c.redo)
    (hrows : ∀ d ∈ ds, ∀ rs, rowsFor (exactKey d.line) = some rs →
      rs = (releasedSet c).filter (exactKey · == exactKey d.line))
    {d : Decision} (hd : d ∈ ds) (hdup : dupR d = true) :
    twin (answering c' rowsFor k ds).c d.line = if (rowsFor (exactKey d.line)).isSome then twin c d.line else none := by
  have hb := rows_key hrows
  have hK : exactKey d.line ∈ ((ds.filter dupR).map (exactKey ·.line)).eraseDups :=
    List.mem_eraseDups.mpr (List.mem_map.mpr ⟨d, List.mem_filter.mpr ⟨hd, hdup⟩, rfl⟩)
  have hr : (answering c' rowsFor k ds).c.redo = c.redo := hredo
  unfold twin own
  rw [answering_released, find_rows _ hb, if_pos hK, rows_contains hb hK, hr]
  cases h : rowsFor (exactKey d.line) with
  | none => simp
  | some rs =>
    rw [hrows d hd rs h]
    simp only [Option.getD_some, Option.isSome_some, if_true]
    rw [← find_sameLine_key]
    have : ((releasedSet c).filter (exactKey · == exactKey d.line)).contains d.line =
        (releasedSet c).contains d.line := by
      apply Bool.eq_iff_iff.mpr
      rw [List.contains_iff_mem, List.contains_iff_mem, List.mem_filter]
      simp
    rw [this]

private theorem twin_none {c : Ctx} {b : List Line} {d : Decision} (hd : d ∈ decideAll c (seen0 c b) (order c b))
    (h : dupR d = false) : twin c d.line = none := by
  cases ht : twin c d.line with
  | none => rfl
  | some x =>
    exfalso
    have hr := twin_reason hd (by simp [ht])
    simp only [dupR, Bool.or_eq_false_iff] at h
    rcases hr with h1 | h1
    · exact absurd h1 (by simpa using h.1)
    · exact absurd h1 (by simpa using h.2)

private theorem dupR_of_twin {c : Ctx} {b : List Line} {d : Decision}
    (hd : d ∈ decideAll c (seen0 c b) (order c b)) (ht : (twin c d.line).isSome = true) : dupR d = true := by
  cases h : dupR d
  · rw [twin_none hd h] at ht; cases ht
  · rfl

/-- A payment with a held line under a key that cannot be read is decided as contested. -/
private theorem k_of_unread {c' : Ctx} {rowsFor : Key → Option (List Line)} {k : List Nat} {ds : List Decision}
    {d : Decision} (hd : d ∈ ds) (hdup : dupR d = true) (hs : rowsFor (exactKey d.line) = none) :
    (answering c' rowsFor k ds).k.contains d.line.pay = true := by
  have hK : exactKey d.line ∈ ((ds.filter dupR).map (exactKey ·.line)).eraseDups :=
    List.mem_eraseDups.mpr (List.mem_map.mpr ⟨d, List.mem_filter.mpr ⟨hd, hdup⟩, rfl⟩)
  have hp : d.line.pay ∈ ((ds.filter dupR).map (·.line.pay)).eraseDups :=
    List.mem_eraseDups.mpr (List.mem_map.mpr ⟨d, List.mem_filter.mpr ⟨hd, hdup⟩, rfl⟩)
  apply List.contains_iff_mem.mpr
  refine List.mem_append_right k (List.mem_filter.mpr ⟨hp, ?_⟩)
  simp only [Bool.or_eq_true]
  refine Or.inr (List.any_eq_true.mpr ⟨d, List.mem_filter.mpr ⟨hd, hdup⟩, ?_⟩)
  simp only [beq_self_eq_true, Bool.true_and]
  exact List.contains_iff_mem.mpr (List.mem_filterMap.mpr
    ⟨(exactKey d.line, rowsFor (exactKey d.line)), List.mem_map.mpr ⟨_, hK, rfl⟩, by simp [hs]⟩)

private theorem pays_contains (c' : Ctx) (rowsFor : Key → Option (List Line)) (k : List Nat) (ds : List Decision)
    (p : Nat) :
    (answering c' rowsFor k ds).pays.contains p =
      answered (answering c' rowsFor k ds).c (answering c' rowsFor k ds).k (ds.filter dupR) p := by
  show (Std.HashSet.ofList (((ds.filter dupR).map (·.line.pay)).eraseDups.filter
    (answered (answering c' rowsFor k ds).c (answering c' rowsFor k ds).k (ds.filter dupR)))).contains p = _
  rw [Std.HashSet.contains_ofList]
  cases ha : answered (answering c' rowsFor k ds).c (answering c' rowsFor k ds).k (ds.filter dupR) p
  · simp [List.mem_filter, ha]
  · have hp : p ∈ ((ds.filter dupR).map (·.line.pay)).eraseDups := by
      unfold answered at ha
      simp only [Bool.and_eq_true, List.any_eq_true, beq_iff_eq] at ha
      obtain ⟨-, d, hd, hp, -⟩ := ha
      exact List.mem_eraseDups.mpr (List.mem_map.mpr ⟨d, hd, hp⟩)
    rw [filter_contains hp, ha]

private theorem answered_answering {c c' : Ctx} {b : List Line} {rowsFor : Key → Option (List Line)}
    {k : List Nat} {ds : List Decision} (hds : ds = decideAll c (seen0 c b) (order c b))
    (hredo : c'.redo = c.redo)
    (hrows : ∀ d ∈ ds, ∀ rs, rowsFor (exactKey d.line) = some rs →
      rs = (releasedSet c).filter (exactKey · == exactKey d.line)) (p : Nat) :
    answered (answering c' rowsFor k ds).c (answering c' rowsFor k ds).k (ds.filter dupR) p =
      answered c (answering c' rowsFor k ds).k ds p := by
  subst hds
  unfold answered
  cases hk : (answering c' rowsFor k (decideAll c (seen0 c b) (order c b))).k.contains p
  · simp only [Bool.not_false, Bool.true_and]
    rw [List.any_filter]
    apply Bool.eq_iff_iff.mpr
    simp only [List.any_eq_true, Bool.and_eq_true, beq_iff_eq]
    constructor
    · rintro ⟨d, hd, hdup, hp, ht⟩
      rw [twin_answering hredo hrows hd hdup] at ht
      split at ht
      · exact ⟨d, hd, hp, ht⟩
      · cases ht
    · rintro ⟨d, hd, hp, ht⟩
      have hdup := dupR_of_twin hd ht
      refine ⟨d, hd, hdup, hp, ?_⟩
      rw [twin_answering hredo hrows hd hdup]
      cases hs : rowsFor (exactKey d.line) with
      | none =>
        have := k_of_unread (c' := c') (k := k) hd hdup hs
        rw [hp, hk] at this
        cases this
      | some rs => simpa using ht
  · simp

private theorem earlier_answering {c c' : Ctx} {b : List Line} {rowsFor : Key → Option (List Line)}
    {k : List Nat} {ds : List Decision} (hds : ds = decideAll c (seen0 c b) (order c b))
    (hredo : c'.redo = c.redo)
    (hrows : ∀ d ∈ ds, ∀ rs, rowsFor (exactKey d.line) = some rs →
      rs = (releasedSet c).filter (exactKey · == exactKey d.line)) (p : Nat)
    (hcut : ∀ d ∈ ds, d.line.pay = p → (rowsFor (exactKey d.line)).isSome = true) :
    earlier (answering c' rowsFor k ds).c (ds.filter dupR) p = earlier c ds p := by
  subst hds
  unfold earlier
  rw [List.filter_filter, List.filterMap_filter, List.filterMap_filter]
  apply filterMap_congr_of
  intro d hd
  by_cases hp : d.line.pay = p
  · cases hdu : dupR d
    · simp [hp, twin_none hd hdu]
    · simp [hp, twin_answering hredo hrows hd hdu, hcut d hd hp]
  · simp [hp]

private theorem decided_contains (ds : List Decision) (p : Nat) :
    (Std.HashSet.ofList ((ds.filter (·.reasons.contains .ALREADY_DECIDED)).map (·.line.pay))).contains p =
      ds.any fun d => d.line.pay == p && d.reasons.contains .ALREADY_DECIDED := by
  apply Bool.eq_iff_iff.mpr
  rw [Std.HashSet.contains_ofList, List.contains_iff_mem, List.any_eq_true]
  simp only [List.mem_map, List.mem_filter, Bool.and_eq_true, beq_iff_eq]
  constructor
  · rintro ⟨d, ⟨hd, ha⟩, rfl⟩; exact ⟨d, hd, rfl, ha⟩
  · rintro ⟨d, hd, rfl, ha⟩; exact ⟨d, ⟨hd, ha⟩, rfl⟩

private theorem k_contains {c' : Ctx} {rowsFor : Key → Option (List Line)} {k : List Nat} {ds : List Decision}
    {p : Nat} (hp : p ∈ ((ds.filter dupR).map (·.line.pay)).eraseDups) :
    (answering c' rowsFor k ds).k.contains p = (k.contains p ||
      ((ds.any fun d => d.line.pay == p && d.reasons.contains .ALREADY_DECIDED) ||
        (earlierBody (answering c' rowsFor k ds).c (ds.filter dupR) p).isNone ||
        (ds.filter dupR).any fun d => d.line.pay == p && (rowsFor (exactKey d.line)).isNone)) := by
  show (k ++ List.filter _ _).contains p = _
  rw [List.contains_append, filter_contains hp]
  dsimp only
  rw [decided_contains]
  congr 1
  congr 1
  apply any_congr_of
  intro d hd
  congr 1
  have hK : exactKey d.line ∈ ((ds.filter dupR).map (exactKey ·.line)).eraseDups :=
    List.mem_eraseDups.mpr (List.mem_map.mpr ⟨d, hd, rfl⟩)
  apply Bool.eq_iff_iff.mpr
  rw [List.contains_iff_mem]
  simp only [List.mem_filterMap, List.mem_map]
  constructor
  · rintro ⟨_, ⟨key, -, rfl⟩, hc⟩
    cases hr : rowsFor key with
    | none => simp [hr] at hc; subst hc; simp [hr]
    | some v => simp [hr] at hc
  · intro h
    exact ⟨_, ⟨exactKey d.line, hK, rfl⟩, by simp [h]⟩

/-- A line held for an exact repeat holds its payment: no bypass, cause release or lift reaches it and none of its
    lines is released. -/
theorem dup_held {c : Ctx} {b : List Line} {d : Decision} (hd : d ∈ decideAll c (seen0 c b) (order c b))
    (hr : Reason.FFS_DUPLICATE_LINE ∈ d.reasons ∨ Reason.CAP_MEMBER_MONTH_DUPLICATE ∈ d.reasons) :
    payOutcome c (decideAll c (seen0 c b) (order c b)) d.line.pay = .HOLD ∧
      bypassed c (decideAll c (seen0 c b) (order c b)) d.line.pay = false ∧
      limitedPay c (decideAll c (seen0 c b) (order c b)) d.line.pay = false ∧
      ∀ l ∈ releasedLines c (decideAll c (seen0 c b) (order c b)), l.pay ≠ d.line.pay := by
  obtain ⟨r, hr, hb, ho⟩ : ∃ r ∈ d.reasons, bypassable r = false ∧ d.outcome = .HOLD := by
    obtain ⟨pre, l, rfl⟩ := mem_decideAll hd
    rcases hr with hr | hr
    · exact ⟨_, hr, rfl, outcomeOf_certain hr rfl⟩
    · exact ⟨_, hr, rfl, outcomeOf_certain hr rfl⟩
  have hho : payOutcome c (decideAll c (seen0 c b) (order c b)) d.line.pay = .HOLD := by
    unfold payOutcome
    rw [if_pos]
    exact List.any_eq_true.mpr ⟨d, List.mem_filter.mpr ⟨hd, by simp⟩, by simp [ho]⟩
  have hlim : limitedPay c (decideAll c (seen0 c b) (order c b)) d.line.pay = false := by
    unfold limitedPay
    split
    · rfl
    · rename_i m hm
      cases hh : (!c.redo.contains d.line.pay && lifts m (decideAll c (seen0 c b) (order c b)) d.line.pay
          (payOutcome c (decideAll c (seen0 c b) (order c b)) d.line.pay))
      · rfl
      · exfalso
        have := (lifts_iff.mp ((Bool.and_eq_true _ _).mp hh).2).2.2 d hd rfl r hr
        rw [hb] at this
        cases this.1
  refine ⟨hho, never_bypassable hd hr hb, hlim, ?_⟩
  intro l hl hlp
  rcases fail_closed_unless_bypass c b l hl with h1 | ⟨m, -, -, hall⟩ | ⟨m, -, hall⟩
  · rw [hlp, hho] at h1
    cases h1
  · have := (hall d hd hlp.symm r hr).1
    rw [hb] at this
    cases this
  · have := (hall d hd hlp.symm r hr).1
    rw [hb] at this
    cases this

/-- The engine's answered payments are the Spec's at the payments `answering` decides as contested (`k`), for any
    reading that gives a key's rows of the released set in set order or none: the set holds a payment exactly when
    `ExactDuplicate.answered` does, and the leaf's reading over the rows read is the same. -/
theorem answering_pays {c c' : Ctx} {b : List Line} {rowsFor : Key → Option (List Line)} {k : List Nat}
    {ds : List Decision} (hds : ds = decideAll c (seen0 c b) (order c b)) (hredo : c'.redo = c.redo)
    (hrows : ∀ d ∈ ds, ∀ rs, rowsFor (exactKey d.line) = some rs →
      rs = (releasedSet c).filter (exactKey · == exactKey d.line)) (p : Nat) :
    (answering c' rowsFor k ds).pays.contains p = answered c (answering c' rowsFor k ds).k ds p ∧
      answered (answering c' rowsFor k ds).c (answering c' rowsFor k ds).k (answering c' rowsFor k ds).ds p =
        answered c (answering c' rowsFor k ds).k ds p :=
  ⟨(pays_contains c' rowsFor k ds p).trans (answered_answering hds hredo hrows p),
    answered_answering hds hredo hrows p⟩

/-- When every key is read (no key past the worker's `capN` postings), the engine answers a payment exactly when
    `ExactDuplicate.answered` does at the sender's contested payments `k`, unless a line of it is already decided or
    its earlier list cannot be written (`earlierBody`); those two are decided as contested. -/
theorem answering_eq {c c' : Ctx} {b : List Line} {rowsFor : Key → Option (List Line)} {k : List Nat}
    {ds : List Decision} (hds : ds = decideAll c (seen0 c b) (order c b)) (hredo : c'.redo = c.redo)
    (hrows : ∀ d ∈ ds, ∀ rs, rowsFor (exactKey d.line) = some rs →
      rs = (releasedSet c).filter (exactKey · == exactKey d.line))
    (hall : ∀ d ∈ ds, (rowsFor (exactKey d.line)).isSome = true) (p : Nat) :
    (answering c' rowsFor k ds).pays.contains p =
      (answered c k ds p && !(ds.any fun d => d.line.pay == p && d.reasons.contains .ALREADY_DECIDED) &&
        (earlierBody c ds p).isSome) := by
  rw [(answering_pays hds hredo hrows p).1]
  unfold answered
  cases hA : ds.any fun d => d.line.pay == p && (twin c d.line).isSome
  · simp
  · obtain ⟨d, hd, hdp⟩ := List.any_eq_true.mp hA
    simp only [Bool.and_eq_true, beq_iff_eq] at hdp
    have hdup := dupR_of_twin (hds ▸ hd) hdp.2
    have hps : p ∈ ((ds.filter dupR).map (·.line.pay)).eraseDups :=
      List.mem_eraseDups.mpr (List.mem_map.mpr ⟨d, List.mem_filter.mpr ⟨hd, hdup⟩, hdp.1⟩)
    have heb : earlierBody (answering c' rowsFor k ds).c (ds.filter dupR) p = earlierBody c ds p := by
      unfold earlierBody
      rw [earlier_answering hds hredo hrows p fun d hd _ => hall d hd]
    have hcut : ((ds.filter dupR).any fun d => d.line.pay == p && (rowsFor (exactKey d.line)).isNone) = false := by
      apply List.any_eq_false.mpr
      intro d hd
      cases h : rowsFor (exactKey d.line) with
      | none => have := hall d (List.mem_filter.mp hd).1; rw [h] at this; cases this
      | some _ => simp
    rw [k_contains hps, heb, hcut]
    cases k.contains p <;> cases ds.any (fun d => d.line.pay == p && d.reasons.contains .ALREADY_DECIDED) <;>
      cases earlierBody c ds p <;> rfl

/-- When every key is read, the earlier list the engine writes for a payment is the Spec's (`earlierBody`). -/
theorem answering_earlierBody {c c' : Ctx} {b : List Line} {rowsFor : Key → Option (List Line)} {k : List Nat}
    {ds : List Decision} (hds : ds = decideAll c (seen0 c b) (order c b)) (hredo : c'.redo = c.redo)
    (hrows : ∀ d ∈ ds, ∀ rs, rowsFor (exactKey d.line) = some rs →
      rs = (releasedSet c).filter (exactKey · == exactKey d.line))
    (hall : ∀ d ∈ ds, (rowsFor (exactKey d.line)).isSome = true) (p : Nat) :
    earlierBody (answering c' rowsFor k ds).c (answering c' rowsFor k ds).ds p = earlierBody c ds p := by
  have h : earlier (answering c' rowsFor k ds).c (answering c' rowsFor k ds).ds p = earlier c ds p :=
    earlier_answering hds hredo hrows p fun d hd _ => hall d hd
  unfold earlierBody
  rw [h]

/-- A payment with a held line under a key the engine cannot read in full (the worker's rows are none past `capN`
    postings) is decided as contested, whatever the decisions: it is never answered, and its leaf and its waiting
    lines are as before the amendment. -/
theorem unread_contested (c c' : Ctx) {rowsFor : Key → Option (List Line)} {k : List Nat} {ds : List Decision}
    {d : Decision} (hd : d ∈ ds)
    (hr : Reason.FFS_DUPLICATE_LINE ∈ d.reasons ∨ Reason.CAP_MEMBER_MONTH_DUPLICATE ∈ d.reasons)
    (hs : rowsFor (exactKey d.line) = none) :
    (answering c' rowsFor k ds).k.contains d.line.pay = true ∧
      (answering c' rowsFor k ds).pays.contains d.line.pay = false ∧
      answered c (answering c' rowsFor k ds).k ds d.line.pay = false ∧
      (∀ unf o, answerLeaf (answering c' rowsFor k ds).c (answering c' rowsFor k ds).k (answering c' rowsFor k ds).ds
        unf o d.line.pay = if unf d.line.pay then .HOLD else .ofOutcome o) ∧
      ∀ l : Line, l.pay = d.line.pay →
        (l ∈ unresolvedLinesX c (answering c' rowsFor k ds).k ds ↔ l ∈ unresolvedLines c ds) := by
  have hdup : dupR d = true := by rcases hr with h | h <;> simp [dupR, h]
  have hk := k_of_unread (c' := c') (k := k) hd hdup hs
  have hna : ∀ (c₀ : Ctx) (ds₀ : List Decision), answered c₀ (answering c' rowsFor k ds).k ds₀ d.line.pay = false :=
    fun _ _ => by unfold answered; rw [hk]; rfl
  exact ⟨hk, (pays_contains c' rowsFor k ds d.line.pay).trans (hna _ _), hna _ _,
    fun unf o => (contested_as_before hk unf o).1, (contested_as_before hk (fun _ => false) .HOLD).2⟩

/-- Over the Spec's decisions, such a payment is also held by the rules with no bypass, cause release or lift, and
    none of its lines is released. -/
theorem answering_unread {c c' : Ctx} {b : List Line} {rowsFor : Key → Option (List Line)} {k : List Nat}
    {d : Decision} (hd : d ∈ decideAll c (seen0 c b) (order c b))
    (hr : Reason.FFS_DUPLICATE_LINE ∈ d.reasons ∨ Reason.CAP_MEMBER_MONTH_DUPLICATE ∈ d.reasons)
    (hs : rowsFor (exactKey d.line) = none) :
    (answering c' rowsFor k (decideAll c (seen0 c b) (order c b))).pays.contains d.line.pay = false ∧
      payOutcome c (decideAll c (seen0 c b) (order c b)) d.line.pay = .HOLD ∧
      bypassed c (decideAll c (seen0 c b) (order c b)) d.line.pay = false ∧
      limitedPay c (decideAll c (seen0 c b) (order c b)) d.line.pay = false ∧
      ∀ l ∈ releasedLines c (decideAll c (seen0 c b) (order c b)), l.pay ≠ d.line.pay :=
  ⟨(unread_contested c c' (k := k) hd hr hs).2.1, dup_held hd hr⟩

private theorem run_eq {c : Ctx} {b : List Line} {K : List Nat} {pays : Nat → Bool}
    (hf : ∀ l : Line, pays l.pay = answered c K (decideAll c (seen0 c b) (order c b)) l.pay) :
    decideBatchX c K b = ⟨(decideBatch c b).decisions, (decideBatch c b).released,
      ⟨(decideBatch c b).unresolved.asOf,
        (decideBatch c b).unresolved.count - ((decideBatch c b).unresolved.entries.length - (unresolvedSet c).length -
          (((decideBatch c b).unresolved.entries.drop (unresolvedSet c).length).filter fun l => !pays l.pay).length),
        (decideBatch c b).unresolved.entries.take (unresolvedSet c).length ++
          ((decideBatch c b).unresolved.entries.drop (unresolvedSet c).length).filter fun l => !pays l.pay⟩⟩ := by
  have hF : (((decideBatch c b).unresolved.entries.drop (unresolvedSet c).length).filter fun l => !pays l.pay) =
      unresolvedLinesX c K (decideAll c (seen0 c b) (order c b)) := by
    show (((view c.today c.unresolvedPrior c.unresolved).entries ++
      unresolvedLines c (decideAll c (seen0 c b) (order c b))).drop
        (view c.today c.unresolvedPrior c.unresolved).entries.length).filter (fun l => !pays l.pay) = _
    rw [List.drop_left]
    exact List.filter_congr fun l _ => by rw [hf l]
  have hle : (unresolvedLinesX c K (decideAll c (seen0 c b) (order c b))).length ≤
      (unresolvedLines c (decideAll c (seen0 c b) (order c b))).length := List.length_filter_le _ _
  rw [hF]
  simp only [decideBatchX, decideBatch, advance, unresolvedSet, List.take_left, List.length_append,
    Result.mk.injEq, Snapshot.mk.injEq, true_and, and_true]
  omega

/-- The vector runner's batch (`commit`: `Fast.Ix.runIn`, then `answering` over the released set) is
    `ExactDuplicate.decideBatchX` at the payments `answering` decides as contested: the same decisions and released
    set, and the unresolved set less every answered payment's lines. -/
theorem decideBatchX_run (c : Ctx) (b : List Line) :
    let x := Fast.Ix.build c b
    let r := x.runIn [] b
    let ax := answering c (fun key => some ((releasedSet c).filter (exactKey · == key))) [] r.decisions
    let unrX := (r.unresolved.entries.drop x.unrN).filter fun l => !ax.pays.contains l.pay
    decideBatchX c ax.k b = ⟨r.decisions, r.released, ⟨r.unresolved.asOf,
      r.unresolved.count - (r.unresolved.entries.length - x.unrN - unrX.length),
      r.unresolved.entries.take x.unrN ++ unrX⟩⟩ := by
  have hr : (Fast.Ix.build c b).runIn [] b = decideBatch c b := Fast.decideBatchFIn_eq c [] b
  have hn : (Fast.Ix.build c b).unrN = (unresolvedSet c).length := Fast.run_unrN
  intro x r ax unrX
  simp only [x, r, ax, unrX, hr, hn]
  exact run_eq (K := (answering c (fun key => some ((releasedSet c).filter (exactKey · == key))) []
      (decideBatch c b).decisions).k)
    (pays := fun p => (answering c (fun key => some ((releasedSet c).filter (exactKey · == key))) []
      (decideBatch c b).decisions).pays.contains p)
    fun l => (answering_pays rfl rfl (fun _ _ _ h => (Option.some.inj h).symm) l.pay).1

/-- Bytes that decode as a cause record are read as one. -/
theorem isCause_of_decode {x : Bytes} {f : CauseRelease.Frame} (h : CauseRelease.decode x = some f) :
    isCause x = true := by
  obtain ⟨rest, hp, -⟩ := CauseRelease.decode_spec h
  rw [(CauseRelease.pDoc_inv hp).1, isCause, List.isPrefixOf_iff_prefix]
  simp only [CauseRelease.encDoc, List.append_assoc, List.prefix_append_right_inj, List.prefix_append]

/-- Bytes that decode as a grant or bypass are never read as a cause record. -/
theorem isCause_of_bypass {x : Bytes} {g : Authority.Frame} (h : Authority.decode x = some g) :
    isCause x = false := by
  obtain ⟨rest, hp⟩ := CauseRelease.authDecode_pDoc h
  apply Bool.eq_false_iff.mpr
  intro hc
  rw [(Authority.pDoc_inv hp).1, isCause, List.isPrefixOf_iff_prefix] at hc
  obtain ⟨⟨st, tn, nb, na, body⟩, sg⟩ := g
  cases body <;>
    simp [Authority.encDoc, Authority.kindByte, CauseRelease.kindByte, natBE, List.append_assoc] at hc

private theorem toOption_ite {ε α : Type} {p : Prop} [Decidable p] {e : ε} {r : Except ε α} {y : α}
    (h : (if p then Except.error e else r).toOption = some y) : r.toOption = some y := by
  split at h
  · cases h
  · exact h

private theorem fm_le {α β : Type} (f : α → Option β) (A B : List α) (hB : ∀ x ∈ B, f x = none) :
    ((A ++ B).filterMap f).length ≤ A.length := by
  rw [List.filterMap_append, List.filterMap_eq_nil_iff.mpr hB, List.append_nil]
  exact List.length_filterMap_le _ _

private theorem length_filter_split {α : Type} (f : α → Bool) (l : List α) :
    (l.filter f).length + (l.filter (!f ·)).length = l.length := by
  induction l with
  | nil => rfl
  | cons a l ih => cases h : f a <;> simp [h] <;> omega

/-- `admit`'s reading of a batch's approvals: of the first `maxBypasses`, those with the cause kind byte are cause
    records read by `CauseRelease.admit` and the rest bypasses read by `Authority.admitBypassR`; at most `maxBypasses`
    are admitted in all; each cause record past them is refused `RULES_CAUSE - TOO_MANY`. -/
theorem admit_kinds {verify : Bytes → Bytes → Bytes → Bool} {pin : Bytes} {rat : Keyset.Ratchet} {stored : Nat}
    {st : St} {a : Admitted} (h : admit verify pin rat stored st = .ok a) :
    ∃ e0 H, st.reqs[0]? = some e0 ∧
      a.causes = (((st.byps.take maxBypasses).filter isCause).map
        (CauseRelease.admit verify H e0.r.tenantId)).filterMap (·.toOption) ∧
      (∀ y ∈ a.byps, ∃ x ∈ (st.byps.take maxBypasses).filter (!isCause ·),
        Authority.admitBypassR verify H e0.r.tenantId x = .ok y) ∧
      a.byps.length + a.causes.length ≤ maxBypasses ∧
      ∃ pre, a.notes = pre ++ ((st.byps.drop maxBypasses).filter isCause).map fun _ => "RULES_CAUSE - TOO_MANY" := by
  obtain ⟨e0, hr⟩ : ∃ e0, st.reqs[0]? = some e0 := by
    cases hr : st.reqs[0]? with
    | none => simp [admit, hr] at h
    | some e0 => exact ⟨e0, rfl⟩
  obtain ⟨gx, hg⟩ : ∃ gx, st.grant = some gx := by
    cases hg : st.grant with
    | none => simp [admit, hr, hg] at h
    | some gx => exact ⟨gx, rfl⟩
  obtain ⟨ks, hk⟩ : ∃ ks, st.keyset = some ks := by
    cases hk : st.keyset with
    | none => simp [admit, hr, hg, hk] at h
    | some ks => exact ⟨ks, rfl⟩
  simp only [admit, hr, hg, hk] at h
  obtain ⟨⟨H, rat'⟩, hH⟩ : ∃ q, SnapshotV2.admitBatchHead verify pin st.today rat ks st.ksteps = some q := by
    cases hq : SnapshotV2.admitBatchHead verify pin st.today rat ks st.ksteps with
    | none => simp [hq] at h
    | some q => exact ⟨q, rfl⟩
  simp only [hH] at h
  split at h
  · cases h
  obtain ⟨fl, hfl⟩ : ∃ fl, effFloor stored st.floorIn = some fl := by
    cases hq : effFloor stored st.floorIn with
    | none => simp [hq] at h
    | some fl => exact ⟨fl, rfl⟩
  simp only [hfl] at h
  cases hG : Authority.admitGrant verify H e0.r.tenantId fl gx with
  | error w => simp [hG] at h
  | ok g =>
    simp only [hG, Except.ok.injEq] at h
    subst h
    refine ⟨e0, H, hr, rfl, ?_, ?_, _, rfl⟩
    · intro y hy
      obtain ⟨e, he, hey⟩ := List.mem_filterMap.mp hy
      rcases List.mem_append.mp he with he | he
      · obtain ⟨q, hq, rfl⟩ := List.mem_map.mp he
        obtain ⟨x, hx, rfl⟩ := List.mem_map.mp hq
        refine ⟨x, hx, ?_⟩
        cases hb : Authority.admitBypassR verify H e0.r.tenantId x with
        | error w => simp [hb, Except.toOption] at hey
        | ok b0 =>
          simp only [hb] at hey
          have := toOption_ite (toOption_ite (toOption_ite (toOption_ite hey)))
          simp only [Except.toOption, Option.some.injEq] at this
          subst this
          rfl
      · obtain ⟨x, -, rfl⟩ := List.mem_map.mp he
        simp [Except.toOption] at hey
    · refine Nat.le_trans (Nat.add_le_add (fm_le _ _ _ ?_) (List.length_filterMap_le _ _)) ?_
      · intro e he
        obtain ⟨x, -, rfl⟩ := List.mem_map.mp he
        rfl
      · have h1 := length_filter_split isCause (st.byps.take maxBypasses)
        have h2 := List.length_take_le maxBypasses st.byps
        simp only [List.length_map]
        omega
