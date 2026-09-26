import BlindLedger.Gate.Rules.Spec

namespace BlindLedger.Gate.Rules

/-! What `decideBatch` guarantees.  `Fact` restates each rule over the pinned
    data in plain propositions; the batch theorems speak about the canonical
    batch, where line `i` is checked against `seenAt c b i`: the keys of the
    released set and those claimed by the lines before it.  The axiom pins at
    the end show no theorem here rests on `sorryAx` or `Lean.ofReduceBool`. -/

/-- A snapshot the rules may read: see `usable`. -/
def Usable {α : Type} (today maxAge : Nat) (ok : α → Bool) (o : Option (Snapshot α)) : Prop :=
  ∃ s, o = some s ∧ validDate today = true ∧ validDate s.asOf = true ∧ s.asOf ≤ today ∧
    dayNum today ≤ dayNum s.asOf + maxAge ∧ s.entries.length = s.count ∧ 0 < s.count ∧
    ∀ x ∈ s.entries, ok x = true

def Whole (o : Option (Snapshot Line)) : Prop := ∃ s, o = some s ∧ s.entries.length = s.count

def Fact (c : Ctx) (seen : List Key) (l : Line) : Reason → Prop
  | .CAP_MEMBER_MONTH_DUPLICATE => l.flow = .CAP_820 ∧ (key l ∈ seen ∨ overlap c l = true)
  | .FFS_DUPLICATE_LINE => l.flow ≠ .CAP_820 ∧ key l ∈ seen
  | .FFS_NEAR_DUPLICATE => l.flow ≠ .CAP_820 ∧ nearKey l ∈ seen ∧ key l ∉ seen
  | .MEMBER_DECEASED => ∃ d ∈ entries c.dmf, d.id = l.member ∧ d.date < l.date
  | .MEMBER_NOT_ENROLLED => ¬∃ s ∈ entries c.enrollment, s.member = l.member ∧ s.start ≤ l.date ∧
      l.date ≤ s.stop ∧ (l.flow ≠ .CAP_820 ∨ s.plan = l.payee)
  | .PROVIDER_DECEASED => ∃ d ∈ entries c.providerDeaths,
      (d.id = l.payee ∨ d.id = l.rendering) ∧ d.date < l.date
  | .PROVIDER_EXCLUDED => ∃ e ∈ entries c.exclusions,
      (e.id = l.payee ∨ e.id = l.rendering) ∧ e.start ≤ l.date ∧ l.date ≤ e.stop
  | .SERVICE_DATE_FUTURE => c.today < l.date
  | .SERVICE_DATE_INVALID => validDate l.date = false
  | .STALE_DMF => ¬Usable c.today 90 okDeath c.dmf
  | .STALE_ENROLLMENT => ¬Usable c.today 7 okSpan c.enrollment
  | .STALE_EXCLUSION => ¬Usable c.today 31 okExclusion c.exclusions
  | .STALE_PROVIDER_DEATH => ¬Usable c.today 90 okDeath c.providerDeaths
  | .STALE_RELEASED => ¬Whole c.released

def seenAt (c : Ctx) (b : List Line) (i : Nat) : List Key :=
  ((canonical b).take i).reverse.flatMap (claim c) ++ (entries c.released).flatMap keys

/-! ## One line -/

theorem usable_iff {α : Type} {t m : Nat} {ok : α → Bool} {o : Option (Snapshot α)} :
    usable t m ok o = true ↔ Usable t m ok o := by
  cases o <;> simp [usable, Usable, List.all_eq_true, and_assoc]

theorem whole_iff {o : Option (Snapshot Line)} : whole o = true ↔ Whole o := by
  cases o <;> simp [whole, Whole]

theorem fires_iff {c seen l} (r : Reason) : fires c seen l r = true ↔ Fact c seen l r := by
  cases r <;> simp [fires, Fact, enrolled, covers, party, isCap, ← usable_iff, ← whole_iff, and_assoc]

theorem mem_all (r : Reason) : r ∈ reasons := by cases r <;> simp [reasons]

theorem decideLine_line {c seen l} : (decideLine c seen l).line = l := rfl

theorem decideLine_outcome {c seen l} :
    (decideLine c seen l).outcome = outcomeOf (decideLine c seen l).reasons := rfl

theorem mem_decideLine {c seen l r} : r ∈ (decideLine c seen l).reasons ↔ Fact c seen l r := by
  simp [decideLine, List.mem_filter, mem_all, fires_iff]

theorem outcomeOf_allow {rs : List Reason} : outcomeOf rs = .ALLOW ↔ rs = [] := by
  cases rs with
  | nil => simp [outcomeOf]
  | cons a t =>
    rw [outcomeOf, if_neg (by simp)]
    exact ⟨(fun h => by split at h <;> cases h), (fun h => by cases h)⟩

theorem outcomeOf_review {rs : List Reason} {r : Reason} (h : r ∈ rs) (hs : review r = true) :
    outcomeOf rs = .HUMAN_REVIEW := by
  cases rs with
  | nil => cases h
  | cons a t => rw [outcomeOf, if_neg (by simp), if_pos (List.any_eq_true.mpr ⟨r, h, hs⟩)]

theorem line_complete {c seen l r} (h : Fact c seen l r) : (decideLine c seen l).outcome ≠ .ALLOW := by
  intro ha
  rw [decideLine_outcome, outcomeOf_allow] at ha
  have hr := mem_decideLine.mpr h
  rw [ha] at hr
  simp at hr

theorem line_review {c seen l r} (h : Fact c seen l r) (hr : review r = true) :
    (decideLine c seen l).outcome = .HUMAN_REVIEW := by
  rw [decideLine_outcome]
  exact outcomeOf_review (mem_decideLine.mpr h) hr

theorem fires_blocks {c seen l r} (hf : fires c seen l r = true)
    (h : (decideLine c seen l).outcome = .ALLOW) : False :=
  line_complete ((fires_iff r).mp hf) h

/-- An ALLOWed line is enrolled, so it claims its keys, and none of them was seen. -/
theorem allow_facts {c seen l} (h : (decideLine c seen l).outcome = .ALLOW) :
    claim c l = keys l ∧ ∀ k ∈ keys l, k ∉ seen := by
  refine ⟨?_, fun k hk hs => ?_⟩
  · cases he : enrolled c l
    · exact (fires_blocks (r := .MEMBER_NOT_ENROLLED) (by simp [fires, he]) h).elim
    · simp [claim, he]
  · by_cases hc : l.flow = .CAP_820
    · simp [keys, hc] at hk
      subst hk
      exact fires_blocks (r := .CAP_MEMBER_MONTH_DUPLICATE) (by simp [fires, isCap, hc, hs]) h
    · simp [keys, hc] at hk
      by_cases hkey : key l ∈ seen
      · exact fires_blocks (r := .FFS_DUPLICATE_LINE) (by simp [fires, isCap, hc, hkey]) h
      · rcases hk with rfl | rfl
        · exact hkey hs
        · exact fires_blocks (r := .FFS_NEAR_DUPLICATE) (by simp [fires, isCap, hc, hkey, hs]) h

theorem keys_nodup (l : Line) : (keys l).Nodup := by
  by_cases hc : l.flow = .CAP_820 <;> simp [keys, key, nearKey, hc]

/-- Reason codes come in the order of `reasons` (ascending by name), each at most once. -/
theorem reasons_sublist {c seen l} : (decideLine c seen l).reasons.Sublist reasons := List.filter_sublist

theorem reasons_nodup {c seen l} : (decideLine c seen l).reasons.Nodup :=
  reasons_sublist.nodup (by decide)

/-! ## The batch -/

theorem decideAll_get (c : Ctx) : ∀ (seen : List Key) (ls : List Line) (i : Nat),
    (decideAll c seen ls)[i]? = ls[i]?.map (decideLine c ((ls.take i).reverse.flatMap (claim c) ++ seen))
  | _, [], _ => by simp [decideAll]
  | _, _ :: _, 0 => by simp [decideAll]
  | seen, l :: ls, i + 1 => by
    simpa [decideAll, List.flatMap_append, List.append_assoc] using decideAll_get c (claim c l ++ seen) ls i

theorem decideBatch_get {c b i} :
    (decideBatch c b).decisions[i]? = (canonical b)[i]?.map (decideLine c (seenAt c b i)) :=
  decideAll_get c ((entries c.released).flatMap keys) (canonical b) i

/-- Soundness: every reason on a decision is a true fact about the pinned data. -/
theorem sound {c b i d r} (hd : (decideBatch c b).decisions[i]? = some d)
    (hr : r ∈ d.reasons) : Fact c (seenAt c b i) d.line r := by
  rw [decideBatch_get, Option.map_eq_some_iff] at hd
  obtain ⟨l, -, rfl⟩ := hd
  exact mem_decideLine.mp hr

/-- Completeness: a line for which any rule's fact holds is not ALLOW. -/
theorem complete {c b i l r} (hl : (canonical b)[i]? = some l) (h : Fact c (seenAt c b i) l r) :
    ∃ d, (decideBatch c b).decisions[i]? = some d ∧ d.line = l ∧ d.outcome ≠ .ALLOW :=
  ⟨decideLine c (seenAt c b i) l, by simp [decideBatch_get, hl], rfl, line_complete h⟩

/-- Bad data or a near duplicate: a line with a fact for a `review` reason is HUMAN_REVIEW. -/
theorem review_complete {c b i l r} (hl : (canonical b)[i]? = some l) (hr : review r = true)
    (h : Fact c (seenAt c b i) l r) :
    ∃ d, (decideBatch c b).decisions[i]? = some d ∧ d.line = l ∧ d.outcome = .HUMAN_REVIEW :=
  ⟨decideLine c (seenAt c b i) l, by simp [decideBatch_get, hl], rfl, line_review h hr⟩

theorem mem_decideAll {c : Ctx} : ∀ {seen : List Key} {ls : List Line} {d : Decision},
    d ∈ decideAll c seen ls → ∃ seen' l, d = decideLine c seen' l
  | _, [], _, h => by simp [decideAll] at h
  | seen, l :: ls, d, h => by
    simp only [decideAll, List.mem_cons] at h
    rcases h with rfl | h
    · exact ⟨seen, l, rfl⟩
    · exact mem_decideAll h

/-- Fail-closed: when any reference snapshot is not usable (missing or failing
    its pin, an invalid today or asOf, dated after today, too old, empty, a
    parsed row count other than the declared one, or a malformed row), or the
    released set is missing or short, every line is HUMAN_REVIEW. -/
theorem fail_closed {c b d}
    (h : ¬Usable c.today 90 okDeath c.dmf ∨ ¬Usable c.today 90 okDeath c.providerDeaths ∨
      ¬Usable c.today 31 okExclusion c.exclusions ∨ ¬Usable c.today 7 okSpan c.enrollment ∨
      ¬Whole c.released)
    (hd : d ∈ (decideBatch c b).decisions) : d.outcome = .HUMAN_REVIEW := by
  obtain ⟨seen, l, rfl⟩ := mem_decideAll (seen := (entries c.released).flatMap keys) (ls := canonical b) hd
  have : ∃ r, review r = true ∧ Fact c seen l r := by
    rcases h with h | h | h | h | h
    · exact ⟨.STALE_DMF, rfl, h⟩
    · exact ⟨.STALE_PROVIDER_DEATH, rfl, h⟩
    · exact ⟨.STALE_EXCLUSION, rfl, h⟩
    · exact ⟨.STALE_ENROLLMENT, rfl, h⟩
    · exact ⟨.STALE_RELEASED, rfl, h⟩
  obtain ⟨r, hs, hf⟩ := this
  exact line_review hf hs

/-! ## Uniqueness -/

theorem allowed_decideAll (c : Ctx) : ∀ (seen : List Key) (ls : List Line),
    ((allowedLines (decideAll c seen ls)).flatMap keys).Nodup ∧
      ∀ k ∈ (allowedLines (decideAll c seen ls)).flatMap keys, k ∉ seen
  | _, [] => by simp [decideAll, allowedLines]
  | seen, l :: ls => by
    obtain ⟨ih1, ih2⟩ := allowed_decideAll c (claim c l ++ seen) ls
    have hsub : ∀ k ∈ (allowedLines (decideAll c (claim c l ++ seen) ls)).flatMap keys,
        k ∉ claim c l ∧ k ∉ seen := fun k hk => by simpa only [List.mem_append, not_or] using ih2 k hk
    by_cases ha : (decideLine c seen l).outcome = .ALLOW
    · obtain ⟨hcl, hks⟩ := allow_facts ha
      have e : (allowedLines (decideAll c seen (l :: ls))).flatMap keys =
          keys l ++ (allowedLines (decideAll c (claim c l ++ seen) ls)).flatMap keys := by
        simp [allowedLines, decideAll, ha, decideLine_line]
      rw [e]
      refine ⟨List.nodup_append.mpr ⟨keys_nodup l, ih1, fun x hx y hy e => ?_⟩, fun k hk => ?_⟩
      · exact (hsub y hy).1 (by rw [hcl, ← e]; exact hx)
      · rcases List.mem_append.mp hk with hk | hk
        · exact hks k hk
        · exact (hsub k hk).2
    · have e : allowedLines (decideAll c seen (l :: ls)) = allowedLines (decideAll c (claim c l ++ seen) ls) := by
        simp [allowedLines, decideAll, ha]
      rw [e]
      exact ⟨ih1, fun k hk => (hsub k hk).2⟩

/-- Uniqueness: if the released set is complete (every line already paid by
    any path, human releases included) and its keys are distinct, then after
    the batch (released lines plus every ALLOWed line) no key appears twice:
    by `key_cap` and `key_ffs`, no member-month is paid twice by capitation
    and no FFS line is paid twice.  A released set missing a paid line is
    outside this theorem. -/
theorem released_nodup {c b} (h : ((entries c.released).flatMap keys).Nodup) :
    ((decideBatch c b).released.flatMap keys).Nodup := by
  obtain ⟨h1, h2⟩ := allowed_decideAll c ((entries c.released).flatMap keys) (canonical b)
  simp only [decideBatch, List.flatMap_append]
  exact List.nodup_append.mpr ⟨h, h1, fun x hx y hy e => h2 y hy (e ▸ hx)⟩

theorem key_cap {x y : Line} (hx : x.flow = .CAP_820) (hy : y.flow = .CAP_820) :
    key x = key y ↔ x.member = y.member ∧ x.date / 100 = y.date / 100 := by
  simp [key, hx, hy]

theorem key_ffs {x y : Line} (hx : x.flow ≠ .CAP_820) (hy : y.flow ≠ .CAP_820) :
    key x = key y ↔ x.member = y.member ∧ x.payee = y.payee ∧ x.date = y.date ∧ x.proc = y.proc ∧
      x.units = y.units ∧ x.cents = y.cents := by
  simp [key, hx, hy]

/-! ## Monotonicity -/

/-- `c'` has every death and exclusion row of `c`, the same day, enrollment
    and released set, and each death or exclusion snapshot is usable exactly
    when it was (so the added rows are well formed and counted). -/
structure Grows (c c' : Ctx) : Prop where
  today : c'.today = c.today
  enrollment : c'.enrollment = c.enrollment
  released : c'.released = c.released
  dmfOk : usable c'.today 90 okDeath c'.dmf = usable c.today 90 okDeath c.dmf
  pdOk : usable c'.today 90 okDeath c'.providerDeaths = usable c.today 90 okDeath c.providerDeaths
  exOk : usable c'.today 31 okExclusion c'.exclusions = usable c.today 31 okExclusion c.exclusions
  dmf : ∀ x ∈ entries c.dmf, x ∈ entries c'.dmf
  pd : ∀ x ∈ entries c.providerDeaths, x ∈ entries c'.providerDeaths
  ex : ∀ x ∈ entries c.exclusions, x ∈ entries c'.exclusions

theorem seenAt_grows {c c'} (g : Grows c c') (b : List Line) (i : Nat) : seenAt c' b i = seenAt c b i := by
  have : claim c' = claim c := funext fun l => by unfold claim enrolled; rw [g.enrollment]
  simp only [seenAt, this, g.released]

theorem fact_mono {c c' seen l} (g : Grows c c') : ∀ {r}, Fact c seen l r → Fact c' seen l r
  | .CAP_MEMBER_MONTH_DUPLICATE, h => by simpa only [Fact, overlap, g.enrollment] using h
  | .FFS_DUPLICATE_LINE, h | .FFS_NEAR_DUPLICATE, h | .SERVICE_DATE_INVALID, h => h
  | .MEMBER_DECEASED, ⟨d, hd, hp⟩ => ⟨d, g.dmf d hd, hp⟩
  | .PROVIDER_DECEASED, ⟨d, hd, hp⟩ => ⟨d, g.pd d hd, hp⟩
  | .PROVIDER_EXCLUDED, ⟨e, he, hp⟩ => ⟨e, g.ex e he, hp⟩
  | .MEMBER_NOT_ENROLLED, h => by simpa only [Fact, g.enrollment] using h
  | .SERVICE_DATE_FUTURE, h => by simpa only [Fact, g.today] using h
  | .STALE_DMF, h => by simpa only [Fact, ← usable_iff, g.dmfOk] using h
  | .STALE_PROVIDER_DEATH, h => by simpa only [Fact, ← usable_iff, g.pdOk] using h
  | .STALE_EXCLUSION, h => by simpa only [Fact, ← usable_iff, g.exOk] using h
  | .STALE_ENROLLMENT, h => by simpa only [Fact, g.today, g.enrollment] using h
  | .STALE_RELEASED, h => by simpa only [Fact, g.released] using h

/-- Monotonicity, for one batch under the same day, enrollment, released set
    and snapshot usability: adding death or exclusion rows never turns a held
    or reviewed line into ALLOW.  Claimed keys depend only on enrollment, so
    line `i` is checked against the same keys under both contexts. -/
theorem monotone {c c' : Ctx} {b : List Line} {i : Nat} {d d' : Decision} (g : Grows c c')
    (hd : (decideBatch c b).decisions[i]? = some d) (hd' : (decideBatch c' b).decisions[i]? = some d')
    (h : d.outcome ≠ .ALLOW) : d'.line = d.line ∧ d'.outcome ≠ .ALLOW := by
  rw [decideBatch_get, Option.map_eq_some_iff] at hd hd'
  obtain ⟨l, hl, rfl⟩ := hd
  obtain ⟨l', hl', rfl⟩ := hd'
  rw [hl] at hl'
  cases hl'
  refine ⟨rfl, fun ha => ?_⟩
  rw [decideLine_outcome, Ne, outcomeOf_allow] at h
  obtain ⟨r, hr⟩ := List.exists_mem_of_ne_nil _ h
  rw [seenAt_grows g b i] at ha
  exact line_complete (fact_mono g (mem_decideLine.mp hr)) ha

/-! ## Determinism -/

theorem tag_inj {a b : Flow} (h : a.tag = b.tag) : a = b := by
  cases a <;> cases b <;> simp_all [Flow.tag]

theorem enc_inj {x y : Line} (h : enc x = enc y) : x = y := by
  cases x; cases y
  simp [enc] at h
  obtain ⟨h1, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩ := h
  cases tag_inj h1; rfl

theorem canonical_perm {b₁ b₂ : List Line} (h : b₁.Perm b₂) : canonical b₁ = canonical b₂ := by
  have trans : ∀ x y z : Line, lineLe x y → lineLe y z → lineLe x z := by
    simp only [lineLe, decide_eq_true_eq]; exact fun _ _ _ => List.le_trans
  have total : ∀ x y : Line, (lineLe x y || lineLe y x) = true := by
    intro x y; simp only [lineLe, Bool.or_eq_true, decide_eq_true_eq]
    exact @List.le_total Nat _ ⟨fun _ _ => Nat.lt_asymm⟩ _ _
  refine List.Perm.eq_of_pairwise (le := fun x y => lineLe x y = true) ?_
    (List.pairwise_mergeSort trans total _) (List.pairwise_mergeSort trans total _)
    ((List.mergeSort_perm _ _).trans (h.trans (List.mergeSort_perm _ _).symm))
  intro x y _ _ hxy hyx
  simp only [lineLe, decide_eq_true_eq] at hxy hyx
  exact enc_inj (List.le_antisymm hxy hyx)

/-- Determinism of order within a batch: the result depends on the batch's
    contents, not their arrival order.  Splitting lines into batches (same
    snapshots, each batch's ALLOW lines released, their exact and near keys
    seen by later batches) is not covered by a theorem.  It can change a
    line's decision only through another line sharing its exact or near key
    (its member-month for CAP_820) that is either
    (a) in an earlier batch, enrolled and not ALLOW there: it claims its keys
        in its own batch but is never released, so a later line is no longer
        its duplicate; or
    (b) in another batch on the other side of it in canonical order: of the
        two, the one decided first is the one not flagged.
    Either way `released_nodup` holds, so no key is paid twice. -/
theorem deterministic {c b₁ b₂} (h : b₁.Perm b₂) : decideBatch c b₁ = decideBatch c b₂ := by
  simp only [decideBatch, canonical_perm h]

/-! Axiom pins: no `sorryAx`, no `Lean.ofReduceBool`. `Classical.choice` in
`deterministic` comes from core `List.le_antisymm`. -/
/-- info: 'BlindLedger.Gate.Rules.sound' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms sound
/-- info: 'BlindLedger.Gate.Rules.complete' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms complete
/-- info: 'BlindLedger.Gate.Rules.released_nodup' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms released_nodup
/-- info: 'BlindLedger.Gate.Rules.monotone' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms monotone
/-- info: 'BlindLedger.Gate.Rules.deterministic' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms deterministic
/-- info: 'BlindLedger.Gate.Rules.fail_closed' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms fail_closed

end BlindLedger.Gate.Rules
