import BlindLedger.Gate.Rules.Spec

namespace BlindLedger.Gate.Rules

/-! What `decideBatch` guarantees.  `Fact` restates each rule over the pinned
    data in plain propositions; the batch theorems speak about the canonical
    batch, where line `i` is checked against `seenAt rel b i`: the released
    keys and the keys of the lines before it.  The axiom pins at the end show
    no theorem here rests on `sorryAx` or `Lean.ofReduceBool`. -/

def Fresh {α : Type} (today maxAge : Nat) (o : Option (Snapshot α)) : Prop :=
  ∃ s, o = some s ∧ s.asOf ≤ today ∧ dayNum today ≤ dayNum s.asOf + maxAge

def Fact (c : Ctx) (seen : List Key) (l : Line) : Reason → Prop
  | .CAP_MEMBER_MONTH_DUPLICATE => l.flow = .CAP_820 ∧ key l ∈ seen
  | .FFS_DUPLICATE_LINE => l.flow ≠ .CAP_820 ∧ key l ∈ seen
  | .MEMBER_DECEASED => ∃ d ∈ entries c.dmf, d.id = l.member ∧ d.date < l.date
  | .MEMBER_NOT_ENROLLED => ¬∃ s ∈ entries c.enrollment, s.member = l.member ∧ s.start ≤ l.date ∧
      l.date ≤ s.stop ∧ (l.flow ≠ .CAP_820 ∨ s.plan = l.payee)
  | .PROVIDER_DECEASED => ∃ d ∈ entries c.providerDeaths,
      (d.id = l.payee ∨ d.id = l.rendering) ∧ d.date < l.date
  | .PROVIDER_EXCLUDED => ∃ e ∈ entries c.exclusions,
      (e.id = l.payee ∨ e.id = l.rendering) ∧ e.start ≤ l.date ∧ l.date ≤ e.stop
  | .STALE_DMF => ¬Fresh c.today 90 c.dmf
  | .STALE_ENROLLMENT => ¬Fresh c.today 7 c.enrollment
  | .STALE_EXCLUSION => ¬Fresh c.today 31 c.exclusions
  | .STALE_PROVIDER_DEATH => ¬Fresh c.today 90 c.providerDeaths

def seenAt (rel : List Key) (b : List Line) (i : Nat) : List Key :=
  (((canonical b).take i).map key).reverse ++ rel

/-! ## One line -/

theorem fresh_iff {α : Type} {t m : Nat} {o : Option (Snapshot α)} : fresh t m o = true ↔ Fresh t m o := by
  cases o <;> simp [fresh, Fresh]

theorem not_fresh {α : Type} {t m : Nat} {o : Option (Snapshot α)} : fresh t m o = false ↔ ¬Fresh t m o := by
  rw [← fresh_iff]; simp

theorem fires_iff {c seen l} (r : Reason) : fires c seen l r = true ↔ Fact c seen l r := by
  cases r <;> simp [fires, Fact, covers, party, isCap, not_fresh, and_assoc]

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

theorem outcomeOf_stale {rs : List Reason} {r : Reason} (h : r ∈ rs) (hs : stale r = true) :
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

/-- An ALLOWed line's key was not seen, so it cannot repeat a released or earlier key. -/
theorem allow_unseen {c seen l} (h : (decideLine c seen l).outcome = .ALLOW) : key l ∉ seen := by
  intro hk
  by_cases hc : l.flow = .CAP_820
  · exact line_complete (r := .CAP_MEMBER_MONTH_DUPLICATE) ⟨hc, hk⟩ h
  · exact line_complete (r := .FFS_DUPLICATE_LINE) ⟨hc, hk⟩ h

/-- Reason codes come in the order of `reasons` (ascending by name), each at most once. -/
theorem reasons_sublist {c seen l} : (decideLine c seen l).reasons.Sublist reasons := List.filter_sublist

theorem reasons_nodup {c seen l} : (decideLine c seen l).reasons.Nodup :=
  reasons_sublist.nodup (by decide)

/-! ## The batch -/

theorem decideAll_get (c : Ctx) : ∀ (seen : List Key) (ls : List Line) (i : Nat),
    (decideAll c seen ls)[i]? = ls[i]?.map (decideLine c (((ls.take i).map key).reverse ++ seen))
  | _, [], _ => by simp [decideAll]
  | _, _ :: _, 0 => by simp [decideAll]
  | seen, l :: ls, i + 1 => by
    simp only [decideAll, List.getElem?_cons_succ, List.take_succ_cons, List.map_cons,
      List.reverse_cons, List.append_assoc, List.cons_append, List.nil_append]
    exact decideAll_get c (key l :: seen) ls i

theorem decisions_eq {c rel b} : (decideBatch c rel b).decisions = decideAll c rel (canonical b) := rfl

theorem decideBatch_get {c rel b i} :
    (decideBatch c rel b).decisions[i]? = (canonical b)[i]?.map (decideLine c (seenAt rel b i)) :=
  decideAll_get c rel (canonical b) i

/-- Soundness: every reason on a decision is a true fact about the pinned data. -/
theorem sound {c rel b i d r} (hd : (decideBatch c rel b).decisions[i]? = some d)
    (hr : r ∈ d.reasons) : Fact c (seenAt rel b i) d.line r := by
  rw [decideBatch_get, Option.map_eq_some_iff] at hd
  obtain ⟨l, -, rfl⟩ := hd
  exact mem_decideLine.mp hr

/-- Completeness: a line for which any rule's fact holds is not ALLOW. -/
theorem complete {c rel b i l r} (hl : (canonical b)[i]? = some l) (h : Fact c (seenAt rel b i) l r) :
    ∃ d, (decideBatch c rel b).decisions[i]? = some d ∧ d.line = l ∧ d.outcome ≠ .ALLOW :=
  ⟨decideLine c (seenAt rel b i) l, by simp [decideBatch_get, hl], rfl, line_complete h⟩

theorem mem_decideAll {c : Ctx} : ∀ {seen : List Key} {ls : List Line} {d : Decision},
    d ∈ decideAll c seen ls → ∃ seen' l, d = decideLine c seen' l
  | _, [], _, h => by simp [decideAll] at h
  | seen, l :: ls, d, h => by
    simp only [decideAll, List.mem_cons] at h
    rcases h with rfl | h
    · exact ⟨seen, l, rfl⟩
    · exact mem_decideAll h

/-- Fail-closed: with any snapshot missing, stale or dated after today, every line is HUMAN_REVIEW. -/
theorem fail_closed {c rel b d}
    (h : ¬Fresh c.today 90 c.dmf ∨ ¬Fresh c.today 90 c.providerDeaths ∨
      ¬Fresh c.today 31 c.exclusions ∨ ¬Fresh c.today 7 c.enrollment)
    (hd : d ∈ (decideBatch c rel b).decisions) : d.outcome = .HUMAN_REVIEW := by
  rw [decisions_eq] at hd
  obtain ⟨seen, l, rfl⟩ := mem_decideAll hd
  have : ∃ r, stale r = true ∧ Fact c seen l r := by
    rcases h with h | h | h | h
    · exact ⟨.STALE_DMF, rfl, h⟩
    · exact ⟨.STALE_PROVIDER_DEATH, rfl, h⟩
    · exact ⟨.STALE_EXCLUSION, rfl, h⟩
    · exact ⟨.STALE_ENROLLMENT, rfl, h⟩
  obtain ⟨r, hs, hf⟩ := this
  rw [decideLine_outcome]
  exact outcomeOf_stale (mem_decideLine.mpr hf) hs

/-! ## Uniqueness -/

theorem allowedKeys_decideAll (c : Ctx) : ∀ (seen : List Key) (ls : List Line),
    (allowedKeys (decideAll c seen ls)).Nodup ∧ ∀ k ∈ allowedKeys (decideAll c seen ls), k ∉ seen
  | _, [] => by simp [decideAll, allowedKeys]
  | seen, l :: ls => by
    obtain ⟨ih1, ih2⟩ := allowedKeys_decideAll c (key l :: seen) ls
    have hsub : ∀ k ∈ allowedKeys (decideAll c (key l :: seen) ls), k ≠ key l ∧ k ∉ seen :=
      fun k hk => by simpa only [List.mem_cons, not_or] using ih2 k hk
    by_cases ha : (decideLine c seen l).outcome = .ALLOW
    · have e : allowedKeys (decideAll c seen (l :: ls)) =
          key l :: allowedKeys (decideAll c (key l :: seen) ls) := by
        simp [allowedKeys, decideAll, ha, decideLine_line]
      rw [e]
      refine ⟨List.nodup_cons.mpr ⟨fun hm => (hsub _ hm).1 rfl, ih1⟩, fun k hk => ?_⟩
      rcases List.mem_cons.mp hk with rfl | hk
      · exact allow_unseen ha
      · exact (hsub k hk).2
    · have e : allowedKeys (decideAll c seen (l :: ls)) = allowedKeys (decideAll c (key l :: seen) ls) := by
        simp [allowedKeys, decideAll, ha]
      rw [e]
      exact ⟨ih1, fun k hk => (hsub k hk).2⟩

theorem released_eq {c rel b} :
    (decideBatch c rel b).released = rel ++ allowedKeys (decideAll c rel (canonical b)) := rfl

/-- Uniqueness: from a duplicate-free released set, the new released set (old
    keys plus every ALLOWed line's key) has no key twice.  By `key_cap` and
    `key_ffs`, no two released CAP_820 lines share a member-month and no two
    released FFS lines are exact duplicates. -/
theorem released_nodup {c rel b} (h : rel.Nodup) : (decideBatch c rel b).released.Nodup := by
  obtain ⟨h1, h2⟩ := allowedKeys_decideAll c rel (canonical b)
  rw [released_eq]
  exact List.nodup_append.mpr ⟨h, h1, fun x hx y hy e => h2 y hy (e ▸ hx)⟩

theorem key_cap {x y : Line} (hx : x.flow = .CAP_820) (hy : y.flow = .CAP_820) :
    key x = key y ↔ x.member = y.member ∧ x.date / 100 = y.date / 100 := by
  simp [key, hx, hy]

theorem key_ffs {x y : Line} (hx : x.flow ≠ .CAP_820) (hy : y.flow ≠ .CAP_820) :
    key x = key y ↔ x.member = y.member ∧ x.payee = y.payee ∧ x.date = y.date ∧ x.proc = y.proc ∧
      x.units = y.units ∧ x.cents = y.cents := by
  simp [key, hx, hy]

/-! ## Monotonicity -/

/-- `c'` has every death and exclusion entry of `c`, with the same snapshot
    dates, the same enrollment and the same day. -/
structure Grows (c c' : Ctx) : Prop where
  today : c'.today = c.today
  enrollment : c'.enrollment = c.enrollment
  dmfAsOf : c'.dmf.map (·.asOf) = c.dmf.map (·.asOf)
  pdAsOf : c'.providerDeaths.map (·.asOf) = c.providerDeaths.map (·.asOf)
  exAsOf : c'.exclusions.map (·.asOf) = c.exclusions.map (·.asOf)
  dmf : ∀ x ∈ entries c.dmf, x ∈ entries c'.dmf
  pd : ∀ x ∈ entries c.providerDeaths, x ∈ entries c'.providerDeaths
  ex : ∀ x ∈ entries c.exclusions, x ∈ entries c'.exclusions

theorem fresh_grows {α : Type} {o o' : Option (Snapshot α)} (h : o'.map (·.asOf) = o.map (·.asOf))
    (t m : Nat) : Fresh t m o' ↔ Fresh t m o := by
  rw [← fresh_iff, ← fresh_iff]
  cases o <;> cases o' <;> simp_all [fresh]

theorem fact_mono {c c' seen l} (g : Grows c c') : ∀ {r}, Fact c seen l r → Fact c' seen l r
  | .CAP_MEMBER_MONTH_DUPLICATE, h | .FFS_DUPLICATE_LINE, h => h
  | .MEMBER_DECEASED, ⟨d, hd, hp⟩ => ⟨d, g.dmf d hd, hp⟩
  | .PROVIDER_DECEASED, ⟨d, hd, hp⟩ => ⟨d, g.pd d hd, hp⟩
  | .PROVIDER_EXCLUDED, ⟨e, he, hp⟩ => ⟨e, g.ex e he, hp⟩
  | .MEMBER_NOT_ENROLLED, h => by simp only [Fact, g.enrollment] at h ⊢; exact h
  | .STALE_DMF, h => by simp only [Fact, g.today, fresh_grows g.dmfAsOf] at h ⊢; exact h
  | .STALE_PROVIDER_DEATH, h => by simp only [Fact, g.today, fresh_grows g.pdAsOf] at h ⊢; exact h
  | .STALE_EXCLUSION, h => by simp only [Fact, g.today, fresh_grows g.exAsOf] at h ⊢; exact h
  | .STALE_ENROLLMENT, h => by simp only [Fact, g.today, g.enrollment] at h ⊢; exact h

/-- Monotonicity: adding death or exclusion entries never turns a held (or
    reviewed) line into ALLOW.  Seen keys do not depend on outcomes, so line
    `i` is checked against the same keys under both contexts. -/
theorem monotone {c c' : Ctx} {rel : List Key} {b : List Line} {i : Nat} {d d' : Decision} (g : Grows c c') (hd : (decideBatch c rel b).decisions[i]? = some d)
    (hd' : (decideBatch c' rel b).decisions[i]? = some d') (h : d.outcome ≠ .ALLOW) :
    d'.line = d.line ∧ d'.outcome ≠ .ALLOW := by
  rw [decideBatch_get, Option.map_eq_some_iff] at hd hd'
  obtain ⟨l, hl, rfl⟩ := hd
  obtain ⟨l', hl', rfl⟩ := hd'
  rw [hl] at hl'
  cases hl'
  refine ⟨rfl, fun ha => ?_⟩
  rw [decideLine_outcome, Ne, outcomeOf_allow] at h
  rw [decideLine_outcome, outcomeOf_allow] at ha
  obtain ⟨r, hr⟩ := List.exists_mem_of_ne_nil _ h
  have hr' := mem_decideLine.mpr (fact_mono g (mem_decideLine.mp hr))
  rw [ha] at hr'
  simp at hr'

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

/-- Determinism: the result depends on the batch's contents, not its arrival order. -/
theorem deterministic {c rel b₁ b₂} (h : b₁.Perm b₂) : decideBatch c rel b₁ = decideBatch c rel b₂ := by
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
