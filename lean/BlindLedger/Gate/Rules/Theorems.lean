import BlindLedger.Gate.Rules.Spec

namespace BlindLedger.Gate.Rules

/-! What `decideBatch` guarantees.  `Fact` restates each rule over the pinned
    data in plain propositions; the batch theorems speak about the canonical
    batch, where line `i` is checked against `seenAt c b i`: the keys of the
    gate's view of the released set and those claimed by the lines before it.  The axiom pins at
    the end show no theorem here rests on `sorryAx` or `Lean.ofReduceBool`. -/

/-- A snapshot the rules may read: see `usable`. -/
def Usable {α : Type} (today maxAge : Nat) (ok : Nat → α → Bool) (o : Option (Snapshot α)) : Prop :=
  ∃ s, o = some s ∧ validDate today = true ∧ validDate s.asOf = true ∧ s.asOf ≤ today ∧
    dayNum today ≤ dayNum s.asOf + maxAge ∧ s.entries.length = s.count ∧ 0 < s.count ∧
    ∀ x ∈ s.entries, ok s.asOf x = true

/-- A released or unresolved set the rules may read: see `chained`. -/
def Chained (today : Nat) (prior : Snapshot Line) (o : Option (Snapshot Line)) : Prop :=
  ∃ s, o = some s ∧ s.entries.length = s.count ∧ validDate s.asOf = true ∧ s.asOf ≤ today ∧
    prior.asOf ≤ s.asOf ∧ prior.entries <+: s.entries

/-! The facts of R1, R3 and R5 as the rows show them. -/
abbrev MemberDead (c : Ctx) (l : Line) : Prop := ∃ d ∈ entries c.dmf, d.id = l.member ∧ d.date < l.date

abbrev NotCovered (c : Ctx) (l : Line) : Prop :=
  ¬∃ s ∈ entries c.enrollment, s.member = l.member ∧ s.start ≤ l.date ∧ l.date ≤ s.stop ∧
    (l.flow ≠ .CAP_820 ∨ s.plan = l.payee)

abbrev ProviderDead (c : Ctx) (l : Line) : Prop :=
  ∃ d ∈ entries c.providerDeaths, (d.id = l.payee ∨ d.id = l.rendering) ∧ d.date < l.date

abbrev Excluded (c : Ctx) (l : Line) : Prop :=
  ∃ e ∈ entries c.exclusions, (e.id = l.payee ∨ e.id = l.rendering) ∧ e.start ≤ l.date ∧ l.date ≤ e.stop

def Fact (c : Ctx) (seen : List Key) (l : Line) : Reason → Prop
  | .ALREADY_DECIDED => idKey l ∈ seen ∨ idKey l ∈ pending c
  | .CAP_MEMBER_MONTH_DUPLICATE => l.flow = .CAP_820 ∧ (exactKey l ∈ seen ∨ nearKey l ∈ seen ∨
      Usable c.today 7 okSpan c.enrollment ∧ validDate l.date = true ∧ overlap c l = true)
  | .COLLIDES_WITH_UNRESOLVED_NEAR => l.flow ≠ .CAP_820 ∧ nearKey l ∈ pending c ∧ exactKey l ∉ pending c
  | .DUPLICATE_OF_UNRESOLVED => exactKey l ∈ pending c ∨ l.flow = .CAP_820 ∧ nearKey l ∈ pending c
  | .FFS_DUPLICATE_LINE => l.flow ≠ .CAP_820 ∧ exactKey l ∈ seen
  | .FFS_DUPLICATE_UNVERIFIED => l.flow ≠ .CAP_820 ∧ exactKey l ∈ looseKeys c
  | .FFS_NEAR_DUPLICATE => l.flow ≠ .CAP_820 ∧ nearKey l ∈ seen ∧ exactKey l ∉ seen
  | .MEMBER_DECEASED => Usable c.today 90 okDeath c.dmf ∧ validDate l.date = true ∧ MemberDead c l
  | .MEMBER_DECEASED_UNVERIFIED => c.dmf.isSome ∧ ¬Usable c.today 90 okDeath c.dmf ∧ validDate l.date = true ∧
      MemberDead c l
  | .MEMBER_NOT_ENROLLED => Usable c.today 7 okSpan c.enrollment ∧ validDate l.date = true ∧ NotCovered c l
  | .MEMBER_NOT_ENROLLED_UNVERIFIED => c.enrollment.isSome ∧ ¬Usable c.today 7 okSpan c.enrollment ∧
      validDate l.date = true ∧ NotCovered c l
  | .PROVIDER_DECEASED => Usable c.today 90 okDeath c.providerDeaths ∧ validDate l.date = true ∧
      ProviderDead c l
  | .PROVIDER_DECEASED_UNVERIFIED => c.providerDeaths.isSome ∧ ¬Usable c.today 90 okDeath c.providerDeaths ∧
      validDate l.date = true ∧ ProviderDead c l
  | .PROVIDER_EXCLUDED => Usable c.today 31 okExclusion c.exclusions ∧ validDate l.date = true ∧ Excluded c l
  | .PROVIDER_EXCLUDED_UNVERIFIED => c.exclusions.isSome ∧ ¬Usable c.today 31 okExclusion c.exclusions ∧
      validDate l.date = true ∧ Excluded c l
  | .SERVICE_DATE_FUTURE => c.today < l.date
  | .SERVICE_DATE_INVALID => validDate l.date = false
  | .STALE_DMF => ¬Usable c.today 90 okDeath c.dmf
  | .STALE_ENROLLMENT => ¬Usable c.today 7 okSpan c.enrollment
  | .STALE_EXCLUSION => ¬Usable c.today 31 okExclusion c.exclusions
  | .STALE_PROVIDER_DEATH => ¬Usable c.today 90 okDeath c.providerDeaths
  | .STALE_RELEASED => ¬Chained c.today c.releasedPrior c.released
  | .STALE_UNRESOLVED => ¬Chained c.today c.unresolvedPrior c.unresolved

def seenAt (c : Ctx) (b : List Line) (i : Nat) : List Key :=
  ((canonical b).take i).reverse.flatMap (claim c) ++ (releasedSet c).flatMap keys

/-! ## One line -/

theorem usable_iff {α : Type} {t m : Nat} {ok : Nat → α → Bool} {o : Option (Snapshot α)} :
    usable t m ok o = true ↔ Usable t m ok o := by
  cases o <;> simp [usable, Usable, List.all_eq_true, and_assoc]

theorem chained_iff {t p o} : chained t p o = true ↔ Chained t p o := by
  cases o <;> simp [chained, Chained, and_assoc]

theorem fires_iff {c seen l} (r : Reason) : fires c seen l r = true ↔ Fact c seen l r := by
  cases r <;> simp [fires, Fact, certain, unverified, notEnrolled, enrolled, covers, party, isCap, memberDead,
    providerDead, excluded, ← usable_iff, ← chained_iff, and_assoc, or_assoc]

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

theorem outcomeOf_certain {rs : List Reason} {r : Reason} (h : r ∈ rs) (hr : review r = false) :
    outcomeOf rs = .HOLD := by
  cases rs with
  | nil => cases h
  | cons a t => rw [outcomeOf, if_neg (by simp), if_pos (List.any_eq_true.mpr ⟨r, h, by simp [hr]⟩)]

theorem outcomeOf_hold {rs : List Reason} (h : outcomeOf rs = .HOLD) : ∃ r ∈ rs, review r = false := by
  unfold outcomeOf at h
  split at h
  · cases h
  · split at h
    · rename_i hr
      obtain ⟨r, hm, hf⟩ := List.any_eq_true.mp hr
      exact ⟨r, hm, by simpa using hf⟩
    · cases h

theorem line_complete {c seen l r} (h : Fact c seen l r) : (decideLine c seen l).outcome ≠ .ALLOW := by
  intro ha
  rw [decideLine_outcome, outcomeOf_allow] at ha
  have hr := mem_decideLine.mpr h
  rw [ha] at hr
  simp at hr

theorem line_hold {c seen l r} (h : Fact c seen l r) (hr : review r = false) :
    (decideLine c seen l).outcome = .HOLD := by
  rw [decideLine_outcome]
  exact outcomeOf_certain (mem_decideLine.mpr h) hr

theorem fires_blocks {c seen l r} (hf : fires c seen l r = true)
    (h : (decideLine c seen l).outcome = .ALLOW) : False :=
  line_complete ((fires_iff r).mp hf) h

theorem idKey_mem {l : Line} : idKey l ∈ keys l := by simp [keys]

theorem idKey_claim {c : Ctx} {l : Line} : idKey l ∈ claim c l := by
  unfold claim; split <;> simp [keys]

/-- The one key an unresolved line may leave unclaimed: the member-month of a
    capitation line whose member is known not to be enrolled with that plan. -/
theorem claim_keys {c x k} (hk : k ∈ keys x) (hc : k ∉ claim c x) :
    x.flow = .CAP_820 ∧ k = nearKey x ∧ notEnrolled c x = true := by
  unfold claim at hc
  split at hc
  · rename_i h
    simp only [Bool.and_eq_true, isCap, beq_iff_eq] at h
    simp only [keys, List.mem_cons, List.not_mem_nil, or_false] at hk hc
    rcases hk with rfl | rfl | rfl
    · simp at hc
    · exact ⟨h.1, rfl, h.2⟩
    · simp at hc
  · exact absurd hk hc

/-- An ALLOWed line claims all its keys, and none of them was seen or is pending. -/
theorem allow_facts {c seen l} (h : (decideLine c seen l).outcome = .ALLOW) :
    claim c l = keys l ∧ ∀ k ∈ keys l, k ∉ seen ∧ k ∉ pending c := by
  have no : ∀ r, fires c seen l r = false := fun r => by
    cases hf : fires c seen l r
    · rfl
    · exact (fires_blocks hf h).elim
  have hn : notEnrolled c l = false := no .MEMBER_NOT_ENROLLED
  refine ⟨by simp [claim, hn], fun k hk => ?_⟩
  have h1 := no .ALREADY_DECIDED
  have h2 := no .CAP_MEMBER_MONTH_DUPLICATE
  have h3 := no .COLLIDES_WITH_UNRESOLVED_NEAR
  have h4 := no .DUPLICATE_OF_UNRESOLVED
  have h5 := no .FFS_DUPLICATE_LINE
  have h6 := no .FFS_NEAR_DUPLICATE
  simp only [fires] at h1 h2 h3 h4 h5 h6
  simp only [keys, List.mem_cons, List.not_mem_nil, or_false] at hk
  rcases hk with rfl | rfl | rfl
  · cases hc : isCap l
    · exact ⟨fun hs => by simp [hc, hs] at h5, fun hp => by simp [hp] at h4⟩
    · exact ⟨fun hs => by simp [hc, hs] at h2, fun hp => by simp [hp] at h4⟩
  · cases hc : isCap l
    · refine ⟨fun hs => ?_, fun hp => ?_⟩
      · by_cases he : exactKey l ∈ seen
        · simp [hc, he] at h5
        · simp [hc, hs, he] at h6
      · by_cases he : exactKey l ∈ pending c
        · simp [he] at h4
        · simp [hc, hp, he] at h3
    · exact ⟨fun hs => by simp [hc, hs] at h2, fun hp => by simp [hc, hp] at h4⟩
  · exact ⟨fun hs => by simp [hs] at h1, fun hp => by simp [hp] at h1⟩

theorem keys_nodup (l : Line) : (keys l).Nodup := by
  cases hc : isCap l <;> simp [keys, exactKey, nearKey, idKey, hc]

/-- Reason codes come in the order of `reasons` (ascending by name), each at most once. -/
theorem reasons_sublist {c seen l} : (decideLine c seen l).reasons.Sublist reasons := List.filter_sublist

theorem reasons_nodup {c seen l} : (decideLine c seen l).reasons.Nodup :=
  reasons_sublist.nodup (by decide)

theorem outcome_cases {c seen l} (h : (decideLine c seen l).outcome ≠ .ALLOW) :
    (decideLine c seen l).outcome = .HUMAN_REVIEW ∨
      ((decideLine c seen l).outcome = .HOLD ∧ ∃ r ∈ (decideLine c seen l).reasons, review r = false) := by
  cases ho : (decideLine c seen l).outcome with
  | ALLOW => exact absurd ho h
  | HOLD => exact Or.inr ⟨rfl, outcomeOf_hold (decideLine_outcome.symm.trans ho)⟩
  | HUMAN_REVIEW => exact Or.inl rfl

/-! ## The batch -/

theorem decideAll_get (c : Ctx) : ∀ (seen : List Key) (ls : List Line) (i : Nat),
    (decideAll c seen ls)[i]? = ls[i]?.map (decideLine c ((ls.take i).reverse.flatMap (claim c) ++ seen))
  | _, [], _ => by simp [decideAll]
  | _, _ :: _, 0 => by simp [decideAll]
  | seen, l :: ls, i + 1 => by
    simpa [decideAll, List.flatMap_append, List.append_assoc] using decideAll_get c (claim c l ++ seen) ls i

theorem decideBatch_get {c b i} :
    (decideBatch c b).decisions[i]? = (canonical b)[i]?.map (decideLine c (seenAt c b i)) :=
  decideAll_get c ((releasedSet c).flatMap keys) (canonical b) i

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

/-- A certain reason outranks review: a line with the fact of a reason that is
    not `review` is HOLD, whatever review reasons it also carries. -/
theorem hold_complete {c b i l r} (hl : (canonical b)[i]? = some l) (hr : review r = false)
    (h : Fact c (seenAt c b i) l r) :
    ∃ d, (decideBatch c b).decisions[i]? = some d ∧ d.line = l ∧ d.outcome = .HOLD :=
  ⟨decideLine c (seenAt c b i) l, by simp [decideBatch_get, hl], rfl, line_hold h hr⟩

/-- Each decision was made against the keys seen so far: earlier claims, then `seen`. -/
theorem mem_decideAll {c : Ctx} : ∀ {seen : List Key} {ls : List Line} {d : Decision},
    d ∈ decideAll c seen ls → ∃ pre l, d = decideLine c (pre ++ seen) l
  | _, [], _, h => by simp [decideAll] at h
  | seen, l :: ls, d, h => by
    simp only [decideAll, List.mem_cons] at h
    rcases h with rfl | h
    · exact ⟨[], l, rfl⟩
    · obtain ⟨pre, l', rfl⟩ := mem_decideAll h
      exact ⟨pre ++ claim c l, l', by rw [List.append_assoc]⟩

/-- Fail-closed: when any reference snapshot is not usable (missing or failing
    its pin, an invalid today or asOf, dated after today, too old, empty, a
    parsed row count other than the declared one, or a malformed row), or the
    released or unresolved set is not chained (missing, miscounted, misdated
    or not extending the checkpoint), no line is ALLOW: each is HUMAN_REVIEW,
    or HOLD on a certain reason (which never rests on the unusable data). -/
theorem fail_closed {c b d}
    (h : ¬Usable c.today 90 okDeath c.dmf ∨ ¬Usable c.today 90 okDeath c.providerDeaths ∨
      ¬Usable c.today 31 okExclusion c.exclusions ∨ ¬Usable c.today 7 okSpan c.enrollment ∨
      ¬Chained c.today c.releasedPrior c.released ∨ ¬Chained c.today c.unresolvedPrior c.unresolved)
    (hd : d ∈ (decideBatch c b).decisions) :
    d.outcome = .HUMAN_REVIEW ∨ (d.outcome = .HOLD ∧ ∃ r ∈ d.reasons, review r = false) := by
  obtain ⟨_, l, rfl⟩ := mem_decideAll (seen := (releasedSet c).flatMap keys) (ls := canonical b) hd
  apply outcome_cases
  rcases h with h | h | h | h | h | h
  · exact line_complete (r := .STALE_DMF) h
  · exact line_complete (r := .STALE_PROVIDER_DEATH) h
  · exact line_complete (r := .STALE_EXCLUSION) h
  · exact line_complete (r := .STALE_ENROLLMENT) h
  · exact line_complete (r := .STALE_RELEASED) h
  · exact line_complete (r := .STALE_UNRESOLVED) h

/-- An ALLOWed line shares no key with any line of the released set, nor with
    what any line of the unresolved set claims: it may share only the
    member-month of an unresolved capitation line whose member is known not to
    be enrolled with that plan.  The sets are the gate's views; an ALLOW line
    has both sets chained (`fail_closed`), so they are the sets read. -/
theorem allow_clear {c b d} (hd : d ∈ (decideBatch c b).decisions) (ha : d.outcome = .ALLOW) :
    ∀ x ∈ releasedSet c ++ unresolvedSet c, ∀ k ∈ keys d.line, k ∈ keys x →
      x.flow = .CAP_820 ∧ k = nearKey x ∧ notEnrolled c x = true := by
  obtain ⟨pre, l, rfl⟩ := mem_decideAll (seen := (releasedSet c).flatMap keys) (ls := canonical b) hd
  intro x hx k hk hkx
  rw [decideLine_line] at hk
  have hf := (allow_facts ha).2 k hk
  rcases List.mem_append.mp hx with hx | hx
  · exact (hf.1 (List.mem_append.mpr (Or.inr (List.mem_flatMap.mpr ⟨x, hx, hkx⟩)))).elim
  · exact claim_keys hkx (fun hc => hf.2 (List.mem_flatMap.mpr ⟨x, hx, hc⟩))

theorem lines_decideAll (c : Ctx) : ∀ (seen : List Key) (ls : List Line),
    (decideAll c seen ls).map (·.line) = ls
  | _, [] => rfl
  | seen, l :: ls => by simp only [decideAll, List.map_cons, decideLine_line, lines_decideAll c _ ls]

/-- Every line of the batch is in the next checkpoint of the released or the
    unresolved set, unless its identity was already decided (release is by
    identity, so such a line is never paid as submitted). -/
theorem decided_kept {c b x} (hx : x ∈ b) :
    x ∈ (decideBatch c b).released.entries ∨ x ∈ (decideBatch c b).unresolved.entries ∨
      ∃ d ∈ (decideBatch c b).decisions, d.line = x ∧ Reason.ALREADY_DECIDED ∈ d.reasons := by
  have hm : x ∈ (decideAll c ((releasedSet c).flatMap keys) (canonical b)).map (·.line) := by
    rw [lines_decideAll]; exact (List.mergeSort_perm b lineLe).mem_iff.mpr hx
  obtain ⟨d, hd, rfl⟩ := List.mem_map.mp hm
  by_cases ha : d.outcome = .ALLOW
  · exact Or.inl (List.mem_append_right _ (List.mem_map.mpr ⟨d, List.mem_filter.mpr ⟨hd, by simp [ha]⟩, rfl⟩))
  · by_cases hr : Reason.ALREADY_DECIDED ∈ d.reasons
    · exact Or.inr (Or.inr ⟨d, hd, rfl, hr⟩)
    · exact Or.inr (Or.inl (List.mem_append_right _
        (List.mem_map.mpr ⟨d, List.mem_filter.mpr ⟨hd, by simp [ha, hr]⟩, rfl⟩)))

/-- The gate's view of a set keeps every line of its checkpoint. -/
theorem prior_view {t p o x} (h : x ∈ p.entries) : x ∈ (view t p o).entries := by
  unfold view
  split
  · rename_i hc
    obtain ⟨s, rfl, -, -, -, -, hp⟩ := chained_iff.mp hc
    exact hp.subset h
  · exact h

/-- A chained set's view is the set read. -/
theorem view_chained {t p o} (h : Chained t p o) : (view t p o).entries = entries o := by
  rw [view, if_pos (chained_iff.mpr h)]
  obtain ⟨s, rfl, -⟩ := h
  rfl

/-- `allow_clear` for the sets as read: an ALLOWed line has both sets chained, so each view is the
    set read (`view_chained`). -/
theorem allow_clear_store {c b d} (hd : d ∈ (decideBatch c b).decisions) (ha : d.outcome = .ALLOW) :
    ∀ x ∈ entries c.released ++ entries c.unresolved, ∀ k ∈ keys d.line, k ∈ keys x →
      x.flow = .CAP_820 ∧ k = nearKey x ∧ notEnrolled c x = true := by
  have hr : Chained c.today c.releasedPrior c.released := chained_iff.mp (by
    cases h : chained c.today c.releasedPrior c.released
    · obtain ⟨_, l, rfl⟩ := mem_decideAll (seen := (releasedSet c).flatMap keys) (ls := canonical b) hd
      exact (fires_blocks (r := .STALE_RELEASED) (by simp [fires, h]) ha).elim
    · rfl)
  have hu : Chained c.today c.unresolvedPrior c.unresolved := chained_iff.mp (by
    cases h : chained c.today c.unresolvedPrior c.unresolved
    · obtain ⟨_, l, rfl⟩ := mem_decideAll (seen := (releasedSet c).flatMap keys) (ls := canonical b) hd
      exact (fires_blocks (r := .STALE_UNRESOLVED) (by simp [fires, h]) ha).elim
    · rfl)
  have := allow_clear hd ha
  rwa [releasedSet, unresolvedSet, view_chained hr, view_chained hu] at this

theorem prior_advance {t p o adds x} (h : x ∈ p.entries) : x ∈ (advance t p o adds).entries :=
  List.mem_append_left _ (prior_view h)

theorem mem_iterate {P : Nat → List Line} {x} :
    ∀ {m}, (∀ k < m, x ∈ P k → x ∈ P (k + 1)) → x ∈ P 0 → x ∈ P m
  | 0, _, h => h
  | m + 1, step, h => step m (Nat.lt_add_one m) (mem_iterate (fun k hk => step k (Nat.lt_succ_of_lt hk)) h)

/-- Across batches, under the checkpoint rule: when the next batch's
    checkpoints are the ones this batch produced (`advance`), whether or not
    this batch's sets were chained, no line it ALLOWs shares an exact key, near
    key, member-month or identity with any line of this batch, whatever that
    line's outcome or enrollment, except the member-month of a capitation line
    whose member is known not to be enrolled with that plan; unless that line
    was itself a resubmitted identity.  A store that rolls back or drops a
    line of this batch no longer chains, so it gets no ALLOW. -/
theorem later_allow_clear {c c₂ : Ctx} {b₁ b₂ x d}
    (hr : c₂.releasedPrior = (decideBatch c b₁).released)
    (hu : c₂.unresolvedPrior = (decideBatch c b₁).unresolved)
    (hx : x ∈ b₁) (hd : d ∈ (decideBatch c₂ b₂).decisions) (ha : d.outcome = .ALLOW) :
    (∃ e ∈ (decideBatch c b₁).decisions, e.line = x ∧ Reason.ALREADY_DECIDED ∈ e.reasons) ∨
      ∀ k ∈ keys d.line, k ∈ keys x → x.flow = .CAP_820 ∧ k = nearKey x ∧ notEnrolled c₂ x = true := by
  rcases decided_kept (c := c) hx with h | h | h
  · exact Or.inr (allow_clear hd ha x (List.mem_append_left _ (prior_view (by rw [hr]; exact h))))
  · exact Or.inr (allow_clear hd ha x (List.mem_append_right _ (prior_view (by rw [hu]; exact h))))
  · exact Or.inl h

/-- `later_allow_clear` for any later batch of a chain in which each batch takes the checkpoints the
    one before produced (batches `0` to `m + 1`): a line of the first batch stays in every later
    checkpoint. -/
theorem later_allow_clear_many {c : Nat → Ctx} {b : Nat → List Line} {m x d}
    (hr : ∀ k ≤ m, (c (k + 1)).releasedPrior = (decideBatch (c k) (b k)).released)
    (hu : ∀ k ≤ m, (c (k + 1)).unresolvedPrior = (decideBatch (c k) (b k)).unresolved)
    (hx : x ∈ b 0) (hd : d ∈ (decideBatch (c (m + 1)) (b (m + 1))).decisions) (ha : d.outcome = .ALLOW) :
    (∃ e ∈ (decideBatch (c 0) (b 0)).decisions, e.line = x ∧ Reason.ALREADY_DECIDED ∈ e.reasons) ∨
      ∀ k ∈ keys d.line, k ∈ keys x → x.flow = .CAP_820 ∧ k = nearKey x ∧ notEnrolled (c (m + 1)) x = true := by
  rcases decided_kept (c := c 0) hx with h | h | h
  · have h := mem_iterate (P := fun k => (decideBatch (c k) (b k)).released.entries) (m := m)
      (fun k hk h => prior_advance (by rw [hr k (Nat.le_of_lt hk)]; exact h)) h
    exact Or.inr (allow_clear hd ha x (List.mem_append_left _ (prior_view (by rw [hr m m.le_refl]; exact h))))
  · have h := mem_iterate (P := fun k => (decideBatch (c k) (b k)).unresolved.entries) (m := m)
      (fun k hk h => prior_advance (by rw [hu k (Nat.le_of_lt hk)]; exact h)) h
    exact Or.inr (allow_clear hd ha x (List.mem_append_right _ (prior_view (by rw [hu m m.le_refl]; exact h))))
  · exact Or.inl h

/-! ## Uniqueness -/

/-- Uniqueness within the batch: the ALLOWed lines' keys (exact, near,
    member-month, identity) are pairwise distinct and none was seen (released
    or claimed earlier).  With `allow_clear` this is the guarantee: no ALLOW
    repeats a key of the released set, of what the unresolved set claims, or
    of another ALLOW line.  A released set missing a paid line is outside it. -/
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
        · exact (hks k hk).1
        · exact (hsub k hk).2
    · have e : allowedLines (decideAll c seen (l :: ls)) = allowedLines (decideAll c (claim c l ++ seen) ls) := by
        simp [allowedLines, decideAll, ha]
      rw [e]
      exact ⟨ih1, fun k hk => (hsub k hk).2⟩

theorem fresh_unseen {c : Ctx} {seen ls e} (he : e ∈ decideAll c seen ls)
    (fe : Reason.ALREADY_DECIDED ∉ e.reasons) : idKey e.line ∉ seen ∧ idKey e.line ∉ pending c := by
  obtain ⟨pre, l, rfl⟩ := mem_decideAll he
  have h : ¬Fact c (pre ++ seen) l .ALREADY_DECIDED := fun h => fe (mem_decideLine.mpr h)
  exact ⟨fun hs => h (Or.inl (List.mem_append_right _ hs)), fun hp => h (Or.inr hp)⟩

theorem fresh_ids (c : Ctx) : ∀ {seen : List Key} {ls : List Line} {a b : Decision},
    a ∈ decideAll c seen ls → b ∈ decideAll c seen ls → a ≠ b →
    Reason.ALREADY_DECIDED ∉ a.reasons → Reason.ALREADY_DECIDED ∉ b.reasons → a.line.id ≠ b.line.id
  | _, [], _, _, ha, _, _, _, _ => by simp [decideAll] at ha
  | seen, l :: ls, a, b, ha, hb, hab, fa, fb => by
    simp only [decideAll, List.mem_cons] at ha hb
    have head : ∀ {e}, e ∈ decideAll c (claim c l ++ seen) ls → Reason.ALREADY_DECIDED ∉ e.reasons →
        l.id ≠ e.line.id := fun {e} he fe hid =>
      (fresh_unseen he fe).1 (List.mem_append_left _ (by
        rw [show idKey e.line = idKey l by simp [idKey, hid]]; exact idKey_claim))
    rcases ha with rfl | ha <;> rcases hb with rfl | hb
    · exact absurd rfl hab
    · exact head hb fb
    · exact fun e => head ha fa e.symm
    · exact fresh_ids c ha hb hab fa fb

theorem allow_nil {c : Ctx} {seen ls d} (hd : d ∈ decideAll c seen ls) (ha : d.outcome = .ALLOW) :
    d.reasons = [] := by
  obtain ⟨pre, l, rfl⟩ := mem_decideAll hd
  exact outcomeOf_allow.mp (decideLine_outcome.symm.trans ha)

/-- Identities: if no identity sits in both views, none sits in both next
    checkpoints; the gate adds each new identity to at most one of them. -/
theorem ids_disjoint {c b} (h : ∀ x ∈ releasedSet c, ∀ y ∈ unresolvedSet c, x.id ≠ y.id) :
    ∀ x ∈ (decideBatch c b).released.entries, ∀ y ∈ (decideBatch c b).unresolved.entries, x.id ≠ y.id := by
  intro x hx y hy hxy
  rcases List.mem_append.mp hx with hx | hx <;> rcases List.mem_append.mp hy with hy | hy
  · exact h x hx y hy hxy
  · obtain ⟨dy, hdy, rfl⟩ := List.mem_map.mp hy
    obtain ⟨hdy, hay⟩ := List.mem_filter.mp hdy
    have fy : dy.outcome ≠ .ALLOW ∧ Reason.ALREADY_DECIDED ∉ dy.reasons := by simpa using hay
    exact (fresh_unseen hdy fy.2).1 (List.mem_flatMap.mpr ⟨x, hx, by
      rw [show idKey dy.line = idKey x by simp [idKey, hxy]]; exact idKey_mem⟩)
  · obtain ⟨dx, hdx, rfl⟩ := List.mem_map.mp hx
    obtain ⟨hdx, hax⟩ := List.mem_filter.mp hdx
    obtain ⟨pre, l, rfl⟩ := mem_decideAll hdx
    have hk := ((allow_facts (by simpa using hax)).2 (idKey l) idKey_mem).2
    have hxy : l.id = y.id := hxy
    exact hk (List.mem_flatMap.mpr ⟨y, hy, by
      rw [show idKey l = idKey y by simp [idKey, hxy]]; exact idKey_claim⟩)
  · obtain ⟨dx, hdx, rfl⟩ := List.mem_map.mp hx
    obtain ⟨hdx, hax⟩ := List.mem_filter.mp hdx
    obtain ⟨dy, hdy, rfl⟩ := List.mem_map.mp hy
    obtain ⟨hdy, hay⟩ := List.mem_filter.mp hdy
    have hax : dx.outcome = .ALLOW := by simpa using hax
    have hay : dy.outcome ≠ .ALLOW ∧ Reason.ALREADY_DECIDED ∉ dy.reasons := by simpa using hay
    exact fresh_ids c hdx hdy (fun e => hay.1 (e ▸ hax)) (by rw [allow_nil hdx hax]; simp) hay.2 hxy

/-! ## Monotonicity -/

/-- `c'` has every death and exclusion row of `c`, the same day, enrollment,
    released and unresolved sets and checkpoints, and each death or exclusion
    snapshot is usable exactly when it was (so the added rows are well formed
    and counted). -/
structure Grows (c c' : Ctx) : Prop where
  today : c'.today = c.today
  enrollment : c'.enrollment = c.enrollment
  released : c'.released = c.released
  unresolved : c'.unresolved = c.unresolved
  releasedPrior : c'.releasedPrior = c.releasedPrior
  unresolvedPrior : c'.unresolvedPrior = c.unresolvedPrior
  dmfOk : usable c'.today 90 okDeath c'.dmf = usable c.today 90 okDeath c.dmf
  pdOk : usable c'.today 90 okDeath c'.providerDeaths = usable c.today 90 okDeath c.providerDeaths
  exOk : usable c'.today 31 okExclusion c'.exclusions = usable c.today 31 okExclusion c.exclusions
  dmf : ∀ x ∈ entries c.dmf, x ∈ entries c'.dmf
  pd : ∀ x ∈ entries c.providerDeaths, x ∈ entries c'.providerDeaths
  ex : ∀ x ∈ entries c.exclusions, x ∈ entries c'.exclusions

theorem claim_grows {c c'} (g : Grows c c') : claim c' = claim c :=
  funext fun l => by unfold claim notEnrolled certain enrolled; rw [g.today, g.enrollment]

theorem pending_grows {c c'} (g : Grows c c') : pending c' = pending c := by
  simp only [pending, unresolvedSet, claim_grows g, g.today, g.unresolved, g.unresolvedPrior]

theorem seenAt_grows {c c'} (g : Grows c c') (b : List Line) (i : Nat) : seenAt c' b i = seenAt c b i := by
  simp only [seenAt, releasedSet, claim_grows g, g.today, g.released, g.releasedPrior]

theorem looseKeys_grows {c c'} (g : Grows c c') : looseKeys c' = looseKeys c := by
  simp only [looseKeys, g.today, g.released, g.releasedPrior, g.unresolved, g.unresolvedPrior]

theorem isSome_of_mem {α : Type} {o : Option (Snapshot α)} {x : α} (h : x ∈ entries o) : o.isSome = true := by
  cases o <;> simp_all [entries]

theorem fact_mono {c c' seen l} (g : Grows c c') : ∀ {r}, Fact c seen l r → Fact c' seen l r
  | .ALREADY_DECIDED, h | .COLLIDES_WITH_UNRESOLVED_NEAR, h | .DUPLICATE_OF_UNRESOLVED, h => by
    simpa only [Fact, pending_grows g] using h
  | .FFS_DUPLICATE_UNVERIFIED, h => by simpa only [Fact, looseKeys_grows g] using h
  | .CAP_MEMBER_MONTH_DUPLICATE, h => by simpa only [Fact, overlap, g.enrollment, g.today] using h
  | .FFS_DUPLICATE_LINE, h | .FFS_NEAR_DUPLICATE, h | .SERVICE_DATE_INVALID, h => h
  | .MEMBER_DECEASED, ⟨hu, hv, d, hd, hp⟩ => ⟨usable_iff.mp (g.dmfOk.trans (usable_iff.mpr hu)), hv, d, g.dmf d hd, hp⟩
  | .PROVIDER_DECEASED, ⟨hu, hv, d, hd, hp⟩ => ⟨usable_iff.mp (g.pdOk.trans (usable_iff.mpr hu)), hv, d, g.pd d hd, hp⟩
  | .PROVIDER_EXCLUDED, ⟨hu, hv, e, he, hp⟩ =>
    ⟨usable_iff.mp (g.exOk.trans (usable_iff.mpr hu)), hv, e, g.ex e he, hp⟩
  | .MEMBER_DECEASED_UNVERIFIED, ⟨_, hu, hv, d, hd, hp⟩ =>
    ⟨isSome_of_mem (g.dmf d hd), fun h => hu (usable_iff.mp (g.dmfOk.symm.trans (usable_iff.mpr h))), hv, d,
      g.dmf d hd, hp⟩
  | .PROVIDER_DECEASED_UNVERIFIED, ⟨_, hu, hv, d, hd, hp⟩ =>
    ⟨isSome_of_mem (g.pd d hd), fun h => hu (usable_iff.mp (g.pdOk.symm.trans (usable_iff.mpr h))), hv, d,
      g.pd d hd, hp⟩
  | .PROVIDER_EXCLUDED_UNVERIFIED, ⟨_, hu, hv, e, he, hp⟩ =>
    ⟨isSome_of_mem (g.ex e he), fun h => hu (usable_iff.mp (g.exOk.symm.trans (usable_iff.mpr h))), hv, e,
      g.ex e he, hp⟩
  | .MEMBER_NOT_ENROLLED, h | .MEMBER_NOT_ENROLLED_UNVERIFIED, h => by
    simpa only [Fact, NotCovered, g.today, g.enrollment] using h
  | .SERVICE_DATE_FUTURE, h => by simpa only [Fact, g.today] using h
  | .STALE_DMF, h => by simpa only [Fact, ← usable_iff, g.dmfOk] using h
  | .STALE_PROVIDER_DEATH, h => by simpa only [Fact, ← usable_iff, g.pdOk] using h
  | .STALE_EXCLUSION, h => by simpa only [Fact, ← usable_iff, g.exOk] using h
  | .STALE_ENROLLMENT, h => by simpa only [Fact, g.today, g.enrollment] using h
  | .STALE_RELEASED, h => by simpa only [Fact, g.today, g.released, g.releasedPrior] using h
  | .STALE_UNRESOLVED, h => by simpa only [Fact, g.today, g.unresolved, g.unresolvedPrior] using h

/-- Monotonicity, for one batch under the same day, enrollment, released and
    unresolved sets and checkpoints, and snapshot usability: adding death or
    exclusion rows never turns a held or reviewed line into ALLOW.  Claimed
    keys depend only on the day and enrollment, so line `i` is checked against
    the same keys under both contexts. -/
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
  obtain ⟨h1, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩ := h
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
    snapshots; each batch's ALLOW lines released and its other new identities
    unresolved, both read by the next batch) can change a line's decision only
    through another line sharing a key with it that is either
    (a) in an earlier batch and not ALLOW there: in one batch the later line
        is a HOLD duplicate (exact key or member-month), a reviewed near
        duplicate or `ALREADY_DECIDED`; after a split it is HOLD
        `DUPLICATE_OF_UNRESOLVED`, reviewed `COLLIDES_WITH_UNRESOLVED_NEAR` or
        `ALREADY_DECIDED`: the reason changes, the outcome does not; or
    (b) in another batch on the other side of it in canonical order: of the
        two, the one decided first is the one not flagged.
    Neither lets a line through that shares a key with an earlier batch's
    line (`later_allow_clear`), and `allowed_decideAll` holds in each batch,
    so no key is paid twice.  The split statement itself is argued here, not
    proved. -/
theorem deterministic {c b₁ b₂} (h : b₁.Perm b₂) : decideBatch c b₁ = decideBatch c b₂ := by
  simp only [decideBatch, canonical_perm h]

/-! Axiom pins: no `sorryAx`, no `Lean.ofReduceBool`. `Classical.choice` in
`deterministic` comes from core `List.le_antisymm`. -/
/-- info: 'BlindLedger.Gate.Rules.sound' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms sound
/-- info: 'BlindLedger.Gate.Rules.complete' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms complete
/-- info: 'BlindLedger.Gate.Rules.hold_complete' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms hold_complete
/-- info: 'BlindLedger.Gate.Rules.allowed_decideAll' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms allowed_decideAll
/-- info: 'BlindLedger.Gate.Rules.allow_clear' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms allow_clear
/-- info: 'BlindLedger.Gate.Rules.ids_disjoint' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms ids_disjoint
/-- info: 'BlindLedger.Gate.Rules.monotone' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms monotone
/-- info: 'BlindLedger.Gate.Rules.deterministic' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms deterministic
/-- info: 'BlindLedger.Gate.Rules.fail_closed' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms fail_closed
/-- info: 'BlindLedger.Gate.Rules.later_allow_clear' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms later_allow_clear
/-- info: 'BlindLedger.Gate.Rules.allow_clear_store' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms allow_clear_store
/-- info: 'BlindLedger.Gate.Rules.later_allow_clear_many' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms later_allow_clear_many

end BlindLedger.Gate.Rules
