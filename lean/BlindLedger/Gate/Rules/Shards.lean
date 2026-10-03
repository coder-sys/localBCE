import BlindLedger.Gate.Rules.Theorems

namespace BlindLedger.Gate.Rules

/-! Shard uniqueness (gate-shard-uniqueness-v1).  `idSeen` and `decideBatchIn` are in `Spec.lean`
    so a pinned executable need not import this module.  Here: the registry answer only adds
    `ALREADY_DECIDED` to foreign ids, and over any shards and batches one line id has one payment. -/

theorem decideBatchIn_nil (c : Ctx) (b : List Line) : decideBatchIn c [] b = decideBatch c b := by
  simp only [decideBatchIn, decideBatch, idSeen, List.map_nil, List.nil_append]

/-! ### The foreign keys change only `ALREADY_DECIDED` -/

theorem exactKey_idSeen (f : List Nat) (l : Line) : exactKey l ∉ idSeen f := by
  intro h
  obtain ⟨i, _, hi⟩ := List.mem_map.mp h
  simp only [exactKey] at hi
  split at hi <;> simp at hi

theorem nearKey_idSeen (f : List Nat) (l : Line) : nearKey l ∉ idSeen f := by
  intro h
  obtain ⟨i, _, hi⟩ := List.mem_map.mp h
  simp only [nearKey] at hi
  split at hi <;> simp at hi

theorem idKey_idSeen {f : List Nat} {l : Line} : idKey l ∈ idSeen f ↔ l.id ∈ f := by
  simp [idKey, idSeen]

theorem fact_idSeen {c : Ctx} {a s : List Key} {f : List Nat} {l : Line} (r : Reason) :
    Fact c (a ++ (idSeen f ++ s)) l r ↔ Fact c (a ++ s) l r ∨ (r = .ALREADY_DECIDED ∧ l.id ∈ f) := by
  have hE : exactKey l ∈ a ++ (idSeen f ++ s) ↔ exactKey l ∈ a ++ s := by
    simp [List.mem_append, exactKey_idSeen]
  have hN : nearKey l ∈ a ++ (idSeen f ++ s) ↔ nearKey l ∈ a ++ s := by
    simp [List.mem_append, nearKey_idSeen]
  have hI : idKey l ∈ a ++ (idSeen f ++ s) ↔ idKey l ∈ a ++ s ∨ l.id ∈ f := by
    simp only [List.mem_append, idKey_idSeen]; grind
  cases r <;> simp only [Fact, hE, hN, hI] <;> simp <;> grind

theorem fires_in {c : Ctx} {a s : List Key} {f : List Nat} {l : Line} (x : Reason) :
    fires c (a ++ (idSeen f ++ s)) l x =
      ((decideLine c (a ++ s) l).reasons.contains x || (x == .ALREADY_DECIDED && f.contains l.id)) := by
  rw [Bool.eq_iff_iff, fires_iff, fact_idSeen]
  simp only [Bool.or_eq_true, Bool.and_eq_true, List.contains_iff_mem, mem_decideLine, beq_iff_eq]

theorem decideLine_in {c : Ctx} {a s : List Key} {f : List Nat} {l : Line} :
    (decideLine c (a ++ (idSeen f ++ s)) l).reasons =
      reasons.filter fun r => (decideLine c (a ++ s) l).reasons.contains r ||
        (r == .ALREADY_DECIDED && f.contains l.id) :=
  List.filter_congr fun x _ => fires_in x

/-- No relaxation: the registry answer adds ALREADY_DECIDED to foreign ids and changes nothing
    else, line by line. -/
theorem decideBatchIn_reasons (c : Ctx) (f : List Nat) (b : List Line) (i : Nat) :
    ((decideBatchIn c f b).decisions[i]?).map (·.line) = ((decideBatch c b).decisions[i]?).map (·.line) ∧
    ((decideBatchIn c f b).decisions[i]?).map (·.reasons) =
      ((decideBatch c b).decisions[i]?).map fun d =>
        reasons.filter fun r => d.reasons.contains r || (r == .ALREADY_DECIDED && f.contains d.line.id) := by
  have e1 : (decideBatchIn c f b).decisions[i]? = (order c b)[i]?.map
      (decideLine c (((order c b).take i).reverse.flatMap (claim c) ++ (idSeen f ++ seen0 c b))) :=
    decideAll_get c _ _ i
  have e0 : (decideBatch c b).decisions[i]? = (order c b)[i]?.map
      (decideLine c (((order c b).take i).reverse.flatMap (claim c) ++ seen0 c b)) :=
    decideAll_get c _ _ i
  rw [e1, e0]
  cases (order c b)[i]? with
  | none => exact ⟨rfl, rfl⟩
  | some l => exact ⟨rfl, congrArg some decideLine_in⟩

/-! ### The registry -/

/-- The registry: (id, owner shard), newest first; an id's first reservation is final. -/
def reserve1 (r : List (Nat × Nat)) (k i : Nat) : List (Nat × Nat) :=
  if (r.lookup i).isSome then r else (i, k) :: r

def reserve (r : List (Nat × Nat)) (k : Nat) (ids : List Nat) : List (Nat × Nat) :=
  ids.foldl (reserve1 · k ·) r

def foreign (r : List (Nat × Nat)) (k : Nat) (ids : List Nat) : List Nat :=
  ids.filter fun i => r.lookup i != some k

theorem reserve1_keeps {r : List (Nat × Nat)} {k i o j : Nat} (h : r.lookup i = some o) :
    (reserve1 r k j).lookup i = some o := by
  unfold reserve1; split
  · exact h
  · rename_i hn
    have hji : (i == j) = false := by
      cases hb : (i == j)
      · rfl
      · have := eq_of_beq hb; subst this; simp [h] at hn
    simp [List.lookup, hji, h]

theorem reserve1_covers {r : List (Nat × Nat)} {k j : Nat} : ((reserve1 r k j).lookup j).isSome = true := by
  unfold reserve1; split
  · assumption
  · simp [List.lookup]

theorem reserve_keeps {r : List (Nat × Nat)} {k i o : Nat} {ids : List Nat}
    (h : r.lookup i = some o) : (reserve r k ids).lookup i = some o := by
  induction ids generalizing r with
  | nil => exact h
  | cons j ids ih => exact ih (reserve1_keeps h)

theorem reserve_covers {r : List (Nat × Nat)} {k i : Nat} {ids : List Nat}
    (h : i ∈ ids) : ((reserve r k ids).lookup i).isSome = true := by
  induction ids generalizing r with
  | nil => cases h
  | cons j ids ih =>
    rcases List.mem_cons.mp h with hij | h
    · obtain ⟨o, ho⟩ := Option.isSome_iff_exists.mp (reserve1_covers (r := r) (k := k) (j := j))
      subst hij
      have := reserve_keeps (r := reserve1 r k i) (k := k) (ids := ids) ho
      show ((reserve (reserve1 r k i) k ids).lookup i).isSome = true
      simp [this]
    · exact ih h

theorem foreign_complete {r : List (Nat × Nat)} {k i : Nat} {ids : List Nat} (h : i ∈ ids)
    (ho : r.lookup i ≠ some k) : i ∈ foreign r k ids :=
  List.mem_filter.mpr ⟨h, by simpa using ho⟩

/-! ### One payment per line across shards -/

theorem released_iff_in {c : Ctx} {f : List Nat} {b : List Line} {x : Line} :
    x ∈ (decideBatchIn c f b).released.entries ↔ x ∈ releasedSet c ∨
      ∃ d ∈ (decideBatchIn c f b).decisions, d.line = x ∧ c.redo.contains x.pay = false ∧
        payOutcome c (decideBatchIn c f b).decisions x.pay = .ALLOW := by
  change x ∈ releasedSet c ++ releasedLines c (decideBatchIn c f b).decisions ↔ _
  rw [List.mem_append]
  refine or_congr_right ⟨fun h => ?_, ?_⟩
  · obtain ⟨hx, hc⟩ := List.mem_filter.mp h
    obtain ⟨d, hd, rfl⟩ := List.mem_map.mp hx
    simp only [Bool.and_eq_true, Bool.not_eq_true', beq_iff_eq] at hc
    exact ⟨d, (List.mem_filter.mp hd).1, rfl, hc.1, hc.2⟩
  · rintro ⟨d, hd, rfl, hr, hp⟩
    exact List.mem_filter.mpr ⟨List.mem_map.mpr ⟨d, List.mem_filter.mpr
      ⟨hd, by simp [(payOutcome_allow hp hd rfl).1]⟩, rfl⟩, by rw [hr, hp]; rfl⟩

theorem seen_all_in {c f b e} (he : e ∈ (decideBatchIn c f b).decisions) (ho : own c e.line = false) :
    ∃ seen, e = decideLine c seen e.line ∧ ∀ x ∈ releasedSet c, ∀ k ∈ keys x, k ∈ seen := by
  change e ∈ decideAll c (idSeen f ++ seen0 c b) (order c b) at he
  rw [order, decideAll_append, List.mem_append] at he
  rcases he with he | he
  · have hl : e.line ∈ canonical (b.filter (own c)) := by
      rw [← lines_decideAll c (idSeen f ++ seen0 c b) (canonical (b.filter (own c)))]
      exact List.mem_map.mpr ⟨e, he, rfl⟩
    have := (List.mem_filter.mp ((List.mergeSort_perm _ _).mem_iff.mp hl)).2
    rw [ho] at this; cases this
  · obtain ⟨pre, l, rfl⟩ := mem_decideAll he
    refine ⟨_, rfl, fun x hx k hk => List.mem_append_right _ ?_⟩
    by_cases hob : own c x = true ∧ x ∈ b
    · refine List.mem_append_left _ (List.mem_flatMap.mpr ⟨x, List.mem_reverse.mpr
        ((List.mergeSort_perm _ _).mem_iff.mpr (List.mem_filter.mpr ⟨hob.2, hob.1⟩)), ?_⟩)
      have hc : claim c x = keys x := by simp [claim, hob.1]
      rwa [hc]
    · exact List.mem_append_right _ (List.mem_append_right _
        (List.mem_flatMap.mpr ⟨x, List.mem_filter.mpr ⟨hx, not_own_mem hob⟩, hk⟩))

theorem one_payment_per_line_in {c : Nat → Ctx} {b : Nat → List Line} {f : Nat → List Nat}
    (hv : ∀ k, releasedSet (c (k + 1)) = (decideBatchIn (c k) (f k) (b k)).released.entries)
    (hn : ∀ k, ((releasedSet (c k)).map (·.id)).Nodup) {i j : Nat} (hij : i ≤ j) {d e : Decision}
    (hd : d ∈ (decideBatchIn (c i) (f i) (b i)).decisions)
    (hpd : payOutcome (c i) (decideBatchIn (c i) (f i) (b i)).decisions d.line.pay = .ALLOW)
    (he : e ∈ (decideBatchIn (c j) (f j) (b j)).decisions)
    (hpe : payOutcome (c j) (decideBatchIn (c j) (f j) (b j)).decisions e.line.pay = .ALLOW)
    (hid : d.line.id = e.line.id) : d.line.pay = e.line.pay := by
  have hdo := payOutcome_allow hpd hd rfl
  have heo := payOutcome_allow hpe he rfl
  have hk : idKey e.line = idKey d.line := by simp [idKey, hid]
  rcases Nat.lt_or_eq_of_le hij with hlt | rfl
  · have hx : d.line ∈ releasedSet (c (i + 1)) := by
      rw [hv i, released_iff_in]
      by_cases hr : (c i).redo.contains d.line.pay = true
      · have := (hdo.2 hr)
        simp only [own, Bool.and_eq_true] at this
        exact Or.inl (by simpa using this.2)
      · exact Or.inr ⟨d, hd, rfl, Bool.eq_false_iff.mpr hr, hpd⟩
    have hgrow : ∀ n, d.line ∈ releasedSet (c (i + 1 + n)) := fun n => by
      induction n with
      | zero => exact hx
      | succ n ih => rw [← Nat.add_assoc, hv]; exact List.mem_append_left _ ih
    have hxj : d.line ∈ releasedSet (c j) := by
      obtain ⟨n, rfl⟩ := Nat.exists_eq_add_of_lt hlt
      have := hgrow n
      rwa [show i + n + 1 = i + 1 + n by omega]
    by_cases hown : own (c j) e.line = true
    · have hy : e.line ∈ releasedSet (c j) := by
        simp only [own, Bool.and_eq_true] at hown
        simpa using hown.2
      rw [map_nodup_inj (hn j) hxj hy hid]
    · obtain ⟨seen, hde, hall⟩ := seen_all_in he (Bool.eq_false_iff.mpr hown)
      have hs : seen.contains (idKey e.line) = true := by
        simpa [hk] using hall d.line hxj (idKey d.line) idKey_mem
      exact (fires_blocks (c := c j) (seen := seen) (l := e.line) (r := .ALREADY_DECIDED)
        (by simp only [fires, hs, Bool.true_or]) (by rw [← hde]; exact heo.1)).elim
  · have hnd : ((allowedLines (decideBatchIn (c i) (f i) (b i)).decisions).flatMap keys).Nodup :=
      (allowed_decideAll (c i) (idSeen (f i) ++ seen0 (c i) (b i)) (order (c i) (b i))).1
    have hmem : ∀ {z : Decision}, z ∈ (decideBatchIn (c i) (f i) (b i)).decisions → z.outcome = .ALLOW →
        z.line ∈ allowedLines (decideBatchIn (c i) (f i) (b i)).decisions := fun hz ha =>
      List.mem_map.mpr ⟨_, List.mem_filter.mpr ⟨hz, by simp [ha]⟩, rfl⟩
    rw [flatMap_nodup_inj hnd (hmem hd hdo.1) (hmem he heo.1) (idKey_mem (l := d.line))
      (hk ▸ idKey_mem (l := e.line))]

theorem idKey_mem_idSeen {f : List Nat} {l : Line} (h : l.id ∈ f) : idKey l ∈ idSeen f :=
  idKey_idSeen.mpr h

/-- A line the registry does not give shard `k` is in `f`, so it is not ALLOW there. -/
theorem allow_owner {reg : Nat → Option Nat} {c : Ctx} {f : List Nat} {b : List Line} {k : Nat} {d : Decision}
    (hf : ∀ l ∈ b, reg l.id ≠ some k → l.id ∈ f)
    (hd : d ∈ (decideBatchIn c f b).decisions) (ha : d.outcome = .ALLOW) : reg d.line.id = some k := by
  have hd' : d ∈ decideAll c (idSeen f ++ seen0 c b) (order c b) := hd
  have hl : d.line ∈ order c b := by
    rw [← lines_decideAll c (idSeen f ++ seen0 c b) (order c b)]; exact List.mem_map.mpr ⟨d, hd', rfl⟩
  have hb := (order_perm c b).mem_iff.mp hl
  refine Classical.byContradiction fun hne => ?_
  exact (fresh_unseen hd' (by rw [allow_nil hd' ha]; simp)).1
    (List.mem_append_left _ (idKey_mem_idSeen (hf d.line hb hne)))

/-- No line id is in two shards' sets (released or unresolved, hence never paid by two shards).
    `hk`, `hk'` say each shard's sets hold only ids the registry gives it. -/
theorem no_id_two_shards {reg : Nat → Option Nat} {c : Nat → Nat → Ctx} {k k' i j : Nat} {x y : Line}
    (hk : ∀ x ∈ releasedSet (c k i) ++ unresolvedSet (c k i), reg x.id = some k)
    (hk' : ∀ y ∈ releasedSet (c k' j) ++ unresolvedSet (c k' j), reg y.id = some k')
    (hx : x ∈ releasedSet (c k i) ++ unresolvedSet (c k i))
    (hy : y ∈ releasedSet (c k' j) ++ unresolvedSet (c k' j)) (hid : x.id = y.id) : k = k' := by
  have h1 := hk x hx
  have h2 := hk' y hy
  rw [hid] at h1
  rw [h1] at h2
  exact Option.some.inj h2

/-- Headline: two ALLOW decisions of one line id, in any shards and batches of a tenant, are the
    same shard and the same payment. -/
theorem one_payment_per_line_sharded {reg : Nat → Option Nat} {c : Nat → Nat → Ctx}
    {b : Nat → Nat → List Line} {f : Nat → Nat → List Nat}
    (hr : ∀ k j, releasedSet (c k (j + 1)) = (decideBatchIn (c k j) (f k j) (b k j)).released.entries)
    (hn : ∀ k j, ((releasedSet (c k j)).map (·.id)).Nodup)
    (hf : ∀ k j, ∀ l ∈ b k j, reg l.id ≠ some k → l.id ∈ f k j)
    {k k' i j : Nat} {d e : Decision}
    (hd : d ∈ (decideBatchIn (c k i) (f k i) (b k i)).decisions)
    (hpd : payOutcome (c k i) (decideBatchIn (c k i) (f k i) (b k i)).decisions d.line.pay = .ALLOW)
    (he : e ∈ (decideBatchIn (c k' j) (f k' j) (b k' j)).decisions)
    (hpe : payOutcome (c k' j) (decideBatchIn (c k' j) (f k' j) (b k' j)).decisions e.line.pay = .ALLOW)
    (hid : d.line.id = e.line.id) : k = k' ∧ d.line.pay = e.line.pay := by
  have hdo := payOutcome_allow hpd hd rfl
  have heo := payOutcome_allow hpe he rfl
  have hkk : k = k' := by
    have h1 := allow_owner (hf k i) hd hdo.1
    have h2 := allow_owner (hf k' j) he heo.1
    rw [hid] at h1; rw [h1] at h2; exact Option.some.inj h2
  subst hkk
  refine ⟨rfl, ?_⟩
  rcases Nat.le_total i j with hij | hij
  · exact one_payment_per_line_in (hr k) (hn k) hij hd hpd he hpe hid
  · exact (one_payment_per_line_in (hr k) (hn k) hij he hpe hd hpd hid.symm).symm

/-! Axiom pins. -/
/-- info: 'BlindLedger.Gate.Rules.decideBatchIn_reasons' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms decideBatchIn_reasons
/-- info: 'BlindLedger.Gate.Rules.one_payment_per_line_in' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms one_payment_per_line_in
/-- info: 'BlindLedger.Gate.Rules.no_id_two_shards' does not depend on any axioms -/
#guard_msgs in #print axioms no_id_two_shards
/-- info: 'BlindLedger.Gate.Rules.one_payment_per_line_sharded' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms one_payment_per_line_sharded

end BlindLedger.Gate.Rules
