import BlindLedger.Gate.Rules.Theorems

namespace BlindLedger.Gate.Rules

/-! Shard uniqueness (gate-shard-uniqueness-v1).  `idSeen` and `decideBatchIn` are in `Spec.lean`
    so a pinned executable need not import this module.  Here: the registry answer only adds
    `ALREADY_DECIDED` to foreign ids, a shard fed the ids it does not own holds only its own ids, and
    so over any shards and batches one line id has one payment. -/

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

/-! ### Ownership: what a shard releases or holds, the registry gave it -/

/-- A line of the batch that the registry does not give shard `k` is in `f`, so it is not fresh. -/
theorem fresh_owner {reg : Nat → Option Nat} {c : Ctx} {f : List Nat} {b : List Line} {k : Nat} {d : Decision}
    (hf : ∀ l ∈ b, reg l.id ≠ some k → l.id ∈ f)
    (hd : d ∈ (decideBatchIn c f b).decisions) (fe : Reason.ALREADY_DECIDED ∉ d.reasons) :
    reg d.line.id = some k := by
  have hd' : d ∈ decideAll c (idSeen f ++ seen0 c b) (order c b) := hd
  have hl : d.line ∈ order c b := by
    rw [← lines_decideAll c (idSeen f ++ seen0 c b) (order c b)]; exact List.mem_map.mpr ⟨d, hd', rfl⟩
  have hb := (order_perm c b).mem_iff.mp hl
  refine Classical.byContradiction fun hne => ?_
  exact (fresh_unseen hd' fe).1 (List.mem_append_left _ (idKey_idSeen.mpr (hf d.line hb hne)))

theorem allow_owner {reg : Nat → Option Nat} {c : Ctx} {f : List Nat} {b : List Line} {k : Nat} {d : Decision}
    (hf : ∀ l ∈ b, reg l.id ≠ some k → l.id ∈ f)
    (hd : d ∈ (decideBatchIn c f b).decisions) (ha : d.outcome = .ALLOW) : reg d.line.id = some k :=
  fresh_owner hf hd (by
    rw [allow_nil (show d ∈ decideAll c (idSeen f ++ seen0 c b) (order c b) from hd) ha]; simp)

/-- The next released set holds the last one's rows and rows of shard `k`. -/
theorem released_owner {reg : Nat → Option Nat} {c : Ctx} {f : List Nat} {b : List Line} {k : Nat}
    (hf : ∀ l ∈ b, reg l.id ≠ some k → l.id ∈ f) {x : Line}
    (hx : x ∈ (decideBatchIn c f b).released.entries) : x ∈ releasedSet c ∨ reg x.id = some k := by
  change x ∈ releasedSet c ++ releasedLines c (decideBatchIn c f b).decisions at hx
  rcases List.mem_append.mp hx with h | h
  · exact Or.inl h
  · obtain ⟨d, hd, rfl⟩ := List.mem_map.mp (List.mem_filter.mp h).1
    obtain ⟨hd, ha⟩ := List.mem_filter.mp hd
    exact Or.inr (allow_owner hf hd (by simpa using ha))

/-- Likewise the unresolved set. -/
theorem unresolved_owner {reg : Nat → Option Nat} {c : Ctx} {f : List Nat} {b : List Line} {k : Nat}
    (hf : ∀ l ∈ b, reg l.id ≠ some k → l.id ∈ f) {x : Line}
    (hx : x ∈ (decideBatchIn c f b).unresolved.entries) : x ∈ unresolvedSet c ∨ reg x.id = some k := by
  change x ∈ unresolvedSet c ++ unresolvedLines c (decideBatchIn c f b).decisions at hx
  rcases List.mem_append.mp hx with h | h
  · exact Or.inl h
  · obtain ⟨d, hd, rfl⟩ := List.mem_map.mp h
    obtain ⟨hd, hq⟩ := List.mem_filter.mp hd
    refine Or.inr (fresh_owner hf hd fun hm => ?_)
    simp only [Bool.and_eq_true, Bool.not_eq_true'] at hq
    rw [List.contains_iff_mem.mpr hm] at hq
    cases hq.1.2

/-- A set that starts with rows of shard `k` and grows by rows of shard `k` holds only those. -/
theorem chain_all {α : Type} {P : α → Prop} {S : Nat → List α} (h0 : ∀ x ∈ S 0, P x)
    (hs : ∀ j, ∀ x ∈ S (j + 1), x ∈ S j ∨ P x) : ∀ j, ∀ x ∈ S j, P x
  | 0 => h0
  | j + 1 => fun x hx => (hs j x hx).elim (chain_all h0 hs j x) id

/-! ### Nodup is kept, so it is assumed once -/

theorem ids_nodup_of_keys {L : List Line} (h : (L.flatMap keys).Nodup) : (L.map (·.id)).Nodup := by
  induction L with
  | nil => simp
  | cons a L ih =>
    rw [List.flatMap_cons, List.nodup_append] at h
    rw [List.map_cons, List.nodup_cons]
    refine ⟨fun hm => ?_, ih h.2.1⟩
    obtain ⟨y, hy, hyi⟩ := List.mem_map.mp hm
    exact h.2.2 _ (idKey_mem (l := a)) _ (List.mem_flatMap.mpr ⟨y, hy, by
      rw [show idKey a = idKey y by simp [idKey, hyi]]; exact idKey_mem⟩) rfl

theorem released_nodup {c : Ctx} {f : List Nat} {b : List Line}
    (hn : ((releasedSet c).map (·.id)).Nodup) :
    (((decideBatchIn c f b).released.entries).map (·.id)).Nodup := by
  change ((releasedSet c ++ releasedLines c (decideBatchIn c f b).decisions).map (·.id)).Nodup
  rw [List.map_append, List.nodup_append]
  refine ⟨hn, ?_, ?_⟩
  · exact (ids_nodup_of_keys (allowed_decideAll c (idSeen f ++ seen0 c b) (order c b)).1).sublist
      (List.filter_sublist.map _)
  · intro i hi j hj hij
    obtain ⟨y, hy, rfl⟩ := List.mem_map.mp hi
    obtain ⟨z, hz, rfl⟩ := List.mem_map.mp hj
    obtain ⟨hz1, hz2⟩ := List.mem_filter.mp hz
    obtain ⟨e, he, rfl⟩ := List.mem_map.mp hz1
    obtain ⟨he, ha⟩ := List.mem_filter.mp he
    have hown : own c e.line = false := by
      simp only [Bool.and_eq_true, Bool.not_eq_true'] at hz2
      simp only [own, hz2.1, Bool.false_and]
    obtain ⟨seen, hde, hall⟩ := seen_all_in he hown
    have hs : seen.contains (idKey e.line) = true := by
      have hk : idKey e.line = idKey y := by simp [idKey, hij]
      simpa [hk] using hall y hy (idKey y) idKey_mem
    exact fires_blocks (c := c) (seen := seen) (l := e.line) (r := .ALREADY_DECIDED)
      (by simp only [fires, hs, Bool.true_or]) (by rw [← hde]; simpa using ha)

/-! ### One payment per line across shards -/

/-- The rows after a batch: the last rows, and each ALLOW payment's lines. -/
theorem row_next {c : Ctx} {f : List Nat} {b : List Line} {x : Line}
    (hx : x ∈ releasedSet c ∨ ∃ d ∈ (decideBatchIn c f b).decisions, d.line = x ∧
      payOutcome c (decideBatchIn c f b).decisions x.pay = .ALLOW) :
    x ∈ (decideBatchIn c f b).released.entries := by
  change x ∈ releasedSet c ++ releasedLines c (decideBatchIn c f b).decisions
  rcases hx with h | ⟨d, hd, rfl, hp⟩
  · exact List.mem_append_left _ h
  · have hdo := payOutcome_allow hp hd rfl
    by_cases hr : c.redo.contains d.line.pay = true
    · have := hdo.2 hr
      simp only [own, Bool.and_eq_true] at this
      exact List.mem_append_left _ (by simpa using this.2)
    · exact List.mem_append_right _ (List.mem_filter.mpr ⟨List.mem_map.mpr ⟨d, List.mem_filter.mpr
        ⟨hd, by simp [hdo.1]⟩, rfl⟩, by rw [Bool.eq_false_iff.mpr hr, hp]; rfl⟩)

/-- Headline: over any shards and batches of a tenant whose registry feeds each shard the ids it does
    not own, a released row or ALLOW decision of one line id is the same shard and the same line.
    Nodup is assumed at batch 0 only; each batch keeps it (`released_nodup`). -/
theorem one_payment_per_line_sharded {reg : Nat → Option Nat} {c : Nat → Nat → Ctx}
    {b : Nat → Nat → List Line} {f : Nat → Nat → List Nat}
    (hr : ∀ k j, releasedSet (c k (j + 1)) = (decideBatchIn (c k j) (f k j) (b k j)).released.entries)
    (hf : ∀ k j, ∀ l ∈ b k j, reg l.id ≠ some k → l.id ∈ f k j)
    (h0 : ∀ k, ∀ x ∈ releasedSet (c k 0), reg x.id = some k)
    (hn : ∀ k, ((releasedSet (c k 0)).map (·.id)).Nodup)
    {k k' i j : Nat} {x y : Line}
    (hx : x ∈ releasedSet (c k i) ∨ ∃ d ∈ (decideBatchIn (c k i) (f k i) (b k i)).decisions, d.line = x ∧
      payOutcome (c k i) (decideBatchIn (c k i) (f k i) (b k i)).decisions x.pay = .ALLOW)
    (hy : y ∈ releasedSet (c k' j) ∨ ∃ d ∈ (decideBatchIn (c k' j) (f k' j) (b k' j)).decisions, d.line = y ∧
      payOutcome (c k' j) (decideBatchIn (c k' j) (f k' j) (b k' j)).decisions y.pay = .ALLOW)
    (hid : x.id = y.id) : k = k' ∧ x = y := by
  have hx' : x ∈ releasedSet (c k (i + 1)) := by rw [hr]; exact row_next hx
  have hy' : y ∈ releasedSet (c k' (j + 1)) := by rw [hr]; exact row_next hy
  have own_ch : ∀ k, ∀ m, ∀ z ∈ releasedSet (c k m), reg z.id = some k := fun k =>
    chain_all (h0 k) fun j z hz => by rw [hr] at hz; exact released_owner (hf k j) hz
  have h1 := own_ch k _ x hx'
  have h2 := own_ch k' _ y hy'
  rw [hid] at h1; rw [h1] at h2
  obtain rfl := Option.some.inj h2
  have grow : ∀ m n, ∀ z ∈ releasedSet (c k m), z ∈ releasedSet (c k (m + n)) := fun m n z hz => by
    induction n with
    | zero => exact hz
    | succ n ih => rw [← Nat.add_assoc, hr]; exact row_next (Or.inl ih)
  have hnd : ∀ m, ((releasedSet (c k m)).map (·.id)).Nodup := fun m => by
    induction m with
    | zero => exact hn k
    | succ m ih => rw [hr]; exact released_nodup ih
  have hyN : y ∈ releasedSet (c k ((i + 1) + (j + 1))) := by
    have := grow (j + 1) (i + 1) y hy'
    rwa [Nat.add_comm (j + 1)] at this
  exact ⟨rfl, map_nodup_inj (hnd _) (grow (i + 1) (j + 1) x hx') hyN hid⟩

/-- No line id is in two shards' released or unresolved sets, at any batches. -/
theorem no_id_two_shards {reg : Nat → Option Nat} {c : Nat → Nat → Ctx}
    {b : Nat → Nat → List Line} {f : Nat → Nat → List Nat}
    (hr : ∀ k j, releasedSet (c k (j + 1)) = (decideBatchIn (c k j) (f k j) (b k j)).released.entries)
    (hu : ∀ k j, unresolvedSet (c k (j + 1)) = (decideBatchIn (c k j) (f k j) (b k j)).unresolved.entries)
    (hf : ∀ k j, ∀ l ∈ b k j, reg l.id ≠ some k → l.id ∈ f k j)
    (h0 : ∀ k, ∀ x ∈ releasedSet (c k 0) ++ unresolvedSet (c k 0), reg x.id = some k)
    {k k' i j : Nat} {x y : Line}
    (hx : x ∈ releasedSet (c k i) ++ unresolvedSet (c k i))
    (hy : y ∈ releasedSet (c k' j) ++ unresolvedSet (c k' j)) (hid : x.id = y.id) : k = k' := by
  have own_ch : ∀ k, ∀ m, ∀ z ∈ releasedSet (c k m) ++ unresolvedSet (c k m), reg z.id = some k := fun k =>
    chain_all (h0 k) fun j z hz => by
      rcases List.mem_append.mp hz with h | h
      · rw [hr] at h
        exact (released_owner (hf k j) h).elim (fun h => Or.inl (List.mem_append_left _ h)) Or.inr
      · rw [hu] at h
        exact (unresolved_owner (hf k j) h).elim (fun h => Or.inl (List.mem_append_right _ h)) Or.inr
  have h1 := own_ch k _ x hx
  have h2 := own_ch k' _ y hy
  rw [hid] at h1; rw [h1] at h2
  exact Option.some.inj h2

/-! Axiom pins. -/
/-- info: 'BlindLedger.Gate.Rules.decideBatchIn_reasons' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms decideBatchIn_reasons
/-- info: 'BlindLedger.Gate.Rules.no_id_two_shards' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms no_id_two_shards
/-- info: 'BlindLedger.Gate.Rules.one_payment_per_line_sharded' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms one_payment_per_line_sharded

end BlindLedger.Gate.Rules
