import BlindLedger.Gate.Rules.Theorems
import BlindLedger.Gate.Rules.Fast
import BlindLedger.Gate.Rules.Run
import BlindLedger.Gate.Anchor

/-! Proves `Fast.decideBatchF` equal to `Spec.decideBatch` (and `pinBytes` to `pinInput`), plus its order laws; not imported by the runner, so a mutant of `Fast.lean` still builds `gate_rules`. -/

namespace BlindLedger.Gate.Rules.Fast

open BlindLedger.Gate.Rules
open Std (HashMap HashSet)

/-! ## Primitives -/

theorem group_aux {α : Type} (key : α → Nat) (xs : List α) :
    ∀ (m : HashMap Nat (List α)) (k : Nat) (x : α),
      x ∈ (xs.foldl (fun m x => m.insert (key x) (x :: m.getD (key x) [])) m).getD k [] ↔
        x ∈ m.getD k [] ∨ (x ∈ xs ∧ key x = k) := by
  induction xs with
  | nil => intro m k x; simp
  | cons a t ih =>
    intro m k x
    rw [List.foldl_cons, ih]
    by_cases h : key a = k
    · subst h
      simp only [HashMap.getD_insert, beq_self_eq_true, if_true, List.mem_cons]
      constructor
      · rintro ((rfl | h) | h) <;> simp_all
      · rintro (h | ⟨rfl | h, h2⟩) <;> simp_all
    · simp only [HashMap.getD_insert, beq_iff_eq, h, if_false, List.mem_cons]
      constructor
      · rintro (h1 | ⟨h1, h2⟩)
        · exact Or.inl h1
        · exact Or.inr ⟨Or.inr h1, h2⟩
      · rintro (h1 | ⟨rfl | h1, h2⟩)
        · exact Or.inl h1
        · exact absurd h2 h
        · exact Or.inr ⟨h1, h2⟩

theorem mem_group {α : Type} {key : α → Nat} {xs : List α} {k : Nat} {x : α} :
    x ∈ (group key xs).getD k [] ↔ x ∈ xs ∧ key x = k := by
  simp [group, group_aux]

theorem posts_count_aux (xs : List Line) : ∀ (m : HashMap Key (List Nat)) (n : Nat),
    (xs.foldl postStep (m, n)).2 = n + xs.length := by
  induction xs with
  | nil => intro m n; simp
  | cons a t ih => intro m n; rw [List.foldl_cons, ih]; simp [postStep]; omega

theorem posts_count (xs : List Line) : (posts xs).2 = xs.length := by
  simp [posts, posts_count_aux]

theorem inner_aux (n : Nat) (ks : List Key) :
    ∀ (m : HashMap Key (List Nat)) (k : Key) (i : Nat),
      i ∈ (ks.foldl (fun m k => m.insert k (n :: m.getD k [])) m).getD k [] ↔
        i ∈ m.getD k [] ∨ (i = n ∧ k ∈ ks) := by
  induction ks with
  | nil => intro m k i; simp
  | cons a t ih =>
    intro m k i
    rw [List.foldl_cons, ih]
    by_cases h : a = k
    · subst h
      simp only [HashMap.getD_insert, beq_self_eq_true, if_true, List.mem_cons]
      constructor
      · rintro ((rfl | h) | h) <;> simp_all
      · rintro (h | ⟨rfl, h2⟩) <;> simp_all
    · simp only [HashMap.getD_insert, beq_iff_eq, h, if_false, List.mem_cons]
      constructor
      · rintro (h1 | ⟨h1, h2⟩)
        · exact Or.inl h1
        · exact Or.inr ⟨h1, Or.inr h2⟩
      · rintro (h1 | ⟨h1, rfl | h2⟩)
        · exact Or.inl h1
        · exact absurd rfl h
        · exact Or.inr ⟨h1, h2⟩

theorem idx_shift {α : Type} {a : α} {t : List α} {d i : Nat} (h : d < i) :
    (a :: t)[i - d]? = t[i - (d + 1)]? := by
  have : i - d = (i - (d + 1)) + 1 := by omega
  rw [this]; simp

theorem posts_aux (xs : List Line) : ∀ (m : HashMap Key (List Nat)) (n : Nat) (k : Key) (i : Nat),
    i ∈ ((xs.foldl postStep (m, n)).1).getD k [] ↔
      i ∈ m.getD k [] ∨ (n ≤ i ∧ ∃ y, xs[i - n]? = some y ∧ k ∈ keys y) := by
  induction xs with
  | nil => intro m n k i; simp
  | cons a t ih =>
    intro m n k i
    rw [List.foldl_cons]
    have e : postStep (m, n) a = ((keys a).foldl (fun m k => m.insert k (n :: m.getD k [])) m, n + 1) := rfl
    rw [e, ih, inner_aux]
    rcases Nat.lt_trichotomy i n with h | rfl | h
    · have h1 : ¬ (n + 1 ≤ i) := by omega
      have h2 : ¬ (n ≤ i) := by omega
      have h3 : i ≠ n := by omega
      simp [h1, h2, h3]
    · have h1 : ¬ (i + 1 ≤ i) := by omega
      simp [h1]
    · have h1 : n + 1 ≤ i := h
      have h2 : i ≠ n := by omega
      rw [idx_shift h]
      simp [h1, h2, Nat.le_of_lt h]

/-- The positions of `k` as a membership statement (`mem_posts` below, with the row named). -/
theorem mem_posts' {xs : List Line} {k : Key} {i : Nat} :
    i ∈ (posts xs).1.getD k [] ↔ ∃ y, xs[i]? = some y ∧ k ∈ keys y := by
  simp [posts, posts_aux]

theorem mem_posts {xs : List Line} {k : Key} {i : Nat} :
    i ∈ (posts xs).1.getD k [] ↔ ∃ h : i < xs.length, k ∈ keys xs[i] := by
  rw [mem_posts']
  simp only [List.getElem?_eq_some_iff]
  constructor
  · rintro ⟨y, ⟨h, rfl⟩, hk⟩; exact ⟨h, hk⟩
  · rintro ⟨h, hk⟩; exact ⟨_, ⟨h, rfl⟩, hk⟩

/-- The incremental form a persistent writer uses (layer 2): `List.foldl_append`. -/
theorem posts_append (xs ys : List Line) : posts (xs ++ ys) = ys.foldl postStep (posts xs) := by
  simp [posts, List.foldl_append]

theorem mem_dedup {l : List Nat} {i : Nat} : i ∈ dedup l ↔ i ∈ l := by
  induction l using dedup.induct with
  | case1 a b rest hab ih =>
    simp only [dedup, hab, if_true]
    rw [ih]; simp at hab; simp [hab]
  | case2 a b rest hab ih =>
    simp [dedup, hab, ih]
  | case3 t h =>
    rcases t with _ | ⟨a, _ | ⟨b, r⟩⟩
    · simp [dedup]
    · simp [dedup]
    · exact absurd rfl (h a b r)

theorem pairwise_dedup {l : List Nat} (h : l.Pairwise (· ≤ ·)) : (dedup l).Pairwise (· < ·) := by
  induction l using dedup.induct with
  | case1 a b rest hab ih =>
    simp only [dedup, hab, if_true]
    exact ih (List.pairwise_cons.mp h).2
  | case2 a b rest hab ih =>
    simp only [dedup, hab]
    have hp := List.pairwise_cons.mp h
    have hp2 := List.pairwise_cons.mp hp.2
    refine List.pairwise_cons.mpr ⟨fun y hy => ?_, ih hp.2⟩
    have hy' : y ∈ b :: rest := mem_dedup.mp hy
    have hab' : a ≤ b := hp.1 b (List.mem_cons_self ..)
    have hne : a ≠ b := by simpa using hab
    rcases List.mem_cons.mp hy' with rfl | hr
    · omega
    · have := hp2.1 y hr
      omega
  | case3 t h' =>
    rcases t with _ | ⟨a, _ | ⟨b, r⟩⟩
    · simp [dedup]
    · simp [dedup]
    · exact absurd rfl (h' a b r)

theorem fm_congr {α β : Type} {f g : α → Option β} :
    ∀ {l : List α}, (∀ x ∈ l, f x = g x) → l.filterMap f = l.filterMap g
  | [], _ => rfl
  | a :: t, h => by
    rw [List.filterMap_cons, List.filterMap_cons, h a (List.mem_cons_self ..),
      fm_congr fun x hx => h x (List.mem_cons_of_mem _ hx)]

theorem sparse_aux {α β : Type} {q : α → Bool} {g : α → Option β} :
    ∀ (xs : List α) (d : Nat) (ps : List Nat), ps.Pairwise (· < ·) →
      (∀ i, i ∈ ps ↔ d ≤ i ∧ ∃ y, xs[i - d]? = some y ∧ q y = true) →
      ps.filterMap (fun i => xs[i - d]?.bind g) = (xs.filter q).filterMap g := by
  intro xs
  induction xs with
  | nil =>
    intro d ps _ hm
    have : ps = [] := List.eq_nil_iff_forall_not_mem.mpr fun i hi => by simpa using (hm i).mp hi
    simp [this]
  | cons a t ih =>
    intro d ps hs hm
    by_cases hq : q a = true
    · have hd : d ∈ ps := (hm d).mpr ⟨Nat.le_refl _, a, by simp, hq⟩
      rcases ps with _ | ⟨p, rest⟩
      · simp at hd
      · have hp := List.pairwise_cons.mp hs
        have hdp : d ≤ p := ((hm p).mp (List.mem_cons_self ..)).1
        have hpd : p = d := by
          rcases List.mem_cons.mp hd with h | h
          · exact h.symm
          · have := hp.1 d h; omega
        subst hpd
        have hrest : ∀ i, i ∈ rest ↔ p + 1 ≤ i ∧ ∃ y, t[i - (p + 1)]? = some y ∧ q y = true := by
          intro i
          constructor
          · intro hi
            have hlt := hp.1 i hi
            have := (hm i).mp (List.mem_cons_of_mem _ hi)
            rw [idx_shift hlt] at this
            exact ⟨hlt, this.2⟩
          · rintro ⟨hlt, hy⟩
            have : i ∈ p :: rest := (hm i).mpr ⟨by omega, by rw [idx_shift hlt]; exact hy⟩
            rcases List.mem_cons.mp this with h | h
            · omega
            · exact h
        have := ih (p + 1) rest hp.2 hrest
        rw [List.filterMap_cons, List.filter_cons_of_pos hq, List.filterMap_cons]
        have e : rest.filterMap (fun i => (a :: t)[i - p]?.bind g) = rest.filterMap (fun i => t[i - (p + 1)]?.bind g) :=
          fm_congr fun i hi => by rw [idx_shift (hp.1 i hi)]
        rw [e, this]
        simp
    · have hnd : ∀ i ∈ ps, d < i := fun i hi => by
        obtain ⟨h1, y, hy, hqy⟩ := (hm i).mp hi
        rcases Nat.eq_or_lt_of_le h1 with rfl | h2
        · simp at hy; subst hy; exact absurd hqy hq
        · exact h2
      have hrest : ∀ i, i ∈ ps ↔ d + 1 ≤ i ∧ ∃ y, t[i - (d + 1)]? = some y ∧ q y = true := by
        intro i
        constructor
        · intro hi
          have hlt := hnd i hi
          have := (hm i).mp hi
          rw [idx_shift hlt] at this
          exact ⟨hlt, this.2⟩
        · rintro ⟨hlt, hy⟩
          exact (hm i).mpr ⟨by omega, by rw [idx_shift hlt]; exact hy⟩
      have := ih (d + 1) ps hs hrest
      rw [List.filter_cons_of_neg hq] at *
      rw [← this]
      exact fm_congr fun i hi => by rw [idx_shift (hnd i hi)]

/-- Strictly increasing positions that are exactly those of the rows passing `q` pick the filter.
    Induction on `xs` generalizing `ps` (shift every position down by one). -/
theorem sparse_filter {xs : List Line} {q : Line → Bool} {g : Line → Option Nat} {ps : List Nat}
    (hs : ps.Pairwise (· < ·)) (hm : ∀ i, i ∈ ps ↔ ∃ h : i < xs.length, q xs[i] = true) :
    ps.filterMap (fun i => xs.toArray[i]?.bind g) = (xs.filter q).filterMap g := by
  have := sparse_aux (q := q) (g := g) xs 0 ps hs fun i => by
    rw [hm i]
    simp only [Nat.zero_le, true_and, Nat.sub_zero, List.getElem?_eq_some_iff]
    constructor
    · rintro ⟨h, hq⟩; exact ⟨_, ⟨h, rfl⟩, hq⟩
    · rintro ⟨y, ⟨h, rfl⟩, hq⟩; exact ⟨h, hq⟩
  simpa using this

theorem filterMap_ite {p : Line → Bool} :
    ∀ xs : List Line, xs.filterMap (fun y => if p y = true then some y.id else none) = (xs.filter p).map (·.id)
  | [] => rfl
  | a :: t => by
    by_cases h : p a = true <;> simp [h, filterMap_ite t]

theorem hits_eq {xs : List Line} {ks : List Key} {p : Line → Bool} :
    hits xs.toArray (posts xs).1 ks p = (xs.filter fun y => ks.any (keys y).contains && p y).map (·.id) := by
  have hsort : ((ks.flatMap (fun k => (posts xs).1.getD k [])).mergeSort fun i j => decide (i ≤ j)).Pairwise (· ≤ ·) := by
    have := List.pairwise_mergeSort (le := fun i j : Nat => decide (i ≤ j))
      (fun a b c h1 h2 => by simp at *; omega) (fun a b => by simp; omega) (ks.flatMap (fun k => (posts xs).1.getD k []))
    simpa using this
  have hs := pairwise_dedup hsort
  have key := sparse_filter (xs := xs) (q := fun y => ks.any (keys y).contains)
    (g := fun y => if p y = true then some y.id else none) hs (by
      intro i
      rw [mem_dedup, List.mem_mergeSort, List.mem_flatMap]
      simp only [mem_posts, List.any_eq_true, List.contains_iff_mem]
      constructor
      · rintro ⟨k, hk, h, hk2⟩; exact ⟨h, k, hk, hk2⟩
      · rintro ⟨h, k, hk, hk2⟩; exact ⟨k, hk, h, hk2⟩)
  unfold hits
  rw [key, filterMap_ite, List.filter_filter]
  exact congrArg _ (List.filter_congr fun x _ => Bool.and_comm _ _)

theorem chainedF_eq {t : Nat} {p : Snapshot Line} {o : Option (Snapshot Line)} :
    chainedF t p o = chained t p o := by
  have : ∀ l : List Line, (HashSet.ofList l).contains = l.contains := fun l => funext fun k => HashSet.contains_ofList
  cases o <;> simp [chainedF, chained, this]

theorem viewF_eq {t p o} : viewF (chained t p o) p o = view t p o := rfl

theorem looseF_eq {t p o} : looseF (chained t p o) p o = loose t p o := by
  simp [looseF, loose, HashSet.contains_ofList]

theorem claim_sub {c : Ctx} {x : Line} {k : Key} (h : k ∈ claim c x) : k ∈ keys x := by
  unfold claim at h
  split at h
  · simp only [keys, List.mem_cons, List.not_mem_nil, or_false] at h ⊢
    rcases h with h | h
    · exact Or.inl h
    · exact Or.inr (Or.inr h)
  · exact h

theorem any_congr_mem {α : Type} {A B : List α} {f : α → Bool} (h : ∀ x, x ∈ A ↔ x ∈ B) :
    A.any f = B.any f := by
  rw [Bool.eq_iff_iff]; simp [List.any_eq_true, h]

theorem covers_member {l : Line} {s : Span} (h : covers l s = true) : s.member = l.member := by
  unfold covers at h
  simp only [Bool.and_eq_true, beq_iff_eq] at h
  exact h.1.1.1

/-- A probe of a posting list: a hit below `V.length` whose row passes `P` is a row of `V`. -/
theorem probe_iff {V L : List Line} {k : Key} {P : Line → Bool} :
    ((posts (V ++ L)).1.getD k []).any (fun i => decide (i < V.length) && (V ++ L).toArray[i]?.any P) = true ↔
      ∃ y ∈ V, k ∈ keys y ∧ P y = true := by
  simp only [List.any_eq_true, Bool.and_eq_true, decide_eq_true_eq, mem_posts', List.getElem?_toArray,
    Option.any_eq_true]
  constructor
  · rintro ⟨i, ⟨y', hy', hk⟩, hlt, y, hy, hP⟩
    have e : y' = y := by rw [hy'] at hy; exact Option.some.inj hy
    subst e
    rw [List.getElem?_append_left hlt] at hy
    exact ⟨y', List.mem_of_getElem? hy, hk, hP⟩
  · rintro ⟨y, hy, hk, hP⟩
    obtain ⟨i, hi⟩ := List.mem_iff_getElem?.mp hy
    have hlt : i < V.length := (List.getElem?_eq_some_iff.mp hi).1
    have hg : (V ++ L)[i]? = some y := by rw [List.getElem?_append_left hlt]; exact hi
    exact ⟨i, ⟨y, hg, hk⟩, hlt, y, hg, hP⟩

/-! ## The index answers as the Spec (fixed `c`, `b`; `x := Ix.build c b`) -/

section
variable {c : Ctx} {b : List Line} {l : Line} {k : Key} {s : HashSet Key} {seen : List Key}

theorem build_relV : (Ix.build c b).relV = view c.today c.releasedPrior c.released := by
  simp [Ix.build, chainedF_eq, viewF_eq]

theorem build_unrV : (Ix.build c b).unrV = view c.today c.unresolvedPrior c.unresolved := by
  simp [Ix.build, chainedF_eq, viewF_eq]

theorem build_relN : (Ix.build c b).relN = (releasedSet c).length := by
  simp [Ix.build, releasedSet, chainedF_eq, viewF_eq]

theorem build_unrN : (Ix.build c b).unrN = (unresolvedSet c).length := by
  simp [Ix.build, unresolvedSet, chainedF_eq, viewF_eq]

theorem build_rel : (Ix.build c b).rel = (releasedSet c ++ loose c.today c.releasedPrior c.released).toArray := by
  simp [Ix.build, releasedSet, chainedF_eq, viewF_eq, looseF_eq]

theorem build_unr :
    (Ix.build c b).unr = (unresolvedSet c ++ loose c.today c.unresolvedPrior c.unresolved).toArray := by
  simp [Ix.build, unresolvedSet, chainedF_eq, viewF_eq, looseF_eq]

theorem build_relPost :
    (Ix.build c b).relPost = (posts (releasedSet c ++ loose c.today c.releasedPrior c.released)).1 := by
  simp [Ix.build, releasedSet, chainedF_eq, viewF_eq, looseF_eq]

theorem build_unrPost :
    (Ix.build c b).unrPost = (posts (unresolvedSet c ++ loose c.today c.unresolvedPrior c.unresolved)).1 := by
  simp [Ix.build, unresolvedSet, chainedF_eq, viewF_eq, looseF_eq]

theorem probe_rel {P : Line → Bool} :
    (((Ix.build c b).relPost.getD k []).any fun i => decide (i < (Ix.build c b).relN) && (Ix.build c b).rel[i]?.any P) =
      true ↔ ∃ y ∈ releasedSet c, k ∈ keys y ∧ P y = true := by
  rw [build_relPost, build_relN, build_rel]; exact probe_iff

theorem probe_unr {P : Line → Bool} :
    (((Ix.build c b).unrPost.getD k []).any fun i => decide (i < (Ix.build c b).unrN) && (Ix.build c b).unr[i]?.any P) =
      true ↔ ∃ y ∈ unresolvedSet c, k ∈ keys y ∧ P y = true := by
  rw [build_unrPost, build_unrN, build_unr]; exact probe_iff

theorem redo_contains {p : Nat} : (Ix.build c b).redo.contains p = c.redo.contains p := by
  simp [Ix.build, HashSet.contains_ofList]

theorem batch_contains {y : Line} : (Ix.build c b).batch.contains y = b.contains y := by
  simp [Ix.build, HashSet.contains_ofList]

theorem own_eq : (Ix.build c b).own l = own c l := by
  unfold Ix.own own
  rw [redo_contains]
  congr 1
  rw [Bool.eq_iff_iff]
  rw [probe_rel (P := (· == l))]
  simp only [List.contains_iff_mem, beq_iff_eq]
  constructor
  · rintro ⟨y, hy, _, rfl⟩; exact hy
  · intro h; exact ⟨l, h, idKey_mem, rfl⟩

theorem build_span : (Ix.build c b).span = group (·.member) (entries c.enrollment) := rfl

theorem enrolled_eq : (Ix.build c b).enrolled l = enrolled c l := by
  unfold Ix.enrolled enrolled
  rw [Bool.eq_iff_iff, build_span]
  simp only [List.any_eq_true]
  constructor
  · rintro ⟨s, hs, hc⟩; exact ⟨s, (mem_group.mp hs).1, hc⟩
  · rintro ⟨s, hs, hc⟩; exact ⟨s, mem_group.mpr ⟨hs, covers_member hc⟩, hc⟩

theorem build_dmfOk : (Ix.build c b).dmfOk = usable c.today 90 okDeath c.dmf := rfl
theorem build_pdOk : (Ix.build c b).pdOk = usable c.today 90 okDeath c.providerDeaths := rfl
theorem build_exclOk : (Ix.build c b).exclOk = usable c.today 31 okExclusion c.exclusions := rfl
theorem build_spanOk : (Ix.build c b).spanOk = usable c.today 7 okSpan c.enrollment := rfl
theorem build_dmfSome : (Ix.build c b).dmfSome = c.dmf.isSome := rfl
theorem build_pdSome : (Ix.build c b).pdSome = c.providerDeaths.isSome := rfl
theorem build_exclSome : (Ix.build c b).exclSome = c.exclusions.isSome := rfl
theorem build_spanSome : (Ix.build c b).spanSome = c.enrollment.isSome := rfl
theorem build_today : (Ix.build c b).today = c.today := rfl
theorem build_relChained : (Ix.build c b).relChained = chained c.today c.releasedPrior c.released := by
  simp [Ix.build, chainedF_eq]
theorem build_unrChained : (Ix.build c b).unrChained = chained c.today c.unresolvedPrior c.unresolved := by
  simp [Ix.build, chainedF_eq]

theorem notEnrolled_eq : (Ix.build c b).notEnrolled l = notEnrolled c l := by
  unfold Ix.notEnrolled notEnrolled certain
  rw [build_spanOk, enrolled_eq]

theorem claim_eq : (Ix.build c b).claim l = claim c l := by
  unfold Ix.claim claim; rw [notEnrolled_eq, own_eq]

theorem memberDead_eq : (Ix.build c b).memberDead l = memberDead c l := by
  unfold Ix.memberDead memberDead
  rw [Bool.eq_iff_iff]
  simp only [List.any_eq_true, Ix.build, mem_group, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq]
  constructor
  · rintro ⟨d, ⟨hd, _⟩, h⟩; exact ⟨d, hd, by omega⟩
  · rintro ⟨d, hd, h1, h2⟩; exact ⟨d, ⟨hd, h1⟩, h2⟩

theorem providerDead_eq : (Ix.build c b).providerDead l = providerDead c l := by
  unfold Ix.providerDead providerDead party
  rw [Bool.eq_iff_iff]
  simp only [List.any_eq_true, Ix.build, mem_group, Bool.and_eq_true, Bool.or_eq_true, beq_iff_eq,
    decide_eq_true_eq]
  constructor
  · rintro (⟨d, ⟨hd, h1⟩, h2⟩ | ⟨d, ⟨hd, h1⟩, h2⟩)
    · exact ⟨d, hd, Or.inl h1, h2⟩
    · exact ⟨d, hd, Or.inr h1, h2⟩
  · rintro ⟨d, hd, h1 | h1, h2⟩
    · exact Or.inl ⟨d, ⟨hd, h1⟩, h2⟩
    · exact Or.inr ⟨d, ⟨hd, h1⟩, h2⟩

theorem excluded_eq : (Ix.build c b).excluded l = excluded c l := by
  unfold Ix.excluded excluded party
  rw [Bool.eq_iff_iff]
  simp only [List.any_eq_true, Ix.build, mem_group, Bool.and_eq_true, Bool.or_eq_true, beq_iff_eq,
    decide_eq_true_eq]
  constructor
  · rintro (⟨d, ⟨hd, h1⟩, h2, h3⟩ | ⟨d, ⟨hd, h1⟩, h2, h3⟩)
    · exact ⟨d, hd, ⟨Or.inl h1, h2⟩, h3⟩
    · exact ⟨d, hd, ⟨Or.inr h1, h2⟩, h3⟩
  · rintro ⟨d, hd, ⟨h1 | h1, h2⟩, h3⟩
    · exact Or.inl ⟨d, ⟨hd, h1⟩, h2, h3⟩
    · exact Or.inr ⟨d, ⟨hd, h1⟩, h2, h3⟩

theorem overlap_eq : (Ix.build c b).overlap l = overlap c l := by
  unfold Ix.overlap overlap
  have hm : ∀ s, s ∈ (Ix.build c b).span.getD l.member [] ↔
      s ∈ (entries c.enrollment).filter (·.member == l.member) := fun s => by
    rw [build_span, mem_group]; simp
  rw [any_congr_mem hm]
  congr 1
  funext s
  exact any_congr_mem hm

theorem seen0_eq : (Ix.build c b).seen0 k = (seen0 c b).contains k := by
  unfold Ix.seen0 seen0
  have hown : (Ix.build c b).own = own c := funext fun _ => own_eq
  rw [Bool.eq_iff_iff, hown]
  simp only [batch_contains]
  rw [probe_rel (P := fun y => !(own c y && b.contains y))]
  simp only [List.contains_iff_mem, List.mem_flatMap, List.mem_filter]
  constructor
  · rintro ⟨y, hy, hk, hp⟩; exact ⟨y, ⟨hy, hp⟩, hk⟩
  · rintro ⟨y, ⟨hy, hp⟩, hk⟩; exact ⟨y, hy, hk, hp⟩

theorem pending_eq : (Ix.build c b).pending k = (pending c).contains k := by
  unfold Ix.pending pending
  have hcl : (Ix.build c b).claim = claim c := funext fun _ => claim_eq
  rw [Bool.eq_iff_iff, hcl]
  rw [probe_unr (P := fun y => (claim c y).contains k)]
  simp only [List.contains_iff_mem, List.mem_flatMap]
  constructor
  · rintro ⟨y, hy, _, hp⟩; exact ⟨y, hy, hp⟩
  · rintro ⟨y, hy, hp⟩; exact ⟨y, hy, claim_sub hp, hp⟩

theorem looseKeys_eq : (Ix.build c b).looseKeys.contains k = (looseKeys c).contains k := by
  simp [Ix.build, looseKeys, HashSet.contains_ofList, chainedF_eq, viewF_eq, looseF_eq]

theorem counterparts_eq : (Ix.build c b).counterparts l =
    ((releasedSet c ++ loose c.today c.releasedPrior c.released).filter (fun x => (keys l).any (keys x).contains) ++
      (unresolvedSet c ++ loose c.today c.unresolvedPrior c.unresolved).filter
        fun x => (keys l).any (claim c x).contains).map (·.id) := by
  unfold Ix.counterparts
  rw [build_rel, build_relPost, build_unr, build_unrPost, hits_eq, hits_eq, List.map_append]
  congr 2
  · simp
  · refine List.filter_congr fun y _ => ?_
    rw [claim_eq]
    cases h : (keys l).any (claim c y).contains
    · simp
    · have : (keys l).any (keys y).contains = true := by
        obtain ⟨k, hk, hc⟩ := List.any_eq_true.mp h
        exact List.any_eq_true.mpr ⟨k, hk, List.contains_iff_mem.mpr (claim_sub (List.contains_iff_mem.mp hc))⟩
      simp [this]

theorem fires_eq (h : ∀ k, (Ix.build c b).seen s k = seen.contains k) (r : Reason) :
    (Ix.build c b).fires s l r = fires c seen l r := by
  cases r <;> simp only [Ix.fires, fires, certain, unverified, h, pending_eq, looseKeys_eq, memberDead_eq,
    providerDead_eq, excluded_eq, overlap_eq, notEnrolled_eq, enrolled_eq, build_dmfOk, build_pdOk,
    build_exclOk, build_spanOk, build_dmfSome, build_pdSome, build_exclSome, build_spanSome, build_today,
    build_relChained, build_unrChained] <;> try rfl

theorem decideLine_eq (h : ∀ k, (Ix.build c b).seen s k = seen.contains k) :
    (Ix.build c b).decideLine s l = decideLine c seen l := by
  unfold Ix.decideLine decideLine
  have : reasons.filter ((Ix.build c b).fires s l) = reasons.filter (fires c seen l) :=
    List.filter_congr fun r _ => fires_eq h r
  rw [this, counterparts_eq]

/-- The seen invariant is kept: `HashSet.contains_insertMany_list`, `List.contains_append`. -/
theorem decideAll_eq : ∀ (s : HashSet Key) (seen : List Key) (ls : List Line),
    (∀ k, (Ix.build c b).seen s k = seen.contains k) → (Ix.build c b).decideAll s ls = decideAll c seen ls := by
  intro s seen ls
  induction ls generalizing s seen with
  | nil => intro _; simp [Ix.decideAll, decideAll]
  | cons l ls ih =>
    intro h
    simp only [Ix.decideAll, decideAll]
    rw [decideLine_eq h]
    congr 1
    apply ih
    intro k
    have hk := h k
    simp only [Ix.seen] at hk ⊢
    rw [claim_eq, HashSet.contains_insertMany_list, List.contains_append, ← hk]
    cases s.contains k <;> cases (claim c l).contains k <;> cases (Ix.build c b).seen0 k <;> rfl

theorem own_fun : (Ix.build c b).own = own c := funext fun _ => own_eq

theorem order_eq : (Ix.build c b).order b = order c b := by
  simp [Ix.order, order, own_fun]

theorem payOutcome_eq {ds : List Decision} {p : Nat} : (Ix.build c b).payOutcome ds p = payOutcome c ds p := by
  simp [Ix.payOutcome, payOutcome, redo_contains, own_fun]

theorem releasedLines_eq {ds} : (Ix.build c b).releasedLines ds = releasedLines c ds := by
  simp [Ix.releasedLines, releasedLines, redo_contains, payOutcome_eq]

theorem unresolvedLines_eq {ds} : (Ix.build c b).unresolvedLines ds = unresolvedLines c ds := by
  simp [Ix.unresolvedLines, unresolvedLines, own_fun]

end

/-! ## The batch -/

/-- THE equality: the twin's decisions, released and unresolved checkpoints equal the Spec's, with `f` the ids another shard owns. -/
theorem decideBatchFIn_eq (c : Ctx) (f : List Nat) (b : List Line) : decideBatchFIn c f b = decideBatchIn c f b := by
  have hds : (Ix.build c b).decideAll (HashSet.ofList (idSeen f)) ((Ix.build c b).order b) =
      decideAll c (idSeen f ++ seen0 c b) (order c b) := by
    rw [order_eq]
    exact decideAll_eq _ _ _ fun k => by simp [Ix.seen, seen0_eq, HashSet.contains_ofList]
  unfold decideBatchFIn Ix.runIn decideBatchIn
  simp only [hds, releasedLines_eq, unresolvedLines_eq, advance, build_relV, build_unrV, build_relN,
    build_unrN, releasedSet, unresolvedSet]

theorem decideBatchF_eq (c : Ctx) (b : List Line) : decideBatchF c b = decideBatch c b :=
  decideBatchFIn_eq c [] b

/-- Replaces the runner's reversed-order re-run: `decideBatchF_eq` and `deterministic`. -/
theorem decideBatchF_perm {c : Ctx} {b₁ b₂ : List Line} (h : b₁.Perm b₂) :
    decideBatchF c b₁ = decideBatchF c b₂ := by
  rw [decideBatchF_eq, decideBatchF_eq, deterministic h]

theorem decideBatchF_reverse (c : Ctx) (b : List Line) : decideBatchF c b.reverse = decideBatchF c b :=
  decideBatchF_perm (List.reverse_perm b)

/-- What the runner's commit reads besides the result. -/
theorem run_relN {c b} : (Ix.build c b).relN = (releasedSet c).length := build_relN

theorem run_unrN {c b} : (Ix.build c b).unrN = (unresolvedSet c).length := build_unrN

/-! ## Pins -/

theorem push_fold (f : Nat → UInt8) :
    ∀ (L : List Nat) (acc : ByteArray),
      (L.foldl (fun a i => a.push (f i)) acc).data.toList = acc.data.toList ++ L.map f
  | [], acc => by simp
  | i :: L, acc => by simp [List.foldl_cons, push_fold f L]

/-- A byte of the low 64 bits: `n.toUInt64 >>> 8i` is `(n >>> 8i) % 256`, for `i < 8`. -/
theorem byte_eq (n i : Nat) (hi : i < 8) :
    (n.toUInt64 >>> (8 * i).toUInt64).toUInt8 = ((n >>> (8 * i)) % 256).toUInt8 := by
  apply UInt8.toNat_inj.mp
  rw [UInt64.toNat_toUInt8, UInt64.toNat_shiftRight]
  rcases (by omega : i = 0 ∨ i = 1 ∨ i = 2 ∨ i = 3 ∨ i = 4 ∨ i = 5 ∨ i = 6 ∨ i = 7) with
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;> simp [Nat.shiftRight_eq_div_pow] <;> omega

/-- Strong induction on `w`: the top `w - 8` bytes are those of `n >>> 64` (`List.range_add`, `Nat.shiftRight_add`), the last 8 `byte_eq`. -/
theorem pushHi_eq (acc : ByteArray) : ∀ (w n : Nat),
    (pushHi acc w n).data.toList = acc.data.toList ++ (List.range w).reverse.map fun i => ((n >>> (8 * i)) % 256).toUInt8 := by
  intro w
  induction w using Nat.strongRecOn with
  | _ w ih =>
    intro n
    unfold pushHi
    by_cases h : w ≤ 8
    · simp only [h, dite_true, pushLow]
      rw [push_fold]
      congr 1
      apply List.map_congr_left
      intro i hi
      simp at hi
      exact byte_eq n i (by omega)
    · simp only [h, dite_false, pushLow]
      rw [push_fold, ih (w - 8) (by omega)]
      have hr : (List.range w).reverse = (List.range (w - 8)).reverse.map (· + 8) ++ (List.range 8).reverse := by
        have e := @List.range_add 8 (w - 8)
        rw [show 8 + (w - 8) = w by omega] at e
        rw [e, List.reverse_append, ← List.map_reverse]
        simp [Nat.add_comm]
      rw [hr, List.map_append, ← List.append_assoc, List.map_map]
      congr 1
      · congr 1
        apply List.map_congr_left
        intro i _
        simp only [Function.comp]
        rw [show 8 * (i + 8) = 64 + 8 * i by omega, Nat.shiftRight_add]
      · apply List.map_congr_left
        intro i hi
        simp at hi
        exact byte_eq n i (by omega)

/-- `pushHi_eq`, then `Nat.shiftRight_eq_div_pow`, `Nat.pow_mul` (2 ^ (8 * i) = 256 ^ i). -/
theorem pushBe_eq {acc : ByteArray} {w n : Nat} :
    (pushBe acc w n).map (·.data.toList) = (be w n).map (acc.data.toList ++ ·) := by
  unfold pushBe be
  by_cases h : n < 256 ^ w
  · simp only [h, if_true, Option.map_some]
    rw [pushHi_eq]
    congr 2
    apply List.map_congr_left
    intro i _
    rw [Nat.shiftRight_eq_div_pow, Nat.pow_mul]
  · simp [h]

theorem pushRow_eq {acc : ByteArray} {fs : List (Nat × Nat)} :
    (pushRow acc fs).map (·.data.toList) =
      ((fs.mapM fun (w, n) => be w n).map List.flatten).map (acc.data.toList ++ ·) := by
  induction fs generalizing acc with
  | nil => simp [pushRow]
  | cons p fs ih =>
    obtain ⟨w, n⟩ := p
    have hb := pushBe_eq (acc := acc) (w := w) (n := n)
    cases hbe : be w n with
    | none =>
      rw [hbe] at hb
      have : pushBe acc w n = none := by simpa using hb
      simp [pushRow, this, hbe]
    | some bs =>
      rw [hbe] at hb
      obtain ⟨a, ha, hat⟩ : ∃ a, pushBe acc w n = some a ∧ a.data.toList = acc.data.toList ++ bs := by
        cases hp : pushBe acc w n with
        | none => rw [hp] at hb; simp at hb
        | some a => rw [hp] at hb; exact ⟨a, rfl, by simpa using hb⟩
      have e : pushRow acc ((w, n) :: fs) = pushRow a fs := by simp [pushRow, ha]
      rw [e, ih]
      cases hm : fs.mapM (fun (w, n) => be w n) with
      | none => simp [List.mapM_cons, hbe, hm]
      | some rest => simp [List.mapM_cons, hbe, hm, hat]

theorem rowBytesFast_eq {tag : UInt8} {l : Line} :
    (Run.rowBytesFast tag l).map (·.data.toList) = Run.rowBytes tag l := by
  have h := pushRow_eq (acc := ByteArray.empty.push tag) (fs := l.fields)
  unfold Run.rowBytesFast Run.rowBytes
  rw [h]
  cases (l.fields.mapM fun (w, n) => be w n) <;> simp

instance : Std.Asymm (· < · : UInt8 → UInt8 → Prop) where
  asymm a b h h' := by
    rw [UInt8.lt_iff_toNat_lt] at h h'; omega

instance : Std.Trichotomous (· < · : UInt8 → UInt8 → Prop) where
  trichotomous a b h h' := by
    rw [UInt8.lt_iff_toNat_lt] at h h'
    exact UInt8.toNat_inj.mp (by omega)

/-- `List.cons_le_cons_iff` (needs `Std.Asymm`/`Std.Trichotomous` for UInt8 `<`; proved above via
    `UInt8.lt_iff_toNat_lt`), `List.drop_eq_getElem_cons`, `Array.getElem_toList`. -/
theorem leFrom_eq {a b : ByteArray} {i : Nat} :
    leFrom a b i = decide (a.data.toList.drop i ≤ b.data.toList.drop i) := by
  have hd : ∀ (a : ByteArray) (i : Nat) (h : i < a.size), a.data.toList.drop i = a[i] :: a.data.toList.drop (i + 1) :=
    fun a i h => by rw [List.drop_eq_getElem_cons (by simpa using h)]; simp; rfl
  fun_induction leFrom a b i with
  | case1 i ha hb hlt =>
    rw [hd a i ha, hd b i hb]
    simp [List.cons_le_cons_iff, hlt]
  | case2 i ha hb hlt heq ih =>
    rw [ih, hd a i ha, hd b i hb]
    have : a[i] = b[i] := by simpa using heq
    simp [List.cons_le_cons_iff, this]
  | case3 i ha hb hlt heq =>
    rw [hd a i ha, hd b i hb]
    have : a[i] ≠ b[i] := by simpa using heq
    simp [List.cons_le_cons_iff, hlt, this]
  | case4 i ha hb =>
    have : b.data.toList.drop i = [] := List.drop_eq_nil_of_le (by simpa using hb)
    rw [hd a i ha, this]; simp
  | case5 i ha =>
    have : a.data.toList.drop i = [] := List.drop_eq_nil_of_le (by simpa using ha)
    rw [this]; simp

theorem baLe_eq {a b : ByteArray} : baLe a b = decide (a.data.toList ≤ b.data.toList) := by
  simp [baLe, leFrom_eq]

/-- The core `ByteArray.toList` loop equals `data.toList`. -/
theorem toList_loop (bs : ByteArray) :
    ∀ (n i : Nat) (r : List UInt8), bs.size - i = n → i ≤ bs.size →
      ByteArray.toList.loop bs i r = r.reverse ++ bs.data.toList.drop i
  | 0, i, r, hn, hi => by
    rw [ByteArray.toList.loop]
    have h1 : ¬ i < bs.size := by omega
    have h2 : bs.data.toList.drop i = [] := List.drop_eq_nil_of_le (by simp; omega)
    simp [h1, h2]
  | n + 1, i, r, hn, hi => by
    rw [ByteArray.toList.loop]
    have h1 : i < bs.size := by omega
    simp only [h1, if_true]
    have hdi : bs.data.toList.drop i = bs.data[i] :: bs.data.toList.drop (i + 1) := by
      rw [List.drop_eq_getElem_cons (show i < bs.data.toList.length by simpa using h1)]; simp
    rw [toList_loop bs n (i + 1) _ (by omega) (by omega), hdi]
    simp [ByteArray.get!, getElem!_pos, h1]

theorem toList_eq (bs : ByteArray) : bs.toList = bs.data.toList := by
  unfold ByteArray.toList
  rw [toList_loop bs bs.size 0 [] (by omega) (by omega)]
  simp

theorem mapM_map {α β γ : Type} (φ : β → γ) (f : α → Option β) (g : α → Option γ)
    (hfg : ∀ x, (f x).map φ = g x) : ∀ l : List α, (l.mapM f).map (List.map φ) = l.mapM g
  | [] => rfl
  | a :: l => by
    have h : g a = (f a).map φ := (hfg a).symm
    have ih := mapM_map φ f g hfg l
    rw [List.mapM_cons, List.mapM_cons, ← ih, h]
    cases f a <;> cases l.mapM f <;> simp

theorem foldl_append_data :
    ∀ (L : List ByteArray) (out : ByteArray),
      (L.foldl (· ++ ·) out).data.toList = out.data.toList ++ (L.map (·.data.toList)).flatten
  | [], out => by simp
  | x :: L, out => by simp [List.foldl_cons, foldl_append_data L]

theorem pin_final {h : ByteArray} {rs : List ByteArray} {q : List UInt8} {ps : List (List UInt8)}
    {dl : List UInt8} {n : Nat} (hh : h.data.toList = dl ++ [0] ++ q) (hr : rs.map (·.data.toList) = ps) :
    ((rs.mergeSort baLe).foldl (· ++ ·) (ByteArray.emptyWithCapacity n ++ h)).data.toList =
      dl ++ 0 :: q ++ (ps.mergeSort fun a b => decide (a ≤ b)).flatten := by
  have hs : (rs.mergeSort baLe).map (·.data.toList) = ps.mergeSort fun a b => decide (a ≤ b) := by
    rw [← hr]
    exact List.map_mergeSort fun a _ b _ => baLe_eq
  have he : (ByteArray.emptyWithCapacity n).data.toList = [] := by
    show (Array.emptyWithCapacity n).toList = []; simp
  rw [foldl_append_data, hs]
  simp [hh, he]

/-- `List.map_mergeSort` with `baLe_eq`; `ByteArray.data_append`; `pushRow_eq`; `String.toUTF8`
    `toList` = `data.toList` (a loop lemma if core lacks it). -/
theorem pinBytes_eq {α : Type} {d : String} {k : Nat} {f : α → List (Nat × Nat)} {s : Snapshot α} :
    (pinBytes d k f s).map (·.data.toList) = pinInput d k f s := by
  have hhead := pushRow_eq (acc := d.toUTF8.push 0) (fs := [(4, k), (4, s.asOf), (4, s.count)])
  have hrows := mapM_map (fun x : ByteArray => x.data.toList) (fun x => pushRow .empty (f x))
    (fun x => ((f x).mapM fun (w, n) => be w n).map List.flatten)
    (fun x => by
      rw [pushRow_eq]
      cases ((f x).mapM fun (w, n) => be w n) <;> simp) s.entries
  have hacc : (d.toUTF8.push 0).data.toList = d.toUTF8.toList ++ [0] := by
    rw [toList_eq]; simp
  rw [hacc] at hhead
  unfold pinBytes pinInput
  dsimp only
  simp only [Function.comp_def]
  generalize Option.map List.flatten (List.mapM (fun x => be x.fst x.snd) [(4, k), (4, s.asOf), (4, s.count)]) = Q
    at hhead ⊢
  generalize List.mapM (fun x => pushRow ByteArray.empty (f x)) s.entries = R at hrows ⊢
  generalize List.mapM (fun x => Option.map List.flatten (List.mapM (fun x => be x.fst x.snd) (f x))) s.entries = P
    at hrows ⊢
  generalize pushRow (d.toUTF8.push 0) [(4, k), (4, s.asOf), (4, s.count)] = H at hhead ⊢
  rcases H with _ | h <;> rcases Q with _ | q <;> rcases R with _ | rs <;> rcases P with _ | ps <;>
    simp at hhead hrows ⊢
  have := pin_final (n := List.foldl (fun x1 x2 => x1 + x2.size) h.size rs) (dl := d.toByteArray.toList)
    (by simpa using hhead) hrows
  simpa using this

/-- The runner hashes `pinBytes` where it hashed `⟨(pinInput …).toArray⟩`. -/
theorem pin_run_eq {α : Type} {d : String} {k : Nat} {f : α → List (Nat × Nat)} {s : Snapshot α} :
    (pinInput d k f s).map (fun bs => ByteArray.mk bs.toArray) = pinBytes d k f s := by
  rw [← pinBytes_eq]; cases pinBytes d k f s <;> simp

/-- The runner's state digest equals the spec's `Gate.setsDigest` for every hash. -/
theorem setsDigestF_eq (H : ByteArray → List UInt8) (r u : Snapshot Line) :
    setsDigestF H r u = BlindLedger.Gate.setsDigest (fun x => H ⟨x.toArray⟩) r u := by
  unfold setsDigestF BlindLedger.Gate.setsDigest BlindLedger.Gate.setPins
  rw [← pin_run_eq, ← pin_run_eq]
  cases pinInput "RR/GATE/RELEASED/v1" 5 Line.fields r <;> cases pinInput "RR/GATE/UNRESOLVED/v1" 6 Line.fields u <;> simp

/-- info: 'BlindLedger.Gate.Rules.Fast.setsDigestF_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms setsDigestF_eq
/-- info: 'BlindLedger.Gate.Rules.Fast.decideBatchF_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms decideBatchF_eq
/-- info: 'BlindLedger.Gate.Rules.Fast.decideBatchFIn_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms decideBatchFIn_eq
/-- info: 'BlindLedger.Gate.Rules.Fast.decideBatchF_perm' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms decideBatchF_perm
/-- info: 'BlindLedger.Gate.Rules.Fast.decideBatchF_reverse' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms decideBatchF_reverse
/-- info: 'BlindLedger.Gate.Rules.Fast.run_relN' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms run_relN
/-- info: 'BlindLedger.Gate.Rules.Fast.run_unrN' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms run_unrN
/-- info: 'BlindLedger.Gate.Rules.Fast.pin_run_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms pin_run_eq
/-- info: 'BlindLedger.Gate.Rules.Fast.pinBytes_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms pinBytes_eq

theorem unhexGo_eq (u : ByteArray) : ∀ (k i : Nat) (a : ByteArray),
    Run.unhexGo u k i a = (List.range' i k).foldlM
      (fun a i => do pure (a.push ((← Run.nib u[2 * i]!) * 16 + (← Run.nib u[2 * i + 1]!)))) a
  | 0, i, a => by simp [Run.unhexGo]
  | k + 1, i, a => by
    simp only [Run.unhexGo, List.range'_succ, List.foldlM_cons]
    cases h1 : Run.nib u[2 * i]! <;> cases h2 : Run.nib u[2 * i + 1]! <;> simp [h1, h2, unhexGo_eq u k (i + 1)]

theorem unhexFast_eq (s : String) : Run.unhexFast s = Run.unhex s := by
  simp only [Run.unhexFast, Run.unhex, unhexGo_eq, List.range_eq_range']

theorem fieldsFast_eq (raw : String) : Run.fieldsFast raw = Run.fields raw := by
  unfold Run.fieldsFast
  split
  · rfl
  · rename_i h
    have h' : '\r' ∉ raw.toList := by simpa [String.contains_char_eq] using h
    unfold Run.fields
    have e : raw.toList.filter (· ≠ '\r') = raw.toList :=
      List.filter_eq_self.mpr fun c hc => by simp; rintro rfl; exact h' hc
    rw [e, String.ofList_toList]

theorem setsDigestF_carry_eq (m : Option Run.Memo) (r u : Snapshot Line) :
    Run.Memo.get m r u = setsDigestF Run.hB r u := by
  unfold Run.Memo.get
  split
  · rename_i m
    split
    · rename_i h
      obtain ⟨h1, h2⟩ := h
      subst h1 h2
      exact m.ok
    · rfl
  · rfl

/-- info: 'BlindLedger.Gate.Rules.Fast.unhexFast_eq' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms unhexFast_eq
/-- info: 'BlindLedger.Gate.Rules.Fast.fieldsFast_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms fieldsFast_eq
/-- info: 'BlindLedger.Gate.Rules.Fast.setsDigestF_carry_eq' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms setsDigestF_carry_eq

end BlindLedger.Gate.Rules.Fast
