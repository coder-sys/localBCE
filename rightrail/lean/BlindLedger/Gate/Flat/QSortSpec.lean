import Lean

/-! `Array.qsort` is a permutation and sorted by its comparison, for a strict order (irreflexive, transitive).
    Core has no lemma for either.  `qsort`'s helpers `sort` and `qpartition.loop` are private in core, so two
    terms below name them; everything else is proved from their defining equations. -/

universe u

namespace BlindLedger.Gate.Flat.QS

open Lean Elab Term in
/-- The private core constant `Array.qsort.sort`, `Array.qpartition.loop` or their `eq_def`. -/
elab "qsPriv " s:str : term =>
  Meta.mkConstWithFreshMVarLevels (Name.mkNum `_private.Init.Data.Array.QSort.Basic 0 ++ s.getString.toName)

local macro "qsSort" : term => `(qsPriv "Array.qsort.sort")
local macro "qsSortDef" : term => `(qsPriv "Array.qsort.sort.eq_def")
local macro "qsLoop" : term => `(qsPriv "Array.qpartition.loop")
local macro "qsLoopDef" : term => `(qsPriv "Array.qpartition.loop.eq_def")

variable {α : Type u} {n lo hi lo' hi' : Nat}

/-- `b` is `a` with the entries of `[lo, hi]` permuted among themselves. -/
structure Rng (lo hi : Nat) (a b : Vector α n) : Prop where
  perm : Vector.Perm b a
  out : ∀ k (hk : k < n), (k < lo ∨ hi < k) → b[k] = a[k]
  inn : ∀ k (hk : k < n), lo ≤ k → k ≤ hi → ∃ k', ∃ hk' : k' < n, lo ≤ k' ∧ k' ≤ hi ∧ b[k] = a[k']

theorem Rng.refl (a : Vector α n) : Rng lo hi a a :=
  ⟨.refl _, fun _ _ _ => rfl, fun k hk h1 h2 => ⟨k, hk, h1, h2, rfl⟩⟩

theorem Rng.trans {a b c : Vector α n} (h1 : Rng lo hi a b) (h2 : Rng lo hi b c) : Rng lo hi a c where
  perm := h2.perm.trans h1.perm
  out k hk ho := by rw [h2.out k hk ho, h1.out k hk ho]
  inn k hk l u := by
    obtain ⟨k', hk', l', u', e⟩ := h2.inn k hk l u
    obtain ⟨k'', hk'', l'', u'', e'⟩ := h1.inn k' hk' l' u'
    exact ⟨k'', hk'', l'', u'', e.trans e'⟩

theorem Rng.widen {a b : Vector α n} (h : Rng lo hi a b) (hl : lo' ≤ lo) (hh : hi ≤ hi') : Rng lo' hi' a b where
  perm := h.perm
  out k hk ho := h.out k hk (by omega)
  inn k hk l u := by
    by_cases hin : lo ≤ k ∧ k ≤ hi
    · obtain ⟨k', hk', l', u', e⟩ := h.inn k hk hin.1 hin.2
      exact ⟨k', hk', by omega, by omega, e⟩
    · exact ⟨k, hk, l, u, h.out k hk (by omega)⟩

theorem Rng.swap (a : Vector α n) (i j : Nat) (hi : i < n) (hj : j < n) (i1 : lo ≤ i) (i2 : i ≤ hi')
    (j1 : lo ≤ j) (j2 : j ≤ hi') : Rng lo hi' a (a.swap i j hi hj) where
  perm := Vector.swap_perm hi hj
  out k hk ho := by
    rw [Vector.getElem_swap, if_neg (by omega), if_neg (by omega)]
  inn k hk l u := by
    rw [Vector.getElem_swap]
    by_cases h1 : k = i
    · rw [if_pos h1]; exact ⟨j, hj, j1, j2, rfl⟩
    · by_cases h2 : k = j
      · rw [if_neg h1, if_pos h2]; exact ⟨i, hi, i1, i2, rfl⟩
      · rw [if_neg h1, if_neg h2]; exact ⟨k, hk, l, u, rfl⟩

theorem Rng.swapIf (c : Prop) [Decidable c] (a : Vector α n) (i j : Nat) (hi : i < n) (hj : j < n)
    (i1 : lo ≤ i) (i2 : i ≤ hi') (j1 : lo ≤ j) (j2 : j ≤ hi') :
    Rng lo hi' a (if c then a.swap i j hi hj else a) := by
  split
  · exact Rng.swap a i j hi hj i1 i2 j1 j2
  · exact Rng.refl a

/-- `lt` is a strict order on the entries satisfying `Q`, and every entry of `a` does. -/
structure Strict (lt : α → α → Bool) (Q : α → Prop) : Prop where
  irr : ∀ x, Q x → lt x x = false
  tr : ∀ x y z, Q x → Q y → Q z → lt x y = true → lt y z = true → lt x z = true

def AllQ (Q : α → Prop) (a : Vector α n) : Prop := ∀ k (hk : k < n), Q a[k]

theorem Rng.allQ {Q : α → Prop} {a b : Vector α n} (h : Rng lo hi a b) (hA : AllQ Q a) : AllQ Q b := by
  intro k hk
  obtain ⟨k', hk', e⟩ := Vector.mem_iff_getElem.1 (h.perm.mem_iff.1 (Vector.getElem_mem hk))
  rw [← e]; exact hA k' hk'

/-! ### The partition -/

def PPost (lt : α → α → Bool) (lo hi : Nat) (pivot : α) (a0 : Vector α n)
    (r : {m // lo ≤ m ∧ m ≤ hi} × Vector α n) : Prop :=
  Rng lo hi a0 r.2 ∧ r.1.1 < hi ∧
  (∀ p (hp : p < n), lo ≤ p → p < r.1.1 → lt r.2[p] pivot = true) ∧
  (∀ p (hp : p < n), p = r.1.1 → r.2[p] = pivot) ∧
  (∀ p (hp : p < n), r.1.1 < p → p ≤ hi → lt r.2[p] pivot = false)

theorem loop_spec (lt : α → α → Bool) (lo hi : Nat) (hhi : hi < n) (pivot : α) (a0 : Vector α n)
    (hpv : a0[hi] = pivot) (mid : Nat) (hmid : mid < hi) (hm : lt a0[mid] pivot = false)
    (as : Vector α n) (i k : Nat) (ilo : lo ≤ i) (ik : i ≤ k) (w : k ≤ hi)
    (hR : Rng lo hi a0 as) (hun : ∀ p (hp : p < n), k ≤ p → p ≤ hi → as[p] = a0[p])
    (hlt : ∀ p (hp : p < n), lo ≤ p → p < i → lt as[p] pivot = true)
    (hge : ∀ p (hp : p < n), i ≤ p → p < k → lt as[p] pivot = false)
    (he : mid < k → i < k) :
    PPost lt lo hi pivot a0 (qsLoop lt lo hi hhi pivot as i k ilo ik w) := by
  rw [qsLoopDef]
  split
  · rename_i h
    split
    · rename_i hc
      refine loop_spec lt lo hi hhi pivot a0 hpv mid hmid hm _ _ _ _ _ _ ?_ ?_ ?_ ?_ ?_
      · exact hR.trans (Rng.swap as i k (by omega) (by omega) ilo (by omega) (by omega) (by omega))
      · intro p hp l u
        rw [Vector.getElem_swap, if_neg (by omega), if_neg (by omega)]
        exact hun p hp (by omega) u
      · intro p hp l u
        rw [Vector.getElem_swap]
        by_cases h1 : p = i
        · rw [if_pos h1]; exact hc
        · rw [if_neg h1, if_neg (by omega)]; exact hlt p hp l (by omega)
      · intro p hp l u
        rw [Vector.getElem_swap]
        by_cases h1 : p = k
        · rw [if_neg (by omega), if_pos h1]; exact hge i (by omega) (Nat.le_refl _) (by omega)
        · rw [if_neg (by omega), if_neg h1]; exact hge p hp (by omega) (by omega)
      · intro hk
        by_cases h1 : mid < k
        · have := he h1; omega
        · exfalso
          have h2 : mid = k := by omega
          subst h2
          rw [hun mid (by omega) (Nat.le_refl _) (by omega)] at hc
          rw [hm] at hc
          exact Bool.false_ne_true hc
    · rename_i hc
      refine loop_spec lt lo hi hhi pivot a0 hpv mid hmid hm _ _ _ _ _ _ ?_ ?_ ?_ ?_ ?_
      · exact hR
      · intro p hp l u; exact hun p hp (by omega) u
      · exact hlt
      · intro p hp l u
        by_cases h1 : p = k
        · subst h1; simpa using hc
        · exact hge p hp l (by omega)
      · intro _; omega
  · have hk : k = hi := by omega
    subst hk
    have hi' : i < k := he hmid
    refine ⟨hR.trans (Rng.swap as i k (by omega) hhi ilo (by omega) (by omega) (Nat.le_refl _)), hi', ?_, ?_, ?_⟩
    · intro p hp l u
      replace u : p < i := u
      show lt (as.swap i k (by omega) hhi)[p] pivot = true
      rw [Vector.getElem_swap, if_neg (by omega), if_neg (by omega)]
      exact hlt p hp l u
    · intro p hp e
      replace e : p = i := e
      show (as.swap i k (by omega) hhi)[p] = pivot
      subst e
      rw [Vector.getElem_swap, if_pos rfl, hun k hhi (Nat.le_refl _) (Nat.le_refl _), hpv]
    · intro p hp l u
      replace l : i < p := l
      show lt (as.swap i k (by omega) hhi)[p] pivot = false
      rw [Vector.getElem_swap]
      by_cases h1 : p = k
      · rw [if_neg (by omega), if_pos h1]; exact hge i (by omega) (Nat.le_refl _) hi'
      · rw [if_neg (by omega), if_neg h1]; exact hge p hp (by omega) (by omega)
termination_by hi - k

theorem lastStep {Q : α → Prop} (lt : α → α → Bool) (hS : Strict lt Q)
    (a : Vector α n) (hA : AllQ Q a) (mid hi : Nat) (hmh : mid < hi) (hhi : hi < n) :
    lt (if lt a[mid] a[hi] = true then a.swap mid hi (by omega) hhi else a)[mid]
       (if lt a[mid] a[hi] = true then a.swap mid hi (by omega) hhi else a)[hi] = false := by
  split
  · rename_i h
    rw [Vector.getElem_swap_left, Vector.getElem_swap_right]
    cases hb : lt a[hi] a[mid]
    · rfl
    · have := hS.tr _ _ _ (hA _ _) (hA _ _) (hA _ _) h hb; rw [hS.irr _ (hA _ _)] at this; exact (Bool.false_ne_true this).elim
  · rename_i h; simpa using h

theorem part_spec {Q : α → Prop} (lt : α → α → Bool) (hS : Strict lt Q)
    (as : Vector α n) (hA : AllQ Q as) (lo hi : Nat) (w : lo ≤ hi) (hlo : lo < n) (hhi : hi < n) (hl : lo < hi) :
    Rng lo hi as (Array.qpartition as lt lo hi w hlo hhi).2 ∧ (Array.qpartition as lt lo hi w hlo hhi).1.1 < hi ∧
    ∀ x y (hx : x < n) (hy : y < n), lo ≤ x → x ≤ (Array.qpartition as lt lo hi w hlo hhi).1.1 →
      (Array.qpartition as lt lo hi w hlo hhi).1.1 < y → y ≤ hi →
      lt (Array.qpartition as lt lo hi w hlo hhi).2[y] (Array.qpartition as lt lo hi w hlo hhi).2[x] = false := by
  have key : ∀ a3 : Vector α n, Rng lo hi as a3 → lt (a3[(lo + hi) / 2]'(by omega)) a3[hi] = false →
      Rng lo hi as (qsLoop lt lo hi hhi a3[hi] a3 lo lo (Nat.le_refl _) (Nat.le_refl _) w).2 ∧
      (qsLoop lt lo hi hhi a3[hi] a3 lo lo (Nat.le_refl _) (Nat.le_refl _) w).1.1 < hi ∧
      ∀ x y (hx : x < n) (hy : y < n), lo ≤ x → x ≤ (qsLoop lt lo hi hhi a3[hi] a3 lo lo (Nat.le_refl _) (Nat.le_refl _) w).1.1 →
        (qsLoop lt lo hi hhi a3[hi] a3 lo lo (Nat.le_refl _) (Nat.le_refl _) w).1.1 < y → y ≤ hi →
        lt (qsLoop lt lo hi hhi a3[hi] a3 lo lo (Nat.le_refl _) (Nat.le_refl _) w).2[y]
           (qsLoop lt lo hi hhi a3[hi] a3 lo lo (Nat.le_refl _) (Nat.le_refl _) w).2[x] = false := by
    intro a3 hR hmed
    obtain ⟨h1, h2, h3, h4, h5⟩ := loop_spec lt lo hi hhi a3[hi] a3 rfl ((lo + hi) / 2) (by omega) hmed a3 lo lo
      (Nat.le_refl _) (Nat.le_refl _) w (Rng.refl _) (fun _ _ _ _ => rfl) (fun p _ l u => by omega) (fun p _ l u => by omega)
      (fun h => by omega)
    refine ⟨hR.trans h1, h2, fun x y hx hy lx xm my yh => ?_⟩
    cases hb : lt (qsLoop lt lo hi hhi a3[hi] a3 lo lo (Nat.le_refl _) (Nat.le_refl _) w).2[y]
        (qsLoop lt lo hi hhi a3[hi] a3 lo lo (Nat.le_refl _) (Nat.le_refl _) w).2[x]
    · rfl
    · exfalso
      by_cases hxm : x < (qsLoop lt lo hi hhi a3[hi] a3 lo lo (Nat.le_refl _) (Nat.le_refl _) w).1.1
      · have hQ := (hR.trans h1).allQ hA
        have := hS.tr _ _ _ (hQ _ _) (hQ _ _) ((hR.allQ hA) hi hhi) hb (h3 x hx lx hxm)
        rw [h5 y hy my yh] at this; exact Bool.false_ne_true this
      · have hx' : x = (qsLoop lt lo hi hhi a3[hi] a3 lo lo (Nat.le_refl _) (Nat.le_refl _) w).1.1 := by omega
        have e := h4 x hx hx'
        rw [e] at hb
        rw [h5 y hy my yh] at hb; exact Bool.false_ne_true hb
  unfold Array.qpartition
  dsimp only
  refine key _ ?_ ?_
  · exact (Rng.swapIf _ _ _ _ _ _ (by omega) (by omega) (by omega) (by omega)).trans
      ((Rng.swapIf _ _ _ _ _ _ (by omega) (by omega) (by omega) (by omega)).trans
        (Rng.swapIf _ _ _ _ _ _ (by omega) (by omega) (by omega) (by omega)))
  · refine lastStep lt hS _ ?_ ((lo + hi) / 2) hi (by omega) hhi
    refine Rng.allQ (lo := lo) (hi := hi) (a := as) ?_ hA
    exact (Rng.swapIf _ _ _ _ _ _ (by omega) (by omega) (by omega) (by omega)).trans
      (Rng.swapIf _ _ _ _ _ _ (by omega) (by omega) (by omega) (by omega))

/-! ### The sort -/

def SPost (lt : α → α → Bool) (lo hi : Nat) (as bs : Vector α n) : Prop :=
  Rng lo hi as bs ∧ ∀ i j (hi' : i < n) (hj : j < n), lo ≤ i → i < j → j ≤ hi → lt bs[j] bs[i] = false

theorem sort_spec {Q : α → Prop} (lt : α → α → Bool) (hS : Strict lt Q)
    (as : Vector α n) (hA : AllQ Q as) (lo hi : Nat) (w : lo ≤ hi) (hlo : lo < n) (hhi : hi < n) :
    SPost lt lo hi as (qsSort lt as lo hi w hlo hhi) := by
  rw [qsSortDef]
  split
  · rename_i hl
    obtain ⟨hR, hm, hc⟩ := part_spec lt hS as hA lo hi w hlo hhi hl
    generalize Array.qpartition as lt lo hi w hlo hhi = q at hR hm hc ⊢
    obtain ⟨⟨mid, hmid⟩, as'⟩ := q
    dsimp only at hR hm hc ⊢
    split
    · omega
    · rename_i h2
      obtain ⟨r1, s1⟩ := sort_spec lt hS as' (hR.allQ hA) lo mid (by omega) hlo (by omega)
      generalize qsSort lt as' lo mid (by omega) hlo (by omega) = as1 at r1 s1 ⊢
      obtain ⟨r2, s2⟩ := sort_spec lt hS as1 ((hR.trans (r1.widen (Nat.le_refl _) (by omega))).allQ hA) (mid + 1) hi (by omega) (by omega) hhi
      generalize qsSort lt as1 (mid + 1) hi (by omega) (by omega) hhi = as2 at r2 s2 ⊢
      refine ⟨hR.trans ((r1.widen (Nat.le_refl _) (by omega)).trans (r2.widen (by omega) (Nat.le_refl _))), ?_⟩
      intro i j hi' hj l ij u
      by_cases c1 : j ≤ mid
      · rw [r2.out j hj (by omega), r2.out i hi' (by omega)]
        exact s1 i j hi' hj l ij c1
      · by_cases c2 : mid < i
        · exact s2 i j hi' hj c2 ij u
        · obtain ⟨i', hi'', l1, u1, e1⟩ := r1.inn i hi' l (by omega)
          obtain ⟨j', hj'', l2, u2, e2⟩ := r2.inn j hj (by omega) u
          rw [r2.out i hi' (by omega), e2, r1.out j' hj'' (by omega), e1]
          exact hc i' j' hi'' hj'' l1 u1 (by omega) u2
  · exact ⟨Rng.refl _, fun i j _ _ l ij u => by omega⟩
termination_by hi - lo

theorem qsort_spec {Q : α → Prop} (lt : α → α → Bool) (hS : Strict lt Q) (a : Array α) (hA : ∀ x ∈ a, Q x) :
    (a.qsort lt).Perm a ∧ ∀ i j (hi : i < (a.qsort lt).size) (hj : j < (a.qsort lt).size), i < j →
      lt (a.qsort lt)[j] (a.qsort lt)[i] = false := by
  unfold Array.qsort
  by_cases h : a.size = 0
  · simp only [h, dif_pos]
    exact ⟨.refl _, fun i j _ hj _ => by omega⟩
  · simp only [dif_neg h]
    obtain ⟨hR, hs⟩ := sort_spec lt hS a.toVector (fun k hk => hA _ (Array.getElem_mem hk)) (min 0 (a.size - 1))
      (max (min 0 (a.size - 1)) (min (a.size - 1) (a.size - 1))) (by omega) (by omega) (by omega)
    refine ⟨?_, fun i j hi hj ij => ?_⟩
    · have := Vector.perm_iff_toArray_perm.1 hR.perm
      simpa using this
    · have hi' : i < a.size := by simpa using hi
      have hj' : j < a.size := by simpa using hj
      exact hs i j hi' hj' (by omega) ij (by omega)

end BlindLedger.Gate.Flat.QS
