import BlindLedger.Gate.Flat.Model
import BlindLedger.Gate.Rules.Theorems

/-! Statements and proofs of the history-flat gate (`Flat/Model.lean`).  The statements are pinned
    in `AxiomCheck.lean` (with their axioms) and `tools/STMT_PIN.txt`.
    Synthetic, nonpayment, non-PHI, activation=false. -/

namespace BlindLedger.Gate.Flat

open BlindLedger.Gate.Rules BlindLedger.Gate.Rules.Fast
open BlindLedger.Gate.OnepIndex (leb unleb capD capD_rel unleb_leb)
open Std (HashSet)

/-! ## Refinement of the Spec -/

-- BEGIN REFINEMENT LEMMAS

theorem Entry.toA_toEntry (e : Entry) : e.toA.toEntry = e := by
  simp [Entry.toA, EntryA.toEntry]

theorem EntryA.push_eq (H : Bytes → Bytes) (e : EntryA) (p : Posting) : (e.push H p).toEntry = e.toEntry.push H p := by
  by_cases h : e.head.size < capN <;> simp [EntryA.push, Entry.push, EntryA.toEntry, h]

theorem push_foldl (H : Bytes → Bytes) : ∀ (ps : List Posting) (e : Entry), e.head.length ≤ capN →
    (ps.foldl (Entry.push H) e).count = e.count + ps.length ∧
    (ps.foldl (Entry.push H) e).head = e.head ++ ps.take (capN - e.head.length)
  | [], e, _ => by simp
  | p :: ps, e, h => by
    by_cases hl : e.head.length < capN
    · have hp : e.push H p = { e with count := e.count + 1, head := e.head ++ [p] } := by simp [Entry.push, hl]
      obtain ⟨h1, h2⟩ := push_foldl H ps (e.push H p) (by rw [hp]; simp; omega)
      rw [hp] at h1 h2
      simp only [List.foldl_cons, hp, List.length_append, List.length_cons] at h1 h2 ⊢
      refine ⟨by omega, ?_⟩
      rw [h2]
      have : capN - e.head.length = (capN - (e.head.length + 1)) + 1 := by omega
      rw [this, List.take_succ_cons]; simp
    · have hp : e.push H p = { e with count := e.count + 1, tail := H (domain "INDEX/TAIL" ++ e.tail ++ encPosting p) } := by
        simp [Entry.push, hl]
      obtain ⟨h1, h2⟩ := push_foldl H ps (e.push H p) (by rw [hp]; exact h)
      rw [hp] at h1 h2
      have hz : capN - e.head.length = 0 := by omega
      simp only [List.foldl_cons, hp, List.length_cons] at h1 h2 ⊢
      refine ⟨by omega, ?_⟩
      rw [h2, hz]; simp

theorem entryOf_count (H : Bytes → Bytes) (R : List Line) (k : Key) :
    (entryOf H R k).count = (postingsFrom k 0 R).length ∧ (entryOf H R k).head = (postingsFrom k 0 R).take capN := by
  obtain ⟨h1, h2⟩ := push_foldl H (postingsFrom k 0 R) Entry.empty (by simp [Entry.empty])
  simp only [Entry.empty, List.length_nil, Nat.sub_zero, List.nil_append, Nat.zero_add] at h1 h2
  exact ⟨h1, h2⟩

theorem mem_postingsFrom {k : Key} : ∀ (R : List Line) (i : Nat) (p : Posting),
    p ∈ postingsFrom k i R ↔ ∃ j, R[j]? = some p.row ∧ p.seq = i + j ∧ k ∈ keys p.row
  | [], i, p => by simp [postingsFrom]
  | l :: ls, i, p => by
    have ih := mem_postingsFrom (k := k) ls (i + 1) p
    by_cases hk : k ∈ keys l
    · have hc : (keys l).contains k = true := List.contains_iff_mem.mpr hk
      simp only [postingsFrom, hc, ↓reduceIte, List.mem_cons, ih]
      constructor
      · rintro (rfl | ⟨j, h1, h2, h3⟩)
        · exact ⟨0, by simp, by simp, hk⟩
        · exact ⟨j + 1, by simpa using h1, by omega, h3⟩
      · rintro ⟨j, h1, h2, h3⟩
        cases j with
        | zero => left; cases p; simp at h1 h2; simp [h1, h2]
        | succ j => right; exact ⟨j, by simpa using h1, by omega, h3⟩
    · have hc : (keys l).contains k = false := by
        cases h : (keys l).contains k
        · rfl
        · exact absurd (List.contains_iff_mem.mp h) hk
      simp only [postingsFrom, hc, Bool.false_eq_true, ↓reduceIte, ih]
      constructor
      · rintro ⟨j, h1, h2, h3⟩; exact ⟨j + 1, by simpa using h1, by omega, h3⟩
      · rintro ⟨j, h1, h2, h3⟩
        cases j with
        | zero => simp at h1; subst h1; exact absurd h3 hk
        | succ j => exact ⟨j, by simpa using h1, by omega, h3⟩

theorem pairwise_postingsFrom {k : Key} : ∀ (R : List Line) (i : Nat),
    (postingsFrom k i R).Pairwise (fun p q => p.seq < q.seq)
  | [], i => by simp [postingsFrom]
  | l :: ls, i => by
    have ih := pairwise_postingsFrom (k := k) ls (i + 1)
    cases hc : (keys l).contains k
    · simpa only [postingsFrom, hc, Bool.false_eq_true, ↓reduceIte] using ih
    · simp only [postingsFrom, hc, ↓reduceIte, List.pairwise_cons]
      refine ⟨fun q hq => ?_, ih⟩
      obtain ⟨j, -, h2, -⟩ := (mem_postingsFrom ls (i + 1) q).mp hq
      omega


def pf (ks : List Key) : Nat → List Line → List Posting
  | _, [] => []
  | i, l :: ls => if ks.any (keys l).contains then ⟨i, l⟩ :: pf ks (i + 1) ls else pf ks (i + 1) ls

theorem mem_pf {ks : List Key} : ∀ (R : List Line) (i : Nat) (p : Posting),
    p ∈ pf ks i R ↔ ∃ j, R[j]? = some p.row ∧ p.seq = i + j ∧ ks.any (keys p.row).contains = true
  | [], i, p => by simp [pf]
  | l :: ls, i, p => by
    have ih := mem_pf (ks := ks) ls (i + 1) p
    cases hk : ks.any (keys l).contains
    · simp only [pf, hk, Bool.false_eq_true, ↓reduceIte, ih]
      constructor
      · rintro ⟨j, h1, h2, h3⟩; exact ⟨j + 1, by simpa using h1, by omega, h3⟩
      · rintro ⟨j, h1, h2, h3⟩
        cases j with
        | zero => simp at h1; subst h1; rw [hk] at h3; exact absurd h3 (by simp)
        | succ j => exact ⟨j, by simpa using h1, by omega, h3⟩
    · simp only [pf, hk, ↓reduceIte, List.mem_cons, ih]
      constructor
      · rintro (rfl | ⟨j, h1, h2, h3⟩)
        · exact ⟨0, by simp, by simp, hk⟩
        · exact ⟨j + 1, by simpa using h1, by omega, h3⟩
      · rintro ⟨j, h1, h2, h3⟩
        cases j with
        | zero => left; cases p; simp at h1 h2; simp [h1, h2]
        | succ j => right; exact ⟨j, by simpa using h1, by omega, h3⟩

theorem pairwise_pf {ks : List Key} : ∀ (R : List Line) (i : Nat),
    (pf ks i R).Pairwise (fun p q => p.seq < q.seq)
  | [], i => by simp [pf]
  | l :: ls, i => by
    have ih := pairwise_pf (ks := ks) ls (i + 1)
    cases hc : ks.any (keys l).contains
    · simpa only [pf, hc, Bool.false_eq_true, ↓reduceIte] using ih
    · simp only [pf, hc, ↓reduceIte, List.pairwise_cons]
      refine ⟨fun q hq => ?_, ih⟩
      obtain ⟨j, -, h2, -⟩ := (mem_pf ls (i + 1) q).mp hq
      omega

theorem map_row_pf {ks : List Key} : ∀ (R : List Line) (i : Nat),
    (pf ks i R).map (·.row) = R.filter (fun y => ks.any (keys y).contains)
  | [], i => by simp [pf]
  | l :: ls, i => by
    have ih := map_row_pf (ks := ks) ls (i + 1)
    cases hc : ks.any (keys l).contains
    · simp only [pf, hc, Bool.false_eq_true, ↓reduceIte, List.filter_cons, ih]
    · simp only [pf, hc, ↓reduceIte, List.filter_cons, List.map_cons, ih]

theorem mem_pf_iff {ks : List Key} (R : List Line) (p : Posting) :
    p ∈ pf ks 0 R ↔ ∃ k ∈ ks, p ∈ postingsFrom k 0 R := by
  rw [mem_pf]
  simp only [mem_postingsFrom, List.any_eq_true, List.contains_iff_mem, Nat.zero_add]
  constructor
  · rintro ⟨j, h1, h2, k, hk, h3⟩; exact ⟨k, hk, j, h1, h2, h3⟩
  · rintro ⟨k, hk, j, h1, h2, h3⟩; exact ⟨j, h1, h2, k, hk, h3⟩

theorem fromR_pf {ks : List Key} (R : List Line) {p : Posting} (h : p ∈ pf ks 0 R) : R[p.seq]? = some p.row := by
  obtain ⟨j, h1, h2, -⟩ := (mem_pf R 0 p).mp h
  rw [h2]; simpa using h1

theorem dedupSeq_spec : ∀ (M : List Posting), M.Pairwise (fun p q => p.seq ≤ q.seq) →
    (∀ p ∈ dedupSeq M, p ∈ M) ∧ (dedupSeq M).Pairwise (fun p q => p.seq < q.seq) ∧
      ∀ p ∈ M, ∃ q ∈ dedupSeq M, q.seq = p.seq
  | [], _ => by simp [dedupSeq]
  | [p], _ => by simp [dedupSeq]
  | p :: q :: t, h => by
    have ht : (q :: t).Pairwise (fun p q => p.seq ≤ q.seq) := (List.pairwise_cons.mp h).2
    obtain ⟨i1, i2, i3⟩ := dedupSeq_spec (q :: t) ht
    have hpq : ∀ r ∈ q :: t, p.seq ≤ r.seq := (List.pairwise_cons.mp h).1
    by_cases he : p.seq = q.seq
    · have : dedupSeq (p :: q :: t) = dedupSeq (q :: t) := by simp [dedupSeq, he]
      rw [this]
      refine ⟨fun r hr => List.mem_cons_of_mem _ (i1 r hr), i2, fun r hr => ?_⟩
      rcases List.mem_cons.mp hr with rfl | hr
      · obtain ⟨u, hu, hs⟩ := i3 q (by simp)
        exact ⟨u, hu, by rw [hs, he]⟩
      · exact i3 r hr
    · have : dedupSeq (p :: q :: t) = p :: dedupSeq (q :: t) := by simp [dedupSeq, he]
      rw [this]
      refine ⟨fun r hr => ?_, ?_, fun r hr => ?_⟩
      · rcases List.mem_cons.mp hr with rfl | hr
        · simp
        · exact List.mem_cons_of_mem _ (i1 r hr)
      · rw [List.pairwise_cons]
        refine ⟨fun r hr => ?_, i2⟩
        have := hpq r (i1 r hr)
        have h2 : p.seq ≤ q.seq := hpq q (by simp)
        have h3 : q.seq ≤ r.seq := by
          rcases List.mem_cons.mp (i1 r hr) with rfl | hr'
          · exact Nat.le_refl _
          · exact (List.pairwise_cons.mp ht).1 r hr'
        omega
      · rcases List.mem_cons.mp hr with rfl | hr
        · exact ⟨r, by simp, rfl⟩
        · obtain ⟨u, hu, hs⟩ := i3 r hr
          exact ⟨u, List.mem_cons_of_mem _ hu, hs⟩


theorem heads_eq {H : Bytes → Bytes} {S : SetIdx} {snap : Snapshot Line} (hS : IdxInv H S snap) {k : Key}
    (h : (S.get k).count ≤ capN) : heads (S.get k) = postingsFrom k 0 snap.entries := by
  rw [hS.2 k] at h ⊢
  obtain ⟨h1, h2⟩ := entryOf_count H snap.entries k
  unfold heads
  rw [h2, List.take_take, Nat.min_self]
  exact List.take_of_length_le (by omega)

theorem posting_eq {R : List Line} {p q : Posting} (hp : R[p.seq]? = some p.row) (hq : R[q.seq]? = some q.row)
    (h : p.seq = q.seq) : p = q := by
  rw [h] at hp
  have : p.row = q.row := Option.some.inj (hp.symm.trans hq)
  cases p; cases q; simp_all

theorem sorted_postings_eq {a b : List Posting} (ha : a.Pairwise (fun p q => p.seq < q.seq))
    (hb : b.Pairwise (fun p q => p.seq < q.seq)) (hm : ∀ p, p ∈ a ↔ p ∈ b) : a = b := by
  have nd : ∀ {l : List Posting}, l.Pairwise (fun p q => p.seq < q.seq) → l.Nodup := fun h =>
    h.imp (fun {p q} hlt heq => by subst heq; omega)
  refine List.Perm.eq_of_pairwise (le := fun p q => p.seq < q.seq) (fun x y _ _ h1 h2 => by omega) ha hb ?_
  exact (List.perm_ext_iff_of_nodup (nd ha) (nd hb)).mpr hm

theorem localRows_eq {H : Bytes → Bytes} {S : SetIdx} {snap : Snapshot Line} (hS : IdxInv H S snap) (ks : List Key)
    (hfull : ∀ k ∈ ks, (S.get k).count ≤ capN) :
    localRows (ks.map fun k => (k, S.get k)) = pf ks 0 snap.entries := by
  obtain ⟨L, hL⟩ : ∃ L, L = (ks.map fun k => (k, S.get k)).flatMap fun ke => heads ke.2 := ⟨_, rfl⟩
  have hLm : ∀ p, p ∈ L ↔ p ∈ pf ks 0 snap.entries := by
    intro p
    rw [mem_pf_iff, hL]
    simp only [List.mem_flatMap, List.mem_map]
    constructor
    · rintro ⟨ke, ⟨k, hk, rfl⟩, hp⟩
      exact ⟨k, hk, by rwa [heads_eq hS (hfull k hk)] at hp⟩
    · rintro ⟨k, hk, hp⟩
      exact ⟨(k, S.get k), ⟨k, hk, rfl⟩, by rw [heads_eq hS (hfull k hk)]; exact hp⟩
  have hM := List.pairwise_mergeSort (le := fun p q : Posting => decide (p.seq ≤ q.seq))
    (fun a b c h1 h2 => by simp at *; omega) (fun a b => by simp; omega) L
  have hM' : (L.mergeSort fun p q : Posting => decide (p.seq ≤ q.seq)).Pairwise (fun p q => p.seq ≤ q.seq) :=
    hM.imp (fun h => by simpa using h)
  have hMm : ∀ p, p ∈ L.mergeSort (fun p q : Posting => decide (p.seq ≤ q.seq)) ↔ p ∈ L := fun p =>
    (List.mergeSort_perm L _).mem_iff
  obtain ⟨i1, i2, i3⟩ := dedupSeq_spec _ hM'
  unfold localRows
  rw [← hL]
  refine sorted_postings_eq i2 (pairwise_pf _ _) fun p => ?_
  constructor
  · intro hp; exact (hLm p).mp ((hMm p).mp (i1 p hp))
  · intro hp
    obtain ⟨q, hq, hs⟩ := i3 p ((hMm p).mpr ((hLm p).mpr hp))
    have hq' : q ∈ pf ks 0 snap.entries := (hLm q).mp ((hMm q).mp (i1 q hq))
    have := posting_eq (fromR_pf snap.entries hq') (fromR_pf snap.entries hp) hs
    rwa [this] at hq


theorem getElem?_cons_sub (p : Posting) (t : List Posting) (n i : Nat) (h : n + 1 ≤ i) :
    (p :: t)[i - n]? = t[i - (n + 1)]? := by
  have : i - n = (i - (n + 1)) + 1 := by omega
  rw [this]; rfl

theorem pos_foldl : ∀ (L : List Posting) (m : Std.HashMap Nat Nat) (n : Nat),
    L.Pairwise (fun p q => p.seq < q.seq) → ∀ s i,
    ((L.foldl (fun (acc : Std.HashMap Nat Nat × Nat) p => (acc.1.insert p.seq acc.2, acc.2 + 1)) (m, n)).1[s]? = some i ↔
      ((n ≤ i ∧ ∃ q, L[i - n]? = some q ∧ q.seq = s) ∨ (m[s]? = some i ∧ ∀ q ∈ L, q.seq ≠ s)))
  | [], m, n, _, s, i => by simp
  | p :: t, m, n, hpw, s, i => by
    have hpw' := List.pairwise_cons.mp hpw
    simp only [List.foldl_cons]
    rw [pos_foldl t (m.insert p.seq n) (n + 1) hpw'.2 s i, Std.HashMap.getElem?_insert]
    by_cases hs : p.seq = s
    · subst hs
      have hq : ∀ q ∈ t, q.seq ≠ p.seq := fun q hq => Nat.ne_of_gt (hpw'.1 q hq)
      simp only [beq_self_eq_true, ↓reduceIte, Option.some.injEq]
      have e1 : ((n + 1 ≤ i ∧ ∃ q, t[i - (n + 1)]? = some q ∧ q.seq = p.seq) ∨ (n = i ∧ ∀ q ∈ t, q.seq ≠ p.seq)) ↔ i = n := by
        constructor
        · rintro (⟨-, q, h2, h3⟩ | ⟨h1, -⟩)
          · exact absurd h3 (hq q (List.mem_of_getElem? h2))
          · exact h1.symm
        · rintro rfl; exact Or.inr ⟨rfl, hq⟩
      have e2 : ((n ≤ i ∧ ∃ q, (p :: t)[i - n]? = some q ∧ q.seq = p.seq) ∨ (m[p.seq]? = some i ∧ ∀ q ∈ p :: t, q.seq ≠ p.seq)) ↔ i = n := by
        constructor
        · rintro (⟨h1, q, h2, h3⟩ | ⟨-, h2⟩)
          · by_cases h : n + 1 ≤ i
            · rw [getElem?_cons_sub p t n i h] at h2
              exact absurd h3 (hq q (List.mem_of_getElem? h2))
            · omega
          · exact absurd rfl (h2 p (by simp))
        · rintro rfl; exact Or.inl ⟨Nat.le_refl _, p, by simp, rfl⟩
      rw [e1, e2]
    · have hb : (p.seq == s) = false := by simpa using hs
      simp only [hb, Bool.false_eq_true, ↓reduceIte]
      constructor
      · rintro (⟨h1, q, h2, h3⟩ | ⟨h1, h2⟩)
        · left
          refine ⟨by omega, q, ?_, h3⟩
          rw [getElem?_cons_sub p t n i h1]; exact h2
        · right
          exact ⟨h1, fun q hq => by
            rcases List.mem_cons.mp hq with rfl | hq
            · exact hs
            · exact h2 q hq⟩
      · rintro (⟨h1, q, h2, h3⟩ | ⟨h1, h2⟩)
        · by_cases h : n + 1 ≤ i
          · left; exact ⟨h, q, by rw [← getElem?_cons_sub p t n i h]; exact h2, h3⟩
          · have : i = n := by omega
            subst this
            simp at h2; subst h2; exact absurd h3 hs
        · right; exact ⟨h1, fun q hq => h2 q (List.mem_cons_of_mem _ hq)⟩


theorem foldl_insert_getD {β : Type} [Inhabited β] (g : Key → β) : ∀ (ks : List Key) (m : Std.HashMap Key β) (k : Key) (d : β),
    (ks.foldl (fun m k => m.insert k (g k)) m).getD k d = if k ∈ ks then g k else m.getD k d
  | [], m, k, d => by simp
  | a :: t, m, k, d => by
    rw [List.foldl_cons, foldl_insert_getD g t (m.insert a (g a)) k d, Std.HashMap.getD_insert]
    by_cases h : a = k
    · subst h; simp
    · have h' : (a == k) = false := by simpa using h
      have h'' : ¬ (k = a) := fun e => h e.symm
      simp [h', h'', List.mem_cons]

theorem postMap_mem {H : Bytes → Bytes} {S : SetIdx} {snap : Snapshot Line} (hS : IdxInv H S snap) (ks : List Key)
    (hfull : ∀ k ∈ ks, (S.get k).count ≤ capN) {k : Key} (hk : k ∈ ks) (i : Nat) :
    i ∈ (postMap (localRows (ks.map fun k => (k, S.get k))) (ks.map fun k => (k, S.get k))).getD k [] ↔
      ∃ q ∈ postingsFrom k 0 snap.entries, (localRows (ks.map fun k => (k, S.get k)))[i]? = some q := by
  have hrr := localRows_eq hS ks hfull
  generalize hL : localRows (ks.map fun k => (k, S.get k)) = rr at hrr ⊢
  unfold postMap
  rw [List.foldl_map, foldl_insert_getD (fun k => (heads (S.get k)).filterMap fun p =>
    (rr.foldl (fun (acc : Std.HashMap Nat Nat × Nat) p => (acc.1.insert p.seq acc.2, acc.2 + 1)) (∅, 0)).1.get? p.seq) ks]
  rw [if_pos hk, heads_eq hS (hfull k hk)]
  simp only [List.mem_filterMap, Std.HashMap.get?_eq_getElem?]
  have hpw : rr.Pairwise (fun p q => p.seq < q.seq) := hrr ▸ pairwise_pf _ _
  constructor
  · rintro ⟨p, hp, hpos⟩
    rw [pos_foldl rr ∅ 0 hpw] at hpos
    simp only [Nat.sub_zero, Nat.zero_le, true_and] at hpos
    rcases hpos with ⟨q, h2, h3⟩ | ⟨h, -⟩
    · refine ⟨p, hp, ?_⟩
      have hq : q ∈ pf ks 0 snap.entries := hrr ▸ List.mem_of_getElem? h2
      have hp' : p ∈ pf ks 0 snap.entries := (mem_pf_iff _ _).mpr ⟨k, hk, hp⟩
      have := posting_eq (fromR_pf _ hq) (fromR_pf _ hp') h3
      rw [← this]; exact h2
    · simp at h
  · rintro ⟨q, hq, h2⟩
    refine ⟨q, hq, ?_⟩
    rw [pos_foldl rr ∅ 0 hpw]
    simp only [Nat.sub_zero, Nat.zero_le, true_and]
    left; exact ⟨q, h2, rfl⟩


theorem dedup_spec : ∀ (M : List Nat), M.Pairwise (· ≤ ·) →
    (∀ a, a ∈ dedup M ↔ a ∈ M) ∧ (dedup M).Pairwise (· < ·)
  | [], _ => by simp [dedup]
  | [a], _ => by simp [dedup]
  | a :: b :: t, h => by
    have ht : (b :: t).Pairwise (· ≤ ·) := (List.pairwise_cons.mp h).2
    obtain ⟨i1, i2⟩ := dedup_spec (b :: t) ht
    have hab : ∀ r ∈ b :: t, a ≤ r := (List.pairwise_cons.mp h).1
    by_cases he : a = b
    · have : dedup (a :: b :: t) = dedup (b :: t) := by simp [dedup, he]
      rw [this]
      refine ⟨fun r => ?_, i2⟩
      rw [i1 r]; subst he; simp
    · have : dedup (a :: b :: t) = a :: dedup (b :: t) := by simp [dedup, he]
      rw [this]
      refine ⟨fun r => ?_, ?_⟩
      · rw [List.mem_cons, List.mem_cons, i1 r]
      · rw [List.pairwise_cons]
        refine ⟨fun r hr => ?_, i2⟩
        have hr' := (i1 r).mp hr
        have h1 := hab r hr'
        have h2 : r = b ∨ b ≤ r := by
          rcases List.mem_cons.mp hr' with h | h
          · exact Or.inl h
          · exact Or.inr ((List.pairwise_cons.mp ht).1 r h)
        have h3 := hab b (by simp)
        omega

theorem sorted_nat_eq {a b : List Nat} (ha : a.Pairwise (· < ·)) (hb : b.Pairwise (· < ·)) (hm : ∀ x, x ∈ a ↔ x ∈ b) :
    a = b := by
  have nd : ∀ {l : List Nat}, l.Pairwise (· < ·) → l.Nodup := fun h => h.imp (fun {p q} hlt heq => by subst heq; omega)
  refine List.Perm.eq_of_pairwise (le := (· < ·)) (fun x y _ _ h1 h2 => by omega) ha hb ?_
  exact (List.perm_ext_iff_of_nodup (nd ha) (nd hb)).mpr hm

theorem getElem?_cons_sub' (p : Line) (t : List Line) (n i : Nat) (h : n + 1 ≤ i) :
    (p :: t)[i - n]? = t[i - (n + 1)]? := by
  have : i - n = (i - (n + 1)) + 1 := by omega
  rw [this]; rfl

theorem filterMap_congr' {α β : Type} {f g : α → Option β} : ∀ (l : List α), (∀ a ∈ l, f a = g a) → l.filterMap f = l.filterMap g
  | [], _ => rfl
  | a :: l, h => by
    simp only [List.filterMap_cons, h a (by simp), filterMap_congr' l fun x hx => h x (List.mem_cons_of_mem _ hx)]

theorem filterMap_range (q p : Line → Bool) : ∀ (rows : List Line) (j : Nat),
    ((List.range' j rows.length).filter (fun i => (rows[i - j]?).any q)).filterMap
        (fun i => rows[i - j]?.bind fun y => if p y then some y.id else none) =
      ((rows.filter q).filter p).map (·.id)
  | [], j => by simp
  | y :: ys, j => by
    have ih := filterMap_range q p ys (j + 1)
    have e1 : (List.range' (j + 1) ys.length).filter (fun i => ((y :: ys)[i - j]?).any q) =
        (List.range' (j + 1) ys.length).filter (fun i => (ys[i - (j + 1)]?).any q) :=
      List.filter_congr fun i hi => by
        have := (List.mem_range'_1.mp hi).1
        rw [getElem?_cons_sub' y ys j i this]
    have e2 : ((List.range' (j + 1) ys.length).filter (fun i => (ys[i - (j + 1)]?).any q)).filterMap
          (fun i => (y :: ys)[i - j]?.bind fun y => if p y then some y.id else none) =
        ((List.range' (j + 1) ys.length).filter (fun i => (ys[i - (j + 1)]?).any q)).filterMap
          (fun i => ys[i - (j + 1)]?.bind fun y => if p y then some y.id else none) :=
      filterMap_congr' _ fun i hi => by
        have := (List.mem_range'_1.mp (List.mem_filter.mp hi).1).1
        rw [getElem?_cons_sub' y ys j i this]
    simp only [List.length_cons, List.range'_succ, List.filter_cons, Nat.sub_self, List.getElem?_cons_zero,
      Option.any_some]
    rw [e1]
    by_cases hq : q y = true
    · simp only [hq, ↓reduceIte, List.filterMap_cons, ]
      rw [e2, ih]
      by_cases hp : p y = true <;> simp [hp]
    · simp only [hq, Bool.false_eq_true, ↓reduceIte]
      rw [e2, ih]


theorem hasKey_mono {ks ks' : List Key} (hsub : ∀ k ∈ ks', k ∈ ks) {y : Line} (h : ks'.any (keys y).contains = true) :
    ks.any (keys y).contains = true := by
  obtain ⟨k, hk, hc⟩ := List.any_eq_true.mp h
  exact List.any_eq_true.mpr ⟨k, hsub k hk, hc⟩

theorem hits_local {H : Bytes → Bytes} {S : SetIdx} {snap : Snapshot Line} (hS : IdxInv H S snap) (ks : List Key)
    (hfull : ∀ k ∈ ks, (S.get k).count ≤ capN) (ks' : List Key) (hsub : ∀ k ∈ ks', k ∈ ks) (p : Line → Bool) :
    hits ((localRows (ks.map fun k => (k, S.get k))).map (·.row)).toArray
      (postMap (localRows (ks.map fun k => (k, S.get k))) (ks.map fun k => (k, S.get k))) ks' p =
    ((snap.entries.filter (fun y => ks'.any (keys y).contains)).filter p).map (·.id) := by
  have hrr := localRows_eq hS ks hfull
  have hpm := fun k hk i => postMap_mem hS ks hfull (k := k) hk i
  generalize localRows (ks.map fun k => (k, S.get k)) = rr at hrr hpm ⊢
  generalize postMap rr (ks.map fun k => (k, S.get k)) = post at hpm ⊢
  have hM := List.pairwise_mergeSort (le := fun i j : Nat => decide (i ≤ j))
    (fun a b c h1 h2 => by simp at *; omega) (fun a b => by simp; omega) (ks'.flatMap (post.getD · []))
  have hM' : ((ks'.flatMap (post.getD · [])).mergeSort fun i j : Nat => decide (i ≤ j)).Pairwise (· ≤ ·) :=
    hM.imp (fun h => by simpa using h)
  obtain ⟨d1, d2⟩ := dedup_spec _ hM'
  have hT : ∀ i, i ∈ dedup ((ks'.flatMap (post.getD · [])).mergeSort fun i j : Nat => decide (i ≤ j)) ↔
      ∃ y, (rr.map (·.row))[i]? = some y ∧ ks'.any (keys y).contains = true := by
    intro i
    rw [d1, (List.mergeSort_perm _ _).mem_iff, List.mem_flatMap]
    constructor
    · rintro ⟨k, hk, hi⟩
      obtain ⟨q, hq, h2⟩ := (hpm k (hsub k hk) i).mp hi
      refine ⟨q.row, by simp [h2], List.any_eq_true.mpr ⟨k, hk, ?_⟩⟩
      obtain ⟨j, -, -, h3⟩ := (mem_postingsFrom _ 0 q).mp hq
      exact List.contains_iff_mem.mpr h3
    · rintro ⟨y, h1, h2⟩
      obtain ⟨k, hk, hc⟩ := List.any_eq_true.mp h2
      simp only [List.getElem?_map, Option.map_eq_some_iff] at h1
      obtain ⟨q, h3, rfl⟩ := h1
      refine ⟨k, hk, (hpm k (hsub k hk) i).mpr ⟨q, ?_, h3⟩⟩
      have hq : q ∈ pf ks 0 snap.entries := hrr ▸ List.mem_of_getElem? h3
      have := fromR_pf _ hq
      exact (mem_postingsFrom _ 0 q).mpr ⟨q.seq, by simpa using this, by simp, List.contains_iff_mem.mp hc⟩
  have hT' : dedup ((ks'.flatMap (post.getD · [])).mergeSort fun i j : Nat => decide (i ≤ j)) =
      (List.range' 0 (rr.map (·.row)).length).filter (fun i => ((rr.map (·.row))[i - 0]?).any (fun y => ks'.any (keys y).contains)) := by
    refine sorted_nat_eq d2 (List.Pairwise.filter _ List.pairwise_lt_range') fun i => ?_
    rw [hT, List.mem_filter, List.mem_range'_1]
    simp only [Nat.sub_zero, Option.any_eq_true]
    constructor
    · rintro ⟨y, h1, h2⟩
      have := (List.getElem?_eq_some_iff.mp h1).1
      exact ⟨⟨Nat.zero_le _, by omega⟩, y, h1, h2⟩
    · rintro ⟨-, y, h1, h2⟩; exact ⟨y, h1, h2⟩
  unfold hits
  rw [hT']
  simp only [List.getElem?_toArray, Nat.sub_zero]
  have := filterMap_range (fun y => ks'.any (keys y).contains) p (rr.map (·.row)) 0
  simp only [Nat.sub_zero] at this
  have hrows : rr.map (·.row) = snap.entries.filter (fun y => ks.any (keys y).contains) := by
    rw [hrr]; exact map_row_pf _ _
  have hf : (snap.entries.filter (fun y => ks.any (keys y).contains)).filter (fun y => ks'.any (keys y).contains) =
      snap.entries.filter (fun y => ks'.any (keys y).contains) := by
    rw [List.filter_filter]
    refine List.filter_congr fun y _ => ?_
    cases h : ks'.any (keys y).contains
    · simp
    · simp [hasKey_mono hsub h]
  rw [this, hrows, hf]


theorem probe_local {H : Bytes → Bytes} {S : SetIdx} {snap : Snapshot Line} (hS : IdxInv H S snap) (ks : List Key)
    (hfull : ∀ k ∈ ks, (S.get k).count ≤ capN) {k : Key} (hk : k ∈ ks) (P : Line → Bool) :
    (((postMap (localRows (ks.map fun k => (k, S.get k))) (ks.map fun k => (k, S.get k))).getD k []).any
      fun i => decide (i < (localRows (ks.map fun k => (k, S.get k))).length) &&
        ((localRows (ks.map fun k => (k, S.get k))).map (·.row)).toArray[i]?.any P) = true ↔
      ∃ y ∈ snap.entries, k ∈ keys y ∧ P y = true := by
  have hrr := localRows_eq hS ks hfull
  have hpm := fun i => postMap_mem hS ks hfull hk i
  generalize localRows (ks.map fun k => (k, S.get k)) = rr at hrr hpm ⊢
  generalize postMap rr (ks.map fun k => (k, S.get k)) = post at hpm ⊢
  simp only [List.any_eq_true, Bool.and_eq_true, decide_eq_true_eq, List.getElem?_toArray, Option.any_eq_true]
  constructor
  · rintro ⟨i, hi, -, y, h1, h2⟩
    obtain ⟨q, hq, h3⟩ := (hpm i).mp hi
    simp only [List.getElem?_map, h3, Option.map_some, Option.some.injEq] at h1
    subst h1
    obtain ⟨j, h4, -, h5⟩ := (mem_postingsFrom _ 0 q).mp hq
    exact ⟨q.row, List.mem_of_getElem? h4, h5, h2⟩
  · rintro ⟨y, hy, hky, hP⟩
    obtain ⟨j, hj⟩ := List.mem_iff_getElem?.mp hy
    have hq : (⟨j, y⟩ : Posting) ∈ postingsFrom k 0 snap.entries :=
      (mem_postingsFrom _ 0 _).mpr ⟨j, hj, by simp, hky⟩
    have hq' : (⟨j, y⟩ : Posting) ∈ rr := hrr ▸ (mem_pf_iff _ _).mpr ⟨k, hk, hq⟩
    obtain ⟨i, hi⟩ := List.mem_iff_getElem?.mp hq'
    exact ⟨i, (hpm i).mpr ⟨_, hq, hi⟩, (List.getElem?_eq_some_iff.mp hi).1, y, by simp [hi], hP⟩

theorem foldl_insert_getD_nat {β : Type} (g : Nat → β) : ∀ (ks : List Nat) (m : Std.HashMap Nat β) (k : Nat) (d : β),
    (ks.foldl (fun m k => m.insert k (g k)) m).getD k d = if k ∈ ks then g k else m.getD k d
  | [], m, k, d => by simp
  | a :: t, m, k, d => by
    rw [List.foldl_cons, foldl_insert_getD_nat g t (m.insert a (g a)) k d, Std.HashMap.getD_insert]
    by_cases h : a = k
    · subst h; simp
    · have h' : (a == k) = false := by simpa using h
      have h'' : ¬ (k = a) := fun e => h e.symm
      simp [h', h'', List.mem_cons]

theorem idMap_getD {α : Type} (g : Nat → List α) (ids : List Nat) (i : Nat) :
    (idMap g ids).getD i [] = if i ∈ ids then facts (g i) else [] := by
  unfold idMap
  rw [foldl_insert_getD_nat (fun i => facts (g i)) ids ∅ i []]
  simp

theorem facts_of_not_over {α : Type} {xs : List α} (h : feedOver xs = false) : facts xs = xs := by
  unfold facts; unfold feedOver at h
  exact List.take_of_length_le (by simpa using h)

theorem uniq_foldl : ∀ (ks : List Key) (acc : HashSet Key × List Key), (∀ x, acc.1.contains x = true ↔ x ∈ acc.2) →
    ∀ x, x ∈ (ks.foldl uniqStep acc).2 ↔ x ∈ acc.2 ∨ x ∈ ks
  | [], acc, _, x => by simp
  | a :: t, acc, h, x => by
    rw [List.foldl_cons]
    by_cases ha : acc.1.contains a = true
    · have : uniqStep acc a = acc := by simp [uniqStep, ha]
      rw [this, uniq_foldl t acc h x]
      have := (h a).mp ha
      constructor
      · rintro (h1 | h1)
        · exact Or.inl h1
        · exact Or.inr (List.mem_cons_of_mem _ h1)
      · rintro (h1 | h1)
        · exact Or.inl h1
        · rcases List.mem_cons.mp h1 with rfl | h2
          · exact Or.inl this
          · exact Or.inr h2
    · have hs : uniqStep acc a = (acc.1.insert a, a :: acc.2) := by simp [uniqStep, ha]
      rw [hs, uniq_foldl t _ (fun y => by
        simp only [HashSet.contains_insert, Bool.or_eq_true, beq_iff_eq, List.mem_cons]
        rw [h y]; constructor <;> rintro (h1 | h1) <;> first | exact Or.inl h1.symm | exact Or.inr h1 | exact Or.inl h1 | exact Or.inr h1) x]
      simp only [List.mem_cons]
      constructor
      · rintro ((h1 | h1) | h1)
        · exact Or.inr (Or.inl h1)
        · exact Or.inl h1
        · exact Or.inr (Or.inr h1)
      · rintro (h1 | h1 | h1)
        · exact Or.inl (Or.inr h1)
        · exact Or.inl (Or.inl h1)
        · exact Or.inr h1

theorem mem_uniq {ks : List Key} {x : Key} : x ∈ uniq ks ↔ x ∈ ks := by
  unfold uniq
  rw [List.mem_reverse, uniq_foldl ks (∅, []) (fun y => by simp) x]
  simp

theorem mem_probeKeys {b : List Line} {k : Key} : k ∈ probeKeys b ↔ ∃ l ∈ b, k ∈ keys l := by
  unfold probeKeys; rw [mem_uniq]; simp [List.mem_flatMap]


def uEs (s : St) (b : List Line) : List (Key × Entry) := (probeKeys b).map fun k => (k, s.unr.get k)

def ksR (s : St) (redo : List Nat) (b : List Line) : List Key := probeKeys b ++ round2 redo (probeKeys b) (uEs s b)

theorem fetch_rel' (s : St) (redo : List Nat) (b : List Line) :
    (fetch s redo b).rel = (ksR s redo b).map fun k => (k, s.rel.get k) := rfl

theorem fetch_unr' (s : St) (redo : List Nat) (b : List Line) : (fetch s redo b).unr = uEs s b := rfl

theorem capCount_lt {C : Key → Nat} {k : Key} {e : Entry} :
    capN < capCount C k e ↔ capN < e.count ∨ ∃ c, keyCore k = some c ∧ capN < C c := by
  unfold capCount
  cases keyCore k with
  | none => simp
  | some c => by_cases h : capN < C c <;> simp [h]

theorem hot_count {fe : Fetched} {fd : Feeds} {b : List Line} {ke : Key × Entry} (hk : ke ∈ fe.rel ++ fe.unr)
    (h : capN < ke.2.count) : (hotKeys fe fd b).contains ke.1 = true := by
  unfold hotKeys
  rw [HashSet.contains_ofList]
  apply List.contains_iff_mem.mpr
  simp only [List.mem_append, List.mem_map, List.mem_filter]
  rcases List.mem_append.mp hk with hk | hk
  · exact Or.inl (Or.inl (Or.inl ⟨ke, ⟨hk, by simpa using capCount_lt.mpr (.inl h)⟩, rfl⟩))
  · exact Or.inl (Or.inl (Or.inr ⟨ke, ⟨hk, by simpa using capCount_lt.mpr (.inl h)⟩, rfl⟩))

theorem hot_span {fe : Fetched} {fd : Feeds} {b : List Line} {ke : Key × Entry} (hk : ke ∈ fe.unr) {p : Posting}
    (hp : p ∈ heads ke.2) (hc : isCap p.row = true) (hov : feedOver (fd.span p.row.member) = true) :
    (hotKeys fe fd b).contains ke.1 = true := by
  unfold hotKeys
  rw [HashSet.contains_ofList]
  apply List.contains_iff_mem.mpr
  simp only [List.mem_append, List.mem_map, List.mem_filter]
  exact Or.inl (Or.inr ⟨ke, ⟨hk, by simp only [List.any_eq_true, Bool.and_eq_true]; exact ⟨p, hp, hc, hov⟩⟩, rfl⟩)

section Unc
variable {fe : Fetched} {fd : Feeds} {b : List Line}

theorem unc_hot (hb : Uncapped fe fd b) {l : Line} (hl : l ∈ b) {k : Key} (hk : k ∈ keys l) :
    (hotKeys fe fd b).contains k = false := by
  have h := hb l hl
  unfold capped at h
  simp only [Bool.or_eq_false_iff] at h
  cases hc : (hotKeys fe fd b).contains k
  · rfl
  · have : (keys l).any (hotKeys fe fd b).contains = true := List.any_eq_true.mpr ⟨k, hk, hc⟩
    rw [this] at h; exact absurd h.1.2 (by simp)

theorem unc_idCapped (hb : Uncapped fe fd b) {l : Line} (hl : l ∈ b) : idCapped fe = false := by
  have h := hb l hl
  unfold capped at h
  simp only [Bool.or_eq_false_iff] at h
  exact h.1.1

theorem unc_feed (hb : Uncapped fe fd b) {l : Line} (hl : l ∈ b) :
    feedOver (fd.dmf l.member) = false ∧ feedOver (fd.span l.member) = false ∧ feedOver (fd.pdeath l.payee) = false ∧
    feedOver (fd.excl l.payee) = false ∧ feedOver (fd.pdeath l.rendering) = false ∧ feedOver (fd.excl l.rendering) = false := by
  have h := hb l hl
  unfold capped feedCapped at h
  simp only [Bool.or_eq_false_iff, List.any_cons, List.any_nil, Bool.or_false] at h
  obtain ⟨-, ⟨⟨h1, h2⟩, ⟨h3, h4⟩⟩⟩ := h
  exact ⟨h1, h2, h3.1, h3.2, h4.1, h4.2⟩

end Unc

theorem round2_cover {redo : List Nat} {ks : List Key} {u : List (Key × Entry)} {ke : Key × Entry} (hke : ke ∈ u)
    {p : Posting} (hp : p ∈ heads ke.2) (hcap : isCap p.row = true) (hred : redo.contains p.row.pay = true) :
    idKey p.row ∈ ks ∨ idKey p.row ∈ round2 redo ks u := by
  by_cases hk : idKey p.row ∈ ks
  · exact Or.inl hk
  · right
    unfold round2
    rw [mem_uniq, List.mem_filter]
    refine ⟨?_, ?_⟩
    · simp only [List.mem_flatMap, List.mem_filterMap]
      have hred' := List.contains_iff_mem.mp hred
      exact ⟨ke, hke, p, hp, by simp [hcap, hred']⟩
    · simp [HashSet.contains_ofList, hk]

theorem mem_round2 {redo : List Nat} {ks : List Key} {u : List (Key × Entry)} {k : Key} (h : k ∈ round2 redo ks u) :
    k.head? = some 4 := by
  unfold round2 at h
  rw [mem_uniq, List.mem_filter] at h
  obtain ⟨h1, -⟩ := h
  simp only [List.mem_flatMap, List.mem_filterMap] at h1
  obtain ⟨ke, -, p, -, h3⟩ := h1
  split at h3
  · simp at h3; subst h3; simp [idKey]
  · simp at h3

theorem cnt_unr {s : St} {redo : List Nat} {fd : Feeds} {b : List Line} (hb : Uncapped (fetch s redo b) fd b) :
    ∀ k ∈ probeKeys b, (s.unr.get k).count ≤ capN := by
  intro k hk
  by_cases hc0 : (s.unr.get k).count ≤ capN
  · exact hc0
  have hc : capN < (s.unr.get k).count := by omega
  obtain ⟨l, hl, hkl⟩ := mem_probeKeys.mp hk
  have := hot_count (fe := fetch s redo b) (fd := fd) (b := b) (ke := (k, s.unr.get k))
    (List.mem_append_right _ (by rw [fetch_unr']; exact List.mem_map.mpr ⟨k, hk, rfl⟩)) (by simpa using hc)
  rw [unc_hot hb hl hkl] at this
  exact absurd this (by simp)

theorem cnt_rel {s : St} {redo : List Nat} {fd : Feeds} {b : List Line} (hb : Uncapped (fetch s redo b) fd b)
    {l0 : Line} (hl0 : l0 ∈ b) : ∀ k ∈ ksR s redo b, (s.rel.get k).count ≤ capN := by
  intro k hk
  by_cases hc0 : (s.rel.get k).count ≤ capN
  · exact hc0
  have hc : capN < (s.rel.get k).count := by omega
  have hmem : (k, s.rel.get k) ∈ (fetch s redo b).rel := by
    rw [fetch_rel']; exact List.mem_map.mpr ⟨k, hk, rfl⟩
  rcases List.mem_append.mp hk with hk | hk
  · obtain ⟨l, hl, hkl⟩ := mem_probeKeys.mp hk
    have := hot_count (fe := fetch s redo b) (fd := fd) (b := b) (ke := (k, s.rel.get k))
      (List.mem_append_left _ hmem) (by simpa using hc)
    rw [unc_hot hb hl hkl] at this
    exact absurd this (by simp)
  · have h4 := mem_round2 hk
    have hid := unc_idCapped hb hl0
    unfold idCapped at hid
    have : (fetch s redo b).rel.any (fun ke => ke.1.head? == some 4 && capN < ke.2.count) = true :=
      List.any_eq_true.mpr ⟨_, hmem, by simp [h4]; omega⟩
    rw [hid] at this; exact absurd this (by simp)


def locIx (s : St) (fc : FCtx) (b : List Line) : Ix :=
  let fe := fetch s fc.redo b
  localIx s.rel.head s.unr.head fe (localRows fe.rel) (localRows fe.unr) fc b

theorem view_self' (t : Nat) (p : Snapshot Line) : view t p (some p) = p := by
  unfold view; split <;> rfl

theorem carried_rel (c₀ : Ctx) (rel unr : Snapshot Line) : releasedSet (carried c₀ rel unr) = rel.entries := by
  simp [releasedSet, carried, view_self']

theorem carried_unr (c₀ : Ctx) (rel unr : Snapshot Line) : unresolvedSet (carried c₀ rel unr) = unr.entries := by
  simp [unresolvedSet, carried, view_self']

section Q
variable {H : Bytes → Bytes} {s : St} {fc : FCtx} {c₀ : Ctx} {rel unr : Snapshot Line} {b : List Line}

theorem probeR (hr : IdxInv H s.rel rel) (hcnt : ∀ k ∈ ksR s fc.redo b, (s.rel.get k).count ≤ capN)
    {k : Key} (hk : k ∈ ksR s fc.redo b) (P : Line → Bool) :
    (((locIx s fc b).relPost.getD k []).any fun i => decide (i < (locIx s fc b).relN) && (locIx s fc b).rel[i]?.any P) = true ↔
      ∃ y ∈ rel.entries, k ∈ keys y ∧ P y = true :=
  probe_local hr (ksR s fc.redo b) hcnt hk P

theorem probeU (hu : IdxInv H s.unr unr) (hcnt : ∀ k ∈ probeKeys b, (s.unr.get k).count ≤ capN)
    {k : Key} (hk : k ∈ probeKeys b) (P : Line → Bool) :
    (((locIx s fc b).unrPost.getD k []).any fun i => decide (i < (locIx s fc b).unrN) && (locIx s fc b).unr[i]?.any P) = true ↔
      ∃ y ∈ unr.entries, k ∈ keys y ∧ P y = true :=
  probe_local hu (probeKeys b) hcnt hk P

theorem own_loc (hr : IdxInv H s.rel rel) (hc : FCtxInv fc c₀) (hb : Uncapped (fetch s fc.redo b) fc.feeds b)
    {l0 : Line} (hl0 : l0 ∈ b) {y : Line} (hy : fc.redo.contains y.pay = true → idKey y ∈ ksR s fc.redo b) :
    (locIx s fc b).own y = own (carried c₀ rel unr) y := by
  unfold Ix.own own
  have hrd : (locIx s fc b).redo.contains y.pay = fc.redo.contains y.pay := by
    simp [locIx, localIx, HashSet.contains_ofList]
  have hrd2 : (carried c₀ rel unr).redo = fc.redo := hc.2.1.symm
  rw [hrd, hrd2, carried_rel]
  by_cases hred : fc.redo.contains y.pay = true
  · rw [hred, Bool.true_and, Bool.true_and, Bool.eq_iff_iff,
      probeR hr (cnt_rel hb hl0) (hy hred) (· == y)]
    simp only [List.contains_iff_mem, beq_iff_eq]
    constructor
    · rintro ⟨y', hy', _, rfl⟩; exact hy'
    · intro h; exact ⟨y, h, idKey_mem, rfl⟩
  · have : fc.redo.contains y.pay = false := by simpa using hred
    rw [this, Bool.false_and, Bool.false_and]


theorem span_get (hc : FCtxInv fc c₀) {i : Nat} (hmem : i ∈ spanIds b (localRows (fetch s fc.redo b).unr))
    (hov : feedOver (fc.feeds.span i) = false) :
    (locIx s fc b).span.getD i [] = (entries c₀.enrollment).filter (·.member == i) := by
  obtain ⟨-, -, -, -, -, -, -, -, -, -, -, -, -, hSp, -⟩ := hc
  show (idMap fc.feeds.span (spanIds b (localRows (fetch s fc.redo b).unr))).getD i [] = _
  rw [idMap_getD, if_pos hmem, facts_of_not_over hov, hSp]

theorem dmf_get (hc : FCtxInv fc c₀) {i : Nat} (hmem : i ∈ members b) (hov : feedOver (fc.feeds.dmf i) = false) :
    (locIx s fc b).dmf.getD i [] = (entries c₀.dmf).filter (·.id == i) := by
  obtain ⟨-, -, -, -, -, -, -, -, -, -, hDm, -, -, -⟩ := hc
  show (idMap fc.feeds.dmf (members b)).getD i [] = _
  rw [idMap_getD, if_pos hmem, facts_of_not_over hov, hDm]

theorem pd_get (hc : FCtxInv fc c₀) {i : Nat} (hmem : i ∈ parties b) (hov : feedOver (fc.feeds.pdeath i) = false) :
    (locIx s fc b).pdeath.getD i [] = (entries c₀.providerDeaths).filter (·.id == i) := by
  obtain ⟨-, -, -, -, -, -, -, -, -, -, -, hPd, -, -⟩ := hc
  show (idMap fc.feeds.pdeath (parties b)).getD i [] = _
  rw [idMap_getD, if_pos hmem, facts_of_not_over hov, hPd]

theorem ex_get (hc : FCtxInv fc c₀) {i : Nat} (hmem : i ∈ parties b) (hov : feedOver (fc.feeds.excl i) = false) :
    (locIx s fc b).excl.getD i [] = (entries c₀.exclusions).filter (·.id == i) := by
  obtain ⟨-, -, -, -, -, -, -, -, -, -, -, -, hEx, -⟩ := hc
  show (idMap fc.feeds.excl (parties b)).getD i [] = _
  rw [idMap_getD, if_pos hmem, facts_of_not_over hov, hEx]

theorem enrolled_loc (hc : FCtxInv fc c₀) {l : Line} (hmem : l.member ∈ spanIds b (localRows (fetch s fc.redo b).unr))
    (hov : feedOver (fc.feeds.span l.member) = false) :
    (locIx s fc b).enrolled l = enrolled (carried c₀ rel unr) l := by
  unfold Ix.enrolled enrolled
  rw [span_get hc hmem hov, Bool.eq_iff_iff]
  simp only [List.any_eq_true, List.mem_filter, beq_iff_eq]
  constructor
  · rintro ⟨sp, ⟨hs, _⟩, hcv⟩; exact ⟨sp, hs, hcv⟩
  · rintro ⟨sp, hs, hcv⟩
    exact ⟨sp, ⟨hs, by have := covers_member hcv; simp [this]⟩, hcv⟩

theorem notEnrolled_loc (hc : FCtxInv fc c₀) {l : Line} (hmem : l.member ∈ spanIds b (localRows (fetch s fc.redo b).unr))
    (hov : feedOver (fc.feeds.span l.member) = false) :
    (locIx s fc b).notEnrolled l = notEnrolled (carried c₀ rel unr) l := by
  unfold Ix.notEnrolled notEnrolled certain
  have hso : (locIx s fc b).spanOk = usable (carried c₀ rel unr).today 7 okSpan (carried c₀ rel unr).enrollment := hc.2.2.2.2.2.2.2.2.2.1
  rw [hso, enrolled_loc hc hmem hov]

theorem memberDead_loc (hc : FCtxInv fc c₀) {l : Line} (hmem : l.member ∈ members b)
    (hov : feedOver (fc.feeds.dmf l.member) = false) :
    (locIx s fc b).memberDead l = memberDead (carried c₀ rel unr) l := by
  unfold Ix.memberDead memberDead
  rw [dmf_get hc hmem hov, Bool.eq_iff_iff]
  simp only [List.any_eq_true, List.mem_filter, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq]
  constructor
  · rintro ⟨d, ⟨hd, h1⟩, h2⟩; exact ⟨d, hd, h1, h2⟩
  · rintro ⟨d, hd, h1, h2⟩; exact ⟨d, ⟨hd, h1⟩, h2⟩

theorem providerDead_loc (hc : FCtxInv fc c₀) {l : Line} (hm1 : l.payee ∈ parties b) (hm2 : l.rendering ∈ parties b)
    (ho1 : feedOver (fc.feeds.pdeath l.payee) = false) (ho2 : feedOver (fc.feeds.pdeath l.rendering) = false) :
    (locIx s fc b).providerDead l = providerDead (carried c₀ rel unr) l := by
  unfold Ix.providerDead providerDead party
  rw [pd_get hc hm1 ho1, pd_get hc hm2 ho2, Bool.eq_iff_iff]
  simp only [List.any_eq_true, List.mem_filter, Bool.and_eq_true, Bool.or_eq_true, beq_iff_eq, decide_eq_true_eq]
  constructor
  · rintro (⟨d, ⟨hd, h1⟩, h2⟩ | ⟨d, ⟨hd, h1⟩, h2⟩)
    · exact ⟨d, hd, Or.inl h1, h2⟩
    · exact ⟨d, hd, Or.inr h1, h2⟩
  · rintro ⟨d, hd, h1 | h1, h2⟩
    · exact Or.inl ⟨d, ⟨hd, h1⟩, h2⟩
    · exact Or.inr ⟨d, ⟨hd, h1⟩, h2⟩

theorem excluded_loc (hc : FCtxInv fc c₀) {l : Line} (hm1 : l.payee ∈ parties b) (hm2 : l.rendering ∈ parties b)
    (ho1 : feedOver (fc.feeds.excl l.payee) = false) (ho2 : feedOver (fc.feeds.excl l.rendering) = false) :
    (locIx s fc b).excluded l = excluded (carried c₀ rel unr) l := by
  unfold Ix.excluded excluded party
  rw [ex_get hc hm1 ho1, ex_get hc hm2 ho2, Bool.eq_iff_iff]
  simp only [List.any_eq_true, List.mem_filter, Bool.and_eq_true, Bool.or_eq_true, beq_iff_eq, decide_eq_true_eq]
  constructor
  · rintro (⟨d, ⟨hd, h1⟩, h2, h3⟩ | ⟨d, ⟨hd, h1⟩, h2, h3⟩)
    · exact ⟨d, hd, ⟨Or.inl h1, h2⟩, h3⟩
    · exact ⟨d, hd, ⟨Or.inr h1, h2⟩, h3⟩
  · rintro ⟨d, hd, ⟨h1 | h1, h2⟩, h3⟩
    · exact Or.inl ⟨d, ⟨hd, h1⟩, h2, h3⟩
    · exact Or.inr ⟨d, ⟨hd, h1⟩, h2, h3⟩

theorem overlap_loc (hc : FCtxInv fc c₀) {l : Line} (hmem : l.member ∈ spanIds b (localRows (fetch s fc.redo b).unr))
    (hov : feedOver (fc.feeds.span l.member) = false) :
    (locIx s fc b).overlap l = overlap (carried c₀ rel unr) l := by
  unfold Ix.overlap overlap
  rw [span_get hc hmem hov]
  rfl


end Q

theorem row_mem {H : Bytes → Bytes} {S : SetIdx} {snap : Snapshot Line} (hS : IdxInv H S snap) (ks : List Key)
    (hfull : ∀ k ∈ ks, (S.get k).count ≤ capN) {k : Key} (hk : k ∈ ks) {y : Line} (hy : y ∈ snap.entries)
    (hky : k ∈ keys y) :
    ∃ q ∈ localRows (ks.map fun k => (k, S.get k)), q.row = y ∧ q ∈ postingsFrom k 0 snap.entries := by
  obtain ⟨j, hj⟩ := List.mem_iff_getElem?.mp hy
  have hq : (⟨j, y⟩ : Posting) ∈ postingsFrom k 0 snap.entries :=
    (mem_postingsFrom _ 0 _).mpr ⟨j, hj, by simp, hky⟩
  refine ⟨⟨j, y⟩, ?_, rfl, hq⟩
  rw [localRows_eq hS ks hfull]
  exact (mem_pf_iff _ _).mpr ⟨k, hk, hq⟩

theorem loose_carried (t : Nat) (p : Snapshot Line) : loose t p (some p) = [] := by
  unfold loose
  split
  · rfl
  · simp [entries]

theorem mem_ksR_of_probe {s : St} {redo : List Nat} {b : List Line} {k : Key} (h : k ∈ probeKeys b) :
    k ∈ ksR s redo b := List.mem_append_left _ h

section Q2
variable {H : Bytes → Bytes} {s : St} {fc : FCtx} {c₀ : Ctx} {rel unr : Snapshot Line} {b : List Line}

theorem own_b (hr : IdxInv H s.rel rel) (hc : FCtxInv fc c₀) (hb : Uncapped (fetch s fc.redo b) fc.feeds b)
    {l : Line} (hl : l ∈ b) : (locIx s fc b).own l = own (carried c₀ rel unr) l :=
  own_loc hr hc hb hl fun _ => mem_ksR_of_probe (mem_probeKeys.mpr ⟨l, hl, idKey_mem⟩)

theorem mem_members {l : Line} (hl : l ∈ b) : l.member ∈ members b := List.mem_map.mpr ⟨l, hl, rfl⟩

theorem mem_spanIds {l : Line} (hl : l ∈ b) (ur : List Posting) : l.member ∈ spanIds b ur :=
  List.mem_append_left _ (mem_members hl)

theorem mem_parties {l : Line} (hl : l ∈ b) : l.payee ∈ parties b ∧ l.rendering ∈ parties b :=
  ⟨List.mem_flatMap.mpr ⟨l, hl, by simp⟩, List.mem_flatMap.mpr ⟨l, hl, by simp⟩⟩

theorem claim_b (hr : IdxInv H s.rel rel) (hc : FCtxInv fc c₀) (hb : Uncapped (fetch s fc.redo b) fc.feeds b)
    {l : Line} (hl : l ∈ b) : (locIx s fc b).claim l = claim (carried c₀ rel unr) l := by
  unfold Ix.claim claim
  rw [notEnrolled_loc hc (mem_spanIds hl _) (unc_feed hb hl).2.1, own_b hr hc hb hl]

theorem claim_u (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr) (hc : FCtxInv fc c₀)
    (hb : Uncapped (fetch s fc.redo b) fc.feeds b) {l0 : Line} (hl0 : l0 ∈ b) {y : Line} (hy : y ∈ unr.entries)
    {k : Key} (hk : k ∈ probeKeys b) (hky : k ∈ keys y) :
    (locIx s fc b).claim y = claim (carried c₀ rel unr) y := by
  have hcu := cnt_unr hb
  obtain ⟨q, hq, hqy, hqp⟩ := row_mem hu (probeKeys b) hcu hk hy hky
  have hhead : q ∈ heads (s.unr.get k) := by rw [heads_eq hu (hcu k hk)]; exact hqp
  have hke : (k, s.unr.get k) ∈ (fetch s fc.redo b).unr := by
    rw [fetch_unr']; exact List.mem_map.mpr ⟨k, hk, rfl⟩
  by_cases hcap : isCap y = true
  · have hy' : fc.redo.contains y.pay = true → idKey y ∈ ksR s fc.redo b := by
      intro hred
      have := round2_cover (redo := fc.redo) (ks := probeKeys b) (u := uEs s b) (ke := (k, s.unr.get k))
        (by exact List.mem_map.mpr ⟨k, hk, rfl⟩) hhead (by rw [hqy]; exact hcap) (by rw [hqy]; exact hred)
      rw [hqy] at this
      rcases this with h | h
      · exact List.mem_append_left _ h
      · exact List.mem_append_right _ h
    have hov : feedOver (fc.feeds.span y.member) = false := by
      cases hh : feedOver (fc.feeds.span y.member)
      · rfl
      · exfalso
        have := hot_span (fe := fetch s fc.redo b) (fd := fc.feeds) (b := b) hke hhead (by rw [hqy]; exact hcap)
          (by rw [hqy]; exact hh)
        obtain ⟨l, hl, hkl⟩ := mem_probeKeys.mp hk
        rw [unc_hot hb hl hkl] at this
        exact absurd this (by simp)
    have hmem : y.member ∈ spanIds b (localRows (fetch s fc.redo b).unr) :=
      List.mem_append_right _ (List.mem_map.mpr ⟨q, by rw [fetch_unr']; exact hq, by rw [hqy]⟩)
    unfold Ix.claim claim
    rw [notEnrolled_loc hc hmem hov, own_loc hr hc hb hl0 hy']
  · have : isCap y = false := by simpa using hcap
    unfold Ix.claim claim
    simp [this]

theorem seen0_loc (hr : IdxInv H s.rel rel) (hc : FCtxInv fc c₀) (hb : Uncapped (fetch s fc.redo b) fc.feeds b)
    {l0 : Line} (hl0 : l0 ∈ b) {k : Key} (hk : k ∈ probeKeys b) :
    (locIx s fc b).seen0 k = (Ix.build (carried c₀ rel unr) b).seen0 k := by
  rw [seen0_eq, Bool.eq_iff_iff]
  unfold Ix.seen0 seen0
  rw [probeR hr (cnt_rel hb hl0) (mem_ksR_of_probe hk)]
  simp only [List.contains_iff_mem, List.mem_flatMap, List.mem_filter, carried_rel]
  have hP : ∀ y, (!((locIx s fc b).own y && (locIx s fc b).batch.contains y)) =
      !(own (carried c₀ rel unr) y && b.contains y) := by
    intro y
    have hbt : (locIx s fc b).batch.contains y = b.contains y := by
      simp [locIx, localIx, HashSet.contains_ofList]
    rw [hbt]
    cases hb' : b.contains y
    · simp
    · rw [own_b hr hc hb (List.contains_iff_mem.mp hb')]
  constructor
  · rintro ⟨y, hy, hky, hp⟩; exact ⟨y, ⟨hy, by rw [← hP]; exact hp⟩, hky⟩
  · rintro ⟨y, ⟨hy, hp⟩, hky⟩; exact ⟨y, hy, hky, by rw [hP]; exact hp⟩

theorem byp_loc (hc : FCtxInv fc c₀) : (locIx s fc b).byp = (carried c₀ rel unr).byp := by
  obtain ⟨-, -, -, -, -, -, -, -, -, -, -, -, -, -, h, -⟩ := hc
  exact h

theorem lim_loc (hc : FCtxInv fc c₀) : (locIx s fc b).lim = (carried c₀ rel unr).lim := by
  obtain ⟨-, -, -, -, -, -, -, -, -, -, -, -, -, -, -, h⟩ := hc
  exact h

theorem pending_loc (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr) (hc : FCtxInv fc c₀)
    (hb : Uncapped (fetch s fc.redo b) fc.feeds b) {l : Line} (hl : l ∈ b) {k : Key} (hk : k ∈ probeKeys b) :
    (locIx s fc b).pending l k = (Ix.build (carried c₀ rel unr) b).pending l k := by
  rw [pending_eq, Bool.eq_iff_iff]
  unfold Ix.pending
  rw [probeU hu (cnt_unr hb) hk, List.contains_iff_mem, mem_pending, byp_loc (rel := rel) (unr := unr) hc]
  simp only [Bool.and_eq_true, List.contains_iff_mem, carried_unr]
  constructor
  · rintro ⟨y, hy, hky, hp, hn⟩
    exact ⟨y, hy, fun h => by simp [h.1, h.2] at hn, by rw [← claim_u hr hu hc hb hl hy hk hky]; exact hp⟩
  · rintro ⟨y, hy, hn, hp⟩
    have hky := claim_sub hp
    exact ⟨y, hy, hky, by rw [claim_u hr hu hc hb hl hy hk hky]; exact hp, keep_row hn⟩

theorem counterparts_loc (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr) (hc : FCtxInv fc c₀)
    (hb : Uncapped (fetch s fc.redo b) fc.feeds b) {l : Line} (hl : l ∈ b) :
    (locIx s fc b).counterparts l = (Ix.build (carried c₀ rel unr) b).counterparts l := by
  have hsubR : ∀ k ∈ keys l, k ∈ ksR s fc.redo b := fun k hk => mem_ksR_of_probe (mem_probeKeys.mpr ⟨l, hl, hk⟩)
  have hsubU : ∀ k ∈ keys l, k ∈ probeKeys b := fun k hk => mem_probeKeys.mpr ⟨l, hl, hk⟩
  have e1 : hits (locIx s fc b).rel (locIx s fc b).relPost (keys l) (fun _ => true) =
      ((rel.entries.filter fun y => (keys l).any (keys y).contains).filter fun _ => true).map (·.id) :=
    hits_local hr (ksR s fc.redo b) (cnt_rel hb hl) (keys l) hsubR (fun _ => true)
  have e2 : hits (locIx s fc b).unr (locIx s fc b).unrPost (keys l)
      (fun y => (keys l).any ((locIx s fc b).claim y).contains) =
      ((unr.entries.filter fun y => (keys l).any (keys y).contains).filter
        fun y => (keys l).any ((locIx s fc b).claim y).contains).map (·.id) :=
    hits_local hu (probeKeys b) (cnt_unr hb) (keys l) hsubU _
  have hU : (unr.entries.filter fun y => (keys l).any (keys y).contains).filter
        (fun y => (keys l).any ((locIx s fc b).claim y).contains) =
      unr.entries.filter fun y => (keys l).any (claim (carried c₀ rel unr) y).contains := by
    rw [List.filter_filter]
    refine List.filter_congr fun y hy => ?_
    cases h : (keys l).any (claim (carried c₀ rel unr) y).contains
    · cases hk : (keys l).any (keys y).contains
      · simp
      · obtain ⟨k, hk1, hk2⟩ := List.any_eq_true.mp hk
        have := claim_u hr hu hc hb hl hy (hsubU k hk1) (List.contains_iff_mem.mp hk2)
        rw [this, h]; simp
    · obtain ⟨k, hk1, hk2⟩ := List.any_eq_true.mp h
      have hky := claim_sub (List.contains_iff_mem.mp hk2)
      have := claim_u hr hu hc hb hl hy (hsubU k hk1) hky
      have hkk : (keys l).any (keys y).contains = true := List.any_eq_true.mpr ⟨k, hk1, List.contains_iff_mem.mpr hky⟩
      rw [hkk, this, h]; simp
  have l1 : loose (carried c₀ rel unr).today (carried c₀ rel unr).releasedPrior (carried c₀ rel unr).released = [] :=
    loose_carried _ _
  have l2 : loose (carried c₀ rel unr).today (carried c₀ rel unr).unresolvedPrior (carried c₀ rel unr).unresolved = [] :=
    loose_carried _ _
  rw [counterparts_eq]
  unfold Ix.counterparts
  rw [e1, e2, hU, l1, l2, List.append_nil, List.append_nil, carried_rel, carried_unr, List.map_append]
  simp


theorem chained_self (t : Nat) (p : Snapshot Line) :
    chained t p (some p) = (p.entries.length == p.count && validDate p.asOf && decide (p.asOf ≤ t)) := by
  unfold chained
  have : p.entries.all p.entries.contains = true := List.all_eq_true.mpr fun x hx => List.contains_iff_mem.mpr hx
  simp [this]

theorem relChained_loc (hr : IdxInv H s.rel rel) (hc : FCtxInv fc c₀) :
    (locIx s fc b).relChained = (Ix.build (carried c₀ rel unr) b).relChained := by
  rw [build_relChained]
  show Head.chained s.rel.head fc.today = chained (carried c₀ rel unr).today (carried c₀ rel unr).releasedPrior (carried c₀ rel unr).released
  rw [hr.1, hc.1]
  exact (chained_self _ _).symm

theorem unrChained_loc (hu : IdxInv H s.unr unr) (hc : FCtxInv fc c₀) :
    (locIx s fc b).unrChained = (Ix.build (carried c₀ rel unr) b).unrChained := by
  rw [build_unrChained]
  show Head.chained s.unr.head fc.today = chained (carried c₀ rel unr).today (carried c₀ rel unr).unresolvedPrior (carried c₀ rel unr).unresolved
  rw [hu.1, hc.1]
  exact (chained_self _ _).symm

theorem fires_loc (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr) (hc : FCtxInv fc c₀)
    (hb : Uncapped (fetch s fc.redo b) fc.feeds b) {l : Line} (hl : l ∈ b) (s' : HashSet Key) (r : Reason) :
    (locIx s fc b).fires s' l r = (Ix.build (carried c₀ rel unr) b).fires s' l r := by
  have hk : ∀ k ∈ keys l, k ∈ probeKeys b := fun k hk => mem_probeKeys.mpr ⟨l, hl, hk⟩
  have hs : ∀ k ∈ keys l, (locIx s fc b).seen s' k = (Ix.build (carried c₀ rel unr) b).seen s' k := fun k hk' => by
    unfold Ix.seen; rw [seen0_loc hr hc hb hl (hk k hk')]
  have hp : ∀ k ∈ keys l, (locIx s fc b).pending l k = (Ix.build (carried c₀ rel unr) b).pending l k := fun k hk' =>
    pending_loc hr hu hc hb hl (hk k hk')
  have hid : idKey l ∈ keys l := idKey_mem
  have hex : exactKey l ∈ keys l := by simp [keys]
  have hne : nearKey l ∈ keys l := by simp [keys]
  obtain ⟨f1, f2, f3, f4, f5, f6⟩ := unc_feed hb hl
  obtain ⟨hpay, hrend⟩ := mem_parties hl
  have hmd : (locIx s fc b).memberDead l = (Ix.build (carried c₀ rel unr) b).memberDead l :=
    (memberDead_loc (s := s) (b := b) (rel := rel) (unr := unr) hc (mem_members hl) f1).trans memberDead_eq.symm
  have hpd : (locIx s fc b).providerDead l = (Ix.build (carried c₀ rel unr) b).providerDead l :=
    (providerDead_loc (s := s) (b := b) (rel := rel) (unr := unr) hc hpay hrend f3 f5).trans providerDead_eq.symm
  have hex' : (locIx s fc b).excluded l = (Ix.build (carried c₀ rel unr) b).excluded l :=
    (excluded_loc (s := s) (b := b) (rel := rel) (unr := unr) hc hpay hrend f4 f6).trans excluded_eq.symm
  have hov : (locIx s fc b).overlap l = (Ix.build (carried c₀ rel unr) b).overlap l :=
    (overlap_loc (s := s) (b := b) (rel := rel) (unr := unr) hc (mem_spanIds hl _) f2).trans overlap_eq.symm
  have hne' : (locIx s fc b).notEnrolled l = (Ix.build (carried c₀ rel unr) b).notEnrolled l :=
    (notEnrolled_loc (s := s) (b := b) (rel := rel) (unr := unr) hc (mem_spanIds hl _) f2).trans notEnrolled_eq.symm
  have hen : (locIx s fc b).enrolled l = (Ix.build (carried c₀ rel unr) b).enrolled l :=
    (enrolled_loc (s := s) (b := b) (rel := rel) (unr := unr) hc (mem_spanIds hl _) f2).trans enrolled_eq.symm
  have l1 : loose (carried c₀ rel unr).today (carried c₀ rel unr).releasedPrior (carried c₀ rel unr).released = [] :=
    loose_carried _ _
  have l2 : loose (carried c₀ rel unr).today (carried c₀ rel unr).unresolvedPrior (carried c₀ rel unr).unresolved = [] :=
    loose_carried _ _
  have hlk : (locIx s fc b).looseKeys.contains (exactKey l) =
      (Ix.build (carried c₀ rel unr) b).looseKeys.contains (exactKey l) := by
    have : looseKeys (carried c₀ rel unr) = [] := by unfold looseKeys; rw [l1, l2]; rfl
    show (∅ : HashSet Key).contains (exactKey l) = _
    rw [looseKeys_eq, this]; simp
  have hrc := relChained_loc (b := b) (unr := unr) hr hc
  have huc := unrChained_loc (b := b) (rel := rel) hu hc
  obtain ⟨hT, -, hDS, hPS, hES, hSS, hDO, hPO, hEO, hSO, -, -, -, -⟩ := hc
  have hto : (locIx s fc b).today = (Ix.build (carried c₀ rel unr) b).today := hT
  have hds : (locIx s fc b).dmfSome = (Ix.build (carried c₀ rel unr) b).dmfSome := hDS
  have hps : (locIx s fc b).pdSome = (Ix.build (carried c₀ rel unr) b).pdSome := hPS
  have hes : (locIx s fc b).exclSome = (Ix.build (carried c₀ rel unr) b).exclSome := hES
  have hss : (locIx s fc b).spanSome = (Ix.build (carried c₀ rel unr) b).spanSome := hSS
  have hdo : (locIx s fc b).dmfOk = (Ix.build (carried c₀ rel unr) b).dmfOk := hDO
  have hpo : (locIx s fc b).pdOk = (Ix.build (carried c₀ rel unr) b).pdOk := hPO
  have heo : (locIx s fc b).exclOk = (Ix.build (carried c₀ rel unr) b).exclOk := hEO
  have hso : (locIx s fc b).spanOk = (Ix.build (carried c₀ rel unr) b).spanOk := hSO
  cases r <;> simp only [Ix.fires, hs _ hex, hs _ hne, hs _ hid, hp _ hex, hp _ hne, hp _ hid, hlk, hmd, hpd, hex', hov,
    hne', hen, hrc, huc, hto, hds, hps, hes, hss, hdo, hpo, heo, hso]


theorem decideLine_loc (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr) (hc : FCtxInv fc c₀)
    (hb : Uncapped (fetch s fc.redo b) fc.feeds b) {l : Line} (hl : l ∈ b) (s' : HashSet Key) :
    (locIx s fc b).decideLine s' l = (Ix.build (carried c₀ rel unr) b).decideLine s' l := by
  unfold Ix.decideLine
  have : reasons.filter ((locIx s fc b).fires s' l) = reasons.filter ((Ix.build (carried c₀ rel unr) b).fires s' l) :=
    List.filter_congr fun r _ => fires_loc hr hu hc hb hl s' r
  rw [this, counterparts_loc hr hu hc hb hl]

theorem decideAll_loc (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr) (hc : FCtxInv fc c₀)
    (hb : Uncapped (fetch s fc.redo b) fc.feeds b) :
    ∀ (ls : List Line) (s' : HashSet Key), (∀ l ∈ ls, l ∈ b) →
      (locIx s fc b).decideAll s' ls = (Ix.build (carried c₀ rel unr) b).decideAll s' ls
  | [], _, _ => rfl
  | l :: ls, s', h => by
    have hl : l ∈ b := h l (by simp)
    have hcl : (locIx s fc b).claim l = (Ix.build (carried c₀ rel unr) b).claim l :=
      (claim_b hr hc hb hl).trans claim_eq.symm
    simp only [Ix.decideAll]
    rw [decideLine_loc hr hu hc hb hl, hcl,
      decideAll_loc hr hu hc hb ls _ (fun l' hl' => h l' (List.mem_cons_of_mem _ hl'))]

theorem own_xy (hr : IdxInv H s.rel rel) (hc : FCtxInv fc c₀) (hb : Uncapped (fetch s fc.redo b) fc.feeds b)
    {l : Line} (hl : l ∈ b) : (locIx s fc b).own l = (Ix.build (carried c₀ rel unr) b).own l :=
  (own_b hr hc hb hl).trans own_eq.symm

theorem order_loc (hr : IdxInv H s.rel rel) (hc : FCtxInv fc c₀) (hb : Uncapped (fetch s fc.redo b) fc.feeds b) :
    (locIx s fc b).order b = (Ix.build (carried c₀ rel unr) b).order b := by
  unfold Ix.order
  have h1 : b.filter (locIx s fc b).own = b.filter (Ix.build (carried c₀ rel unr) b).own :=
    List.filter_congr fun l hl => own_xy hr hc hb hl
  have h2 : b.filter (fun y => !(locIx s fc b).own y) = b.filter (fun y => !(Ix.build (carried c₀ rel unr) b).own y) :=
    List.filter_congr fun l hl => by rw [own_xy hr hc hb hl]
  rw [h1, h2]

theorem order_mem (x : Ix) {b : List Line} {l : Line} (h : l ∈ x.order b) : l ∈ b := by
  unfold Ix.order canonical at h
  rcases List.mem_append.mp h with h | h
  · exact (List.mem_filter.mp ((List.mergeSort_perm _ _).mem_iff.mp h)).1
  · exact (List.mem_filter.mp ((List.mergeSort_perm _ _).mem_iff.mp h)).1

theorem decideAll_line (x : Ix) : ∀ (s' : HashSet Key) (ls : List Line), ∀ d ∈ x.decideAll s' ls, d.line ∈ ls
  | _, [], d, hd => by simp [Ix.decideAll] at hd
  | s', l :: ls, d, hd => by
    simp only [Ix.decideAll, List.mem_cons] at hd
    rcases hd with rfl | hd
    · simp [Ix.decideLine]
    · exact List.mem_cons_of_mem _ (decideAll_line x _ ls d hd)

theorem redo_loc (hc : FCtxInv fc c₀) :
    (locIx s fc b).redo = (Ix.build (carried c₀ rel unr) b).redo := by
  show HashSet.ofList fc.redo = HashSet.ofList c₀.redo
  rw [hc.2.1]

theorem payOutcome_loc (hr : IdxInv H s.rel rel) (hc : FCtxInv fc c₀) (hb : Uncapped (fetch s fc.redo b) fc.feeds b)
    {ds : List Decision} (hds : ∀ d ∈ ds, d.line ∈ b) (p : Nat) :
    (locIx s fc b).payOutcome ds p = (Ix.build (carried c₀ rel unr) b).payOutcome ds p := by
  unfold Ix.payOutcome
  rw [redo_loc (rel := rel) (unr := unr) (b := b) hc]
  have key : ∀ (ls : List Decision), (∀ d ∈ ls, d ∈ ds) →
      ls.all (fun d => d.outcome == .ALLOW && (!(Ix.build (carried c₀ rel unr) b).redo.contains p || (locIx s fc b).own d.line)) =
      ls.all (fun d => d.outcome == .ALLOW && (!(Ix.build (carried c₀ rel unr) b).redo.contains p ||
        (Ix.build (carried c₀ rel unr) b).own d.line)) := by
    intro ls hls
    induction ls with
    | nil => rfl
    | cons d t ih =>
      simp only [List.all_cons, own_xy (unr := unr) hr hc hb (hds d (hls d (by simp))),
        ih (fun e he => hls e (List.mem_cons_of_mem _ he))]
  dsimp only
  rw [key (ds.filter (·.line.pay == p)) (fun d hd => (List.mem_filter.mp hd).1)]

theorem held_loc (hu : IdxInv H s.unr unr) (hb : Uncapped (fetch s fc.redo b) fc.feeds b) {l : Line} (hl : l ∈ b) :
    (locIx s fc b).held l = (Ix.build (carried c₀ rel unr) b).held l := by
  rw [held_eq, Bool.eq_iff_iff]
  unfold Ix.held
  rw [probeU hu (cnt_unr hb) (mem_probeKeys.mpr ⟨l, hl, idKey_mem⟩)]
  simp only [List.contains_iff_mem, beq_iff_eq, carried_unr]
  constructor
  · rintro ⟨y, hy, _, rfl⟩; exact hy
  · intro h; exact ⟨l, h, idKey_mem, rfl⟩

theorem ownU_loc (hu : IdxInv H s.unr unr) (hc : FCtxInv fc c₀) (hb : Uncapped (fetch s fc.redo b) fc.feeds b)
    {l : Line} (hl : l ∈ b) :
    (locIx s fc b).ownU l = (Ix.build (carried c₀ rel unr) b).ownU l := by
  unfold Ix.ownU
  rw [byp_loc (rel := rel) (unr := unr) hc, held_loc hu hb hl]
  rfl

theorem any_congr' {α : Type} (xs : List α) (f g : α → Bool) (h : ∀ x ∈ xs, f x = g x) : xs.any f = xs.any g := by
  induction xs with
  | nil => rfl
  | cons x t ih => simp only [List.any_cons, h x (by simp), ih fun y hy => h y (by simp [hy])]

theorem bypassed_loc (hu : IdxInv H s.unr unr) (hc : FCtxInv fc c₀)
    (hb : Uncapped (fetch s fc.redo b) fc.feeds b) {ds : List Decision} (hds : ∀ d ∈ ds, d.line ∈ b) (p : Nat) :
    (locIx s fc b).bypassed ds p = (Ix.build (carried c₀ rel unr) b).bypassed ds p := by
  unfold Ix.bypassed
  rw [byp_loc (rel := rel) (unr := unr) hc, build_byp (c := carried c₀ rel unr) (b := b),
    redo_loc (rel := rel) (unr := unr) (b := b) hc]
  cases (carried c₀ rel unr).byp.lookup p with
  | none => rfl
  | some m =>
    simp only []
    rw [any_congr' ds _ (fun d => d.line.pay == p && (Ix.build (carried c₀ rel unr) b).held d.line)
      (fun d hd => by rw [held_loc hu hb (hds d hd)])]

theorem limitedPay_loc (hr : IdxInv H s.rel rel) (hc : FCtxInv fc c₀)
    (hb : Uncapped (fetch s fc.redo b) fc.feeds b) {ds : List Decision} (hds : ∀ d ∈ ds, d.line ∈ b) (p : Nat) :
    (locIx s fc b).limitedPay ds p = (Ix.build (carried c₀ rel unr) b).limitedPay ds p := by
  unfold Ix.limitedPay
  rw [lim_loc (rel := rel) (unr := unr) hc, show (Ix.build (carried c₀ rel unr) b).lim = (carried c₀ rel unr).lim from rfl]
  cases (carried c₀ rel unr).lim.lookup p with
  | none => rfl
  | some m => rw [payOutcome_loc (unr := unr) hr hc hb hds p, redo_loc (rel := rel) (unr := unr) (b := b) hc]

theorem releasedLines_loc (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr) (hc : FCtxInv fc c₀)
    (hb : Uncapped (fetch s fc.redo b) fc.feeds b) {ds : List Decision} (hds : ∀ d ∈ ds, d.line ∈ b) :
    (locIx s fc b).releasedLines ds = (Ix.build (carried c₀ rel unr) b).releasedLines ds := by
  unfold Ix.releasedLines
  rw [redo_loc (rel := rel) (unr := unr) (b := b) hc]
  congr 1
  exact List.filter_congr fun d hd => by
    rw [payOutcome_loc hr hc hb hds, bypassed_loc hu hc hb hds, limitedPay_loc (unr := unr) hr hc hb hds, own_xy hr hc hb (hds d hd)]

theorem unresolvedLines_loc (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr) (hc : FCtxInv fc c₀)
    (hb : Uncapped (fetch s fc.redo b) fc.feeds b) {ds : List Decision} (hds : ∀ d ∈ ds, d.line ∈ b) :
    (locIx s fc b).unresolvedLines ds = (Ix.build (carried c₀ rel unr) b).unresolvedLines ds := by
  unfold Ix.unresolvedLines
  congr 1
  exact List.filter_congr fun d hd => by
    rw [own_xy hr hc hb (hds d hd), ownU_loc hu hc hb (hds d hd), bypassed_loc hu hc hb hds, limitedPay_loc (unr := unr) hr hc hb hds]

end Q2

theorem idx_eq_ix (H : Bytes → Bytes) (s : St) (fc : FCtx) (c₀ : Ctx) (rel unr : Snapshot Line) (f : List Nat)
    (b : List Line) (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr) (hc : FCtxInv fc c₀)
    (hb : Uncapped (fetch s fc.redo b) fc.feeds b) :
    decideBatchIdx s fc f b =
      ((Ix.build (carried c₀ rel unr) b).decideAll (HashSet.ofList (idSeen f)) ((Ix.build (carried c₀ rel unr) b).order b),
       (Ix.build (carried c₀ rel unr) b).releasedLines
         ((Ix.build (carried c₀ rel unr) b).decideAll (HashSet.ofList (idSeen f)) ((Ix.build (carried c₀ rel unr) b).order b)),
       (Ix.build (carried c₀ rel unr) b).unresolvedLines
         ((Ix.build (carried c₀ rel unr) b).decideAll (HashSet.ofList (idSeen f)) ((Ix.build (carried c₀ rel unr) b).order b))) := by
  have hord : ∀ l ∈ (locIx s fc b).order b, l ∈ b := fun l hl => order_mem _ hl
  have hdsx : (locIx s fc b).decideAll (HashSet.ofList (idSeen f)) ((locIx s fc b).order b) =
      (Ix.build (carried c₀ rel unr) b).decideAll (HashSet.ofList (idSeen f)) ((Ix.build (carried c₀ rel unr) b).order b) := by
    rw [decideAll_loc hr hu hc hb _ _ hord, order_loc hr hc hb]
  have hlines : ∀ d ∈ (locIx s fc b).decideAll (HashSet.ofList (idSeen f)) ((locIx s fc b).order b), d.line ∈ b :=
    fun d hd => hord _ (decideAll_line _ _ _ d hd)
  have hmap : ((locIx s fc b).decideAll (HashSet.ofList (idSeen f)) ((locIx s fc b).order b)).map
      (fun d => if capped (hotKeys (fetch s fc.redo b) fc.feeds b) (fetch s fc.redo b) fc.feeds d.line then capD d else d) =
      (locIx s fc b).decideAll (HashSet.ofList (idSeen f)) ((locIx s fc b).order b) := by
    rw [List.map_congr_left (g := id)]
    · exact List.map_id _
    · intro d hd
      have := hb d.line (hlines d hd)
      simp [this]
  have hx : decideBatchIdx s fc f b =
      (let ds := ((locIx s fc b).decideAll (HashSet.ofList (idSeen f)) ((locIx s fc b).order b)).map
        (fun d => if capped (hotKeys (fetch s fc.redo b) fc.feeds b) (fetch s fc.redo b) fc.feeds d.line then capD d else d)
       (ds, (locIx s fc b).releasedLines ds, (locIx s fc b).unresolvedLines ds)) := rfl
  rw [hx]
  simp only []
  rw [hmap]
  rw [releasedLines_loc hr hu hc hb hlines, unresolvedLines_loc hr hu hc hb hlines, hdsx]

-- END REFINEMENT LEMMAS

/-- On a batch no cap touches, the decisions and the appended rows are the Spec's, on the carried state the index
    holds. -/
theorem decideBatchIdx_eq (H : Bytes → Bytes) (s : St) (fc : FCtx) (c₀ : Ctx) (rel unr : Snapshot Line)
    (f : List Nat) (b : List Line) (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr) (hc : FCtxInv fc c₀)
    (hb : Uncapped (fetch s fc.redo b) fc.feeds b) :
    decideBatchIdx s fc f b =
      ((decideBatchIn (carried c₀ rel unr) f b).decisions,
       batchFresh (carried c₀ rel unr) (decideBatchIn (carried c₀ rel unr) f b)) := by
  rw [idx_eq_ix H s fc c₀ rel unr f b hr hu hc hb, ← decideBatchFIn_eq]
  unfold decideBatchFIn Ix.runIn batchFresh
  simp only [build_relV, build_unrV, releasedSet, unresolvedSet]
  rw [List.drop_left' rfl, List.drop_left' rfl]

/-- A capped line is HOLD with `POSTING_CAP`, whatever was fetched (fail closed, row by row). -/
theorem cap_hold (hr hu : Head) (fe : Fetched) (fc : FCtx) (f : List Nat) (b : List Line) :
    ∀ d ∈ (decideFetched hr hu fe fc f b).1, capped (hotKeys fe fc.feeds b) fe fc.feeds d.line = true →
      d.outcome = .HOLD ∧ Reason.POSTING_CAP ∈ d.reasons := by
  intro d hd hc
  simp only [decideFetched, List.mem_map, cappedWith_eq] at hd
  obtain ⟨d0, -, rfl⟩ := hd
  by_cases h : capped (hotKeys fe fc.feeds b) fe fc.feeds d0.line = true
  · simp only [h, if_true]; exact capD_rel d0
  · simp [h] at hc

/-- A line one of whose feed ids has more than `capN` facts is HOLD with `POSTING_CAP`. -/
theorem feed_cap_hold (hr hu : Head) (fe : Fetched) (fc : FCtx) (f : List Nat) (b : List Line) :
    ∀ d ∈ (decideFetched hr hu fe fc f b).1, feedCapped fc.feeds d.line = true →
      d.outcome = .HOLD ∧ Reason.POSTING_CAP ∈ d.reasons :=
  fun d hd h => cap_hold hr hu fe fc f b d hd (by simp [capped, h])

/-! ## Per core against per key -/

theorem capD_capD (d : Decision) : capD (capD d) = capD d := by
  have h : ∀ r ∈ reasons, (r == Reason.POSTING_CAP ||
      (reasons.filter fun r => r == Reason.POSTING_CAP || d.reasons.contains r).contains r) =
      (r == Reason.POSTING_CAP || d.reasons.contains r) := by
    intro r hr
    cases h1 : (r == Reason.POSTING_CAP) <;> cases h2 : d.reasons.contains r <;> simp_all
  simp only [capD, List.filter_congr h]

theorem key_core {l : Line} {k : Key} (hk : k ∈ keys l) {c : Key} (hc : keyCore k = some c) : c = coreKey l := by
  simp only [keys, List.mem_cons, List.not_mem_nil, or_false] at hk
  rcases hk with rfl | rfl | rfl
  · rw [keyCore_exact] at hc; exact (Option.some.inj hc).symm
  · rw [keyCore_near] at hc; exact (Option.some.inj hc).symm
  · rw [keyCore_id] at hc; exact absurd hc (by simp)

/-- A line of the batch reads a hot key under the per-core count iff it does under the per-key count (no core counts,
    `St.perKey`) or its core holds more than `capN` rows in either set. -/
theorem hot_perKey (s : St) (redo : List Nat) (fd : Feeds) {b : List Line} {l : Line} (hl : l ∈ b) :
    (keys l).any (hotKeys (fetch s redo b) fd b).contains =
      ((keys l).any (hotKeys (fetch s.perKey redo b) fd b).contains ||
        (capN < s.rel.core (coreKey l) || capN < s.unr.core (coreKey l))) := by
  have hp : ∀ k ∈ keys l, k ∈ probeKeys b := fun k hk => mem_probeKeys.mpr ⟨l, hl, hk⟩
  have hR : ∀ k ∈ keys l, (k, s.rel.get k) ∈ (fetch s redo b).rel := fun k hk => by
    rw [fetch_rel']; exact List.mem_map.mpr ⟨k, mem_ksR_of_probe (hp k hk), rfl⟩
  have hU : ∀ k ∈ keys l, (k, s.unr.get k) ∈ (fetch s redo b).unr := fun k hk => by
    rw [fetch_unr']; exact List.mem_map.mpr ⟨k, hp k hk, rfl⟩
  have hx : keyCore (exactKey l) = some (coreKey l) := keyCore_exact l
  have hxk : exactKey l ∈ keys l := by simp [keys]
  have z : ∀ k (e : Entry), capCount (fun _ => 0) k e = e.count := fun k e => by
    unfold capCount; cases keyCore k <;> simp
  apply Bool.eq_iff_iff.mpr
  simp only [List.any_eq_true, Bool.or_eq_true, decide_eq_true_eq, hotKeys, HashSet.contains_ofList,
    List.contains_iff_mem, List.mem_append, List.mem_map, List.mem_filter]
  constructor
  · rintro ⟨k, hk, ((⟨ke, ⟨hm, hc⟩, rfl⟩ | ⟨ke, ⟨hm, hc⟩, rfl⟩) | h3) | h4⟩
    · rcases capCount_lt.mp hc with hc | ⟨c, hc, ho⟩
      · exact .inl ⟨ke.1, hk, .inl (.inl (.inl ⟨ke, ⟨hm, by simpa [St.perKey, fetch, z] using hc⟩, rfl⟩))⟩
      · exact .inr (.inl (key_core hk hc ▸ ho))
    · rcases capCount_lt.mp hc with hc | ⟨c, hc, ho⟩
      · exact .inl ⟨ke.1, hk, .inl (.inl (.inr ⟨ke, ⟨hm, by simpa [St.perKey, fetch, z] using hc⟩, rfl⟩))⟩
      · exact .inr (.inr (key_core hk hc ▸ ho))
    · exact .inl ⟨k, hk, .inl (.inr h3)⟩
    · exact .inl ⟨k, hk, .inr h4⟩
  · rintro (⟨k, hk, ((⟨ke, ⟨hm, hc⟩, rfl⟩ | ⟨ke, ⟨hm, hc⟩, rfl⟩) | h3) | h4⟩ | ho | ho)
    · refine ⟨ke.1, hk, .inl (.inl (.inl ⟨ke, ⟨hm, capCount_lt.mpr (.inl ?_)⟩, rfl⟩))⟩
      simpa [St.perKey, fetch, z] using hc
    · refine ⟨ke.1, hk, .inl (.inl (.inr ⟨ke, ⟨hm, capCount_lt.mpr (.inl ?_)⟩, rfl⟩))⟩
      simpa [St.perKey, fetch, z] using hc
    · exact ⟨k, hk, .inl (.inr h3)⟩
    · exact ⟨k, hk, .inr h4⟩
    · exact ⟨exactKey l, hxk, .inl (.inl (.inl ⟨_, ⟨hR _ hxk, capCount_lt.mpr (.inr ⟨_, hx, ho⟩)⟩, rfl⟩))⟩
    · exact ⟨exactKey l, hxk, .inl (.inl (.inr ⟨_, ⟨hU _ hxk, capCount_lt.mpr (.inr ⟨_, hx, ho⟩)⟩, rfl⟩))⟩

/-- The cap counts per core: each decision is the per-key rule's (`St.perKey`), made HOLD with `POSTING_CAP`
    (`capD`) when its line's core holds more than `capN` rows in either set.  So the per-core rule only adds holds: a
    line the per-key rule holds with `POSTING_CAP` gets the same decision, and any other line's decision is unchanged
    unless its core is over `capN`. -/
theorem decide_perCore (s : St) (fc : FCtx) (f : List Nat) (b : List Line) :
    (decideBatchIdx s fc f b).1 = (decideBatchIdx s.perKey fc f b).1.map fun d =>
      if capN < s.rel.core (coreKey d.line) || capN < s.unr.core (coreKey d.line) then capD d else d := by
  simp only [decideBatchIdx, decideFetched, List.map_map]
  apply List.map_congr_left
  intro d hd
  have hl : d.line ∈ b := order_mem _ (decideAll_line _ _ _ d hd)
  have hc : cappedWith (idCapped (fetch s fc.redo b)) (hotKeys (fetch s fc.redo b) fc.feeds b) fc.feeds d.line =
      (cappedWith (idCapped (fetch s.perKey fc.redo b)) (hotKeys (fetch s.perKey fc.redo b) fc.feeds b) fc.feeds
        d.line || (capN < s.rel.core (coreKey d.line) || capN < s.unr.core (coreKey d.line))) := by
    have : idCapped (fetch s.perKey fc.redo b) = idCapped (fetch s fc.redo b) := rfl
    simp only [cappedWith, hot_perKey s fc.redo fc.feeds hl, this]
    cases idCapped (fetch s fc.redo b) <;>
      cases (keys d.line).any (hotKeys (fetch s.perKey fc.redo b) fc.feeds b).contains <;>
      cases feedCapped fc.feeds d.line <;> simp
  rw [hc]
  have hline : (capD d).line = d.line := rfl
  cases h1 : cappedWith (idCapped (fetch s.perKey fc.redo b)) (hotKeys (fetch s.perKey fc.redo b) fc.feeds b)
      fc.feeds d.line <;>
    cases h2 : (capN < s.rel.core (coreKey d.line) || capN < s.unr.core (coreKey d.line)) <;>
    simp only [Function.comp_apply, h1, h2, hline, capD_capD, Bool.false_or, Bool.true_or, Bool.or_false,
      Bool.false_eq_true, ↓reduceIte]

/-- A line whose core holds more than `capN` rows in either set is HOLD with `POSTING_CAP`. -/
theorem core_hold (s : St) (rel unr : Snapshot Line) (hr : CoreInv s.rel rel) (hu : CoreInv s.unr unr) (fc : FCtx)
    (f : List Nat) (b : List Line) :
    ∀ d ∈ (decideBatchIdx s fc f b).1, (capN < (rel.entries.filter (coreKey · == coreKey d.line)).length ∨
      capN < (unr.entries.filter (coreKey · == coreKey d.line)).length) →
      d.outcome = .HOLD ∧ Reason.POSTING_CAP ∈ d.reasons := by
  intro d hd ho
  rw [decide_perCore, List.mem_map] at hd
  obtain ⟨d0, -, rfl⟩ := hd
  have hl : (if capN < s.rel.core (coreKey d0.line) || capN < s.unr.core (coreKey d0.line) then capD d0 else d0).line =
      d0.line := by split <;> rfl
  rw [hl] at ho
  have h : (capN < s.rel.core (coreKey d0.line) || capN < s.unr.core (coreKey d0.line)) = true := by
    rw [hr, hu]; simpa using ho
  simp only [h, if_true]
  exact capD_rel d0

private theorem filter_mono {α : Type} {p q : α → Bool} :
    ∀ l : List α, (∀ a ∈ l, p a = true → q a = true) → (l.filter p).Sublist (l.filter q)
  | [], _ => .slnil
  | a :: l, h => by
    have ih := filter_mono l fun y hy => h y (.tail _ hy)
    by_cases hp : p a = true
    · simp only [List.filter_cons, hp, h a (.head _) hp, if_true]; exact ih.cons_cons a
    · simp only [List.filter_cons, hp, Bool.false_eq_true, if_false]
      by_cases hq : q a = true
      · simp only [hq, if_true]; exact ih.cons a
      · simp only [hq, Bool.false_eq_true, if_false]; exact ih

/-- Whether a payment is lifted reads its own decisions only. -/
private theorem lifts_filter (m : Nat) (L : List Decision) (p : Nat) (o : Outcome) :
    lifts m L p o = lifts m (L.filter (·.line.pay == p)) p o := by
  have h : ∀ d : Decision, (!(d.line.pay == p) || (d.line.pay != p ||
      d.reasons.all fun r => bypassable r && !(m >>> r.idx % 2 == 1))) =
      (d.line.pay != p || d.reasons.all fun r => bypassable r && !(m >>> r.idx % 2 == 1)) := by
    intro d; by_cases e : d.line.pay = p <;> simp [e]
  simp only [lifts, List.any_filter, List.all_filter, Bool.and_self, h]

/-- Turning decisions into POSTING_CAP holds, line by line, only narrows the released lines: each line released after
    `g` was released before. -/
theorem released_hold (x : Ix) (g : Decision → Decision)
    (hg : ∀ d, (g d).line = d.line ∧ (g d = d ∨ (g d).outcome = .HOLD ∧ Reason.POSTING_CAP ∈ (g d).reasons))
    (ds : List Decision) : (x.releasedLines (ds.map g)).Sublist (x.releasedLines ds) := by
  have ha : ∀ d, (g d).outcome = .ALLOW → g d = d := fun d h => by
    rcases (hg d).2 with e | ⟨e, -⟩
    · exact e
    · rw [e] at h; cases h
  have hp : ∀ p, x.payOutcome (ds.map g) p = .ALLOW → x.payOutcome ds p = .ALLOW := by
    intro p h
    have hf : (ds.map g).filter (·.line.pay == p) = (ds.filter (·.line.pay == p)).map g := by
      rw [List.filter_map]
      congr 1
      exact List.filter_congr fun d _ => by simp only [Function.comp_apply, (hg d).1]
    unfold Ix.payOutcome at h ⊢
    simp only [hf] at h
    have heq : (ds.filter (·.line.pay == p)).map g = ds.filter (·.line.pay == p) := by
      split at h
      · cases h
      · split at h
        · rename_i hc
          simp only [Bool.and_eq_true, List.all_eq_true] at hc
          rw [List.map_congr_left (g := id) fun d hd => ha d (by
            have e := hc.2 (g d) (List.mem_map_of_mem hd)
            simp only [beq_iff_eq] at e
            exact e.1), List.map_id]
        · cases h
    rw [heq] at h
    exact h
  have hy : ∀ p, x.bypassed (ds.map g) p = true → x.bypassed ds p = true := by
    intro p h
    unfold Ix.bypassed at h ⊢
    cases hm : x.byp.lookup p with
    | none => simp [hm] at h
    | some m =>
      simp only [hm, Bool.and_eq_true, List.any_map, List.all_map, List.all_eq_true, List.any_eq_true] at h ⊢
      obtain ⟨⟨h1, h2⟩, h3⟩ := h
      refine ⟨⟨h1, ?_⟩, fun d hd => ?_⟩
      · obtain ⟨d, hd, e⟩ := h2
        simp only [Function.comp_apply, (hg d).1, Bool.and_eq_true] at e
        exact ⟨d, hd, e⟩
      · have e := h3 d hd
        simp only [Function.comp_apply, (hg d).1] at e
        rcases (hg d).2 with e' | ⟨-, e'⟩
        · rwa [e'] at e
        · have hc : ((g d).reasons.all fun r => bypassable r && (m >>> r.idx % 2 == 1)) = false :=
            List.all_eq_false.2 ⟨_, e', by simp [bypassable]⟩
          rw [hc, Bool.or_false] at e
          rw [e, Bool.true_or]
  -- a payment lifted after `g` has no POSTING_CAP line (the reason is never lifted), so `g` left its lines alone
  have hlp : ∀ p, x.limitedPay (ds.map g) p = true → x.limitedPay ds p = true := by
    intro p h
    unfold Ix.limitedPay at h ⊢
    cases hm : x.lim.lookup p with
    | none => simp [hm] at h
    | some m =>
      simp only [hm] at h ⊢
      have hid : ∀ d ∈ ds, d.line.pay = p → g d = d := by
        intro d hd hdp
        rcases (hg d).2 with e | ⟨-, e'⟩
        · exact e
        · exfalso
          simp only [lifts, Bool.and_eq_true, List.all_eq_true, List.all_map] at h
          have e := h.2.2 d hd
          simp only [Function.comp_apply, (hg d).1, hdp, bne_self_eq_false, Bool.false_or] at e
          have hc : ((g d).reasons.all fun r => bypassable r && !(m >>> r.idx % 2 == 1)) = false :=
            List.all_eq_false.2 ⟨_, e', by simp [bypassable]⟩
          rw [hc] at e; cases e
      have hfil : (ds.map g).filter (·.line.pay == p) = ds.filter (·.line.pay == p) := by
        rw [List.filter_map]
        have e : ds.filter ((·.line.pay == p) ∘ g) = ds.filter (·.line.pay == p) :=
          List.filter_congr fun d _ => by simp only [Function.comp_apply, (hg d).1]
        rw [e]
        refine (List.map_congr_left fun d hd => ?_).trans (List.map_id _)
        have hd' := List.mem_filter.1 hd
        exact hid d hd'.1 (by simpa using hd'.2)
      have hpo : x.payOutcome (ds.map g) p = x.payOutcome ds p := by
        unfold Ix.payOutcome; simp only [hfil]
      rw [hpo, lifts_filter, hfil] at h
      rw [lifts_filter]
      exact h
  unfold Ix.releasedLines
  rw [List.filter_map, List.map_map]
  have hl : (Decision.line ∘ g) = Decision.line := funext fun d => (hg d).1
  rw [hl]
  refine (filter_mono ds fun d _ h => ?_).map _
  simp only [Function.comp_apply, (hg d).1, Bool.or_eq_true, Bool.and_eq_true, beq_iff_eq] at h ⊢
  rcases h with (⟨⟨h1, h2⟩, h3⟩ | h4) | ⟨h5, h6⟩
  · refine .inl (.inl ⟨⟨?_, h2⟩, hp _ h3⟩)
    rw [← ha d h1]; exact h1
  · exact .inl (.inr (hy _ h4))
  · exact .inr ⟨hlp _ h5, h6⟩

/-- The per-core rule never releases a line the per-key rule does not: the lines it appends to the released set are
    a sublist of the per-key rule's. -/
theorem released_perCore (s : St) (fc : FCtx) (f : List Nat) (b : List Line) :
    (decideBatchIdx s fc f b).2.1.Sublist (decideBatchIdx s.perKey fc f b).2.1 := by
  have h := decide_perCore s fc f b
  simp only [decideBatchIdx, decideFetched] at h ⊢
  rw [h]
  refine released_hold _ _ (fun d => ?_) _
  split
  · exact ⟨rfl, .inr (capD_rel d)⟩
  · exact ⟨rfl, .inl rfl⟩

/-! ## The index follows the appended rows -/

theorem postingsFrom_append (k : Key) (ys : List Line) :
    ∀ (xs : List Line) (i : Nat), postingsFrom k i (xs ++ ys) = postingsFrom k i xs ++ postingsFrom k (i + xs.length) ys
  | [], i => by simp [postingsFrom]
  | x :: xs, i => by
    have e : i + 1 + xs.length = i + (x :: xs).length := by simp only [List.length_cons]; omega
    cases hc : (keys x).contains k <;>
      simp only [postingsFrom, hc, ↓reduceIte, Bool.false_eq_true, List.cons_append, postingsFrom_append k ys xs, e]

theorem foldl_add (H : Bytes → Bytes) : ∀ (adds : List Line) (x : SetIdx),
    (adds.foldl (SetIdx.add H) x).head = { x.head with n := x.head.n + adds.length } ∧
    ∀ k, (adds.foldl (SetIdx.add H) x).get k = (postingsFrom k x.head.n adds).foldl (Entry.push H) (x.get k)
  | [], _ => ⟨rfl, fun _ => rfl⟩
  | l :: ls, x => by
    obtain ⟨h1, h2⟩ := foldl_add H ls (x.add H l)
    refine ⟨?_, fun k => ?_⟩
    · rw [List.foldl_cons, h1]
      simp only [SetIdx.add, List.length_cons, Head.mk.injEq, true_and] <;> omega
    · rw [List.foldl_cons, h2]
      cases hc : (keys l).contains k <;>
        simp only [SetIdx.add, postingsFrom, hc, ↓reduceIte, Bool.false_eq_true, List.foldl_cons]

theorem addRows_inv (H : Bytes → Bytes) (x : SetIdx) (s : Snapshot Line) (adds : List Line) (hx : IdxInv H x s) :
    IdxInv H (x.addRows H adds) ⟨s.asOf, s.entries.length + adds.length, s.entries ++ adds⟩ := by
  obtain ⟨hh, hg⟩ := hx
  obtain ⟨h1, h2⟩ := foldl_add H adds x
  refine ⟨?_, fun k => ?_⟩
  · simp [SetIdx.addRows, h1, hh]
  · simp only [SetIdx.addRows, h2, hg, hh, entryOf, postingsFrom_append, List.foldl_append, Nat.zero_add]

theorem foldl_core (H : Bytes → Bytes) : ∀ (adds : List Line) (x : SetIdx) (c : Key),
    (adds.foldl (SetIdx.add H) x).core c = x.core c + (adds.filter (coreKey · == c)).length
  | [], _, _ => by simp
  | l :: ls, x, c => by
    rw [List.foldl_cons, foldl_core H ls (x.add H l) c, List.filter_cons]
    by_cases h : coreKey l = c
    · subst h; simp [SetIdx.add]; omega
    · have h' : ¬c = coreKey l := fun e => h e.symm
      simp [SetIdx.add, h, h']

/-- Appended rows keep each set's core counts exact. -/
theorem addRows_core (H : Bytes → Bytes) (x : SetIdx) (s : Snapshot Line) (adds : List Line) (hx : CoreInv x s) :
    CoreInv (x.addRows H adds) ⟨s.asOf, s.entries.length + adds.length, s.entries ++ adds⟩ := fun c => by
  simp only [SetIdx.addRows, foldl_core, hx c, List.filter_append, List.length_append]

/-- Applying a batch's appended rows keeps each set's index exact (`Spec.advance` of the carried state). -/
theorem apply_inv (H : Bytes → Bytes) (s : St) (rel unr : Snapshot Line) (r : List Decision × List Line × List Line)
    (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr) :
    IdxInv H (s.apply H r).rel ⟨rel.asOf, rel.entries.length + r.2.1.length, rel.entries ++ r.2.1⟩ ∧
    IdxInv H (s.apply H r).unr ⟨unr.asOf, unr.entries.length + r.2.2.length, unr.entries ++ r.2.2⟩ :=
  ⟨addRows_inv H s.rel rel r.2.1 hr, addRows_inv H s.unr unr r.2.2 hu⟩

/-! ## Flat work: no term grows with the history -/

theorem sum_le {α : Type} (g : α → Nat) (c : Nat) : ∀ (xs : List α), (∀ x ∈ xs, g x ≤ c) →
    (xs.map g).sum ≤ xs.length * c
  | [], _ => by simp
  | x :: xs, h => by
    have h1 := h x (by simp)
    have h2 := sum_le g c xs fun y hy => h y (by simp [hy])
    simp only [List.map_cons, List.sum_cons, List.length_cons, Nat.add_mul, Nat.one_mul]
    omega

theorem uniq_length (ks : List Key) : (uniq ks).length ≤ ks.length := by
  have key : ∀ (ks : List Key) (acc : HashSet Key × List Key),
      (ks.foldl uniqStep acc).2.length ≤ acc.2.length + ks.length := by
    intro ks
    induction ks with
    | nil => intro acc; simp
    | cons k ks ih =>
      intro acc
      rw [List.foldl_cons]
      by_cases hk : acc.1.contains k = true
      · rw [show uniqStep acc k = acc from if_pos hk]
        have := ih acc; simp only [List.length_cons]; omega
      · rw [show uniqStep acc k = (acc.1.insert k, k :: acc.2) from if_neg hk]
        have := ih (acc.1.insert k, k :: acc.2); simp only [List.length_cons] at this ⊢; omega
  have := key ks (∅, [])
  simp only [uniq, List.length_reverse]
  simpa using this

theorem dedupSeq_length : ∀ ps : List Posting, (dedupSeq ps).length ≤ ps.length
  | [] => by simp [dedupSeq]
  | [_] => by simp [dedupSeq]
  | p :: q :: t => by
    have ih := dedupSeq_length (q :: t)
    simp only [dedupSeq]
    split <;> simp only [List.length_cons] at * <;> omega

theorem heads_length (e : Entry) : (heads e).length ≤ capN := by
  unfold heads; rw [List.length_take]; exact Nat.min_le_left _ _

theorem facts_length {α : Type} (xs : List α) : (facts xs).length ≤ capN := by
  unfold facts; rw [List.length_take]; exact Nat.min_le_left _ _

theorem flatMap_heads_length {β : Type} (es : List (β × Entry)) :
    (es.flatMap fun ke => heads ke.2).length ≤ es.length * capN := by
  rw [List.length_flatMap]; exact sum_le _ _ es fun ke _ => heads_length ke.2

theorem localRows_length (es : List (Key × Entry)) : (localRows es).length ≤ es.length * capN := by
  unfold localRows
  have := dedupSeq_length ((es.flatMap fun ke => heads ke.2).mergeSort fun p q => decide (p.seq ≤ q.seq))
  rw [List.length_mergeSort] at this
  exact Nat.le_trans this (flatMap_heads_length es)

theorem entryWork_le (es : List (Key × Entry)) : entryWork es ≤ es.length * (1 + capN) :=
  sum_le _ _ es fun ke _ => by have := heads_length ke.2; omega

theorem factWork_le {α : Type} (g : Nat → List α) (ids : List Nat) : factWork g ids ≤ ids.length * (1 + capN) :=
  sum_le _ _ ids fun i _ => by have := facts_length (g i); omega

theorem probeKeys_length (b : List Line) : (probeKeys b).length ≤ b.length * 3 := by
  have := uniq_length (b.flatMap keys)
  rw [List.length_flatMap] at this
  exact Nat.le_trans this (sum_le _ _ b fun l _ => by simp [keys])

theorem round2_length (redo : List Nat) (ks : List Key) (u : List (Key × Entry)) :
    (round2 redo ks u).length ≤ u.length * capN := by
  unfold round2
  refine Nat.le_trans (uniq_length _) (Nat.le_trans (List.length_filter_le _ _) ?_)
  rw [List.length_flatMap]
  exact sum_le _ _ u fun ke _ => Nat.le_trans (List.length_filterMap_le _ _) (heads_length ke.2)

theorem parties_length (b : List Line) : (parties b).length ≤ b.length * 2 := by
  unfold parties; rw [List.length_flatMap]; exact sum_le _ _ b fun _ _ => by simp

/-- THE flatness bound: a batch's history and feed reads are at most `workC` per line, whatever the history. -/
theorem work_le (s : St) (fd : Feeds) (redo : List Nat) (b : List Line) :
    work (fetch s redo b) fd b ≤ workC * b.length := by
  have hK := probeKeys_length b
  have hR := round2_length redo (probeKeys b) ((probeKeys b).map fun k => (k, s.unr.get k))
  have e1 := entryWork_le (fetch s redo b).rel
  have e2 := entryWork_le (fetch s redo b).unr
  have hl := localRows_length (fetch s redo b).unr
  have f1 := factWork_le fd.dmf (members b)
  have f2 := factWork_le fd.span (spanIds b (localRows (fetch s redo b).unr))
  have f3 := factWork_le fd.pdeath (parties b)
  have f4 := factWork_le fd.excl (parties b)
  have hp := parties_length b
  have hm : (members b).length = b.length := by simp [members]
  have hs : (spanIds b (localRows (fetch s redo b).unr)).length = b.length + (localRows (fetch s redo b).unr).length := by
    simp [spanIds, members]
  have hrel : (fetch s redo b).rel.length = (probeKeys b).length +
      (round2 redo (probeKeys b) ((probeKeys b).map fun k => (k, s.unr.get k))).length := by simp [fetch]
  have hunr : (fetch s redo b).unr.length = (probeKeys b).length := by simp [fetch]
  rw [List.length_map] at hR
  rw [hrel] at e1
  rw [hunr] at e2 hl
  rw [hm] at f1
  rw [hs] at f2
  unfold work workC
  simp only [capN] at *
  have g3 : factWork fd.pdeath (parties b) ≤ b.length * 2 * 1025 :=
    Nat.le_trans f3 (Nat.mul_le_mul_right _ hp)
  have g4 : factWork fd.excl (parties b) ≤ b.length * 2 * 1025 :=
    Nat.le_trans f4 (Nat.mul_le_mul_right _ hp)
  omega

/-! ## Entry codec -/

theorem beNat_snoc' (d : Bytes) (x : UInt8) : beNat (d ++ [x]) = beNat d * 256 + x.toNat := by
  simp [beNat, List.foldl_append]

theorem natBE_succ' (w v : Nat) : natBE (w + 1) v = natBE w (v / 256) ++ [UInt8.ofNat (v % 256)] := by
  unfold natBE
  rw [List.range_succ_eq_map]
  simp only [List.reverse_cons, List.map_append, List.map_cons, List.map_nil, Nat.pow_zero, Nat.div_one]
  rw [← List.map_reverse, List.map_map]
  congr 1
  apply List.map_congr_left
  intro i _
  simp [Nat.pow_succ, Nat.div_div_eq_div_mul, Nat.mul_comm]

theorem beNat_natBE' : ∀ (w v : Nat), v < 256 ^ w → beNat (natBE w v) = v
  | 0, v, h => by
    have : v = 0 := by simpa using h
    subst this; rfl
  | w + 1, v, h => by
    rw [natBE_succ', beNat_snoc', beNat_natBE' w (v / 256) (by rw [Nat.pow_succ] at h; omega)]
    simp only [UInt8.toNat_ofNat']
    omega


theorem takeN_app (n : Nat) (a b : Bytes) (h : a.length = n) : takeN n (a ++ b) = some (a, b) := by
  subst h; simp [takeN]

theorem unlebN_leb : ∀ (xs : List Nat) (r : Bytes), unlebN xs.length (xs.flatMap leb ++ r) = some (xs, r)
  | [], _ => rfl
  | x :: xs, r => by simp [unlebN, List.append_assoc, unleb_leb, unlebN_leb xs r]

theorem decLine_encLine (l : Line) (r : Bytes) : decLine (encLine l ++ r) = some (l, r) := by
  have h : unlebN 10 (encLine l ++ r) = some (enc l, r) := unlebN_leb (enc l) r
  unfold decLine
  rw [h]
  cases l with
  | mk i p fl m py rd dt pr u ct => cases fl <;> rfl

theorem decPostings_enc : ∀ (ps : List Posting) (r : Bytes),
    decPostings ps.length (ps.flatMap encPosting ++ r) = some (ps, r)
  | [], _ => rfl
  | p :: ps, r => by
    simp [decPostings, encPosting, List.append_assoc, unleb_leb, decLine_encLine, decPostings_enc ps r]

/-- A well-formed entry decodes from its bytes. -/
theorem entry_codec (e : Entry) (h : e.Wf) : decEntry (encEntry e) = some e := by
  cases e with
  | mk c hd t =>
    obtain ⟨h1, h2, h3⟩ := h
    simp only at h1 h2 h3
    simp [decEntry, encEntry, List.append_assoc, unleb_leb, decPostings_enc, takeN, h2, h3]
    simp [h1]
    exact List.take_of_length_le (Nat.le_of_eq h2)

/-! ## The chain binds the history -/

theorem snoc_ind {α : Type} {P : List α → Prop} (h0 : P []) (hs : ∀ l a, P l → P (l ++ [a])) (l : List α) : P l := by
  have : ∀ n (l : List α), l.length = n → P l := by
    intro n
    induction n with
    | zero => intro l hl; rw [List.length_eq_zero_iff.mp hl]; exact h0
    | succ n ih =>
      intro l hl
      rcases List.eq_nil_or_concat l with rfl | ⟨l', b, rfl⟩
      · simp at hl
      · simp only [List.concat_eq_append, List.length_append, List.length_singleton] at hl ⊢
        exact hs _ _ (ih _ (by omega))
  exact this _ l rfl

theorem leb_inj {a b : Nat} {r r' : Bytes} (h : leb a ++ r = leb b ++ r') : a = b ∧ r = r' := by
  have := congrArg unleb h
  rw [unleb_leb, unleb_leb] at this
  simpa using this

theorem decLine_inj {l l' : Line} {r r' : Bytes} (h : encLine l ++ r = encLine l' ++ r') : l = l' ∧ r = r' := by
  have := congrArg decLine h
  rw [decLine_encLine, decLine_encLine] at this
  simpa using this

theorem lines_inj : ∀ (ls ls' : List Line) (r r' : Bytes), ls.length = ls'.length →
    ls.flatMap encLine ++ r = ls'.flatMap encLine ++ r' → ls = ls' ∧ r = r'
  | [], [], r, r', _, h => by simpa using h
  | [], _ :: _, _, _, hl, _ => by simp at hl
  | _ :: _, [], _, _, hl, _ => by simp at hl
  | l :: ls, l' :: ls', r, r', hl, h => by
    simp only [List.flatMap_cons, List.append_assoc] at h
    obtain ⟨h1, h2⟩ := decLine_inj h
    obtain ⟨h3, h4⟩ := lines_inj ls ls' r r' (by simpa using hl) h2
    subst h1 h3
    exact ⟨rfl, h4⟩

theorem encSet_inj {s s' : Snapshot Line} {r r' : Bytes} (h : encSet s ++ r = encSet s' ++ r') : s = s' ∧ r = r' := by
  simp only [encSet, List.append_assoc] at h
  obtain ⟨h1, h⟩ := leb_inj h
  obtain ⟨h2, h⟩ := leb_inj h
  obtain ⟨h3, h⟩ := leb_inj h
  obtain ⟨h4, h5⟩ := lines_inj _ _ _ _ h3 h
  cases s; cases s'
  simp only at h1 h2 h4
  subst h1 h2 h4
  exact ⟨rfl, h5⟩

theorem encDelta_inj {d d' : List Line × List Line} (h : encDelta d = encDelta d') : d = d' := by
  simp only [encDelta, List.append_assoc] at h
  obtain ⟨hl, h⟩ := leb_inj h
  obtain ⟨e1, h⟩ := lines_inj _ _ _ _ hl h
  obtain ⟨hl2, h⟩ := leb_inj h
  obtain ⟨e2, -⟩ := lines_inj _ _ [] [] hl2 (by simpa using h)
  exact Prod.ext e1 e2

/-- The input `chainStep H D s` hashes. -/
def stepIn (D : Bytes) (s : Bytes × (List Line × List Line)) : Bytes :=
  domain "CHAIN" ++ [0x01] ++ D ++ leb s.1.length ++ s.1 ++ encDelta s.2

/-- The input `chainStart H k pin g` hashes. -/
def startIn (k : Nat) (pin : Bytes) (g : Snapshot Line × Snapshot Line) : Bytes :=
  domain "CHAIN" ++ [0x00] ++ leb k ++ leb pin.length ++ pin ++ encSet g.1 ++ encSet g.2

/-- The step inputs hashed from digest `D` over the batches `ds`, in order. -/
def stepInputs (H : Bytes → Bytes) : Bytes → List (Bytes × (List Line × List Line)) → List Bytes
  | _, [] => []
  | D, s :: ds => stepIn D s :: stepInputs H (chainStep H D s) ds

/-- Every input `chainHead H k pin g ds` hashes: the genesis input, then each step input. -/
def chainInputs (H : Bytes → Bytes) (k : Nat) (pin : Bytes) (g : Snapshot Line × Snapshot Line)
    (ds : List (Bytes × (List Line × List Line))) : List Bytes :=
  startIn k pin g :: stepInputs H (chainStart H k pin g) ds

theorem chainHead_len (H : Bytes → Bytes) (hH : ∀ x, (H x).length = digestBytes) (k : Nat) (pin : Bytes)
    (g : Snapshot Line × Snapshot Line) (ds : List (Bytes × (List Line × List Line))) :
    (chainHead H k pin g ds).length = digestBytes := by
  induction ds using snoc_ind with
  | h0 => exact hH _
  | hs ds d _ => simp only [chainHead, List.foldl_append, List.foldl_cons, List.foldl_nil, chainStep]; exact hH _

/-- A genesis input never equals a step input (tag 0x00 against 0x01). -/
theorem start_ne_step (k : Nat) (pin : Bytes) (g : Snapshot Line × Snapshot Line) (D : Bytes)
    (s : Bytes × (List Line × List Line)) : startIn k pin g ≠ stepIn D s := by
  intro e
  simp only [startIn, stepIn, List.append_assoc, List.singleton_append] at e
  have := List.append_cancel_left e
  simp at this

/-- Equal genesis inputs: the same shard, pin and sets. -/
theorem startIn_inj {k k' : Nat} {pin pin' : Bytes} {g g' : Snapshot Line × Snapshot Line}
    (e : startIn k pin g = startIn k' pin' g') : k = k' ∧ pin = pin' ∧ g = g' := by
  simp only [startIn, List.append_assoc, List.singleton_append] at e
  have e := (List.cons.inj (List.append_cancel_left e)).2
  obtain ⟨h1, e⟩ := leb_inj e
  obtain ⟨hl, e⟩ := leb_inj e
  obtain ⟨h2, e⟩ := List.append_inj e hl
  obtain ⟨h3, e⟩ := encSet_inj (r := encSet g.2) (r' := encSet g'.2) e
  obtain ⟨h4, -⟩ := encSet_inj (r := []) (r' := []) (by simpa using e)
  exact ⟨h1, h2, Prod.ext h3 h4⟩

/-- Equal step inputs over digests of one length: the same digest, authority record and delta. -/
theorem stepIn_inj {D D' : Bytes} {s s' : Bytes × (List Line × List Line)} (hl : D.length = D'.length)
    (e : stepIn D s = stepIn D' s') : D = D' ∧ s = s' := by
  simp only [stepIn, List.append_assoc, List.singleton_append] at e
  have e := (List.cons.inj (List.append_cancel_left e)).2
  obtain ⟨e1, e⟩ := List.append_inj e hl
  obtain ⟨ha, e⟩ := leb_inj e
  obtain ⟨e2, e⟩ := List.append_inj e ha
  exact ⟨e1, Prod.ext e2 (encDelta_inj e)⟩

theorem chainInputs_snoc (H : Bytes → Bytes) (k : Nat) (pin : Bytes) (g : Snapshot Line × Snapshot Line)
    (ds : List (Bytes × (List Line × List Line))) (d : Bytes × (List Line × List Line)) :
    chainInputs H k pin g (ds ++ [d]) = chainInputs H k pin g ds ++ [stepIn (chainHead H k pin g ds) d] := by
  have : ∀ (D : Bytes) (ds : List (Bytes × (List Line × List Line))), stepInputs H D (ds ++ [d]) =
      stepInputs H D ds ++ [stepIn (ds.foldl (chainStep H) D) d] := by
    intro D ds
    induction ds generalizing D with
    | nil => rfl
    | cons e ds ih => simp only [List.cons_append, stepInputs, ih, List.foldl_cons]
  simp only [chainInputs, this, chainHead, List.cons_append]

/-- Equal chain heads mean the same shard, key-set pin, genesis, and per batch the same authority record and appended
    rows (so the same sets, `Spec.replay`), or two distinct inputs of these chains have the same SHA3-512 digest. -/
theorem chain_binds (H : Bytes → Bytes) (hH : ∀ x, (H x).length = digestBytes) (k k' : Nat) (pin pin' : Bytes)
    (g g' : Snapshot Line × Snapshot Line) (ds ds' : List (Bytes × (List Line × List Line)))
    (h : chainHead H k pin g ds = chainHead H k' pin' g' ds') :
    (k = k' ∧ pin = pin' ∧ g = g' ∧ ds = ds') ∨
      ∃ x ∈ chainInputs H k pin g ds, ∃ y ∈ chainInputs H k' pin' g' ds', x ≠ y ∧ H x = H y := by
  induction ds using snoc_ind generalizing ds' with
  | h0 =>
    induction ds' using snoc_ind with
    | h0 =>
      by_cases e : startIn k pin g = startIn k' pin' g'
      · left
        obtain ⟨h1, h2, h3⟩ := startIn_inj e
        exact ⟨h1, h2, h3, rfl⟩
      · exact Or.inr ⟨_, List.mem_cons_self, _, List.mem_cons_self, e, h⟩
    | hs ds d _ =>
      simp only [chainHead, List.foldl_append, List.foldl_cons, List.foldl_nil] at h
      rw [chainInputs_snoc]
      exact Or.inr ⟨_, List.mem_cons_self, _, List.mem_append_right _ (List.mem_singleton_self _),
        start_ne_step k pin g _ d, h⟩
  | hs ds d ih =>
    induction ds' using snoc_ind with
    | h0 =>
      simp only [chainHead, List.foldl_append, List.foldl_cons, List.foldl_nil] at h
      rw [chainInputs_snoc]
      exact Or.inr ⟨_, List.mem_append_right _ (List.mem_singleton_self _), _, List.mem_cons_self,
        (start_ne_step k' pin' g' _ d).symm, h⟩
    | hs ds' d' _ =>
      simp only [chainHead, List.foldl_append, List.foldl_cons, List.foldl_nil] at h
      rw [chainInputs_snoc, chainInputs_snoc]
      by_cases e : stepIn (chainHead H k pin g ds) d = stepIn (chainHead H k' pin' g' ds') d'
      · obtain ⟨e1, e2⟩ := stepIn_inj ((chainHead_len H hH k pin g ds).trans (chainHead_len H hH k' pin' g' ds').symm) e
        rcases ih ds' e1 with ⟨a, b, c, f⟩ | ⟨x, hx, y, hy, c⟩
        · left; subst a b c f e2; exact ⟨rfl, rfl, rfl, rfl⟩
        · exact Or.inr ⟨x, List.mem_append_left _ hx, y, List.mem_append_left _ hy, c⟩
      · exact Or.inr ⟨_, List.mem_append_right _ (List.mem_singleton_self _), _,
          List.mem_append_right _ (List.mem_singleton_self _), e, h⟩


end BlindLedger.Gate.Flat
