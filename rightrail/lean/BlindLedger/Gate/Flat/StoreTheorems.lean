import BlindLedger.Gate.Flat.ChunkTheorems
import BlindLedger.Gate.Flat.Store
import BlindLedger.Gate.Flat.Theorems

/-! Statements and proofs of the store layout (`Flat/Store.lean`): the directory finds every stored row of a key, so
    under `FInv` a lookup returns the state's entry whatever the directory's false positives; applying a batch,
    sealing, installing and reclaiming keep `FInv` (reclaim drops only superseded versions).  Synthetic, nonpayment, non-PHI,
    activation=false. -/

namespace BlindLedger.Gate.Flat.Store

open Chunk
open BlindLedger.Gate.Rules
open BlindLedger.Gate.OnepIndex (leb unleb unleb_leb)
open Std (HashMap HashSet)

/-! ## Keys -/

theorem encKey_inj {k k' : Key} (h : encKey k = encKey k') : k = k' := by
  have h1 := unleb_leb k.length (k.flatMap leb)
  have h2 := unleb_leb k'.length (k'.flatMap leb)
  simp only [encKey] at h
  rw [h, h2] at h1
  simp only [Option.some.injEq, Prod.mk.injEq] at h1
  have h3 := unlebN_leb k []
  have h4 := unlebN_leb k' []
  simp only [List.append_nil] at h3 h4
  rw [← h1.1, ← h1.2, h4] at h3
  simp at h3
  exact h3.symm

theorem skey_inj {u u' : Bool} {k k' : Key} (h : skey u k = skey u' k') : u = u' ∧ k = k' := by
  cases u <;> cases u' <;> simp [skey] at h <;> simp [encKey_inj h]

/-! ## Directory -/

theorem fpOf_lt (h : UInt64) : fpOf h < 2 ^ 14 := by unfold fpOf; omega

theorem slot_toNat {fp c : Nat} (hf : fp < 2 ^ 14) (hc : c < 2 ^ cBits) : (slot fp c).toNat = fp * 2 ^ cBits + c := by
  simp only [slot, cBits, UInt32.toNat_ofNat'] at *
  omega

theorem slot_ne_zero (h : UInt64) {c : Nat} (hc : c < 2 ^ cBits) : slot (fpOf h) c ≠ 0 := by
  intro h0
  have := slot_toNat (fpOf_lt h) hc
  rw [h0] at this
  simp only [UInt32.toNat_zero, cBits] at this
  unfold fpOf at this; omega

theorem slot_mod {h : UInt64} {c : Nat} (hc : c < 2 ^ cBits) : (slot (fpOf h) c).toNat % 2 ^ cBits = c := by
  rw [slot_toNat (fpOf_lt h) hc]; simp only [cBits] at *; omega

private theorem fpv_slot {h : UInt64} {c : Nat} (hc : c < 2 ^ cBits) : fpv (slot (fpOf h) c) = fpOf h := by
  rw [fpv, slot_toNat (fpOf_lt h) hc]; simp only [cBits] at *; omega

/-- The other bucket undoes itself. -/
theorem alt_alt {nb f b : Nat} (hb : b < nb) : alt nb f (alt nb f b) = b := by
  unfold alt
  have hd := Nat.div_add_mod (f * 2654435761 + (nb - b)) nb
  have hl := Nat.mod_lt (f * 2654435761 + (nb - b)) (Nat.lt_of_le_of_lt (Nat.zero_le b) hb)
  have he : f * 2654435761 + (nb - (f * 2654435761 + (nb - b)) % nb) =
      b + nb * ((f * 2654435761 + (nb - b)) / nb) := by omega
  rw [he, Nat.add_mul_mod_self_left, Nat.mod_eq_of_lt hb]

/-- Both buckets of a pair carry its label. -/
theorem cls_alt {nb f b : Nat} (hb : b < nb) : cls nb f (alt nb f b) = cls nb f b := by
  unfold cls; rw [alt_alt hb]; exact Nat.min_comm _ _

/-- Buckets of one label and fingerprint are the two of one pair: same-fingerprint keys share both or neither. -/
theorem cls_eq {nb f b b' : Nat} (hb : b < nb) (hb' : b' < nb) (h : cls nb f b' = cls nb f b) :
    b' = b ∨ b' = alt nb f b := by
  have e1 := alt_alt (f := f) hb
  have e2 := alt_alt (f := f) hb'
  unfold cls at h
  rcases (by omega : b' = b ∨ b' = alt nb f b ∨ alt nb f b' = b ∨ alt nb f b' = alt nb f b) with e | e | e | e
  · exact .inl e
  · exact .inr e
  · exact .inr (by rw [← e, e2])
  · exact .inl (by rw [← e2, e, e1])

private theorem mem_idxs {nb f b j : Nat} : j ∈ idxs nb f b ↔ j / 4 = b ∨ j / 4 = alt nb f b := by
  simp only [idxs, List.mem_append, List.mem_map, List.mem_range]
  constructor
  · rintro (⟨a, ha, rfl⟩ | ⟨a, ha, rfl⟩) <;> omega
  · rintro (e | e)
    · exact .inl ⟨j % 4, by omega, by omega⟩
    · exact .inr ⟨j % 4, by omega, by omega⟩

private theorem at_eq {d : Dir} {j : Nat} {v : UInt32} {l : Nat} :
    d.at j = some (v, l) ↔ d.t[j]? = some v ∧ v ≠ 0 ∧ cls d.nb (fpv v) (j / 4) = l := by
  unfold Dir.at
  cases d.t[j]? with
  | none => simp
  | some w =>
    by_cases h0 : w = 0
    · subst h0
      constructor
      · intro e; simp at e
      · rintro ⟨e, h, -⟩; exact absurd (Option.some.inj e).symm h
    · simp only [h0, ↓reduceIte]
      constructor
      · intro e; obtain ⟨rfl, rfl⟩ := Prod.mk.inj (Option.some.inj e); exact ⟨rfl, h0, rfl⟩
      · rintro ⟨e, -, rfl⟩; rw [Option.some.inj e]

private theorem at_set {d : Dir} {j : Nat} (hj : j < d.t.size) (v : UInt32) (i : Nat) :
    ({ d with t := d.t.set! j v } : Dir).at i =
      if i = j then (if v = 0 then none else some (v, cls d.nb (fpv v) (j / 4))) else d.at i := by
  by_cases e : i = j
  · subst e; simp [Dir.at, Array.set!, hj]
  · simp [Dir.at, Array.set!, e, Ne.symm e]

theorem ok_set {d : Dir} (hO : d.Ok) (j : Nat) (v : UInt32) : ({ d with t := d.t.set! j v } : Dir).Ok :=
  ⟨hO.1, by simp [Array.set!, hO.2.1], hO.2.2⟩

private theorem fm_cons {β α : Type} (f : β → Option α) (a : β) (l : List β) :
    (a :: l).filterMap f = (f a).toList ++ l.filterMap f := by
  cases h : f a <;> simp [h]

private theorem fm_out {β α : Type} {F G : β → Option α} {j : β} :
    ∀ l : List β, (∀ i ∈ l, i ≠ j → G i = F i) → j ∉ l → l.filterMap G = l.filterMap F
  | [], _, _ => rfl
  | i :: l, h, hj => by
    rw [fm_cons, fm_cons, h i (List.mem_cons_self ..) (fun e => hj (by rw [← e]; exact List.mem_cons_self ..)),
      fm_out l (fun i' hi' => h i' (List.mem_cons_of_mem _ hi')) (fun hm => hj (List.mem_cons_of_mem _ hm))]

/-- A point update of a list's values changes what it keeps by exactly the old and new value there. -/
private theorem fm_upd {β α : Type} [BEq α] {F G : β → Option α} {j : β} (x : α) :
    ∀ l : List β, (∀ i ∈ l, i ≠ j → G i = F i) → l.Nodup → j ∈ l →
      (l.filterMap G).count x + (F j).toList.count x = (l.filterMap F).count x + (G j).toList.count x
  | [], _, _, hj => by simp at hj
  | i :: l, h, hn, hj => by
    obtain ⟨hi, hn⟩ := List.nodup_cons.mp hn
    have h' : ∀ i' ∈ l, i' ≠ j → G i' = F i' := fun i' hi' => h i' (List.mem_cons_of_mem _ hi')
    rw [fm_cons, fm_cons, List.count_append, List.count_append]
    by_cases e : i = j
    · subst e
      rw [fm_out l h' hi]
      omega
    · rw [h i (List.mem_cons_self ..) e]
      have := fm_upd x l h' hn ((List.mem_cons.mp hj).resolve_left fun e' => e e'.symm)
      omega

private theorem items_set {d : Dir} {j : Nat} (hj : j < d.t.size) (v : UInt32) (x : UInt32 × Nat) :
    ({ d with t := d.t.set! j v } : Dir).items.count x + (d.at j).toList.count x =
      d.items.count x + (if v = 0 then none else some (v, cls d.nb (fpv v) (j / 4))).toList.count x := by
  have hu := fm_upd (F := d.at) (G := ({ d with t := d.t.set! j v } : Dir).at) x (List.range d.t.size)
    (fun i _ e => by rw [at_set hj, if_neg e]) List.nodup_range (List.mem_range.mpr hj)
  rw [at_set hj, if_pos rfl] at hu
  have hs : (d.t.set! j v).size = d.t.size := by simp [Array.set!]
  unfold Dir.items
  simp only [List.count_append, hs]
  omega

private theorem count_cons' {α : Type} [BEq α] (x a : α) (l : List α) :
    (a :: l).count x = [a].count x + l.count x := by
  rw [← List.singleton_append, List.count_append]

private theorem put_free {d : Dir} {v : UInt32} {b j : Nat} (hb : b < d.nb) (hv : v ≠ 0)
    (hf : (idxs d.nb (fpv v) b).find? (d.t[·]? = some 0) = some j) (x : UInt32 × Nat) :
    ({ d with t := d.t.set! j v } : Dir).items.count x = ((v, cls d.nb (fpv v) b) :: d.items).count x := by
  have hj0 : d.t[j]? = some 0 := by simpa using List.find?_some hf
  have hlt : j < d.t.size := by
    rcases Nat.lt_or_ge j d.t.size with h1 | h1
    · exact h1
    · simp [Array.getElem?_eq_none h1] at hj0
  have hcl : cls d.nb (fpv v) (j / 4) = cls d.nb (fpv v) b := by
    rcases mem_idxs.mp (List.mem_of_find?_eq_some hf) with e | e
    · rw [e]
    · rw [e, cls_alt hb]
  have hs := items_set hlt v x
  have h0 : d.at j = none := by simp [Dir.at, hj0]
  rw [h0, if_neg hv, hcl] at hs
  simp only [Option.toList_none, Option.toList_some, List.count_nil] at hs
  rw [count_cons']
  omega

/-- Inserting slot `v` into the pair of bucket `b` adds exactly that slot under the pair's label, and every other
    (slot, pair) keeps its count, whatever slots the kicks move; the shape and bucket count stay. -/
theorem put_count (n : Nat) : ∀ {d d' : Dir} {v : UInt32} {b : Nat}, d.Ok → b < d.nb → v ≠ 0 →
    d.put v b n = .ok d' → d'.Ok ∧ d'.nb = d.nb ∧
      ∀ x, d'.items.count x = d.items.count x + if (v, cls d.nb (fpv v) b) = x then 1 else 0 := by
  suffices H : ∀ {d d' : Dir} {v : UInt32} {b : Nat}, d.Ok → b < d.nb → v ≠ 0 → d.put v b n = .ok d' →
      d'.Ok ∧ d'.nb = d.nb ∧ ∀ x, d'.items.count x = ((v, cls d.nb (fpv v) b) :: d.items).count x by
    intro d d' v b hO hb hv h
    obtain ⟨a1, a2, a3⟩ := H hO hb hv h
    exact ⟨a1, a2, fun x => by rw [a3 x, List.count_cons]; simp⟩
  induction n with
  | zero =>
    intro d d' v b hO hb hv h
    unfold Dir.put at h
    cases hf : (idxs d.nb (fpv v) b).find? (d.t[·]? = some 0) with
    | some j =>
      simp only [hf, Except.ok.injEq] at h
      subst h
      exact ⟨ok_set hO j v, rfl, put_free hb hv hf⟩
    | none =>
      simp only [hf] at h
      split at h
      · rename_i hl
        simp only [Except.ok.injEq] at h
        subst h
        exact ⟨⟨hO.1, hO.2.1, show d.stash.length + 1 ≤ stashCap by omega⟩, rfl,
          fun x => List.perm_middle.count_eq x⟩
      · cases h
  | succ n ih =>
    intro d d' v b hO hb hv h
    unfold Dir.put at h
    cases hf : (idxs d.nb (fpv v) b).find? (d.t[·]? = some 0) with
    | some j =>
      simp only [hf, Except.ok.injEq] at h
      subst h
      exact ⟨ok_set hO j v, rfl, put_free hb hv hf⟩
    | none =>
      simp only [hf] at h
      have hf' := List.find?_eq_none.mp hf
      have hb' : alt d.nb (fpv v) b < d.nb := Nat.mod_lt _ hO.1
      have hcv : cls d.nb (fpv v) (alt d.nb (fpv v) b) = cls d.nb (fpv v) b := cls_alt hb
      have hpm : 4 * alt d.nb (fpv v) b + n % 4 ∈ idxs d.nb (fpv v) b := mem_idxs.mpr (.inr (by omega))
      generalize hB : alt d.nb (fpv v) b = B at h hb' hcv hpm
      have hp : 4 * B + n % 4 < d.t.size := by rw [hO.2.1]; omega
      generalize hP : 4 * B + n % 4 = p at h hp hpm
      have hw : d.t[p]? = some d.t[p] := by simp [hp]
      have hw0 : d.t[p] ≠ 0 := fun e => hf' p hpm (by simp [hw, e])
      rw [hw, Option.getD_some] at h
      obtain ⟨hO', hn', hc⟩ := ih (ok_set hO p v) hb' hw0 h
      refine ⟨hO', hn', fun x => ?_⟩
      have hc := hc x
      dsimp only at hc
      have hs := items_set hp v x
      have hp4 : p / 4 = B := by omega
      have hat : d.at p = some (d.t[p], cls d.nb (fpv d.t[p]) B) := at_eq.mpr ⟨hw, hw0, by rw [hp4]⟩
      rw [hat, if_neg hv, hp4, hcv] at hs
      simp only [Option.toList_some] at hs
      rw [count_cons'] at hc ⊢
      omega

/-- Erasing slot `v` of the pair of bucket `b` takes exactly one such slot under the pair's label when there is one,
    and nothing else; the shape and bucket count stay. -/
theorem erase_count {d : Dir} {v : UInt32} {b : Nat} (hO : d.Ok) (hb : b < d.nb) (hv : v ≠ 0) :
    (d.erase v b).Ok ∧ (d.erase v b).nb = d.nb ∧
      ∀ x, (d.erase v b).items.count x = d.items.count x - if (v, cls d.nb (fpv v) b) = x then 1 else 0 := by
  unfold Dir.erase
  cases hf : (idxs d.nb (fpv v) b).find? (d.t[·]? = some v) with
  | some j =>
    simp only
    refine ⟨ok_set hO j 0, trivial, fun x => ?_⟩
    have hjv : d.t[j]? = some v := by simpa using List.find?_some hf
    have hlt : j < d.t.size := by
      rcases Nat.lt_or_ge j d.t.size with h1 | h1
      · exact h1
      · simp [Array.getElem?_eq_none h1] at hjv
    have hcl : cls d.nb (fpv v) (j / 4) = cls d.nb (fpv v) b := by
      rcases mem_idxs.mp (List.mem_of_find?_eq_some hf) with e | e
      · rw [e]
      · rw [e, cls_alt hb]
    have hs := items_set hlt 0 x
    rw [at_eq.mpr ⟨hjv, hv, hcl⟩, if_pos rfl] at hs
    simp only [Option.toList_none, Option.toList_some, List.count_nil] at hs
    rw [show (if (v, cls d.nb (fpv v) b) = x then 1 else 0) = [(v, cls d.nb (fpv v) b)].count x by
      simp [List.count_singleton]]
    omega
  | none =>
    simp only
    refine ⟨⟨hO.1, hO.2.1, Nat.le_trans List.length_erase_le hO.2.2⟩, trivial, fun x => ?_⟩
    have hn : (v, cls d.nb (fpv v) b) ∉ (List.range d.t.size).filterMap d.at := by
      intro hm
      obtain ⟨j, hj, ha⟩ := List.mem_filterMap.mp hm
      obtain ⟨ht, -, hl⟩ := at_eq.mp ha
      have hj4 : j / 4 < d.nb := by have := List.mem_range.mp hj; rw [hO.2.1] at this; omega
      have := List.find?_eq_none.mp hf j (mem_idxs.mpr (cls_eq hb hj4 hl))
      simp [ht] at this
    have he : ({ d with stash := d.stash.erase (v, cls d.nb (fpv v) b) } : Dir).items =
        d.items.erase (v, cls d.nb (fpv v) b) := by
      unfold Dir.items; rw [List.erase_append_right _ hn]; rfl
    rw [he, List.count_erase]
    simp

/-- A slot the directory holds names its chunk among the key's candidates. -/
theorem Dir.sound {d : Dir} {h : UInt64} {c : Nat} (hO : d.Ok) (hc : c < 2 ^ cBits) (hd : d.Has h c) :
    c ∈ d.cands h := by
  have hv : (fun v : UInt32 => if fpv v = fpOf h then some (v.toNat % 2 ^ cBits) else none) (slot (fpOf h) c) =
      some c := by simp [fpv_slot hc, slot_mod hc]
  simp only [Dir.cands]
  rw [List.mem_filterMap]
  refine ⟨slot (fpOf h) c, ?_, hv⟩
  rcases List.mem_append.mp hd with hm | hs
  · obtain ⟨j, hj, ha⟩ := List.mem_filterMap.mp hm
    obtain ⟨ht, -, hl⟩ := at_eq.mp ha
    rw [fpv_slot hc] at hl
    have hj4 : j / 4 < d.nb := by have := List.mem_range.mp hj; rw [hO.2.1] at this; omega
    exact List.mem_append_left _
      (List.mem_filterMap.mpr ⟨j, mem_idxs.mpr (cls_eq (Nat.mod_lt _ hO.1) hj4 hl), ht⟩)
  · exact List.mem_append_right _ (List.mem_filterMap.mpr ⟨_, hs, by simp [Dir.item]⟩)

theorem drop_ok {d : Dir} (hO : d.Ok) (c : Nat) : (d.drop c).Ok :=
  ⟨hO.1, by simp [Dir.drop, hO.2.1], by simp only [Dir.drop]; exact Nat.le_trans (List.length_filter_le ..) hO.2.2⟩

/-- Dropping chunk `c` takes every slot of chunk `c` and nothing else. -/
theorem drop_count {d : Dir} (c : Nat) (x : UInt32 × Nat) :
    (d.drop c).items.count x = if x.1.toNat % 2 ^ cBits = c then 0 else d.items.count x := by
  have hat : ∀ j, (d.drop c).at j = (d.at j).filter fun y => decide (y.1.toNat % 2 ^ cBits ≠ c) := by
    intro j
    simp only [Dir.at, Dir.drop, Array.getElem?_map]
    cases d.t[j]? with
    | none => rfl
    | some v =>
      by_cases h0 : v = 0
      · subst h0; simp
      · by_cases hc : v.toNat % 2 ^ cBits = c <;> simp [h0, hc, Option.filter]
  have hi : (d.drop c).items = d.items.filter fun y => decide (y.1.toNat % 2 ^ cBits ≠ c) := by
    have hs : (d.drop c).t.size = d.t.size := by simp [Dir.drop]
    unfold Dir.items
    rw [List.filter_append, List.filter_filterMap, hs]
    congr 1
    exact congrArg (List.filterMap · _) (funext hat)
  rw [hi]
  split
  · rename_i e
    exact List.count_eq_zero.mpr fun hm => by simp [List.mem_filter, e] at hm
  · rename_i e
    exact List.count_filter (by simpa using e)

/-- Inserting the key hashes `hs` for chunk `c` adds exactly their slots; the shape and bucket count stay. -/
theorem ins_count {c : Nat} (hc : c < 2 ^ cBits) : ∀ (hs : List UInt64) {d d' : Dir}, d.Ok →
    hs.foldlM (fun d h => d.insert h c) d = .ok d' →
      d'.Ok ∧ d'.nb = d.nb ∧ ∀ x, d'.items.count x = d.items.count x + (hs.map (Dir.item d.nb · c)).count x
  | [], d, d', hO, e => by
    obtain rfl : d = d' := Except.ok.inj e
    exact ⟨hO, rfl, by simp⟩
  | h :: hs, d, d', hO, e => by
    simp only [List.foldlM_cons] at e
    cases h1 : d.insert h c with
    | error r => rw [h1] at e; cases e
    | ok d1 =>
      rw [h1] at e
      obtain ⟨a1, a2, a3⟩ := put_count maxKicks hO (Nat.mod_lt _ hO.1) (slot_ne_zero h hc) h1
      obtain ⟨b1, b2, b3⟩ := ins_count hc hs a1 e
      refine ⟨b1, b2.trans a2, fun x => ?_⟩
      rw [b3 x, a3 x, a2, fpv_slot hc, List.map_cons, List.count_cons]
      have : (if (slot (fpOf h) c, cls d.nb (fpOf h) (h.toNat % d.nb)) = x then 1 else 0) =
          (if (Dir.item d.nb h c == x) = true then 1 else 0) := by simp [Dir.item]
      omega

theorem rebuild_all : ∀ (cs : List (Nat × List UInt64)) {d0 d : Dir}, d0.Ok → (∀ ch ∈ cs, ch.1 < 2 ^ cBits) →
    cs.foldlM (fun d ch => ch.2.foldlM (fun d h => d.insert h ch.1) d) d0 = .ok d →
      d.Ok ∧ d.nb = d0.nb ∧
        ∀ x, d.items.count x = d0.items.count x + (cs.flatMap fun ch => ch.2.map (Dir.item d0.nb · ch.1)).count x
  | [], d0, d, hO, _, e => by
    obtain rfl : d0 = d := Except.ok.inj e
    exact ⟨hO, rfl, by simp⟩
  | ch :: cs, d0, d, hO, hb, e => by
    simp only [List.foldlM_cons] at e
    cases h1 : ch.2.foldlM (fun d h => d.insert h ch.1) d0 with
    | error r => rw [h1] at e; cases e
    | ok d1 =>
      rw [h1] at e
      obtain ⟨a1, a2, a3⟩ := ins_count (hb ch (List.mem_cons_self ..)) ch.2 hO h1
      obtain ⟨b1, b2, b3⟩ := rebuild_all cs a1 (fun x hx => hb x (List.mem_cons_of_mem _ hx)) e
      refine ⟨b1, b2.trans a2, fun x => ?_⟩
      rw [b3 x, a3 x, a2, List.flatMap_cons, List.count_append]
      omega

private theorem empty_count (nb : Nat) (x : UInt32 × Nat) : (Dir.empty nb).items.count x = 0 := by
  obtain ⟨v, l⟩ := x
  refine List.count_eq_zero.mpr fun hm => ?_
  rcases List.mem_append.mp hm with hm | hm
  · obtain ⟨j, -, ha⟩ := List.mem_filterMap.mp hm
    obtain ⟨ht, h0, -⟩ := at_eq.mp ha
    simp only [Dir.empty, Array.getElem?_replicate] at ht
    split at ht
    · exact h0 (Option.some.inj ht).symm
    · cases ht
  · simp [Dir.empty] at hm

/-- Load and growth: a rebuilt directory keeps its shape and holds exactly one slot for each key hash of each
    chunk it was built from. -/
theorem rebuild_inv {nb : Nat} {cs : List (Nat × List UInt64)} {d : Dir} (h0 : 0 < nb)
    (hb : ∀ ch ∈ cs, ch.1 < 2 ^ cBits) (h : Dir.rebuild nb cs = .ok d) :
    d.Ok ∧ d.nb = nb ∧ ∀ x, d.items.count x = (cs.flatMap fun ch => ch.2.map (Dir.item nb · ch.1)).count x := by
  obtain ⟨a1, a2, a3⟩ := rebuild_all cs (d0 := Dir.empty nb) ⟨h0, by simp [Dir.empty], by simp [Dir.empty]⟩ hb h
  refine ⟨a1, a2, fun x => ?_⟩
  have := a3 x
  rw [empty_count, Nat.zero_add] at this
  exact this

/-! ## Rows, dead bits, windows -/

theorem mem_ixs : ∀ (ws : List Row) (i n : Nat) (w : Row), (n, w) ∈ ixs i ws ↔ i ≤ n ∧ ws[n - i]? = some w
  | [], i, n, w => by simp [ixs]
  | x :: ws, i, n, w => by
    simp only [ixs, List.mem_cons, Prod.mk.injEq, mem_ixs ws (i + 1) n w]
    constructor
    · rintro (⟨rfl, rfl⟩ | ⟨h1, h2⟩)
      · simp
      · refine ⟨by omega, ?_⟩
        rw [show n - i = (n - (i + 1)) + 1 by omega]; simpa using h2
    · rintro ⟨h1, h2⟩
      by_cases hn : n = i
      · subst hn; left; simp at h2; exact ⟨rfl, h2.symm⟩
      · right; refine ⟨by omega, ?_⟩
        rw [show n - i = (n - (i + 1)) + 1 by omega] at h2; simpa using h2

theorem mem_ixs0 {ws : List Row} {n : Nat} {w : Row} : (n, w) ∈ ixs 0 ws ↔ ws[n]? = some w := by
  simp [mem_ixs]

theorem isDead_kill (d : HashMap Nat (HashSet Nat)) (c i c' i' : Nat) :
    isDead (kill d c i) c' i' = true ↔ (c = c' ∧ i = i') ∨ isDead d c' i' = true := by
  unfold isDead kill
  rw [Std.HashMap.get?_insert]
  by_cases hc : c = c'
  · subst hc
    cases d.get? c <;> simp [Std.HashSet.contains_insert]
  · simp [hc]

theorem isDead_erase (d : HashMap Nat (HashSet Nat)) (c c' i : Nat) :
    isDead (d.erase c) c' i = true ↔ c ≠ c' ∧ isDead d c' i = true := by
  unfold isDead
  rw [Std.HashMap.get?_erase]
  by_cases hc : c = c' <;> simp [hc]

private theorem isDead_kill_ne {d : HashMap Nat (HashSet Nat)} {c i c' i' : Nat} (h : ¬(c = c' ∧ i = i')) :
    isDead (kill d c i) c' i' = isDead d c' i' :=
  Bool.eq_iff_iff.mpr ⟨fun e => ((isDead_kill d c i c' i').mp e).resolve_left h,
    fun e => (isDead_kill d c i c' i').mpr (.inr e)⟩

private theorem isDead_erase_ne {d : HashMap Nat (HashSet Nat)} {c c' i : Nat} (h : c ≠ c') :
    isDead (d.erase c) c' i = isDead d c' i :=
  Bool.eq_iff_iff.mpr ((isDead_erase d c c' i).trans ⟨And.right, fun e => ⟨h, e⟩⟩)

private theorem isDead_insert_ne {d : HashMap Nat (HashSet Nat)} {c c' i : Nat} {s : HashSet Nat} (h : c ≠ c') :
    isDead (d.insert c s) c' i = isDead d c' i := by
  unfold isDead; rw [Std.HashMap.get?_insert]; simp [h]

/-! ## Live rows and their slots -/

private theorem ixs_nodup : ∀ (i : Nat) (ws : List Row), (ixs i ws).Nodup
  | _, [] => List.nodup_nil
  | i, w :: ws => List.nodup_cons.mpr ⟨fun hm => by have := ((mem_ixs ws (i + 1) i w).mp hm).1; omega,
      ixs_nodup (i + 1) ws⟩

private theorem liveHashes_congr {kh : Bytes → UInt64} {D D' : HashMap Nat (HashSet Nat)} {c : Nat} {ws : List Row}
    (h : ∀ i, isDead D c i = isDead D' c i) : liveHashes kh D c ws = liveHashes kh D' c ws := by
  unfold liveHashes
  congr 1
  funext iw
  simp only [liveHash, h]

/-- Killing live row `i` of chunk `c` takes exactly its key hash from the chunk's live hashes. -/
private theorem kill_chunk {kh : Bytes → UInt64} {dead : HashMap Nat (HashSet Nat)} {c i : Nat} {ws : List Row}
    {w : Row} (hw : ws[i]? = some w) (hd : isDead dead c i = false) :
    (liveHashes kh (kill dead c i) c ws ++ [kh w.1]).Perm (liveHashes kh dead c ws) := by
  refine List.perm_iff_count.mpr fun y => ?_
  have hu := fm_upd (F := liveHash kh dead c) (G := liveHash kh (kill dead c i) c) (j := (i, w)) y (ixs 0 ws)
    (fun iw hm hne => by
      obtain ⟨i', w'⟩ := iw
      have hi : ¬(c = c ∧ i = i') := fun ⟨_, e⟩ => by
        rw [← e] at hm hne
        exact hne (by rw [Option.some.inj ((mem_ixs0.mp hm).symm.trans hw)])
      simp only [liveHash, isDead_kill_ne hi])
    (ixs_nodup 0 ws) (mem_ixs0.mpr hw)
  have e1 : liveHash kh dead c (i, w) = some (kh w.1) := by simp [liveHash, hd]
  have e2 : liveHash kh (kill dead c i) c (i, w) = none := by
    simp [liveHash, (isDead_kill dead c i c i).mpr (.inl ⟨rfl, rfl⟩)]
  rw [e1, e2, Option.toList_some, Option.toList_none, List.count_nil] at hu
  rw [List.count_append]
  unfold liveHashes
  omega

private theorem fl_congr {α β : Type} {f g : α → List β} :
    ∀ {l : List α}, (∀ a ∈ l, f a = g a) → l.flatMap f = l.flatMap g
  | [], _ => rfl
  | a :: l, h => by
    rw [List.flatMap_cons, List.flatMap_cons, h a (List.mem_cons_self ..),
      fl_congr fun b hb => h b (List.mem_cons_of_mem _ hb)]

private theorem hs_nodup (s : HashSet Nat) : s.toList.Nodup :=
  Std.HashSet.distinct_toList.imp fun h e => by simp [e] at h

/-- A set that is `t` with `c` added: its listing's parts are `c`'s and `t`'s. -/
private theorem split_of {β : Type} {s t : HashSet Nat} {c : Nat} (h : ∀ a, a ∈ s ↔ a = c ∨ a ∈ t) (hc : c ∉ t)
    (f : Nat → List β) : (s.toList.flatMap f).Perm (f c ++ t.toList.flatMap f) := by
  have hp : s.toList.Perm (c :: t.toList) :=
    (List.perm_ext_iff_of_nodup (hs_nodup s)
      (List.nodup_cons.mpr ⟨fun hm => hc (Std.HashSet.mem_toList.mp hm), hs_nodup t⟩)).mpr fun a => by
      simp only [List.mem_cons, Std.HashSet.mem_toList, h]
  simpa only [List.flatMap_cons] using hp.flatMap_right f

private theorem erase_mem {inst : HashSet Nat} {c c' : Nat} (h : c' ∈ (inst.erase c).toList) :
    c ≠ c' ∧ inst.contains c' = true := by
  have := Std.HashSet.mem_erase.mp (Std.HashSet.mem_toList.mp h)
  exact ⟨by simpa using this.1, Std.HashSet.mem_iff_contains.mp this.2⟩

private theorem split_erase {β : Type} {inst : HashSet Nat} {c : Nat} (hc : inst.contains c = true)
    (f : Nat → List β) : (inst.toList.flatMap f).Perm (f c ++ (inst.erase c).toList.flatMap f) :=
  split_of (fun a => by
      rw [Std.HashSet.mem_erase]
      by_cases e : a = c
      · rw [e]; simp [Std.HashSet.mem_iff_contains, hc]
      · simp [e, Ne.symm e])
    (fun h => (erase_mem (Std.HashSet.mem_toList.mpr h)).1 rfl) f

private theorem split_insert {β : Type} {inst : HashSet Nat} {c : Nat} (hc : inst.contains c = false)
    (f : Nat → List β) : ((inst.insert c).toList.flatMap f).Perm (f c ++ inst.toList.flatMap f) :=
  split_of (fun a => by rw [Std.HashSet.mem_insert, beq_iff_eq, @eq_comm _ c a])
    (fun h => by rw [Std.HashSet.mem_iff_contains, hc] at h; cases h) f

private theorem live_mem {kh : Bytes → UInt64} {inst : HashSet Nat} {dead : HashMap Nat (HashSet Nat)} {nb : Nat}
    {rows : Nat → List Row} {c i : Nat} {w : Row} (hc : inst.contains c = true) (hw : (rows c)[i]? = some w)
    (hd : isDead dead c i = false) : Dir.item nb (kh w.1) c ∈ liveItems kh inst dead nb rows :=
  List.mem_flatMap.mpr ⟨c, Std.HashSet.mem_toList.mpr (Std.HashSet.mem_iff_contains.mpr hc),
    List.mem_map.mpr ⟨kh w.1, List.mem_filterMap.mpr ⟨(i, w), mem_ixs0.mpr hw, by simp [liveHash, hd]⟩, rfl⟩⟩

/-- The directory holds a slot for every live installed row: it holds as many as the live rows need. -/
private theorem live_has {kh : Bytes → UInt64} {fs : Fs} {rows : Nat → List Row} {c i : Nat} {kb : Bytes}
    {e : Entry} (hN : ∀ x, fs.dir.items.count x = (liveItems kh fs.inst fs.dead fs.dir.nb rows).count x)
    (hl : Live fs rows c i kb e) : fs.dir.Has (kh kb) c := by
  have h := List.count_pos_iff.mpr (live_mem (kh := kh) (nb := fs.dir.nb) hl.1 hl.2.1 hl.2.2)
  rw [← hN] at h
  exact List.count_pos_iff.mp h

/-- Killing live row `i` of installed chunk `c` takes exactly that row's slot from the slots the live rows need. -/
private theorem kill_count {kh : Bytes → UInt64} {inst : HashSet Nat} {dead : HashMap Nat (HashSet Nat)} {nb : Nat}
    {rows : Nat → List Row} {c i : Nat} {w : Row} (hc : inst.contains c = true) (hw : (rows c)[i]? = some w)
    (hd : isDead dead c i = false) (y : UInt32 × Nat) :
    (liveItems kh inst (kill dead c i) nb rows).count y + [Dir.item nb (kh w.1) c].count y =
      (liveItems kh inst dead nb rows).count y := by
  have hrest : ((inst.erase c).toList.flatMap fun c' => (liveHashes kh (kill dead c i) c' (rows c')).map
      (Dir.item nb · c')) =
      (inst.erase c).toList.flatMap fun c' => (liveHashes kh dead c' (rows c')).map (Dir.item nb · c') :=
    fl_congr fun c' hm => by
      rw [liveHashes_congr fun _ => isDead_kill_ne fun h => (erase_mem hm).1 h.1]
  have hk := ((kill_chunk (kh := kh) hw hd).map (Dir.item nb · c)).count_eq y
  rw [List.map_append, List.count_append] at hk
  simp only [List.map_cons, List.map_nil] at hk
  unfold liveItems
  rw [(split_erase hc _).count_eq, (split_erase hc _).count_eq, List.count_append, List.count_append, hrest]
  omega

/-- Reclaiming installed chunk `c` takes exactly the slots of chunk `c` from the slots the live rows need. -/
private theorem live_erase {kh : Bytes → UInt64} {inst : HashSet Nat} {dead : HashMap Nat (HashSet Nat)} {nb : Nat}
    {rows : Nat → List Row} {c : Nat} (hc : inst.contains c = true)
    (hb : ∀ c', inst.contains c' = true → c' < 2 ^ cBits) (y : UInt32 × Nat) :
    (liveItems kh (inst.erase c) (dead.erase c) nb rows).count y =
      if y.1.toNat % 2 ^ cBits = c then 0 else (liveItems kh inst dead nb rows).count y := by
  have hrest : ((inst.erase c).toList.flatMap fun c' => (liveHashes kh (dead.erase c) c' (rows c')).map
      (Dir.item nb · c')) =
      (inst.erase c).toList.flatMap fun c' => (liveHashes kh dead c' (rows c')).map (Dir.item nb · c') :=
    fl_congr fun c' hm => by
      rw [liveHashes_congr fun _ => isDead_erase_ne (erase_mem hm).1]
  have hch : ∀ c', c' < 2 ^ cBits → ∀ z ∈ (liveHashes kh dead c' (rows c')).map (Dir.item nb · c'),
      z.1.toNat % 2 ^ cBits = c' := fun c' hc' z hz => by
    obtain ⟨h, -, rfl⟩ := List.mem_map.mp hz
    exact slot_mod hc'
  unfold liveItems
  rw [hrest, (split_erase hc _).count_eq, List.count_append]
  split
  · rename_i e
    refine List.count_eq_zero.mpr fun hz => ?_
    obtain ⟨c', hc', hz⟩ := List.mem_flatMap.mp hz
    have h2 := erase_mem hc'
    exact h2.1 (e.symm.trans (hch c' (hb c' h2.2) y hz))
  · rename_i e
    rw [List.count_eq_zero.mpr fun hz => e (hch c (hb c hc) y hz), Nat.zero_add]

/-- Installing chunk `c0` adds exactly the slots of its live rows to the slots the live rows need. -/
private theorem live_insert {kh : Bytes → UInt64} {inst : HashSet Nat} {dead : HashMap Nat (HashSet Nat)}
    {nb c0 : Nat} {bd : HashSet Nat} {rows rows' : Nat → List Row} (hc : inst.contains c0 = false)
    (hr : ∀ c', c' ≠ c0 → rows' c' = rows c') (y : UInt32 × Nat) :
    (liveItems kh (inst.insert c0) (dead.insert c0 bd) nb rows').count y =
      ((liveHashes kh (dead.insert c0 bd) c0 (rows' c0)).map (Dir.item nb · c0)).count y +
        (liveItems kh inst dead nb rows).count y := by
  have hrest : (inst.toList.flatMap fun c => (liveHashes kh (dead.insert c0 bd) c (rows' c)).map
      (Dir.item nb · c)) = inst.toList.flatMap fun c => (liveHashes kh dead c (rows c)).map (Dir.item nb · c) :=
    fl_congr fun c hm => by
      have hne : c ≠ c0 := fun e => by
        rw [e, Std.HashSet.mem_toList, Std.HashSet.mem_iff_contains, hc] at hm
        cases hm
      rw [hr c hne, liveHashes_congr fun _ => isDead_insert_ne (Ne.symm hne)]
  unfold liveItems
  rw [(split_insert hc _).count_eq, List.count_append, hrest]

theorem win_fold_out {kb : Bytes} : ∀ (ch : List (Bytes × Entry)) (m : HashMap Bytes Entry),
    (∀ ke ∈ ch, ke.1 ≠ kb) →
    (ch.foldl (fun m ke => m.insert ke.1 ke.2) m).get? kb = m.get? kb
  | [], _, _ => rfl
  | ke :: ch, m, h => by
    rw [List.foldl_cons, win_fold_out ch _ (fun x hx => h x (List.mem_cons_of_mem _ hx)), Std.HashMap.get?_insert]
    simp [h ke (List.mem_cons_self ..)]

theorem win_fold_in {kb : Bytes} {v : Entry} : ∀ (ch : List (Bytes × Entry)) (m : HashMap Bytes Entry),
    (∀ ke ∈ ch, ke.1 = kb → ke.2 = v) → (∃ ke ∈ ch, ke.1 = kb) →
    (ch.foldl (fun m ke => m.insert ke.1 ke.2) m).get? kb = some v
  | [], _, _, ⟨_, h, _⟩ => by simp at h
  | ke :: ch, m, hv, hx => by
    rw [List.foldl_cons]
    by_cases hin : ∃ x ∈ ch, x.1 = kb
    · exact win_fold_in ch _ (fun x hx => hv x (List.mem_cons_of_mem _ hx)) hin
    · have hout : ∀ x ∈ ch, x.1 ≠ kb := fun x hx he => hin ⟨x, hx, he⟩
      rw [win_fold_out ch _ hout, Std.HashMap.get?_insert]
      obtain ⟨x, hx, he⟩ := hx
      rcases List.mem_cons.mp hx with rfl | hx
      · simp [he, hv x (List.mem_cons_self ..) he]
      · exact absurd he (hout x hx)

theorem win_reclaim (D : HashMap Nat (HashSet Nat)) (c : Nat) (kb : Bytes) :
    ∀ (xs : List (Nat × Row)) (m : HashMap Bytes Entry),
    (∀ e, (xs.foldl (fun m iw => if isDead D c iw.1 then m else m.insert iw.2.1 iw.2.2) m).get? kb = some e →
      m.get? kb = some e ∨ ∃ iw ∈ xs, isDead D c iw.1 = false ∧ iw.2 = (kb, e)) ∧
    ((xs.foldl (fun m iw => if isDead D c iw.1 then m else m.insert iw.2.1 iw.2.2) m).get? kb = none →
      m.get? kb = none ∧ ∀ iw ∈ xs, isDead D c iw.1 = false → iw.2.1 ≠ kb)
  | [], m => by simp
  | iw :: xs, m => by
    obtain ⟨h1, h2⟩ := win_reclaim D c kb xs (if isDead D c iw.1 then m else m.insert iw.2.1 iw.2.2)
    have hF : (if isDead D c iw.1 then m else m.insert iw.2.1 iw.2.2).get? kb =
        if isDead D c iw.1 = false ∧ iw.2.1 = kb then some iw.2.2 else m.get? kb := by
      by_cases hd : isDead D c iw.1 <;> by_cases hk : iw.2.1 = kb <;> simp [hd, hk, Std.HashMap.getElem?_insert]
    rw [List.foldl_cons]
    refine ⟨fun e he => ?_, fun hn => ?_⟩
    · rcases h1 e he with h | ⟨y, hy, hy'⟩
      · rw [hF] at h
        split at h
        · rename_i hc
          exact .inr ⟨iw, List.mem_cons_self .., hc.1, Prod.ext hc.2 (by simpa using h)⟩
        · exact .inl h
      · exact .inr ⟨y, List.mem_cons_of_mem _ hy, hy'⟩
    · obtain ⟨hm, hx⟩ := h2 hn
      rw [hF] at hm
      split at hm
      · simp at hm
      · rename_i hc
        refine ⟨hm, fun y hy hyd => ?_⟩
        rcases List.mem_cons.mp hy with rfl | hy
        · exact fun hk => hc ⟨hyd, hk⟩
        · exact hx y hy hyd

/-! ## Lookups -/

theorem hits_sound {kh : Bytes → UInt64} {fs : Fs} {rows : Nat → List Row} {kb : Bytes} {x : Nat × Nat × Entry}
    (hx : x ∈ hits kh fs rows kb) : Live fs rows x.1 x.2.1 kb x.2.2 := by
  simp only [hits, List.mem_flatMap] at hx
  obtain ⟨c', -, hx⟩ := hx
  split at hx
  · rename_i hin
    rw [List.mem_filterMap] at hx
    obtain ⟨⟨i', w⟩, hw, hx⟩ := hx
    simp only at hx
    split at hx
    · rename_i hc
      simp only [Option.some.injEq] at hx
      subst hx
      refine ⟨hin, ?_, hc.2⟩
      rw [mem_ixs0.mp hw]
      exact congrArg some (Prod.ext hc.1 rfl)
    · simp at hx
  · simp at hx

theorem hits_complete {kh : Bytes → UInt64} {fs : Fs} {rows : Nat → List Row} {kb : Bytes} {c i : Nat} {e : Entry}
    (hO : fs.dir.Ok) (hD : fs.dir.Has (kh kb) c) (hc : c < 2 ^ cBits) (hL : Live fs rows c i kb e) :
    (c, i, e) ∈ hits kh fs rows kb := by
  obtain ⟨hin, hr, hd⟩ := hL
  simp only [hits, List.mem_flatMap]
  refine ⟨c, Dir.sound hO hc hD, ?_⟩
  rw [if_pos hin, List.mem_filterMap]
  exact ⟨(i, (kb, e)), mem_ixs0.mpr hr, by simp [hd]⟩

/-- Under `FInv`, a lookup returns the state's entry, whatever false positives the directory gives. -/
theorem lookup_eq {H : Bytes → Bytes} {kh : Bytes → UInt64} {fs : Fs} {files : Nat → Chunk} {s : St}
    (hI : FInv H kh fs files s) (u : Bool) (k : Key) : lookup kh fs (layout H kh files) (skey u k) = sget s u k := by
  obtain ⟨-, -, hC, -, -, -, hK, hNc, hO⟩ := hI
  obtain ⟨hW, hS, hN, hL, -⟩ := hK u k
  unfold lookup
  cases hw : fs.win.get? (skey u k) with
  | some e => exact hW e hw
  | none =>
    cases hs : sealGet fs (skey u k) with
    | some e => exact hS hw e hs
    | none =>
      cases hx : hits kh fs (layout H kh files) (skey u k) with
      | cons x t =>
        have hm : x ∈ hits kh fs (layout H kh files) (skey u k) := by rw [hx]; exact List.mem_cons_self ..
        obtain ⟨c, i, e⟩ := x
        exact hL _ _ _ (hits_sound hm)
      | nil =>
        rcases hN hw hs with h | ⟨c, i, hl⟩
        · exact h.symm
        · have hm := hits_complete hO (live_has hNc hl) (hC c hl.1).1 hl
          rw [hx] at hm; simp at hm

/-- The store holds exactly the state's heads and entries, so the decisions read from it are the spec's on that state
    without core counts (`St.perKey`: the store caps per key). -/
theorem view_eq {H : Bytes → Bytes} {kh : Bytes → UInt64} {fs : Fs} {files : Nat → Chunk} {s : St}
    (hI : FInv H kh fs files s) : view kh fs (layout H kh files) = s.perKey := by
  obtain ⟨⟨hr, gr, cr⟩, ⟨hu, gu, cu⟩⟩ := s
  have h1 := hI.1
  have h2 := hI.2.1
  simp only at h1 h2
  simp only [view, St.perKey, h1, h2, St.mk.injEq, SetIdx.mk.injEq, true_and, and_true]
  exact ⟨funext fun k => by simpa [sget] using lookup_eq hI false k,
    funext fun k => by simpa [sget] using lookup_eq hI true k⟩

/-- Under `FInv`, a lookup's walk of the chunks the directory names finds at most one live row of a key, however
    often the directory names its chunk. -/
theorem hits_one {H : Bytes → Bytes} {kh : Bytes → UInt64} {fs : Fs} {files : Nat → Chunk} {s : St}
    (hI : FInv H kh fs files s) (u : Bool) (k : Key) {x y : Nat × Nat × Entry}
    (hx : x ∈ hits kh fs (layout H kh files) (skey u k)) (hy : y ∈ hits kh fs (layout H kh files) (skey u k)) :
    x = y := by
  obtain ⟨-, -, -, hL, hU⟩ := hI.2.2.2.2.2.2.1 u k
  obtain ⟨c, i, e⟩ := x
  obtain ⟨c', i', e'⟩ := y
  have lx := hits_sound hx
  have ly := hits_sound hy
  dsimp only at lx ly
  obtain ⟨rfl, rfl⟩ := (hU c i e lx).2.2 c' i' e' ly
  rw [hL _ _ _ lx, hL _ _ _ ly]

/-- A lookup reads the directory at 8 positions, 4 in each of the key hash's two buckets, and the stash, which
    `FInv` caps at `stashCap`: it visits at most `2 * 4 + stashCap` candidate chunks. -/
theorem read_bound {H : Bytes → Bytes} {kh : Bytes → UInt64} {fs : Fs} {files : Nat → Chunk} {s : St}
    (hI : FInv H kh fs files s) (h : UInt64) :
    (idxs fs.dir.nb (fpOf h) (h.toNat % fs.dir.nb)).length = 2 * 4 ∧
    (∀ j ∈ idxs fs.dir.nb (fpOf h) (h.toNat % fs.dir.nb),
      j / 4 = h.toNat % fs.dir.nb ∨ j / 4 = alt fs.dir.nb (fpOf h) (h.toNat % fs.dir.nb)) ∧
    (fs.dir.cands h).length ≤ 2 * 4 + stashCap := by
  have hl : (idxs fs.dir.nb (fpOf h) (h.toNat % fs.dir.nb)).length = 2 * 4 := by simp [idxs]
  refine ⟨hl, fun j hj => mem_idxs.mp hj, ?_⟩
  dsimp only [Dir.cands]
  refine Nat.le_trans (List.length_filterMap_le _ _) ?_
  rw [List.length_append]
  exact Nat.add_le_add (Nat.le_trans (List.length_filterMap_le _ _) (Nat.le_of_eq hl))
    (Nat.le_trans (List.length_filterMap_le _ _) hI.2.2.2.2.2.2.2.2.2.2)

/-! ## Steps keep the invariant -/

theorem postingsFrom_nil {k : Key} : ∀ (i : Nat) (ls : List Line), k ∉ ls.flatMap keys → postingsFrom k i ls = []
  | _, [], _ => rfl
  | i, l :: ls, h => by
    simp only [List.flatMap_cons, List.mem_append, not_or] at h
    simp [postingsFrom, h.1, postingsFrom_nil (i + 1) ls h.2]

theorem addRows_get {H : Bytes → Bytes} {x : SetIdx} {adds : List Line} {k : Key} (h : k ∉ adds.flatMap keys) :
    (x.addRows H adds).get k = x.get k := by
  simp only [SetIdx.addRows, (foldl_add H adds x).2 k, postingsFrom_nil _ _ h, List.foldl_nil]

theorem changed_fst {s' : St} {r : List Decision × List Line × List Line} {u : Bool} {k : Key}
    {ke : Bytes × Entry} (hm : ke ∈ changed s' r) (he : ke.1 = skey u k) :
    ke.2 = sget s' u k ∧ k ∈ (if u then r.2.2 else r.2.1).flatMap keys := by
  simp only [changed, List.mem_append, List.mem_map] at hm
  rcases hm with ⟨k', hk', rfl⟩ | ⟨k', hk', rfl⟩ <;> obtain ⟨rfl, rfl⟩ := skey_inj he <;> simp [sget, hk']

theorem changed_key {s' : St} {r : List Decision × List Line × List Line} {ke : Bytes × Entry}
    (hm : ke ∈ changed s' r) : ∃ u k, ke.1 = skey u k := by
  simp only [changed, List.mem_append, List.mem_map] at hm
  rcases hm with ⟨k, -, rfl⟩ | ⟨k, -, rfl⟩
  · exact ⟨false, k, rfl⟩
  · exact ⟨true, k, rfl⟩

theorem changed_mem {s' : St} {r : List Decision × List Line × List Line} {u : Bool} {k : Key}
    (h : k ∈ (if u then r.2.2 else r.2.1).flatMap keys) : (skey u k, sget s' u k) ∈ changed s' r := by
  cases u <;> simp only [Bool.false_eq_true, ↓reduceIte] at h <;>
    simp only [changed, sget, Bool.false_eq_true, ↓reduceIte, List.mem_append, List.mem_map]
  · exact .inl ⟨k, h, rfl⟩
  · exact .inr ⟨k, h, rfl⟩

/-- Killing one row of key bytes `kb`: when it is live, its dead bit is set and exactly its slot leaves; when it is
    dead already, nothing changes. -/
private theorem killRow_step {kh : Bytes → UInt64} {inst : HashSet Nat} {rows : Nat → List Row} {kb : Bytes}
    {a : HashMap Nat (HashSet Nat) × Dir} {x : Nat × Nat × Entry} (hc : inst.contains x.1 = true)
    (hcb : x.1 < 2 ^ cBits) (hr : (rows x.1)[x.2.1]? = some (kb, x.2.2)) (hO : a.2.Ok)
    (hN : ∀ y, a.2.items.count y = (liveItems kh inst a.1 a.2.nb rows).count y) :
    (killRow (kh kb) a x).2.Ok ∧ (killRow (kh kb) a x).2.nb = a.2.nb ∧
    (∀ y, (killRow (kh kb) a x).2.items.count y =
      (liveItems kh inst (killRow (kh kb) a x).1 (killRow (kh kb) a x).2.nb rows).count y) ∧
    ∀ c i, isDead (killRow (kh kb) a x).1 c i = true ↔ isDead a.1 c i = true ∨ (x.1 = c ∧ x.2.1 = i) := by
  unfold killRow
  split
  · rename_i hd
    refine ⟨hO, rfl, hN, fun c i => ⟨.inl, ?_⟩⟩
    rintro (h | ⟨rfl, rfl⟩)
    · exact h
    · exact hd
  · rename_i hd
    have hd : isDead a.1 x.1 x.2.1 = false := by simpa using hd
    dsimp only
    obtain ⟨e1, e2, e3⟩ := erase_count (v := slot (fpOf (kh kb)) x.1) hO (Nat.mod_lt (kh kb).toNat hO.1)
      (slot_ne_zero (kh kb) hcb)
    refine ⟨e1, e2, fun y => ?_, fun c i => (isDead_kill a.1 x.1 x.2.1 c i).trans Or.comm⟩
    have hk := kill_count (kh := kh) (nb := a.2.nb) hc hr hd y
    dsimp only at hk
    rw [e3 y, e2, hN y, fpv_slot hcb]
    have : (if (slot (fpOf (kh kb)) x.1, cls a.2.nb (fpOf (kh kb)) ((kh kb).toNat % a.2.nb)) = y then 1 else 0) =
        [Dir.item a.2.nb (kh kb) x.1].count y := by simp [List.count_singleton, Dir.item]
    omega

/-- Killing the hits of key bytes `kb`, live rows of `fs`: the counted slots stay exact and the dead rows are the
    old ones and the hits. -/
private theorem kills_hits {kh : Bytes → UInt64} {fs : Fs} {rows : Nat → List Row} {kb : Bytes}
    (hC : ∀ c, fs.inst.contains c = true → c < 2 ^ cBits) :
    ∀ (xs : List (Nat × Nat × Entry)) (a a' : HashMap Nat (HashSet Nat) × Dir),
    (∀ x ∈ xs, Live fs rows x.1 x.2.1 kb x.2.2) → xs.foldl (killRow (kh kb)) a = a' → a.2.Ok →
    (∀ y, a.2.items.count y = (liveItems kh fs.inst a.1 a.2.nb rows).count y) →
    a'.2.Ok ∧ a'.2.nb = a.2.nb ∧ (∀ y, a'.2.items.count y = (liveItems kh fs.inst a'.1 a'.2.nb rows).count y) ∧
    ∀ c i, isDead a'.1 c i = true ↔ isDead a.1 c i = true ∨ ∃ x ∈ xs, x.1 = c ∧ x.2.1 = i
  | [], a, a', _, e, hO, hN => by subst e; exact ⟨hO, rfl, hN, fun c i => by simp⟩
  | x :: xs, a, a', hL, e, hO, hN => by
    rw [List.foldl_cons] at e
    have hx := hL x (List.mem_cons_self ..)
    obtain ⟨s1, s2, s3, s4⟩ := killRow_step hx.1 (hC _ hx.1) hx.2.1 hO hN
    obtain ⟨t1, t2, t3, t4⟩ := kills_hits hC xs _ a' (fun y hy => hL y (List.mem_cons_of_mem _ hy)) e s1 s3
    refine ⟨t1, t2.trans s2, t3, fun c i => ?_⟩
    rw [t4, s4]
    constructor
    · rintro ((h | h) | ⟨y, hy, h⟩)
      · exact .inl h
      · exact .inr ⟨x, List.mem_cons_self .., h⟩
      · exact .inr ⟨y, List.mem_cons_of_mem _ hy, h⟩
    · rintro (h | ⟨y, hy, h⟩)
      · exact .inl (.inl h)
      · rcases List.mem_cons.mp hy with rfl | hy
        · exact .inl (.inr h)
        · exact .inr ⟨y, hy, h⟩

private theorem kills_all {kh : Bytes → UInt64} {fs : Fs} {rows : Nat → List Row}
    (hC : ∀ c, fs.inst.contains c = true → c < 2 ^ cBits) :
    ∀ (ch : List (Bytes × Entry)) (a a' : HashMap Nat (HashSet Nat) × Dir),
    ch.foldl (fun a ke => (hits kh fs rows ke.1).foldl (killRow (kh ke.1)) a) a = a' → a.2.Ok →
    (∀ y, a.2.items.count y = (liveItems kh fs.inst a.1 a.2.nb rows).count y) →
    a'.2.Ok ∧ a'.2.nb = a.2.nb ∧ (∀ y, a'.2.items.count y = (liveItems kh fs.inst a'.1 a'.2.nb rows).count y) ∧
    ∀ c i, isDead a'.1 c i = true ↔
      isDead a.1 c i = true ∨ ∃ ke ∈ ch, ∃ x ∈ hits kh fs rows ke.1, x.1 = c ∧ x.2.1 = i
  | [], a, a', e, hO, hN => by subst e; exact ⟨hO, rfl, hN, fun c i => by simp⟩
  | ke :: ch, a, a', e, hO, hN => by
    rw [List.foldl_cons] at e
    obtain ⟨s1, s2, s3, s4⟩ := kills_hits hC (hits kh fs rows ke.1) a _ (fun x hx => hits_sound hx) rfl hO hN
    obtain ⟨t1, t2, t3, t4⟩ := kills_all hC ch _ a' e s1 s3
    refine ⟨t1, t2.trans s2, t3, fun c i => ?_⟩
    rw [t4, s4]
    constructor
    · rintro ((h | h) | ⟨y, hy, h⟩)
      · exact .inl h
      · exact .inr ⟨ke, List.mem_cons_self .., h⟩
      · exact .inr ⟨y, List.mem_cons_of_mem _ hy, h⟩
    · rintro (h | ⟨y, hy, h⟩)
      · exact .inl (.inl h)
      · rcases List.mem_cons.mp hy with rfl | hy
        · exact .inl (.inr h)
        · exact .inr ⟨y, hy, h⟩

/-- Core counts change no head and no entry of a batch's next state. -/
theorem perKey_apply (H : Bytes → Bytes) (s : St) (r : List Decision × List Line × List Line) :
    (s.perKey.apply H r).perKey = (s.apply H r).perKey := by
  have e : ∀ (x : SetIdx) (adds : List Line), ({ ({ x with core := fun _ => 0 } : SetIdx).addRows H adds with
      core := fun _ => 0 } : SetIdx) = { x.addRows H adds with core := fun _ => 0 } := fun x adds => by
    obtain ⟨a1, a2⟩ := foldl_add H adds x
    obtain ⟨b1, b2⟩ := foldl_add H adds { x with core := fun _ => 0 }
    simp only [SetIdx.addRows, SetIdx.mk.injEq, and_true]
    exact ⟨by simp [a1, b1], funext fun k => by simp [a2, b2]⟩
  simp only [St.perKey, St.apply, e]

/-- Applying a batch's result keeps `FInv` with the spec's next state, whose entries are `Entry.Wf` (`entryOf_wf`). -/
theorem apply_inv {H : Bytes → Bytes} {kh : Bytes → UInt64} {fs : Fs} {files : Nat → Chunk} {s : St}
    (hI : FInv H kh fs files s) (r : List Decision × List Line × List Line)
    (hS : ∀ u k, (sget (s.apply H r) u k).Wf) :
    FInv H kh (apply H kh fs (layout H kh files) r) files (s.apply H r) := by
  have hv := view_eq hI
  have hc : changed (s.perKey.apply H r) r = changed (s.apply H r) r :=
    show changed (s.perKey.apply H r).perKey r = changed (s.apply H r).perKey r by rw [perKey_apply]
  have hh : (s.perKey.apply H r).rel.head = (s.apply H r).rel.head ∧
      (s.perKey.apply H r).unr.head = (s.apply H r).unr.head :=
    show (s.perKey.apply H r).perKey.rel.head = (s.apply H r).perKey.rel.head ∧
      (s.perKey.apply H r).perKey.unr.head = (s.apply H r).perKey.unr.head by rw [perKey_apply]; exact ⟨rfl, rfl⟩
  obtain ⟨-, -, hC, hD, hDI, hWf, hK, hNc, hO⟩ := hI
  have hwin : (apply H kh fs (layout H kh files) r).win =
      (changed (s.apply H r) r).foldl (fun m ke => m.insert ke.1 ke.2) fs.win := by simp only [apply, hv, hc, hh.1, hh.2]
  obtain ⟨hkO, -, hkN, hkd⟩ := kills_all (rows := layout H kh files) (fun c h => (hC c h).1)
    (changed (s.apply H r) r) (fs.dead, fs.dir) _ rfl hO hNc
  have hda : (apply H kh fs (layout H kh files) r).dead = ((changed (s.apply H r) r).foldl
      (fun a ke => (hits kh fs (layout H kh files) ke.1).foldl (killRow (kh ke.1)) a) (fs.dead, fs.dir)).1 := by
    simp only [apply, hv, hc, hh.1, hh.2]
  have hdi : (apply H kh fs (layout H kh files) r).dir = ((changed (s.apply H r) r).foldl
      (fun a ke => (hits kh fs (layout H kh files) ke.1).foldl (killRow (kh ke.1)) a) (fs.dead, fs.dir)).2 := by
    simp only [apply, hv, hc, hh.1, hh.2]
  have hdead : ∀ c i, isDead (apply H kh fs (layout H kh files) r).dead c i = true ↔ isDead fs.dead c i = true ∨
      ∃ ke ∈ changed (s.apply H r) r, ∃ x ∈ hits kh fs (layout H kh files) ke.1, x.1 = c ∧ x.2.1 = i := by
    intro c i; rw [hda]; exact hkd c i
  have hold : ∀ c i, isDead fs.dead c i = true → isDead (apply H kh fs (layout H kh files) r).dead c i = true :=
    fun c i h => (hdead c i).mpr (.inl h)
  refine ⟨by simp only [apply, hv, hc, hh.1, hh.2], by simp only [apply, hv, hc, hh.1, hh.2], hC, hD, fun c i h => ?_, fun kb e he => ?_,
    fun u k => ?_, fun x => by rw [hda, hdi]; exact hkN x, by rw [hdi]; exact hkO⟩
  · rcases (hdead c i).mp h with h | ⟨_, -, x, hx, rfl, -⟩
    · exact hDI _ _ h
    · exact (hits_sound hx).1
  · rcases he with he | he
    · rw [hwin] at he
      by_cases hx : ∃ ke ∈ changed (s.apply H r) r, ke.1 = kb
      · obtain ⟨ke, hke, rfl⟩ := hx
        obtain ⟨u, k, hk⟩ := changed_key hke
        have hv := win_fold_in (v := sget (s.apply H r) u k) _ fs.win
          (fun x hm hx => (changed_fst hm hx).1) ⟨ke, hke, hk⟩
        rw [hk, hv] at he
        obtain rfl := Option.some.inj he
        exact hS u k
      · rw [win_fold_out _ _ (fun x hm hx' => hx ⟨x, hm, hx'⟩)] at he
        exact hWf kb e (.inl he)
    · exact hWf kb e (.inr he)
  · obtain ⟨hW, hS, hN, hL, hU⟩ := hK u k
    by_cases hT : k ∈ (if u then r.2.2 else r.2.1).flatMap keys
    · have hw := win_fold_in (v := sget (s.apply H r) u k) (changed (s.apply H r) r) fs.win
        (fun ke hm he => (changed_fst hm he).1) ⟨_, changed_mem hT, rfl⟩
      rw [← hwin] at hw
      have hno : ∀ c i e, ¬Live (apply H kh fs (layout H kh files) r) (layout H kh files) c i (skey u k) e := by
        rintro c i e ⟨hin, hr, hd⟩
        have hd0 : isDead fs.dead c i = false := by
          cases h0 : isDead fs.dead c i
          · rfl
          · rw [hold c i h0] at hd; cases hd
        have hm := hits_complete hO (live_has hNc ⟨hin, hr, hd0⟩) (hC c hin).1 ⟨hin, hr, hd0⟩
        have := (hdead c i).mpr (.inr ⟨_, changed_mem hT, _, hm, rfl, rfl⟩)
        rw [hd] at this; cases this
      refine ⟨fun e he => ?_, fun h => ?_, fun h => ?_, fun c i e hl => absurd hl (hno c i e),
        fun c i e hl => absurd hl (hno c i e)⟩
      · rw [hw] at he; exact (Option.some.inj he).symm
      · rw [hw] at h; cases h
      · rw [hw] at h; cases h
    · have hout : ∀ ke ∈ changed (s.apply H r) r, ke.1 ≠ skey u k := fun ke hm he => hT (changed_fst hm he).2
      have hw := win_fold_out (changed (s.apply H r) r) fs.win hout
      rw [← hwin] at hw
      have hn : sget (s.apply H r) u k = sget s u k := by
        cases u <;> simp only [sget, St.apply, Bool.false_eq_true, ↓reduceIte] at hT ⊢ <;> exact addRows_get hT
      rw [hn]
      have hlive : ∀ c i e, Live (apply H kh fs (layout H kh files) r) (layout H kh files) c i (skey u k) e ↔
          Live fs (layout H kh files) c i (skey u k) e := by
        intro c i e
        refine ⟨fun ⟨hin, hr, hd⟩ => ⟨hin, hr, ?_⟩, fun ⟨hin, hr, hd⟩ => ⟨hin, hr, ?_⟩⟩
        · cases h0 : isDead fs.dead c i
          · rfl
          · rw [hold c i h0] at hd; cases hd
        · cases h0 : isDead (apply H kh fs (layout H kh files) r).dead c i
          · rfl
          · rcases (hdead c i).mp h0 with h | ⟨ke, hke, x, hx, rfl, rfl⟩
            · rw [hd] at h; cases h
            · have hs := (hits_sound hx).2.1
              rw [hr] at hs
              simp only [Option.some.injEq, Prod.mk.injEq] at hs
              exact absurd hs.1.symm (hout ke hke)
      have hsg : sealGet (apply H kh fs (layout H kh files) r) (skey u k) = sealGet fs (skey u k) := rfl
      refine ⟨fun e he => hW e (by rw [← hw]; exact he),
        fun h e he => hS (by rw [← hw]; exact h) e (by rw [← hsg]; exact he),
        fun h hs => ?_, fun c i e hl => hL c i e ((hlive c i e).mp hl), fun c i e hl => ?_⟩
      · rcases hN (by rw [← hw]; exact h) (by rw [← hsg]; exact hs) with h | ⟨c, i, hl⟩
        · exact .inl h
        · exact .inr ⟨c, i, (hlive c i _).mpr hl⟩
      obtain ⟨u1, u2, u3⟩ := hU c i _ ((hlive c i _).mp hl)
      exact ⟨by rw [hw]; exact u1, by rw [hsg]; exact u2, fun c' i' e' hl' => u3 c' i' e' ((hlive c' i' e').mp hl')⟩

/-- Sealing the window keeps `FInv` (same state). -/
theorem seal_inv {H : Bytes → Bytes} {kh : Bytes → UInt64} {fs fs' : Fs} {files : Nat → Chunk} {s : St}
    (hI : FInv H kh fs files s) (h : sealWindow fs = some fs') : FInv H kh fs' files s := by
  unfold sealWindow at h
  split at h
  · rename_i hsn
    simp only [Option.some.injEq] at h
    subst h
    obtain ⟨h1, h2, hC, hD, hDI, hWf, hK, hNc, hO⟩ := hI
    refine ⟨h1, h2, hC, hD, hDI, fun kb e he => ?_, fun u k => ?_, hNc, hO⟩
    · rcases he with he | he
      · simp at he
      · exact hWf kb e (.inl (by simpa [sealGet] using he))
    obtain ⟨hW, hS, hN, hL, hU⟩ := hK u k
    refine ⟨fun e he => by simp at he, fun _ e he => hW e (by simpa [sealGet] using he), fun _ hs => ?_, hL,
      fun c i e hl => ⟨by simp, by simpa [sealGet] using (hU c i e hl).1, (hU c i e hl).2.2⟩⟩
    exact hN (by simpa [sealGet] using hs) (by simp [sealGet, hsn])
  · simp at h

/-- Reclaim keeps `FInv` (same state): it refuses a chunk that is not installed; an installed chunk's live rows
    re-enter the window, and only its dead rows, which hold superseded versions, are dropped. -/
theorem reclaim_inv {H : Bytes → Bytes} {kh : Bytes → UInt64} {fs fs' : Fs} {files : Nat → Chunk} {s : St} {c : Nat}
    (hI : FInv H kh fs files s) (h : reclaim fs (layout H kh files) c = some fs') : FInv H kh fs' files s := by
  unfold reclaim at h
  split at h
  case isFalse => simp at h
  rename_i hc
  simp only [Option.some.injEq] at h
  have hq := h
  have fw : fs'.win = (ixs 0 (layout H kh files c)).foldl
      (fun m iw => if isDead fs.dead c iw.1 then m else m.insert iw.2.1 iw.2.2) fs.win := by rw [← hq]
  have fsg : ∀ kb, sealGet fs' kb = sealGet fs kb := fun kb => by rw [← hq]; rfl
  obtain ⟨h1, h2, hC, hD, hDI, hWf, hK, hNc, hO⟩ := hI
  have hin : ∀ c', fs'.inst.contains c' = true ↔ c ≠ c' ∧ fs.inst.contains c' = true := fun c' => by
    rw [← hq]; simp [Std.HashSet.contains_erase]
  have hdd : ∀ c' i, isDead fs'.dead c' i = true ↔ c ≠ c' ∧ isDead fs.dead c' i = true := fun c' i => by
    rw [← hq]; exact isDead_erase _ _ _ _
  have hlive : ∀ c' i kb e, Live fs' (layout H kh files) c' i kb e ↔
      c ≠ c' ∧ Live fs (layout H kh files) c' i kb e := by
    intro c' i kb e
    constructor
    · rintro ⟨ha, hb, hd⟩
      obtain ⟨hne, ha⟩ := (hin c').mp ha
      refine ⟨hne, ha, hb, ?_⟩
      cases h0 : isDead fs.dead c' i
      · rfl
      · rw [(hdd c' i).mpr ⟨hne, h0⟩] at hd; exact absurd hd (by simp)
    · rintro ⟨hne, ha, hb, hd⟩
      refine ⟨(hin c').mpr ⟨hne, ha⟩, hb, ?_⟩
      cases h0 : isDead fs'.dead c' i
      · rfl
      · rw [((hdd c' i).mp h0).2] at hd; exact absurd hd (by simp)
  have hr1 : ∀ kb e, fs'.win.get? kb = some e →
      fs.win.get? kb = some e ∨ ∃ i, (layout H kh files c)[i]? = some (kb, e) ∧ isDead fs.dead c i = false :=
    fun kb e he => by
      rw [fw] at he
      rcases (win_reclaim fs.dead c kb (ixs 0 (layout H kh files c)) fs.win).1 e he with h | ⟨⟨i, w⟩, hm, hd, rfl⟩
      · exact .inl h
      · exact .inr ⟨i, mem_ixs0.mp hm, hd⟩
  refine ⟨by rw [← hq]; exact h1, by rw [← hq]; exact h2, fun c' h => hC c' ((hin c').mp h).2,
    fun c' i w h hw => hD c' i w ((hin c').mp h).2 hw, fun c' i h => ?_, fun kb e he => ?_, fun u k => ?_,
    fun x => ?_, by rw [← hq]; exact drop_ok hO c⟩
  · obtain ⟨hne, h⟩ := (hdd c' i).mp h
    exact (hin c').mpr ⟨hne, hDI c' i h⟩
  · rcases he with he | he
    · rcases hr1 kb e he with he | ⟨i, hr, -⟩
      · exact hWf kb e (.inl he)
      · exact hD c i _ hc hr
    · exact hWf kb e (.inr (by rw [← fsg]; exact he))
  · obtain ⟨hW, hS, hN, hL, hU⟩ := hK u k
    have r2 := fun hn => (win_reclaim fs.dead c (skey u k) (ixs 0 (layout H kh files c)) fs.win).2 (by rw [← fw]; exact hn)
    refine ⟨fun e he => ?_, fun h e he => hS (r2 h).1 e (by rw [← fsg]; exact he), fun h hs => ?_,
      fun c' i e hl => hL c' i e ((hlive c' i _ e).mp hl).2, fun c' i e hl => ?_⟩
    · rcases hr1 _ e he with h | ⟨i, hr, hd⟩
      · exact hW e h
      · exact hL c i _ ⟨hc, hr, hd⟩
    · obtain ⟨hw, hx⟩ := r2 h
      rcases hN hw (by rw [← fsg]; exact hs) with h | ⟨c', i, hl⟩
      · exact .inl h
      · by_cases he : c = c'
        · subst he
          exact absurd rfl (hx (i, (skey u k, sget s u k)) (mem_ixs0.mpr hl.2.1) hl.2.2)
        · exact .inr ⟨c', i, (hlive c' i _ _).mpr ⟨he, hl⟩⟩
    · obtain ⟨hne, hl0⟩ := (hlive c' i _ e).mp hl
      obtain ⟨u1, u2, u3⟩ := hU c' i e hl0
      refine ⟨?_, by rw [fsg]; exact u2, fun c'' i'' e'' hl'' => u3 c'' i'' e'' ((hlive c'' i'' _ e'').mp hl'').2⟩
      cases hg : fs'.win.get? (skey u k) with
      | none => rfl
      | some e0 =>
        rcases hr1 _ e0 hg with h | ⟨i0, hr, hd⟩
        · rw [u1] at h; cases h
        · exact absurd (u3 c i0 e0 ⟨hc, hr, hd⟩).1 hne
  · rw [← hq]
    show (fs.dir.drop c).items.count x =
      (liveItems kh (fs.inst.erase c) (fs.dead.erase c) fs.dir.nb (layout H kh files)).count x
    rw [drop_count, live_erase hc (fun c' h => (hC c' h).1), hNc x]

/-! ## Well-formed entries -/

theorem rising_of_pairwise : ∀ {ps : List Posting}, ps.Pairwise (fun p q => p.seq < q.seq) → rising ps = true
  | [], _ => by simp [rising]
  | [_], _ => by simp [rising]
  | p :: q :: ps, h => by
    have h1 := List.pairwise_cons.mp h
    have ih := rising_of_pairwise h1.2
    simp only [rising, List.drop_one, List.tail_cons, List.zip_cons_cons, List.all_cons, Bool.and_eq_true,
      decide_eq_true_eq] at ih ⊢
    exact ⟨h1.1 q (List.mem_cons_self ..), ih⟩

theorem push_tail {H : Bytes → Bytes} (hH : ∀ x, (H x).length = digestBytes) : ∀ (ps : List Posting) (e : Entry),
    e.tail.length = digestBytes → (ps.foldl (Entry.push H) e).tail.length = digestBytes
  | [], _, h => h
  | p :: ps, e, h => push_tail hH ps _ (by unfold Entry.push; split <;> simp [h, hH])

/-- Every entry of the spec's index is `Entry.Wf`, so the store can encode it. -/
theorem entryOf_wf {H : Bytes → Bytes} (hH : ∀ x, (H x).length = digestBytes) (R : List Line) (k : Key) :
    (entryOf H R k).Wf := by
  obtain ⟨h1, h2⟩ := entryOf_count H R k
  refine ⟨by rw [h1, h2, List.length_take, Nat.min_comm], ?_, ?_⟩
  · exact push_tail hH _ _ (by simp [Entry.empty, zeroDigest])
  · rw [h2]; exact rising_of_pairwise ((pairwise_postingsFrom R 0).sublist (List.take_sublist ..))

/-! ## Sorting a window -/

theorem bytesLt_asymm : ∀ a b : Bytes, bytesLt a b = true → bytesLt b a = true → False
  | [], [], h, _ => by simp [bytesLt] at h
  | [], _ :: _, _, h => by simp [bytesLt] at h
  | _ :: _, [], h, _ => by simp [bytesLt] at h
  | x :: xs, y :: ys, h, h' => by
    simp only [bytesLt, Bool.or_eq_true, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at h h'
    rcases h with h | ⟨rfl, h⟩ <;> rcases h' with h' | ⟨e, h'⟩
    · have := UInt8.lt_iff_toNat_lt.mp h; have := UInt8.lt_iff_toNat_lt.mp h'; omega
    · subst e; have := UInt8.lt_iff_toNat_lt.mp h; omega
    · have := UInt8.lt_iff_toNat_lt.mp h'; omega
    · exact bytesLt_asymm xs ys h h'

theorem bytesLt_trans : ∀ a b c : Bytes, bytesLt a b = true → bytesLt b c = true → bytesLt a c = true
  | [], [], _, h, _ => by simp [bytesLt] at h
  | _ :: _, [], _, h, _ => by simp [bytesLt] at h
  | _, _ :: _, [], _, h => by simp [bytesLt] at h
  | [], _ :: _, _ :: _, _, _ => rfl
  | x :: xs, y :: ys, z :: zs, h1, h2 => by
    simp only [bytesLt, Bool.or_eq_true, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at h1 h2 ⊢
    rcases h1 with h1 | ⟨rfl, h1⟩ <;> rcases h2 with h2 | ⟨rfl, h2⟩
    · exact .inl (UInt8.lt_iff_toNat_lt.mpr
        (by have := UInt8.lt_iff_toNat_lt.mp h1; have := UInt8.lt_iff_toNat_lt.mp h2; omega))
    · exact .inl h1
    · exact .inl h2
    · exact .inr ⟨rfl, bytesLt_trans xs ys zs h1 h2⟩

theorem bytesLt_total : ∀ a b : Bytes, a ≠ b → bytesLt a b = true ∨ bytesLt b a = true
  | [], [], h => absurd rfl h
  | [], _ :: _, _ => .inl rfl
  | _ :: _, [], _ => .inr rfl
  | x :: xs, y :: ys, h => by
    simp only [bytesLt, Bool.or_eq_true, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq]
    rcases Nat.lt_trichotomy x.toNat y.toNat with hl | hl | hl
    · exact .inl (.inl (UInt8.lt_iff_toNat_lt.mpr hl))
    · have hx : x = y := UInt8.toNat_inj.mp hl
      subst hx
      rcases bytesLt_total xs ys (fun e => h (by rw [e])) with h' | h'
      · exact .inl (.inr ⟨rfl, h'⟩)
      · exact .inr (.inr ⟨rfl, h'⟩)
    · exact .inr (.inl (UInt8.lt_iff_toNat_lt.mpr hl))

theorem rowLt_asymm {kh : Bytes → UInt64} {a b : Bytes} (h : rowLt kh a b = true) (h' : rowLt kh b a = true) :
    False := by
  simp only [rowLt, Bool.or_eq_true, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at h h'
  rcases h with h | ⟨e, h⟩ <;> rcases h' with h' | ⟨e', h'⟩
  · have := UInt64.lt_iff_toNat_lt.mp h; have := UInt64.lt_iff_toNat_lt.mp h'; omega
  · rw [e'] at h; have := UInt64.lt_iff_toNat_lt.mp h; omega
  · rw [e] at h'; have := UInt64.lt_iff_toNat_lt.mp h'; omega
  · exact bytesLt_asymm a b h h'

theorem rowLt_trans {kh : Bytes → UInt64} {a b c : Bytes} (h1 : rowLt kh a b = true) (h2 : rowLt kh b c = true) :
    rowLt kh a c = true := by
  simp only [rowLt, Bool.or_eq_true, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at h1 h2 ⊢
  rcases h1 with h1 | ⟨e1, h1⟩ <;> rcases h2 with h2 | ⟨e2, h2⟩
  · exact .inl (UInt64.lt_iff_toNat_lt.mpr
      (by have := UInt64.lt_iff_toNat_lt.mp h1; have := UInt64.lt_iff_toNat_lt.mp h2; omega))
  · exact .inl (by rw [← e2]; exact h1)
  · exact .inl (by rw [e1]; exact h2)
  · exact .inr ⟨e1.trans e2, bytesLt_trans a b c h1 h2⟩

theorem rowLt_total {kh : Bytes → UInt64} {a b : Bytes} (h : a ≠ b) : rowLt kh a b = true ∨ rowLt kh b a = true := by
  simp only [rowLt, Bool.or_eq_true, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq]
  rcases Nat.lt_trichotomy (kh a).toNat (kh b).toNat with hl | hl | hl
  · exact .inl (.inl (UInt64.lt_iff_toNat_lt.mpr hl))
  · have e := UInt64.toNat_inj.mp hl
    rcases bytesLt_total a b h with h' | h'
    · exact .inl (.inr ⟨e, h'⟩)
    · exact .inr (.inr ⟨e.symm, h'⟩)
  · exact .inr (.inl (UInt64.lt_iff_toNat_lt.mpr hl))

theorem sortedB_of_pairwise {kh : Bytes → UInt64} :
    ∀ {ws : List Row}, ws.Pairwise (fun a b => rowLt kh a.1 b.1 = true) → sortedB kh ws = true
  | [], _ => rfl
  | [_], _ => rfl
  | a :: b :: ws, h => by
    have h1 := List.pairwise_cons.mp h
    simp only [sortedB, Bool.and_eq_true]
    exact ⟨h1.1 b (List.mem_cons_self ..), sortedB_of_pairwise h1.2⟩

/-- Rows of distinct keys sort strictly rising, as a chunk needs. -/
theorem sortRows_sorted (kh : Bytes → UInt64) {ws : List Row} (hd : ws.Pairwise (fun a b => a.1 ≠ b.1)) :
    sortedB kh (sortRows kh ws) = true := by
  unfold sortRows
  have hle := List.pairwise_mergeSort (le := fun a b : Row => !rowLt kh b.1 a.1)
    (fun a b c h1 h2 => by
      simp only [Bool.not_eq_eq_eq_not, Bool.not_true] at h1 h2 ⊢
      cases h3 : rowLt kh c.1 a.1
      · rfl
      · by_cases e : b.1 = a.1
        · rw [← e] at h3; rw [h3] at h2; cases h2
        · rcases rowLt_total (kh := kh) e with h4 | h4
          · rw [h4] at h1; cases h1
          · have := rowLt_trans h3 h4; rw [this] at h2; cases h2)
    (fun a b => by
      cases h1 : rowLt kh b.1 a.1 <;> cases h2 : rowLt kh a.1 b.1 <;> simp
      exact rowLt_asymm h1 h2) ws
  have hne := (List.mergeSort_perm ws fun a b : Row => !rowLt kh b.1 a.1).symm.pairwise hd (fun h e => h e.symm)
  refine sortedB_of_pairwise ((hle.and hne).imp fun {a b} ⟨h1, h2⟩ => ?_)
  rcases rowLt_total (kh := kh) h2 with h | h
  · exact h
  · simp [h] at h1

theorem mem_sortRows {kh : Bytes → UInt64} {m : HashMap Bytes Entry} {w : Row} :
    w ∈ sortRows kh m.toList ↔ m.get? w.1 = some w.2 := by
  rw [sortRows, (List.mergeSort_perm _ _).mem_iff, Std.HashMap.get?_eq_getElem?,
    ← Std.HashMap.mem_toList_iff_getElem?_eq_some]

theorem sortRows_distinct (m : HashMap Bytes Entry) :
    m.toList.Pairwise (fun a b => a.1 ≠ b.1) :=
  Std.HashMap.distinct_keys_toList.imp fun h e => by simp [e] at h

/-! ## Install -/

theorem freeNum_spec {inst : HashSet Nat} : ∀ (n c c' : Nat), freeNum inst n c = some c' →
    inst.contains c' = false ∧ c' < c + n
  | 0, _, _, h => by simp [freeNum] at h
  | n + 1, c, c', h => by
    unfold freeNum at h
    split at h
    · have := freeNum_spec n (c + 1) c' h; exact ⟨this.1, by omega⟩
    · rename_i hc; simp only [Option.some.injEq] at h; subst h; exact ⟨by simpa using hc, by omega⟩

theorem born_fold (win : HashMap Bytes Entry) (i : Nat) : ∀ (xs : List (Nat × Row)) (s0 : HashSet Nat),
    (xs.foldl (fun s iw => if win.contains iw.2.1 then s.insert iw.1 else s) s0).contains i = true ↔
      s0.contains i = true ∨ ∃ iw ∈ xs, win.contains iw.2.1 = true ∧ iw.1 = i
  | [], s0 => by simp
  | iw :: xs, s0 => by
    rw [List.foldl_cons, born_fold win i xs]
    by_cases hw : win.contains iw.2.1 = true
    · simp only [hw, ↓reduceIte, Std.HashSet.contains_insert, Bool.or_eq_true, beq_iff_eq, List.mem_cons,
        exists_eq_or_imp, true_and]
      constructor
      · rintro ((h | h) | h)
        · exact .inr (.inl h)
        · exact .inl h
        · exact .inr (.inr h)
      · rintro (h | h | h)
        · exact .inl (.inr h)
        · exact .inl (.inl h)
        · exact .inr h
    · simp only [hw, Bool.false_eq_true, ↓reduceIte, List.mem_cons, exists_eq_or_imp, false_and, false_or]

theorem bornDead_iff {win : HashMap Bytes Entry} {ws : List Row} {i : Nat} :
    (bornDead win ws).contains i = true ↔ ∃ w, ws[i]? = some w ∧ win.contains w.1 = true := by
  rw [bornDead, born_fold]
  constructor
  · rintro (h | ⟨⟨j, w⟩, hm, hw, rfl⟩)
    · simp at h
    · exact ⟨w, mem_ixs0.mp hm, hw⟩
  · rintro ⟨w, hw, hc⟩
    exact .inr ⟨(i, w), mem_ixs0.mpr hw, hc, rfl⟩

theorem contains_of_get? {m : HashMap Bytes Entry} {kb : Bytes} : m.contains kb = true ↔ m.get? kb ≠ none := by
  rw [Std.HashMap.contains_eq_isSome_getElem?, Std.HashMap.get?_eq_getElem?]
  cases m[kb]? <;> simp

/-- Rows of distinct keys: one key sits at one index. -/
private theorem idx_uniq {ws : List Row} (hd : ws.Pairwise (fun a b : Row => a.1 ≠ b.1)) {i j : Nat} {a b : Row}
    (hi : ws[i]? = some a) (hj : ws[j]? = some b) (e : a.1 = b.1) : i = j := by
  obtain ⟨hi', rfl⟩ := List.getElem?_eq_some_iff.mp hi
  obtain ⟨hj', rfl⟩ := List.getElem?_eq_some_iff.mp hj
  rcases Nat.lt_trichotomy i j with h | h | h
  · exact absurd e (List.pairwise_iff_getElem.mp hd i j hi' hj' h)
  · exact h
  · exact absurd e.symm (List.pairwise_iff_getElem.mp hd j i hj' hi' h)

theorem place_inv {H : Bytes → Bytes} {kh : Bytes → UInt64} {fs fs' : Fs} {files : Nat → Chunk} {s : St}
    {m : HashMap Bytes Entry} {c0 : Nat} {ws : List Row} (hI : FInv H kh fs files s) (hs : fs.sealing = some m)
    (hfree : fs.inst.contains c0 = false ∧ c0 < 2 ^ cBits) (hws : sortRows kh m.toList = ws)
    (hdec : decChunk H kh (encChunk H kh ws) = some ws)
    (hlay : ∀ c', layout H kh (fun j => if j = c0 then encChunk H kh ws else files j) c' =
      if c' = c0 then ws else layout H kh files c') (hp : place kh fs c0 ws = .ok fs') :
    FInv H kh fs' (fun j => if j = c0 then encChunk H kh ws else files j) s := by
  obtain ⟨h1, h2, hC, hD, hDI, hWf, hK, hNc, hO⟩ := hI
  have hmem : ∀ w, w ∈ ws ↔ sealGet fs w.1 = some w.2 := fun w => by
    rw [← hws, mem_sortRows]; simp [sealGet, hs]
  have hnd : ws.Pairwise (fun a b : Row => a.1 ≠ b.1) := by
    rw [← hws]; unfold sortRows
    exact (List.mergeSort_perm m.toList fun a b : Row => !rowLt kh b.1 a.1).symm.pairwise (sortRows_distinct m)
      (fun h e => h e.symm)
  cases hdir : (liveHashes kh (fs.dead.insert c0 (bornDead fs.win ws)) c0 ws).foldlM
      (fun (d : Dir) h => d.insert h c0) fs.dir with
  | error r => simp [place, hdir, Except.map] at hp
  | ok d0 =>
  simp only [place, hdir, Except.map, Except.ok.injEq] at hp
  obtain ⟨hdO, hdn, hdc⟩ := ins_count hfree.2 _ hO hdir
  have hq := hp
  have fin : ∀ c', fs'.inst.contains c' = true ↔ c0 = c' ∨ fs.inst.contains c' = true := fun c' => by
    rw [← hq]; simp [Std.HashSet.contains_insert]
  have fdd : ∀ c' i, isDead fs'.dead c' i =
      if c0 = c' then (bornDead fs.win ws).contains i else isDead fs.dead c' i := fun c' i => by
    rw [← hq]; unfold isDead; rw [Std.HashMap.get?_insert]; by_cases e : c0 = c' <;> simp [e]
  have fw : fs'.win = fs.win := by rw [← hq]
  have fsg : ∀ kb, sealGet fs' kb = none := fun kb => by rw [← hq]; rfl
  have hne : ∀ c', fs.inst.contains c' = true → c0 ≠ c' := fun c' h e => by
    subst e; rw [hfree.1] at h; cases h
  have hlive : ∀ c' i kb e,
      Live fs' (layout H kh (fun j => if j = c0 then encChunk H kh ws else files j)) c' i kb e ↔
      (c0 = c' ∧ ws[i]? = some (kb, e) ∧ (bornDead fs.win ws).contains i = false) ∨
        Live fs (layout H kh files) c' i kb e := by
    intro c' i kb e
    unfold Live
    rw [fin, fdd, hlay]
    by_cases e0 : c0 = c'
    · subst e0
      simp [hfree.1]
    · have e1 : c' ≠ c0 := Ne.symm e0
      simp [e0, e1]
  refine ⟨by rw [← hq]; exact h1, by rw [← hq]; exact h2, fun c' hc => ?_, fun c' i w hc hw => ?_,
    fun c' i hd' => ?_, fun kb e he => ?_, fun u k => ?_, fun x => ?_, by rw [← hq]; exact hdO⟩
  · rcases (fin c').mp hc with rfl | hc
    · exact ⟨hfree.2, by simp [hdec]⟩
    · have e1 : c' ≠ c0 := Ne.symm (hne c' hc)
      simpa [e1] using hC c' hc
  · rw [hlay] at hw
    rcases (fin c').mp hc with rfl | hc
    · simp only [↓reduceIte] at hw
      exact hWf w.1 w.2 (.inr ((hmem w).mp (List.mem_of_getElem? hw)))
    · have e1 : c' ≠ c0 := Ne.symm (hne c' hc)
      simp only [e1, ↓reduceIte] at hw
      exact hD c' i w hc hw
  · rw [fdd] at hd'
    refine (fin c').mpr ?_
    by_cases e0 : c0 = c'
    · exact .inl e0
    · simp only [e0, ↓reduceIte] at hd'; exact .inr (hDI c' i hd')
  · rcases he with he | he
    · exact hWf kb e (.inl (fw ▸ he))
    · rw [fsg] at he; cases he
  · obtain ⟨hW, hS, hN, hL, hU⟩ := hK u k
    have hwn : ∀ i e, ws[i]? = some (skey u k, e) → (bornDead fs.win ws).contains i = false →
        fs.win.get? (skey u k) = none := fun i e hi hb => by
      cases hg : fs.win.get? (skey u k) with
      | none => rfl
      | some _ =>
        have : (bornDead fs.win ws).contains i = true :=
          bornDead_iff.mpr ⟨_, hi, contains_of_get?.mpr (by rw [hg]; simp)⟩
        rw [this] at hb; cases hb
    refine ⟨fun e he => hW e (fw ▸ he), fun _ e he => ?_, fun hw _ => ?_, fun c' i e hl => ?_,
      fun c' i e hl => ?_⟩
    · rw [fsg] at he; cases he
    · rw [fw] at hw
      cases hsg : sealGet fs (skey u k) with
      | some e =>
        have he := hS hw e hsg
        obtain ⟨i, hi⟩ := List.mem_iff_getElem?.mp ((hmem (skey u k, e)).mpr hsg)
        have hb : (bornDead fs.win ws).contains i = false := by
          cases hb : (bornDead fs.win ws).contains i
          · rfl
          · obtain ⟨w, hw', hc⟩ := bornDead_iff.mp hb
            rw [hi] at hw'; cases hw'
            exact absurd hw (contains_of_get?.mp hc)
        exact .inr ⟨c0, i, (hlive c0 i _ _).mpr (.inl ⟨rfl, he ▸ hi, hb⟩)⟩
      | none =>
        rcases hN hw hsg with h | ⟨c', i, hl⟩
        · exact .inl h
        · exact .inr ⟨c', i, (hlive c' i _ _).mpr (.inr hl)⟩
    · rcases (hlive c' i _ e).mp hl with ⟨rfl, hi, hb⟩ | hl
      · exact hS (hwn i e hi hb) e ((hmem (skey u k, e)).mp (List.mem_of_getElem? hi))
      · exact hL c' i e hl
    · rw [fw, fsg]
      rcases (hlive c' i _ e).mp hl with ⟨rfl, hi, hb⟩ | hl0
      · have hse := (hmem (skey u k, e)).mp (List.mem_of_getElem? hi)
        refine ⟨hwn i e hi hb, rfl, fun c'' i'' e'' hl'' => ?_⟩
        rcases (hlive c'' i'' _ e'').mp hl'' with ⟨rfl, hi', -⟩ | hl''
        · exact ⟨rfl, idx_uniq hnd hi' hi rfl⟩
        · rw [(hU c'' i'' e'' hl'').2.1] at hse; cases hse
      · obtain ⟨u1, u2, u3⟩ := hU c' i e hl0
        refine ⟨u1, rfl, fun c'' i'' e'' hl'' => ?_⟩
        rcases (hlive c'' i'' _ e'').mp hl'' with ⟨rfl, hi', -⟩ | hl''
        · rw [(hmem (skey u k, e'')).mp (List.mem_of_getElem? hi')] at u2; cases u2
        · exact u3 c'' i'' e'' hl''
  · rw [← hq]
    show d0.items.count x = (liveItems kh (fs.inst.insert c0) (fs.dead.insert c0 (bornDead fs.win ws)) d0.nb
      (layout H kh (fun j => if j = c0 then encChunk H kh ws else files j))).count x
    rw [live_insert hfree.1 (fun c' e => by rw [hlay, if_neg e]), hlay, if_pos rfl, hdc x, hdn, hNc x]
    omega

/-- Growth keeps `FInv` (same state): the rebuilt directory keeps its shape (so its stash is within `stashCap`) and
    holds exactly one slot for each live row of every installed chunk. -/
theorem regrow_inv {H : Bytes → Bytes} {kh : Bytes → UInt64} {fs fs' : Fs} {files : Nat → Chunk} {s : St}
    (hI : FInv H kh fs files s) (hg : regrow kh fs (layout H kh files) = .ok fs') : FInv H kh fs' files s := by
  obtain ⟨h1, h2, hC, hD, hDI, hWf, hK, -, -⟩ := hI
  cases hr : Dir.rebuild (2 * fs.dir.nb + 1)
      (fs.inst.toList.map fun c => (c, liveHashes kh fs.dead c (layout H kh files c))) with
  | error r => simp [regrow, hr, Except.map] at hg
  | ok d =>
  simp only [regrow, hr, Except.map, Except.ok.injEq] at hg
  subst hg
  have hb : ∀ ch ∈ fs.inst.toList.map (fun c => (c, liveHashes kh fs.dead c (layout H kh files c))),
      ch.1 < 2 ^ cBits := by
    intro ch hch
    obtain ⟨c', hc', rfl⟩ := List.mem_map.mp hch
    exact (hC c' (Std.HashSet.mem_iff_contains.mp (Std.HashSet.mem_toList.mp hc'))).1
  obtain ⟨hdO, hdn, hdc⟩ := rebuild_inv (by omega) hb hr
  refine ⟨h1, h2, hC, hD, hDI, hWf, hK, fun x => (hdc x).trans ?_, hdO⟩
  rw [hdn]
  simp only [liveItems, List.flatMap_map]

/-- Growth changes no lookup of any key. -/
theorem regrow_lookup {H : Bytes → Bytes} {kh : Bytes → UInt64} {fs fs' : Fs} {files : Nat → Chunk} {s : St}
    (hI : FInv H kh fs files s) (hg : regrow kh fs (layout H kh files) = .ok fs') (u : Bool) (k : Key) :
    lookup kh fs' (layout H kh files) (skey u k) = lookup kh fs (layout H kh files) (skey u k) := by
  rw [lookup_eq (regrow_inv hI hg), lookup_eq hI]

theorem regrow_view {H : Bytes → Bytes} {kh : Bytes → UInt64} {fs fs' : Fs} {files : Nat → Chunk} {s : St}
    (hI : FInv H kh fs files s) (hg : regrow kh fs (layout H kh files) = .ok fs') :
    view kh fs' (layout H kh files) = view kh fs (layout H kh files) := by
  rw [view_eq (regrow_inv hI hg), view_eq hI]

/-- Loading what a commit point keeps (heads, installed chunks, dead bits; both windows empty) over the same chunk files
    keeps `FInv` for the same state, for any directory size: the directory is rebuilt from the live rows' key hashes. -/
theorem load_inv {H : Bytes → Bytes} {kh : Bytes → UInt64} {fs fs' : Fs} {files : Nat → Chunk} {s : St} {nb : Nat}
    (hI : FInv H kh fs files s) (hw : fs.win = ∅) (hs : fs.sealing = none) (h0 : 0 < nb)
    (hl : load kh nb fs.hr fs.hu fs.inst fs.dead (layout H kh files) = .ok fs') : FInv H kh fs' files s := by
  obtain ⟨h1, h2, hC, hD, hDI, hWf, hK, -, -⟩ := hI
  cases hr : Dir.rebuild nb (fs.inst.toList.map fun c => (c, liveHashes kh fs.dead c (layout H kh files c))) with
  | error r => simp [load, hr, Except.map] at hl
  | ok d =>
  simp only [load, hr, Except.map, Except.ok.injEq] at hl
  subst hl
  have he : (⟨fs.hr, fs.hu, d, fs.inst, fs.dead, ∅, none⟩ : Fs) = { fs with dir := d } := by
    cases fs with
    | mk a b c e f g k => simp only at hw hs; subst hw hs; rfl
  rw [he]
  have hb : ∀ ch ∈ fs.inst.toList.map (fun c => (c, liveHashes kh fs.dead c (layout H kh files c))),
      ch.1 < 2 ^ cBits := by
    intro ch hch
    obtain ⟨c', hc', rfl⟩ := List.mem_map.mp hch
    exact (hC c' (Std.HashSet.mem_iff_contains.mp (Std.HashSet.mem_toList.mp hc'))).1
  obtain ⟨hdO, hdn, hdc⟩ := rebuild_inv h0 hb hr
  refine ⟨h1, h2, hC, hD, hDI, hWf, hK, fun x => (hdc x).trans ?_, hdO⟩
  rw [hdn]
  simp only [liveItems, List.flatMap_map]

/-- Installing the sealed window keeps `FInv` (same state), with the returned chunk written at its number, whether or
    not the directory grows. -/
theorem install_inv {H : Bytes → Bytes} {kh : Bytes → UInt64} {fs fs' : Fs} {files : Nat → Chunk} {s : St}
    {c : Nat} {ch : Chunk} (hI : FInv H kh fs files s)
    (h : install H kh fs (layout H kh files) = .ok (fs', c, ch)) :
    FInv H kh fs' (fun j => if j = c then ch else files j) s := by
  cases hs : fs.sealing with
  | none => simp [install, hs] at h
  | some m =>
  cases hf : freeNum fs.inst (2 ^ cBits) 0 with
  | none => simp [install, hs, hf] at h
  | some c0 =>
  simp only [install, hs, hf] at h
  have hsorted := sortRows_sorted kh (sortRows_distinct m)
  generalize hws : sortRows kh m.toList = ws at h hsorted
  have hfree := freeNum_spec _ _ _ hf
  simp only [Nat.zero_add] at hfree
  have hmem : ∀ w, w ∈ ws ↔ sealGet fs w.1 = some w.2 := fun w => by
    rw [← hws, mem_sortRows]; simp [sealGet, hs]
  have hdec : decChunk H kh (encChunk H kh ws) = some ws :=
    decChunk_encChunk H kh ws hsorted (fun w hw => hI.2.2.2.2.2.1 w.1 w.2 (.inr ((hmem w).mp hw)))
  have hlay : ∀ c', layout H kh (fun j => if j = c0 then encChunk H kh ws else files j) c' =
      if c' = c0 then ws else layout H kh files c' := fun c' => by
    by_cases e : c' = c0 <;> simp [layout, e, hdec]
  have hP : ∀ g p, FInv H kh g files s → g.sealing = some m → g.inst = fs.inst → place kh g c0 ws = .ok p →
      FInv H kh p (fun j => if j = c0 then encChunk H kh ws else files j) s :=
    fun g p hg hgs hgi hp => place_inv hg hgs (by rw [hgi]; exact hfree) hws hdec hlay hp
  split at h
  · rename_i p hp
    simp only [Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl, rfl⟩ := h
    exact hP fs p hI hs rfl hp
  · split at h
    · rename_i g hg
      have hgf : g.sealing = fs.sealing ∧ g.inst = fs.inst := by
        cases hr : Dir.rebuild (2 * fs.dir.nb + 1)
            (fs.inst.toList.map fun c => (c, liveHashes kh fs.dead c (layout H kh files c))) with
        | error r => simp [regrow, hr, Except.map] at hg
        | ok d =>
          simp only [regrow, hr, Except.map, Except.ok.injEq] at hg
          subst hg; exact ⟨rfl, rfl⟩
      cases hp : place kh g c0 ws with
      | error r => simp [hp, Except.map] at h
      | ok p =>
        simp only [hp, Except.map, Except.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl, rfl⟩ := h
        exact hP g p (regrow_inv hI hg) (hgf.1.trans hs) hgf.2 hp
    · cases h

end BlindLedger.Gate.Flat.Store
