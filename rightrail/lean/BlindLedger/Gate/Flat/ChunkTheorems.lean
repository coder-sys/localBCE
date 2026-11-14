import BlindLedger.Gate.Flat.Chunk
import BlindLedger.Gate.Flat.Theorems

/-! Statements and proofs of the chunk format and the whole-state root (`Flat/Chunk.lean`): a sorted run of
    well-formed rows decodes from its chunk; a chunk decodes only from its canonical bytes; the tree a writer updates
    leaf by leaf always holds the root of its chunk map; equal roots mean equal chunk maps or a named SHA3-512
    collision.  Synthetic, nonpayment, non-PHI, activation=false. -/

namespace BlindLedger.Gate.Flat.Chunk

open BlindLedger.Gate.OnepIndex (leb unleb unleb_leb)

/-! ## Rows -/

theorem leb_length_pos (n : Nat) : 0 < (leb n).length := by
  have h := unleb_leb n []
  cases hl : leb n with
  | nil => rw [hl] at h; simp [unleb] at h
  | cons _ _ => simp

theorem decTail_enc (t r : Bytes) (h : t.length = digestBytes) : decTail (encTail t ++ r) = some (t, r) := by
  unfold encTail
  by_cases hz : t = zeroDigest
  · subst hz; simp [decTail]
  · simp [hz, decTail, takeN_app _ _ _ h]

theorem decBody_enc (w : Row) (hw : w.2.Wf) : decBody (encBody w) = some w := by
  obtain ⟨k, c, hd, t⟩ := w
  obtain ⟨h1, h2, h3⟩ := hw
  simp only at h1 h2 h3
  have hk : takeN k.length (k ++ (leb c ++ (leb hd.length ++ (hd.flatMap encPosting ++ encTail t)))) =
      some (k, leb c ++ (leb hd.length ++ (hd.flatMap encPosting ++ encTail t))) := takeN_app _ _ _ rfl
  have hp := decPostings_enc hd (encTail t)
  have ht := decTail_enc t [] h2
  simp only [List.append_nil] at ht
  simp [decBody, encBody, List.append_assoc, unleb_leb, hk, hp, ht, h3]
  exact h1

theorem encRow_length_pos (w : Row) : 0 < (encRow w).length := by
  simp only [encRow, List.length_append]; have := leb_length_pos (encBody w).length; omega

theorem rows_length_le (ws : List Row) : ws.length ≤ (ws.flatMap encRow).length := by
  induction ws with
  | nil => simp
  | cons w ws ih => simp only [List.flatMap_cons, List.length_append, List.length_cons]; have := encRow_length_pos w; omega

theorem decRows_enc : ∀ (ws : List Row) (r : Bytes) (f : Nat), ws.length < f → (∀ w ∈ ws, w.2.Wf) →
    decRows f (ws.flatMap encRow ++ leb 0 ++ r) = some ws
  | [], r, f + 1, _, _ => by simp [decRows, unleb_leb]
  | w :: ws, r, f + 1, hf, hw => by
    have hb : 0 < (encBody w).length := by
      simp only [encBody, List.length_append]; have := leb_length_pos w.1.length; omega
    have ht : takeN (encBody w).length (encBody w ++ (ws.flatMap encRow ++ leb 0 ++ r)) =
        some (encBody w, ws.flatMap encRow ++ leb 0 ++ r) := takeN_app _ _ _ rfl
    have ih := decRows_enc ws r f (by simp at hf; omega) (fun x hx => hw x (List.mem_cons_of_mem _ hx))
    simp only [List.flatMap_cons, encRow, List.append_assoc] at ht ih ⊢
    simp [decRows, unleb_leb, Nat.pos_iff_ne_zero.mp hb, ht, decBody_enc w (hw w (List.mem_cons_self ..)), ih]
  | _ :: _, _, 0, hf, _ => by simp at hf

/-! ## Pages -/

theorem pagesN_flatten : ∀ (f : Nat) (d : Bytes), d.length ≤ f → ∃ z, (pagesN f d).flatten = d ++ List.replicate z 0
  | 0, d, h => ⟨0, by simp at h; simp [pagesN, h]⟩
  | f + 1, d, h => by
    by_cases he : d.isEmpty
    · exact ⟨0, by simp [pagesN, List.isEmpty_iff.mp he]⟩
    · have hl : 0 < d.length := by cases d <;> simp_all
      obtain ⟨z, hz⟩ := pagesN_flatten f (d.drop pageSize) (by rw [List.length_drop]; simp only [pageSize]; omega)
      simp only [pagesN, he, Bool.false_eq_true, ↓reduceIte, List.flatten_cons, hz]
      by_cases hs : pageSize ≤ d.length
      · refine ⟨z, ?_⟩
        rw [show pageSize - d.length = 0 by omega, List.replicate_zero, List.append_nil, ← List.append_assoc,
          List.take_append_drop]
      · refine ⟨pageSize - d.length + z, ?_⟩
        rw [List.take_of_length_le (by omega), List.drop_of_length_le (by omega), List.nil_append,
          List.append_assoc, List.replicate_append_replicate]

/-! ## Chunks -/

/-- A sorted run of well-formed rows decodes from its chunk. -/
theorem decChunk_encChunk (H : Bytes → Bytes) (kh : Bytes → UInt64) (ws : List Row) (hs : sortedB kh ws = true)
    (hw : ∀ w ∈ ws, w.2.Wf) : decChunk H kh (encChunk H kh ws) = some ws := by
  obtain ⟨z, hz⟩ := pagesN_flatten (encData ws).length (encData ws) (Nat.le_refl _)
  have hlt : ws.length < (encData ws ++ List.replicate z 0).length := by
    have h1 := rows_length_le ws; have h2 := leb_length_pos 0
    simp only [encData, List.length_append]; omega
  have hd : decRows (encData ws ++ List.replicate z 0).length (encData ws ++ List.replicate z 0) = some ws :=
    decRows_enc ws (List.replicate z 0) _ hlt hw
  simp only [decChunk, encChunk, pagesOf, hz]
  rw [hd]
  simp [hs]

/-- A chunk decodes only from the canonical bytes of its rows, and those rows are sorted. -/
theorem decChunk_canon {H : Bytes → Bytes} {kh : Bytes → UInt64} {c : Chunk} {ws : List Row}
    (h : decChunk H kh c = some ws) : c = encChunk H kh ws ∧ sortedB kh ws = true := by
  simp only [decChunk, bind, Option.bind] at h
  split at h
  · simp at h
  · rename_i ws' _
    by_cases hc : sortedB kh ws' = true ∧ encChunk H kh ws' = c
    · simp [hc] at h; subst h; exact ⟨hc.2.symm, hc.1⟩
    · simp only [Bool.and_eq_true, decide_eq_true_eq] at h; simp [hc] at h

theorem decPostings_length : ∀ (n : Nat) (r : Bytes) {ps : List Posting} {r' : Bytes},
    decPostings n r = some (ps, r') → ps.length = n
  | 0, _, _, _, h => by simp [decPostings] at h; obtain ⟨rfl, rfl⟩ := h; rfl
  | n + 1, r, ps, r', h => by
    rcases h1 : unleb r with _ | ⟨s, r1⟩
    · simp [decPostings, h1] at h
    rcases h2 : decLine r1 with _ | ⟨l, r2⟩
    · simp [decPostings, h1, h2] at h
    rcases h3 : decPostings n r2 with _ | ⟨ps', r3⟩
    · simp [decPostings, h1, h2, h3] at h
    simp [decPostings, h1, h2, h3] at h
    obtain ⟨rfl, rfl⟩ := h
    simp [decPostings_length n r2 h3]

theorem decTail_length {r t r' : Bytes} (h : decTail r = some (t, r')) : t.length = digestBytes := by
  cases r with
  | nil => simp [decTail] at h
  | cons f r =>
    simp only [decTail] at h
    by_cases h0 : f = 0
    · rw [if_pos h0] at h; obtain ⟨rfl, -⟩ := Prod.mk.inj (Option.some.inj h); simp [zeroDigest]
    · rw [if_neg h0] at h
      by_cases h1 : f = 1
      · rw [if_pos h1] at h
        unfold takeN at h
        by_cases hle : digestBytes ≤ r.length
        · rw [if_pos hle] at h
          obtain ⟨rfl, -⟩ := Prod.mk.inj (Option.some.inj h)
          rw [List.length_take]; exact Nat.min_eq_left hle
        · rw [if_neg hle] at h; cases h
      · rw [if_neg h1] at h; cases h

theorem decBody_wf {bs : Bytes} {w : Row} (h : decBody bs = some w) : w.2.Wf := by
  rcases h1 : unleb bs with _ | ⟨kl, r1⟩
  · simp [decBody, h1] at h
  rcases h2 : takeN kl r1 with _ | ⟨k, r2⟩
  · simp [decBody, h1, h2] at h
  rcases h3 : unleb r2 with _ | ⟨c, r3⟩
  · simp [decBody, h1, h2, h3] at h
  rcases h4 : unleb r3 with _ | ⟨n, r4⟩
  · simp [decBody, h1, h2, h3, h4] at h
  rcases h5 : decPostings n r4 with _ | ⟨ps, r5⟩
  · simp [decBody, h1, h2, h3, h4, h5] at h
  rcases h6 : decTail r5 with _ | ⟨t, r6⟩
  · simp [decBody, h1, h2, h3, h4, h5, h6] at h
  have hl := decPostings_length n r4 h5
  have ht := decTail_length h6
  simp [decBody, h1, h2, h3, h4, h5, h6] at h
  obtain ⟨hc, rfl⟩ := h
  refine ⟨?_, ht, ?_⟩ <;> simp_all

theorem decRows_wf : ∀ (f : Nat) (bs : Bytes) {ws : List Row}, decRows f bs = some ws → ∀ w ∈ ws, w.2.Wf
  | 0, _, _, h => by simp [decRows] at h
  | f + 1, bs, ws, h => by
    rcases h1 : unleb bs with _ | ⟨l, r⟩
    · simp [decRows, h1] at h
    by_cases hl : l = 0
    · simp [decRows, h1, hl] at h; subst h; simp
    rcases h2 : takeN l r with _ | ⟨b, r2⟩
    · simp [decRows, h1, hl, h2] at h
    rcases h3 : decBody b with _ | w0
    · simp [decRows, h1, hl, h2, h3] at h
    rcases h4 : decRows f r2 with _ | ws'
    · simp [decRows, h1, hl, h2, h3, h4] at h
    simp [decRows, h1, hl, h2, h3, h4] at h
    subst h
    intro w hw
    rcases List.mem_cons.mp hw with rfl | hw
    · exact decBody_wf h3
    · exact decRows_wf f r2 h4 w hw

/-- Every row a chunk decodes to holds an `Entry.Wf` entry (load relies on it). -/
theorem decChunk_wf {H : Bytes → Bytes} {kh : Bytes → UInt64} {c : Chunk} {ws : List Row}
    (h : decChunk H kh c = some ws) : ∀ w ∈ ws, w.2.Wf := by
  simp only [decChunk, bind, Option.bind] at h
  split at h
  · simp at h
  · rename_i ws' hd
    by_cases hc : sortedB kh ws' = true ∧ encChunk H kh ws' = c
    · simp [hc] at h; subst h; exact decRows_wf _ _ hd
    · simp only [Bool.and_eq_true, decide_eq_true_eq] at h; simp [hc] at h

/-! ## The whole-state root -/

def TreeInv (H : Bytes → Bytes) (t : Tree) (m : Nat → Option Bytes) : Prop :=
  ∀ l i, l ≤ depth → t.get l i = nodeSpec H m l i

theorem emptyAt_spec (H : Bytes → Bytes) : ∀ l i, nodeSpec H (fun _ => none) l i = emptyAt H l
  | 0, _ => rfl
  | l + 1, i => by simp [nodeSpec, emptyAt, emptyAt_spec H l]

theorem empty_inv (H : Bytes → Bytes) : TreeInv H (Tree.empty H) (fun _ => none) := by
  intro l i hl
  simp [Tree.get, Tree.empty, emptyAt_spec, Array.getD_eq_getD_getElem?, List.getElem?_range (Nat.lt_succ_of_le hl)]

theorem get_put (t : Tree) (l i : Nat) (x : Bytes) (l' i' : Nat) :
    (t.put l i x).get l' i' = if l = l' ∧ i = i' then x else t.get l' i' := by
  simp only [Tree.put, Tree.get, Std.HashMap.getD_insert, beq_iff_eq, Prod.mk.injEq]

theorem div_pow_succ (i l : Nat) : i / 2 ^ (l + 1) = i / 2 ^ l / 2 := by
  rw [Nat.pow_succ, Nat.div_div_eq_div_mul]

/-- Node `j` of level `l` reads only the leaves below it. -/
theorem nodeSpec_upd (H : Bytes → Bytes) (m : Nat → Option Bytes) (i : Nat) (v : Option Bytes) :
    ∀ l j, i / 2 ^ l ≠ j → nodeSpec H (upd m i v) l j = nodeSpec H m l j
  | 0, j, h => by simp at h; simp [nodeSpec, upd, Ne.symm h]
  | l + 1, j, h => by
    rw [div_pow_succ] at h
    simp only [nodeSpec]
    rw [nodeSpec_upd H m i v l (2 * j) (by omega), nodeSpec_upd H m i v l (2 * j + 1) (by omega)]

theorem up_inv (H : Bytes → Bytes) (m : Nat → Option Bytes) (i : Nat) (v : Option Bytes) :
    ∀ k (t : Tree) l, l + k = depth →
      (∀ l' x, l' ≤ l → t.get l' x = nodeSpec H (upd m i v) l' x) →
      (∀ l' x, l < l' → l' ≤ depth → t.get l' x = nodeSpec H m l' x) →
      TreeInv H (t.up H k l (i / 2 ^ l)) (upd m i v)
  | 0, t, l, hk, hlo, _ => fun l' x hl' => by simp only [Tree.up]; exact hlo l' x (by omega)
  | k + 1, t, l, hk, hlo, hhi => by
    simp only [Tree.up]
    rw [← div_pow_succ]
    refine up_inv H m i v k _ (l + 1) (by omega) ?_ ?_
    · intro l' x hl'
      rw [get_put]
      by_cases hx : l + 1 = l' ∧ i / 2 ^ (l + 1) = x
      · obtain ⟨rfl, rfl⟩ := hx
        simp only [and_self, ↓reduceIte, nodeSpec]
        rw [hlo l _ (Nat.le_refl _), hlo l _ (Nat.le_refl _)]
      · rw [if_neg hx]
        by_cases hl : l' ≤ l
        · exact hlo l' x hl
        · have he : l' = l + 1 := by omega
          subst he
          rw [hhi (l + 1) x (by omega) (by omega), nodeSpec_upd H m i v (l + 1) x (fun h => hx ⟨rfl, h⟩)]
    · intro l' x hl' hd
      rw [get_put, if_neg (by omega)]
      exact hhi l' x (by omega) hd

theorem set_up {H : Bytes → Bytes} {t : Tree} {m : Nat → Option Bytes} (hI : TreeInv H t m) (i : Nat)
    (v : Option Bytes) : TreeInv H (Tree.up H (t.put 0 i (leafH H v)) depth 0 i) (upd m i v) := by
  have h := up_inv H m i v depth (t.put 0 i (leafH H v)) 0 (by simp)
  simp only [Nat.pow_zero, Nat.div_one] at h
  refine h ?_ ?_
  · intro l' x hl'
    have : l' = 0 := by omega
    subst this
    rw [get_put]
    by_cases hx : i = x
    · subst hx; simp [nodeSpec, upd]
    · simp only [true_and, hx, ↓reduceIte]
      rw [hI 0 x (Nat.zero_le _)]
      simp [nodeSpec, upd, Ne.symm hx]
  · intro l' x hl' hd
    rw [get_put, if_neg (by omega)]
    exact hI l' x hd

/-- Setting one leaf keeps the tree equal to the root map with that leaf changed; it succeeds only for a leaf the
    root covers. -/
theorem set_inv {H : Bytes → Bytes} {t t' : Tree} {m : Nat → Option Bytes} {i : Nat} {v : Option Bytes}
    (hI : TreeInv H t m) (hs : t.set H i v = some t') : TreeInv H t' (upd m i v) ∧ i < 2 ^ depth := by
  unfold Tree.set at hs
  split at hs
  · rename_i hi
    simp only [Option.some.injEq] at hs
    subst hs
    exact ⟨set_up hI i v, hi⟩
  · simp at hs

theorem root_eq {H : Bytes → Bytes} {t : Tree} {m : Nat → Option Bytes} (hI : TreeInv H t m) :
    t.root = rootB H m := hI depth 0 (Nat.le_refl _)

/-- The root after one leaf is set is the root over the leaves with that leaf changed: the engine keeps the tree and
    updates one path instead of rebuilding. -/
theorem treeUpd_root {H : Bytes → Bytes} {t t' : Tree} {m : Nat → Option Bytes} {i : Nat} {v : Option Bytes}
    (hI : TreeInv H t m) (hs : t.set H i v = some t') : t'.root = rootB H (upd m i v) :=
  root_eq (set_inv hI hs).1

theorem foldSet_none {H : Bytes → Bytes} (xs : List (Nat × Bytes)) :
    xs.foldl (fun (r : Option Tree) (x : Nat × Bytes) => r.bind fun (t : Tree) => t.set H x.1 (some x.2)) none = none := by
  induction xs with
  | nil => rfl
  | cons y ys ih => simpa [List.foldl] using ih

/-- A tree built by setting a list of leaves in turn, as a load does, holds the root map with those leaves set. -/
theorem foldSet_inv {H : Bytes → Bytes} :
    ∀ (xs : List (Nat × Bytes)) {t t' : Tree} {m : Nat → Option Bytes}, TreeInv H t m →
      xs.foldl (fun (r : Option Tree) (x : Nat × Bytes) => r.bind fun (t : Tree) => t.set H x.1 (some x.2)) (some t) = some t' →
      TreeInv H t' (xs.foldl (fun m x => upd m x.1 (some x.2)) m)
  | [], _, _, _, hI, h => by simp only [List.foldl, Option.some.injEq] at h; subst h; exact hI
  | x :: xs, t, t', m, hI, h => by
    simp only [List.foldl, Option.bind_some] at h ⊢
    cases hs : t.set H x.1 (some x.2) with
    | none =>
      rw [hs] at h; rw [foldSet_none] at h; simp at h
    | some t1 =>
      rw [hs] at h
      exact foldSet_inv xs (set_inv hI hs).1 h

theorem nodeSpec_length {H : Bytes → Bytes} (hH : ∀ x, (H x).length = digestBytes) (m : Nat → Option Bytes) :
    ∀ l j, (nodeSpec H m l j).length = digestBytes
  | 0, j => by simp only [nodeSpec, leafH]; split <;> exact hH _
  | _ + 1, _ => hH _

theorem nodeSpec_binds {H : Bytes → Bytes} (hH : ∀ x, (H x).length = digestBytes) (m m' : Nat → Option Bytes) :
    ∀ l j, nodeSpec H m l j = nodeSpec H m' l j →
      (∀ i, i / 2 ^ l = j → m i = m' i) ∨ ∃ x y, x ≠ y ∧ H x = H y
  | 0, j, h => by
    by_cases hc : ∃ x y, x ≠ y ∧ H x = H y
    · exact .inr hc
    · refine .inl fun i hi => ?_
      simp only [Nat.pow_zero, Nat.div_one] at hi; subst hi
      have hin : ∀ x y, H x = H y → x = y := fun x y hxy =>
        Classical.byContradiction fun hne => hc ⟨x, y, hne, hxy⟩
      simp only [nodeSpec] at h
      cases hm : m i <;> cases hm' : m' i <;> rw [hm, hm'] at h <;> simp only [leafH] at h <;>
        have he := hin _ _ h <;> simp_all
  | l + 1, j, h => by
    simp only [nodeSpec, nodeH] at h
    by_cases hc : ∃ x y, x ≠ y ∧ H x = H y
    · exact .inr hc
    · have hin : ∀ x y, H x = H y → x = y := fun x y hxy =>
        Classical.byContradiction fun hne => hc ⟨x, y, hne, hxy⟩
      have he := hin _ _ h
      simp only [List.append_assoc, List.append_cancel_left_eq] at he
      obtain ⟨ha, hb⟩ := List.append_inj he (by rw [nodeSpec_length hH, nodeSpec_length hH])
      rcases nodeSpec_binds hH m m' l (2 * j) ha with hA | hA
      · rcases nodeSpec_binds hH m m' l (2 * j + 1) hb with hB | hB
        · refine .inl fun i hi => ?_
          rw [div_pow_succ] at hi
          by_cases hq : i / 2 ^ l = 2 * j
          · exact hA i hq
          · exact hB i (by omega)
        · exact .inr hB
      · exact .inr hA

/-- Equal whole-state roots mean equal chunk maps, unless the hash has a collision (named inputs). -/
theorem root_binds {H : Bytes → Bytes} (hH : ∀ x, (H x).length = digestBytes) {m m' : Nat → Option Bytes}
    (h : rootB H m = rootB H m') : (∀ i < 2 ^ depth, m i = m' i) ∨ ∃ x y, x ≠ y ∧ H x = H y := by
  rcases nodeSpec_binds hH m m' depth 0 h with h1 | h1
  · exact .inl fun i hi => h1 i (Nat.div_eq_of_lt hi)
  · exact .inr h1

end BlindLedger.Gate.Flat.Chunk
