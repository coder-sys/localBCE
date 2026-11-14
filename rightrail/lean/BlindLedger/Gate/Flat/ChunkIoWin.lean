import BlindLedger.Gate.Flat.ChunkIoEq
import BlindLedger.Gate.Flat.StoreIndex

namespace BlindLedger.Gate.Flat.ChunkIo

open Chunk Store
open BlindLedger.Gate.OnepIndex (leb unleb unleb_leb)

/-! ## The binary search -/

theorem partGo_eq {α : Type} [Inhabited α] (a : Array α) (p : α → Bool) (k : Nat) (hk : k ≤ a.size)
    (h1 : ∀ i, i < k → p a[i]! = true) (h2 : ∀ i, k ≤ i → i < a.size → p a[i]! = false) :
    ∀ f lo hi, hi - lo ≤ f → lo ≤ k → k ≤ hi → hi ≤ a.size → partGo a p f lo hi = k := by
  intro f
  induction f with
  | zero => intro lo hi hn hlk hkh _; simp only [partGo]; omega
  | succ f ih =>
    intro lo hi hn hlk hkh hha
    simp only [partGo]
    by_cases hlt : lo < hi
    · simp only [hlt, if_true]
      by_cases hp : p a[(lo + hi) / 2]! = true
      · have hm : (lo + hi) / 2 < k := Nat.lt_of_not_ge fun hc => by
          have := h2 _ (by omega) (by omega)
          simp [this] at hp
        simp only [hp, if_true]
        exact ih _ _ (by omega) (by omega) hkh hha
      · have hm : k ≤ (lo + hi) / 2 := Nat.le_of_not_lt fun hc => hp (h1 _ hc)
        simp only [hp, if_false]
        exact ih _ _ (by omega) hlk (by omega) (by omega)
    · simp only [hlt, if_false]; omega

theorem partPoint_eq {α : Type} [Inhabited α] (a : Array α) (p : α → Bool) (k : Nat) (hk : k ≤ a.size)
    (h1 : ∀ i, i < k → p a[i]! = true) (h2 : ∀ i, k ≤ i → i < a.size → p a[i]! = false) :
    partPoint a p = k :=
  partGo_eq a p k hk h1 h2 _ 0 a.size (by omega) (Nat.zero_le _) hk (Nat.le_refl _)

/-! ## The index the encoder builds -/

/-- The index entry of row `j`: its page, key hash, offset in the page, number and `fresh` flag. -/
def Eix (kh : Bytes → UInt64) (ws : List Row) (j : Nat) : Ix :=
  ⟨off ws j / pageSize, hashAt kh ws j, off ws j % pageSize, j, fresh kh ws j⟩

theorem mk_ix (kh : Bytes → UInt64) (ws : List Row) (offs khs : Array Nat) (first : Array (Option Nat))
    (rowsIn : Array Nat) (np : Nat)
    (hoff : ∀ j, j < ws.length → offs[j]! = off ws j) (hkh : ∀ j, khs[j]! = hashAt kh ws j)
    (hfirst : ∀ p, p < np → first[p]! = (List.range ws.length).find? (fun j => offs[j]! / pageSize == p)) :
    ∀ m, m ≤ np → (mkRun offs khs first rowsIn np m).2.1.toList =
      (List.range m).filterMap (fun p => ((pidx ws).find? (fun x => off ws x / pageSize == p)).map (Eix kh ws)) := by
  have hf : ∀ p, p < np → first[p]! = (List.range ws.length).find? (fun j => off ws j / pageSize == p) := by
    intro p hp
    rw [hfirst p hp]
    apply find?_range_congr
    intro j hj
    rw [hoff j hj]
  intro m
  induction m with
  | zero => intro _; simp [mkRun]
  | succ m ih =>
    intro hm
    have e : mkRun offs khs first rowsIn np (m + 1) = mkStep offs khs first rowsIn (mkRun offs khs first rowsIn np m) m := by
      simp [mkRun, List.range_succ, List.foldl_append]
    rw [e, List.range_succ, List.filterMap_append, ← ih (by omega)]
    unfold mkStep
    rw [hf m (by omega), ← pidx_find ws m]
    cases hfd : (pidx ws).find? (fun x => off ws x / pageSize == m) with
    | none => simp [hfd]
    | some j =>
      have hj := hfd
      rw [pidx_find, List.find?_range_eq_some] at hj
      obtain ⟨-, hjm, -⟩ := hj
      have hjl := List.mem_range.mp hjm
      simp only [List.filterMap_cons, List.filterMap_nil, Array.toList_push]
      have h1 : Ix.mk m khs[j]! (offs[j]! % pageSize) j (j == 0 || khs[j - 1]! != khs[j]!) = Eix kh ws j := by
        have hq := List.find?_some hfd
        simp only [beq_iff_eq] at hq
        simp only [Eix, fresh, hkh, hoff j hjl, hq]
      rw [h1]
      simp [hfd]

theorem Q_ix {ws : List Row} {A : ByteArray × Array Nat × Array Nat} {np : Nat} (h : QH ws A np) :
    (qMK ws A np).2.1.toList = (pidx ws).map (Eix kh ws) := by
  obtain ⟨hL, hsz, hnp⟩ := Q_np h
  have hps : pageSize = 4096 := rfl
  have hoff : ∀ j, j < ws.length → A.2.1[j]! = off ws j := by
    intro j hj
    rw [arr_getBang_opt _ _ h.h2 j]
    simp [hj]
  have hkh : ∀ j, A.2.2[j]! = hashAt kh ws j := by
    intro j
    rw [arr_getBang_opt _ _ h.h3 j]
    simp [hashAt, List.getElem?_map]
  have hn : ∀ j, j < ws.length → A.2.1[j]! / pageSize < np := by
    intro j hj
    rw [hoff j hj]
    have h1 : off ws j ≤ (ws.flatMap encRow).length := by
      rw [← off_len]; exact off_mono ws (by omega)
    rw [hps, hnp]
    omega
  obtain ⟨-, -, hf, -⟩ := fm_fold A.2.1 ws.length np hn ws.length (Nat.le_refl _)
  unfold qMK
  rw [mk_ix kh ws A.2.1 A.2.2 (fmRun A.2.1 np ws.length).1 (fmRun A.2.1 np ws.length).2 np hoff hkh hf np
    (Nat.le_refl _), List.range_eq_range']
  exact fm_find _ _ _ 0 _ (pidx_pages ws) fun x hx => ⟨Nat.zero_le _, by
    have h1 : off ws x ≤ (ws.flatMap encRow).length := by
      rw [← off_len]; exact off_mono ws (Nat.le_of_lt (pidx_lt hx))
    rw [Nat.zero_add, hps, hnp]
    omega⟩

theorem encFast_ix (ws : List Row) : (encFast ws).ix.toList = (pidx ws).map (Eix kh ws) := by
  rw [encFast_eq_P, encFastP_eq_Q]
  exact Q_ix (encFast_QH ws)

/-! ## The window -/

theorem pidx_inc (ws : List Row) : (pidx ws).Pairwise (· < ·) := by
  unfold pidx
  exact List.Pairwise.filter _ (List.pairwise_lt_range (n := ws.length))

theorem exist_cut (f : Nat → Nat) (h : Nat) : ∀ n, (∀ i j, i ≤ j → j < n → f i ≤ f j) →
    ∃ k, k ≤ n ∧ (∀ i, i < k → f i < h) ∧ (∀ i, k ≤ i → i < n → h ≤ f i)
  | 0, _ => ⟨0, Nat.le_refl _, fun _ hi => absurd hi (Nat.not_lt_zero _),
      fun _ _ hi => absurd hi (Nat.not_lt_zero _)⟩
  | n + 1, hm => by
    obtain ⟨k, hk, h1, h2⟩ := exist_cut f h n (fun i j hij hj => hm i j hij (by omega))
    by_cases hkn : k < n
    · refine ⟨k, by omega, h1, fun i hi hin => ?_⟩
      by_cases hin' : i < n
      · exact h2 i hi hin'
      · have e : i = n := by omega
        rw [e]
        exact Nat.le_trans (h2 k (Nat.le_refl _) hkn) (hm k n (by omega) (by omega))
    · by_cases hf : f n < h
      · refine ⟨n + 1, Nat.le_refl _, fun i hi => ?_, fun i hi hin => absurd hin (by omega)⟩
        by_cases hik : i < n
        · exact h1 i (by omega)
        · have e : i = n := by omega
          rw [e]; exact hf
      · refine ⟨n, by omega, fun i hi => h1 i (by omega), fun i hi hin => ?_⟩
        have e : i = n := by omega
        rw [e]; exact Nat.le_of_not_lt hf

theorem foldl_max_eq (l : List Nat) (t : Nat) (h1 : t = 0 ∨ t ∈ l) (h2 : ∀ x ∈ l, x ≤ t) :
    l.foldl max 0 = t := by
  obtain ⟨g1, g2⟩ := foldl_max_ge l 0
  apply Nat.le_antisymm
  · rcases foldl_max_mem l 0 with e | e
    · omega
    · exact h2 _ e
  · rcases h1 with e | e
    · omega
    · exact g2 t e

theorem foldl_min_eq (l : List Nat) (L t : Nat) (h1 : t = L ∨ t ∈ l) (h2 : ∀ x ∈ l, t ≤ x) (h3 : t ≤ L) :
    l.foldl min L = t := by
  obtain ⟨g1, g2⟩ := foldl_min_le l L
  apply Nat.le_antisymm
  · rcases h1 with e | e
    · omega
    · exact g2 t e
  · rcases foldl_min_mem l L with e | e
    · omega
    · exact h2 _ e

theorem loQ_fresh {kh : Bytes → UInt64} {ws : List Row} {h j : Nat} (e : hashAt kh ws j = h) :
    loQ kh ws h j = fresh kh ws j := by
  simp [loQ, fresh, e]

theorem window_ix (kh : Bytes → UInt64) {ws : List Row} (hs : sortedB kh ws = true) (m : CMetaR)
    (hix : m.ix.toList = (pidx ws).map (Eix kh ws)) (hn : m.nrows = ws.length)
    (hrb : m.rowBytes = off ws ws.length) (h : Nat) :
    m.window h = (loIx kh ws h, off ws (loIx kh ws h), hiIx kh ws h, off ws (hiIx kh ws h)) := by
  by_cases hw : ws = []
  · subst hw
    have hsz : m.ix.size = 0 := by rw [← Array.length_toList, hix]; simp [pidx]
    have e : m.ix = #[] := Array.eq_empty_of_size_eq_zero hsz
    have hp : ∀ p : Ix → Bool, partPoint (#[] : Array Ix) p = 0 := fun p =>
      partPoint_eq _ p 0 (by simp) (fun i hi => absurd hi (Nat.not_lt_zero _)) (fun i _ hi => absurd hi (by simp))
    unfold CMetaR.window
    rw [e]
    simp only [hp]
    simp [pidx, off, loIx, hiIx, hn, hrb]
    exact ⟨rfl, Nat.zero_mul _, rfl⟩
  · have hn0 : 0 ∈ pidx ws := by
      unfold pidx
      rw [List.mem_filter, List.mem_range]
      exact ⟨Nat.pos_of_ne_zero fun e => hw (List.eq_nil_of_length_eq_zero e), by simp⟩
    have hinc := pidx_inc ws
    have hlenws : ∀ x ∈ pidx ws, x < ws.length := fun x hx => pidx_lt hx
    generalize hps : pidx ws = ps at *
    have hsz : m.ix.size = ps.length := by rw [← Array.length_toList, hix, List.length_map]
    have hnpos : 0 < ps.length := List.length_pos_of_mem hn0
    have gb : ∀ i (hi : i < ps.length), ps[i]! = ps[i] := fun i hi => by simp [hi]
    have hlt : ∀ i j, i < j → j < ps.length → ps[i]! < ps[j]! := by
      intro i j hij hj
      rw [gb i (by omega), gb j hj]
      exact List.pairwise_iff_getElem.mp hinc i j (by omega) hj hij
    have hle : ∀ i j, i ≤ j → j < ps.length → ps[i]! ≤ ps[j]! := by
      intro i j hij hj
      rcases Nat.eq_or_lt_of_le hij with e | e
      · rw [e]; exact Nat.le_refl _
      · exact Nat.le_of_lt (hlt i j e hj)
    have hmem : ∀ i, i < ps.length → ps[i]! ∈ ps := fun i hi => by rw [gb i hi]; exact List.getElem_mem _
    have hlen : ∀ i, i < ps.length → ps[i]! < ws.length := fun i hi => hlenws _ (hmem i hi)
    have hsurj : ∀ x ∈ ps, ∃ t, t < ps.length ∧ ps[t]! = x := by
      intro x hx
      obtain ⟨t, ht, e⟩ := List.mem_iff_getElem.mp hx
      exact ⟨t, ht, by rw [gb t ht]; exact e⟩
    have hq0 : ps[0]! = 0 := by
      obtain ⟨t, ht, e⟩ := hsurj 0 hn0
      rcases Nat.eq_zero_or_pos t with et | et
      · rw [et] at e; exact e
      · have := hlt 0 t et ht
        omega
    have hA : ∀ i, i < ps.length → m.ix[i]? = some (Eix kh ws ps[i]!) := by
      intro i hi
      rw [← Array.getElem?_toList, hix, List.getElem?_map, List.getElem?_eq_getElem hi, gb i hi]
      rfl
    have hAb : ∀ i, i < ps.length → m.ix[i]! = Eix kh ws ps[i]! := by
      intro i hi
      rw [Array.getElem!_eq_getD, Array.getD_eq_getD_getElem?, hA i hi]
      rfl
    have hmono : ∀ i j, i ≤ j → j < ps.length → hashAt kh ws ps[i]! ≤ hashAt kh ws ps[j]! := fun i j hij hj =>
      hashAt_mono hs (hle i j hij hj) (hlen j hj)
    obtain ⟨k1, hk1, c1, c1'⟩ := exist_cut (fun i => hashAt kh ws ps[i]!) h ps.length hmono
    obtain ⟨k2, hk2, c2, c2'⟩ := exist_cut (fun i => hashAt kh ws ps[i]!) (h + 1) ps.length hmono
    have hp1 : partPoint m.ix (·.fence < h) = k1 := by
      apply partPoint_eq m.ix _ k1 (by omega)
      · intro i hi
        rw [hAb i (by omega)]
        have : hashAt kh ws ps[i]! < h := c1 i hi
        exact decide_eq_true this
      · intro i hi hin
        rw [hAb i (by omega)]
        have : h ≤ hashAt kh ws ps[i]! := c1' i hi (by omega)
        exact decide_eq_false (show ¬ hashAt kh ws ps[i]! < h by omega)
    have hp2 : partPoint m.ix (·.fence ≤ h) = k2 := by
      apply partPoint_eq m.ix _ k2 (by omega)
      · intro i hi
        rw [hAb i (by omega)]
        have : hashAt kh ws ps[i]! < h + 1 := c2 i hi
        exact decide_eq_true (show hashAt kh ws ps[i]! ≤ h by omega)
      · intro i hi hin
        rw [hAb i (by omega)]
        have : h + 1 ≤ hashAt kh ws ps[i]! := c2' i hi (by omega)
        exact decide_eq_false (show ¬ hashAt kh ws ps[i]! ≤ h by omega)
    have key : ∀ t, k1 < t → t < ps.length → hashAt kh ws ps[t]! = h →
        hashAt kh ws (ps[t]! - 1) = h ∧ 0 < ps[t]! := by
      intro t hkt ht eh
      have h1 : h ≤ hashAt kh ws ps[k1]! := c1' k1 (Nat.le_refl _) (by omega)
      have h2 := hmono k1 t (by omega) ht
      have h3 : ps[k1]! < ps[t]! := hlt k1 t hkt ht
      have h4 := hashAt_mono hs (show ps[k1]! ≤ ps[t]! - 1 by omega)
        (show ps[t]! - 1 < ws.length by have := hlen t ht; omega)
      have h5 := hashAt_mono hs (show ps[t]! - 1 ≤ ps[t]! by omega) (hlen t ht)
      exact ⟨by omega, by omega⟩
    have Lx : ∀ t, t < ps.length → loQ kh ws h ps[t]! = true →
        t < k1 ∨ (t = k1 ∧ hashAt kh ws ps[k1]! = h ∧ fresh kh ws ps[k1]! = true) := by
      intro t ht hq
      by_cases hlt1 : t < k1
      · exact .inl hlt1
      · have hc : h ≤ hashAt kh ws ps[t]! := c1' t (by omega) ht
        by_cases e1 : hashAt kh ws ps[t]! = h
        · have hf : fresh kh ws ps[t]! = true := by rw [← loQ_fresh e1]; exact hq
          have et : t = k1 := by
            by_cases hkt : k1 < t
            · exfalso
              obtain ⟨e2, e3⟩ := key t hkt ht e1
              simp only [fresh, Bool.or_eq_true, beq_iff_eq, bne_iff_ne, ne_eq] at hf
              rcases hf with e | e
              · omega
              · exact e (by rw [e1]; exact e2)
            · omega
          exact .inr ⟨et, by rw [← et]; exact e1, by rw [← et]; exact hf⟩
        · exfalso
          unfold loQ at hq
          simp only [Bool.or_eq_true, decide_eq_true_eq, Bool.and_eq_true, beq_iff_eq] at hq
          rcases hq with hq | ⟨hq, -⟩
          · omega
          · exact e1 hq
    have hNC : ¬ (k1 < ps.length ∧ hashAt kh ws ps[k1]! = h ∧ fresh kh ws ps[k1]! = true) →
        ∀ t, t < ps.length → loQ kh ws h ps[t]! = true → t < k1 := by
      intro hnc t ht hq
      rcases Lx t ht hq with e | ⟨e, e1, e2⟩
      · exact e
      · exact absurd ⟨by omega, e1, e2⟩ hnc
    have hlo_pos : ¬ (k1 < ps.length ∧ hashAt kh ws ps[k1]! = h ∧ fresh kh ws ps[k1]! = true) → 0 < k1 →
        loIx kh ws h = ps[k1 - 1]! := by
      intro hnc hk
      unfold loIx
      rw [hps]
      apply foldl_max_eq
      · right
        refine List.mem_filter.mpr ⟨hmem _ (by omega), ?_⟩
        have : hashAt kh ws ps[k1 - 1]! < h := c1 (k1 - 1) (by omega)
        unfold loQ
        rw [decide_eq_true this, Bool.true_or]
      · intro x hx
        obtain ⟨hxp, hxq⟩ := List.mem_filter.mp hx
        obtain ⟨t, ht, rfl⟩ := hsurj x hxp
        exact hle t (k1 - 1) (by have := hNC hnc t ht hxq; omega) (by omega)
    have hlo_zero : ¬ (k1 < ps.length ∧ hashAt kh ws ps[k1]! = h ∧ fresh kh ws ps[k1]! = true) → k1 = 0 →
        loIx kh ws h = 0 := by
      intro hnc hk
      unfold loIx
      rw [hps]
      apply foldl_max_eq
      · exact .inl rfl
      · intro x hx
        obtain ⟨hxp, hxq⟩ := List.mem_filter.mp hx
        obtain ⟨t, ht, rfl⟩ := hsurj x hxp
        have := hNC hnc t ht hxq
        omega
    have hlo_some : ∀ e, m.ix[k1]? = some e →
        (if e.fence == h && e.fresh then e else (if k1 > 0 then m.ix[k1 - 1]! else m.ix[0]!)) =
          Eix kh ws (loIx kh ws h) := by
      intro e he
      have hk : k1 < ps.length := by
        by_cases hk : k1 < ps.length
        · exact hk
        · rw [Array.getElem?_eq_none (by omega)] at he; cases he
      rw [hA k1 hk] at he
      obtain rfl := Option.some.inj he
      by_cases hC : k1 < ps.length ∧ hashAt kh ws ps[k1]! = h ∧ fresh kh ws ps[k1]! = true
      · obtain ⟨-, e, hf⟩ := hC
        have hl : loIx kh ws h = ps[k1]! := by
          unfold loIx
          rw [hps]
          apply foldl_max_eq
          · right
            exact List.mem_filter.mpr ⟨hmem _ hk, by rw [loQ_fresh e]; exact hf⟩
          · intro x hx
            obtain ⟨hxp, hxq⟩ := List.mem_filter.mp hx
            obtain ⟨t, ht, rfl⟩ := hsurj x hxp
            rcases Lx t ht hxq with e' | ⟨e', -⟩
            · exact Nat.le_of_lt (hlt t k1 e' hk)
            · rw [e']; exact Nat.le_refl _
        rw [if_pos (by simp only [Eix, Bool.and_eq_true, beq_iff_eq]; exact ⟨e, hf⟩), hl]
      · have hcond : ¬ ((Eix kh ws ps[k1]!).fence == h && (Eix kh ws ps[k1]!).fresh) = true := by
          intro hb
          simp only [Eix, Bool.and_eq_true, beq_iff_eq] at hb
          exact hC ⟨hk, hb.1, hb.2⟩
        rw [if_neg hcond]
        rcases Nat.eq_zero_or_pos k1 with e0 | e0
        · rw [hlo_zero hC e0, if_neg (by omega), hAb 0 hnpos, hq0]
        · rw [if_pos e0, hAb (k1 - 1) (by omega), hlo_pos hC e0]
    have hlo_none : m.ix[k1]? = none → m.ix.back! = Eix kh ws (loIx kh ws h) := by
      intro he
      have hk : ps.length ≤ k1 := by
        by_cases hk : k1 < ps.length
        · rw [hA k1 hk] at he; cases he
        · omega
      have hC : ¬ (k1 < ps.length ∧ hashAt kh ws ps[k1]! = h ∧ fresh kh ws ps[k1]! = true) := fun hc => by
        have := hc.1; omega
      show m.ix[m.ix.size - 1]! = _
      rw [hsz, hAb _ (by omega), hlo_pos hC (by omega)]
      have : k1 = ps.length := by omega
      rw [this]
    have hhl : ∀ x ∈ ps.filter (fun j => decide (h < hashAt kh ws j)), h < hashAt kh ws x := fun x hx =>
      of_decide_eq_true (List.mem_filter.mp hx).2
    have hhi_some : ∀ e, m.ix[k2]? = some e →
        e.row = hiIx kh ws h ∧ e.page * pageSize + e.off = off ws (hiIx kh ws h) := by
      intro e he
      have hk : k2 < ps.length := by
        by_cases hk : k2 < ps.length
        · exact hk
        · rw [Array.getElem?_eq_none (by omega)] at he; cases he
      rw [hA k2 hk] at he
      obtain rfl := Option.some.inj he
      have hl : hiIx kh ws h = ps[k2]! := by
        unfold hiIx
        rw [hps]
        apply foldl_min_eq
        · right
          have : h + 1 ≤ hashAt kh ws ps[k2]! := c2' k2 (Nat.le_refl _) hk
          exact List.mem_filter.mpr ⟨hmem _ hk, decide_eq_true (by omega)⟩
        · intro x hx
          obtain ⟨t, ht, rfl⟩ := hsurj x (List.mem_filter.mp hx).1
          have h1 := hhl _ hx
          refine hle k2 t (Nat.le_of_not_lt fun hc => ?_) ht
          have : hashAt kh ws ps[t]! < h + 1 := c2 t hc
          omega
        · exact Nat.le_of_lt (hlen k2 hk)
      rw [hl]
      exact ⟨rfl, Nat.div_add_mod' _ _⟩
    have hhi_none : m.ix[k2]? = none → hiIx kh ws h = ws.length := by
      intro he
      have hk : ps.length ≤ k2 := by
        by_cases hk : k2 < ps.length
        · rw [hA k2 hk] at he; cases he
        · omega
      unfold hiIx
      rw [hps]
      apply foldl_min_eq
      · exact .inl rfl
      · intro x hx
        obtain ⟨t, ht, rfl⟩ := hsurj x (List.mem_filter.mp hx).1
        have h1 := hhl _ hx
        have : hashAt kh ws ps[t]! < h + 1 := c2 t (by omega)
        omega
      · exact Nat.le_refl _
    unfold CMetaR.window
    dsimp only
    rw [hp1, hp2]
    rcases hm1 : m.ix[k1]? with _ | e1 <;> rcases hm2 : m.ix[k2]? with _ | e2 <;> dsimp only
    all_goals first | rw [hlo_none hm1] | rw [hlo_some _ hm1]
    all_goals first
      | (rw [hn, hrb, ← hhi_none hm2]; simp only [Eix]; rw [Nat.div_add_mod'])
      | (obtain ⟨g1, g2⟩ := hhi_some _ hm2; rw [g1, g2]; simp only [Eix]; rw [Nat.div_add_mod'])

theorem window_spec {c : Chunk} {ws : List Row} (hd : decChunk hl kh c = some ws) (m : CMetaR)
    (M : CMeta) (hM : M = metaOf hl kh ws c.pages)
    (hix : m.ix = (encFast ws).ix) (hn : m.nrows = (encFast ws).nrows) (hrb : m.rowBytes = (encFast ws).rowBytes)
    (h : Nat) :
    m.window h = (loF M h, byteAt M (loF M h) 0, hiF M h, byteAt M (hiF M h) M.dlen) := by
  subst hM
  obtain ⟨-, hs⟩ := decChunk_canon hd
  have hsp := encFast_spec ws
  rw [window_ix kh hs m (by rw [hix]; exact encFast_ix ws) (by rw [hn, hsp.2.2.2.2])
    (by rw [hrb, hsp.2.2.2.1, off_len]) h, loF_eq hd h, hiF_eq hd h, lb_eq hd h, hb_eq hd h]

/-! ## Scanning the window's bytes -/

theorem drop_step {l a r : List UInt8} {i : Nat} (h : l.drop i = a ++ r) : l.drop (i + a.length) = r := by
  rw [← List.drop_drop, h, List.drop_left' rfl]

theorem unlebAt_of (d : ByteArray) (i n : Nat) (r : Bytes) (h : d.toList.drop i = leb n ++ r) :
    Bin.unlebAt d i = some (n, i + (leb n).length) := by
  obtain ⟨e1, e2⟩ := Bin.unlebAt_eq d i
  rw [h, unleb_leb] at e1
  have hl := Bin.size_eq_length' d
  have hlen := congrArg List.length h
  simp only [List.length_drop, List.length_append] at hlen
  have hp := leb_length_pos n
  rcases hu : Bin.unlebAt d i with _ | ⟨m, j⟩
  · rw [hu] at e1; simp at e1
  · rw [hu] at e1
    simp only [Option.map_some, Option.some.injEq, Prod.mk.injEq] at e1
    obtain ⟨rfl, e3⟩ := e1
    have hj := e2 _ _ hu
    have := congrArg List.length e3
    simp only [List.length_drop] at this
    rw [← Bin.size_eq_length'] at this
    rw [← Bin.size_eq_length'] at hlen
    have : j = i + (leb n).length := by omega
    rw [this]

theorem bytes_at (buf : ByteArray) (p : Nat) (k X : Bytes) (h : buf.toList.drop p = k ++ X) (i : Nat)
    (hi : i < k.length) : buf[p + i]! = k[i] := by
  have hl := Bin.size_eq_length' buf
  have hlen := congrArg List.length h
  simp only [List.length_drop, List.length_append] at hlen
  have hlt : p + i < buf.toList.length := by omega
  have h1 := congrArg (·[i]?) h
  simp only [List.getElem?_drop, List.getElem?_append_left hi] at h1
  rw [List.getElem?_eq_getElem hlt, List.getElem?_eq_getElem hi] at h1
  rw [Bin.getBang' buf (p + i) (by omega)]
  exact Option.some.inj h1

theorem sa_aux (buf : ByteArray) (p : Nat) (kb : ByteArray) (l : List Nat) :
    (forIn (m := Id) l ((none : Option Bool), ()) (fun i _ =>
      if (buf[p + i]! != kb[i]!) = true then pure (ForInStep.done ((some false : Option Bool), ()))
      else pure (ForInStep.yield ((none : Option Bool), ())))) =
    (if ∀ i ∈ l, buf[p + i]! = kb[i]! then ((none : Option Bool), ()) else ((some false : Option Bool), ())) := by
  induction l with
  | nil => rfl
  | cons a l ih =>
    rw [List.forIn_cons]
    by_cases hb : buf[p + a]! = kb[a]!
    · rw [if_neg (by simp [hb])]
      simp only [pure_bind]
      rw [ih]
      simp [hb]
    · rw [if_pos (by simp [hb])]
      simp [hb]
      rfl

theorem sameAt_iff (buf : ByteArray) (p : Nat) (kb : ByteArray) :
    sameAt buf p kb = true ↔ ∀ i, i < kb.size → buf[p + i]! = kb[i]! := by
  unfold sameAt
  simp only [Id.run, Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.sub_zero, Nat.add_sub_cancel,
    Nat.div_one]
  rw [sa_aux]
  by_cases hc : ∀ i ∈ List.range' 0 kb.size, buf[p + i]! = kb[i]!
  · rw [if_pos hc]
    show (true = true) ↔ _
    exact ⟨fun _ i hi => hc i (List.mem_range'_1.2 ⟨by omega, by omega⟩), fun _ => rfl⟩
  · rw [if_neg hc]
    show (false = true) ↔ _
    constructor
    · intro h; exact absurd h (by decide)
    · intro h; exact absurd (fun i hi => h i (by have := List.mem_range'_1.1 hi; omega)) hc

theorem ixs_append (j : Nat) (A B : List Row) : ixs j (A ++ B) = ixs j A ++ ixs (j + A.length) B := by
  induction A generalizing j with
  | nil => simp [ixs]
  | cons a A ih =>
    simp only [List.cons_append, ixs, ih, List.length_cons]
    rw [show j + 1 + A.length = j + (A.length + 1) by omega]

theorem encRow_pos (w : Row) : 0 < (encRow w).length := by
  have := leb_length_pos (encBody w).length
  simp only [encRow, List.length_append]
  omega

theorem row_at (buf : ByteArray) (kb : ByteArray) (pos : Nat) (w : Row) (rest : Bytes) (hw : w.2.Wf)
    (hd : buf.toList.drop pos = encRow w ++ rest) (len p1 kl p2 : Nat) (hlen : len = (encBody w).length)
    (hp1 : p1 = pos + (leb len).length) (hkl : kl = w.1.length) (hp2 : p2 = p1 + (leb kl).length) :
    Bin.unlebAt buf pos = some (len, p1) ∧ Bin.unlebAt buf p1 = some (kl, p2) ∧
    (len == 0 || decide (p1 + len > buf.size) || decide (p2 + kl > p1 + len)) = false ∧
    (kl == kb.size && sameAt buf p2 kb) = decide (w.1 = kb.toList) ∧
    decBody (buf.extract p1 (p1 + len)).toList = some w := by
  obtain ⟨T, hT⟩ : ∃ T, encBody w = leb w.1.length ++ (w.1 ++ T) :=
    ⟨leb w.2.count ++ (leb w.2.head.length ++ (w.2.head.flatMap encPosting ++ encTail w.2.tail)),
      by simp [encBody, List.append_assoc]⟩
  have hd1 : buf.toList.drop pos = leb len ++ (encBody w ++ rest) := by
    rw [hd, hlen]; simp only [encRow, List.append_assoc]
  have H1 := unlebAt_of buf pos len _ hd1
  have hd2 : buf.toList.drop p1 = encBody w ++ rest := by rw [hp1]; exact drop_step hd1
  have hd2' : buf.toList.drop p1 = leb kl ++ (w.1 ++ (T ++ rest)) := by
    rw [hd2, hT, hkl]; simp only [List.append_assoc]
  have H2 := unlebAt_of buf p1 kl _ hd2'
  have hd3 : buf.toList.drop p2 = w.1 ++ (T ++ rest) := by rw [hp2]; exact drop_step hd2'
  have hlenB : len = (leb kl).length + kl + T.length := by
    rw [hlen, hT, hkl]; simp only [List.length_append]; omega
  have hpk := leb_length_pos kl
  have hl := Bin.size_eq_length' buf
  have hz := congrArg List.length hd2
  simp only [List.length_drop, List.length_append] at hz
  refine ⟨by rw [H1, hp1], by rw [H2, hp2], ?_, ?_, ?_⟩
  · simp only [Bool.or_eq_false_iff, beq_eq_false_iff_ne, decide_eq_false_iff_not]
    refine ⟨⟨?_, ?_⟩, ?_⟩ <;> omega
  · by_cases hk : w.1 = kb.toList
    · have hkb : kb.size = kl := by rw [Bin.size_eq_length', ← hk, hkl]
      have hsa : sameAt buf p2 kb = true := (sameAt_iff buf p2 kb).2 fun i hi => by
        rw [bytes_at buf p2 w.1 _ hd3 i (by omega), Bin.getBang' kb i hi]
        exact List.getElem_of_eq hk _
      rw [decide_eq_true hk, hsa, hkb]
      simp
    · rw [decide_eq_false hk]
      cases hq : (kl == kb.size)
      · rfl
      · have hkb : kl = kb.size := by simpa using hq
        cases hs : sameAt buf p2 kb
        · simp
        · exfalso
          apply hk
          have hs' := (sameAt_iff buf p2 kb).1 hs
          refine List.ext_getElem (by rw [← hkl, hkb, Bin.size_eq_length']) fun i h1 h2 => ?_
          have e1 := hs' i (by rw [Bin.size_eq_length']; omega)
          rw [bytes_at buf p2 w.1 _ hd3 i h1, Bin.getBang' kb i (by omega)] at e1
          exact e1
  · rw [Bin.toList_extract', hd2, Nat.add_sub_cancel_left, hlen, List.take_left' rfl]
    exact decBody_enc w hw

theorem scanGo_spec (buf kb : ByteArray) (stp : Nat) (j0 : Nat) (R : List Row) (post : Bytes)
    (hwf : ∀ w ∈ R, w.2.Wf) :
    ∀ f (Rd Rr : List Row) (out : Array (Nat × Row)) (pos j : Nat), R = Rd ++ Rr →
      out = ((ixs j0 Rd).filter (fun iw => decide (iw.2.1 = kb.toList))).toArray →
      stp = pos + (Rr.flatMap encRow).length → j = j0 + Rd.length →
      buf.toList.drop pos = Rr.flatMap encRow ++ post → (Rr.flatMap encRow).length ≤ f →
      scanGo buf kb stp f out pos j = some ((ixs j0 R).filter (fun iw => decide (iw.2.1 = kb.toList))).toArray := by
  intro f
  induction f with
  | zero =>
    intro Rd Rr out pos j hR hout hstp hj hdr hf
    rcases Rr with _ | ⟨w, Rr'⟩
    · rw [List.append_nil] at hR
      subst hR
      have hlt : ¬ pos < stp := by simp at hstp; omega
      simp only [scanGo, if_neg hlt, hout]
    · have := encRow_pos w
      simp only [List.flatMap_cons, List.length_append] at hf
      omega
  | succ f ih =>
    intro Rd Rr out pos j hR hout hstp hj hdr hf
    rcases Rr with _ | ⟨w, Rr'⟩
    · rw [List.append_nil] at hR
      subst hR
      have hlt : ¬ pos < stp := by simp at hstp; omega
      simp only [scanGo, if_neg hlt, hout]
    · have hwfw : w.2.Wf := hwf w (by rw [hR]; simp)
      have hdr' : buf.toList.drop pos = encRow w ++ (Rr'.flatMap encRow ++ post) := by
        rw [hdr, List.flatMap_cons, List.append_assoc]
      obtain ⟨len, hlen⟩ : ∃ len, len = (encBody w).length := ⟨_, rfl⟩
      obtain ⟨p1, hp1⟩ : ∃ p1, p1 = pos + (leb len).length := ⟨_, rfl⟩
      obtain ⟨kl, hkl⟩ : ∃ kl, kl = w.1.length := ⟨_, rfl⟩
      obtain ⟨p2, hp2⟩ : ∃ p2, p2 = p1 + (leb kl).length := ⟨_, rfl⟩
      obtain ⟨H1, H2, Hb, Hs, Hd⟩ := row_at buf kb pos w _ hwfw hdr' len p1 kl p2 hlen hp1 hkl hp2
      have hel : (encRow w).length = (leb len).length + len := by
        simp only [encRow, List.length_append]; rw [hlen]
      have hlt : pos < stp := by
        have h3 := encRow_pos w
        simp only [List.flatMap_cons, List.length_append] at hstp
        omega
      have hnext : p1 + len = pos + (encRow w).length := by rw [hel]; omega
      have hR' : R = (Rd ++ [w]) ++ Rr' := by simp [hR]
      have hstp' : stp = (p1 + len) + (Rr'.flatMap encRow).length := by
        simp only [List.flatMap_cons, List.length_append] at hstp
        omega
      have hj' : j + 1 = j0 + (Rd ++ [w]).length := by
        simp only [List.length_append, List.length_cons, List.length_nil]; omega
      have hdr2 : buf.toList.drop (p1 + len) = Rr'.flatMap encRow ++ post := by
        rw [hnext]; exact drop_step hdr'
      have hf' : (Rr'.flatMap encRow).length ≤ f := by
        have h3 := encRow_pos w
        simp only [List.flatMap_cons, List.length_append] at hf
        omega
      by_cases hk : w.1 = kb.toList
      · have hkd : decide (w.1 = kb.toList) = true := by simp [hk]
        simp only [scanGo, if_pos hlt, H1, H2, Hb, Hs, hkd, Hd, Bool.false_eq_true, if_false, if_true]
        refine ih (Rd ++ [w]) Rr' _ (p1 + len) (j + 1) hR' ?_ hstp' hj' hdr2 hf'
        rw [ixs_append, List.filter_append, hout, hj]
        simp [ixs, hk]
      · have hkd : decide (w.1 = kb.toList) = false := by simp [hk]
        simp only [scanGo, if_pos hlt, H1, H2, Hb, Hs, hkd, Hd, Bool.false_eq_true, if_false, if_true]
        refine ih (Rd ++ [w]) Rr' _ (p1 + len) (j + 1) hR' ?_ hstp' hj' hdr2 hf'
        rw [ixs_append, List.filter_append, hout]
        simp [ixs, hk]

theorem scan_spec (buf : ByteArray) (bufOff j0 start stop : Nat) (kb : ByteArray) (R : List Row) (post : Bytes)
    (hwf : ∀ w ∈ R, w.2.Wf) (hd : buf.toList.drop (start - bufOff) = R.flatMap encRow ++ post)
    (hstop : stop - bufOff = start - bufOff + (R.flatMap encRow).length) :
    scan buf bufOff j0 start stop kb =
      some ((ixs j0 R).filter (fun iw => decide (iw.2.1 = kb.toList))).toArray :=
  scanGo_spec buf kb (stop - bufOff) j0 R post hwf _ [] R #[] (start - bufOff) j0 rfl (by simp [ixs]) hstop
    (by simp) hd (by omega)

/-- The pure part of `readHits`, as it computes it: the window, then (when it is not empty) `scan` over the pages
    `p0 ..< p0 + np` read as one buffer `buf`.  It is `readWin`'s result filtered by the key bytes. -/
theorem readHits_pure {c : Chunk} {ws : List Row} (hd : decChunk hl kh c = some ws) (hW : ∀ w ∈ ws, w.2.Wf)
    (m : CMetaR) (M : CMeta) (hM : M = metaOf hl kh ws c.pages)
    (hix : m.ix = (encFast ws).ix) (hn : m.nrows = (encFast ws).nrows) (hrb : m.rowBytes = (encFast ws).rowBytes)
    (pg : Nat → Bytes) (hpg : ∀ p, p < c.pages.length → c.pages[p]? = some (pg p)) (h : Nat) (kb buf : ByteArray)
    (hbuf : ∀ lo loOff hi hiOff, m.window h = (lo, loOff, hi, hiOff) → lo < hi →
      buf.toList = ((List.range' (loOff / pageSize) ((hiOff - 1) / pageSize - loOff / pageSize + 1)).map pg).flatten) :
    (match m.window h with
      | (lo, loOff, hi, hiOff) =>
        if hi ≤ lo then some [] else (scan buf (loOff / pageSize * pageSize) lo loOff hiOff kb).map (·.toList)) =
      (readWin hl M (some (chunkRoot hl c)) pg h).map fun l => l.filter fun iw => decide (iw.2.1 = kb.toList) := by
  have hw := window_spec hd m M hM hix hn hrb h
  have hlo := loF_eq hd h
  have hhi := hiF_eq hd h
  have hlb := lb_eq hd h
  have hhb := hb_eq hd h
  have hhl : hiIx kh ws h ≤ ws.length := (foldl_min_le _ _).1
  subst hM
  rw [hlo, hhi, hlb, hhb] at hw
  have hbuf' := hbuf _ _ _ _ hw
  rw [hw, readWin_ok hd hW hpg h]
  have hinW : inWin kh ws h = fun iw => decide (loIx kh ws h ≤ iw.1) && decide (iw.1 < hiIx kh ws h) := rfl
  dsimp only
  rw [Option.map_some, hinW, ixs_win ws _ _ hhl]
  obtain ⟨hc, -⟩ := decChunk_canon hd
  subst hc
  generalize loIx kh ws h = lo at *
  generalize hiIx kh ws h = hi at *
  by_cases hlh : hi ≤ lo
  · rw [if_pos hlh, show hi - lo = 0 by omega]
    simp [ixs]
  rw [if_neg hlh]
  have hbuf2 := hbuf' (by omega)
  obtain ⟨z, hz⟩ := pagesN_flatten (encData ws).length (encData ws) (Nat.le_refl _)
  have hfl : (encChunk hl kh ws).pages.flatten = ws.flatMap encRow ++ (leb 0 ++ List.replicate z 0) := by
    rw [show (encChunk hl kh ws).pages.flatten = encData ws ++ List.replicate z 0 from hz, encData, List.append_assoc]
  have hsz : ∀ p ∈ (encChunk hl kh ws).pages, p.length = pageSize := pagesN_sizes _ _
  have hlt : off ws lo < off ws hi := by
    have e := off_succ (List.getElem?_eq_getElem (show lo < ws.length by omega))
    have := off_mono ws (show lo + 1 ≤ hi by omega)
    have := encRow_length_pos ws[lo]
    omega
  have hend : off ws hi < (encData ws).length := by
    have := off_mono ws hhl
    have := leb_length_pos 0
    simp only [encData, List.length_append, off, List.take_length] at *
    omega
  have hpe : (off ws hi - 1) / pageSize < (encChunk hl kh ws).pages.length :=
    pagesN_len _ _ _ (Nat.le_refl _) (Nat.lt_of_le_of_lt (Nat.div_mul_le_self _ _) (by omega))
  have ha : off ws lo / pageSize ≤ (off ws hi - 1) / pageSize := Nat.div_le_div_right (by omega)
  have hk : off ws lo / pageSize + ((off ws hi - 1) / pageSize - off ws lo / pageSize + 1) ≤
      (encChunk hl kh ws).pages.length := by omega
  rw [range'_map _ _ hk hpg, pages_slice hsz, hfl] at hbuf2
  have hA : off ws lo / pageSize * pageSize ≤ off ws lo := Nat.div_mul_le_self _ _
  have hB : off ws hi ≤ off ws lo / pageSize * pageSize + ((off ws hi - 1) / pageSize - off ws lo / pageSize + 1) *
      pageSize := by
    have hps : pageSize = 4096 := rfl
    rw [hps] at *
    omega
  have e1 : ws.flatMap encRow = (ws.take lo).flatMap encRow ++
      (((ws.drop lo).take (hi - lo)).flatMap encRow ++ ((ws.drop lo).drop (hi - lo)).flatMap encRow) := by
    rw [← List.flatMap_append, List.take_append_drop, ← List.flatMap_append, List.take_append_drop]
  have e2 : off ws hi = off ws lo + (((ws.drop lo).take (hi - lo)).flatMap encRow).length := by
    have := show off ws (lo + (hi - lo)) = off ws lo + (((ws.drop lo).take (hi - lo)).flatMap encRow).length by
      simp only [off, List.take_add, List.flatMap_append, List.length_append]
    rwa [show lo + (hi - lo) = hi by omega] at this
  have hWR : ∀ w ∈ (ws.drop lo).take (hi - lo), w.2.Wf := fun w hm =>
    hW w (List.mem_of_mem_drop (List.mem_of_mem_take hm))
  have hdrop : buf.toList.drop (off ws lo - off ws lo / pageSize * pageSize) =
      ((ws.drop lo).take (hi - lo)).flatMap encRow ++
        ((((ws.drop lo).drop (hi - lo)).flatMap encRow ++ (leb 0 ++ List.replicate z 0)).take
          (((off ws hi - 1) / pageSize - off ws lo / pageSize + 1) * pageSize -
            (off ws lo - off ws lo / pageSize * pageSize) - (((ws.drop lo).take (hi - lo)).flatMap encRow).length)) := by
    have hdl : ∀ X : Bytes, ((ws.take lo).flatMap encRow ++ X).drop (off ws lo) = X := fun X => List.drop_left
    have hRb : (((ws.drop lo).take (hi - lo)).flatMap encRow).length ≤
        ((off ws hi - 1) / pageSize - off ws lo / pageSize + 1) * pageSize -
          (off ws lo - off ws lo / pageSize * pageSize) := by omega
    rw [hbuf2, List.drop_take, List.drop_drop, show off ws lo / pageSize * pageSize +
      (off ws lo - off ws lo / pageSize * pageSize) = off ws lo by omega, e1, List.append_assoc, List.append_assoc,
      hdl, List.take_append, List.take_of_length_le hRb]
  rw [scan_spec buf _ lo (off ws lo) (off ws hi) kb _ _ hWR hdrop (by omega)]
  simp

end BlindLedger.Gate.Flat.ChunkIo
