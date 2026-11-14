import BlindLedger.Gate.Flat.StoreTheorems

/-! The page index of a chunk and what a key lookup inside a chunk reads.

    A chunk's rows are sorted by key hash and packed into `pageSize` pages.  The index names, for every page, the
    first row that starts in it, with that row's key hash (its fence) and whether the row before it has another key
    hash.  A lookup of key hash `h` reads the rows from `loIx` to `hiIx`: from the last indexed row below `h`, or the
    indexed row that begins the run of hash `h`, up to the first indexed row above `h`.  Every row of hash `h` lies in
    that window (`inWin_of`), so `hits` reads the same live rows through the window as through the whole chunk
    (`hits_win`).  When no other row of the chunk shares the hash and no row is longer than a page, the window spans at
    most 2 pages (`pagesIn_le`), so a lookup reads at most `(2 * 4 + stashCap) * 2` pages (`lookup_pages`).  The
    page marks a chunk's metadata records are this index (`marks_index`).

    `fetchFast` reads a batch from the store as the worker does: the windows, then for each candidate chunk its
    in-memory metadata, checked against the chunk's committed root, and only the pages of the key's window, each
    checked against its SHA3-512 in the metadata, before exactly the window's rows are decoded from them
    (`pages_slice`, `rows_mid`).  Under `ReadsOk` it gives the spec's fetch (`fetchFast_eq`, `decideFast_eq`); a
    failing root or page makes it refuse (`fetchFast_bad`); it reads at most `q + 1` pages per candidate chunk when
    no row is longer than `q` pages (`pagesRead_le`). -/

namespace BlindLedger.Gate.Flat.Store

open Chunk
open BlindLedger.Gate.OnepIndex (leb unleb unleb_leb)

/-- An indexed row a lookup of hash `h` may start at: below `h`, or the first row of hash `h`. -/
def loQ (kh : Bytes → UInt64) (ws : List Row) (h j : Nat) : Bool :=
  hashAt kh ws j < h || (hashAt kh ws j == h && (j == 0 || hashAt kh ws (j - 1) != h))

def loIx (kh : Bytes → UInt64) (ws : List Row) (h : Nat) : Nat := ((pidx ws).filter (loQ kh ws h)).foldl max 0

def hiIx (kh : Bytes → UInt64) (ws : List Row) (h : Nat) : Nat :=
  ((pidx ws).filter fun j => h < hashAt kh ws j).foldl min ws.length

/-- Row `iw` lies in the window a lookup of hash `h` reads. -/
def inWin (kh : Bytes → UInt64) (ws : List Row) (h : Nat) (iw : Nat × Row) : Bool :=
  loIx kh ws h ≤ iw.1 && iw.1 < hiIx kh ws h

/-- The pages a lookup of hash `h` reads: those holding a byte of a row of its window. -/
def pagesIn (kh : Bytes → UInt64) (ws : List Row) (h : Nat) : List Nat :=
  let lo := loIx kh ws h
  let hi := hiIx kh ws h
  if lo < hi then List.range' (off ws lo / pageSize) ((off ws hi - 1) / pageSize + 1 - off ws lo / pageSize) else []

/-! ## Sorted rows -/

theorem sorted_tail {kh : Bytes → UInt64} {a : Row} : ∀ {ws : List Row}, sortedB kh (a :: ws) = true →
    sortedB kh ws = true
  | [], _ => rfl
  | _ :: _, h => by simp only [sortedB, Bool.and_eq_true] at h; exact h.2

theorem sorted_head {kh : Bytes → UInt64} : ∀ {a : Row} {ws : List Row}, sortedB kh (a :: ws) = true →
    ∀ b ∈ ws, (kh a.1).toNat ≤ (kh b.1).toNat
  | _, [], _, b, hb => by simp at hb
  | a, b :: ws, h, c, hc => by
    simp only [sortedB, Bool.and_eq_true] at h
    have hab : (kh a.1).toNat ≤ (kh b.1).toNat := by
      have h1 := h.1
      simp only [rowLt, Bool.or_eq_true, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at h1
      rcases h1 with h1 | ⟨h1, -⟩
      · exact Nat.le_of_lt (UInt64.lt_iff_toNat_lt.mp h1)
      · exact Nat.le_of_eq (congrArg UInt64.toNat h1)
    rcases List.mem_cons.mp hc with rfl | hc
    · exact hab
    · exact Nat.le_trans hab (sorted_head h.2 c hc)

theorem sorted_mono {kh : Bytes → UInt64} : ∀ {ws : List Row} {i j : Nat} {a b : Row}, sortedB kh ws = true →
    ws[i]? = some a → ws[j]? = some b → i ≤ j → (kh a.1).toNat ≤ (kh b.1).toNat
  | [], _, _, _, _, _, ha, _, _ => by simp at ha
  | _ :: _, 0, 0, _, _, _, ha, hb, _ => by simp at ha hb; subst ha; subst hb; exact Nat.le_refl _
  | _ :: _, 0, _ + 1, _, b, hs, ha, hb, _ => by
    simp at ha hb; subst ha; exact sorted_head hs b (List.mem_of_getElem? hb)
  | _ :: _, _ + 1, 0, _, _, _, _, _, hij => by omega
  | _ :: _, _ + 1, _ + 1, _, _, hs, ha, hb, hij => by
    simp only [List.getElem?_cons_succ] at ha hb; exact sorted_mono (sorted_tail hs) ha hb (by omega)

theorem hashAt_of {kh : Bytes → UInt64} {ws : List Row} {j : Nat} {w : Row} (h : ws[j]? = some w) :
    hashAt kh ws j = (kh w.1).toNat := by simp [hashAt, h]

theorem hashAt_mono {kh : Bytes → UInt64} {ws : List Row} (hs : sortedB kh ws = true) {i j : Nat} (hij : i ≤ j)
    (hj : j < ws.length) : hashAt kh ws i ≤ hashAt kh ws j := by
  have ea := List.getElem?_eq_getElem (show i < ws.length by omega)
  have eb := List.getElem?_eq_getElem hj
  rw [hashAt_of ea, hashAt_of eb]
  exact sorted_mono hs ea eb hij

/-! ## The window holds every row of its hash -/

theorem foldl_max_ge : ∀ (l : List Nat) (a : Nat), a ≤ l.foldl max a ∧ ∀ x ∈ l, x ≤ l.foldl max a
  | [], a => by simp
  | y :: l, a => by
    obtain ⟨h1, h2⟩ := foldl_max_ge l (max a y)
    simp only [List.foldl_cons, List.mem_cons]
    exact ⟨Nat.le_trans (Nat.le_max_left a y) h1,
      fun x hx => hx.elim (fun e => by subst e; exact Nat.le_trans (Nat.le_max_right a x) h1) (h2 x)⟩

theorem foldl_max_mem : ∀ (l : List Nat) (a : Nat), l.foldl max a = a ∨ l.foldl max a ∈ l
  | [], a => by simp
  | y :: l, a => by
    simp only [List.foldl_cons, List.mem_cons]
    rcases foldl_max_mem l (max a y) with h | h
    · rw [h]
      by_cases hy : a ≤ y
      · exact .inr (.inl (Nat.max_eq_right hy))
      · exact .inl (Nat.max_eq_left (by omega))
    · exact .inr (.inr h)

theorem foldl_min_le : ∀ (l : List Nat) (a : Nat), l.foldl min a ≤ a ∧ ∀ x ∈ l, l.foldl min a ≤ x
  | [], a => by simp
  | y :: l, a => by
    obtain ⟨h1, h2⟩ := foldl_min_le l (min a y)
    simp only [List.foldl_cons, List.mem_cons]
    exact ⟨Nat.le_trans h1 (Nat.min_le_left a y),
      fun x hx => hx.elim (fun e => by subst e; exact Nat.le_trans h1 (Nat.min_le_right a x)) (h2 x)⟩

theorem foldl_min_mem : ∀ (l : List Nat) (a : Nat), l.foldl min a = a ∨ l.foldl min a ∈ l
  | [], a => by simp
  | y :: l, a => by
    simp only [List.foldl_cons, List.mem_cons]
    rcases foldl_min_mem l (min a y) with h | h
    · rw [h]
      by_cases hy : y ≤ a
      · exact .inr (.inl (Nat.min_eq_right hy))
      · exact .inl (Nat.min_eq_left (by omega))
    · exact .inr (.inr h)

theorem pidx_lt {ws : List Row} {j : Nat} (h : j ∈ pidx ws) : j < ws.length :=
  List.mem_range.mp (List.mem_filter.mp h).1

/-- Every row of a sorted chunk lies in the window of its own key hash. -/
theorem inWin_of {kh : Bytes → UInt64} {ws : List Row} (hs : sortedB kh ws = true) {i : Nat} {w : Row}
    (hw : ws[i]? = some w) : inWin kh ws (kh w.1).toNat (i, w) = true := by
  have hi : i < ws.length := by
    rcases Nat.lt_or_ge i ws.length with hc | hc
    · exact hc
    · rw [List.getElem?_eq_none hc] at hw; cases hw
  have hh := hashAt_of (kh := kh) hw
  simp only [inWin, Bool.and_eq_true, decide_eq_true_eq]
  constructor
  · unfold loIx
    rcases foldl_max_mem ((pidx ws).filter (loQ kh ws (kh w.1).toNat)) 0 with e | e
    · rw [e]; exact Nat.zero_le _
    · obtain ⟨hp, hq⟩ := List.mem_filter.mp e
      generalize List.foldl max 0 (List.filter (loQ kh ws (kh w.1).toNat) (pidx ws)) = lo at hp hq ⊢
      have hl := pidx_lt hp
      simp only [loQ, Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq, bne_iff_ne, ne_eq] at hq
      refine Nat.le_of_not_lt fun hlt => ?_
      have m1 := hashAt_mono hs (Nat.le_of_lt hlt) hl
      rcases hq with hq | ⟨hq1, hq2 | hq2⟩
      · omega
      · omega
      · have m2 := hashAt_mono hs (show i ≤ lo - 1 by omega) (show lo - 1 < ws.length by omega)
        have m3 := hashAt_mono hs (show lo - 1 ≤ lo by omega) hl
        omega
  · unfold hiIx
    rcases foldl_min_mem ((pidx ws).filter fun j => (kh w.1).toNat < hashAt kh ws j) ws.length with e | e
    · rw [e]; exact hi
    · obtain ⟨hp, hq⟩ := List.mem_filter.mp e
      generalize List.foldl min ws.length (List.filter (fun j => (kh w.1).toNat < hashAt kh ws j) (pidx ws)) = hi'
        at hp hq ⊢
      have hl := pidx_lt hp
      simp only [decide_eq_true_eq] at hq
      refine Nat.lt_of_not_le fun hle => ?_
      have := hashAt_mono hs hle hi
      omega

private theorem filterMap_filter_of {α β : Type} (p : α → Bool) (F : α → Option β) :
    ∀ (l : List α), (∀ a ∈ l, (F a).isSome = true → p a = true) → (l.filter p).filterMap F = l.filterMap F
  | [], _ => rfl
  | a :: l, h => by
    have ih := filterMap_filter_of p F l fun b hb => h b (List.mem_cons_of_mem _ hb)
    by_cases hp : p a = true
    · simp [hp, List.filterMap_cons, ih]
    · have hF : F a = none := by
        cases hF : F a with
        | none => rfl
        | some _ => exact absurd (h a (List.mem_cons_self ..) (by simp [hF])) hp
      simp [hp, hF, ih]

/-- `hits` reads each candidate chunk through its page index: the window's live rows of the key are the whole
    chunk's. -/
theorem hits_win {kh : Bytes → UInt64} {fs : Fs} {rows : Nat → List Row} {kb : Bytes}
    (hS : ∀ c, fs.inst.contains c = true → sortedB kh (rows c) = true) :
    hits kh fs rows kb = (fs.dir.cands (kh kb)).flatMap fun c =>
      if fs.inst.contains c then
        ((ixs 0 (rows c)).filter (inWin kh (rows c) (kh kb).toNat)).filterMap fun iw =>
          if iw.2.1 = kb ∧ isDead fs.dead c iw.1 = false then some (c, iw.1, iw.2.2) else none
      else [] := by
  unfold hits
  congr 1
  funext c
  split
  · rename_i hc
    refine (filterMap_filter_of _ _ _ fun iw hm hF => ?_).symm
    obtain ⟨i, w⟩ := iw
    split at hF
    · rename_i hk
      have hw := mem_ixs0.mp hm
      simp only at hk
      rw [← hk.1]
      exact inWin_of (hS c hc) hw
    · simp at hF
  · rfl

/-- Under `FInv` every installed chunk is sorted, so `hits` reads through the page index. -/
theorem hits_win_inv {H : Bytes → Bytes} {kh : Bytes → UInt64} {fs : Fs} {files : Nat → Chunk} {s : St}
    (hI : FInv H kh fs files s) (kb : Bytes) :
    hits kh fs (layout H kh files) kb = (fs.dir.cands (kh kb)).flatMap fun c =>
      if fs.inst.contains c then
        ((ixs 0 (layout H kh files c)).filter (inWin kh (layout H kh files c) (kh kb).toNat)).filterMap fun iw =>
          if iw.2.1 = kb ∧ isDead fs.dead c iw.1 = false then some (c, iw.1, iw.2.2) else none
      else [] :=
  hits_win fun c hc => by
    obtain ⟨ws, hw⟩ := Option.isSome_iff_exists.mp (hI.2.2.1 c hc).2
    simp only [layout, hw, Option.getD_some]
    exact (decChunk_canon hw).2

/-! ## Pages read -/

theorem off_succ {ws : List Row} {j : Nat} {w : Row} (h : ws[j]? = some w) :
    off ws (j + 1) = off ws j + (encRow w).length := by
  simp [off, List.take_add_one, h]

/-- With no other row of hash `h` and no row longer than `q` pages, the window of `h` covers at most `q + 1` pages:
    its rows all start in the page of its first row. -/
private theorem pagesIn_le_q {kh : Bytes → UInt64} {ws : List Row} {h q : Nat}
    (hP : ∀ w ∈ ws, (encRow w).length ≤ q * pageSize)
    (hU : ∀ i j, i < ws.length → j < ws.length → hashAt kh ws i = h → hashAt kh ws j = h → i = j) :
    (pagesIn kh ws h).length ≤ q + 1 := by
  unfold pagesIn
  dsimp only
  split
  · rename_i hlh
    rw [List.length_range']
    have hhl : hiIx kh ws h ≤ ws.length := (foldl_min_le _ _).1
    have step : ∀ d, loIx kh ws h + d < hiIx kh ws h →
        off ws (loIx kh ws h + d) / pageSize ≤ off ws (loIx kh ws h) / pageSize := by
      intro d
      induction d with
      | zero => intro _; exact Nat.le_refl _
      | succ d ih =>
        intro hd
        rw [show loIx kh ws h + (d + 1) = loIx kh ws h + d + 1 by omega] at hd ⊢
        have ih := ih (by omega)
        refine Nat.le_of_not_lt fun hq => ?_
        have hj : loIx kh ws h + d + 1 < ws.length := by omega
        have hpi : loIx kh ws h + d + 1 ∈ pidx ws := List.mem_filter.mpr ⟨List.mem_range.mpr hj, by
          simp only [Bool.or_eq_true, beq_iff_eq, decide_eq_true_eq]
          exact .inr (by rw [show loIx kh ws h + d + 1 - 1 = loIx kh ws h + d by omega]; omega)⟩
        rcases Nat.lt_trichotomy (hashAt kh ws (loIx kh ws h + d + 1)) h with hl | he | hg
        · have := (foldl_max_ge ((pidx ws).filter (loQ kh ws h)) 0).2 _
            (List.mem_filter.mpr ⟨hpi, by unfold loQ; simp only [Bool.or_eq_true, decide_eq_true_eq]; exact .inl hl⟩)
          unfold loIx at *; omega
        · by_cases hp : hashAt kh ws (loIx kh ws h + d + 1 - 1) = h
          · have := hU _ _ (by omega) hj hp he
            omega
          · have := (foldl_max_ge ((pidx ws).filter (loQ kh ws h)) 0).2 _
              (List.mem_filter.mpr ⟨hpi, by
                unfold loQ
                simp only [Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq, bne_iff_ne, ne_eq]
                exact .inr ⟨he, .inr hp⟩⟩)
            unfold loIx at *; omega
        · have := (foldl_min_le ((pidx ws).filter fun j => h < hashAt kh ws j) ws.length).2 _
            (List.mem_filter.mpr ⟨hpi, by simp only [decide_eq_true_eq]; exact hg⟩)
          unfold hiIx at *; omega
    have hlast := step (hiIx kh ws h - 1 - loIx kh ws h) (by omega)
    rw [show loIx kh ws h + (hiIx kh ws h - 1 - loIx kh ws h) = hiIx kh ws h - 1 by omega] at hlast
    have ew := List.getElem?_eq_getElem (show hiIx kh ws h - 1 < ws.length by omega)
    have hs := off_succ ew
    rw [show hiIx kh ws h - 1 + 1 = hiIx kh ws h by omega] at hs
    have hw := hP _ (List.getElem_mem (show hiIx kh ws h - 1 < ws.length by omega))
    simp only [pageSize] at *
    omega
  · simp

/-- A lookup of hash `h` in a chunk with no other row of hash `h` and no row longer than a page reads at most 2
    pages. -/
theorem pagesIn_le {kh : Bytes → UInt64} {ws : List Row} {h : Nat}
    (hP : ∀ w ∈ ws, (encRow w).length ≤ pageSize)
    (hU : ∀ i j, i < ws.length → j < ws.length → hashAt kh ws i = h → hashAt kh ws j = h → i = j) :
    (pagesIn kh ws h).length ≤ 2 :=
  pagesIn_le_q (q := 1) (fun w hw => by rw [Nat.one_mul]; exact hP w hw) hU

private theorem sum_le {b : Nat} : ∀ (l : List Nat), (∀ x ∈ l, x ≤ b) → l.sum ≤ l.length * b
  | [], _ => by simp
  | x :: l, h => by
    have := sum_le l fun y hy => h y (List.mem_cons_of_mem _ hy)
    have hx := h x (List.mem_cons_self ..)
    simp only [List.sum_cons, List.length_cons, Nat.succ_mul]
    omega

/-- The cost of a lookup all the way down: at most `2 * 4 + stashCap` candidate chunks, each read through its page
    index in at most 2 pages, when no installed chunk holds another row of the key's hash and no row is longer than a
    page. -/
theorem lookup_pages {H : Bytes → Bytes} {kh : Bytes → UInt64} {fs : Fs} {files : Nat → Chunk} {s : St}
    (hI : FInv H kh fs files s) (kb : Bytes)
    (hP : ∀ c, fs.inst.contains c = true → ∀ w ∈ layout H kh files c, (encRow w).length ≤ pageSize)
    (hU : ∀ c, fs.inst.contains c = true → ∀ i j, i < (layout H kh files c).length → j < (layout H kh files c).length →
      hashAt kh (layout H kh files c) i = (kh kb).toNat → hashAt kh (layout H kh files c) j = (kh kb).toNat → i = j) :
    ((fs.dir.cands (kh kb)).map fun c =>
      if fs.inst.contains c then (pagesIn kh (layout H kh files c) (kh kb).toNat).length else 0).sum ≤
      (2 * 4 + stashCap) * 2 := by
  refine Nat.le_trans (sum_le (b := 2) _ fun x hx => ?_) ?_
  · obtain ⟨c, -, rfl⟩ := List.mem_map.mp hx
    split
    · rename_i hc; exact pagesIn_le (hP c hc) (hU c hc)
    · exact Nat.zero_le _
  · rw [List.length_map]
    exact Nat.mul_le_mul_right 2 (read_bound hI (kh kb)).2.2

/-! ## The marks on disk are the page index -/

theorem off_succ_le {ws : List Row} (j : Nat) : off ws j ≤ off ws (j + 1) := by
  cases h : ws[j]? with
  | some w => rw [off_succ h]; omega
  | none =>
    have hl : ws.length ≤ j := List.getElem?_eq_none_iff.mp h
    simp [off, List.take_of_length_le hl, List.take_of_length_le (show ws.length ≤ j + 1 by omega)]

private theorem off_mono {ws : List Row} : ∀ {i j : Nat}, i ≤ j → off ws i ≤ off ws j
  | _, 0, h => by rw [Nat.le_zero.mp h]; exact Nat.le_refl _
  | i, j + 1, h => by
    by_cases hi : i ≤ j
    · exact Nat.le_trans (off_mono hi) (off_succ_le j)
    · rw [show i = j + 1 by omega]; exact Nat.le_refl _

private theorem fm_congr {α β : Type} {f f' : α → Option β} :
    ∀ {l : List α}, (∀ x ∈ l, f x = f' x) → l.filterMap f = l.filterMap f'
  | [], _ => rfl
  | a :: _, h => by
    rw [List.filterMap_cons, List.filterMap_cons, h a (List.mem_cons_self ..),
      fm_congr fun x hx => h x (List.mem_cons_of_mem _ hx)]

/-- The indexed rows start in strictly rising pages. -/
theorem pidx_pages (ws : List Row) :
    (pidx ws).Pairwise fun a b => off ws a / pageSize < off ws b / pageSize := by
  unfold pidx
  rw [List.pairwise_filter]
  refine (List.pairwise_lt_range (n := ws.length)).imp fun {a b} hab _ hb => ?_
  simp only [Bool.or_eq_true, beq_iff_eq, decide_eq_true_eq] at hb
  rcases hb with hb | hb
  · omega
  · exact Nat.lt_of_le_of_lt (Nat.div_le_div_right (off_mono (show a ≤ b - 1 by omega))) hb

/-- Walking pages `s ..< s + k` and taking the element of `l` in each page gives `l`, when `l`'s pages rise strictly
    inside that range. -/
theorem fm_find {β : Type} (g : Nat → Nat) (F : Nat → β) : ∀ (k s : Nat) (l : List Nat),
    l.Pairwise (fun a b => g a < g b) → (∀ x ∈ l, s ≤ g x ∧ g x < s + k) →
    (List.range' s k).filterMap (fun p => (l.find? (g · == p)).map F) = l.map F
  | 0, _, [], _, _ => rfl
  | 0, _, a :: _, _, hb => by have := hb a (List.mem_cons_self ..); omega
  | k + 1, s, [], _, _ => by
    simp [List.range'_succ, fm_find g F k (s + 1) [] List.Pairwise.nil (by simp)]
  | k + 1, s, a :: t, hp, hb => by
    have ht := List.pairwise_cons.mp hp
    have ha := hb a (List.mem_cons_self ..)
    rw [List.range'_succ, List.filterMap_cons]
    by_cases hs : g a = s
    · have hr := fm_find g F k (s + 1) t ht.2 fun x hx => by
        have := hb x (List.mem_cons_of_mem _ hx); have := ht.1 x hx; omega
      have hc : (List.range' (s + 1) k).filterMap (fun p => ((a :: t).find? (g · == p)).map F) =
          (List.range' (s + 1) k).filterMap (fun p => (t.find? (g · == p)).map F) :=
        fm_congr fun p hp => by
          have := (List.mem_range'_1.mp hp).1
          simp [List.find?_cons, show (g a == p) = false by simp; omega]
      have hs' : (a :: t).find? (g · == s) = some a := by simp [List.find?_cons, hs]
      rw [hs', Option.map_some, hc, hr, List.map_cons]
    · have hn : (a :: t).find? (g · == s) = none := List.find?_eq_none.mpr fun x hx => by
        rcases List.mem_cons.mp hx with rfl | hx
        · simp; omega
        · have := ht.1 x hx; simp; omega
      rw [hn, Option.map_none]
      exact fm_find g F k (s + 1) (a :: t) hp fun x hx => by
        rcases List.mem_cons.mp hx with rfl | hx
        · omega
        · have := hb x (List.mem_cons_of_mem _ hx); have := ht.1 x hx; omega

theorem pagesN_len (f : Nat) : ∀ (d : Bytes) (p : Nat), d.length ≤ f → p * pageSize < d.length →
    p < (pagesN f d).length := by
  induction f with
  | zero => intro d p h hp; exact absurd (Nat.lt_of_lt_of_le hp h) (Nat.not_lt_zero _)
  | succ f ih =>
    intro d p h hp
    have hl : 0 < d.length := Nat.lt_of_le_of_lt (Nat.zero_le _) hp
    have he : d.isEmpty = false := by
      cases d with
      | nil => exact absurd hl (Nat.lt_irrefl 0)
      | cons => rfl
    rw [pagesN, he, if_neg Bool.false_ne_true, List.length_cons]
    cases p with
    | zero => exact Nat.succ_pos _
    | succ p =>
      have hd : (d.drop pageSize).length = d.length - pageSize := List.length_drop ..
      have h1 : (d.drop pageSize).length ≤ f := by rw [hd]; unfold pageSize; omega
      have h2 : p * pageSize < (d.drop pageSize).length := by
        rw [hd]; rw [Nat.add_mul, Nat.one_mul] at hp; omega
      exact Nat.succ_lt_succ (ih _ p h1 h2)

/-- Every indexed row starts in a page of its chunk. -/
private theorem pidx_page_lt {H : Bytes → Bytes} {kh : Bytes → UInt64} {ws : List Row} {x : Nat} (hx : x ∈ pidx ws) :
    off ws x / pageSize < (encChunk H kh ws).pages.length := by
  have h1 : off ws x ≤ off ws ws.length := off_mono (Nat.le_of_lt (pidx_lt hx))
  have h2 : off ws ws.length = (ws.flatMap encRow).length := by simp [off]
  have h3 := leb_length_pos 0
  have h4 := Nat.div_mul_le_self (off ws x) pageSize
  have h5 : off ws x / pageSize * pageSize < (encData ws).length := by
    simp only [encData, List.length_append]; omega
  exact pagesN_len _ _ _ (Nat.le_refl _) h5

/-- The marks a chunk records with an offset inside their page are its page index, each with its row's key hash
    and `fresh` flag (the row before has another key hash): a lookup's window computed from the metadata is the one
    computed from the rows. -/
theorem marks_index {H : Bytes → Bytes} {kh : Bytes → UInt64} {c : Chunk} {ws : List Row}
    (h : decChunk H kh c = some ws) :
    c.mdata = Chunk.encMeta H kh ws c.pages ∧
    (pageMarks kh ws c.pages.length).filterMap
        (fun m => if m.2.1 < pageSize then some (m.2.2.1, m.1, m.2.2.2) else none) =
      (pidx ws).map fun j => (j, hashAt kh ws j, fresh kh ws j) := by
  obtain ⟨hc, -⟩ := decChunk_canon h
  subst hc
  refine ⟨rfl, ?_⟩
  unfold pageMarks
  rw [List.filterMap_map, List.range_eq_range']
  have hF : ((fun m : Nat × Nat × Nat × Bool => if m.2.1 < pageSize then some (m.2.2.1, m.1, m.2.2.2) else none) ∘
      markAt kh ws) = fun p => ((pidx ws).find? (off ws · / pageSize == p)).map
        fun j => (j, hashAt kh ws j, fresh kh ws j) := by
    funext p
    simp only [Function.comp]
    unfold markAt
    split
    · rename_i j hj; rw [hj]; simp [Nat.mod_lt _ (show 0 < pageSize by decide)]
    · rename_i hj; rw [hj]; simp
  rw [hF]
  exact fm_find _ _ _ 0 _ (pidx_pages ws) fun x hx => ⟨Nat.zero_le _, by rw [Nat.zero_add]; exact pidx_page_lt hx⟩

/-! ## Reading a window from the metadata and its pages -/

/-- The rows the marks name as the first to start in their page: `(row, start byte, fence, fresh)`. -/
def wIdx (mk : List (Nat × Nat × Nat × Bool)) : List (Nat × Nat × Nat × Bool) :=
  (List.range mk.length).filterMap fun p =>
    (mk[p]?).bind fun k => if k.2.1 < pageSize then some (k.2.2.1, p * pageSize + k.2.1, k.1, k.2.2.2) else none

/-- `loIx` read from the metadata. -/
def loF (m : CMeta) (h : Nat) : Nat :=
  (((wIdx m.marks).filter fun x => decide (x.2.2.1 < h) || (x.2.2.1 == h && x.2.2.2)).map (·.1)).foldl max 0

/-- `hiIx` read from the metadata. -/
def hiF (m : CMeta) (h : Nat) : Nat :=
  (((wIdx m.marks).filter fun x => decide (h < x.2.2.1)).map (·.1)).foldl min m.khs.length

/-- Where marked row `j` starts; `d` when no mark names it. -/
def byteAt (m : CMeta) (j d : Nat) : Nat := (((wIdx m.marks).find? (·.1 == j)).map (·.2.1)).getD d

/-- The pages holding the window of hash `h`: from where its first row starts to where its last row ends (where the
    next marked row starts, or the end of the row data). -/
def winPages (m : CMeta) (h : Nat) : List Nat :=
  let lb := byteAt m (loF m h) 0
  let hb := byteAt m (hiF m h) m.dlen
  if loF m h < hiF m h then List.range' (lb / pageSize) ((hb - 1) / pageSize + 1 - lb / pageSize) else []

/-- The window of hash `h` with its row numbers, read from metadata `m`, the chunk's committed root `rt` and its
    pages `pg`.  Refused unless `m` matches `rt` and every window page matches its SHA3-512 in `m`; only then are
    the window's bytes decoded, so no byte of a failing page is decoded. -/
def readWin (H : Bytes → Bytes) (m : CMeta) (rt : Option Bytes) (pg : Nat → Bytes) (h : Nat) :
    Option (List (Nat × Row)) :=
  if rt = some (metaRoot H m) ∧ (winPages m h).all (fun p => decide (m.phs[p]? = some (pageHash H (pg p)))) = true
  then (decRowsN (hiF m h - loF m h)
    (((winPages m h).map pg).flatten.drop (byteAt m (loF m h) 0 % pageSize))).map (ixs (loF m h))
  else none

/-- `hits` read through the chunk metadata `ms`, the committed chunk roots `rts` and the pages `pg` (`pg c p` is
    page `p` of chunk `c`); `none` is a refusal. -/
def hitsFast (H : Bytes → Bytes) (kh : Bytes → UInt64) (fs : Fs) (ms : Nat → CMeta) (rts : Nat → Option Bytes)
    (pg : Nat → Nat → Bytes) (kb : Bytes) : Option (List (Nat × Nat × Entry)) :=
  ((fs.dir.cands (kh kb)).mapM fun c =>
    if fs.inst.contains c then
      (readWin H (ms c) (rts c) (pg c) (kh kb).toNat).map fun iws => iws.filterMap fun iw =>
        if iw.2.1 = kb ∧ isDead fs.dead c iw.1 = false then some (c, iw.1, iw.2.2) else none
    else some []).map List.flatten

def lookupFast (H : Bytes → Bytes) (kh : Bytes → UInt64) (fs : Fs) (ms : Nat → CMeta) (rts : Nat → Option Bytes)
    (pg : Nat → Nat → Bytes) (kb : Bytes) : Option Entry :=
  match fs.win.get? kb with
  | some e => some e
  | none =>
    match sealGet fs kb with
    | some e => some e
    | none => (hitsFast H kh fs ms rts pg kb).map fun xs => (xs.head?.map (·.2.2)).getD Entry.empty

/-- Each key with its entry; `none` when a read is refused. -/
def readKeys (g : Rules.Key → Option Entry) (ks : List Rules.Key) : Option (List (Rules.Key × Entry)) :=
  ks.mapM fun k => (g k).map ((k, ·))

/-- `fetch` read from the store; refused when any read is. -/
def fetchFast (H : Bytes → Bytes) (kh : Bytes → UInt64) (fs : Fs) (ms : Nat → CMeta) (rts : Nat → Option Bytes)
    (pg : Nat → Nat → Bytes) (redo : List Nat) (b : List Rules.Line) : Option Fetched := do
  let ks := probeKeys b
  let u ← readKeys (fun k => lookupFast H kh fs ms rts pg (skey true k)) ks
  let r ← readKeys (fun k => lookupFast H kh fs ms rts pg (skey false k)) (ks ++ round2 redo ks u)
  pure ⟨r, u, fun _ => 0, fun _ => 0⟩

def decideFast (H : Bytes → Bytes) (kh : Bytes → UInt64) (fs : Fs) (ms : Nat → CMeta) (rts : Nat → Option Bytes)
    (pg : Nat → Nat → Bytes) (fc : FCtx) (f : List Nat) (b : List Rules.Line) :
    Option (List Rules.Decision × List Rules.Line × List Rules.Line) :=
  (fetchFast H kh fs ms rts pg fc.redo b).map fun fe => decideFetched fs.hr fs.hu fe fc f b

/-- The pages a lookup of `kb` may read: its window in each installed chunk the directory names. -/
def pagesRead (kh : Bytes → UInt64) (fs : Fs) (ms : Nat → CMeta) (kb : Bytes) : Nat :=
  ((fs.dir.cands (kh kb)).map fun c => if fs.inst.contains c then (winPages (ms c) (kh kb).toNat).length else 0).sum

/-- The reader's inputs are the store's: each installed chunk's metadata is its chunk's, its committed root is its
    chunk's root, and each of its pages reads as written. -/
def ReadsOk (H : Bytes → Bytes) (kh : Bytes → UInt64) (files : Nat → Chunk) (ms : Nat → CMeta)
    (rts : Nat → Option Bytes) (pg : Nat → Nat → Bytes) (fs : Fs) : Prop :=
  ∀ c, fs.inst.contains c = true →
    ms c = metaOf H kh (layout H kh files c) (files c).pages ∧ rts c = some (chunkRoot H (files c)) ∧
    ∀ p, p < (files c).pages.length → (files c).pages[p]? = some (pg c p)

/-! ### The window from the metadata is the window from the rows -/

def G (kh : Bytes → UInt64) (ws : List Row) (j : Nat) : Nat × Nat × Nat × Bool :=
  (j, off ws j, hashAt kh ws j, fresh kh ws j)

theorem wIdx_eq {H : Bytes → Bytes} {kh : Bytes → UInt64} {c : Chunk} {ws : List Row}
    (hd : decChunk H kh c = some ws) : wIdx (metaOf H kh ws c.pages).marks = (pidx ws).map (G kh ws) := by
  obtain ⟨hc, -⟩ := decChunk_canon hd
  subst hc
  unfold wIdx
  have hn : (metaOf H kh ws (encChunk H kh ws).pages).marks.length = (encChunk H kh ws).pages.length := by
    simp [metaOf, pageMarks]
  rw [hn, fm_congr (f' := fun p => ((pidx ws).find? (off ws · / pageSize == p)).map (G kh ws)) fun p hp => ?_,
    List.range_eq_range']
  · exact fm_find _ _ _ 0 _ (pidx_pages ws) fun x hx => ⟨Nat.zero_le _, by rw [Nat.zero_add]; exact pidx_page_lt hx⟩
  · have hp := List.mem_range.mp hp
    rw [show (metaOf H kh ws (encChunk H kh ws).pages).marks[p]? = some (markAt kh ws p) by
      simp [metaOf, pageMarks, hp]]
    dsimp only [Option.bind]
    unfold markAt
    split
    · rename_i j hj
      have hq := List.find?_some hj
      simp only [beq_iff_eq] at hq
      subst hq
      rw [hj, if_pos (Nat.mod_lt _ (by decide))]
      simp [G, Nat.div_add_mod']
    · rename_i hj; rw [hj]; simp

private theorem find_map_fst (G : Nat → Nat × Nat × Nat × Bool) (hG : ∀ i, (G i).1 = i) (j : Nat) :
    ∀ l : List Nat, (l.map G).find? (·.1 == j) = if j ∈ l then some (G j) else none
  | [] => by simp
  | a :: l => by
    by_cases e : a = j
    · subst e; simp [hG]
    · simp [hG, e, Ne.symm e, find_map_fst G hG j l]

private theorem filter_map_fst (G : Nat → Nat × Nat × Nat × Bool) (hG : ∀ i, (G i).1 = i)
    (p : Nat × Nat × Nat × Bool → Bool) : ∀ l : List Nat, ((l.map G).filter p).map (·.1) = l.filter fun i => p (G i)
  | [] => rfl
  | a :: l => by by_cases hp : p (G a) = true <;> simp [hp, hG, filter_map_fst G hG p l]

theorem byteAt_of {H : Bytes → Bytes} {kh : Bytes → UInt64} {c : Chunk} {ws : List Row}
    (hd : decChunk H kh c = some ws) (j d : Nat) :
    byteAt (metaOf H kh ws c.pages) j d = if j ∈ pidx ws then off ws j else d := by
  unfold byteAt
  rw [wIdx_eq hd, find_map_fst (G kh ws) (fun _ => rfl)]
  by_cases hj : j ∈ pidx ws <;> simp [hj, G]

theorem loF_eq {H : Bytes → Bytes} {kh : Bytes → UInt64} {c : Chunk} {ws : List Row}
    (hd : decChunk H kh c = some ws) (h : Nat) : loF (metaOf H kh ws c.pages) h = loIx kh ws h := by
  unfold loF loIx
  rw [wIdx_eq hd, filter_map_fst (G kh ws) (fun _ => rfl)]
  congr 2
  funext j
  show (decide (hashAt kh ws j < h) || (hashAt kh ws j == h && fresh kh ws j)) = loQ kh ws h j
  unfold loQ fresh
  by_cases e : hashAt kh ws j = h
  · subst e; rfl
  · rw [show (hashAt kh ws j == h) = false by simp [e]]; rfl

theorem hiF_eq {H : Bytes → Bytes} {kh : Bytes → UInt64} {c : Chunk} {ws : List Row}
    (hd : decChunk H kh c = some ws) (h : Nat) : hiF (metaOf H kh ws c.pages) h = hiIx kh ws h := by
  unfold hiF hiIx
  rw [wIdx_eq hd, filter_map_fst (G kh ws) (fun _ => rfl)]
  simp [metaOf, G] <;> rfl

theorem lb_eq {H : Bytes → Bytes} {kh : Bytes → UInt64} {c : Chunk} {ws : List Row}
    (hd : decChunk H kh c = some ws) (h : Nat) :
    byteAt (metaOf H kh ws c.pages) (loIx kh ws h) 0 = off ws (loIx kh ws h) := by
  rw [byteAt_of hd]
  split
  · rfl
  · rename_i hn
    rcases foldl_max_mem ((pidx ws).filter (loQ kh ws h)) 0 with e | e
    · unfold loIx; rw [e]; simp [off]
    · exact absurd (List.mem_filter.mp e).1 hn

theorem hb_eq {H : Bytes → Bytes} {kh : Bytes → UInt64} {c : Chunk} {ws : List Row}
    (hd : decChunk H kh c = some ws) (h : Nat) :
    byteAt (metaOf H kh ws c.pages) (hiIx kh ws h) (metaOf H kh ws c.pages).dlen = off ws (hiIx kh ws h) := by
  rw [byteAt_of hd]
  split
  · rfl
  · rename_i hn
    rcases foldl_min_mem ((pidx ws).filter fun j => h < hashAt kh ws j) ws.length with e | e
    · unfold hiIx; rw [e]; simp [off, metaOf]
    · exact absurd (List.mem_filter.mp e).1 hn

private theorem winPages_eq {H : Bytes → Bytes} {kh : Bytes → UInt64} {c : Chunk} {ws : List Row}
    (hd : decChunk H kh c = some ws) (h : Nat) : winPages (metaOf H kh ws c.pages) h = pagesIn kh ws h := by
  simp only [winPages, pagesIn, loF_eq hd, hiF_eq hd, lb_eq hd, hb_eq hd]

/-! ### Rows and pages -/

private theorem ixs_append : ∀ (i : Nat) (a b : List Row), ixs i (a ++ b) = ixs i a ++ ixs (i + a.length) b
  | i, [], b => by simp [ixs]
  | i, x :: a, b => by
    simp only [List.cons_append, ixs, ixs_append (i + 1) a b, List.length_cons, List.cons_append]
    rw [show i + (a.length + 1) = i + 1 + a.length by omega]

private theorem ixs_bound {i n : Nat} {l : List Row} {w : Row} (h : (n, w) ∈ ixs i l) : i ≤ n ∧ n < i + l.length := by
  obtain ⟨h1, h2⟩ := (mem_ixs l i n w).mp h
  have := (List.getElem?_eq_some_iff.mp h2).1
  omega

/-- The rows of a window, with their numbers, are the rows `lo ..< hi`. -/
theorem ixs_win (ws : List Row) (lo hi : Nat) (hh : hi ≤ ws.length) :
    (ixs 0 ws).filter (fun iw => decide (lo ≤ iw.1) && decide (iw.1 < hi)) = ixs lo ((ws.drop lo).take (hi - lo)) := by
  by_cases hl : hi ≤ lo
  · rw [show hi - lo = 0 by omega, List.take_zero]
    exact List.filter_eq_nil_iff.mpr fun x _ => by simp; omega
  · have e : ws = ws.take lo ++ ((ws.drop lo).take (hi - lo) ++ (ws.drop lo).drop (hi - lo)) := by
      rw [List.take_append_drop, List.take_append_drop]
    have l1 : (ws.take lo).length = lo := by simp; omega
    have l2 : ((ws.drop lo).take (hi - lo)).length = hi - lo := by simp; omega
    have f1 : (ixs 0 (ws.take lo)).filter (fun iw => decide (lo ≤ iw.1) && decide (iw.1 < hi)) = [] :=
      List.filter_eq_nil_iff.mpr fun ⟨n, w⟩ hx => by have := ixs_bound hx; simp; omega
    have f2 : (ixs lo ((ws.drop lo).take (hi - lo))).filter (fun iw => decide (lo ≤ iw.1) && decide (iw.1 < hi)) =
        ixs lo ((ws.drop lo).take (hi - lo)) :=
      List.filter_eq_self.mpr fun ⟨n, w⟩ hx => by have := ixs_bound hx; simp; omega
    have f3 : (ixs (lo + (hi - lo)) ((ws.drop lo).drop (hi - lo))).filter
        (fun iw => decide (lo ≤ iw.1) && decide (iw.1 < hi)) = [] :=
      List.filter_eq_nil_iff.mpr fun ⟨n, w⟩ hx => by have := ixs_bound hx; simp; omega
    conv => lhs; rw [e]
    rw [ixs_append, ixs_append, l1, l2, Nat.zero_add, List.filter_append, List.filter_append, f1, f2, f3]
    simp

theorem pagesN_sizes : ∀ (f : Nat) (d : Bytes), ∀ p ∈ pagesN f d, p.length = pageSize
  | 0, _, p, hp => by simp [pagesN] at hp
  | f + 1, d, p, hp => by
    unfold pagesN at hp
    split at hp
    · simp at hp
    · rcases List.mem_cons.mp hp with rfl | hp
      · simp only [List.length_append, List.length_take, List.length_replicate]; omega
      · exact pagesN_sizes f _ p hp

private theorem flatten_drop {L : List Bytes} (hL : ∀ p ∈ L, p.length = pageSize) :
    ∀ a, (L.drop a).flatten = L.flatten.drop (a * pageSize) := by
  induction L with
  | nil => simp
  | cons x L ih =>
    intro a
    have hx := hL x (List.mem_cons_self ..)
    cases a with
    | zero => simp
    | succ a =>
      rw [List.drop_succ_cons, ih (fun p hp => hL p (List.mem_cons_of_mem _ hp)), List.flatten_cons,
        List.drop_append, List.drop_of_length_le (l := x) (by rw [hx, Nat.add_mul, Nat.one_mul]; omega),
        List.nil_append, hx, Nat.add_mul, Nat.one_mul, Nat.add_sub_cancel]

private theorem flatten_take {L : List Bytes} (hL : ∀ p ∈ L, p.length = pageSize) :
    ∀ k, (L.take k).flatten = L.flatten.take (k * pageSize) := by
  induction L with
  | nil => simp
  | cons x L ih =>
    intro k
    have hx := hL x (List.mem_cons_self ..)
    cases k with
    | zero => simp
    | succ k =>
      rw [List.take_succ_cons, List.flatten_cons, List.flatten_cons,
        ih (fun p hp => hL p (List.mem_cons_of_mem _ hp)), List.take_append,
        List.take_of_length_le (l := x) (by rw [hx, Nat.add_mul, Nat.one_mul]; omega), hx, Nat.add_mul, Nat.one_mul,
        Nat.add_sub_cancel]

/-- Pages `a ..< a + k` of a chunk are its bytes from `a * pageSize`, `k * pageSize` of them. -/
theorem pages_slice {L : List Bytes} (hL : ∀ p ∈ L, p.length = pageSize) (a k : Nat) :
    ((L.drop a).take k).flatten = (L.flatten.drop (a * pageSize)).take (k * pageSize) := by
  rw [flatten_take (fun p hp => hL p (List.mem_of_mem_drop hp)), flatten_drop hL]

theorem range'_map {L : List Bytes} {pg : Nat → Bytes} : ∀ (a k : Nat), a + k ≤ L.length →
    (∀ p, p < L.length → L[p]? = some (pg p)) → (List.range' a k).map pg = (L.drop a).take k
  | _, 0, _, _ => by simp
  | a, k + 1, hl, hp => by
    rw [List.range'_succ, List.map_cons, range'_map (a + 1) k (by omega) hp,
      List.drop_eq_getElem_cons (show a < L.length by omega), List.take_succ_cons]
    have e := hp a (by omega)
    rw [List.getElem?_eq_getElem (show a < L.length by omega)] at e
    rw [Option.some.inj e]

private theorem decRowsN_enc : ∀ (ws : List Row) (r : Bytes), (∀ w ∈ ws, w.2.Wf) →
    decRowsN ws.length (ws.flatMap encRow ++ r) = some ws
  | [], _, _ => rfl
  | w :: ws, r, hw => by
    have ht : takeN (encBody w).length (encBody w ++ (ws.flatMap encRow ++ r)) =
        some (encBody w, ws.flatMap encRow ++ r) := takeN_app _ _ _ rfl
    have ih := decRowsN_enc ws r fun x hx => hw x (List.mem_cons_of_mem _ hx)
    simp only [List.flatMap_cons, encRow, List.append_assoc] at ht ih ⊢
    simp [decRowsN, unleb_leb, ht, decBody_enc w (hw w (List.mem_cons_self ..)), ih]

/-- From the byte where row `lo` starts, with at least the bytes of rows `lo ..< lo + k`, decoding exactly `k` rows
    gives those rows, whatever bytes follow. -/
theorem rows_mid {ws : List Row} (hw : ∀ w ∈ ws, w.2.Wf) {lo k n : Nat} (hk : lo + k ≤ ws.length)
    (hn : off ws (lo + k) ≤ off ws lo + n) (z : Bytes) :
    decRowsN k (((ws.flatMap encRow ++ z).drop (off ws lo)).take n) = some ((ws.drop lo).take k) := by
  have e1 : ws.flatMap encRow = (ws.take lo).flatMap encRow ++
      (((ws.drop lo).take k).flatMap encRow ++ ((ws.drop lo).drop k).flatMap encRow) := by
    rw [← List.flatMap_append, List.take_append_drop, ← List.flatMap_append, List.take_append_drop]
  have e2 : off ws (lo + k) = off ws lo + (((ws.drop lo).take k).flatMap encRow).length := by
    simp only [off, List.take_add, List.flatMap_append, List.length_append]
  have hl : ((ws.drop lo).take k).length = k := by simp; omega
  have hW : ∀ w ∈ (ws.drop lo).take k, w.2.Wf := fun w hm => hw w (List.mem_of_mem_drop (List.mem_of_mem_take hm))
  have := decRowsN_enc ((ws.drop lo).take k) ((((ws.drop lo).drop k).flatMap encRow ++ z).take
    (n - (((ws.drop lo).take k).flatMap encRow).length)) hW
  rw [hl] at this
  rw [e1, List.append_assoc, List.append_assoc,
    show off ws lo = ((ws.take lo).flatMap encRow).length from rfl, List.drop_left,
    List.take_append, List.take_of_length_le (by omega)]
  exact this

/-! ### The fast read is the spec read -/

theorem readWin_ok {H : Bytes → Bytes} {kh : Bytes → UInt64} {c : Chunk} {ws : List Row} {pg : Nat → Bytes}
    (hd : decChunk H kh c = some ws) (hW : ∀ w ∈ ws, w.2.Wf)
    (hpg : ∀ p, p < c.pages.length → c.pages[p]? = some (pg p)) (h : Nat) :
    readWin H (metaOf H kh ws c.pages) (some (chunkRoot H c)) pg h = some ((ixs 0 ws).filter (inWin kh ws h)) := by
  have hwp := winPages_eq hd h
  have hlo := loF_eq hd h
  have hhi := hiF_eq hd h
  have hlb := lb_eq hd h
  have hhl : hiIx kh ws h ≤ ws.length := (foldl_min_le _ _).1
  obtain ⟨hc, -⟩ := decChunk_canon hd
  subst hc
  have hroot : chunkRoot H (encChunk H kh ws) = metaRoot H (metaOf H kh ws (encChunk H kh ws).pages) := rfl
  obtain ⟨z, hz⟩ := pagesN_flatten (encData ws).length (encData ws) (Nat.le_refl _)
  have hfl : (encChunk H kh ws).pages.flatten = ws.flatMap encRow ++ (leb 0 ++ List.replicate z 0) := by
    rw [show (encChunk H kh ws).pages.flatten = encData ws ++ List.replicate z 0 from hz, encData, List.append_assoc]
  have hsz : ∀ p ∈ (encChunk H kh ws).pages, p.length = pageSize := pagesN_sizes _ _
  have hinW : inWin kh ws h = fun iw => decide (loIx kh ws h ≤ iw.1) && decide (iw.1 < hiIx kh ws h) := rfl
  rw [hinW, ixs_win ws _ _ hhl]
  unfold readWin
  rw [hwp, hlo, hhi, hlb]
  by_cases hlh : loIx kh ws h < hiIx kh ws h
  · have hpin : pagesIn kh ws h = List.range' (off ws (loIx kh ws h) / pageSize)
        ((off ws (hiIx kh ws h) - 1) / pageSize + 1 - off ws (loIx kh ws h) / pageSize) := by
      unfold pagesIn; dsimp only; rw [if_pos hlh]
    rw [hpin]
    generalize loIx kh ws h = lo at *
    generalize hiIx kh ws h = hi at *
    have hlt : off ws lo < off ws hi := by
      have e := off_succ (List.getElem?_eq_getElem (show lo < ws.length by omega))
      have := off_mono (ws := ws) (show lo + 1 ≤ hi by omega)
      have := encRow_length_pos ws[lo]
      omega
    have hend : off ws hi < (encData ws).length := by
      have := off_mono (ws := ws) hhl
      have := leb_length_pos 0
      simp only [encData, List.length_append, off, List.take_length] at *
      omega
    have hpe : (off ws hi - 1) / pageSize < (encChunk H kh ws).pages.length :=
      pagesN_len _ _ _ (Nat.le_refl _) (Nat.lt_of_le_of_lt (Nat.div_mul_le_self _ _) (by omega))
    have ha : off ws lo / pageSize ≤ (off ws hi - 1) / pageSize := Nat.div_le_div_right (by omega)
    have hk : off ws lo / pageSize + ((off ws hi - 1) / pageSize + 1 - off ws lo / pageSize) ≤
        (encChunk H kh ws).pages.length := by omega
    have hall : ∀ p ∈ List.range' (off ws lo / pageSize) ((off ws hi - 1) / pageSize + 1 - off ws lo / pageSize),
        (metaOf H kh ws (encChunk H kh ws).pages).phs[p]? = some (pageHash H (pg p)) := fun p hp => by
      have hp' := (List.mem_range'_1.mp hp).2
      simp [metaOf, List.getElem?_map, hpg p (by omega)]
    rw [if_pos ⟨by rw [hroot], List.all_eq_true.mpr fun p hp => decide_eq_true (hall p hp)⟩,
      range'_map _ _ hk hpg, pages_slice hsz, hfl, List.drop_take, List.drop_drop, Nat.div_add_mod']
    have hn : off ws (lo + (hi - lo)) ≤ off ws lo + (((off ws hi - 1) / pageSize + 1 - off ws lo / pageSize) *
        pageSize - off ws lo % pageSize) := by
      rw [show lo + (hi - lo) = hi by omega]
      have := Nat.div_add_mod' (off ws lo) pageSize
      unfold pageSize at *
      omega
    rw [rows_mid hW (show lo + (hi - lo) ≤ ws.length by omega) hn]
    rfl
  · have hpin : pagesIn kh ws h = [] := by unfold pagesIn; dsimp only; rw [if_neg hlh]
    rw [hpin, if_pos ⟨by rw [hroot], rfl⟩, show hiIx kh ws h - loIx kh ws h = 0 by omega]
    rfl

private theorem mapM_some {α β : Type} {f : α → Option β} {g : α → β} :
    ∀ {l : List α}, (∀ x ∈ l, f x = some (g x)) → l.mapM f = some (l.map g)
  | [], _ => rfl
  | a :: l, h => by
    rw [List.mapM_cons, h a (List.mem_cons_self ..), mapM_some fun x hx => h x (List.mem_cons_of_mem _ hx)]
    rfl

private theorem mapM_none {α β : Type} {f : α → Option β} :
    ∀ {l : List α} {x : α}, x ∈ l → f x = none → l.mapM f = none
  | a :: l, x, hx, h => by
    rw [List.mapM_cons]
    rcases List.mem_cons.mp hx with rfl | hx
    · rw [h]; rfl
    · cases f a with
      | none => rfl
      | some _ => rw [mapM_none hx h]; rfl

private theorem hitsFast_eq {H : Bytes → Bytes} {kh : Bytes → UInt64} {fs : Fs} {files : Nat → Chunk} {s : St}
    {ms : Nat → CMeta} {rts : Nat → Option Bytes} {pg : Nat → Nat → Bytes}
    (hI : FInv H kh fs files s) (hR : ReadsOk H kh files ms rts pg fs) (kb : Bytes) :
    hitsFast H kh fs ms rts pg kb = some (hits kh fs (layout H kh files) kb) := by
  rw [hits_win_inv hI kb]
  unfold hitsFast
  rw [mapM_some (g := fun c => if fs.inst.contains c then
      ((ixs 0 (layout H kh files c)).filter (inWin kh (layout H kh files c) (kh kb).toNat)).filterMap fun iw =>
        if iw.2.1 = kb ∧ isDead fs.dead c iw.1 = false then some (c, iw.1, iw.2.2) else none
    else []) fun c _ => ?_]
  · rfl
  · by_cases hc : fs.inst.contains c = true
    · obtain ⟨hm, hr, hp⟩ := hR c hc
      obtain ⟨ws, hw⟩ := Option.isSome_iff_exists.mp (hI.2.2.1 c hc).2
      have hl : layout H kh files c = ws := by simp [layout, hw]
      have hW : ∀ w ∈ ws, w.2.Wf := fun w hm' => by
        obtain ⟨i, hi⟩ := List.mem_iff_getElem?.mp hm'
        exact hI.2.2.2.1 c i w hc (by rw [hl]; exact hi)
      simp only [hc, ↓reduceIte, hm, hr, hl]
      rw [readWin_ok hw hW hp]
      rfl
    · simp [hc]

private theorem lookupFast_eq {H : Bytes → Bytes} {kh : Bytes → UInt64} {fs : Fs} {files : Nat → Chunk} {s : St}
    {ms : Nat → CMeta} {rts : Nat → Option Bytes} {pg : Nat → Nat → Bytes}
    (hI : FInv H kh fs files s) (hR : ReadsOk H kh files ms rts pg fs) (kb : Bytes) :
    lookupFast H kh fs ms rts pg kb = some (lookup kh fs (layout H kh files) kb) := by
  unfold lookupFast lookup
  rw [hitsFast_eq hI hR kb]
  cases fs.win.get? kb with
  | some e => rfl
  | none =>
    cases sealGet fs kb with
    | some e => rfl
    | none =>
      cases hits kh fs (layout H kh files) kb with
      | nil => rfl
      | cons x t => obtain ⟨_, _, _⟩ := x; rfl

/-- Under `FInv` and `ReadsOk`, the fast fetch reads exactly the spec's entries: each key through the windows, each
    candidate chunk through its window pages only.  It reads no core counts (`St.perKey`): the store caps per key. -/
theorem fetchFast_eq {H : Bytes → Bytes} {kh : Bytes → UInt64} {fs : Fs} {files : Nat → Chunk} {s : St}
    {ms : Nat → CMeta} {rts : Nat → Option Bytes} {pg : Nat → Nat → Bytes}
    (hI : FInv H kh fs files s) (hR : ReadsOk H kh files ms rts pg fs) (redo : List Nat) (b : List Rules.Line) :
    fetchFast H kh fs ms rts pg redo b = some (fetch s.perKey redo b) := by
  rw [← view_eq hI]
  have hk : ∀ (u : Bool) (ks : List Rules.Key), readKeys (fun k => lookupFast H kh fs ms rts pg (skey u k)) ks =
      some (ks.map fun k => (k, lookup kh fs (layout H kh files) (skey u k))) := fun u ks =>
    mapM_some fun k _ => by simp [lookupFast_eq hI hR]
  simp only [fetchFast, hk]
  rfl

/-- A batch's fetch refuses when a key it reads reaches an installed chunk whose metadata fails its committed root or
    a page of whose window fails its SHA3-512; the window's bytes are then never decoded. -/
theorem fetchFast_bad {H : Bytes → Bytes} {kh : Bytes → UInt64} {fs : Fs} {ms : Nat → CMeta}
    {rts : Nat → Option Bytes} {pg : Nat → Nat → Bytes} {redo : List Nat} {b : List Rules.Line} {k : Rules.Key}
    (hk : k ∈ probeKeys b) (u : Bool) (hw : fs.win.get? (skey u k) = none) (hs : sealGet fs (skey u k) = none)
    {c : Nat} (hc : c ∈ fs.dir.cands (kh (skey u k))) (hi : fs.inst.contains c = true)
    (hbad : rts c ≠ some (metaRoot H (ms c)) ∨
      ∃ p ∈ winPages (ms c) (kh (skey u k)).toNat, (ms c).phs[p]? ≠ some (pageHash H (pg c p))) :
    fetchFast H kh fs ms rts pg redo b = none := by
  have hr : readWin H (ms c) (rts c) (pg c) (kh (skey u k)).toNat = none := by
    unfold readWin
    rw [if_neg]
    rintro ⟨h1, h2⟩
    rcases hbad with hb | ⟨p, hp, hb⟩
    · exact hb h1
    · exact hb (of_decide_eq_true (List.all_eq_true.mp h2 p hp))
  have hh : hitsFast H kh fs ms rts pg (skey u k) = none := by
    unfold hitsFast
    rw [mapM_none hc]
    · rfl
    · simp [hi, hr]
  have hl : lookupFast H kh fs ms rts pg (skey u k) = none := by simp only [lookupFast, hw, hs, hh, Option.map_none]
  have rk : ∀ {g : Rules.Key → Option Entry} {ks : List Rules.Key}, k ∈ ks → g k = none → readKeys g ks = none :=
    fun hm hg => mapM_none hm (by simp [hg])
  unfold fetchFast
  cases u
  · cases hU : readKeys (fun k => lookupFast H kh fs ms rts pg (skey true k)) (probeKeys b) with
    | none => simp [hU]
    | some u' => simp [hU, rk (g := fun k => lookupFast H kh fs ms rts pg (skey false k))
      (List.mem_append_left (round2 redo (probeKeys b) u') hk) hl]
  · simp [rk (g := fun k => lookupFast H kh fs ms rts pg (skey true k)) hk hl]

/-- Under `FInv` and `ReadsOk`, deciding from the fast fetch is deciding from the spec fetch. -/
theorem decideFast_eq {H : Bytes → Bytes} {kh : Bytes → UInt64} {fs : Fs} {files : Nat → Chunk} {s : St}
    {ms : Nat → CMeta} {rts : Nat → Option Bytes} {pg : Nat → Nat → Bytes}
    (hI : FInv H kh fs files s) (hR : ReadsOk H kh files ms rts pg fs) (fc : FCtx) (f : List Nat)
    (b : List Rules.Line) :
    decideFast H kh fs ms rts pg fc f b =
      some (decideFetched s.rel.head s.unr.head (fetch s.perKey fc.redo b) fc f b) := by
  rw [decideFast, fetchFast_eq hI hR, hI.1, hI.2.1]
  rfl

/-- The store decides as the per-core rule except on lines whose core holds more than `capN` rows in either set: the
    per-core decisions are the store's, made HOLD with `POSTING_CAP` (`capD`) on exactly those lines. -/
theorem decideFast_perCore {H : Bytes → Bytes} {kh : Bytes → UInt64} {fs : Fs} {files : Nat → Chunk} {s : St}
    {ms : Nat → CMeta} {rts : Nat → Option Bytes} {pg : Nat → Nat → Bytes}
    (hI : FInv H kh fs files s) (hR : ReadsOk H kh files ms rts pg fs) (fc : FCtx) (f : List Nat)
    (b : List Rules.Line) :
    ∃ r, decideFast H kh fs ms rts pg fc f b = some r ∧ (decideBatchIdx s fc f b).1 = r.1.map fun d =>
      if capN < s.rel.core (coreKey d.line) || capN < s.unr.core (coreKey d.line) then OnepIndex.capD d else d :=
  ⟨_, decideFast_eq hI hR fc f b, decide_perCore s fc f b⟩

/-- The pages one key's lookup reads: at most `q + 1` per candidate chunk when no row is longer than `q` pages and no
    installed chunk holds another row of the key's hash, so at most `(2 * 4 + stashCap) * 2 = 32` when no row spans
    more than one page. -/
theorem pagesRead_le {H : Bytes → Bytes} {kh : Bytes → UInt64} {fs : Fs} {files : Nat → Chunk} {s : St}
    {ms : Nat → CMeta} {rts : Nat → Option Bytes} {pg : Nat → Nat → Bytes}
    (hI : FInv H kh fs files s) (hR : ReadsOk H kh files ms rts pg fs) (kb : Bytes) (q : Nat)
    (hP : ∀ c, fs.inst.contains c = true → ∀ w ∈ layout H kh files c, (encRow w).length ≤ q * pageSize)
    (hU : ∀ c, fs.inst.contains c = true → ∀ i j, i < (layout H kh files c).length → j < (layout H kh files c).length →
      hashAt kh (layout H kh files c) i = (kh kb).toNat → hashAt kh (layout H kh files c) j = (kh kb).toNat → i = j) :
    pagesRead kh fs ms kb ≤ (2 * 4 + stashCap) * (q + 1) := by
  unfold pagesRead
  refine Nat.le_trans (sum_le (b := q + 1) _ fun x hx => ?_) ?_
  · obtain ⟨c, -, rfl⟩ := List.mem_map.mp hx
    split
    · rename_i hc
      obtain ⟨ws, hw⟩ := Option.isSome_iff_exists.mp (hI.2.2.1 c hc).2
      have hl : layout H kh files c = ws := by simp [layout, hw]
      have hP' := hP c hc
      have hU' := hU c hc
      rw [hl] at hP' hU'
      rw [(hR c hc).1, hl, winPages_eq hw]
      exact pagesIn_le_q hP' hU'
    · exact Nat.zero_le _
  · rw [List.length_map]
    exact Nat.mul_le_mul_right _ (read_bound hI (kh kb)).2.2

end BlindLedger.Gate.Flat.Store
