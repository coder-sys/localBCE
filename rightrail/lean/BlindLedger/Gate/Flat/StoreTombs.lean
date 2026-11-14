import BlindLedger.Gate.Flat.StoreTheorems

/-! The dead bits on disk: metadata v2 reads back what it wrote, and the dead bits load sets from the chunk files'
    tombstones (`deadOf`) are the store's own (`fs.dead`) at every step of a run that writes the tombstones `Store.lean`
    names: apply, seal, place, directory growth and reclaim keep `BInv`.  Synthetic, nonpayment, non-PHI,
    activation=false. -/

namespace BlindLedger.Gate.Flat.Store

open Chunk
open BlindLedger.Gate.OnepIndex (leb unleb unleb_leb)
open BlindLedger.Gate.Rules
open Std (HashMap HashSet)

/-! ## Metadata v2 -/

theorem decTombs_enc : ∀ (ts : List Tomb) (r : Bytes), decTombs ts.length (ts.flatMap encTomb ++ r) = some (ts, r)
  | [], r => rfl
  | t :: ts, r => by
    simp [decTombs, encTomb, List.append_assoc, unleb_leb, decTombs_enc ts r]

theorem decMeta2_enc (m : Bytes) (seq : Nat) (ts : List Tomb) :
    decMeta2 (encMeta2 m seq ts) = some (m, seq, ts) := by
  have ht := decTombs_enc ts []
  rw [List.append_nil] at ht
  have hm : takeN m.length (m ++ (leb seq ++ leb ts.length ++ ts.flatMap encTomb)) =
      some (m, leb seq ++ leb ts.length ++ ts.flatMap encTomb) := by simp [takeN]
  simp only [decMeta2, encMeta2, List.append_assoc] at hm ⊢
  simp [unleb_leb, hm, ht]

/-! ## The chunk store's chain step -/

theorem decBs_enc (b r : Bytes) : decBs (encBs b ++ r) = some (b, r) := by
  simp [decBs, encBs, List.append_assoc, unleb_leb, takeN_app]

theorem decHead_enc (h : Head) (r : Bytes) : decHead (encHead h ++ r) = some (h, r) := by
  simp [decHead, encHead, List.append_assoc, unleb_leb]

theorem decKhs_enc : ∀ (ks : List Nat) (r : Bytes), (∀ k ∈ ks, k < 2 ^ 64) →
    decKhs ks.length (ks.flatMap (natBE 8) ++ r) = some (ks, r)
  | [], r, _ => rfl
  | k :: ks, r, h => by
    have hk : k < 256 ^ 8 := by have := h k (by simp); simpa using this
    have hs := decKhs_enc ks r (fun x hx => h x (by simp [hx]))
    have hl : (natBE 8 k).length = 8 := by simp [natBE]
    simp only [List.length_cons, List.flatMap_cons, List.append_assoc, decKhs]
    rw [takeNFast_eq, takeN_app 8 _ _ hl]
    simp [hs, beNat_natBE' 8 k hk]

theorem decMarks_enc : ∀ (ms : List (Nat × Nat × Nat × Bool)) (r : Bytes),
    decMarks ms.length (ms.flatMap encMark ++ r) = some (ms, r)
  | [], r => rfl
  | (f, o, j, fr) :: ms, r => by
    have hs := decMarks_enc ms r
    cases fr <;>
      simp [decMarks, encMark, List.append_assoc, unleb_leb, takeN, hs]

theorem decBss_enc : ∀ (ps : List Bytes) (r : Bytes),
    decBss ps.length ((ps.flatMap fun p => leb p.length ++ p) ++ r) = some (ps, r)
  | [], r => rfl
  | p :: ps, r => by
    have hs := decBss_enc ps r
    have hb := decBs_enc p ((ps.flatMap fun p => leb p.length ++ p) ++ r)
    simp only [encBs, List.append_assoc] at hb
    simp only [List.length_cons, List.flatMap_cons, List.append_assoc, decBss]
    rw [hb]
    simp [hs]

/-- Chunk metadata reads back as written, once every stored key hash fits eight bytes (those of `kh` do). -/
theorem decM_encM (m : CMeta) (h : ∀ k ∈ m.khs, k < 2 ^ 64) : decM (encM m) = some m := by
  have h1 := decKhs_enc m.khs (leb m.dlen ++ (leb m.marks.length ++ (m.marks.flatMap encMark ++
    (leb m.phs.length ++ (m.phs.flatMap fun p => leb p.length ++ p))))) h
  have h2 := decMarks_enc m.marks (leb m.phs.length ++ (m.phs.flatMap fun p => leb p.length ++ p))
  have h3 := decBss_enc m.phs []
  rw [List.append_nil] at h3
  simp only [decM, encM, List.append_assoc]
  simp [unleb_leb, h1, h2, h3]

/-- The chunk store's chain step binds the state root: equal heads from heads and batch digests of equal lengths
    mean the same head before, batch digest and state root, or two distinct step inputs with one SHA3-512 digest. -/
theorem chainStepR_binds (H : Bytes → Bytes) {D D' bd bd' rb rb' : Bytes} (hD : D.length = D'.length)
    (hb : bd.length = bd'.length) (h : chainStepR H D bd rb = chainStepR H D' bd' rb') :
    (D = D' ∧ bd = bd' ∧ rb = rb') ∨
      (domain "CHAIN" ++ [0x02] ++ D ++ bd ++ rb ≠ domain "CHAIN" ++ [0x02] ++ D' ++ bd' ++ rb' ∧
        H (domain "CHAIN" ++ [0x02] ++ D ++ bd ++ rb) = H (domain "CHAIN" ++ [0x02] ++ D' ++ bd' ++ rb')) := by
  by_cases e : domain "CHAIN" ++ [0x02] ++ D ++ bd ++ rb = domain "CHAIN" ++ [0x02] ++ D' ++ bd' ++ rb'
  · left
    simp only [List.append_assoc] at e
    obtain ⟨h1, e⟩ := List.append_inj (List.append_cancel_left (List.append_cancel_left e)) hD
    obtain ⟨h2, h3⟩ := List.append_inj e hb
    exact ⟨h1, h2, h3⟩
  · exact Or.inr ⟨e, h⟩

/-- The batch digest binds the authority record: equal digests mean the same record (so the same key-set pin, key-set
    epoch and grant floor) and the same appended rows, or two distinct inputs with one SHA3-512 digest. -/
theorem batchDigest_binds (H : Bytes → Bytes) {au au' : Bytes} {d d' : List Line × List Line}
    (h : batchDigest H au d = batchDigest H au' d') :
    (au = au' ∧ d = d') ∨
      (domain "CHAIN" ++ [0x03] ++ leb au.length ++ au ++ encDelta d ≠
          domain "CHAIN" ++ [0x03] ++ leb au'.length ++ au' ++ encDelta d' ∧
        H (domain "CHAIN" ++ [0x03] ++ leb au.length ++ au ++ encDelta d) =
          H (domain "CHAIN" ++ [0x03] ++ leb au'.length ++ au' ++ encDelta d')) := by
  by_cases e : domain "CHAIN" ++ [0x03] ++ leb au.length ++ au ++ encDelta d =
      domain "CHAIN" ++ [0x03] ++ leb au'.length ++ au' ++ encDelta d'
  · left
    simp only [List.append_assoc] at e
    obtain ⟨hl, e⟩ := leb_inj (List.append_cancel_left (List.append_cancel_left e))
    obtain ⟨h1, e⟩ := List.append_inj e hl
    exact ⟨h1, encDelta_inj e⟩
  · exact Or.inr ⟨e, h⟩

/-! ## Tombstones -/

private theorem ex_cons {α : Type} {p : α → Prop} {a : α} {l : List α} :
    (∃ x ∈ a :: l, p x) ↔ p a ∨ ∃ x ∈ l, p x := by
  constructor
  · rintro ⟨x, hx, h⟩
    rcases List.mem_cons.mp hx with rfl | hx
    · exact .inl h
    · exact .inr ⟨x, hx, h⟩
  · rintro (h | ⟨x, hx, h⟩)
    · exact ⟨a, List.mem_cons_self .., h⟩
    · exact ⟨x, List.mem_cons_of_mem _ hx, h⟩

theorem isDead_empty (c i : Nat) : isDead (∅ : HashMap Nat (HashSet Nat)) c i = false := by
  simp [isDead]

theorem isDead_insert (d : HashMap Nat (HashSet Nat)) (c : Nat) (S : HashSet Nat) (c' i : Nat) :
    isDead (d.insert c S) c' i = if c = c' then S.contains i else isDead d c' i := by
  unfold isDead
  rw [Std.HashMap.get?_insert]
  by_cases h : c = c' <;> simp [h]

theorem current_iff {L : Book} {t : Tomb} : current L t = true ↔ ∃ x ∈ L, x.1 = t.c ∧ x.2.1 = t.seq := by
  simp [current]

private theorem fold_dead (L : Book) (c i : Nat) : ∀ (ts : List Tomb) (d : HashMap Nat (HashSet Nat)),
    isDead (ts.foldl (fun d t => if current L t then kill d t.c t.i else d) d) c i = true ↔
      isDead d c i = true ∨ ∃ t ∈ ts, current L t = true ∧ t.c = c ∧ t.i = i
  | [], d => by simp
  | t :: ts, d => by
    rw [List.foldl_cons, fold_dead L c i ts, ex_cons]
    by_cases ht : current L t = true
    · rw [if_pos ht, isDead_kill]
      constructor
      · rintro ((⟨h1, h2⟩ | h) | h)
        · exact .inr (.inl ⟨ht, h1, h2⟩)
        · exact .inl h
        · exact .inr (.inr h)
      · rintro (h | ⟨-, h1, h2⟩ | h)
        · exact .inl (.inr h)
        · exact .inl (.inl ⟨h1, h2⟩)
        · exact .inr h
    · rw [if_neg ht]
      constructor
      · rintro (h | h)
        · exact .inl h
        · exact .inr (.inr h)
      · rintro (h | ⟨h0, -⟩ | h)
        · exact .inl h
        · exact absurd h0 ht
        · exact .inr h

/-- Row `i` of chunk `c` is dead by `deadOf` exactly when a current tombstone names it. -/
theorem isDead_deadOf (L : Book) (pend : List Tomb) (c i : Nat) :
    isDead (deadOf L pend) c i = true ↔
      ∃ t ∈ L.flatMap (·.2.2) ++ pend, current L t = true ∧ t.c = c ∧ t.i = i := by
  rw [deadOf, fold_dead, isDead_empty]
  simp only [Bool.false_eq_true, false_or]

private theorem kill_inner (c i : Nat) (h : UInt64) : ∀ (xs : List (Nat × Nat × Entry)) (a : HashMap Nat (HashSet Nat) × Dir),
    isDead (xs.foldl (killRow h) a).1 c i = true ↔ isDead a.1 c i = true ∨ ∃ x ∈ xs, x.1 = c ∧ x.2.1 = i
  | [], a => by simp
  | x :: xs, a => by
    rw [List.foldl_cons, kill_inner c i h xs, ex_cons]
    unfold killRow
    by_cases hd : isDead a.1 x.1 x.2.1 = true
    · rw [if_pos hd]
      constructor
      · rintro (h | h)
        · exact .inl h
        · exact .inr (.inr h)
      · rintro (h | ⟨rfl, rfl⟩ | h)
        · exact .inl h
        · exact .inl hd
        · exact .inr h
    · rw [if_neg hd]
      simp only [isDead_kill]
      constructor
      · rintro ((⟨h1, h2⟩ | h) | h)
        · exact .inr (.inl ⟨h1, h2⟩)
        · exact .inl h
        · exact .inr (.inr h)
      · rintro (h | ⟨h1, h2⟩ | h)
        · exact .inl (.inr h)
        · exact .inl (.inl ⟨h1, h2⟩)
        · exact .inr h

private theorem kill_outer (kh : Bytes → UInt64) (ks : Bytes → List (Nat × Nat × Entry)) (c i : Nat) :
    ∀ (ch : List (Bytes × Entry)) (a : HashMap Nat (HashSet Nat) × Dir),
    isDead (ch.foldl (fun a ke => (ks ke.1).foldl (killRow (kh ke.1)) a) a).1 c i = true ↔
      isDead a.1 c i = true ∨ ∃ ke ∈ ch, ∃ x ∈ ks ke.1, x.1 = c ∧ x.2.1 = i
  | [], a => by simp
  | ke :: ch, a => by
    rw [List.foldl_cons, kill_outer kh ks c i ch, kill_inner, ex_cons]
    constructor
    · rintro ((h | h) | h)
      · exact .inl h
      · exact .inr (.inl h)
      · exact .inr (.inr h)
    · rintro (h | h | h)
      · exact .inl (.inl h)
      · exact .inl (.inr h)
      · exact .inr h

theorem seqOf_mem {L : Book} {c : Nat} (h : ∃ x ∈ L, x.1 = c) :
    ∃ x ∈ L, x.1 = c ∧ x.2.1 = seqOf L c := by
  unfold seqOf
  cases hf : L.find? (·.1 == c) with
  | none =>
    exfalso
    obtain ⟨x, hx, hxc⟩ := h
    have := List.find?_eq_none.mp hf x hx
    simp [hxc] at this
  | some x =>
    have hp := List.find?_some hf
    simp only [beq_iff_eq] at hp
    exact ⟨x, List.mem_of_find?_eq_some hf, hp, rfl⟩

/-- An empty store with no files and nothing pending. -/
theorem book_init {fs : Fs} (hi : ∀ c, fs.inst.contains c = false) (hd : ∀ c i, isDead fs.dead c i = false) :
    BInv fs [] [] 0 := by
  refine ⟨fun c => by simp [hi c], List.nodup_nil, by simp, by simp, fun c i => ?_⟩
  rw [hd]; exact (isDead_empty c i).symm

/-- `BInv` reads only the installed set and the dead bits: sealing and directory growth keep it. -/
theorem book_congr {fs fs' : Fs} {L : Book} {pend : List Tomb} {nx : Nat} (hi : fs'.inst = fs.inst)
    (hd : fs'.dead = fs.dead) (hB : BInv fs L pend nx) : BInv fs' L pend nx := by
  rw [BInv, hi, hd]; exact hB

/-- Killing rows of installed chunks, with their tombstones pending, keeps `BInv`. -/
theorem kills_book {kh : Bytes → UInt64} {fs fs' : Fs} {L : Book} {pend : List Tomb} {nx : Nat}
    (ks : Bytes → List (Nat × Nat × Entry)) (ch : List (Bytes × Entry)) (hB : BInv fs L pend nx)
    (hk : ∀ ke ∈ ch, ∀ x ∈ ks ke.1, fs.inst.contains x.1 = true) (hi : fs'.inst = fs.inst)
    (hd : fs'.dead = (ch.foldl (fun a ke => (ks ke.1).foldl (killRow (kh ke.1)) a) (fs.dead, fs.dir)).1) :
    BInv fs' L (pend ++ ch.flatMap fun ke => (ks ke.1).map fun x => ⟨x.1, seqOf L x.1, x.2.1⟩) nx := by
  obtain ⟨hI, hN, hS, hT, hD⟩ := hB
  have hinst : ∀ {ke : Bytes × Entry} {x : Nat × Nat × Entry}, ke ∈ ch → x ∈ ks ke.1 → ∃ y ∈ L, y.1 = x.1 :=
    fun hke hx => (hI _).mp (hk _ hke _ hx)
  have hmem : ∀ {t : Tomb}, t ∈ ch.flatMap (fun ke => (ks ke.1).map fun x => (⟨x.1, seqOf L x.1, x.2.1⟩ : Tomb)) ↔
      ∃ ke ∈ ch, ∃ x ∈ ks ke.1, (⟨x.1, seqOf L x.1, x.2.1⟩ : Tomb) = t := by
    intro t; simp only [List.mem_flatMap, List.mem_map]
  refine ⟨fun c => by rw [hi]; exact hI c, hN, hS, fun t ht => ?_, fun c i => Bool.eq_iff_iff.mpr ?_⟩
  · rw [← List.append_assoc, List.mem_append] at ht
    rcases ht with ht | ht
    · exact hT t ht
    · obtain ⟨ke, hke, x, hx, rfl⟩ := hmem.mp ht
      obtain ⟨y, hy, -, hs⟩ := seqOf_mem (hinst hke hx)
      exact hs ▸ hS y hy
  · rw [hd, kill_outer, hD c i, isDead_deadOf, isDead_deadOf, ← List.append_assoc]
    constructor
    · rintro (⟨t, ht, h⟩ | ⟨ke, hke, x, hx, h1, h2⟩)
      · exact ⟨t, List.mem_append_left _ ht, h⟩
      · obtain ⟨y, hy, hy1, hy2⟩ := seqOf_mem (hinst hke hx)
        exact ⟨⟨x.1, seqOf L x.1, x.2.1⟩, List.mem_append_right _ (hmem.mpr ⟨ke, hke, x, hx, rfl⟩),
          current_iff.mpr ⟨y, hy, hy1, hy2⟩, h1, h2⟩
    · rintro ⟨t, ht, h⟩
      rcases List.mem_append.mp ht with ht | ht
      · exact .inl ⟨t, ht, h⟩
      · obtain ⟨ke, hke, x, hx, rfl⟩ := hmem.mp ht
        exact .inr ⟨ke, hke, x, hx, h.2.1, h.2.2⟩

/-- Applying a batch, with the tombstones of the rows it kills pending, keeps `BInv`. -/
theorem apply_book {H : Bytes → Bytes} {kh : Bytes → UInt64} {fs : Fs} {rows : Nat → List Row}
    {r : List Decision × List Line × List Line} {L : Book} {pend : List Tomb} {nx : Nat} (hB : BInv fs L pend nx) :
    BInv (apply H kh fs rows r) L
      (pend ++ applyTombs kh fs rows L (changed ((view kh fs rows).apply H r) r)) nx :=
  kills_book (hits kh fs rows) _ hB (fun _ _ _ hx => (hits_sound hx).1) rfl rfl

/-- Placing a chunk at a free number `c` with install number `nx` writes its file with the pending tombstones and one
    for each row dead at birth, and keeps `BInv` with nothing pending. -/
theorem place_book {kh : Bytes → UInt64} {fs fs' : Fs} {c : Nat} {ws : List Row} {L : Book} {pend : List Tomb}
    {nx : Nat} (hB : BInv fs L pend nx) (hc : fs.inst.contains c = false) (h : place kh fs c ws = .ok fs') :
    BInv fs' (L ++ [(c, nx, placeTombs fs.win c nx ws pend)]) [] (nx + 1) := by
  obtain ⟨hI, hN, hS, hT, hD⟩ := hB
  have ⟨hi, hd⟩ : fs'.inst = fs.inst.insert c ∧ fs'.dead = fs.dead.insert c (bornDead fs.win ws) := by
    simp only [place, Except.map] at h
    split at h <;> cases h <;> exact ⟨rfl, rfl⟩
  have hcL : ¬∃ x ∈ L, x.1 = c := fun e => by rw [← hI] at e; simp [hc] at e
  -- the born-dead tombstones
  have hborn : ∀ {t : Tomb}, t ∈ (ixs 0 ws).filterMap (fun iw => if fs.win.contains iw.2.1 then some (⟨c, nx, iw.1⟩ : Tomb)
      else none) ↔ ∃ w, ws[t.i]? = some w ∧ fs.win.contains w.1 = true ∧ t.c = c ∧ t.seq = nx := by
    intro t
    simp only [List.mem_filterMap]
    constructor
    · rintro ⟨iw, hiw, he⟩
      split at he
      · cases he; exact ⟨iw.2, mem_ixs0.mp hiw, by assumption, rfl, rfl⟩
      · cases he
    · rintro ⟨w, hw, hwin, h1, h2⟩
      refine ⟨(t.i, w), mem_ixs0.mpr hw, ?_⟩
      rw [if_pos hwin]; cases t; simp_all
  have hcur : ∀ {t : Tomb}, current (L ++ [(c, nx, placeTombs fs.win c nx ws pend)]) t = true ↔
      current L t = true ∨ (t.c = c ∧ t.seq = nx) := by
    intro t
    rw [current_iff, current_iff]
    simp only [List.mem_append, List.mem_singleton]
    constructor
    · rintro ⟨x, hx | rfl, h1, h2⟩
      · exact .inl ⟨x, hx, h1, h2⟩
      · exact .inr ⟨h1.symm, h2.symm⟩
    · rintro (⟨x, hx, h1, h2⟩ | ⟨h1, h2⟩)
      · exact ⟨x, .inl hx, h1, h2⟩
      · exact ⟨_, .inr rfl, h1.symm, h2.symm⟩
  have hall : (L ++ [(c, nx, placeTombs fs.win c nx ws pend)]).flatMap (·.2.2) ++ [] =
      (L.flatMap (·.2.2) ++ pend) ++ (ixs 0 ws).filterMap (fun iw => if fs.win.contains iw.2.1 then
        some (⟨c, nx, iw.1⟩ : Tomb) else none) := by
    simp [placeTombs, List.flatMap_append, List.append_assoc]
  refine ⟨fun c' => ?_, ?_, fun x hx => ?_, fun t ht => ?_, fun c' i => Bool.eq_iff_iff.mpr ?_⟩
  · rw [hi, Std.HashSet.contains_insert]
    simp only [List.mem_append, List.mem_singleton, Bool.or_eq_true, beq_iff_eq]
    rw [hI c']
    constructor
    · rintro (rfl | ⟨x, hx, h1⟩)
      · exact ⟨_, .inr rfl, rfl⟩
      · exact ⟨x, .inl hx, h1⟩
    · rintro ⟨x, hx | rfl, h1⟩
      · exact .inr ⟨x, hx, h1⟩
      · exact .inl h1
  · rw [List.map_append, List.nodup_append]
    refine ⟨hN, by simp, ?_⟩
    intro a ha b hb
    simp only [List.map_cons, List.map_nil, List.mem_singleton] at hb
    subst hb
    obtain ⟨y, hy, rfl⟩ := List.mem_map.mp ha
    exact fun e => hcL ⟨y, hy, e⟩
  · simp only [List.mem_append, List.mem_singleton] at hx
    rcases hx with hx | rfl
    · exact Nat.lt_succ_of_lt (hS x hx)
    · exact Nat.lt_succ_self nx
  · rw [hall, List.mem_append] at ht
    rcases ht with ht | ht
    · exact Nat.lt_succ_of_lt (hT t ht)
    · obtain ⟨-, -, -, -, h2⟩ := hborn.mp ht
      rw [h2]; exact Nat.lt_succ_self nx
  · rw [hd, isDead_insert, isDead_deadOf, hall]
    -- an old tombstone is current after the place exactly when it was before
    have hold : ∀ {t : Tomb}, t ∈ L.flatMap (·.2.2) ++ pend →
        (current (L ++ [(c, nx, placeTombs fs.win c nx ws pend)]) t = true ↔ current L t = true) := by
      intro t ht
      rw [hcur]
      exact ⟨fun e => e.resolve_right fun ⟨_, h2⟩ => Nat.lt_irrefl nx (h2 ▸ hT t ht), .inl⟩
    by_cases hcc : c = c'
    · subst hcc
      rw [if_pos rfl, bornDead_iff]
      constructor
      · rintro ⟨w, hw, hwin⟩
        refine ⟨⟨c, nx, i⟩, List.mem_append_right _ (hborn.mpr ⟨w, hw, hwin, rfl, rfl⟩), hcur.mpr (.inr ⟨rfl, rfl⟩),
          rfl, rfl⟩
      · rintro ⟨t, ht, hct, h1, h2⟩
        rcases List.mem_append.mp ht with ht | ht
        · obtain ⟨x, hx, hx1, -⟩ := current_iff.mp ((hold ht).mp hct)
          exact absurd ⟨x, hx, hx1.trans h1⟩ hcL
        · obtain ⟨w, hw, hwin, -, -⟩ := hborn.mp ht
          exact ⟨w, h2 ▸ hw, hwin⟩
    · rw [if_neg hcc, hD c' i, isDead_deadOf]
      constructor
      · rintro ⟨t, ht, hct, h1, h2⟩
        exact ⟨t, List.mem_append_left _ ht, (hold ht).mpr hct, h1, h2⟩
      · rintro ⟨t, ht, hct, h1, h2⟩
        rcases List.mem_append.mp ht with ht | ht
        · exact ⟨t, ht, (hold ht).mp hct, h1, h2⟩
        · obtain ⟨-, -, -, h1', -⟩ := hborn.mp ht
          exact absurd (h1'.symm.trans h1) hcc

/-- Reclaiming installed chunk `c` removes its file, carries its tombstones that name a current chunk into the pending
    ones, and keeps `BInv`. -/
theorem reclaim_book {fs fs' : Fs} {rows : Nat → List Row} {c : Nat} {L : Book} {pend : List Tomb} {nx : Nat}
    (hB : BInv fs L pend nx) (h : reclaim fs rows c = some fs') :
    BInv fs' (reclaimBook L pend c).1 (reclaimBook L pend c).2 nx := by
  obtain ⟨hI, hN, hS, hT, hD⟩ := hB
  have ⟨hi, hd⟩ : fs'.inst = fs.inst.erase c ∧ fs'.dead = fs.dead.erase c := by
    unfold reclaim at h
    split at h
    · cases h; exact ⟨rfl, rfl⟩
    · cases h
  simp only [reclaimBook]
  have hcur : ∀ {t : Tomb}, current (L.filter (·.1 != c)) t = true ↔ current L t = true ∧ t.c ≠ c := by
    intro t
    rw [current_iff, current_iff]
    simp only [List.mem_filter, bne_iff_ne, ne_eq]
    constructor
    · rintro ⟨x, ⟨hx, hxc⟩, h1, h2⟩
      exact ⟨⟨x, hx, h1, h2⟩, h1 ▸ hxc⟩
    · rintro ⟨⟨x, hx, h1, h2⟩, htc⟩
      exact ⟨x, ⟨hx, h1 ▸ htc⟩, h1, h2⟩
  -- every tombstone after the reclaim was there before
  have hsub : ∀ {t : Tomb}, t ∈ (L.filter (·.1 != c)).flatMap (·.2.2) ++ (pend ++
      ((L.filter (·.1 == c)).flatMap (·.2.2)).filter (current (L.filter (·.1 != c)))) → t ∈ L.flatMap (·.2.2) ++ pend := by
    intro t ht
    simp only [List.mem_append, List.mem_flatMap, List.mem_filter] at ht ⊢
    rcases ht with ⟨x, ⟨hx, -⟩, ht⟩ | ht | ⟨⟨x, ⟨hx, -⟩, ht⟩, -⟩
    · exact .inl ⟨x, hx, ht⟩
    · exact .inr ht
    · exact .inl ⟨x, hx, ht⟩
  refine ⟨fun c' => ?_, ?_, fun x hx => hS x (List.mem_filter.mp hx).1, fun t ht => hT t (hsub ht),
    fun c' i => Bool.eq_iff_iff.mpr ?_⟩
  · rw [hi, Std.HashSet.contains_erase]
    simp only [Bool.and_eq_true, Bool.not_eq_true', beq_eq_false_iff_ne, ne_eq, List.mem_filter, bne_iff_ne]
    rw [hI c']
    constructor
    · rintro ⟨hne, x, hx, rfl⟩
      exact ⟨x, ⟨hx, fun e => hne e.symm⟩, rfl⟩
    · rintro ⟨x, ⟨hx, hxc⟩, rfl⟩
      exact ⟨fun e => hxc e.symm, x, hx, rfl⟩
  · exact hN.sublist (List.Sublist.map _ List.filter_sublist)
  · rw [hd, isDead_erase, hD c' i, isDead_deadOf, isDead_deadOf]
    constructor
    · rintro ⟨hne, t, ht, hct, h1, h2⟩
      have hc' : current (L.filter (·.1 != c)) t = true := hcur.mpr ⟨hct, h1 ▸ fun e => hne e.symm⟩
      refine ⟨t, ?_, hc', h1, h2⟩
      simp only [List.mem_append, List.mem_flatMap, List.mem_filter, bne_iff_ne, ne_eq, beq_iff_eq] at ht ⊢
      rcases ht with ⟨x, hx, htx⟩ | ht
      · by_cases hxc : x.1 = c
        · exact .inr (.inr ⟨⟨x, ⟨hx, hxc⟩, htx⟩, hc'⟩)
        · exact .inl ⟨x, ⟨hx, hxc⟩, htx⟩
      · exact .inr (.inl ht)
    · rintro ⟨t, ht, hct, h1, h2⟩
      obtain ⟨hct, htc⟩ := hcur.mp hct
      exact ⟨fun e => htc (h1.trans e.symm), t, hsub ht, hct, h1, h2⟩

/-- Installing the sealed window `m` writes the new chunk's file with the pending tombstones and one for each row dead
    at birth, and keeps `BInv` with nothing pending, whether or not the directory grows first (growth changes only
    the directory). -/
theorem install_book {H : Bytes → Bytes} {kh : Bytes → UInt64} {fs fs' : Fs} {rows : Nat → List Row}
    {m : HashMap Bytes Entry} {c : Nat} {ch : Chunk} {L : Book} {pend : List Tomb} {nx : Nat}
    (hB : BInv fs L pend nx) (hs : fs.sealing = some m) (h : install H kh fs rows = .ok (fs', c, ch)) :
    BInv fs' (L ++ [(c, nx, placeTombs fs.win c nx (sortRows kh m.toList) pend)]) [] (nx + 1) := by
  cases hf : freeNum fs.inst (2 ^ cBits) 0 with
  | none => simp [install, hs, hf] at h
  | some c0 =>
  have hc0 := (freeNum_spec _ _ _ hf).1
  simp only [install, hs, hf] at h
  split at h
  · rename_i p hp
    simp only [Except.ok.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl, -⟩ := h
    exact place_book hB hc0 hp
  · split at h
    · rename_i g hg
      have hgf : g.inst = fs.inst ∧ g.dead = fs.dead ∧ g.win = fs.win := by
        cases hr : Dir.rebuild (2 * fs.dir.nb + 1)
            (fs.inst.toList.map fun c => (c, liveHashes kh fs.dead c (rows c))) with
        | error r => simp [regrow, hr, Except.map] at hg
        | ok d =>
          simp only [regrow, hr, Except.map, Except.ok.injEq] at hg
          subst hg; exact ⟨rfl, rfl, rfl⟩
      cases hp : place kh g c0 (sortRows kh m.toList) with
      | error r => simp [hp, Except.map] at h
      | ok p =>
        simp only [hp, Except.map, Except.ok.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl, -⟩ := h
        rw [← hgf.2.2]
        exact place_book (book_congr hgf.1 hgf.2.1 hB) (hgf.1 ▸ hc0) hp
    · cases h

/-! ## `FInv` reads the installed set and the dead bits only by membership -/

private theorem toList_perm {s t : HashSet Nat} (h : ∀ c, s.contains c = t.contains c) : s.toList.Perm t.toList := by
  have nd : ∀ u : HashSet Nat, u.toList.Nodup := fun u =>
    Std.HashSet.distinct_toList.imp fun h e => by simp [e] at h
  refine (List.perm_ext_iff_of_nodup (nd s) (nd t)).mpr fun c => ?_
  rw [Std.HashSet.mem_toList, Std.HashSet.mem_toList, Std.HashSet.mem_iff_contains, Std.HashSet.mem_iff_contains, h]

/-- `FInv` holds of a store with the same heads, directory and windows whose installed chunks and dead rows are the
    same as another's, by membership: so it holds of a store whose installed set and dead bits are rebuilt from files. -/
theorem finv_congr {H : Bytes → Bytes} {kh : Bytes → UInt64} {fs fs' : Fs} {files : Nat → Chunk} {s : St}
    (h1 : fs'.hr = fs.hr) (h2 : fs'.hu = fs.hu) (hdir : fs'.dir = fs.dir) (hw : fs'.win = fs.win)
    (hs : fs'.sealing = fs.sealing) (hi : ∀ c, fs'.inst.contains c = fs.inst.contains c)
    (hd : ∀ c i, isDead fs'.dead c i = isDead fs.dead c i) (hI : FInv H kh fs files s) : FInv H kh fs' files s := by
  obtain ⟨e1, e2, hC, hD, hDI, hWf, hK, hcnt, hO⟩ := hI
  have hsg : ∀ kb, sealGet fs' kb = sealGet fs kb := fun kb => by simp [sealGet, hs]
  have hL : ∀ rows c i kb e, Live fs' rows c i kb e ↔ Live fs rows c i kb e := fun _ c i _ _ => by
    simp only [Live, hi c, hd c i]
  have hlh : ∀ c ws, liveHashes kh fs'.dead c ws = liveHashes kh fs.dead c ws := fun c ws => by
    unfold liveHashes; congr 1; funext iw; simp only [liveHash, hd]
  refine ⟨h1.trans e1, h2.trans e2, fun c hc => hC c ((hi c).symm.trans hc),
    fun c i w hc => hD c i w ((hi c).symm.trans hc), fun c i h => (hi c).trans (hDI c i ((hd c i).symm.trans h)),
    fun kb e h => hWf kb e (by rwa [hw, hsg] at h), fun u k => ?_, fun x => ?_, hdir ▸ hO⟩
  · simp only [KeyInv, hw, hsg, hL]; exact hK u k
  · rw [hdir, hcnt x]
    simp only [liveItems, hlh]
    exact ((toList_perm hi).flatMap_right _).count_eq x |>.symm

/-- Load from the chunk files: with the installed set the files name and the dead bits their tombstones set
    (`deadOf L []`), what a commit point keeps loads to a store with `FInv` for the same state. -/
theorem load_book {H : Bytes → Bytes} {kh : Bytes → UInt64} {fs fs' : Fs} {files : Nat → Chunk} {s : St} {nb : Nat}
    {L : Book} {nx : Nat} {inst : HashSet Nat} (hI : FInv H kh fs files s) (hw : fs.win = ∅)
    (hs : fs.sealing = none) (hB : BInv fs L [] nx) (h0 : 0 < nb) (hinst : ∀ c, inst.contains c = true ↔ ∃ x ∈ L, x.1 = c)
    (hl : load kh nb fs.hr fs.hu inst (deadOf L []) (layout H kh files) = .ok fs') : FInv H kh fs' files s :=
  load_inv (fs := { fs with inst, dead := deadOf L [] })
    (finv_congr (fs := fs) rfl rfl rfl rfl rfl (fun c => Bool.eq_iff_iff.mpr ((hinst c).trans (hB.1 c).symm))
      (fun c i => (hB.2.2.2.2 c i).symm) hI) hw hs h0 hl

end BlindLedger.Gate.Flat.Store
