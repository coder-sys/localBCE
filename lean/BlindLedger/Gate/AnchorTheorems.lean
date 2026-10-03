import BlindLedger.Gate.Anchor
import BlindLedger.Gate.ProducerTheorems
import BlindLedger.Gate.Rules.Shards

/-! Theorems of the prior-digest check (gate-producer-v1 §4).  Statements: rr-core's
    `gate-producer-goals.lean`, fixed. -/
namespace BlindLedger.Gate

/-! ### Big-endian naturals -/

theorem beNat_append_singleton (d : Bytes) (x : UInt8) : beNat (d ++ [x]) = beNat d * 256 + x.toNat := by
  simp [beNat, List.foldl_append]

theorem natBE_succ (w v : Nat) : natBE (w + 1) v = natBE w (v / 256) ++ [UInt8.ofNat (v % 256)] := by
  unfold natBE
  rw [List.range_succ_eq_map]
  simp only [List.reverse_cons, List.map_append, List.map_cons, List.map_nil, Nat.pow_zero, Nat.div_one]
  rw [← List.map_reverse, List.map_map]
  congr 1
  apply List.map_congr_left
  intro i _
  simp [Nat.pow_succ, Nat.div_div_eq_div_mul, Nat.mul_comm]

theorem natBE_beNat_aux : ∀ (n : Nat) (d : Bytes), d.length = n → natBE n (beNat d) = d
  | 0, d, h => by
    cases d with
    | nil => rfl
    | cons _ _ => simp at h
  | n + 1, d, h => by
    have hne : d ≠ [] := by
      rintro rfl
      simp at h
    obtain ⟨d', x, rfl⟩ : ∃ d' x, d = d' ++ [x] := ⟨d.dropLast, d.getLast hne, (List.dropLast_concat_getLast hne).symm⟩
    have hl : d'.length = n := by simpa using h
    have hx : x.toNat < 256 := by have := UInt8.toNat_lt x; omega
    have h1 : (beNat d' * 256 + x.toNat) / 256 = beNat d' := by omega
    have h2 : (beNat d' * 256 + x.toNat) % 256 = x.toNat := by omega
    rw [beNat_append_singleton, natBE_succ, h1, h2, natBE_beNat_aux n d' hl, UInt8.ofNat_toNat]

/-- The anchor the producer passes (`beNat` of the signed digest) is the digest it came from. -/
theorem natBE_beNat (d : Bytes) : natBE d.length (beNat d) = d := natBE_beNat_aux d.length d rfl

theorem beNat_natBE : ∀ (w v : Nat), v < 256 ^ w → beNat (natBE w v) = v
  | 0, v, h => by
    have : v = 0 := by simpa using h
    subst this; rfl
  | w + 1, v, h => by
    rw [natBE_succ, beNat_append_singleton, beNat_natBE w (v / 256)
      (by rw [Nat.pow_succ] at h; omega)]
    simp only [UInt8.toNat_ofNat']
    omega

/-! ### Anchoring -/

theorem decideAnchored_some {H : Bytes → Bytes} {c : Rules.Ctx} {b : List Rules.Line} {r : Rules.Result}
    (h : decideAnchored H c b = some r) : anchored H c = true ∧ r = Rules.decideBatch c b := by
  unfold decideAnchored at h
  by_cases ha : anchored H c = true
  · rw [if_pos ha] at h
    exact ⟨ha, (Option.some.inj h).symm⟩
  · rw [if_neg ha] at h
    cases h

theorem load_ok {H : Bytes → Bytes} {r u : Rules.Snapshot Rules.Line} {st : ShardState}
    (h : ShardState.load H r u = some st) : st.Ok H ∧ st.released = r ∧ st.unresolved = u := by
  unfold ShardState.load at h
  cases hd : setsDigest H r u with
  | none => rw [hd] at h; cases h
  | some d =>
    rw [hd] at h
    cases h
    exact ⟨hd, rfl, rfl⟩

/-- The cached digest is sound: every step decides exactly `decideAnchored` on the state's own sets, and the
    next state is the result's sets with their digest. -/
theorem step_ok {H : Bytes → Bytes} {st st' : ShardState} {c : Rules.Ctx} {b : List Rules.Line}
    {r : Rules.Result} (hs : st.Ok H) (h : st.step H c b = some (r, st')) :
    decideAnchored H { c with releasedPrior := st.released, unresolvedPrior := st.unresolved } b = some r ∧
      st'.Ok H ∧ st'.released = r.released ∧ st'.unresolved = r.unresolved := by
  unfold ShardState.step at h
  by_cases hd : (st.digest == natBE digestBytes c.anchor) = true
  · rw [if_pos hd] at h
    dsimp only at h
    cases hl : ShardState.load H
        (Rules.decideBatch { c with releasedPrior := st.released, unresolvedPrior := st.unresolved } b).released
        (Rules.decideBatch { c with releasedPrior := st.released, unresolvedPrior := st.unresolved } b).unresolved with
    | none => rw [hl] at h; cases h
    | some st0 =>
      rw [hl] at h
      simp only [Option.map_some, Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      obtain ⟨ho, hr, hu⟩ := load_ok hl
      refine ⟨?_, ho, hr, hu⟩
      unfold decideAnchored anchored
      have hok : setsDigest H st.released st.unresolved = some st.digest := hs
      simp only [hok]
      simp only [beq_iff_eq] at hd
      simp [hd]
  · rw [if_neg hd] at h
    cases h

theorem anchored_binding {H : Bytes → Bytes} (hl : ∀ x, (H x).length = digestBytes) {c c' : Rules.Ctx}
    (h : anchored H c = true) (h' : anchored H c' = true) (ha : c.anchor = c'.anchor) :
    (Rules.pinInput "RR/GATE/RELEASED/v1" 5 Rules.Line.fields c.releasedPrior =
        Rules.pinInput "RR/GATE/RELEASED/v1" 5 Rules.Line.fields c'.releasedPrior ∧
      Rules.pinInput "RR/GATE/UNRESOLVED/v1" 6 Rules.Line.fields c.unresolvedPrior =
        Rules.pinInput "RR/GATE/UNRESOLVED/v1" 6 Rules.Line.fields c'.unresolvedPrior) ∨
    ∃ x y, x ≠ y ∧ H x = H y := by
  unfold anchored setsDigest setPins at h h'
  simp only [beq_iff_eq] at h h'
  cases hA : Rules.pinInput "RR/GATE/RELEASED/v1" 5 Rules.Line.fields c.releasedPrior with
  | none => simp [hA] at h
  | some A =>
  cases hB : Rules.pinInput "RR/GATE/UNRESOLVED/v1" 6 Rules.Line.fields c.unresolvedPrior with
  | none => simp [hA, hB] at h
  | some B =>
  cases hA' : Rules.pinInput "RR/GATE/RELEASED/v1" 5 Rules.Line.fields c'.releasedPrior with
  | none => simp [hA'] at h'
  | some A' =>
  cases hB' : Rules.pinInput "RR/GATE/UNRESOLVED/v1" 6 Rules.Line.fields c'.unresolvedPrior with
  | none => simp [hA', hB'] at h'
  | some B' =>
  simp [hA, hB] at h
  simp [hA', hB'] at h'
  rw [← ha] at h'
  have e : stateDigest H (H A) (H B) = stateDigest H (H A') (H B') := h.trans h'.symm
  unfold stateDigest at e
  by_cases hq : domain "STATE" ++ H A ++ H B = domain "STATE" ++ H A' ++ H B'
  · obtain ⟨hq1, hq2⟩ := List.append_inj' hq (by rw [hl, hl])
    have hq3 := List.append_cancel_left hq1
    by_cases hAA : A = A'
    · by_cases hBB : B = B'
      · subst hAA; subst hBB; exact Or.inl ⟨rfl, rfl⟩
      · exact Or.inr ⟨B, B', hBB, hq2⟩
    · exact Or.inr ⟨A, A', hAA, hq3⟩
  · exact Or.inr ⟨_, _, hq, e⟩

/-- `anchored_binding` with the collision named: its right disjunct alone is always true by pigeonhole, so
    this one ties the colliding pair to the four pin inputs `A B A' B'` and the two state-digest inputs. -/
theorem anchored_binding_witness {H : Bytes → Bytes} (hl : ∀ x, (H x).length = digestBytes) {c c' : Rules.Ctx}
    (h : anchored H c = true) (h' : anchored H c' = true) (ha : c.anchor = c'.anchor) {A B A' B' : Bytes}
    (hA : Rules.pinInput "RR/GATE/RELEASED/v1" 5 Rules.Line.fields c.releasedPrior = some A)
    (hB : Rules.pinInput "RR/GATE/UNRESOLVED/v1" 6 Rules.Line.fields c.unresolvedPrior = some B)
    (hA' : Rules.pinInput "RR/GATE/RELEASED/v1" 5 Rules.Line.fields c'.releasedPrior = some A')
    (hB' : Rules.pinInput "RR/GATE/UNRESOLVED/v1" 6 Rules.Line.fields c'.unresolvedPrior = some B') :
    (Rules.pinInput "RR/GATE/RELEASED/v1" 5 Rules.Line.fields c.releasedPrior =
        Rules.pinInput "RR/GATE/RELEASED/v1" 5 Rules.Line.fields c'.releasedPrior ∧
      Rules.pinInput "RR/GATE/UNRESOLVED/v1" 6 Rules.Line.fields c.unresolvedPrior =
        Rules.pinInput "RR/GATE/UNRESOLVED/v1" 6 Rules.Line.fields c'.unresolvedPrior) ∨
    ∃ x y, x ≠ y ∧ H x = H y ∧ ((x, y) = (A, A') ∨ (x, y) = (B, B') ∨
      (x, y) = (domain "STATE" ++ H A ++ H B, domain "STATE" ++ H A' ++ H B')) := by
  unfold anchored setsDigest setPins at h h'
  simp only [beq_iff_eq] at h h'
  simp [hA, hB] at h
  simp [hA', hB'] at h'
  rw [← ha] at h'
  have e : stateDigest H (H A) (H B) = stateDigest H (H A') (H B') := h.trans h'.symm
  unfold stateDigest at e
  by_cases hq : domain "STATE" ++ H A ++ H B = domain "STATE" ++ H A' ++ H B'
  · obtain ⟨hq1, hq2⟩ := List.append_inj' hq (by rw [hl, hl])
    have hq3 := List.append_cancel_left hq1
    by_cases hAA : A = A'
    · by_cases hBB : B = B'
      · subst hAA; subst hBB; rw [hA, hA', hB, hB']; exact Or.inl ⟨rfl, rfl⟩
      · exact Or.inr ⟨B, B', hBB, hq2, Or.inr (Or.inl rfl)⟩
    · exact Or.inr ⟨A, A', hAA, hq3, Or.inl rfl⟩
  · exact Or.inr ⟨_, _, hq, e, Or.inr (Or.inr rfl)⟩


/-! ### The pin input is injective up to row order -/

/-- The fixed-width big-endian fields of one row, concatenated (`Rules.pinInput`'s local `row`). -/
def rowOf (fs : List (Nat × Nat)) : Option (List UInt8) :=
  (fs.mapM fun (w, n) => Rules.be w n).map List.flatten

def rowF (l : Rules.Line) : List UInt8 := (rowOf (Rules.Line.fields l)).getD []

theorem be_eq {w n : Nat} {a : List UInt8} (h : Rules.be w n = some a) : a = natBE w n ∧ n < 256 ^ w := by
  unfold Rules.be at h
  by_cases hn : n < 256 ^ w
  · rw [if_pos hn] at h
    exact ⟨(Option.some.inj h).symm, hn⟩
  · rw [if_neg hn] at h
    cases h

theorem be_length {w n : Nat} {a : List UInt8} (h : Rules.be w n = some a) : a.length = w := by
  rw [(be_eq h).1]
  simp [natBE]

theorem be_inj {w n n' : Nat} {a : List UInt8} (h : Rules.be w n = some a) (h' : Rules.be w n' = some a) :
    n = n' := by
  obtain ⟨e, hn⟩ := be_eq h
  obtain ⟨e', hn'⟩ := be_eq h'
  rw [← beNat_natBE w n hn, ← beNat_natBE w n' hn', ← e, ← e']

theorem mapM_cons_some {α β : Type} {f : α → Option β} {a : α} {l : List α} {r : List β}
    (h : (a :: l).mapM f = some r) : ∃ b bs, f a = some b ∧ l.mapM f = some bs ∧ r = b :: bs := by
  rw [List.mapM_cons] at h
  obtain ⟨b, hb, h⟩ := bind_some h
  obtain ⟨bs, hbs, h⟩ := bind_some h
  exact ⟨b, bs, hb, hbs, (Option.some.inj h).symm⟩

theorem rowOf_cons {w n : Nat} {fs : List (Nat × Nat)} {r : List UInt8} (h : rowOf ((w, n) :: fs) = some r) :
    ∃ a ar, Rules.be w n = some a ∧ rowOf fs = some ar ∧ r = a ++ ar := by
  unfold rowOf at h
  obtain ⟨bs, hbs, hr⟩ := Option.map_eq_some_iff.mp h
  obtain ⟨a, as, ha, has, rfl⟩ := mapM_cons_some hbs
  refine ⟨a, as.flatten, ha, ?_, by rw [← hr]; rfl⟩
  unfold rowOf
  rw [has]
  rfl

theorem rowOf_length : ∀ (fs : List (Nat × Nat)) (r : List UInt8), rowOf fs = some r →
    r.length = (fs.map (·.1)).sum
  | [], r, h => by
    simp [rowOf] at h
    subst h
    rfl
  | (w, n) :: fs, r, h => by
    obtain ⟨a, ar, ha, har, rfl⟩ := rowOf_cons h
    rw [List.length_append, be_length ha, rowOf_length fs ar har]
    simp

theorem rowOf_inj : ∀ (fs fs' : List (Nat × Nat)) (r : List UInt8), fs.map (·.1) = fs'.map (·.1) →
    rowOf fs = some r → rowOf fs' = some r → fs = fs'
  | [], fs', _, hw, _, _ => by
    cases fs' with
    | nil => rfl
    | cons _ _ => simp at hw
  | (w, n) :: fs, [], _, hw, _, _ => by simp at hw
  | (w, n) :: fs, (w', n') :: fs', r, hw, h, h' => by
    simp only [List.map_cons, List.cons.injEq] at hw
    obtain ⟨rfl, hw⟩ := hw
    obtain ⟨a, ar, ha, har, rfl⟩ := rowOf_cons h
    obtain ⟨a', ar', ha', har', e⟩ := rowOf_cons h'
    obtain ⟨e1, e2⟩ := List.append_inj e (by rw [be_length ha, be_length ha'])
    have hn : n = n' := be_inj ha (by rw [e1]; exact ha')
    have hf := rowOf_inj fs fs' ar hw har (by rw [e2]; exact har')
    rw [hn, hf]

theorem fields_inj {l l' : Rules.Line} (h : Rules.Line.fields l = Rules.Line.fields l') : l = l' := by
  obtain ⟨a, b, f, c, d, e, g, p, u, z⟩ := l
  obtain ⟨a', b', f', c', d', e', g', p', u', z'⟩ := l'
  cases f <;> cases f' <;> simp_all [Rules.Line.fields, Rules.Flow.tag]

theorem fields_width (l : Rules.Line) : ((Rules.Line.fields l).map (·.1)).sum = 923 := by
  simp [Rules.Line.fields, Rules.idWidth, Rules.payWidth]

theorem flatten_inj {α : Type} (n : Nat) (hn : 0 < n) :
    ∀ (L L' : List (List α)), (∀ a ∈ L, a.length = n) → (∀ a ∈ L', a.length = n) →
      L.flatten = L'.flatten → L = L'
  | [], [], _, _, _ => rfl
  | [], a :: L', _, h', e => by
    have hl := h' a (by simp)
    have h1 : (a :: L').flatten.length = a.length + L'.flatten.length := by simp
    rw [← e] at h1
    have h0 : ([] : List (List α)).flatten.length = 0 := rfl
    omega
  | a :: L, [], h, _, e => by
    have hl := h a (by simp)
    have h1 : (a :: L).flatten.length = a.length + L.flatten.length := by simp
    rw [e] at h1
    have h0 : ([] : List (List α)).flatten.length = 0 := rfl
    omega
  | a :: L, a' :: L', h, h', e => by
    rw [List.flatten_cons, List.flatten_cons] at e
    obtain ⟨e1, e2⟩ := List.append_inj e (by rw [h a (by simp), h' a' (by simp)])
    rw [e1, flatten_inj n hn L L' (fun x hx => h x (List.mem_cons_of_mem _ hx))
      (fun x hx => h' x (List.mem_cons_of_mem _ hx)) e2]

theorem count_map_inj {α β : Type} [BEq α] [LawfulBEq α] [BEq β] [LawfulBEq β] (F : α → β) (e : α) :
    ∀ l : List α, (∀ a ∈ l, F a = F e → a = e) → List.count (F e) (l.map F) = List.count e l
  | [], _ => rfl
  | a :: l, h => by
    have ih := count_map_inj F e l (fun x hx => h x (List.mem_cons_of_mem _ hx))
    rw [List.map_cons, List.count_cons, List.count_cons, ih]
    by_cases hae : F a = F e
    · have := h a (by simp) hae
      subst this
      simp
    · have hne : a ≠ e := fun h' => hae (by rw [h'])
      simp [hae, hne]

theorem mapM_rows : ∀ (l : List Rules.Line) (rows : List (List UInt8)),
    l.mapM (rowOf ∘ Rules.Line.fields) = some rows →
      rows = l.map rowF ∧ ∀ a ∈ l, ∃ r, rowOf (Rules.Line.fields a) = some r
  | [], rows, h => by
    rw [List.mapM_nil] at h
    have := Option.some.inj h
    subst this
    simp
  | a :: l, rows, h => by
    obtain ⟨b, bs, hb, hbs, rfl⟩ := mapM_cons_some h
    obtain ⟨ih1, ih2⟩ := mapM_rows l bs hbs
    have hb' : rowOf (Rules.Line.fields a) = some b := hb
    refine ⟨?_, ?_⟩
    · have : rowF a = b := by
        unfold rowF
        rw [hb']
        rfl
      rw [List.map_cons, this, ← ih1]
    · intro x hx
      rcases List.mem_cons.mp hx with rfl | hx'
      · exact ⟨b, hb'⟩
      · exact ih2 x hx'

theorem pinInput_some {d : String} {k : Nat} {s : Rules.Snapshot Rules.Line} {x : Bytes}
    (h : Rules.pinInput d k Rules.Line.fields s = some x) :
    ∃ head rows, rowOf [(4, k), (4, s.asOf), (4, s.count)] = some head ∧
      s.entries.mapM (rowOf ∘ Rules.Line.fields) = some rows ∧
      x = d.toUTF8.toList ++ 0 :: head ++ (rows.mergeSort fun a b => decide (a ≤ b)).flatten := by
  unfold Rules.pinInput at h
  obtain ⟨head, h1, h⟩ := bind_some h
  obtain ⟨rows, h2, h⟩ := bind_some h
  exact ⟨head, rows, h1, h2, (Option.some.inj h).symm⟩

/-- Equal pin inputs mean the same date, count and rows (in any order). -/
theorem pinInput_lines {d : String} {k : Nat} {s s' : Rules.Snapshot Rules.Line} {x : Bytes}
    (h : Rules.pinInput d k Rules.Line.fields s = some x) (h' : Rules.pinInput d k Rules.Line.fields s' = some x) :
    s.asOf = s'.asOf ∧ s.count = s'.count ∧ s.entries.Perm s'.entries := by
  obtain ⟨hd, rows, hh, hr, hx⟩ := pinInput_some h
  obtain ⟨hd', rows', hh', hr', hx'⟩ := pinInput_some h'
  have hl : hd.length = 12 := (rowOf_length _ _ hh).trans rfl
  have hl' : hd'.length = 12 := (rowOf_length _ _ hh').trans rfl
  obtain ⟨e1, e2⟩ := List.append_inj (hx.symm.trans hx') (by simp [hl, hl'])
  have e4 : hd = hd' := (List.cons.inj (List.append_cancel_left e1)).2
  rw [← e4] at hh'
  have e5 := rowOf_inj [(4, k), (4, s.asOf), (4, s.count)] [(4, k), (4, s'.asOf), (4, s'.count)] hd rfl hh hh'
  injection e5 with _ t1
  injection t1 with u1 t2
  injection u1 with _ ea
  injection t2 with u2 _
  injection u2 with _ ec
  refine ⟨ea, ec, ?_⟩
  obtain ⟨hr1, hdef⟩ := mapM_rows _ _ hr
  obtain ⟨hr1', hdef'⟩ := mapM_rows _ _ hr'
  have hlen : ∀ (es : List Rules.Line) (rs : List (List UInt8)), rs = es.map rowF →
      (∀ a ∈ es, ∃ r, rowOf (Rules.Line.fields a) = some r) →
      ∀ y ∈ rs.mergeSort (fun a b => decide (a ≤ b)), y.length = 923 := by
    intro es rs hrs hdf y hy
    have hy' := (List.mergeSort_perm rs _).mem_iff.mp hy
    rw [hrs, List.mem_map] at hy'
    obtain ⟨a, ha, rfl⟩ := hy'
    obtain ⟨r, hrr⟩ := hdf a ha
    unfold rowF
    rw [hrr, Option.getD_some]
    exact (rowOf_length _ _ hrr).trans (fields_width a)
  have hS := flatten_inj 923 (by omega) _ _ (hlen _ _ hr1 hdef) (hlen _ _ hr1' hdef') e2
  have p1 := List.mergeSort_perm rows (fun a b => decide (a ≤ b))
  have p2 := List.mergeSort_perm rows' (fun a b => decide (a ≤ b))
  rw [hS] at p1
  have hperm := List.perm_iff_count.mp (p1.symm.trans p2)
  refine List.perm_iff_count.mpr fun e => ?_
  by_cases hm : e ∈ s.entries ∨ e ∈ s'.entries
  · obtain ⟨re, hre⟩ : ∃ r, rowOf (Rules.Line.fields e) = some r := by
      rcases hm with hm | hm
      · exact hdef e hm
      · exact hdef' e hm
    have inj : ∀ a, (∃ r, rowOf (Rules.Line.fields a) = some r) → rowF a = rowF e → a = e := by
      rintro a ⟨ra, hra⟩ hE
      unfold rowF at hE
      rw [hra, hre] at hE
      simp only [Option.getD_some] at hE
      subst hE
      exact fields_inj (rowOf_inj _ _ ra rfl hra hre)
    rw [← count_map_inj rowF e s.entries fun a ha => inj a (hdef a ha),
      ← count_map_inj rowF e s'.entries fun a ha => inj a (hdef' a ha), ← hr1, ← hr1']
    exact hperm _
  · simp only [not_or] at hm
    rw [List.count_eq_zero_of_not_mem hm.1, List.count_eq_zero_of_not_mem hm.2]

/-- With no foreign id the registry-aware step is today's step. -/
theorem stepIn_nil (H : Bytes → Bytes) (st : ShardState) (c : Rules.Ctx) (b : List Rules.Line) :
    st.stepIn H c [] b = st.step H c b := by
  simp only [ShardState.stepIn, ShardState.step, Rules.decideBatchIn_nil]

end BlindLedger.Gate
