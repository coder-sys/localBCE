import BlindLedger.Gate.Witness
import BlindLedger.Gate.Theorems
import BlindLedger.Gate.ProducerTheorems

/-! The four statements of design key-authority-witnesses §5.  `c` is the crypto of one frame: only tenant `T`'s
    certificates are root-signed under it (`realCrypto [(T, rootPk)]`), which is `hT`. -/

namespace BlindLedger.Gate

/-! ### Installed certificates: at most one per tenant and epoch, each under its tenant's fence -/

def Uniq (s : PayerState) : Prop :=
  s.certs.Pairwise fun x y => x.tenantId = y.tenantId → x.epoch ≠ y.epoch ∧ x.shardCount = y.shardCount

theorem uniq_eq : ∀ {l : List EpochCert},
    l.Pairwise (fun x y => x.tenantId = y.tenantId → x.epoch ≠ y.epoch ∧ x.shardCount = y.shardCount) →
    ∀ {x y : EpochCert}, x ∈ l → y ∈ l → x.tenantId = y.tenantId → x.epoch = y.epoch → x = y
  | [], _, _, _, hx, _, _, _ => by simp at hx
  | a :: l, hp, x, y, hx, hy, ht, he => by
    rw [List.pairwise_cons] at hp
    rcases List.mem_cons.1 hx with h1 | h1 <;> rcases List.mem_cons.1 hy with h2 | h2
    · rw [h1, h2]
    · subst h1; exact absurd he (hp.1 y h2 ht).1
    · subst h2; exact absurd he.symm (hp.1 x h1 ht.symm).1
    · exact uniq_eq hp.2 h1 h2 ht he

theorem uniq_shard : ∀ {l : List EpochCert},
    l.Pairwise (fun x y => x.tenantId = y.tenantId → x.epoch ≠ y.epoch ∧ x.shardCount = y.shardCount) →
    ∀ {x y : EpochCert}, x ∈ l → y ∈ l → x.tenantId = y.tenantId → x.shardCount = y.shardCount
  | [], _, _, _, hx, _, _ => by simp at hx
  | a :: l, hp, x, y, hx, hy, ht => by
    rw [List.pairwise_cons] at hp
    rcases List.mem_cons.1 hx with h1 | h1 <;> rcases List.mem_cons.1 hy with h2 | h2
    · rw [h1, h2]
    · subst h1; exact (hp.1 y h2 ht).2
    · subst h2; exact (hp.1 x h1 ht.symm).2.symm
    · exact uniq_shard hp.2 h1 h2 ht

theorem installCert_uniq (c : Crypto) (s : PayerState) (e : EpochCert) (hu : Uniq s) :
    Uniq (installCert c s e).1 := by
  unfold Uniq at *
  rw [installCert_certs]
  split
  · rename_i h
    simp only [Bool.and_eq_true, fits, List.all_eq_true] at h
    refine List.Pairwise.cons (fun y hy ht => ?_) hu
    have := h.2.2 y hy
    simp [ht] at this
    exact ⟨fun h => this.2 h.symm, this.1.symm⟩
  · exact hu

theorem foldl_inv (c : Crypto) : ∀ (h : List EpochCert) (s : PayerState), Uniq s → Coherent s →
    Uniq (h.foldl (fun s e => (installCert c s e).1) s) ∧ Coherent (h.foldl (fun s e => (installCert c s e).1) s)
  | [], _, hu, hc => ⟨hu, hc⟩
  | e :: h, s, hu, hc => foldl_inv c h _ (installCert_uniq c s e hu) (installCert_coherent c e hc)

theorem replay_inv (c : Crypto) (h : List EpochCert) : Uniq (replay c h) ∧ Coherent (replay c h) :=
  foldl_inv c h emptyState (by simp [Uniq, emptyState]) (coherent_empty (s := emptyState) rfl rfl)

theorem rowsFrom_snoc (c : Crypto) (e : EpochCert) : ∀ (h : List EpochCert) (s : PayerState),
    rowsFrom c s (h ++ [e]) = rowsFrom c s h ++
      (if (classify c (h.foldl (fun s e => (installCert c s e).1) s) e).kept
       then [(e, classify c (h.foldl (fun s e => (installCert c s e).1) s) e)] else [])
  | [], s => by simp only [List.nil_append, rowsFrom, List.append_nil, List.foldl_nil] <;> rfl
  | x :: h, s => by
    simp only [List.cons_append, rowsFrom, rowsFrom_snoc c e h, List.append_assoc, List.foldl_cons] <;> rfl

/-! ### Picking rows by position -/

theorem mem_pick {α : Type} {l : List α} {ids : List Nat} {a : α} (h : a ∈ pick l ids) : a ∈ l := by
  simp only [pick, List.mem_map, List.mem_filter] at h
  obtain ⟨⟨b, i⟩, ⟨hm, _⟩, rfl⟩ := h
  exact List.fst_mem_of_mem_zipIdx hm

theorem pick_findIdx {α : Type} {l : List α} {ids : List Nat} {q : α → Bool} {i : Nat}
    (hf : l.findIdx? q = some i) (hi : i ∈ ids) : ∃ a ∈ pick l ids, q a = true := by
  obtain ⟨hl, hq, -⟩ := List.findIdx?_eq_some_iff_getElem.1 hf
  refine ⟨l[i], ?_, hq⟩
  simp only [pick, List.mem_map, List.mem_filter]
  refine ⟨(l[i], i), ⟨?_, by simpa using hi⟩, rfl⟩
  rw [List.mem_zipIdx_iff_getElem?]
  simp

theorem findIdx_of_mem {α : Type} {l : List α} {q : α → Bool} {a : α} (ha : a ∈ l) (hq : q a = true) :
    ∃ i, l.findIdx? q = some i := by
  have : (l.findIdx? q).isSome = true := by
    rw [List.findIdx?_isSome]; exact List.any_eq_true.2 ⟨a, ha, hq⟩
  exact Option.isSome_iff_exists.1 this

/-! ### Forks -/

def blockF (T : Bytes) (sh E : Nat) (f : Stored × Stored) : Bool :=
  f.1.checkpoint.tenantId == T &&
    (f.1.checkpoint.shardId == sh || f.1.checkpoint.epoch == E || f.2.checkpoint.epoch == E)

theorem pick_blockF {forks : List (Stored × Stored)} {ids : List Nat} {q : Stored × Stored → Bool} {i : Nat}
    {T : Bytes} {sh E : Nat} (hf : forks.findIdx? q = some i) (hi : i ∈ ids)
    (hq : ∀ f, q f = true → blockF T sh E f = true) : ∃ b ∈ pick forks ids, blockF T sh E b = true := by
  obtain ⟨b, hb, hqb⟩ := pick_findIdx hf hi
  exact ⟨b, hb, hq b hqb⟩

theorem selectForks_any (forks : List (Stored × Stored)) (T : Bytes) (S Q : List Nat) {sh E : Nat}
    (hs : sh ∈ S) (hE : E ∈ Q) : (selectForks forks T S Q).any (blockF T sh E) = forks.any (blockF T sh E) := by
  apply Bool.eq_iff_iff.2
  simp only [List.any_eq_true]
  constructor
  · rintro ⟨a, ha, hb⟩; exact ⟨a, mem_pick ha, hb⟩
  · rintro ⟨a, ha, hb⟩
    simp only [blockF, Bool.and_eq_true, Bool.or_eq_true, beq_iff_eq] at hb
    obtain ⟨hT, (hsh | he1) | he2⟩ := hb
    · obtain ⟨i, hi⟩ := findIdx_of_mem (q := fun f : Stored × Stored =>
        f.1.checkpoint.tenantId == T && f.1.checkpoint.shardId == sh) ha (by simp [hT, hsh])
      exact pick_blockF hi (by simp only [selectForkIds, List.mem_append, List.mem_flatMap]; exact Or.inl ⟨sh, hs, by simp [hi]⟩)
        (fun f hf => by simp only [Bool.and_eq_true, beq_iff_eq] at hf; simp [blockF, hf.1, hf.2])
    · obtain ⟨i, hi⟩ := findIdx_of_mem (q := fun f : Stored × Stored =>
        f.1.checkpoint.tenantId == T && f.1.checkpoint.epoch == E) ha (by simp [hT, he1])
      exact pick_blockF hi (by simp only [selectForkIds, List.mem_append, List.mem_flatMap]; exact Or.inr ⟨E, hE, by simp [hi]⟩)
        (fun f hf => by simp only [Bool.and_eq_true, beq_iff_eq] at hf; simp [blockF, hf.1, hf.2])
    · obtain ⟨i, hi⟩ := findIdx_of_mem (q := fun f : Stored × Stored =>
        f.1.checkpoint.tenantId == T && f.2.checkpoint.epoch == E) ha (by simp [hT, he2])
      exact pick_blockF hi (by simp only [selectForkIds, List.mem_append, List.mem_flatMap]; exact Or.inr ⟨E, hE, by simp [hi]⟩)
        (fun f hf => by simp only [Bool.and_eq_true, beq_iff_eq] at hf; simp [blockF, hf.1, hf.2])

theorem blocked_eq (s : PayerState) (T : Bytes) (sh E : Nat) :
    blocked s T sh E = (s.forked.any (blockF T sh E) ||
      s.equivocations.any fun q => q.1.tenantId == T && q.1.epoch == E) := rfl

theorem storeOutcome_congr {c : Crypto} {a b : PayerState} {old : List Stored} {fa fb : List (Stored × Stored)}
    {new : Bytes} {x : SignedCheckpoint} (hx : decodeCheckpoint new = some x)
    (hc : (a.certs.any fun e => e.tenantId == x.checkpoint.tenantId && e.epoch == x.checkpoint.epoch &&
        (c.keyUsable e && c.sigOk e.publicKey x.header x.signature)) =
      (b.certs.any fun e => e.tenantId == x.checkpoint.tenantId && e.epoch == x.checkpoint.epoch &&
        (c.keyUsable e && c.sigOk e.publicKey x.header x.signature)))
    (hb : blocked { a with checkpoints := old, forked := fa } x.checkpoint.tenantId x.checkpoint.shardId
        x.checkpoint.epoch =
      blocked { b with checkpoints := old, forked := fb } x.checkpoint.tenantId x.checkpoint.shardId
        x.checkpoint.epoch) :
    storeOutcome c a old fa new = storeOutcome c b old fb new := by
  unfold storeOutcome storeCheckpoint
  rw [hx]
  dsimp only
  rw [hc]
  split
  · cases old.find? (forks ⟨c.hash x.header, x.checkpoint, new⟩) with
    | some o => simp
    | none =>
      dsimp only
      rw [hb]
      split
      · rfl
      · cases fa <;> cases fb <;> simp
  · rfl

/-- The checks of `firstFailure` read the certificates only through the shard count and the equivocations only
    through check 11. -/
theorem firstFailure_congr {c : Crypto} {a b : PayerState} {p : Payment} {tok : Bytes}
    (hk : a.checkpoints = b.checkpoints) (hf : a.fence = b.fence) (hn : a.now = b.now) (hg : a.grants = b.grants)
    (hr : a.released = b.released) (hp : a.pins = b.pins)
    (hs : shardCountOf a p.tenantId = shardCountOf b p.tenantId)
    (hu : ∀ t st, decodeToken tok = some t → batchOf b t = some st → inBatch c st.checkpoint t = true →
      unforked a t = unforked b t) :
    firstFailure c a p tok = firstFailure c b p tok := by
  cases ht : decodeToken tok with
  | none => simp only [firstFailure, ht]
  | some t =>
    have hb : batchOf a t = batchOf b t := by simp [batchOf, hk]
    simp only [firstFailure, ht]
    rw [hb]
    cases hbt : batchOf b t with
    | none => rfl
    | some st =>
      dsimp only
      have h2 : aboveFence a t = aboveFence b t := by simp [aboveFence, hf]
      have h3 : unexpired a t = unexpired b t := by simp [unexpired, hn]
      have h5 : routed c a p t = routed c b p t := by simp [routed, hs]
      have h7 : granted a t = granted b t := by simp [granted, hg]
      have h8 : unreleased a t = unreleased b t := by simp [unreleased, hr]
      have h10 : keyPinned a t = keyPinned b t := by simp [keyPinned, hp]
      rw [h2, h3, h5, h7, h8, h10]
      cases hi : inBatch c st.checkpoint t
      · simp
      · rw [hu t st ht hbt hi]

/-- RELEASE verifies its one checkpoint against no stored one: what it holds is that checkpoint, or nothing. -/
theorem release_cps {c : Crypto} {s0 : PayerState} {cp : Bytes} (h0 : s0.checkpoints = []) {st : Stored}
    (h : st ∈ ((storeCheckpoint c { s0 with equivocations := [], forked := [] } cp).getD s0).checkpoints) :
    ∃ x, decodeCheckpoint cp = some x ∧ st.checkpoint = x.checkpoint := by
  unfold storeCheckpoint at h
  cases hx : decodeCheckpoint cp with
  | none => simp [hx, h0] at h
  | some x =>
    refine ⟨x, rfl, ?_⟩
    simp only [hx, h0, List.find?_nil, blocked, List.any_nil, Bool.or_false] at h
    split at h
    · simp at h; rw [h]
    · simp [h0] at h

/-! ### Positions -/

theorem findIdx_get {α : Type} {l : List α} {p : α → Bool} {k : Nat} (h : l.findIdx? p = some k) :
    ∃ a, l[k]? = some a ∧ p a = true ∧ ∀ j b, j < k → l[j]? = some b → p b = false := by
  obtain ⟨hk, hp, hmin⟩ := List.findIdx?_eq_some_iff_getElem.1 h
  refine ⟨l[k], List.getElem?_eq_getElem hk, hp, fun j b hj hb => ?_⟩
  rw [List.getElem?_eq_getElem (Nat.lt_trans hj hk), Option.some.injEq] at hb
  subst hb
  exact Bool.eq_false_iff.2 (hmin j hj)

/-- The first position satisfying `p` is at or before any position that does. -/
theorem first_le {α : Type} {l : List α} {p : α → Bool} {j : Nat} {a : α} (hj : l[j]? = some a)
    (hp : p a = true) : ∃ k b, l.findIdx? p = some k ∧ k ≤ j ∧ l[k]? = some b ∧ p b = true := by
  obtain ⟨k, hk⟩ := findIdx_of_mem (List.mem_iff_getElem?.2 ⟨j, hj⟩) hp
  obtain ⟨b, hb, hpb, hmin⟩ := findIdx_get hk
  refine ⟨k, b, hk, Nat.le_of_not_lt fun hlt => ?_, hb, hpb⟩
  have := hmin j a hlt hj
  rw [hp] at this
  cases this

theorem mem_pick_idx {α : Type} {l : List α} {ids : List Nat} {k : Nat} {a : α} (hk : l[k]? = some a)
    (hi : k ∈ ids) : a ∈ pick l ids := by
  simp only [pick, List.mem_map, List.mem_filter]
  exact ⟨(a, k), ⟨List.mem_zipIdx_iff_getElem?.2 hk, by simpa using hi⟩, rfl⟩

theorem pick_snoc {α : Type} (l : List α) (a : α) (ids : List Nat) :
    pick (l ++ [a]) ids = pick l ids ++ (if l.length ∈ ids then [a] else []) := by
  by_cases hc : l.length ∈ ids <;> simp [pick, List.zipIdx_append, hc]

theorem mem_sel1 {R : List (EpochCert × Role)} {T : Bytes} {Q : List Nat} {k : Nat}
    (hk : R.findIdx? (fun r => r.1.tenantId == T && r.2 == .INSTALLED) = some k) : k ∈ selectIds R T Q := by
  simp only [selectIds, List.mem_append, List.mem_flatMap, Option.mem_toList]
  exact Or.inl (Or.inl hk)

theorem mem_sel2 {R : List (EpochCert × Role)} {T : Bytes} {Q : List Nat} {m k : Nat} (hm : topEpoch R T = some m)
    (hk : R.findIdx? (fun r => r.1.tenantId == T && r.1.epoch == m) = some k) : k ∈ selectIds R T Q := by
  simp only [selectIds, List.mem_append, List.mem_flatMap, Option.mem_toList]
  exact Or.inl (Or.inr (Option.bind_eq_some_iff.2 ⟨m, hm, hk⟩))

theorem mem_sel3 {R : List (EpochCert × Role)} {T : Bytes} {Q : List Nat} {E k : Nat} (hE : E ∈ Q)
    (hk : R.findIdx? (fun r => r.1.tenantId == T && r.2 == .INSTALLED && r.1.epoch == E) = some k) :
    k ∈ selectIds R T Q := by
  simp only [selectIds, List.mem_append, List.mem_flatMap, Option.mem_toList]
  exact Or.inr ⟨E, hE, Or.inl hk⟩

theorem mem_sel4 {R : List (EpochCert × Role)} {T : Bytes} {Q : List Nat} {E k : Nat} (hE : E ∈ Q)
    (hk : R.findIdx? (fun r => r.1.tenantId == T && r.2 == .EQUIVOCATES && r.1.epoch == E) = some k) :
    k ∈ selectIds R T Q := by
  simp only [selectIds, List.mem_append, List.mem_flatMap, Option.mem_toList]
  exact Or.inr ⟨E, hE, Or.inr hk⟩

/-! ### What a role says about the state -/

theorem classify_unsigned {c : Crypto} {s : PayerState} {e : EpochCert} (hr : c.rootSigned e = false) :
    classify c s e = .REFUSED := by
  unfold classify; simp only [hr] <;> rfl

theorem classify_fits {c : Crypto} {s : PayerState} {e : EpochCert} (hr : c.rootSigned e = true)
    (hf : fits s e = true) : classify c s e = .INSTALLED := by
  unfold classify; simp only [hr, hf] <;> rfl

theorem classify_find {c : Crypto} {s : PayerState} {e : EpochCert} (hr : c.rootSigned e = true)
    (hf : fits s e = false) : classify c s e =
      match s.certs.find? (fun x => x.tenantId == e.tenantId && x.epoch == e.epoch) with
      | some x => if x.publicKey == e.publicKey && x.shardCount == e.shardCount then .SAME else .EQUIVOCATES
      | none => .FENCE_ONLY := by
  unfold classify; simp only [hr, hf] <;> rfl

theorem kept_signed {c : Crypto} {s : PayerState} {e : EpochCert} (hk : (classify c s e).kept = true) :
    c.rootSigned e = true := by
  cases hr : c.rootSigned e
  · rw [classify_unsigned hr] at hk; simp [Role.kept] at hk
  · rfl

theorem classify_inst {c : Crypto} {s : PayerState} {e : EpochCert} (h : classify c s e = .INSTALLED) :
    c.rootSigned e = true ∧ fits s e = true := by
  cases hr : c.rootSigned e
  · rw [classify_unsigned hr] at h; cases h
  · cases hf : fits s e
    · rw [classify_find hr hf] at h
      split at h
      · split at h <;> cases h
      · cases h
    · exact ⟨rfl, rfl⟩

theorem fits_at {s : PayerState} {e x : EpochCert} (hx : x ∈ s.certs) (ht : x.tenantId = e.tenantId)
    (he : x.epoch = e.epoch) : fits s e = false := by
  have : (s.certs.all fun y => y.tenantId != e.tenantId || y.shardCount == e.shardCount && y.epoch != e.epoch)
      = false := by
    rw [Bool.eq_false_iff]; intro hall
    have := List.all_eq_true.1 hall x hx
    simp [ht, he] at this
  simp [fits, this]

theorem find_at {s : PayerState} (hu : Uniq s) {x : EpochCert} {T : Bytes} {E : Nat} (hx : x ∈ s.certs)
    (ht : x.tenantId = T) (he : x.epoch = E) :
    s.certs.find? (fun y => y.tenantId == T && y.epoch == E) = some x := by
  cases hf : s.certs.find? (fun y => y.tenantId == T && y.epoch == E) with
  | none => have := List.find?_eq_none.1 hf x hx; simp [ht, he] at this
  | some y =>
    have hy := List.find?_some hf
    simp only [Bool.and_eq_true, beq_iff_eq] at hy
    rw [uniq_eq hu (List.mem_of_find?_eq_some hf) hx (hy.1.trans ht.symm) (hy.2.trans he.symm)]

theorem classify_eqv {c : Crypto} {s : PayerState} {e : EpochCert} (hr : c.rootSigned e = true) (hu : Uniq s) :
    classify c s e = .EQUIVOCATES ↔ ∃ x ∈ s.certs, x.tenantId = e.tenantId ∧ x.epoch = e.epoch ∧
      ¬(x.publicKey = e.publicKey ∧ x.shardCount = e.shardCount) := by
  constructor
  · intro hc
    cases hf : fits s e
    · rw [classify_find hr hf] at hc
      split at hc
      · rename_i x hx
        have hxp := List.find?_some hx
        simp only [Bool.and_eq_true, beq_iff_eq] at hxp
        split at hc
        · cases hc
        · rename_i hne
          exact ⟨x, List.mem_of_find?_eq_some hx, hxp.1, hxp.2, fun ⟨a, b⟩ => hne (by simp [a, b])⟩
      · cases hc
    · rw [classify_fits hr hf] at hc; cases hc
  · rintro ⟨x, hx, ht, he, hne⟩
    rw [classify_find hr (fits_at hx ht he), find_at hu hx ht he]
    show (if (x.publicKey == e.publicKey && x.shardCount == e.shardCount) = true then Role.SAME
      else Role.EQUIVOCATES) = Role.EQUIVOCATES
    rw [if_neg]
    intro hc
    simp only [Bool.and_eq_true, beq_iff_eq] at hc
    exact hne hc

/-- On a smaller set of installed certificates that keeps one of the tenant's (if it has any) and the one of
    the certificate's epoch (if any), a certificate gets the same role. -/
theorem classify_sub {c : Crypto} {a b : PayerState} {e : EpochCert} (hu : Uniq b)
    (hsub : ∀ x ∈ a.certs, x ∈ b.certs)
    (hA : ∀ x ∈ b.certs, x.tenantId = e.tenantId → ∃ y ∈ a.certs, y.tenantId = e.tenantId)
    (hB : ∀ x ∈ b.certs, x.tenantId = e.tenantId → x.epoch = e.epoch → x ∈ a.certs) :
    classify c a e = classify c b e := by
  cases hr : c.rootSigned e
  · rw [classify_unsigned hr, classify_unsigned hr]
  cases hf : fits b e
  · cases hx : b.certs.find? (fun y => y.tenantId == e.tenantId && y.epoch == e.epoch) with
    | some x =>
      have hxm := List.mem_of_find?_eq_some hx
      have hxp := List.find?_some hx
      simp only [Bool.and_eq_true, beq_iff_eq] at hxp
      have hxa := hB x hxm hxp.1 hxp.2
      have hxa' : a.certs.find? (fun y => y.tenantId == e.tenantId && y.epoch == e.epoch) = some x := by
        cases ha : a.certs.find? (fun y => y.tenantId == e.tenantId && y.epoch == e.epoch) with
        | none => have := List.find?_eq_none.1 ha x hxa; simp [hxp.1, hxp.2] at this
        | some y =>
          have hy := List.find?_some ha
          simp only [Bool.and_eq_true, beq_iff_eq] at hy
          rw [uniq_eq hu (hsub y (List.mem_of_find?_eq_some ha)) hxm (hy.1.trans hxp.1.symm)
            (hy.2.trans hxp.2.symm)]
      rw [classify_find hr hf, classify_find hr (fits_at hxa hxp.1 hxp.2), hx, hxa']
    | none =>
      have hna : a.certs.find? (fun y => y.tenantId == e.tenantId && y.epoch == e.epoch) = none :=
        List.find?_eq_none.2 fun y hy => List.find?_eq_none.1 hx y (hsub y hy)
      have hfa : fits a e = false := by
        rw [Bool.eq_false_iff] at hf ⊢
        intro hfa; apply hf
        unfold fits at hfa ⊢
        simp only [Bool.and_eq_true] at hfa ⊢
        refine ⟨hfa.1, List.all_eq_true.2 fun z hz => ?_⟩
        by_cases hzt : z.tenantId = e.tenantId
        · obtain ⟨y, hy, hyt⟩ := hA z hz hzt
          have h1 := List.all_eq_true.1 hfa.2 y hy
          have hsh : y.shardCount = z.shardCount := uniq_shard hu (hsub y hy) hz (hyt.trans hzt.symm)
          have hne : z.epoch ≠ e.epoch := fun hze => by
            have := List.find?_eq_none.1 hx z hz; simp [hzt, hze] at this
          simp [hyt] at h1
          have h2 : z.shardCount = e.shardCount := hsh.symm.trans h1.1
          simp [hzt, h2, hne]
        · simp [hzt]
      rw [classify_find hr hf, classify_find hr hfa, hx, hna]
  · have hfa : fits a e = true := by
      unfold fits at hf ⊢
      simp only [Bool.and_eq_true] at hf ⊢
      exact ⟨hf.1, List.all_eq_true.2 fun y hy => List.all_eq_true.1 hf.2 y (hsub y hy)⟩
    rw [classify_fits hr hf, classify_fits hr hfa]

/-! ### The store's rows describe the state -/

/-- Induction on a history by its last certificate. -/
theorem snoc_induction {α : Type} {motive : List α → Prop} (nil : motive [])
    (snoc : ∀ l a, motive l → motive (l ++ [a])) (l : List α) : motive l := by
  have : ∀ l : List α, motive l.reverse := by
    intro l
    induction l with
    | nil => exact nil
    | cons a l ih => rw [List.reverse_cons]; exact snoc _ a ih
  simpa using this l.reverse

theorem replay_snoc (c : Crypto) (h : List EpochCert) (e : EpochCert) :
    replay c (h ++ [e]) = (installCert c (replay c h) e).1 := by
  unfold replay; rw [List.foldl_append]; rfl

theorem table_snoc (c : Crypto) (h : List EpochCert) (e : EpochCert) :
    table c (h ++ [e]) = table c h ++
      (if (classify c (replay c h) e).kept then [(e, classify c (replay c h) e)] else []) :=
  rowsFrom_snoc c e h emptyState

theorem foldl_cps (c : Crypto) : ∀ (l : List EpochCert) (s : PayerState),
    (l.foldl (fun s e => (installCert c s e).1) s).checkpoints = s.checkpoints
  | [], _ => rfl
  | e :: l, s => by
    rw [List.foldl_cons, foldl_cps c l]
    unfold installCert; split <;> rfl

theorem replay_cps (c : Crypto) (h : List EpochCert) : (replay c h).checkpoints = [] :=
  foldl_cps c h emptyState

theorem rows_signed (c : Crypto) : ∀ (h : List EpochCert) (s : PayerState) (r : EpochCert × Role),
    r ∈ rowsFrom c s h → c.rootSigned r.1 = true
  | [], _, _, hr => by simp [rowsFrom] at hr
  | e :: h, s, r, hr => by
    simp only [rowsFrom, List.mem_append] at hr
    rcases hr with hr | hr
    · split at hr
      · rename_i hk
        rw [List.mem_singleton.1 hr]
        exact kept_signed hk
      · simp at hr
    · exact rows_signed c h _ r hr

theorem row_tenant {c : Crypto} {T : Bytes} (hT : ∀ e, c.rootSigned e = true → e.tenantId = T)
    {h : List EpochCert} {r : EpochCert × Role} (hr : r ∈ table c h) : r.1.tenantId = T :=
  hT _ (rows_signed c h emptyState r hr)

/-- The installed certificates are exactly the `INSTALLED` rows. -/
theorem mem_certs (c : Crypto) (h : List EpochCert) (x : EpochCert) :
    x ∈ (replay c h).certs ↔ (x, Role.INSTALLED) ∈ table c h := by
  induction h using snoc_induction with
  | nil => simp [replay, table, rowsFrom, emptyState]
  | snoc h e ih =>
    rw [replay_snoc, table_snoc, installCert_certs, List.mem_append]
    by_cases hi : (c.rootSigned e && fits (replay c h) e) = true
    · rw [if_pos hi]
      simp only [Bool.and_eq_true] at hi
      rw [classify_fits hi.1 hi.2, List.mem_cons, ih]
      simp [Role.kept, Or.comm]
    · rw [if_neg hi, ih]
      have hcl : classify c (replay c h) e ≠ .INSTALLED := fun hc => hi (by
        rw [Bool.and_eq_true]; exact classify_inst hc)
      constructor
      · exact fun hx => Or.inl hx
      · rintro (hx | hx)
        · exact hx
        · split at hx
          · exact absurd (congrArg Prod.snd (List.mem_singleton.1 hx)).symm hcl
          · simp at hx

/-- The recorded equivocations of a tenant and epoch are exactly its `EQUIVOCATES` rows. -/
theorem eqv_any (c : Crypto) (h : List EpochCert) (y : Bytes) (E : Nat) :
    ((replay c h).equivocations.any fun q => q.1.tenantId == y && q.1.epoch == E) =
      (table c h).any fun r => r.2 == .EQUIVOCATES && r.1.tenantId == y && r.1.epoch == E := by
  induction h using snoc_induction with
  | nil => simp [replay, table, rowsFrom, emptyState]
  | snoc h e ih =>
    rw [replay_snoc, table_snoc, List.any_append, ← ih]
    cases hr : c.rootSigned e
    · have : installCert c (replay c h) e = (replay c h, false) := by simp [installCert, hr]
      rw [this, classify_unsigned hr]
      simp [Role.kept]
    · have hu := (replay_inv c h).1
      have heq : (installCert c (replay c h) e).1.equivocations =
          ((replay c h).certs.filter fun x => x.tenantId == e.tenantId && x.epoch == e.epoch &&
            (x.publicKey != e.publicKey || x.shardCount != e.shardCount)).map (·, e) ++
            (replay c h).equivocations := by
        simp [installCert, hr]
      rw [heq, List.any_append, Bool.or_comm]
      congr 1
      apply Bool.eq_iff_iff.2
      rw [List.any_eq_true]
      constructor
      · rintro ⟨q, hq, hp⟩
        obtain ⟨x, hx, rfl⟩ := List.mem_map.1 hq
        obtain ⟨hxm, hxf⟩ := List.mem_filter.1 hx
        simp only [Bool.and_eq_true, beq_iff_eq, Bool.or_eq_true, bne_iff_ne, ne_eq] at hxf hp
        have hcl : classify c (replay c h) e = .EQUIVOCATES :=
          (classify_eqv hr hu).2 ⟨x, hxm, hxf.1.1, hxf.1.2, fun ⟨a, b⟩ => hxf.2.elim (· a) (· b)⟩
        have h1 : e.tenantId = y := hxf.1.1.symm.trans hp.1
        have h2 : e.epoch = E := hxf.1.2.symm.trans hp.2
        rw [hcl]
        simp [Role.kept, h1, h2]
      · intro hany
        split at hany
        · simp only [List.any_cons, List.any_nil, Bool.or_false, Bool.and_eq_true, beq_iff_eq] at hany
          obtain ⟨x, hxm, hxt, hxe, hne⟩ := (classify_eqv hr hu).1 hany.1.1
          refine ⟨(x, e), List.mem_map.2 ⟨x, List.mem_filter.2 ⟨hxm, ?_⟩, rfl⟩, ?_⟩
          · have : x.publicKey ≠ e.publicKey ∨ x.shardCount ≠ e.shardCount := by
              by_cases hp : x.publicKey = e.publicKey
              · exact Or.inr fun hs => hne ⟨hp, hs⟩
              · exact Or.inl hp
            simp [hxt, hxe, this]
          · simp [hxt, hxe, hany.1.2, hany.2]
        · simp at hany

/-- A tenant's fence is the highest epoch of its rows. -/
theorem fence_le (c : Crypto) (h : List EpochCert) (y : Bytes) (n : Nat) :
    (replay c h).fence y ≤ n ↔ ∀ r ∈ table c h, r.1.tenantId = y → r.1.epoch ≤ n := by
  induction h using snoc_induction with
  | nil => simp [replay, table, rowsFrom, emptyState]
  | snoc h e ih =>
    rw [replay_snoc, table_snoc]
    cases hr : c.rootSigned e
    · have : installCert c (replay c h) e = (replay c h, false) := by simp [installCert, hr]
      rw [this, classify_unsigned hr]
      simp [Role.kept, ih]
    · have hfe : (installCert c (replay c h) e).1.fence = raiseFence (replay c h).fence e.tenantId e.epoch := by
        simp [installCert, hr]
      rw [hfe]
      by_cases hk : (classify c (replay c h) e).kept = true
      · rw [if_pos hk]
        simp only [raiseFence]
        split
        · rename_i hy
          subst hy
          rw [Nat.max_le]
          constructor
          · rintro ⟨h1, h2⟩ r hr hrt
            rcases List.mem_append.1 hr with hr | hr
            · exact ih.1 h1 r hr hrt
            · rw [List.mem_singleton.1 hr]; exact h2
          · intro hall
            exact ⟨ih.2 fun r hr hrt => hall r (List.mem_append_left _ hr) hrt,
              hall _ (List.mem_append_right _ (List.mem_singleton_self _)) rfl⟩
        · rename_i hy
          constructor
          · intro h1 r hr hrt
            rcases List.mem_append.1 hr with hr | hr
            · exact ih.1 h1 r hr hrt
            · rw [List.mem_singleton.1 hr] at hrt; exact absurd hrt.symm hy
          · intro hall; exact ih.2 fun r hr hrt => hall r (List.mem_append_left _ hr) hrt
      · rw [if_neg hk, List.append_nil]
        simp only [raiseFence]
        split
        · rename_i hy
          subst hy
          have hx : ∃ x ∈ (replay c h).certs, x.tenantId = e.tenantId ∧ x.epoch = e.epoch := by
            cases hf : fits (replay c h) e
            · rw [classify_find hr hf] at hk
              split at hk
              · rename_i x hx
                have hxp := List.find?_some hx
                simp only [Bool.and_eq_true, beq_iff_eq] at hxp
                exact ⟨x, List.mem_of_find?_eq_some hx, hxp⟩
              · exact absurd rfl hk
            · rw [classify_fits hr hf] at hk; exact absurd rfl hk
          obtain ⟨x, hx, hxt, hxe⟩ := hx
          have hxf := (replay_inv c h).2.1 x hx
          rw [hxt] at hxf
          rw [Nat.max_le]
          constructor
          · exact fun h1 => ih.1 h1.1
          · intro hall
            have hf := ih.2 hall
            exact ⟨hf, by rw [← hxe]; exact Nat.le_trans hxf hf⟩
        · exact ih

/-! ### The witnesses keep every row's role -/

/-- Each kept row after a row of its tenant's `INSTALLED` one has a kept `INSTALLED` row of that tenant before it. -/
def ClosedA (R : List (EpochCert × Role)) (K : List Nat) : Prop :=
  ∀ i j ei ri x, i ∈ K → R[i]? = some (ei, ri) → j < i → R[j]? = some (x, Role.INSTALLED) →
    x.tenantId = ei.tenantId → ∃ k y, k ∈ K ∧ k < i ∧ R[k]? = some (y, Role.INSTALLED) ∧ y.tenantId = ei.tenantId

/-- Each kept `EQUIVOCATES` row has the `INSTALLED` row of its tenant and epoch kept. -/
def ClosedB (R : List (EpochCert × Role)) (K : List Nat) : Prop :=
  ∀ i j ei x, i ∈ K → R[i]? = some (ei, Role.EQUIVOCATES) → j < i → R[j]? = some (x, Role.INSTALLED) →
    x.tenantId = ei.tenantId → x.epoch = ei.epoch →
    ∃ k y, k ∈ K ∧ k < i ∧ R[k]? = some (y, Role.INSTALLED) ∧ y.tenantId = ei.tenantId ∧ y.epoch = ei.epoch

theorem roles_kept (c : Crypto) (K : List Nat) (R : List (EpochCert × Role)) (hA : ClosedA R K)
    (hB : ClosedB R K) : ∀ (h : List EpochCert) (t : List (EpochCert × Role)), table c h ++ t = R →
      table c ((pick (table c h) K).map (·.1)) = pick (table c h) K := by
  intro h
  induction h using snoc_induction with
  | nil => intro _ _; simp [table, rowsFrom, pick]
  | snoc h e ih =>
    intro t hR
    rw [table_snoc] at hR ⊢
    by_cases hk : (classify c (replay c h) e).kept = true
    · rw [if_pos hk] at hR ⊢
      have hR' : table c h ++ ((e, classify c (replay c h) e) :: t) = R := by rw [← hR]; simp
      have ih' := ih _ hR'
      rw [pick_snoc]
      by_cases hn : (table c h).length ∈ K
      · rw [if_pos hn]
        have hRn : R[(table c h).length]? = some (e, classify c (replay c h) e) := by
          rw [← hR', List.getElem?_append_right (Nat.le_refl _), Nat.sub_self]; rfl
        have hpre : ∀ j, j < (table c h).length → R[j]? = (table c h)[j]? := fun j hj => by
          rw [← hR', List.getElem?_append_left hj]
        have hsub : ∀ x ∈ (replay c ((pick (table c h) K).map (·.1))).certs, x ∈ (replay c h).certs :=
          fun x hx => by
            rw [mem_certs, ih'] at hx; rw [mem_certs]; exact mem_pick hx
        have hA' : ∀ x ∈ (replay c h).certs, x.tenantId = e.tenantId →
            ∃ y ∈ (replay c ((pick (table c h) K).map (·.1))).certs, y.tenantId = e.tenantId := by
          intro x hx hxt
          obtain ⟨j, hj⟩ := List.mem_iff_getElem?.1 ((mem_certs c h x).1 hx)
          have hjn : j < (table c h).length := (List.getElem?_eq_some_iff.1 hj).1
          obtain ⟨k, y, hkK, hkn, hRk, hyt⟩ := hA _ j e _ x hn hRn hjn (by rw [hpre j hjn]; exact hj) hxt
          refine ⟨y, ?_, hyt⟩
          rw [mem_certs, ih']
          exact mem_pick_idx (by rw [← hpre k hkn]; exact hRk) hkK
        have hB' : ∀ x ∈ (replay c h).certs, x.tenantId = e.tenantId → x.epoch = e.epoch →
            x ∈ (replay c ((pick (table c h) K).map (·.1))).certs := by
          intro x hx hxt hxe
          have hr : c.rootSigned e = true := kept_signed hk
          have hEQ : classify c (replay c h) e = .EQUIVOCATES := by
            have hk2 := hk
            rw [classify_find hr (fits_at hx hxt hxe), find_at (replay_inv c h).1 hx hxt hxe] at hk2 ⊢
            by_cases hc : (x.publicKey == e.publicKey && x.shardCount == e.shardCount) = true
            · have : (if (x.publicKey == e.publicKey && x.shardCount == e.shardCount) = true then Role.SAME
                  else Role.EQUIVOCATES).kept = true := hk2
              rw [if_pos hc] at this; simp [Role.kept] at this
            · show (if (x.publicKey == e.publicKey && x.shardCount == e.shardCount) = true then Role.SAME
                else Role.EQUIVOCATES) = Role.EQUIVOCATES
              rw [if_neg hc]
          obtain ⟨j, hj⟩ := List.mem_iff_getElem?.1 ((mem_certs c h x).1 hx)
          have hjn : j < (table c h).length := (List.getElem?_eq_some_iff.1 hj).1
          obtain ⟨k, y, hkK, hkn, hRk, hyt, hye⟩ := hB _ j e x hn (by rw [← hEQ]; exact hRn) hjn
            (by rw [hpre j hjn]; exact hj) hxt hxe
          have hyk : (table c h)[k]? = some (y, Role.INSTALLED) := by rw [← hpre k hkn]; exact hRk
          have hyH : y ∈ (replay c h).certs := (mem_certs c h y).2 (List.mem_iff_getElem?.2 ⟨k, hyk⟩)
          have hyx := uniq_eq (replay_inv c h).1 hyH hx (hyt.trans hxt.symm) (hye.trans hxe.symm)
          rw [← hyx, mem_certs, ih']
          exact mem_pick_idx hyk hkK
        have hcl : classify c (replay c ((pick (table c h) K).map (·.1))) e = classify c (replay c h) e :=
          classify_sub (replay_inv c h).1 hsub hA' hB'
        simp only [List.map_append, List.map_cons, List.map_nil]
        rw [table_snoc, ih', hcl, if_pos hk]
      · rw [if_neg hn, List.append_nil]; exact ih'
    · rw [if_neg hk, List.append_nil] at hR ⊢
      exact ih t hR

section
variable {c : Crypto} {T : Bytes} (hT : ∀ e, c.rootSigned e = true → e.tenantId = T) (h : List EpochCert)
  (Q : List Nat)
include hT

theorem sel_closedA : ClosedA (table c h) (selectIds (table c h) T Q) := by
  intro i j ei ri x _ _ hji hRj hxt
  have hxT : x.tenantId = T := row_tenant hT (List.mem_iff_getElem?.2 ⟨j, hRj⟩)
  obtain ⟨k, ⟨y, ry⟩, hk, hkj, hRk, hp⟩ :=
    first_le (p := fun r => r.1.tenantId == T && r.2 == .INSTALLED) hRj (by simp [hxT])
  simp only [Bool.and_eq_true, beq_iff_eq] at hp
  obtain ⟨hyT, rfl⟩ := hp
  exact ⟨k, y, mem_sel1 hk, Nat.lt_of_le_of_lt hkj hji, hRk, hyT.trans (hxT.symm.trans hxt)⟩

theorem sel_closedB : ClosedB (table c h) (selectIds (table c h) T Q) := by
  intro i j ei x hi hRi hji hRj hxt hxe
  have hxT : x.tenantId = T := row_tenant hT (List.mem_iff_getElem?.2 ⟨j, hRj⟩)
  simp only [selectIds, List.mem_append, List.mem_flatMap, Option.mem_toList] at hi
  rcases hi with (hi | hi) | ⟨E, hE, hi | hi⟩
  · obtain ⟨a, ha, hpa, -⟩ := findIdx_get hi
    rw [hRi, Option.some.injEq] at ha; subst ha
    simp at hpa
  · rw [Option.bind_eq_some_iff] at hi
    obtain ⟨m, -, hm⟩ := hi
    obtain ⟨a, ha, hpa, hmin⟩ := findIdx_get hm
    rw [hRi, Option.some.injEq] at ha; subst ha
    simp only [Bool.and_eq_true, beq_iff_eq] at hpa
    have := hmin j _ hji hRj
    simp [hxT, hxe, hpa.2] at this
  · obtain ⟨a, ha, hpa, -⟩ := findIdx_get hi
    rw [hRi, Option.some.injEq] at ha; subst ha
    simp at hpa
  · obtain ⟨a, ha, hpa, -⟩ := findIdx_get hi
    rw [hRi, Option.some.injEq] at ha; subst ha
    simp only [Bool.and_eq_true, beq_iff_eq] at hpa
    obtain ⟨k, ⟨y, ry⟩, hk, hkj, hRk, hp⟩ :=
      first_le (p := fun r => r.1.tenantId == T && r.2 == .INSTALLED && r.1.epoch == E) hRj
        (by simp [hxT, hxe, hpa.2])
    simp only [Bool.and_eq_true, beq_iff_eq] at hp
    obtain ⟨⟨hyT, rfl⟩, hyE⟩ := hp
    exact ⟨k, y, mem_sel3 hE hk, Nat.lt_of_le_of_lt hkj hji, hRk, hyT.trans hpa.1.1.symm, hyE.trans hpa.2.symm⟩

theorem select_roles : table c (select (table c h) T Q) = pick (table c h) (selectIds (table c h) T Q) :=
  roles_kept c _ _ (sel_closedA hT h Q) (sel_closedB hT h Q) h [] (List.append_nil _)

theorem sel_mem (x : EpochCert) : x ∈ (replay c (select (table c h) T Q)).certs ↔
    (x, Role.INSTALLED) ∈ pick (table c h) (selectIds (table c h) T Q) := by
  rw [mem_certs, select_roles hT h Q]

theorem sel_sub {x : EpochCert} (hx : x ∈ (replay c (select (table c h) T Q)).certs) : x ∈ (replay c h).certs :=
  (mem_certs c h x).2 (mem_pick ((sel_mem hT h Q x).1 hx))

/-- The witnesses install a certificate of each tenant the history installs one for. -/
theorem sel_first {x : EpochCert} (hx : x ∈ (replay c h).certs) :
    ∃ y ∈ (replay c (select (table c h) T Q)).certs, y.tenantId = x.tenantId := by
  have hxR := (mem_certs c h x).1 hx
  obtain ⟨j, hj⟩ := List.mem_iff_getElem?.1 hxR
  have hxT : x.tenantId = T := row_tenant hT hxR
  obtain ⟨k, ⟨y, ry⟩, hk, -, hRk, hp⟩ :=
    first_le (p := fun r => r.1.tenantId == T && r.2 == .INSTALLED) hj (by simp [hxT])
  simp only [Bool.and_eq_true, beq_iff_eq] at hp
  obtain ⟨hyT, rfl⟩ := hp
  exact ⟨y, (sel_mem hT h Q y).2 (mem_pick_idx hRk (mem_sel1 hk)), hyT.trans hxT.symm⟩

/-- The witnesses install the history's certificate of each epoch in `Q`. -/
theorem sel_at {x : EpochCert} (hx : x ∈ (replay c h).certs) (hE : x.epoch ∈ Q) :
    x ∈ (replay c (select (table c h) T Q)).certs := by
  have hxR := (mem_certs c h x).1 hx
  obtain ⟨j, hj⟩ := List.mem_iff_getElem?.1 hxR
  have hxT : x.tenantId = T := row_tenant hT hxR
  obtain ⟨k, ⟨y, ry⟩, hk, -, hRk, hp⟩ :=
    first_le (p := fun r => r.1.tenantId == T && r.2 == .INSTALLED && r.1.epoch == x.epoch) hj (by simp [hxT])
  simp only [Bool.and_eq_true, beq_iff_eq] at hp
  obtain ⟨⟨hyT, rfl⟩, hye⟩ := hp
  have hyL := mem_pick_idx hRk (mem_sel3 hE hk)
  have hyx := uniq_eq (replay_inv c h).1 ((mem_certs c h y).2 (mem_pick hyL)) hx (hyT.trans hxT.symm) hye
  rw [sel_mem hT h Q, ← hyx]
  exact hyL

theorem certs_any {x : SignedCheckpoint} (hE : x.checkpoint.epoch ∈ Q) :
    ((replay c (select (table c h) T Q)).certs.any fun e => e.tenantId == x.checkpoint.tenantId &&
      e.epoch == x.checkpoint.epoch && (c.keyUsable e && c.sigOk e.publicKey x.header x.signature)) =
    ((replay c h).certs.any fun e => e.tenantId == x.checkpoint.tenantId &&
      e.epoch == x.checkpoint.epoch && (c.keyUsable e && c.sigOk e.publicKey x.header x.signature)) := by
  apply Bool.eq_iff_iff.2
  simp only [List.any_eq_true]
  constructor
  · rintro ⟨a, ha, hp⟩; exact ⟨a, sel_sub hT h Q ha, hp⟩
  · rintro ⟨b, hb, hp⟩
    refine ⟨b, sel_at hT h Q hb ?_, hp⟩
    simp only [Bool.and_eq_true, beq_iff_eq] at hp
    rw [hp.1.2]; exact hE

theorem eqv_view {E : Nat} (hE : E ∈ Q) (y : Bytes) :
    ((replay c (select (table c h) T Q)).equivocations.any fun q => q.1.tenantId == y && q.1.epoch == E) =
      ((replay c h).equivocations.any fun q => q.1.tenantId == y && q.1.epoch == E) := by
  rw [eqv_any, eqv_any, select_roles hT h Q]
  apply Bool.eq_iff_iff.2
  simp only [List.any_eq_true]
  constructor
  · rintro ⟨a, ha, hp⟩; exact ⟨a, mem_pick ha, hp⟩
  · rintro ⟨⟨b, rb⟩, hb, hp⟩
    simp only [Bool.and_eq_true, beq_iff_eq] at hp
    obtain ⟨⟨rfl, hby⟩, hbE⟩ := hp
    obtain ⟨j, hj⟩ := List.mem_iff_getElem?.1 hb
    have hbT : b.tenantId = T := row_tenant hT hb
    obtain ⟨k, ⟨a, ra⟩, hk, -, hRk, hpa⟩ :=
      first_le (p := fun r => r.1.tenantId == T && r.2 == .EQUIVOCATES && r.1.epoch == E) hj (by simp [hbT, hbE])
    simp only [Bool.and_eq_true, beq_iff_eq] at hpa
    obtain ⟨⟨haT, rfl⟩, haE⟩ := hpa
    have hay : a.tenantId = y := haT.trans (hbT.symm.trans hby)
    exact ⟨(a, .EQUIVOCATES), mem_pick_idx hRk (mem_sel4 hE hk), by simp [hay, haE]⟩

theorem fence_view : (replay c (select (table c h) T Q)).fence = (replay c h).fence := by
  funext y
  have key : ∀ n, (replay c (select (table c h) T Q)).fence y ≤ n ↔ (replay c h).fence y ≤ n := by
    intro n
    rw [fence_le, fence_le, select_roles hT h Q]
    constructor
    · intro hall r hr hrt
      have hrT := row_tenant hT hr
      have hmem : r.1.epoch ∈ ((table c h).filter (·.1.tenantId == T)).map (·.1.epoch) :=
        List.mem_map.2 ⟨r, List.mem_filter.2 ⟨hr, by simp [hrT]⟩, rfl⟩
      obtain ⟨m, hm⟩ := Option.isSome_iff_exists.1 (List.isSome_max?_of_mem hmem)
      have hm' := List.max?_eq_some_iff.1 hm
      obtain ⟨r', hr'f, hr'e⟩ := List.mem_map.1 hm'.1
      have hr'R := (List.mem_filter.1 hr'f).1
      have hr'T := row_tenant hT hr'R
      obtain ⟨j, hj⟩ := List.mem_iff_getElem?.1 hr'R
      obtain ⟨k, a, hk, -, hRk, hpa⟩ :=
        first_le (p := fun r => r.1.tenantId == T && r.1.epoch == m) hj (by simp [hr'T, hr'e])
      have haL := mem_pick_idx hRk (mem_sel2 (Q := Q) hm hk)
      simp only [Bool.and_eq_true, beq_iff_eq] at hpa
      have := hall a haL (hpa.1.trans (hrT.symm.trans hrt))
      rw [hpa.2] at this
      exact Nat.le_trans (hm'.2 _ hmem) this
    · intro hall r hr hrt; exact hall r (mem_pick hr) hrt
  exact Nat.le_antisymm ((key _).2 (Nat.le_refl _)) ((key _).1 (Nat.le_refl _))

theorem shard_view (y : Bytes) :
    shardCountOf (replay c (select (table c h) T Q)) y = shardCountOf (replay c h) y := by
  unfold shardCountOf
  cases hb : (replay c h).certs.find? (·.tenantId == y) with
  | none => rw [List.find?_eq_none.2 fun x hx => List.find?_eq_none.1 hb x (sel_sub hT h Q hx)]
  | some b =>
    have hbm := List.mem_of_find?_eq_some hb
    have hbp := List.find?_some hb
    simp only [beq_iff_eq] at hbp
    obtain ⟨a, ha, hat⟩ := sel_first hT h Q hbm
    cases ha' : (replay c (select (table c h) T Q)).certs.find? (·.tenantId == y) with
    | none => have := List.find?_eq_none.1 ha' a ha; simp [hat, hbp] at this
    | some a' =>
      have ha'm := sel_sub hT h Q (List.mem_of_find?_eq_some ha')
      have ha'p := List.find?_some ha'
      simp only [beq_iff_eq] at ha'p
      show some a'.shardCount = some b.shardCount
      rw [uniq_shard (replay_inv c h).1 ha'm hbm (ha'p.trans hbp.symm)]

end

/-! ### RELEASE's one checkpoint -/

theorem store_keeps {c : Crypto} {s s' : PayerState} {cp : Bytes} (h : storeCheckpoint c s cp = some s') :
    s'.fence = s.fence ∧ s'.certs = s.certs := by
  unfold storeCheckpoint at h
  revert h
  cases decodeCheckpoint cp with
  | none => intro h; cases h
  | some x =>
    dsimp only
    split
    · split
      · intro h; cases h; exact ⟨rfl, rfl⟩
      · split
        · intro h; cases h
        · intro h; cases h; exact ⟨rfl, rfl⟩
    · intro h; cases h

theorem getD_fence {c : Crypto} {s0 : PayerState} {cp : Bytes} :
    ((storeCheckpoint c { s0 with equivocations := [], forked := [] } cp).getD s0).fence = s0.fence := by
  cases h : storeCheckpoint c { s0 with equivocations := [], forked := [] } cp with
  | none => rfl
  | some s' => exact (store_keeps h).1

theorem getD_certs {c : Crypto} {s0 : PayerState} {cp : Bytes} :
    ((storeCheckpoint c { s0 with equivocations := [], forked := [] } cp).getD s0).certs = s0.certs := by
  cases h : storeCheckpoint c { s0 with equivocations := [], forked := [] } cp with
  | none => rfl
  | some s' => exact (store_keeps h).2

theorem s1_cps {c : Crypto} {s0 : PayerState} {cp : Bytes} (h0 : s0.checkpoints = []) :
    ((storeCheckpoint c { s0 with equivocations := [], forked := [] } cp).getD s0).checkpoints =
      match decodeCheckpoint cp with
      | none => []
      | some x => if (s0.certs.any fun e => e.tenantId == x.checkpoint.tenantId && e.epoch == x.checkpoint.epoch &&
          (c.keyUsable e && c.sigOk e.publicKey x.header x.signature)) then [⟨c.hash x.header, x.checkpoint, cp⟩]
          else [] := by
  unfold storeCheckpoint
  cases decodeCheckpoint cp with
  | none => exact h0
  | some x =>
    dsimp only
    split
    · simp [h0, blocked]
    · exact h0

theorem s1_cps_congr {c : Crypto} {a b : PayerState} {cp : Bytes} (ha : a.checkpoints = [])
    (hb : b.checkpoints = [])
    (hc : ∀ x, decodeCheckpoint cp = some x →
      (a.certs.any fun e => e.tenantId == x.checkpoint.tenantId && e.epoch == x.checkpoint.epoch &&
        (c.keyUsable e && c.sigOk e.publicKey x.header x.signature)) =
      (b.certs.any fun e => e.tenantId == x.checkpoint.tenantId && e.epoch == x.checkpoint.epoch &&
        (c.keyUsable e && c.sigOk e.publicKey x.header x.signature))) :
    ((storeCheckpoint c { a with equivocations := [], forked := [] } cp).getD a).checkpoints =
      ((storeCheckpoint c { b with equivocations := [], forked := [] } cp).getD b).checkpoints := by
  rw [s1_cps ha, s1_cps hb]
  cases hx : decodeCheckpoint cp with
  | none => rfl
  | some x =>
    exact congrArg (fun z : Bool => if z then [(⟨c.hash x.header, x.checkpoint, cp⟩ : Stored)] else []) (hc x hx)

/-! ### The four statements -/

/-- A STORE or RELEASE on the certificate witnesses of its tenant and epochs answers as on the whole history. -/
theorem select_decides {c : Crypto} {T : Bytes} (hT : ∀ e, c.rootSigned e = true → e.tenantId = T)
    (h : List EpochCert) (Q : List Nat) :
    (∀ old forks new x, decodeCheckpoint new = some x → x.checkpoint.epoch ∈ Q →
      storeOutcome c (replay c (select (table c h) T Q)) old forks new = storeOutcome c (replay c h) old forks new) ∧
    (∀ forks cp now grants released pin p token, (∀ x, decodeCheckpoint cp = some x → x.checkpoint.epoch ∈ Q) →
      releaseOutcome c (replay c (select (table c h) T Q)) forks cp now grants released pin p token =
        releaseOutcome c (replay c h) forks cp now grants released pin p token) := by
  refine ⟨fun old forks new x hx hE => ?_, fun forks cp now grants released pin p token hcp => ?_⟩
  · refine storeOutcome_congr hx (certs_any hT h Q hE) ?_
    simp only [blocked_eq]
    rw [eqv_view hT h Q hE]
  · unfold releaseOutcome
    dsimp only
    refine firstFailure_congr ?_ ?_ ?_ ?_ ?_ ?_ ?_ ?_
    all_goals try rfl
    · exact s1_cps_congr (replay_cps c _) (replay_cps c _) fun x hx => certs_any hT h Q (hcp x hx)
    · dsimp only
      rw [getD_fence, getD_fence]
      exact fence_view hT h Q
    · unfold shardCountOf
      dsimp only
      rw [getD_certs, getD_certs]
      exact shard_view hT h Q p.tenantId
    · intro t st _ hbt hi
      obtain ⟨x, hx, hst⟩ := release_cps (replay_cps c h) (List.mem_of_find?_eq_some hbt)
      simp only [inBatch, Bool.and_eq_true, beq_iff_eq] at hi
      have h3 : t.leaf.epoch ∈ Q := by rw [← hi.1.1.2, hst]; exact hcp x hx
      simp only [unforked, blocked_eq]
      rw [eqv_view hT h Q h3]

/-- INSTALL on the witnesses of the new certificate's tenant and epoch classifies it as the whole history
    does, and the store's rows grow by exactly the row that answer writes. -/
theorem install_classifies {c : Crypto} {T : Bytes} (hT : ∀ e, c.rootSigned e = true → e.tenantId = T)
    (h : List EpochCert) (e : EpochCert) :
    classify c (replay c (select (table c h) T [e.epoch])) e = classify c (replay c h) e ∧
      table c (h ++ [e]) = table c h ++
        (if (classify c (replay c h) e).kept then [(e, classify c (replay c h) e)] else []) := by
  refine ⟨classify_sub (replay_inv c h).1 (fun x hx => sel_sub hT h _ hx) (fun x hx hxt => ?_)
    (fun x hx _ hxe => sel_at hT h _ hx (by rw [hxe]; exact List.mem_singleton_self _)), table_snoc c h e⟩
  obtain ⟨y, hy, hyt⟩ := sel_first hT h [e.epoch] hx
  exact ⟨y, hy, hyt.trans hxt⟩

/-- A re-signature of an installed body (or a replay of its bytes) leaves the state, so every later decision, as
    it was, and writes no row. -/
theorem resign_noop (c : Crypto) (h : List EpochCert) {x e : EpochCert} (hx : x ∈ (replay c h).certs)
    (ht : e.tenantId = x.tenantId) (he : e.epoch = x.epoch) (hk : e.publicKey = x.publicKey)
    (hs : e.shardCount = x.shardCount) :
    (installCert c (replay c h) e).1 = replay c h ∧ (classify c (replay c h) e).kept = false := by
  obtain ⟨hu, hc⟩ := replay_inv c h
  generalize replay c h = s at hx hu hc ⊢
  have hnf : fits s e = false := by
    have : (s.certs.all fun y => y.tenantId != e.tenantId || y.shardCount == e.shardCount && y.epoch != e.epoch)
        = false := by
      rw [Bool.eq_false_iff]; intro hall
      have := List.all_eq_true.1 hall x hx
      simp [ht, he] at this
    simp [fits, this]
  have hsame : ∀ y ∈ s.certs, y.tenantId = e.tenantId → y.epoch = e.epoch → y = x :=
    fun y hy h1 h2 => uniq_eq hu hy hx (h1.trans ht) (h2.trans he)
  constructor
  · unfold installCert
    split
    · have hfil : (s.certs.filter fun y => y.tenantId == e.tenantId && y.epoch == e.epoch &&
          (y.publicKey != e.publicKey || y.shardCount != e.shardCount)) = [] := by
        rw [List.filter_eq_nil_iff]
        intro y hy
        by_cases h1 : y.tenantId = e.tenantId
        · by_cases h2 : y.epoch = e.epoch
          · obtain rfl := hsame y hy h1 h2
            simp [hk, hs]
          · simp [h2]
        · simp [h1]
      have hfence : raiseFence s.fence e.tenantId e.epoch = s.fence := by
        funext y
        unfold raiseFence
        split
        · rename_i hy
          subst hy
          have := hc.1 x hx
          rw [← ht, ← he] at this
          exact Nat.max_eq_left this
        · rfl
      simp only [hnf, hfil, hfence]
      simp
    · rfl
  · unfold classify
    cases hr : c.rootSigned e
    · simp [Role.kept]
    · have hfind : s.certs.find? (fun y => y.tenantId == e.tenantId && y.epoch == e.epoch) = some x := by
        cases hf : s.certs.find? (fun y => y.tenantId == e.tenantId && y.epoch == e.epoch) with
        | none =>
          have := List.find?_eq_none.1 hf x hx
          simp [ht, he] at this
        | some y =>
          have hy := List.find?_some hf
          have hym := List.mem_of_find?_eq_some hf
          simp only [Bool.and_eq_true, beq_iff_eq] at hy
          rw [hsame y hym hy.1 hy.2]
      simp [hnf, hfind, hk, hs, Role.kept]

/-- A STORE of a checkpoint of tenant `T`, a shard in `S` and an epoch in `Q`, or a RELEASE whose checkpoint is
    one, answers on the fork witnesses as on every recorded fork. -/
theorem forks_witness (c : Crypto) (s0 : PayerState) (forks : List (Stored × Stored)) (T : Bytes) (S Q : List Nat) :
    (∀ old new x, decodeCheckpoint new = some x → x.checkpoint.tenantId = T → x.checkpoint.shardId ∈ S →
      x.checkpoint.epoch ∈ Q →
      storeOutcome c s0 old (selectForks forks T S Q) new = storeOutcome c s0 old forks new) ∧
    (∀ cp now grants released pin p token, s0.checkpoints = [] →
      (∀ x, decodeCheckpoint cp = some x →
        x.checkpoint.tenantId = T ∧ x.checkpoint.shardId ∈ S ∧ x.checkpoint.epoch ∈ Q) →
      releaseOutcome c s0 (selectForks forks T S Q) cp now grants released pin p token =
        releaseOutcome c s0 forks cp now grants released pin p token) := by
  refine ⟨fun old new x hx hT hs hq => ?_, fun cp now grants released pin p token h0 hcp => ?_⟩
  · refine storeOutcome_congr hx rfl ?_
    simp only [blocked_eq]
    rw [hT, selectForks_any forks T S Q hs hq]
  · unfold releaseOutcome
    dsimp only
    refine firstFailure_congr ?_ ?_ ?_ ?_ ?_ ?_ ?_ ?_
    all_goals try rfl
    intro t st _ hbt hi
    obtain ⟨x, hx, hst⟩ := release_cps h0 (List.mem_of_find?_eq_some hbt)
    obtain ⟨hT, hs, hq⟩ := hcp x hx
    simp only [inBatch, Bool.and_eq_true, beq_iff_eq] at hi
    have h1 : t.leaf.tenantId = T := by rw [← hi.1.1.1.1.1, hst, hT]
    have h2 : t.leaf.shardId ∈ S := by rw [← hi.1.1.1.2, hst]; exact hs
    have h3 : t.leaf.epoch ∈ Q := by rw [← hi.1.1.2, hst]; exact hq
    simp only [unforked, blocked_eq]
    rw [h1, selectForks_any forks T S Q h2 h3]

/-! ### A later duplicate row changes no witness

The store's `UNIQUE(tenant, epoch, role, body)` keeps the first row of each key and writes no later one
(`ON CONFLICT DO NOTHING`).  `select` of the table without the later duplicates is `select` of the table with them. -/

/-- The part of a row every witness clause reads: tenant, epoch and role. -/
def rowClass (r : EpochCert × Role) : Bytes × Nat × Role := (r.1.tenantId, r.1.epoch, r.2)

/-- The store's unique key: a row's class and its signed body. -/
def rowKey (r : EpochCert × Role) : (Bytes × Nat × Role) × Bytes := (rowClass r, certBody r.1)

def dropFrom : List ((Bytes × Nat × Role) × Bytes) → List (EpochCert × Role) → List (EpochCert × Role)
  | _, [] => []
  | seen, r :: rs =>
    if rowKey r ∈ seen then dropFrom seen rs else r :: dropFrom (rowKey r :: seen) rs

/-- The rows with every row after the first of its key dropped. -/
def dropLaterDuplicates (rows : List (EpochCert × Role)) : List (EpochCert × Role) := dropFrom [] rows

/-- The rows that are the first match of some clause of `gs`, in order; a row that matched is not matched again. -/
def firstPicks : List ((Bytes × Nat × Role) → Bool) → List (EpochCert × Role) → List (EpochCert × Role)
  | _, [] => []
  | gs, r :: rs =>
    (if gs.any (fun g => g (rowClass r)) then [r] else []) ++ firstPicks (gs.filter fun g => !g (rowClass r)) rs

/-- `pick` for a list whose positions start at `n`. -/
def pickAt {α : Type} (l : List α) (n : Nat) (ids : List Nat) : List α :=
  ((l.zipIdx n).filter fun p => ids.contains p.2).map (·.1)

theorem findIdx_cons_map {α : Type} (p : α → Bool) (a : α) (l : List α) (n : Nat) :
    ((a :: l).findIdx? p).map (· + n) = if p a = true then some n else (l.findIdx? p).map (· + (n + 1)) := by
  by_cases hp : p a = true
  · simp [List.findIdx?_cons, hp]
  · cases h : l.findIdx? p <;> simp [List.findIdx?_cons, hp, h] <;> omega

/-- The positions of the first match of each clause pick exactly `firstPicks`. -/
theorem pickAt_first : ∀ (l : List (EpochCert × Role)) (n : Nat) (gs : List ((Bytes × Nat × Role) → Bool))
    (ids : List Nat),
    (∀ i, i ∈ ids ↔ ∃ g ∈ gs, (l.findIdx? fun r => g (rowClass r)).map (· + n) = some i) →
    pickAt l n ids = firstPicks gs l
  | [], n, gs, ids, _ => by simp [pickAt, firstPicks]
  | a :: l, n, gs, ids, h => by
    have hcont : n ∈ ids ↔ (gs.any fun g => g (rowClass a)) = true := by
      rw [h n, List.any_eq_true]
      constructor
      · rintro ⟨g, hg, hm⟩
        refine ⟨g, hg, ?_⟩
        by_cases hga : g (rowClass a) = true
        · exact hga
        · exfalso
          simp only [findIdx_cons_map] at hm
          rw [if_neg hga] at hm
          cases hj : l.findIdx? (fun r => g (rowClass r)) with
          | none => simp [hj] at hm
          | some j => simp [hj] at hm <;> omega
      · rintro ⟨g, hg, hga⟩
        exact ⟨g, hg, by simp [findIdx_cons_map, hga]⟩
    have hmem : ∀ i, i ∈ ids.filter (fun i => decide (n + 1 ≤ i)) ↔
        ∃ g ∈ gs.filter (fun g => !g (rowClass a)), (l.findIdx? fun r => g (rowClass r)).map (· + (n + 1)) = some i := by
      intro i
      rw [List.mem_filter, h i]
      constructor
      · rintro ⟨⟨g, hg, hm⟩, hle⟩
        by_cases hga : g (rowClass a) = true
        · simp [findIdx_cons_map, hga] at hm
          simp at hle
          omega
        · refine ⟨g, List.mem_filter.2 ⟨hg, by simpa using hga⟩, ?_⟩
          simpa [findIdx_cons_map, hga] using hm
      · rintro ⟨g, hg, hm⟩
        obtain ⟨hg, hga⟩ := List.mem_filter.1 hg
        have hga' : ¬ g (rowClass a) = true := by simpa using hga
        refine ⟨⟨g, hg, by simpa [findIdx_cons_map, hga'] using hm⟩, ?_⟩
        cases hj : l.findIdx? (fun r => g (rowClass r)) with
        | none => simp [hj] at hm
        | some j => simp [hj] at hm <;> simp <;> omega
    have hpa : pickAt (a :: l) n ids = (if n ∈ ids then [a] else []) ++ pickAt l (n + 1) ids := by
      by_cases hc : n ∈ ids <;> simp [pickAt, List.zipIdx_cons, List.filter_cons, hc]
    have hpb : pickAt l (n + 1) ids = pickAt l (n + 1) (ids.filter fun i => decide (n + 1 ≤ i)) := by
      unfold pickAt
      congr 1
      apply List.filter_congr
      rintro ⟨x, i⟩ hx
      have hle : n + 1 ≤ i := List.le_snd_of_mem_zipIdx hx
      rw [Bool.eq_iff_iff, List.contains_iff_mem, List.contains_iff_mem, List.mem_filter]
      exact ⟨fun h' => ⟨h', by simpa using hle⟩, fun h' => h'.1⟩
    rw [hpa, hpb, pickAt_first l (n + 1) _ _ hmem]
    simp only [firstPicks]
    by_cases hc : n ∈ ids
    · simp [hc, hcont.1 hc]
    · have hany : ¬ (gs.any fun g => g (rowClass a)) = true := fun h' => hc (hcont.2 h')
      simp [hc, hany]

theorem dropFrom_skip {r : EpochCert × Role} {seen : List ((Bytes × Nat × Role) × Bytes)} {rs : List (EpochCert × Role)}
    (h : rowKey r ∈ seen) : dropFrom seen (r :: rs) = dropFrom seen rs := by simp [dropFrom, h]

theorem dropFrom_keep {r : EpochCert × Role} {seen : List ((Bytes × Nat × Role) × Bytes)} {rs : List (EpochCert × Role)}
    (h : rowKey r ∉ seen) : dropFrom seen (r :: rs) = r :: dropFrom (rowKey r :: seen) rs := by simp [dropFrom, h]

theorem mem_dropFrom : ∀ (R : List (EpochCert × Role)) (seen : List ((Bytes × Nat × Role) × Bytes))
    {x : EpochCert × Role}, x ∈ dropFrom seen R → x ∈ R
  | [], seen, x, h => by simp [dropFrom] at h
  | r :: rs, seen, x, h => by
    by_cases hs : rowKey r ∈ seen
    · rw [dropFrom_skip hs] at h
      exact List.mem_cons_of_mem _ (mem_dropFrom rs seen h)
    · rw [dropFrom_keep hs] at h
      rcases List.mem_cons.1 h with h | h
      · rw [h]; simp
      · exact List.mem_cons_of_mem _ (mem_dropFrom rs _ h)

theorem cover_dropFrom : ∀ (R : List (EpochCert × Role)) (seen : List ((Bytes × Nat × Role) × Bytes))
    {x : EpochCert × Role}, x ∈ R → rowKey x ∈ seen ∨ ∃ y ∈ dropFrom seen R, rowKey y = rowKey x
  | [], _, x, h => by simp at h
  | r :: rs, seen, x, h => by
    by_cases hs : rowKey r ∈ seen
    · rw [dropFrom_skip hs]
      rcases List.mem_cons.1 h with h | h
      · rw [h]; exact Or.inl hs
      · exact cover_dropFrom rs seen h
    · rw [dropFrom_keep hs]
      rcases List.mem_cons.1 h with h | h
      · rw [h]; exact Or.inr ⟨r, by simp, rfl⟩
      · rcases cover_dropFrom rs (rowKey r :: seen) h with h1 | ⟨y, hy, hk⟩
        · rcases List.mem_cons.1 h1 with h2 | h2
          · exact Or.inr ⟨r, by simp, h2.symm⟩
          · exact Or.inl h2
        · exact Or.inr ⟨y, List.mem_cons_of_mem _ hy, hk⟩

/-- Dropping rows whose key is already seen changes no pick of clauses that no seen key matches. -/
theorem firstPicks_dropFrom : ∀ (R : List (EpochCert × Role)) (seen : List ((Bytes × Nat × Role) × Bytes))
    (gs : List ((Bytes × Nat × Role) → Bool)),
    (∀ k ∈ seen, ∀ g ∈ gs, g k.1 = false) → firstPicks gs (dropFrom seen R) = firstPicks gs R
  | [], seen, gs, _ => by simp [dropFrom, firstPicks]
  | r :: rs, seen, gs, hinv => by
    by_cases hs : rowKey r ∈ seen
    · have hnone : ∀ g ∈ gs, g (rowClass r) = false := fun g hg => hinv _ hs g hg
      have h0 : ¬ (gs.any fun g => g (rowClass r)) = true := by
        rw [List.any_eq_true]
        rintro ⟨g, hg, h⟩
        simp [hnone g hg] at h
      have hf : gs.filter (fun g => !g (rowClass r)) = gs := List.filter_eq_self.2 (fun g hg => by simp [hnone g hg])
      rw [dropFrom_skip hs]
      simp only [firstPicks]
      rw [if_neg h0, List.nil_append, hf]
      exact firstPicks_dropFrom rs seen gs hinv
    · rw [dropFrom_keep hs]
      simp only [firstPicks]
      rw [firstPicks_dropFrom rs (rowKey r :: seen) (gs.filter fun g => !g (rowClass r)) ?_]
      intro k hk g hg
      obtain ⟨hg, hgr⟩ := List.mem_filter.1 hg
      rcases List.mem_cons.1 hk with hk | hk
      · rw [hk]
        show g (rowClass r) = false
        simpa using hgr
      · exact hinv k hk g hg

theorem max?_congr {a b : List Nat} (h : ∀ x, x ∈ a ↔ x ∈ b) : a.max? = b.max? := by
  cases ha : a.max? with
  | none =>
    have ha0 : a = [] := List.max?_eq_none_iff.1 ha
    cases hb : b.max? with
    | none => rfl
    | some m => exact absurd ((h m).2 (List.max?_mem hb)) (by simp [ha0])
  | some m =>
    obtain ⟨hm, hle⟩ := List.max?_eq_some_iff.1 ha
    exact (List.max?_eq_some_iff.2 ⟨(h m).1 hm, fun x hx => hle x ((h x).2 hx)⟩).symm

theorem topEpoch_dedup (rows : List (EpochCert × Role)) (T : Bytes) :
    topEpoch (dropLaterDuplicates rows) T = topEpoch rows T := by
  unfold topEpoch
  refine max?_congr fun e => ?_
  simp only [List.mem_map, List.mem_filter, beq_iff_eq]
  constructor
  · rintro ⟨x, ⟨hx, ht⟩, rfl⟩
    exact ⟨x, ⟨mem_dropFrom rows [] hx, ht⟩, rfl⟩
  · rintro ⟨x, ⟨hx, ht⟩, rfl⟩
    rcases cover_dropFrom rows [] hx with h | ⟨y, hy, hk⟩
    · simp at h
    · have hc : rowClass y = rowClass x := congrArg Prod.fst hk
      simp only [rowClass, Prod.mk.injEq] at hc
      exact ⟨y, ⟨hy, hc.1.trans ht⟩, hc.2.1⟩

/-- `select`'s clauses on the class of a row, for the tenant's top epoch `m`. -/
def selClauses (m : Option Nat) (T : Bytes) (Q : List Nat) : List ((Bytes × Nat × Role) → Bool) :=
  [fun k => k.1 == T && k.2.2 == .INSTALLED] ++ m.toList.map (fun m => fun k => k.1 == T && k.2.1 == m) ++
    Q.flatMap fun E => [fun k => k.1 == T && k.2.2 == .INSTALLED && k.2.1 == E,
                        fun k => k.1 == T && k.2.2 == .EQUIVOCATES && k.2.1 == E]

theorem selectIds_iff (R : List (EpochCert × Role)) (T : Bytes) (Q : List Nat) (i : Nat) :
    i ∈ selectIds R T Q ↔ ∃ g ∈ selClauses (topEpoch R T) T Q, (R.findIdx? fun r => g (rowClass r)) = some i := by
  constructor
  · intro hi
    simp only [selectIds, List.mem_append, List.mem_flatMap, Option.mem_toList] at hi
    rcases hi with (h1 | h2) | ⟨E, hE, h3 | h4⟩
    · exact ⟨fun k => k.1 == T && k.2.2 == .INSTALLED,
        List.mem_append.2 (Or.inl (List.mem_append.2 (Or.inl (by simp)))), h1⟩
    · obtain ⟨m, hm, h2⟩ := Option.bind_eq_some_iff.1 h2
      exact ⟨fun k => k.1 == T && k.2.1 == m,
        List.mem_append.2 (Or.inl (List.mem_append.2 (Or.inr (List.mem_map.2 ⟨m, Option.mem_toList.2 hm, rfl⟩)))), h2⟩
    · exact ⟨fun k => k.1 == T && k.2.2 == .INSTALLED && k.2.1 == E,
        List.mem_append.2 (Or.inr (List.mem_flatMap.2 ⟨E, hE, by simp⟩)), h3⟩
    · exact ⟨fun k => k.1 == T && k.2.2 == .EQUIVOCATES && k.2.1 == E,
        List.mem_append.2 (Or.inr (List.mem_flatMap.2 ⟨E, hE, by simp⟩)), h4⟩
  · rintro ⟨g, hg, hf⟩
    rcases List.mem_append.1 hg with hg | hg
    · rcases List.mem_append.1 hg with hg | hg
      · rw [List.mem_singleton] at hg
        subst hg
        exact mem_sel1 hf
      · obtain ⟨m, hm, hgm⟩ := List.mem_map.1 hg
        subst hgm
        exact mem_sel2 (Option.mem_toList.1 hm) hf
    · obtain ⟨E, hE, hg⟩ := List.mem_flatMap.1 hg
      rcases List.mem_cons.1 hg with hg | hg
      · subst hg
        exact mem_sel3 hE hf
      · rw [List.mem_singleton] at hg
        subst hg
        exact mem_sel4 hE hf

/-- Dropping every later row of the same (tenant, epoch, role, body) key does not change a witness selection. -/
theorem select_dedup (rows : List (EpochCert × Role)) (T : Bytes) (Q : List Nat) :
    select (dropLaterDuplicates rows) T Q = select rows T Q := by
  have z : ∀ o : Option Nat, o.map (· + 0) = o := fun o => by cases o <;> rfl
  have key : ∀ R : List (EpochCert × Role),
      select R T Q = (firstPicks (selClauses (topEpoch R T) T Q) R).map (·.1) := fun R => by
    unfold select
    congr 1
    exact pickAt_first R 0 _ _ (fun i => by simp only [z]; exact selectIds_iff R T Q i)
  rw [key, key, topEpoch_dedup]
  have := firstPicks_dropFrom rows [] (selClauses (topEpoch rows T) T Q) (by simp)
  rw [dropLaterDuplicates, this]

end BlindLedger.Gate
