import BlindLedger.Gate.Witness
import BlindLedger.Gate.Theorems
import BlindLedger.Gate.ProducerTheorems

/-! The statements of design key-authority-witnesses §5, on the authority state (root-rotation, 2026-11-01).
    `ok` is a frame's check of a carried certificate (`underLinks`); only tenant `T`'s certificates pass it. -/
namespace BlindLedger.Gate

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
    blocked s T sh E = (s.forked.any (blockF T sh E) || Cosign.certBlocked s.toAuth T E ||
      Cosign.linkBlocked s.toAuth T E) := rfl

/-- STORE's second certificate test (signature and cosignature under one certificate) agrees on two states that
    agree on every test of the certificates of the checkpoint's tenant and epoch. -/
theorem any_cosigned {c : Crypto} {a b : PayerState} {x : SignedCheckpoint}
    (hc : ∀ g : Cosign.KeyCert → Bool,
      (a.certs.any fun e => e.tenantId == x.checkpoint.tenantId && e.epoch == x.checkpoint.epoch && g e) =
      (b.certs.any fun e => e.tenantId == x.checkpoint.tenantId && e.epoch == x.checkpoint.epoch && g e)) :
    (a.certs.any fun e => e.tenantId == x.checkpoint.tenantId && e.epoch == x.checkpoint.epoch &&
        c.verify e.key x.header x.signature && x.cosign.any (cosignOk c e (c.hash x.header))) =
      (b.certs.any fun e => e.tenantId == x.checkpoint.tenantId && e.epoch == x.checkpoint.epoch &&
        c.verify e.key x.header x.signature && x.cosign.any (cosignOk c e (c.hash x.header))) := by
  have h := hc fun e => c.verify e.key x.header x.signature && x.cosign.any (cosignOk c e (c.hash x.header))
  simpa only [Bool.and_assoc] using h

/-- STORE reads the certificates only through those of the checkpoint's tenant and epoch, and the blocks only
    when one of them exists. -/
theorem storeOutcome_congr {c : Crypto} {a b : PayerState} {old : List Stored} {fa fb : List (Stored × Stored)}
    {new : Bytes} {x : SignedCheckpoint} (hx : decodeCheckpoint new = some x)
    (hc : ∀ g : Cosign.KeyCert → Bool,
      (a.certs.any fun e => e.tenantId == x.checkpoint.tenantId && e.epoch == x.checkpoint.epoch && g e) =
      (b.certs.any fun e => e.tenantId == x.checkpoint.tenantId && e.epoch == x.checkpoint.epoch && g e))
    (hb : (∃ e ∈ b.certs, e.tenantId = x.checkpoint.tenantId) →
      blocked { a with checkpoints := old, forked := fa } x.checkpoint.tenantId x.checkpoint.shardId
        x.checkpoint.epoch =
      blocked { b with checkpoints := old, forked := fb } x.checkpoint.tenantId x.checkpoint.shardId
        x.checkpoint.epoch) :
    storeOutcome c a old fa new = storeOutcome c b old fb new := by
  have hc1 := hc fun e => c.verify e.key x.header x.signature
  have hc2 := any_cosigned (c := c) hc
  unfold storeOutcome storeCheckpoint
  rw [hx]
  dsimp only
  rw [hc1, hc2]
  split
  · rename_i hany
    have hb' := hb (by
      obtain ⟨e, he, hp⟩ := List.any_eq_true.1 hany
      simp only [Bool.and_eq_true, beq_iff_eq] at hp
      exact ⟨e, he, hp.1.1⟩)
    cases old.find? (forks ⟨c.hash x.header, x.checkpoint, new⟩) with
    | some o => simp
    | none =>
      dsimp only
      rw [hb']
      split
      · rfl
      · split
        · cases fa <;> cases fb <;> simp
        · rfl
  · rfl

/-- The checks of `firstFailure` read the certificates only through the shard count of the token's epoch, and
    the blocks only through check 11; both only for a token of the stored checkpoint. -/
theorem firstFailure_congr {c : Crypto} {a b : PayerState} {p : Payment} {tok : Bytes}
    (hk : a.checkpoints = b.checkpoints) (hf : a.fence = b.fence) (hn : a.now = b.now) (hg : a.grants = b.grants)
    (hr : a.released = b.released) (hp : a.pins = b.pins)
    (hu : ∀ t st, decodeToken tok = some t → batchOf b t = some st → inBatch c st.checkpoint t = true →
      routed c a p t = routed c b p t ∧ unforked a t = unforked b t) :
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
      have h7 : granted a t = granted b t := by simp [granted, hg]
      have h8 : unreleased a t = unreleased b t := by simp [unreleased, hr]
      have h10 : keyPinned a t = keyPinned b t := by simp [keyPinned, hp]
      rw [h2, h3, h7, h8, h10]
      cases hi : inBatch c st.checkpoint t
      · simp
      · rw [(hu t st ht hbt hi).1, (hu t st ht hbt hi).2]

/-! ### RELEASE's one checkpoint -/

theorem store_keeps {c : Crypto} {s s' : PayerState} {cp : Bytes} (h : storeCheckpoint c s cp = some s') :
    s'.fence = s.fence ∧ s'.certs = s.certs ∧ s'.chainOf = s.chainOf := by
  unfold storeCheckpoint at h
  revert h
  cases decodeCheckpoint cp with
  | none => intro h; cases h
  | some x =>
    dsimp only
    split
    · split
      · intro h; cases h; exact ⟨rfl, rfl, rfl⟩
      · split
        · intro h; cases h
        · split
          · intro h; cases h; exact ⟨rfl, rfl, rfl⟩
          · intro h; cases h
    · intro h; cases h

theorem getD_fence {c : Crypto} {s0 : PayerState} {cp : Bytes} :
    ((storeCheckpoint c { s0 with equivocations := [], conflicts := [], forked := [] } cp).getD s0).fence =
      s0.fence := by
  cases h : storeCheckpoint c { s0 with equivocations := [], conflicts := [], forked := [] } cp with
  | none => rfl
  | some s' => exact (store_keeps h).1

theorem getD_certs {c : Crypto} {s0 : PayerState} {cp : Bytes} :
    ((storeCheckpoint c { s0 with equivocations := [], conflicts := [], forked := [] } cp).getD s0).certs =
      s0.certs := by
  cases h : storeCheckpoint c { s0 with equivocations := [], conflicts := [], forked := [] } cp with
  | none => rfl
  | some s' => exact (store_keeps h).2.1

theorem getD_chain {c : Crypto} {s0 : PayerState} {cp : Bytes} :
    ((storeCheckpoint c { s0 with equivocations := [], conflicts := [], forked := [] } cp).getD s0).chainOf =
      s0.chainOf := by
  cases h : storeCheckpoint c { s0 with equivocations := [], conflicts := [], forked := [] } cp with
  | none => rfl
  | some s' => exact (store_keeps h).2.2

/-- RELEASE verifies its one checkpoint against no stored one and no recorded block: what it holds is that
    checkpoint, when a certificate of its tenant and epoch verifies its signature and cosignature, or nothing. -/
theorem s1_cps {c : Crypto} {s0 : PayerState} {cp : Bytes} (h0 : s0.checkpoints = []) :
    ((storeCheckpoint c { s0 with equivocations := [], conflicts := [], forked := [] } cp).getD s0).checkpoints =
      match decodeCheckpoint cp with
      | none => []
      | some x => if (s0.certs.any fun e => e.tenantId == x.checkpoint.tenantId && e.epoch == x.checkpoint.epoch &&
          c.verify e.key x.header x.signature &&
          x.cosign.any (cosignOk c e (c.hash x.header))) then [⟨c.hash x.header, x.checkpoint, cp⟩]
          else [] := by
  unfold storeCheckpoint
  cases decodeCheckpoint cp with
  | none => exact h0
  | some x =>
    have hBA : (s0.certs.any (fun e => e.tenantId == x.checkpoint.tenantId && e.epoch == x.checkpoint.epoch &&
          c.verify e.key x.header x.signature &&
          x.cosign.any (cosignOk c e (c.hash x.header)))) = true →
        (s0.certs.any (fun e => e.tenantId == x.checkpoint.tenantId && e.epoch == x.checkpoint.epoch &&
          c.verify e.key x.header x.signature)) = true := by
      intro h2
      obtain ⟨e, he, hp⟩ := List.any_eq_true.1 h2
      simp only [Bool.and_eq_true] at hp
      exact List.any_eq_true.2 ⟨e, he, by simp only [Bool.and_eq_true]; exact hp.1⟩
    dsimp only
    generalize (s0.certs.any (fun e => e.tenantId == x.checkpoint.tenantId && e.epoch == x.checkpoint.epoch &&
          c.verify e.key x.header x.signature &&
          x.cosign.any (cosignOk c e (c.hash x.header)))) = B at hBA ⊢
    generalize (s0.certs.any (fun e => e.tenantId == x.checkpoint.tenantId && e.epoch == x.checkpoint.epoch &&
          c.verify e.key x.header x.signature)) = A at hBA ⊢
    cases A <;> cases B <;> simp_all [blocked, Cosign.certBlocked, Cosign.linkBlocked]

/-- The checkpoint RELEASE holds is the frame's, and a certificate of its tenant is installed. -/
theorem release_cps {c : Crypto} {s0 : PayerState} {cp : Bytes} (h0 : s0.checkpoints = []) {st : Stored}
    (h : st ∈ ((storeCheckpoint c { s0 with equivocations := [], conflicts := [], forked := [] } cp).getD
      s0).checkpoints) :
    ∃ x, decodeCheckpoint cp = some x ∧ st.checkpoint = x.checkpoint ∧
      ∃ e ∈ s0.certs, e.tenantId = x.checkpoint.tenantId := by
  rw [s1_cps h0] at h
  cases hx : decodeCheckpoint cp with
  | none => simp [hx] at h
  | some x =>
    simp only [hx] at h
    split at h
    · rename_i hany
      obtain ⟨e, he, hp⟩ := List.any_eq_true.1 hany
      simp only [Bool.and_eq_true, beq_iff_eq] at hp
      rw [List.mem_singleton.1 h]
      exact ⟨x, rfl, rfl, e, he, hp.1.1.1⟩
    · simp at h

theorem s1_cps_congr {c : Crypto} {a b : PayerState} {cp : Bytes} (ha : a.checkpoints = [])
    (hb : b.checkpoints = [])
    (hc : ∀ x, decodeCheckpoint cp = some x → ∀ g : Cosign.KeyCert → Bool,
      (a.certs.any fun e => e.tenantId == x.checkpoint.tenantId && e.epoch == x.checkpoint.epoch && g e) =
      (b.certs.any fun e => e.tenantId == x.checkpoint.tenantId && e.epoch == x.checkpoint.epoch && g e)) :
    ((storeCheckpoint c { a with equivocations := [], conflicts := [], forked := [] } cp).getD a).checkpoints =
      ((storeCheckpoint c { b with equivocations := [], conflicts := [], forked := [] } cp).getD b).checkpoints := by
  rw [s1_cps ha, s1_cps hb]
  cases hx : decodeCheckpoint cp with
  | none => rfl
  | some x =>
    exact congrArg (fun z : Bool => if z then [(⟨c.hash x.header, x.checkpoint, cp⟩ : Stored)] else [])
      (any_cosigned (c := c) (hc x hx))

/-! ### Link conflicts -/

theorem lowerGen_any (g : Nat) : ∀ (l : List (Nat × Cosign.Link)) (init : Option (Nat × Cosign.Link)),
    (l.foldl lowerGen init).any (fun q => decide (q.2.gen ≤ g)) =
      (init.any (fun q => decide (q.2.gen ≤ g)) || l.any fun q => decide (q.2.gen ≤ g))
  | [], init => by simp
  | q :: l, init => by
    rw [List.foldl_cons, lowerGen_any g l, List.any_cons, ← Bool.or_assoc]
    congr 1
    cases init with
    | none => simp [lowerGen]
    | some b =>
      by_cases hle : q.2.gen ≤ b.2.gen
      · simp only [lowerGen, if_pos hle, Option.any_some]
        apply Bool.eq_iff_iff.2
        simp only [Bool.or_eq_true, decide_eq_true_eq]
        omega
      · simp only [lowerGen, if_neg hle, Option.any_some]
        apply Bool.eq_iff_iff.2
        simp only [Bool.or_eq_true, decide_eq_true_eq]
        omega

/-- The carried link conflict blocks exactly the epochs the recorded conflicts of the tenant's present chain
    block. -/
theorem selectConflict_blocks (s : Cosign.Auth) (T : Bytes) (E : Nat) :
    Cosign.linkBlocked s T E = (selectConflict s T).any fun q => decide (q.2.gen ≤ Cosign.genOf E) := by
  unfold Cosign.linkBlocked selectConflict
  cases s.chainOf T with
  | none => rfl
  | some ch =>
    simp only [Option.any_some, Option.bind_some, lowerGen_any, Option.any_none, Bool.false_or, List.any_filter]

/-- A frame's link part blocks an epoch exactly when the conflict it carries is the tenant's, of the head's
    chain, at or below the epoch's generation. -/
theorem linkView_blocked (H : Bytes → Bytes) (head : Cosign.SignedLink) (conflict : Option Cosign.SignedLink)
    (fence E : Nat) (hr : head.root ≠ head.witness) :
    Cosign.linkBlocked (linkView H head conflict fence) head.tenantId E =
      conflict.any fun n => n.tenantId == head.tenantId && n.base == head.base &&
        decide (n.gen ≤ Cosign.genOf E) := by
  have hs : Cosign.Chain.start (head.link H) = some (.genesis (head.link H) hr) := dif_pos hr
  cases conflict with
  | none => simp [Cosign.linkBlocked, linkView]
  | some n =>
    simp only [Cosign.linkBlocked, linkView, hs, Option.any_some, Option.filter_some]
    cases hn : (n.tenantId == head.tenantId && n.base == head.base)
    · simp
    · simp only [Bool.and_eq_true, beq_iff_eq] at hn
      simp [hn.1, Cosign.Chain.base, Cosign.Chain.genesis, Cosign.SignedLink.link]

/-- A frame's link part puts the tenant's fence at the head's generation and the fence certificate's epoch. -/
theorem linkView_fence (H : Bytes → Bytes) (head : Cosign.SignedLink) (conflict : Option Cosign.SignedLink)
    (fence : Nat) :
    (linkView H head conflict fence).fence =
      raiseFence (raiseFence (fun _ => 0) head.tenantId (head.gen * Cosign.genSpan)) head.tenantId fence := by
  funext y
  unfold linkView raiseFence
  dsimp only
  split
  · omega
  · rfl

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


theorem rowsFrom_snoc (ok : Cosign.KeyCert → Bool) (e : Cosign.KeyCert) :
    ∀ (h : List Cosign.KeyCert) (s : PayerState), rowsFrom ok s (h ++ [e]) = rowsFrom ok s h ++
      ((admit ok (h.foldl (fun s e => (admit ok s e).1) s) e).2.map (e, ·)).toList
  | [], s => by simp [rowsFrom]
  | x :: h, s => by
    simp only [List.cons_append, rowsFrom, rowsFrom_snoc ok e h, List.append_assoc, List.foldl_cons]

theorem replay_snoc (ok : Cosign.KeyCert → Bool) (h : List Cosign.KeyCert) (e : Cosign.KeyCert) :
    replay ok (h ++ [e]) = (admit ok (replay ok h) e).1 := by
  unfold replay; rw [List.foldl_append]; rfl

theorem table_snoc (ok : Cosign.KeyCert → Bool) (h : List Cosign.KeyCert) (e : Cosign.KeyCert) :
    table ok (h ++ [e]) = table ok h ++ ((admit ok (replay ok h) e).2.map (e, ·)).toList :=
  rowsFrom_snoc ok e h emptyState

/-- `admit` leaves the state and writes no row, or records the certificate and writes `Cosign.record`'s answer. -/
theorem admit_cases (ok : Cosign.KeyCert → Bool) (s : PayerState) (e : Cosign.KeyCert) :
    (admit ok s e = (s, none) ∧ (ok e = false ∨ Cosign.held s.toAuth e = true)) ∨
    (ok e = true ∧ Cosign.held s.toAuth e = false ∧
      admit ok s e = ({ s with toAuth := (Cosign.record s.toAuth e).1 }, some (Cosign.record s.toAuth e).2)) := by
  cases ho : ok e <;> cases hh : Cosign.held s.toAuth e <;> simp [admit, ho, hh]

/-- What a store's certificate rows say about the state they were recorded into. -/
structure Described (ok : Cosign.KeyCert → Bool) (s : PayerState)
    (R : List (Cosign.KeyCert × Cosign.CertAnswer)) : Prop where
  /-- The installed certificates are the `installed` rows. -/
  certs : ∀ x, x ∈ s.certs ↔ (x, Cosign.CertAnswer.installed) ∈ R
  /-- The equivocating certificates are the `equivocates` rows. -/
  eqv : ∀ y, (∃ q ∈ s.equivocations, q.2 = y) ↔ (y, Cosign.CertAnswer.equivocates) ∈ R
  /-- Each equivocation is with an installed certificate of its tenant and epoch. -/
  pair : ∀ q ∈ s.equivocations, q.1 ∈ s.certs ∧ q.1.tenantId = q.2.tenantId ∧ q.1.epoch = q.2.epoch
  /-- A tenant's fence is the highest epoch of its rows. -/
  fence : ∀ y n, s.fence y ≤ n ↔ ∀ r ∈ R, r.1.tenantId = y → r.1.epoch ≤ n
  /-- One installed certificate per tenant and epoch. -/
  uniq : ∀ x ∈ s.certs, ∀ y ∈ s.certs, x.tenantId = y.tenantId → x.epoch = y.epoch → x = y
  /-- A tenant's installed shard counts extend one another in epoch order. -/
  ordered : ∀ x ∈ s.certs, ∀ y ∈ s.certs, x.tenantId = y.tenantId → x.epoch < y.epoch →
    x.chain.isPrefixOf y.chain = true
  /-- Every row's certificate passed the check. -/
  passed : ∀ r ∈ R, ok r.1 = true
  rest : s.checkpoints = []
  /-- The rows hold no link: every certificate counts for a fit (`Cosign.fits_chainless`). -/
  chainless : ∀ t, s.chainOf t = none

theorem described_record {ok : Cosign.KeyCert → Bool} {s : PayerState}
    {R : List (Cosign.KeyCert × Cosign.CertAnswer)} (d : Described ok s R) {e : Cosign.KeyCert}
    (hok : ok e = true) :
    Described ok { s with toAuth := (Cosign.record s.toAuth e).1 }
      (R ++ [(e, (Cosign.record s.toAuth e).2)]) := by
  have hc := Cosign.record_certs s.toAuth e
  have hq := Cosign.record_equivocations s.toAuth e
  have hcl : ∀ t, (Cosign.record s.toAuth e).1.chainOf t = none := fun t => by
    rw [(Cosign.record_links _ _).1]; exact d.chainless t
  have hfence : ∀ y n, (Cosign.record s.toAuth e).1.fence y ≤ n ↔
      ∀ r ∈ R ++ [(e, (Cosign.record s.toAuth e).2)], r.1.tenantId = y → r.1.epoch ≤ n := by
    intro y n
    have hfy : (Cosign.record s.toAuth e).1.fence y =
        if y = e.tenantId then max (s.fence y) e.epoch else s.fence y := by
      rw [Cosign.record_fence]; rfl
    rw [hfy]
    by_cases hy : y = e.tenantId
    · rw [if_pos hy]
      constructor
      · intro h r hr hry
        rcases List.mem_append.1 hr with hr | hr
        · exact (d.fence y n).1 (Nat.le_trans (Nat.le_max_left _ _) h) r hr hry
        · rw [List.mem_singleton.1 hr]
          exact Nat.le_trans (Nat.le_max_right _ _) h
      · intro h
        exact Nat.max_le.2 ⟨(d.fence y n).2 fun r hr hry => h r (List.mem_append_left _ hr) hry,
          h (e, _) (List.mem_append_right _ (List.mem_singleton.2 rfl)) hy.symm⟩
    · rw [if_neg hy]
      constructor
      · intro h r hr hry
        rcases List.mem_append.1 hr with hr | hr
        · exact (d.fence y n).1 h r hr hry
        · rw [List.mem_singleton.1 hr] at hry
          exact absurd hry.symm hy
      · intro h
        exact (d.fence y n).2 fun r hr hry => h r (List.mem_append_left _ hr) hry
  have hpassed : ∀ r ∈ R ++ [(e, (Cosign.record s.toAuth e).2)], ok r.1 = true := by
    intro r hr
    rcases List.mem_append.1 hr with hr | hr
    · exact d.passed r hr
    · rw [List.mem_singleton.1 hr]; exact hok
  rcases Cosign.record_answer s.toAuth e with hr | hr | hr
  · -- installed
    obtain ⟨hany, hfit⟩ := Cosign.record_installed.1 hr
    simp only [hr, reduceCtorEq, ↓reduceIte] at hc hq
    rw [hr] at hfence hpassed ⊢
    have hno : ∀ z ∈ s.certs, z.tenantId = e.tenantId → z.epoch = e.epoch → False := by
      intro z hz h1 h2
      have : (s.certs.any fun x => x.tenantId == e.tenantId && x.epoch == e.epoch) = true :=
        List.any_eq_true.2 ⟨z, hz, by simp [h1, h2]⟩
      rw [hany] at this
      cases this
    have hfz : ∀ z ∈ s.certs, z.tenantId = e.tenantId →
        (if z.epoch < e.epoch then z.chain.isPrefixOf e.chain else e.chain.isPrefixOf z.chain) = true := by
      intro z hz h1
      rw [Cosign.fits_chainless (d.chainless _)] at hfit
      have := List.all_eq_true.1 hfit z hz
      simp only [h1, bne_self_eq_false, Bool.false_or, Bool.and_eq_true] at this
      exact this.2
    refine { certs := fun x => ?_, eqv := fun y => ?_, pair := fun q hq' => ?_, fence := hfence, uniq := ?_,
             ordered := ?_, passed := hpassed, rest := d.rest,
             chainless := hcl }
    · show x ∈ (Cosign.record s.toAuth e).1.certs ↔ _
      rw [hc, List.mem_cons, d.certs x, List.mem_append, List.mem_singleton, Prod.mk.injEq]
      constructor
      · rintro (h | h)
        · exact .inr ⟨h, rfl⟩
        · exact .inl h
      · rintro (h | h)
        · exact .inr h
        · exact .inl h.1
    · show (∃ q ∈ (Cosign.record s.toAuth e).1.equivocations, q.2 = y) ↔ _
      rw [hq, d.eqv y, List.mem_append, List.mem_singleton, Prod.mk.injEq]
      constructor
      · exact .inl
      · rintro (h | ⟨-, h⟩)
        · exact h
        · cases h
    · have hq'' : q ∈ (Cosign.record s.toAuth e).1.equivocations := hq'
      rw [hq] at hq''
      obtain ⟨h1, h2, h3⟩ := d.pair q hq''
      refine ⟨?_, h2, h3⟩
      show q.1 ∈ (Cosign.record s.toAuth e).1.certs
      rw [hc]
      exact List.mem_cons_of_mem _ h1
    · intro x hx y hy hxt hxe
      have hx' : x ∈ (Cosign.record s.toAuth e).1.certs := hx
      have hy' : y ∈ (Cosign.record s.toAuth e).1.certs := hy
      rw [hc] at hx' hy'
      rcases List.mem_cons.1 hx' with hxe' | hx' <;> rcases List.mem_cons.1 hy' with hye' | hy'
      · rw [hxe', hye']
      · rw [hxe'] at hxt hxe
        exact (hno y hy' hxt.symm hxe.symm).elim
      · rw [hye'] at hxt hxe
        exact (hno x hx' hxt hxe).elim
      · exact d.uniq x hx' y hy' hxt hxe
    · intro x hx y hy hxt hlt
      have hx' : x ∈ (Cosign.record s.toAuth e).1.certs := hx
      have hy' : y ∈ (Cosign.record s.toAuth e).1.certs := hy
      rw [hc] at hx' hy'
      rcases List.mem_cons.1 hx' with hxe' | hx' <;> rcases List.mem_cons.1 hy' with hye' | hy'
      · rw [hxe', hye'] at hlt
        exact absurd hlt (Nat.lt_irrefl _)
      · rw [hxe'] at hxt hlt ⊢
        have := hfz y hy' hxt.symm
        rw [if_neg (Nat.lt_asymm hlt)] at this
        exact this
      · rw [hye'] at hxt hlt ⊢
        have := hfz x hx' hxt
        rw [if_pos hlt] at this
        exact this
      · exact d.ordered x hx' y hy' hxt hlt
  · -- unfit
    simp only [hr, reduceCtorEq, ↓reduceIte] at hc hq
    rw [hr] at hfence hpassed ⊢
    refine { certs := fun x => ?_, eqv := fun y => ?_, pair := fun q hq' => ?_, fence := hfence, uniq := ?_,
             ordered := ?_, passed := hpassed, rest := d.rest,
             chainless := hcl }
    · show x ∈ (Cosign.record s.toAuth e).1.certs ↔ _
      rw [hc, d.certs x, List.mem_append, List.mem_singleton, Prod.mk.injEq]
      constructor
      · exact .inl
      · rintro (h | ⟨-, h⟩)
        · exact h
        · cases h
    · show (∃ q ∈ (Cosign.record s.toAuth e).1.equivocations, q.2 = y) ↔ _
      rw [hq, d.eqv y, List.mem_append, List.mem_singleton, Prod.mk.injEq]
      constructor
      · exact .inl
      · rintro (h | ⟨-, h⟩)
        · exact h
        · cases h
    · have hq'' : q ∈ (Cosign.record s.toAuth e).1.equivocations := hq'
      rw [hq] at hq''
      obtain ⟨h1, h2, h3⟩ := d.pair q hq''
      refine ⟨?_, h2, h3⟩
      show q.1 ∈ (Cosign.record s.toAuth e).1.certs
      rw [hc]
      exact h1
    · intro x hx y hy
      have hx' : x ∈ (Cosign.record s.toAuth e).1.certs := hx
      have hy' : y ∈ (Cosign.record s.toAuth e).1.certs := hy
      rw [hc] at hx' hy'
      exact d.uniq x hx' y hy'
    · intro x hx y hy
      have hx' : x ∈ (Cosign.record s.toAuth e).1.certs := hx
      have hy' : y ∈ (Cosign.record s.toAuth e).1.certs := hy
      rw [hc] at hx' hy'
      exact d.ordered x hx' y hy'
  · -- equivocates
    have hany := Cosign.record_equivocates.1 hr
    simp only [hr, reduceCtorEq, ↓reduceIte] at hc hq
    rw [hr] at hfence hpassed ⊢
    have hcert : ∀ z, z ∈ s.certs → z ∈ (Cosign.record s.toAuth e).1.certs := by
      intro z hz; rw [hc]; exact hz
    refine { certs := fun x => ?_, eqv := fun y => ?_, pair := fun q hq' => ?_, fence := hfence, uniq := ?_,
             ordered := ?_, passed := hpassed, rest := d.rest,
             chainless := hcl }
    · show x ∈ (Cosign.record s.toAuth e).1.certs ↔ _
      rw [hc, d.certs x, List.mem_append, List.mem_singleton, Prod.mk.injEq]
      constructor
      · exact .inl
      · rintro (h | ⟨-, h⟩)
        · exact h
        · cases h
    · show (∃ q ∈ (Cosign.record s.toAuth e).1.equivocations, q.2 = y) ↔ _
      rw [hq, List.mem_append, List.mem_singleton, Prod.mk.injEq]
      constructor
      · rintro ⟨q, hq', rfl⟩
        rcases List.mem_append.1 hq' with h | h
        · obtain ⟨z, -, rfl⟩ := List.mem_map.1 h
          exact .inr ⟨rfl, rfl⟩
        · exact .inl ((d.eqv q.2).1 ⟨q, h, rfl⟩)
      · rintro (h | ⟨hy, -⟩)
        · obtain ⟨q, hq', hqy⟩ := (d.eqv y).2 h
          exact ⟨q, List.mem_append_right _ hq', hqy⟩
        · obtain ⟨z, hz, hp⟩ := List.any_eq_true.1 hany
          exact ⟨(z, e), List.mem_append_left _ (List.mem_map.2 ⟨z, List.mem_filter.2 ⟨hz, hp⟩, rfl⟩), hy.symm⟩
    · have hq'' : q ∈ (Cosign.record s.toAuth e).1.equivocations := hq'
      rw [hq] at hq''
      rcases List.mem_append.1 hq'' with h | h
      · obtain ⟨z, hz, rfl⟩ := List.mem_map.1 h
        obtain ⟨hz, hp⟩ := List.mem_filter.1 hz
        simp only [Bool.and_eq_true, beq_iff_eq] at hp
        exact ⟨hcert z hz, hp.1, hp.2⟩
      · obtain ⟨h1, h2, h3⟩ := d.pair q h
        exact ⟨hcert _ h1, h2, h3⟩
    · intro x hx y hy
      have hx' : x ∈ (Cosign.record s.toAuth e).1.certs := hx
      have hy' : y ∈ (Cosign.record s.toAuth e).1.certs := hy
      rw [hc] at hx' hy'
      exact d.uniq x hx' y hy'
    · intro x hx y hy
      have hx' : x ∈ (Cosign.record s.toAuth e).1.certs := hx
      have hy' : y ∈ (Cosign.record s.toAuth e).1.certs := hy
      rw [hc] at hx' hy'
      exact d.ordered x hx' y hy'

/-- The store's rows describe the state the history was recorded into. -/
theorem described (ok : Cosign.KeyCert → Bool) (h : List Cosign.KeyCert) :
    Described ok (replay ok h) (table ok h) := by
  induction h using snoc_induction with
  | nil => constructor <;> simp [replay, table, rowsFrom, emptyState, Cosign.Auth.empty]
  | snoc h e ih =>
    rw [replay_snoc, table_snoc]
    rcases admit_cases ok (replay ok h) e with ⟨ha, -⟩ | ⟨hok, -, ha⟩
    · rw [ha]; simpa using ih
    · rw [ha]; exact described_record ih hok

/-! ### A selection of rows replays to itself -/

theorem mem_pick_iff {α : Type} {l : List α} {ids : List Nat} {a : α} :
    a ∈ pick l ids ↔ ∃ i, l[i]? = some a ∧ i ∈ ids := by
  constructor
  · intro h
    simp only [pick, List.mem_map, List.mem_filter] at h
    obtain ⟨⟨b, i⟩, ⟨hm, hc⟩, rfl⟩ := h
    exact ⟨i, List.mem_zipIdx_iff_getElem?.1 hm, by simpa using hc⟩
  · rintro ⟨i, hi, hids⟩
    exact mem_pick_idx hi hids

theorem pick_mono {α : Type} {l : List α} {ids ids' : List Nat} (h : ∀ i, i ∈ ids → i ∈ ids') {a : α}
    (ha : a ∈ pick l ids) : a ∈ pick l ids' := by
  obtain ⟨i, hi, hids⟩ := mem_pick_iff.1 ha
  exact mem_pick_idx hi (h i hids)

theorem any_false_sub {α : Type} {A B : List α} (h : ∀ x ∈ A, x ∈ B) {p : α → Bool} (hb : B.any p = false) :
    A.any p = false := by
  rw [List.any_eq_false] at hb ⊢
  exact fun x hx => hb x (h x hx)

theorem all_sub {α : Type} {A B : List α} (h : ∀ x ∈ A, x ∈ B) {p : α → Bool} (hb : B.all p = true) :
    A.all p = true := by
  rw [List.all_eq_true] at hb ⊢
  exact fun x hx => hb x (h x hx)

/-- The certificates and equivocations of a state lie in those of a state whose rows include its rows. -/
theorem described_sub {ok : Cosign.KeyCert → Bool} {W s : PayerState}
    {P L : List (Cosign.KeyCert × Cosign.CertAnswer)} (dW : Described ok W P) (d : Described ok s L)
    (hP : ∀ r ∈ P, r ∈ L) :
    (∀ x ∈ W.certs, x ∈ s.certs) ∧ (∀ q ∈ W.equivocations, ∃ q' ∈ s.equivocations, q'.2 = q.2) :=
  ⟨fun x hx => (d.certs x).2 (hP _ ((dW.certs x).1 hx)),
   fun q hq => (d.eqv q.2).2 (hP _ ((dW.eqv q.2).1 ⟨q, hq, rfl⟩))⟩

theorem held_sub {a b : Cosign.Auth} (hc : ∀ x ∈ a.certs, x ∈ b.certs)
    (hq : ∀ q ∈ a.equivocations, ∃ q' ∈ b.equivocations, q'.2 = q.2) {e : Cosign.KeyCert}
    (h : Cosign.held a e = true) : Cosign.held b e = true := by
  unfold Cosign.held at h ⊢
  simp only [Bool.or_eq_true, List.any_eq_true] at h ⊢
  rcases h with ⟨x, hx, hb⟩ | ⟨q, hq', hb⟩
  · exact .inl ⟨x, hc x hx, hb⟩
  · obtain ⟨q', hm, he⟩ := hq q hq'
    exact .inr ⟨q', hm, by rw [he]; exact hb⟩

/-- Rows picked from a store's rows, each `installed` or `equivocates`, with an `installed` row of its tenant and
    epoch picked beside each `equivocates` row, are recorded again with the same answers when their certificates
    are admitted in order: the picked certificates' table is the picked rows. -/
theorem table_pick (ok : Cosign.KeyCert → Bool) (h : List Cosign.KeyCert) : ∀ ids : List Nat,
    (∀ r ∈ pick (table ok h) ids, r.2 = .installed ∨ r.2 = .equivocates) →
    (∀ y ∈ pick (table ok h) ids, y.2 = .equivocates → ∃ x ∈ pick (table ok h) ids, x.2 = .installed ∧
      x.1.tenantId = y.1.tenantId ∧ x.1.epoch = y.1.epoch) →
    table ok ((pick (table ok h) ids).map (·.1)) = pick (table ok h) ids := by
  induction h using snoc_induction with
  | nil => intro ids _ _; simp [table, rowsFrom, pick]
  | snoc h e ih =>
    intro ids h1 h2
    have d := described ok h
    rw [table_snoc] at h1 h2 ⊢
    rcases admit_cases ok (replay ok h) e with ⟨ha, -⟩ | ⟨hok, hheld, ha⟩
    · rw [ha] at h1 h2 ⊢
      simp only [Option.map_none, Option.toList_none, List.append_nil] at h1 h2 ⊢
      exact ih ids h1 h2
    · rw [ha] at h1 h2 ⊢
      simp only [Option.map_some, Option.toList_some] at h1 h2 ⊢
      generalize hr : (Cosign.record (replay ok h).toAuth e).2 = r at h1 h2 ⊢
      rw [pick_snoc] at h1 h2 ⊢
      have hPL : ∀ r ∈ pick (table ok h) ids, r ∈ table ok h := fun r hr => mem_pick hr
      have h1' : ∀ r ∈ pick (table ok h) ids, r.2 = .installed ∨ r.2 = .equivocates :=
        fun r hr => h1 r (List.mem_append_left _ hr)
      have h2' : ∀ y ∈ pick (table ok h) ids, y.2 = .equivocates → ∃ x ∈ pick (table ok h) ids,
          x.2 = .installed ∧ x.1.tenantId = y.1.tenantId ∧ x.1.epoch = y.1.epoch := by
        intro y hy hye
        obtain ⟨x, hx, hxi, hxt, hxe⟩ := h2 y (List.mem_append_left _ hy) hye
        rcases List.mem_append.1 hx with hx | hx
        · exact ⟨x, hx, hxi, hxt, hxe⟩
        · exfalso
          split at hx
          · rw [List.mem_singleton] at hx
            subst hx
            have hyL : (y.1, Cosign.CertAnswer.equivocates) ∈ table ok h := by rw [← hye]; exact hPL y hy
            obtain ⟨q, hq, hq2⟩ := (d.eqv y.1).2 hyL
            obtain ⟨hq1, hqt, hqe⟩ := d.pair q hq
            have hany : ((replay ok h).certs.any fun x => x.tenantId == e.tenantId && x.epoch == e.epoch) = true :=
              List.any_eq_true.2 ⟨q.1, hq1, by
                simp only [Bool.and_eq_true, beq_iff_eq]
                exact ⟨by rw [hqt, hq2]; exact hxt.symm, by rw [hqe, hq2]; exact hxe.symm⟩⟩
            have hre := Cosign.record_equivocates.2 hany
            rw [hr] at hre
            simp [hre] at hxi
          · simp at hx
      have ihP := ih ids h1' h2'
      have dW : Described ok (replay ok ((pick (table ok h) ids).map (·.1))) (pick (table ok h) ids) := by
        have := described ok ((pick (table ok h) ids).map (·.1)); rwa [ihP] at this
      obtain ⟨hsc, hsq⟩ := described_sub dW d hPL
      by_cases hin : (table ok h).length ∈ ids
      · rw [if_pos hin] at h1 h2 ⊢
        rw [List.map_append, List.map_singleton, table_snoc, ihP]
        congr 1
        have hnh : Cosign.held (replay ok ((pick (table ok h) ids).map (·.1))).toAuth e = false := by
          cases hw : Cosign.held (replay ok ((pick (table ok h) ids).map (·.1))).toAuth e
          · rfl
          · rw [held_sub hsc hsq hw] at hheld; cases hheld
        have hrec : (Cosign.record (replay ok ((pick (table ok h) ids).map (·.1))).toAuth e).2 = r := by
          rcases h1 (e, r) (List.mem_append_right _ (List.mem_singleton_self _)) with hri | hre
          · have hri' : r = .installed := hri
            have hs := hr.trans hri'
            obtain ⟨hany, hfit⟩ := Cosign.record_installed.1 hs
            rw [hri', Cosign.record_installed]
            exact ⟨any_false_sub hsc hany, by
              rw [Cosign.fits_chainless (d.chainless _)] at hfit
              rw [Cosign.fits_chainless (dW.chainless _)]; exact all_sub hsc hfit⟩
          · obtain ⟨x, hx, hxi, hxt, hxe⟩ :=
              h2 (e, r) (List.mem_append_right _ (List.mem_singleton_self _)) hre
            rcases List.mem_append.1 hx with hx | hx
            · have hre' : r = .equivocates := hre
              rw [hre', Cosign.record_equivocates]
              refine List.any_eq_true.2 ⟨x.1, (dW.certs x.1).2 (by rw [← hxi]; exact hx), ?_⟩
              simp only [Bool.and_eq_true, beq_iff_eq]
              exact ⟨hxt, hxe⟩
            · rw [List.mem_singleton] at hx
              subst hx
              have h1r : r = .installed := hxi
              have h2r : r = .equivocates := hre
              rw [h1r] at h2r; cases h2r
        simp [admit, hok, hnh, hrec]
      · rw [if_neg hin] at h1 h2 ⊢
        simp only [List.append_nil]
        exact ihP

/-! ### The certificate witnesses of a STORE or RELEASE -/

theorem mem_selectIds {rows : List (Cosign.KeyCert × Cosign.CertAnswer)} {T : Bytes} {Q : List Nat} {i : Nat} :
    i ∈ selectIds rows T Q ↔ ∃ E ∈ Q,
      rows.findIdx? (fun r => r.1.tenantId == T && r.2 == .installed && r.1.epoch == E) = some i ∨
      rows.findIdx? (fun r => r.1.tenantId == T && r.2 == .equivocates && r.1.epoch == E) = some i := by
  simp only [selectIds, List.mem_flatMap, List.mem_append, Option.mem_toList]

/-- A witness row is the tenant's, of an epoch of `Q`, `installed` or `equivocates`. -/
theorem sel_row {rows : List (Cosign.KeyCert × Cosign.CertAnswer)} {T : Bytes} {Q : List Nat}
    {r : Cosign.KeyCert × Cosign.CertAnswer} (hr : r ∈ pick rows (selectIds rows T Q)) :
    r.1.tenantId = T ∧ r.1.epoch ∈ Q ∧ (r.2 = .installed ∨ r.2 = .equivocates) := by
  obtain ⟨i, hi, hids⟩ := mem_pick_iff.1 hr
  obtain ⟨E, hE, hf | hf⟩ := mem_selectIds.1 hids
  · obtain ⟨a, ha, hp, -⟩ := findIdx_get hf
    obtain rfl : r = a := Option.some.inj (hi.symm.trans ha)
    simp only [Bool.and_eq_true, beq_iff_eq] at hp
    exact ⟨hp.1.1, by rw [hp.2]; exact hE, .inl hp.1.2⟩
  · obtain ⟨a, ha, hp, -⟩ := findIdx_get hf
    obtain rfl : r = a := Option.some.inj (hi.symm.trans ha)
    simp only [Bool.and_eq_true, beq_iff_eq] at hp
    exact ⟨hp.1.1, by rw [hp.2]; exact hE, .inr hp.1.2⟩

/-- For a row of the tenant, of an epoch of `Q`, `installed` or `equivocates`, the witnesses hold a row of the
    same answer, tenant and epoch. -/
theorem sel_first {rows : List (Cosign.KeyCert × Cosign.CertAnswer)} {T : Bytes} {Q : List Nat}
    {r : Cosign.KeyCert × Cosign.CertAnswer} (hr : r ∈ rows) (ht : r.1.tenantId = T) (hE : r.1.epoch ∈ Q)
    (h2 : r.2 = .installed ∨ r.2 = .equivocates) :
    ∃ r' ∈ pick rows (selectIds rows T Q), r'.2 = r.2 ∧ r'.1.tenantId = T ∧ r'.1.epoch = r.1.epoch := by
  rcases h2 with h2 | h2
  · obtain ⟨k, hk⟩ := findIdx_of_mem (q := fun x : Cosign.KeyCert × Cosign.CertAnswer =>
      x.1.tenantId == T && x.2 == .installed && x.1.epoch == r.1.epoch) hr (by simp [ht, h2])
    obtain ⟨a, ha, hp, -⟩ := findIdx_get hk
    simp only [Bool.and_eq_true, beq_iff_eq] at hp
    exact ⟨a, mem_pick_idx ha (mem_selectIds.2 ⟨r.1.epoch, hE, .inl hk⟩), by rw [hp.1.2, h2], hp.1.1, hp.2⟩
  · obtain ⟨k, hk⟩ := findIdx_of_mem (q := fun x : Cosign.KeyCert × Cosign.CertAnswer =>
      x.1.tenantId == T && x.2 == .equivocates && x.1.epoch == r.1.epoch) hr (by simp [ht, h2])
    obtain ⟨a, ha, hp, -⟩ := findIdx_get hk
    simp only [Bool.and_eq_true, beq_iff_eq] at hp
    exact ⟨a, mem_pick_idx ha (mem_selectIds.2 ⟨r.1.epoch, hE, .inr hk⟩), by rw [hp.1.2, h2], hp.1.1, hp.2⟩

/-- The witnesses replay to their own rows. -/
theorem table_select (ok : Cosign.KeyCert → Bool) (h : List Cosign.KeyCert) (T : Bytes) (Q : List Nat) :
    table ok (select (table ok h) T Q) = pick (table ok h) (selectIds (table ok h) T Q) := by
  have d := described ok h
  unfold select
  refine table_pick ok h _ (fun r hr => (sel_row hr).2.2) fun y hy hye => ?_
  obtain ⟨hyt, hyE, -⟩ := sel_row hy
  obtain ⟨q, hq, hq2⟩ := (d.eqv y.1).2 (by rw [← hye]; exact mem_pick hy)
  obtain ⟨hq1, hqt, hqe⟩ := d.pair q hq
  obtain ⟨r', hr', h2, ht', hE'⟩ := sel_first (T := T) (Q := Q) (r := (q.1, .installed)) ((d.certs q.1).1 hq1)
    (show q.1.tenantId = T by rw [hqt, hq2, hyt]) (show q.1.epoch ∈ Q by rw [hqe, hq2]; exact hyE) (.inl rfl)
  exact ⟨r', hr', h2, by rw [ht', hyt], by rw [hE']; show q.1.epoch = _; rw [hqe, hq2]⟩

/-- On the witnesses of tenant `T` and epochs `Q`, the installed certificates are the whole history's of those
    epochs, and an equivocation blocks an epoch of `Q` exactly when it does on the whole history. -/
theorem select_view {ok : Cosign.KeyCert → Bool} {T : Bytes} (hT : ∀ e, ok e = true → e.tenantId = T)
    (h : List Cosign.KeyCert) (Q : List Nat) :
    (∀ x, x ∈ (replay ok (select (table ok h) T Q)).certs ↔ x ∈ (replay ok h).certs ∧ x.epoch ∈ Q) ∧
    (∀ E ∈ Q, ((replay ok (select (table ok h) T Q)).equivocations.any
        fun q => q.1.tenantId == T && q.1.epoch == E) =
      ((replay ok h).equivocations.any fun q => q.1.tenantId == T && q.1.epoch == E)) := by
  have d := described ok h
  have dW : Described ok (replay ok (select (table ok h) T Q)) (pick (table ok h) (selectIds (table ok h) T Q)) := by
    have := described ok (select (table ok h) T Q); rwa [table_select] at this
  obtain ⟨hsc, hsq⟩ := described_sub dW d fun r hr => mem_pick hr
  refine ⟨fun x => ⟨fun hx => ⟨hsc x hx, (sel_row ((dW.certs x).1 hx)).2.1⟩, fun ⟨hx, hE⟩ => ?_⟩, fun E hE => ?_⟩
  · have hxL := (d.certs x).1 hx
    obtain ⟨r', hr', h2, ht', hE'⟩ := sel_first (T := T) hxL (hT _ (d.passed _ hxL)) hE (.inl rfl)
    have h2' : r'.2 = .installed := h2
    have hr'W : r'.1 ∈ (replay ok (select (table ok h) T Q)).certs := (dW.certs r'.1).2 (by rw [← h2']; exact hr')
    have hxT : x.tenantId = T := hT _ (d.passed _ hxL)
    rw [d.uniq r'.1 (hsc _ hr'W) x hx (ht'.trans hxT.symm) hE'] at hr'W
    exact hr'W
  · apply Bool.eq_iff_iff.2
    simp only [List.any_eq_true, Bool.and_eq_true, beq_iff_eq]
    constructor
    · rintro ⟨q, hq, hqt, hqe⟩
      obtain ⟨-, hpt, hpe⟩ := dW.pair q hq
      obtain ⟨q', hq', hq2⟩ := hsq q hq
      obtain ⟨-, h1, h2⟩ := d.pair q' hq'
      exact ⟨q', hq', by rw [h1, hq2, ← hpt, hqt], by rw [h2, hq2, ← hpe, hqe]⟩
    · rintro ⟨q, hq, hqt, hqe⟩
      obtain ⟨-, hpt, hpe⟩ := d.pair q hq
      obtain ⟨r', hr', h2, ht', hE'⟩ := sel_first (T := T) (Q := Q) ((d.eqv q.2).1 ⟨q, hq, rfl⟩)
        (show q.2.tenantId = T by rw [← hpt, hqt]) (show q.2.epoch ∈ Q by rw [← hpe, hqe]; exact hE) (.inr rfl)
      have h2' : r'.2 = .equivocates := h2
      obtain ⟨q'', hq'', hq''2⟩ := (dW.eqv r'.1).2 (by rw [← h2']; exact hr')
      obtain ⟨-, h1, h2''⟩ := dW.pair q'' hq''
      exact ⟨q'', hq'', by rw [h1, hq''2, ht'], by rw [h2'', hq''2, hE']; show q.2.epoch = E; rw [← hpe, hqe]⟩

/-- No row of another tenant: that tenant's fence is 0. -/
theorem fence_other {ok : Cosign.KeyCert → Bool} {T : Bytes} (hT : ∀ e, ok e = true → e.tenantId = T)
    {s : PayerState} {R : List (Cosign.KeyCert × Cosign.CertAnswer)} (d : Described ok s R) {y : Bytes}
    (hy : y ≠ T) : s.fence y = 0 :=
  Nat.le_zero.1 ((d.fence y 0).2 fun r hr hry => (hy (hry.symm.trans (hT _ (d.passed r hr)))).elim)

theorem selectFence_spec {rows : List (Cosign.KeyCert × Cosign.CertAnswer)} {T : Bytes} {Q : List Nat}
    {x : Cosign.KeyCert} (h : selectFence rows T Q = some x) : ∃ r ∈ rows, r.1 = x ∧ r.1.tenantId = T := by
  unfold selectFence at h
  obtain ⟨r, hr, h⟩ := Option.bind_eq_some_iff.1 h
  obtain ⟨m, -, hf⟩ := Option.bind_eq_some_iff.1 hr
  have hp := List.find?_some hf
  simp only [Bool.and_eq_true, beq_iff_eq] at hp
  split at h
  · cases h
  · cases h; exact ⟨r, List.mem_of_find?_eq_some hf, rfl, hp.1⟩

/-- The tenant's highest epoch and its first row. -/
theorem topEpoch_spec {rows : List (Cosign.KeyCert × Cosign.CertAnswer)} {T : Bytes}
    {r : Cosign.KeyCert × Cosign.CertAnswer} (hr : r ∈ rows) (ht : r.1.tenantId = T) :
    ∃ m r1, topEpoch rows T = some m ∧ r.1.epoch ≤ m ∧
      rows.find? (fun r => r.1.tenantId == T && r.1.epoch == m) = some r1 ∧ r1 ∈ rows ∧
      r1.1.tenantId = T ∧ r1.1.epoch = m := by
  have hmem : r.1.epoch ∈ (rows.filter (·.1.tenantId == T)).map (·.1.epoch) :=
    List.mem_map.2 ⟨r, List.mem_filter.2 ⟨hr, by simp [ht]⟩, rfl⟩
  obtain ⟨m, hm⟩ := Option.isSome_iff_exists.1 (List.isSome_max?_of_mem hmem)
  obtain ⟨hmm, hmax⟩ := List.max?_eq_some_iff.1 hm
  obtain ⟨r0, hr0, hr0e⟩ := List.mem_map.1 hmm
  obtain ⟨hr0L, hr0t⟩ := List.mem_filter.1 hr0
  obtain ⟨r1, hf⟩ : ∃ r1, rows.find? (fun r => r.1.tenantId == T && r.1.epoch == m) = some r1 := by
    cases hf : rows.find? (fun r => r.1.tenantId == T && r.1.epoch == m) with
    | some r1 => exact ⟨r1, rfl⟩
    | none =>
      have := List.find?_eq_none.1 hf r0 hr0L
      simp only [beq_iff_eq] at hr0t
      simp [hr0t, hr0e] at this
  have h1 := List.find?_some hf
  simp only [Bool.and_eq_true, beq_iff_eq] at h1
  exact ⟨m, r1, hm, hmax _ hmem, hf, List.mem_of_find?_eq_some hf, h1.1, h1.2⟩

/-- The witnesses and the fence certificate give the tenant the fence the whole history gives it. -/
theorem select_fence {ok : Cosign.KeyCert → Bool} {T : Bytes} (hT : ∀ e, ok e = true → e.tenantId = T)
    (h : List Cosign.KeyCert) (Q : List Nat) (a : Cosign.Auth) :
    (onLinks (replay ok (select (table ok h) T Q))
        { a with fence := raiseFence a.fence T (fenceOf ok (selectFence (table ok h) T Q)) }).fence =
      (onLinks (replay ok h) a).fence := by
  have d := described ok h
  have dW : Described ok (replay ok (select (table ok h) T Q)) (pick (table ok h) (selectIds (table ok h) T Q)) := by
    have := described ok (select (table ok h) T Q); rwa [table_select] at this
  have hcerts := (select_view hT h Q).1
  have hWle : (replay ok (select (table ok h) T Q)).fence T ≤ (replay ok h).fence T :=
    (dW.fence T _).2 fun r hr hrt => (d.fence T _).1 (Nat.le_refl _) r (mem_pick hr) hrt
  have hFle : fenceOf ok (selectFence (table ok h) T Q) ≤ (replay ok h).fence T := by
    unfold fenceOf
    cases hf : selectFence (table ok h) T Q with
    | none => exact Nat.zero_le _
    | some x =>
      obtain ⟨r, hr, hrx, hrt⟩ := selectFence_spec hf
      have := (d.fence T _).1 (Nat.le_refl _) r hr hrt
      rw [hrx] at this
      cases hx : ok x <;> simp [Option.filter, hx, this]
  have hge : (replay ok h).fence T ≤
      max ((replay ok (select (table ok h) T Q)).fence T) (fenceOf ok (selectFence (table ok h) T Q)) := by
    refine (d.fence T _).2 fun r hr hrt => ?_
    obtain ⟨m, r1, hm, hle, hf, hr1, hr1t, hr1e⟩ := topEpoch_spec hr hrt
    refine Nat.le_trans hle ?_
    by_cases hc : (Q.contains r1.1.epoch && (r1.2 == .installed || r1.2 == .equivocates)) = true
    · simp only [Bool.and_eq_true, Bool.or_eq_true, beq_iff_eq, List.contains_iff_mem] at hc
      obtain ⟨x, hx, hxt, hxe⟩ : ∃ x ∈ (replay ok h).certs, x.tenantId = T ∧ x.epoch = m := by
        rcases hc.2 with hi | hq
        · exact ⟨r1.1, (d.certs r1.1).2 (by rw [← hi]; exact hr1), hr1t, hr1e⟩
        · obtain ⟨q, hq', hq2⟩ := (d.eqv r1.1).2 (by rw [← hq]; exact hr1)
          obtain ⟨hq1, hqt, hqe⟩ := d.pair q hq'
          exact ⟨q.1, hq1, by rw [hqt, hq2, hr1t], by rw [hqe, hq2, hr1e]⟩
      have hxW := (hcerts x).2 ⟨hx, by rw [hxe, ← hr1e]; exact hc.1⟩
      have := (dW.fence T _).1 (Nat.le_refl _) (x, .installed) ((dW.certs x).1 hxW) hxt
      rw [hxe] at this
      exact Nat.le_trans this (Nat.le_max_left _ _)
    · have hsf : selectFence (table ok h) T Q = some r1.1 := by
        unfold selectFence
        rw [hm, Option.bind_some, hf, Option.bind_some, if_neg hc]
      have hok : ok r1.1 = true := d.passed r1 hr1
      refine Nat.le_trans ?_ (Nat.le_max_right _ _)
      simp [fenceOf, hsf, Option.filter, hok, hr1e]
  funext t
  simp only [onLinks, raiseFence]
  by_cases ht : t = T
  · subst ht
    rw [if_pos rfl]
    apply Nat.le_antisymm
    · exact Nat.max_le.2 ⟨Nat.le_trans hWle (Nat.le_max_left _ _),
        Nat.max_le.2 ⟨Nat.le_max_right _ _, Nat.le_trans hFle (Nat.le_max_left _ _)⟩⟩
    · exact Nat.max_le.2 ⟨Nat.le_trans hge (Nat.max_le.2 ⟨Nat.le_max_left _ _,
        Nat.le_trans (Nat.le_max_right _ _) (Nat.le_max_right _ _)⟩),
        Nat.le_trans (Nat.le_max_left _ _) (Nat.le_max_right _ _)⟩
  · rw [if_neg ht, fence_other hT dW ht, fence_other hT d ht]

/-! ### The four statements -/

/-- A STORE or RELEASE on the certificate witnesses of its tenant and epochs, with the fence certificate raising
    the fence, answers as on the whole history, under any link part `a`. -/
theorem select_decides {c : Crypto} {ok : Cosign.KeyCert → Bool} {T : Bytes}
    (hT : ∀ e, ok e = true → e.tenantId = T) (h : List Cosign.KeyCert) (Q : List Nat) (a : Cosign.Auth) :
    (∀ old forks new x, decodeCheckpoint new = some x → x.checkpoint.epoch ∈ Q →
      storeOutcome c (onLinks (replay ok (select (table ok h) T Q))
          { a with fence := raiseFence a.fence T (fenceOf ok (selectFence (table ok h) T Q)) }) old forks new =
        storeOutcome c (onLinks (replay ok h) a) old forks new) ∧
    (∀ forks cp now grants released pin p token, (∀ x, decodeCheckpoint cp = some x → x.checkpoint.epoch ∈ Q) →
      releaseOutcome c (onLinks (replay ok (select (table ok h) T Q))
          { a with fence := raiseFence a.fence T (fenceOf ok (selectFence (table ok h) T Q)) })
          forks cp now grants released pin p token =
        releaseOutcome c (onLinks (replay ok h) a) forks cp now grants released pin p token) := by
  have d := described ok h
  have dW := described ok (select (table ok h) T Q)
  obtain ⟨hcerts, heqv⟩ := select_view hT h Q
  have htn : ∀ x ∈ (replay ok h).certs, x.tenantId = T := fun x hx => hT _ (d.passed _ ((d.certs x).1 hx))
  have hany : ∀ (y : Bytes) (E : Nat), E ∈ Q → ∀ g : Cosign.KeyCert → Bool,
      ((replay ok (select (table ok h) T Q)).certs.any fun e => e.tenantId == y && e.epoch == E && g e) =
      ((replay ok h).certs.any fun e => e.tenantId == y && e.epoch == E && g e) := by
    intro y E hE g
    apply Bool.eq_iff_iff.2
    simp only [List.any_eq_true, Bool.and_eq_true, beq_iff_eq]
    constructor
    · rintro ⟨x, hx, hp⟩; exact ⟨x, ((hcerts x).1 hx).1, hp⟩
    · rintro ⟨x, hx, hp⟩; exact ⟨x, (hcerts x).2 ⟨hx, by rw [hp.1.2]; exact hE⟩, hp⟩
  have hfind : ∀ (y : Bytes) (E : Nat), E ∈ Q →
      (replay ok (select (table ok h) T Q)).certs.find? (fun e => e.tenantId == y && e.epoch == E) =
      (replay ok h).certs.find? (fun e => e.tenantId == y && e.epoch == E) := by
    intro y E hE
    cases hs : (replay ok h).certs.find? (fun e => e.tenantId == y && e.epoch == E) with
    | none =>
      rw [List.find?_eq_none] at hs ⊢
      exact fun x hx => hs x ((hcerts x).1 hx).1
    | some x =>
      have hxm := List.mem_of_find?_eq_some hs
      have hxp := List.find?_some hs
      simp only [Bool.and_eq_true, beq_iff_eq] at hxp
      have hxW := (hcerts x).2 ⟨hxm, by rw [hxp.2]; exact hE⟩
      cases hw : (replay ok (select (table ok h) T Q)).certs.find? (fun e => e.tenantId == y && e.epoch == E) with
      | none =>
        have := List.find?_eq_none.1 hw x hxW
        simp [hxp.1, hxp.2] at this
      | some z =>
        have hzm := ((hcerts z).1 (List.mem_of_find?_eq_some hw)).1
        have hzp := List.find?_some hw
        simp only [Bool.and_eq_true, beq_iff_eq] at hzp
        rw [d.uniq z hzm x hxm (hzp.1.trans hxp.1.symm) (hzp.2.trans hxp.2.symm)]
  refine ⟨fun old forks new x hx hE => ?_, fun forks cp now grants released pin p token hcp => ?_⟩
  · refine storeOutcome_congr hx (hany _ _ hE) ?_
    rintro ⟨e, he, het⟩
    have hxT : x.checkpoint.tenantId = T := het ▸ htn e he
    simp only [blocked_eq, Cosign.certBlocked, Cosign.linkBlocked, onLinks, hxT]
    rw [heqv _ hE]
  · unfold releaseOutcome
    dsimp only
    refine firstFailure_congr ?_ ?_ ?_ ?_ ?_ ?_ ?_
    all_goals try rfl
    · exact s1_cps_congr dW.rest d.rest fun x hx => hany _ _ (hcp x hx)
    · rw [getD_fence, getD_fence]; exact select_fence hT h Q a
    · intro t st _ hbt hi
      obtain ⟨x, hx, hst, e, he, het⟩ :=
        release_cps (s0 := onLinks (replay ok h) a) d.rest (List.mem_of_find?_eq_some hbt)
      simp only [inBatch, Bool.and_eq_true, beq_iff_eq] at hi
      have h3 : t.leaf.epoch ∈ Q := by rw [← hi.1.1.2, hst]; exact hcp x hx
      have h1 : t.leaf.tenantId = T := by rw [← hi.1.1.1.1.1, hst, ← het]; exact htn e he
      refine ⟨?_, ?_⟩
      · simp only [routed, countAt]
        rw [getD_certs, getD_certs]
        simp only [onLinks]
        rw [hfind _ _ h3]
      · simp only [unforked, blocked_eq, Cosign.certBlocked, Cosign.linkBlocked]
        rw [getD_chain, getD_chain]
        simp only [onLinks, h1]
        rw [heqv _ h3]

theorem lowerId_spec {rows : List (Cosign.KeyCert × Cosign.CertAnswer)} {T : Bytes} {E k : Nat}
    (h : lowerId rows T E = some k) : ∃ r, rows[k]? = some r ∧ r.1.tenantId = T ∧ r.2 = .installed ∧
      r.1.epoch < E ∧ ∀ r' ∈ rows, r'.1.tenantId = T → r'.2 = .installed → r'.1.epoch < E →
        r'.1.epoch ≤ r.1.epoch := by
  unfold lowerId at h
  obtain ⟨m, hm, h⟩ := Option.bind_eq_some_iff.1 h
  obtain ⟨hmm, hmax⟩ := List.max?_eq_some_iff.1 hm
  obtain ⟨r, hr, hp, -⟩ := findIdx_get h
  simp only [Bool.and_eq_true, beq_iff_eq] at hp
  obtain ⟨r0, hr0, hr0e⟩ := List.mem_map.1 hmm
  simp only [List.mem_filter, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at hr0
  refine ⟨r, hr, hp.1.1, hp.1.2, by rw [hp.2, ← hr0e]; exact hr0.2.2, fun r' hr' h1 h2 h3 => ?_⟩
  rw [hp.2]
  exact hmax _ (List.mem_map.2 ⟨r', List.mem_filter.2 ⟨hr', by simp [h1, h2, h3]⟩, rfl⟩)

theorem upperId_spec {rows : List (Cosign.KeyCert × Cosign.CertAnswer)} {T : Bytes} {E k : Nat}
    (h : upperId rows T E = some k) : ∃ r, rows[k]? = some r ∧ r.1.tenantId = T ∧ r.2 = .installed ∧
      E < r.1.epoch ∧ ∀ r' ∈ rows, r'.1.tenantId = T → r'.2 = .installed → E < r'.1.epoch →
        r.1.epoch ≤ r'.1.epoch := by
  unfold upperId at h
  obtain ⟨m, hm, h⟩ := Option.bind_eq_some_iff.1 h
  obtain ⟨hmm, hmin⟩ := List.min?_eq_some_iff.1 hm
  obtain ⟨r, hr, hp, -⟩ := findIdx_get h
  simp only [Bool.and_eq_true, beq_iff_eq] at hp
  obtain ⟨r0, hr0, hr0e⟩ := List.mem_map.1 hmm
  simp only [List.mem_filter, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at hr0
  refine ⟨r, hr, hp.1.1, hp.1.2, by rw [hp.2, ← hr0e]; exact hr0.2.2, fun r' hr' h1 h2 h3 => ?_⟩
  rw [hp.2]
  exact hmin _ (List.mem_map.2 ⟨r', List.mem_filter.2 ⟨hr', by simp [h1, h2, h3]⟩, rfl⟩)

theorem lowerId_some {rows : List (Cosign.KeyCert × Cosign.CertAnswer)} {T : Bytes} {E : Nat}
    {r : Cosign.KeyCert × Cosign.CertAnswer} (hr : r ∈ rows) (h1 : r.1.tenantId = T) (h2 : r.2 = .installed)
    (h3 : r.1.epoch < E) : ∃ k, lowerId rows T E = some k := by
  have hmem : r.1.epoch ∈ (rows.filter fun r => r.1.tenantId == T && r.2 == .installed && r.1.epoch < E).map
      (·.1.epoch) := List.mem_map.2 ⟨r, List.mem_filter.2 ⟨hr, by simp [h1, h2, h3]⟩, rfl⟩
  obtain ⟨m, hm⟩ := Option.isSome_iff_exists.1 (List.isSome_max?_of_mem hmem)
  obtain ⟨hmm, -⟩ := List.max?_eq_some_iff.1 hm
  obtain ⟨r0, hr0, hr0e⟩ := List.mem_map.1 hmm
  simp only [List.mem_filter, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at hr0
  obtain ⟨k, hk⟩ := findIdx_of_mem (q := fun r : Cosign.KeyCert × Cosign.CertAnswer =>
    r.1.tenantId == T && r.2 == .installed && r.1.epoch == m) hr0.1 (by simp [hr0.2.1.1, hr0.2.1.2, hr0e])
  exact ⟨k, by unfold lowerId; rw [hm, Option.bind_some]; exact hk⟩

theorem upperId_some {rows : List (Cosign.KeyCert × Cosign.CertAnswer)} {T : Bytes} {E : Nat}
    {r : Cosign.KeyCert × Cosign.CertAnswer} (hr : r ∈ rows) (h1 : r.1.tenantId = T) (h2 : r.2 = .installed)
    (h3 : E < r.1.epoch) : ∃ k, upperId rows T E = some k := by
  have hmem : r.1.epoch ∈ (rows.filter fun r => r.1.tenantId == T && r.2 == .installed && E < r.1.epoch).map
      (·.1.epoch) := List.mem_map.2 ⟨r, List.mem_filter.2 ⟨hr, by simp [h1, h2, h3]⟩, rfl⟩
  obtain ⟨m, hm⟩ := Option.isSome_iff_exists.1 (List.isSome_min?_of_mem hmem)
  obtain ⟨hmm, -⟩ := List.min?_eq_some_iff.1 hm
  obtain ⟨r0, hr0, hr0e⟩ := List.mem_map.1 hmm
  simp only [List.mem_filter, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at hr0
  obtain ⟨k, hk⟩ := findIdx_of_mem (q := fun r : Cosign.KeyCert × Cosign.CertAnswer =>
    r.1.tenantId == T && r.2 == .installed && r.1.epoch == m) hr0.1 (by simp [hr0.2.1.1, hr0.2.1.2, hr0e])
  exact ⟨k, by unfold upperId; rw [hm, Option.bind_some]; exact hk⟩

theorem prefix_trans {a b c : List Nat} (h1 : a.isPrefixOf b = true) (h2 : b.isPrefixOf c = true) :
    a.isPrefixOf c = true := by
  rw [List.isPrefixOf_iff_prefix] at h1 h2 ⊢
  exact h1.trans h2

theorem find_any {α β : Type} (l : List α) (p : α → Bool) (f : α → β) (g : β → Bool)
    (hpg : ∀ a, p a = true → g (f a) = true) : ((l.find? p).map f).any g = l.any p := by
  cases hf : l.find? p with
  | none => rw [Option.map_none, Option.any_none]; exact (List.any_eq_false.2 (List.find?_eq_none.1 hf)).symm
  | some a =>
    rw [Option.map_some, Option.any_some, hpg a (List.find?_some hf)]
    exact (List.any_eq_true.2 ⟨a, List.mem_of_find?_eq_some hf, List.find?_some hf⟩).symm

/-- INSTALL on the witnesses of the new certificate's epoch and the tenant's installed certificates of the
    nearest epochs below and above answers as on the whole history (shard counts fit by chain prefix); the held
    row the frame carries answers `same` exactly when the whole history holds the body; and the store's rows grow
    by exactly the row that answer writes. -/
theorem install_classifies {ok : Cosign.KeyCert → Bool} {T : Bytes} (hT : ∀ e, ok e = true → e.tenantId = T)
    (h : List Cosign.KeyCert) (e : Cosign.KeyCert) (he : ok e = true) :
    (Cosign.record (replay ok (selectInstall (table ok h) T e.epoch)).toAuth e).2 =
        (Cosign.record (replay ok h).toAuth e).2 ∧
      (sameRow (table ok h) e).any (·.body == e.body) = Cosign.held (replay ok h).toAuth e ∧
      table ok (h ++ [e]) = table ok h ++
        (if Cosign.held (replay ok h).toAuth e then [] else [(e, (Cosign.record (replay ok h).toAuth e).2)]) := by
  have d := described ok h
  have hET : e.tenantId = T := hT e he
  have hmemI : ∀ {i}, i ∈ selectIds (table ok h) T [e.epoch] ++ (lowerId (table ok h) T e.epoch).toList ++
      (upperId (table ok h) T e.epoch).toList ↔ i ∈ selectIds (table ok h) T [e.epoch] ∨
        lowerId (table ok h) T e.epoch = some i ∨ upperId (table ok h) T e.epoch = some i := by
    intro i; simp only [List.mem_append, Option.mem_toList, or_assoc]
  have hrowI : ∀ r ∈ pick (table ok h) (selectIds (table ok h) T [e.epoch] ++ (lowerId (table ok h) T e.epoch).toList ++
      (upperId (table ok h) T e.epoch).toList),
      (r.1.tenantId = T ∧ r.1.epoch = e.epoch ∧ (r.2 = .installed ∨ r.2 = .equivocates)) ∨ r.2 = .installed := by
    intro r hr
    obtain ⟨i, hi, hids⟩ := mem_pick_iff.1 hr
    rcases hmemI.1 hids with hs | hl | hu
    · have := sel_row (mem_pick_idx hi hs)
      exact .inl ⟨this.1, by simpa using this.2.1, this.2.2⟩
    · obtain ⟨r', hr', -, h2, -⟩ := lowerId_spec hl
      obtain rfl : r = r' := Option.some.inj (hi.symm.trans hr')
      exact .inr h2
    · obtain ⟨r', hr', -, h2, -⟩ := upperId_spec hu
      obtain rfl : r = r' := Option.some.inj (hi.symm.trans hr')
      exact .inr h2
  have htp : table ok (selectInstall (table ok h) T e.epoch) = pick (table ok h)
      (selectIds (table ok h) T [e.epoch] ++ (lowerId (table ok h) T e.epoch).toList ++
        (upperId (table ok h) T e.epoch).toList) := by
    unfold selectInstall
    refine table_pick ok h _ (fun r hr => ?_) fun y hy hye => ?_
    · rcases hrowI r hr with ⟨-, -, h'⟩ | h'
      · exact h'
      · exact .inl h'
    · rcases hrowI y hy with ⟨hyt, hyE, -⟩ | hyi
      · obtain ⟨q, hq, hq2⟩ := (d.eqv y.1).2 (by rw [← hye]; exact mem_pick hy)
        obtain ⟨hq1, hqt, hqe⟩ := d.pair q hq
        obtain ⟨r', hr', h2, ht', hE'⟩ := sel_first (T := T) (Q := [e.epoch]) (r := (q.1, .installed))
          ((d.certs q.1).1 hq1) (show q.1.tenantId = T by rw [hqt, hq2, hyt])
          (show q.1.epoch ∈ [e.epoch] by rw [hqe, hq2, hyE]; exact List.mem_singleton_self _) (.inl rfl)
        exact ⟨r', pick_mono (fun i hi => hmemI.2 (.inl hi)) hr', h2, by rw [ht', hyt],
          by rw [hE']; show q.1.epoch = _; rw [hqe, hq2]⟩
      · rw [hyi] at hye; cases hye
  have dW : Described ok (replay ok (selectInstall (table ok h) T e.epoch)) (pick (table ok h)
      (selectIds (table ok h) T [e.epoch] ++ (lowerId (table ok h) T e.epoch).toList ++
        (upperId (table ok h) T e.epoch).toList)) := by
    have := described ok (selectInstall (table ok h) T e.epoch); rwa [htp] at this
  obtain ⟨hsc, -⟩ := described_sub dW d fun r hr => mem_pick hr
  have hany : ((replay ok (selectInstall (table ok h) T e.epoch)).certs.any
        fun x => x.tenantId == e.tenantId && x.epoch == e.epoch) =
      ((replay ok h).certs.any fun x => x.tenantId == e.tenantId && x.epoch == e.epoch) := by
    apply Bool.eq_iff_iff.2
    simp only [List.any_eq_true, Bool.and_eq_true, beq_iff_eq]
    constructor
    · rintro ⟨x, hx, hp⟩; exact ⟨x, hsc x hx, hp⟩
    · rintro ⟨x, hx, hxt, hxe⟩
      obtain ⟨r', hr', h2, ht', hE'⟩ := sel_first (T := T) (Q := [e.epoch]) (r := (x, .installed))
        ((d.certs x).1 hx) (show x.tenantId = T by rw [hxt, hET])
        (show x.epoch ∈ [e.epoch] by rw [hxe]; exact List.mem_singleton_self _) (.inl rfl)
      have h2' : r'.2 = .installed := h2
      refine ⟨r'.1, (dW.certs r'.1).2 ?_, by rw [ht', hET], by rw [hE']; exact hxe⟩
      rw [← h2']; exact pick_mono (fun i hi => hmemI.2 (.inl hi)) hr'
  have hW : ∀ x ∈ (replay ok h).certs, x.tenantId = T → (x, Cosign.CertAnswer.installed) ∈ table ok h →
      ∀ k, (table ok h)[k]? = some (x, .installed) →
        k ∈ selectIds (table ok h) T [e.epoch] ++ (lowerId (table ok h) T e.epoch).toList ++
          (upperId (table ok h) T e.epoch).toList → x ∈ (replay ok (selectInstall (table ok h) T e.epoch)).certs :=
    fun x _ _ _ k hk hi => (dW.certs x).2 (mem_pick_idx hk hi)
  refine ⟨Cosign.record_congr hany fun hno => ?_, ?_, ?_⟩
  · apply Bool.eq_iff_iff.2
    rw [Cosign.fits_chainless (dW.chainless _), Cosign.fits_chainless (d.chainless _)]
    simp only [List.all_eq_true]
    constructor
    · intro hfW x hx
      by_cases hxt : x.tenantId = e.tenantId
      · have hne : x.epoch ≠ e.epoch := fun h' => by
          have := List.any_eq_false.1 hno x hx
          simp [hxt, h'] at this
        have hxT : x.tenantId = T := hxt.trans hET
        have hxL := (d.certs x).1 hx
        rcases Nat.lt_or_gt_of_ne hne with hlt | hgt
        · obtain ⟨k, hk⟩ := lowerId_some (r := (x, .installed)) hxL hxT rfl hlt
          obtain ⟨r, hr, hrt, hri, hrE, hmax⟩ := lowerId_spec hk
          have hrW : r.1 ∈ (replay ok (selectInstall (table ok h) T e.epoch)).certs :=
            (dW.certs r.1).2 (by rw [← hri]; exact mem_pick_idx hr (hmemI.2 (.inr (.inl hk))))
          have h1 := hfW r.1 hrW
          have hrt' : r.1.tenantId = e.tenantId := hrt.trans hET.symm
          simp only [hrt', bne_self_eq_false, Bool.false_or, Bool.and_eq_true, if_pos hrE] at h1
          have hle := hmax (x, .installed) hxL hxT rfl hlt
          have hxr : x.chain.isPrefixOf r.1.chain = true := by
            rcases Nat.lt_or_eq_of_le hle with hl | he'
            · exact d.ordered x hx r.1 (hsc _ hrW) (hxT.trans hrt.symm) hl
            · rw [d.uniq x hx r.1 (hsc _ hrW) (hxT.trans hrt.symm) he']
              exact List.isPrefixOf_iff_prefix.2 (List.prefix_refl _)
          simp [hxt, hne, hlt, prefix_trans hxr h1.2]
        · obtain ⟨k, hk⟩ := upperId_some (r := (x, .installed)) hxL hxT rfl hgt
          obtain ⟨r, hr, hrt, hri, hrE, hmin⟩ := upperId_spec hk
          have hrW : r.1 ∈ (replay ok (selectInstall (table ok h) T e.epoch)).certs :=
            (dW.certs r.1).2 (by rw [← hri]; exact mem_pick_idx hr (hmemI.2 (.inr (.inr hk))))
          have h1 := hfW r.1 hrW
          have hrt' : r.1.tenantId = e.tenantId := hrt.trans hET.symm
          simp only [hrt', bne_self_eq_false, Bool.false_or, Bool.and_eq_true,
            if_neg (Nat.not_lt.2 (Nat.le_of_lt hrE))] at h1
          have hle := hmin (x, .installed) hxL hxT rfl hgt
          have hrx : r.1.chain.isPrefixOf x.chain = true := by
            rcases Nat.lt_or_eq_of_le hle with hl | he'
            · exact d.ordered r.1 (hsc _ hrW) x hx (hrt.trans hxT.symm) hl
            · rw [d.uniq r.1 (hsc _ hrW) x hx (hrt.trans hxT.symm) he']
              exact List.isPrefixOf_iff_prefix.2 (List.prefix_refl _)
          simp [hxt, hne, Nat.not_lt.2 (Nat.le_of_lt hgt), prefix_trans h1.2 hrx]
      · simp [hxt]
    · intro hS x hx; exact hS x (hsc x hx)
  · unfold sameRow
    rw [find_any _ _ _ _ fun r hr => by simp only [Bool.and_eq_true] at hr; exact hr.2]
    unfold Cosign.held
    apply Bool.eq_iff_iff.2
    simp only [List.any_eq_true, Bool.or_eq_true, Bool.and_eq_true, beq_iff_eq]
    constructor
    · rintro ⟨r, hr, hi | hq, hb⟩
      · exact .inl ⟨r.1, (d.certs r.1).2 (by rw [← hi]; exact hr), hb⟩
      · obtain ⟨q, hq', hq2⟩ := (d.eqv r.1).2 (by rw [← hq]; exact hr)
        exact .inr ⟨q, hq', by rw [hq2]; exact hb⟩
    · rintro (⟨x, hx, hb⟩ | ⟨q, hq, hb⟩)
      · exact ⟨(x, .installed), (d.certs x).1 hx, .inl rfl, hb⟩
      · exact ⟨(q.2, .equivocates), (d.eqv q.2).1 ⟨q, hq, rfl⟩, .inr rfl, hb⟩
  · rw [table_snoc]
    congr 1
    cases hh : Cosign.held (replay ok h).toAuth e <;> simp [admit, he, hh]

/-- A re-signature of an installed body (or a replay of its bytes) answers `same` and leaves the state, so every
    later decision, as it was, and writes no row. -/
theorem resign_noop (c : Crypto) (ok : Cosign.KeyCert → Bool) (h : List Cosign.KeyCert) {x e : Cosign.KeyCert}
    (hx : x ∈ (replay ok h).certs) (hb : x.body = e.body) :
    Cosign.install c (replay ok h).toAuth e = ((replay ok h).toAuth, .same) ∧
      admit ok (replay ok h) e = (replay ok h, none) := by
  have hh : Cosign.held (replay ok h).toAuth e = true := by
    unfold Cosign.held
    rw [Bool.or_eq_true]
    exact .inl (List.any_eq_true.2 ⟨x, hx, by simp [hb]⟩)
  exact ⟨by simp [Cosign.install, hh], by simp [admit, hh]⟩

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
  · refine storeOutcome_congr hx (fun _ => rfl) fun _ => ?_
    simp only [blocked_eq]
    rw [hT, selectForks_any forks T S Q hs hq]
  · unfold releaseOutcome
    dsimp only
    refine firstFailure_congr ?_ ?_ ?_ ?_ ?_ ?_ ?_
    all_goals try rfl
    intro t st _ hbt hi
    obtain ⟨x, hx, hst, -⟩ := release_cps h0 (List.mem_of_find?_eq_some hbt)
    obtain ⟨hT, hs, hq⟩ := hcp x hx
    simp only [inBatch, Bool.and_eq_true, beq_iff_eq] at hi
    have h1 : t.leaf.tenantId = T := by rw [← hi.1.1.1.1.1, hst, hT]
    have h2 : t.leaf.shardId ∈ S := by rw [← hi.1.1.1.2, hst]; exact hs
    have h3 : t.leaf.epoch ∈ Q := by rw [← hi.1.1.2, hst]; exact hq
    refine ⟨rfl, ?_⟩
    simp only [unforked, blocked_eq]
    rw [h1, selectForks_any forks T S Q h2 h3]

/-- INSTALL's answer from what the frame carries is `Cosign.install`'s, `belowFence` included, when the frame carries
    the tenant's head, the chain's links of the certificate's generation and the next, links whose key test is the
    whole chain's and retired links', the held certificate exactly when the state holds the body, and witnesses that
    agree with the state on the certificate's epoch and, when it holds none there, on the fit (`install_classifies`
    for the rows, `Cosign.fits_neighbours` for the certificates the chain owns). -/
theorem installOutcome_install (c : Crypto) (s : Cosign.Auth) {ch : Cosign.Chain} {e : Cosign.KeyCert}
    (hch : s.chainOf e.tenantId = some ch) (keyLinks : List Cosign.Link)
    (hk : Cosign.keysApart c.hash keyLinks e = Cosign.keysApart c.hash (ch.links ++ Cosign.retiredLinks s e.tenantId) e)
    (same : Option Cosign.KeyCert) (hs : same.any (·.body == e.body) = Cosign.held s e) (s0 : PayerState)
    (hany : (s0.certs.any fun x => x.tenantId == e.tenantId && x.epoch == e.epoch) =
      (s.certs.any fun x => x.tenantId == e.tenantId && x.epoch == e.epoch))
    (hfit : (s.certs.any fun x => x.tenantId == e.tenantId && x.epoch == e.epoch) = false →
      Cosign.fits s0.toAuth e = Cosign.fits s e) :
    installOutcome c (some ch.head) (ch.linkAt (Cosign.genOf e.epoch)) (ch.linkAt (Cosign.genOf e.epoch + 1)) keyLinks
      same s0 e = (Cosign.install c s e).2 := by
  have hj : Cosign.judgeWith c ch.head (ch.linkAt (Cosign.genOf e.epoch)) keyLinks
      (ch.head.gen ≤ Cosign.genOf e.epoch ||
        ((ch.linkAt (Cosign.genOf e.epoch + 1)).bind (·.closedThrough)).any (e.epoch ≤ ·)) e =
      Cosign.judge c ch (Cosign.retiredLinks s e.tenantId) e := by
    unfold Cosign.judge Cosign.Chain.inTime Cosign.judgeWith
    rw [hk]
  have hl : Cosign.late s0.toAuth ch.head e = Cosign.late s ch.head e := by
    unfold Cosign.late
    rw [hany]
  unfold installOutcome Cosign.install
  rw [hs]
  cases hh : Cosign.held s e
  · simp only [Bool.false_eq_true, ↓reduceIte, hch]
    rw [hj, hl]
    cases Cosign.judge c ch (Cosign.retiredLinks s e.tenantId) e with
    | error r => rfl
    | ok _ =>
      cases Cosign.late s ch.head e
      · simp only [Bool.false_eq_true, ↓reduceIte]
        exact Cosign.record_congr hany hfit
      · rfl
  · simp

end BlindLedger.Gate
