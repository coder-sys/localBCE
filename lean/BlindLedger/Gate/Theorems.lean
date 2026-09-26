import BlindLedger.Gate.Spec

namespace BlindLedger.Gate

/-! What the payer's steps and the Merkle path guarantee, for every `Crypto`. -/

/-- The eleven payer checks, as one proposition; check 2 names the stored batch `st`. -/
def Checks (c : Crypto) (s : PayerState) (p : Payment) (bytes : Bytes) (t : Token) (st : Stored) :
    Prop :=
  decodeToken bytes = some t ∧ batchOf s t = some st ∧ inBatch c st.checkpoint t = true ∧
    aboveFence s t = true ∧ unexpired s t = true ∧ paymentMatches c p t = true ∧
    routed c s p t = true ∧ allows t = true ∧ granted s t = true ∧ unreleased s t = true ∧
    unforked s t = true

/-- `verifyToken` accepts exactly when all eleven checks hold. -/
theorem verifyToken_iff (c : Crypto) (s : PayerState) (p : Payment) (bytes : Bytes) :
    verifyToken c s p bytes = true ↔ ∃ t st, Checks c s p bytes t st := by
  unfold verifyToken Checks
  cases h : decodeToken bytes with
  | none => simp
  | some t =>
    cases hb : batchOf s t with
    | none => simp [hb]
    | some st => simp [hb, Bool.and_eq_true, and_assoc]

/-- No accepted token is below its tenant's fence (the model's `NoFencedTokenAccepted`). -/
theorem verifyToken_epoch_ge_fence {c : Crypto} {s : PayerState} {p : Payment} {bytes : Bytes}
    (h : verifyToken c s p bytes = true) :
    ∃ t, decodeToken bytes = some t ∧ s.fence t.leaf.tenantId ≤ t.leaf.epoch := by
  obtain ⟨t, -, hd, -, -, h4, -⟩ := (verifyToken_iff c s p bytes).1 h
  exact ⟨t, hd, by simpa [aboveFence] using h4⟩

theorem raiseFence_ge {f : Bytes → Nat} {tenant : Bytes} {e : Nat} (x : Bytes) :
    f x ≤ raiseFence f tenant e x := by
  unfold raiseFence
  split
  · exact Nat.le_max_left _ _
  · exact Nat.le_refl _

theorem raiseFence_self (f : Bytes → Nat) (tenant : Bytes) (e : Nat) :
    e ≤ raiseFence f tenant e tenant := by
  unfold raiseFence
  rw [if_pos rfl]
  exact Nat.le_max_right _ _

/-- Installing a certificate never lowers a fence and lifts its tenant's to
    at least its epoch (the model's `PayerLearnFence`). -/
theorem installCert_raises_fence {c : Crypto} {s s' : PayerState} {e : EpochCert}
    (h : installCert c s e = some s') :
    e.epoch ≤ s'.fence e.tenantId ∧ ∀ x, s.fence x ≤ s'.fence x := by
  unfold installCert at h
  split at h
  · obtain rfl := Option.some.inj h
    exact ⟨raiseFence_self _ _ _, fun x => raiseFence_ge x⟩
  · simp at h

/-- The payer invariant: each tenant's fence is at or above every installed
    certificate's epoch, and every stored checkpoint was verified under an
    installed certificate for its tenant and epoch. -/
def Coherent (s : PayerState) : Prop :=
  (∀ e ∈ s.certs, e.epoch ≤ s.fence e.tenantId) ∧
    ∀ x ∈ s.checkpoints, ∃ e ∈ s.certs,
      e.tenantId = x.checkpoint.tenantId ∧ e.epoch = x.checkpoint.epoch

theorem coherent_empty {s : PayerState} (hc : s.certs = []) (hk : s.checkpoints = []) :
    Coherent s := by
  simp [Coherent, hc, hk]

theorem installCert_coherent {c : Crypto} {s s' : PayerState} {e : EpochCert}
    (hs : Coherent s) (h : installCert c s e = some s') : Coherent s' := by
  unfold installCert at h
  split at h
  · obtain rfl := Option.some.inj h
    refine ⟨fun e' he' => ?_, fun x hx => ?_⟩
    · rcases List.mem_cons.1 he' with rfl | he'
      · exact raiseFence_self _ _ _
      · exact Nat.le_trans (hs.1 e' he') (raiseFence_ge _)
    · obtain ⟨e', he', h1, h2⟩ := hs.2 x hx
      exact ⟨e', List.mem_cons_of_mem _ he', h1, h2⟩
  · simp at h

theorem storeCheckpoint_coherent {c : Crypto} {s s' : PayerState} {bytes : Bytes}
    (hs : Coherent s) (h : storeCheckpoint c s bytes = some s') : Coherent s' := by
  unfold storeCheckpoint at h
  cases hd : decodeCheckpoint bytes with
  | none => rw [hd] at h; simp at h
  | some x =>
    rw [hd] at h
    dsimp only at h
    split at h
    · rename_i hany
      split at h
      · obtain rfl := Option.some.inj h
        exact hs
      · obtain rfl := Option.some.inj h
        refine ⟨hs.1, fun y hy => ?_⟩
        rcases List.mem_cons.1 hy with rfl | hy
        · obtain ⟨e, he, hm⟩ := List.any_eq_true.1 hany
          simp only [Bool.and_eq_true, beq_iff_eq] at hm
          exact ⟨e, he, hm.1.1, hm.1.2⟩
        · exact hs.2 y hy
    · simp at h

theorem release_coherent {c : Crypto} {s s' : PayerState} {p : Payment} {bytes : Bytes}
    (hs : Coherent s) (h : release c s p bytes = some s') : Coherent s' := by
  unfold release at h
  split at h
  · simp at h
  · split at h
    · obtain rfl := Option.some.inj h
      exact hs
    · simp at h

/-- On a coherent state an accepted token's epoch is exactly its tenant's
    fence.  So `release` raises nothing: the model's `PayerRelease` sets
    `fence' = t.ep`, which already holds. -/
theorem verifyToken_fence_eq_epoch {c : Crypto} {s : PayerState} {p : Payment} {bytes : Bytes}
    {t : Token} (hs : Coherent s) (h : verifyToken c s p bytes = true)
    (hd : decodeToken bytes = some t) : s.fence t.leaf.tenantId = t.leaf.epoch := by
  obtain ⟨t', st, hd', hb, hin, hf, -⟩ := (verifyToken_iff c s p bytes).1 h
  obtain rfl : t' = t := Option.some.inj (hd'.symm.trans hd)
  obtain ⟨e, he, ht, hep⟩ := hs.2 st (List.mem_of_find?_eq_some hb)
  simp only [inBatch, Bool.and_eq_true, beq_iff_eq] at hin
  simp only [aboveFence, decide_eq_true_eq] at hf
  have hle := hs.1 e he
  rw [ht, hin.1.1.1.1.1, hep, hin.1.1.2] at hle
  exact Nat.le_antisymm hf hle

/-- One shard per payment: two tokens the payer accepts for one payment come
    from the same shard, the route of its member key (check 7).  So a
    decision on any other shard, as a gate that enforced one decision per
    payment only per shard would sign it, is never released. -/
theorem verifyToken_one_shard {c : Crypto} {s : PayerState} {p : Payment} {b b' : Bytes}
    {t t' : Token} (h : verifyToken c s p b = true) (h' : verifyToken c s p b' = true)
    (hd : decodeToken b = some t) (hd' : decodeToken b' = some t') :
    t.leaf.shardId = t'.leaf.shardId := by
  obtain ⟨u, -, hu, -, -, -, -, -, hr, -⟩ := (verifyToken_iff c s p b).1 h
  obtain ⟨u', -, hu', -, -, -, -, -, hr', -⟩ := (verifyToken_iff c s p b').1 h'
  obtain rfl : u = t := Option.some.inj (hu.symm.trans hd)
  obtain rfl : u' = t' := Option.some.inj (hu'.symm.trans hd')
  unfold routed at hr hr'
  cases hf : s.certs.find? (·.tenantId == p.tenantId) with
  | none => simp [hf] at hr
  | some e =>
    simp only [hf, Option.any_some, beq_iff_eq] at hr hr'
    rw [hr, hr']

/-- A detected fork blocks its tenant, shard and epoch: no token under that
    key is accepted while the fork is on record (check 11). -/
theorem verifyToken_unforked {c : Crypto} {s : PayerState} {p : Payment} {bytes : Bytes}
    {t : Token} (h : verifyToken c s p bytes = true) (hd : decodeToken bytes = some t) :
    ∀ f ∈ s.forked, (f.1.checkpoint.tenantId, f.1.checkpoint.shardId, f.1.checkpoint.epoch) ≠
      (t.leaf.tenantId, t.leaf.shardId, t.leaf.epoch) := by
  obtain ⟨u, -, hu, -, -, -, -, -, -, -, -, -, hf⟩ := (verifyToken_iff c s p bytes).1 h
  obtain rfl : u = t := Option.some.inj (hu.symm.trans hd)
  intro f hm heq
  simp only [unforked, Bool.not_eq_true', List.any_eq_false, beq_iff_eq] at hf
  exact hf f hm heq

/-- `release` happens exactly on the bytes `verifyToken` accepts. -/
theorem release_isSome (c : Crypto) (s : PayerState) (p : Payment) (bytes : Bytes) :
    (release c s p bytes).isSome = verifyToken c s p bytes := by
  unfold release
  cases hd : decodeToken bytes with
  | none => simp [verifyToken, hd]
  | some t => by_cases hv : verifyToken c s p bytes = true <;> simp [hv]

/-- At most one release per payment (the model's `AtMostOnceRelease`): after a
    release, every token for the same tenant, program and payment id, under
    any flow, is rejected. -/
theorem release_at_most_once {c : Crypto} {s s' : PayerState} {p p' : Payment}
    {bytes bytes' : Bytes} {t t' : Token} (h : release c s p bytes = some s')
    (hd : decodeToken bytes = some t) (hd' : decodeToken bytes' = some t')
    (hk : payKey t' = payKey t) : verifyToken c s' p' bytes' = false := by
  unfold release at h
  rw [hd] at h
  dsimp only at h
  split at h
  · obtain rfl := Option.some.inj h
    simp [verifyToken, hd', unreleased, hk]
    split <;> rfl
  · simp at h

/-- Whatever `pathCollision` returns is a collision: distinct inputs, one output. -/
theorem pathCollision_sound {H : Bytes → Bytes} {d : Bytes} (fuel : Nat) :
    ∀ (i n : Nat) (a b : Bytes) (p q : List Bytes) (x y : Bytes),
      pathCollision H d fuel i n a b p q = some (x, y) → x ≠ y ∧ H x = H y := by
  induction fuel with
  | zero => intro i n a b p q x y h; simp [pathCollision] at h
  | succ fuel ih =>
    intro i n a b p q x y h
    simp only [pathCollision] at h
    by_cases hn : n ≤ 1
    · rw [if_pos hn] at h
      exact absurd h (by simp)
    rw [if_neg hn] at h
    by_cases hc : (i % 2 == 0 && i + 1 == n) = true
    · rw [if_pos hc] at h
      exact ih _ _ _ _ _ _ _ _ h
    rw [if_neg hc] at h
    cases p with
    | nil => simp at h
    | cons s ps =>
    cases q with
    | nil => simp at h
    | cons t qs =>
    simp only at h
    by_cases hx : stepInput d i a s ≠ stepInput d i b t ∧
        H (stepInput d i a s) = H (stepInput d i b t)
    · rw [if_pos hx] at h
      obtain ⟨rfl, rfl⟩ := Prod.mk.inj (Option.some.inj h)
      exact hx
    · rw [if_neg hx] at h
      exact ih _ _ _ _ _ _ _ _ h

/-- Two different equal-length nodes folding to one root at one position make
    `pathCollision` return a pair, provided every hash output has one length. -/
theorem pathCollision_complete {H : Bytes → Bytes} {d : Bytes}
    (hlen : ∀ z, (H z).length = digestBytes) (fuel : Nat) :
    ∀ (i n : Nat) (a b : Bytes) (p q : List Bytes) (r : Bytes), a ≠ b → a.length = b.length →
      pathRoot H d fuel i n a p = some r → pathRoot H d fuel i n b q = some r →
      pathCollision H d fuel i n a b p q ≠ none := by
  induction fuel with
  | zero => intro i n a b p q r _ _ ha _; simp [pathRoot] at ha
  | succ fuel ih =>
    intro i n a b p q r hne hl ha hb
    simp only [pathRoot] at ha hb
    simp only [pathCollision]
    by_cases hn : n ≤ 1
    · rw [if_pos hn] at ha hb
      have hra : a = r := by
        split at ha
        · exact Option.some.inj ha
        · exact absurd ha (by simp)
      have hrb : b = r := by
        split at hb
        · exact Option.some.inj hb
        · exact absurd hb (by simp)
      exact absurd (hra.trans hrb.symm) hne
    rw [if_neg hn] at ha hb
    rw [if_neg hn]
    by_cases hc : (i % 2 == 0 && i + 1 == n) = true
    · rw [if_pos hc] at ha hb
      rw [if_pos hc]
      exact ih _ _ a b p q r hne hl ha hb
    rw [if_neg hc] at ha hb
    rw [if_neg hc]
    cases p with
    | nil => simp at ha
    | cons s ps =>
    cases q with
    | nil => simp at hb
    | cons t qs =>
    simp only at ha hb ⊢
    have hstep : stepInput d i a s ≠ stepInput d i b t := by
      intro heq
      unfold stepInput at heq
      have h2 := (List.cons.inj (List.append_cancel_left heq)).2
      by_cases he : (i % 2 == 0) = true
      · rw [if_pos he, if_pos he] at h2
        exact hne (List.append_inj h2 hl).1
      · rw [if_neg he, if_neg he] at h2
        exact hne (List.append_inj' h2 hl).2
    by_cases hx : stepInput d i a s ≠ stepInput d i b t ∧
        H (stepInput d i a s) = H (stepInput d i b t)
    · rw [if_pos hx]
      simp
    · rw [if_neg hx]
      exact ih _ _ _ _ ps qs r (fun e => hx ⟨hstep, e⟩) (by rw [hlen, hlen]) ha hb

/-- The Merkle reduction: if one root, index and batch size accept two
    different leaves, `leafCollision` returns an explicit SHA3 collision
    (distinct inputs, one output).  So a second leaf under a signed root costs
    a collision the caller can print. -/
theorem verifyPath_collision {H : Bytes → Bytes} {d : Bytes}
    (hlen : ∀ z, (H z).length = digestBytes) {x y : Bytes} {i n : Nat} {p q : List Bytes}
    {r : Bytes} (hx : verifyPath H d x i n p r = true) (hy : verifyPath H d y i n q r = true)
    (hne : x ≠ y) : ∃ a b, leafCollision H d x y i n p q = some (a, b) ∧ a ≠ b ∧ H a = H b := by
  simp only [verifyPath, Bool.and_eq_true, beq_iff_eq] at hx hy
  unfold leafCollision
  by_cases hc : d ++ (0 :: x) ≠ d ++ (0 :: y) ∧ H (d ++ (0 :: x)) = H (d ++ (0 :: y))
  · rw [if_pos hc]
    exact ⟨_, _, rfl, hc⟩
  · rw [if_neg hc]
    have hin : d ++ (0 :: x) ≠ d ++ (0 :: y) := fun e =>
      hne (List.cons.inj (List.append_cancel_left e)).2
    have hH : leafHash H d x ≠ leafHash H d y := fun e => hc ⟨hin, e⟩
    match hm : pathCollision H d treeFuel i n (leafHash H d x) (leafHash H d y) p q with
    | some (a, b) => exact ⟨a, b, rfl, pathCollision_sound _ _ _ _ _ _ _ _ _ hm⟩
    | none =>
      exact absurd hm (pathCollision_complete hlen _ _ _ _ _ _ _ _ hH
        (by simp [leafHash, hlen]) hx.2 hy.2)

end BlindLedger.Gate
