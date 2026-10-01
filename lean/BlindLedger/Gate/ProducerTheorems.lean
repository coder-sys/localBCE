import BlindLedger.Gate.Producer
import BlindLedger.Gate.Payer

/-! Theorems of the checkpoint producer and the payer adapter (gate-producer-v1 §3).  Statements: rr-core's
    `gate-producer-goals.lean`, fixed. -/
namespace BlindLedger.Gate

/-! ### The decoder's guarantees -/

theorem bind_some {α β : Type} {x : Option α} {f : α → Option β} {y : β} (h : (x >>= f) = some y) :
    ∃ a, x = some a ∧ f a = some y := by
  cases x <;> simp_all

theorem need_ok {ok : Bool} {b : Bytes} {r : Unit × Bytes} (h : (need ok).run b = some r) : ok = true := by
  by_cases hok : ok = true
  · exact hok
  · simp [need, StateT.run, hok] at h

theorem nat_ok {w lo hi : Nat} {b : Bytes} {r : Nat × Bytes} (h : (nat w lo hi).run b = some r) :
    lo ≤ r.1 ∧ r.1 ≤ hi := by
  simp only [nat, StateT.run_bind] at h
  obtain ⟨a, -, h⟩ := bind_some h
  obtain ⟨c, hc, h⟩ := bind_some h
  have := need_ok hc
  simp only [Bool.and_eq_true, decide_eq_true_eq] at this
  simp only [StateT.run_pure, Option.pure_def, Option.some.injEq] at h
  subst h
  exact this

theorem pCheckpoint_wf {b rest : Bytes} {cp : Checkpoint} (h : pCheckpoint.run b = some (cp, rest)) :
    cp.seqFrom ≤ cp.seqTo ∧ (cp.seqFrom = 0 → cp.prevCheckpoint = zeroDigest) := by
  simp only [pCheckpoint, StateT.run_bind] at h
  obtain ⟨a1, -, h⟩ := bind_some h
  obtain ⟨a2, -, h⟩ := bind_some h
  obtain ⟨a3, -, h⟩ := bind_some h
  obtain ⟨a4, -, h⟩ := bind_some h
  obtain ⟨a5, -, h⟩ := bind_some h
  obtain ⟨a6, -, h⟩ := bind_some h
  obtain ⟨a7, -, h⟩ := bind_some h
  obtain ⟨a8, -, h⟩ := bind_some h
  obtain ⟨a9, -, h⟩ := bind_some h
  obtain ⟨a10, -, h⟩ := bind_some h
  obtain ⟨a11, -, h⟩ := bind_some h
  obtain ⟨a12, -, h⟩ := bind_some h
  obtain ⟨a13, -, h⟩ := bind_some h
  obtain ⟨a14, hc, h⟩ := bind_some h
  obtain ⟨a15, -, h⟩ := bind_some h
  obtain ⟨a16, h16, h⟩ := bind_some h
  obtain ⟨a17, h17, h⟩ := bind_some h
  obtain ⟨a18, h18, h⟩ := bind_some h
  have e17 := need_ok h17
  have e18 := need_ok h18
  have c13 := nat_ok hc
  simp only [StateT.run_pure, Option.pure_def, Option.some.injEq, Prod.mk.injEq] at h
  obtain ⟨rfl, -⟩ := h
  simp only [beq_iff_eq] at e17
  dsimp only
  refine ⟨by omega, fun h0 => ?_⟩
  simp [h0] at e18
  exact e18

theorem consumed_run {α : Type} {p : P α} {b : Bytes} {r : (α × Bytes) × Bytes}
    (h : (consumed p).run b = some r) : p.run b = some (r.1.1, r.2) := by
  have h' : (match p.run b with
      | some (x, rest) => some ((x, b.take (b.length - rest.length)), rest)
      | none => none) = some r := h
  rcases hp : p.run b with _ | ⟨x, q⟩
  · rw [hp] at h'
    simp at h'
  · rw [hp] at h'
    simp only [Option.some.injEq] at h'
    subst h'
    rfl

theorem pSigned_wf {b rest : Bytes} {y : SignedCheckpoint} (h : pSignedCheckpoint.run b = some (y, rest)) :
    y.checkpoint.seqFrom ≤ y.checkpoint.seqTo ∧
      (y.checkpoint.seqFrom = 0 → y.checkpoint.prevCheckpoint = zeroDigest) := by
  simp only [pSignedCheckpoint, StateT.run_bind] at h
  obtain ⟨c, hc, h⟩ := bind_some h
  obtain ⟨s, -, h⟩ := bind_some h
  simp only [StateT.run_pure, Option.pure_def, Option.some.injEq, Prod.mk.injEq] at h
  obtain ⟨rfl, -⟩ := h
  exact pCheckpoint_wf (consumed_run hc)

theorem storedOf_wf {H : Bytes → Bytes} {b : Bytes} {x : Stored} (h : storedOf H b = some x) : Wf x := by
  unfold storedOf at h
  cases hd : decodeCheckpoint b with
  | none => simp [hd] at h
  | some y =>
    simp only [hd, Option.map_some, Option.some.injEq] at h
    subst h
    unfold decodeCheckpoint parse at hd
    by_cases hl : b.length > maxCheckpointBytes
    · simp [hl] at hd
    · simp only [hl, if_false] at hd
      cases hr : pSignedCheckpoint.run b with
      | none => simp [hr] at hd
      | some r =>
        obtain ⟨z, rest⟩ := r
        cases rest with
        | nil =>
          simp [hr] at hd
          subst hd
          exact pSigned_wf hr
        | cons a l => simp [hr] at hd

/-! ### The chain -/

theorem forks_comm (a b : Stored) : forks a b = forks b a := by
  grind [forks, misLinked]

theorem follows_some {p n : Stored} (h : follows (some p) n = true) :
    p.checkpoint.tenantId = n.checkpoint.tenantId ∧ p.checkpoint.shardId = n.checkpoint.shardId ∧
    n.checkpoint.eventHead = p.digest ∧
    ((p.checkpoint.epoch = n.checkpoint.epoch ∧ p.checkpoint.seqTo + 1 = n.checkpoint.seqFrom ∧
        n.checkpoint.prevCheckpoint = p.digest) ∨
      (p.checkpoint.epoch < n.checkpoint.epoch ∧ n.checkpoint.seqFrom = 0)) := by
  unfold follows at h
  by_cases he : p.checkpoint.epoch = n.checkpoint.epoch
  · simp [he] at h
    grind
  · simp [he] at h
    grind

/-- Along a linked chain (newest first) tenant and shard are constant, epochs do not fall, and within an
    epoch the older ranges end strictly before the head's begins. -/
theorem chain_facts : ∀ (l : List Stored) (m : Stored), chainOk (m :: l) = true → (∀ x ∈ m :: l, Wf x) →
    ∀ x ∈ l, x.checkpoint.tenantId = m.checkpoint.tenantId ∧ x.checkpoint.shardId = m.checkpoint.shardId ∧
      x.checkpoint.epoch ≤ m.checkpoint.epoch ∧
      (x.checkpoint.epoch = m.checkpoint.epoch → x.checkpoint.seqTo < m.checkpoint.seqFrom)
  | [], m, _, _, x, hx => by simp at hx
  | y :: l', m, hc, hw, x, hx => by
    have hc' : follows (some y) m = true ∧ chainOk (y :: l') = true := by simpa [chainOk] using hc
    obtain ⟨hf, hc2⟩ := hc'
    have ih := chain_facts l' y hc2 (fun z hz => hw z (List.mem_cons_of_mem _ hz))
    obtain ⟨ht, hs, -, hd⟩ := follows_some hf
    have wy : Wf y := hw y (by simp)
    have wy1 := wy.1
    rcases List.mem_cons.mp hx with rfl | hx'
    · refine ⟨ht, hs, ?_, ?_⟩ <;> rcases hd with ⟨h1, h2, -⟩ | ⟨h1, h2⟩ <;> omega
    · obtain ⟨t1, s1, e1, q1⟩ := ih x hx'
      refine ⟨t1.trans ht, s1.trans hs, ?_, ?_⟩
      · rcases hd with ⟨h1, -, -⟩ | ⟨h1, -⟩ <;> omega
      · intro he
        rcases hd with ⟨h1, h2, -⟩ | ⟨h1, -⟩
        · have := q1 (by omega)
          omega
        · omega

/-- Every checkpoint of a linked chain links to an older member's digest, or is a genesis (zero). -/
theorem chain_prev : ∀ (cs : List Stored), chainOk cs = true → (∀ x ∈ cs, Wf x) →
    ∀ x ∈ cs, x.checkpoint.prevCheckpoint = zeroDigest ∨ x.checkpoint.prevCheckpoint ∈ cs.map (·.digest)
  | [], _, _, x, hx => by simp at hx
  | n :: rest, hc, hw, x, hx => by
    have hc' : follows rest.head? n = true ∧ chainOk rest = true := by simpa [chainOk] using hc
    rcases List.mem_cons.mp hx with rfl | hx'
    · cases rest with
      | nil =>
        left
        have h := hc'.1
        simp [follows] at h
        exact (hw _ (by simp)).2 h.1
      | cons y l' =>
        obtain ⟨-, -, -, hd⟩ := follows_some (by simpa using hc'.1)
        rcases hd with ⟨-, -, h3⟩ | ⟨-, h2⟩
        · right; simp [h3]
        · left; exact (hw _ (by simp)).2 h2
    · rcases chain_prev rest hc'.2 (fun z hz => hw z (List.mem_cons_of_mem _ hz)) x hx' with h | h
      · exact Or.inl h
      · exact Or.inr (by simp [h])

/-- No two checkpoints of a well-linked store fork (the producer's self-check, done by construction):
    digests distinct and never zero (the store's UNIQUE column; a zero digest is a SHA3-512 preimage). -/
theorem chain_no_fork {cs : List Stored} (hc : chainOk cs = true) (hw : ∀ x ∈ cs, Wf x)
    (hd : (zeroDigest :: cs.map (·.digest)).Nodup) :
    cs.Pairwise fun n x => forks x n = false := by
  induction cs with
  | nil => exact List.Pairwise.nil
  | cons n rest ih =>
    have hc' : follows rest.head? n = true ∧ chainOk rest = true := by simpa [chainOk] using hc
    have hwr : ∀ x ∈ rest, Wf x := fun x hx => hw x (List.mem_cons_of_mem _ hx)
    have hdn : (zeroDigest :: n.digest :: rest.map (·.digest)).Nodup := by simpa using hd
    have hdr : (zeroDigest :: rest.map (·.digest)).Nodup := by
      simp only [List.nodup_cons, List.mem_cons, not_or] at hdn ⊢
      exact ⟨hdn.1.2, hdn.2.2⟩
    refine List.Pairwise.cons ?_ (ih hc'.2 hwr hdr)
    intro x hx
    cases rest with
    | nil => simp at hx
    | cons y l' =>
      have hnr : n.digest ∉ (y :: l').map (·.digest) := (List.nodup_cons.mp (List.nodup_cons.mp hdn).2).1
      have hz := (List.nodup_cons.mp hdn).1
      have hnz : n.digest ≠ zeroDigest := fun h => hz (List.mem_cons.mpr (Or.inl h.symm))
      have hyl : y.digest ∉ l'.map (·.digest) :=
        (List.nodup_cons.mp (List.nodup_cons.mp (List.nodup_cons.mp hdn).2).2).1
      show forks x n = false
      have hf : follows (some y) n = true := by simpa using hc'.1
      obtain ⟨-, -, -, hdy⟩ := follows_some hf
      obtain ⟨-, -, hle, hlt⟩ := chain_facts (y :: l') n hc hw x hx
      have wn := hw n (by simp)
      have wx : Wf x := hw x (List.mem_cons_of_mem _ hx)
      have wn1 := wn.1
      have wx1 := wx.1
      unfold forks
      by_cases he : x.checkpoint.epoch = n.checkpoint.epoch
      · have hlt' := hlt he
        have h1 : (x.checkpoint.seqFrom ≤ n.checkpoint.seqTo && n.checkpoint.seqFrom ≤ x.checkpoint.seqTo) = false := by
          rw [Bool.eq_false_iff]; simp; omega
        have hml1 : misLinked x n = false := by
          unfold misLinked
          by_cases hxy : x = y
          · rw [hxy] at he ⊢
            rcases hdy with ⟨-, h2, h3⟩ | ⟨h1, -⟩
            · simp [h2, h3]
            · omega
          · have hx' : x ∈ l' := by simpa [hxy] using hx
            obtain ⟨-, -, e1, q1⟩ := chain_facts l' y hc'.2 (fun z hz => hw z (List.mem_cons_of_mem _ hz)) x hx'
            have wy1 := (hw y (by simp)).1
            rcases hdy with ⟨h2, h3, h4⟩ | ⟨h2, -⟩
            · have hq := q1 (by omega)
              have a1 : ¬ (x.checkpoint.seqTo + 1 = n.checkpoint.seqFrom) := by omega
              have a2 : ¬ (n.checkpoint.prevCheckpoint = x.digest) := by
                rw [h4]
                intro h
                exact hyl (List.mem_map.mpr ⟨x, hx', h.symm⟩)
              rw [beq_eq_false_iff_ne.mpr a1, beq_eq_false_iff_ne.mpr a2]
              rfl
            · omega
        have hml2 : misLinked n x = false := by
          unfold misLinked
          have a1 : ¬ (n.checkpoint.seqTo + 1 = x.checkpoint.seqFrom) := by omega
          have a2 : ¬ (x.checkpoint.prevCheckpoint = n.digest) := by
            intro h
            rcases chain_prev (y :: l') hc'.2 (fun z hz => hw z (List.mem_cons_of_mem _ hz)) x hx with h' | h'
            · exact hnz (h.symm.trans h')
            · rw [h] at h'
              exact hnr h'
          rw [beq_eq_false_iff_ne.mpr a1, beq_eq_false_iff_ne.mpr a2]
          rfl
        simp only [h1, hml1, hml2]
        simp
      · simp [he]

/-- Two successors of one checkpoint in one epoch fork: equivocation and rewind surface as a fork. -/
theorem follows_twice_forks {p : Option Stored} {y n : Stored}
    (hy : follows p y = true) (hn : follows p n = true) (hd : y.digest ≠ n.digest)
    (ht : y.checkpoint.tenantId = n.checkpoint.tenantId) (hs : y.checkpoint.shardId = n.checkpoint.shardId)
    (he : y.checkpoint.epoch = n.checkpoint.epoch) (hwy : Wf y) (hwn : Wf n) :
    forks y n = true := by
  obtain ⟨hy1, -⟩ := hwy
  obtain ⟨hn1, -⟩ := hwn
  have key : y.checkpoint.seqFrom = n.checkpoint.seqFrom := by
    cases p with
    | none => simp [follows] at hy hn; omega
    | some p =>
      by_cases h1 : p.checkpoint.epoch = y.checkpoint.epoch
      · have h2 : p.checkpoint.epoch = n.checkpoint.epoch := h1.trans he
        simp [follows, h1] at hy
        simp [follows, h2] at hn
        first | omega | (simp_all; omega)
      · have h2 : ¬p.checkpoint.epoch = n.checkpoint.epoch := he ▸ h1
        simp [follows, h1] at hy
        simp [follows, h2] at hn
        first | omega | (simp_all; omega)
  have o1 : y.checkpoint.seqFrom ≤ n.checkpoint.seqTo := by omega
  have o2 : n.checkpoint.seqFrom ≤ y.checkpoint.seqTo := by omega
  simp [forks, hd, ht, hs, he, o1, o2]

/-! ### The publish check -/

theorem lexLt_irrefl : ∀ a : Bytes, lexLt a a = false
  | [] => rfl
  | x :: xs => by simp [lexLt, lexLt_irrefl xs]

theorem lexLt_trans : ∀ (a b c : Bytes), lexLt a b = true → lexLt b c = true → lexLt a c = true
  | [], [], _, h, _ => by simp [lexLt] at h
  | [], _ :: _, [], _, h => by simp [lexLt] at h
  | [], _ :: _, _ :: _, _, _ => by simp [lexLt]
  | _ :: _, [], _, h, _ => by simp [lexLt] at h
  | _ :: _, _ :: _, [], _, h => by simp [lexLt] at h
  | a :: as, b :: bs, c :: cs, h1, h2 => by
    simp only [lexLt, Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] at h1 h2 ⊢
    rcases h1 with h1 | ⟨rfl, h1⟩ <;> rcases h2 with h2 | ⟨rfl, h2⟩
    · exact Or.inl (UInt8.lt_trans h1 h2)
    · exact Or.inl h1
    · exact Or.inl h2
    · exact Or.inr ⟨rfl, lexLt_trans as bs cs h1 h2⟩

theorem ascending_head : ∀ (l : List Bytes) (a : Bytes), ascending (a :: l) = true → ∀ x ∈ l, lexLt a x = true
  | [], _, _, x, hx => by simp at hx
  | b :: rest, a, h, x, hx => by
    simp only [ascending, Bool.and_eq_true] at h
    rcases List.mem_cons.mp hx with rfl | hx'
    · exact h.1
    · exact lexLt_trans a b x h.1 (ascending_head rest b h.2 x hx')

theorem ascending_nodup : ∀ l : List Bytes, ascending l = true → l.Nodup
  | [], _ => List.nodup_nil
  | [_], _ => by simp
  | a :: b :: rest, h => by
    have h' : lexLt a b = true ∧ ascending (b :: rest) = true := by simpa [ascending] using h
    refine List.nodup_cons.mpr ⟨fun hm => ?_, ascending_nodup (b :: rest) h'.2⟩
    have := ascending_head (b :: rest) a h
    have := this a hm
    simp [lexLt_irrefl] at this

theorem nodup_of_map {α β : Type} (f : α → β) {l : List α} (h : (l.map f).Nodup) : l.Nodup :=
  (List.pairwise_map.1 h).imp fun hne e => hne (congrArg f e)

/-- What a published batch satisfies. -/
theorem publishOk_sound {rootPk cert new : Bytes} {last : Option Bytes} {tokens : List Bytes}
    (h : publishOk rootPk cert last new tokens = true) :
    accepts rootPk cert new = true ∧ (last.all fun b => (storedOf sha3 b).isSome) = true ∧
    ∃ e n, decodeKeyCert cert = some e ∧ storedOf sha3 new = some n ∧
      follows (last.bind (storedOf sha3)) n = true ∧ tokens.length = n.checkpoint.count ∧
      (∀ i (hi : i < tokens.length),
        tokenFits (realCrypto [(n.checkpoint.tenantId, rootPk)]) e.shardCount n i tokens[i] = true) ∧
      ((tokens.filterMap decodeToken).map payKey).Nodup := by
  unfold publishOk at h
  cases hk : decodeKeyCert cert with
  | none => simp [hk] at h
  | some e =>
    cases hn : storedOf sha3 new with
    | none => simp [hk, hn] at h
    | some n =>
      simp only [hk, hn, Bool.and_eq_true, beq_iff_eq] at h
      obtain ⟨⟨⟨⟨⟨ha, hl⟩, hf⟩, hlen⟩, hall⟩, hasc⟩ := h
      refine ⟨ha, hl, e, n, rfl, rfl, hf, hlen, ?_, ?_⟩
      · intro i hi
        have hm : (tokens[i], i) ∈ tokens.zipIdx := List.mk_mem_zipIdx_iff_getElem?.mpr (by simp [hi])
        exact (List.all_eq_true.mp hall) _ hm
      · have hnd := ascending_nodup _ hasc
        exact nodup_of_map (fun k : PayKey => k.2.2) (by rw [List.map_map]; exact hnd)

/-- A published token never fails a payer on parse, batch, Merkle path or route: at any payer that stored
    its checkpoint under the same shard count, `verifyToken` is exactly the payment-dependent checks. -/
theorem publish_payer_local {c c' : Crypto} (hh : c.hash = c'.hash) {k i : Nat} {x : Stored}
    {bytes : Bytes} {t : Token} {s : PayerState} {p : Payment}
    (hf : tokenFits c k x i bytes = true) (ht : decodeToken bytes = some t)
    (hb : batchOf s t = some x) (hk : shardCountOf s t.leaf.tenantId = some k) :
    verifyToken c' s p bytes = true ↔
      (aboveFence s t && unexpired s t && paymentMatches c' p t && allows t && granted s t &&
        unreleased s t && unforked s t && keyPinned s t) = true := by
  unfold tokenFits at hf
  rw [ht] at hf
  simp only [Bool.and_eq_true, beq_iff_eq] at hf
  obtain ⟨⟨⟨-, -⟩, hin⟩, hshard⟩ := hf
  have hin' : inBatch c' x.checkpoint t = true := by
    unfold inBatch at hin ⊢
    rw [← hh]
    exact hin
  have hr : paymentMatches c' p t = true → routed c' s p t = true := fun hpm => by
    unfold paymentMatches at hpm
    simp only [Bool.and_eq_true, beq_iff_eq] at hpm
    obtain ⟨⟨⟨⟨⟨⟨⟨⟨ht', -⟩, -⟩, -⟩, hm⟩, -⟩, -⟩, -⟩, -⟩ := hpm
    unfold routed
    rw [← ht', hk]
    simp only [Option.any_some, beq_iff_eq]
    rw [← hm, ← hh]
    exact hshard
  unfold verifyToken
  rw [ht]
  dsimp only
  rw [hb]
  simp only [hin', Bool.true_and, Bool.and_eq_true]
  grind

/-! ### The payer's slices -/

theorem find?_filter_of_imp {α : Type} (l : List α) (q f : α → Bool) (h : ∀ a, f a = true → q a = true) :
    (l.filter q).find? f = l.find? f := by
  induction l with
  | nil => rfl
  | cons a t ih =>
    by_cases hq : q a = true
    · simp [List.filter_cons, hq, List.find?_cons, ih]
    · have hfa : f a = false := by
        cases hf : f a
        · rfl
        · exact absurd (h a hf) hq
      simp [List.filter_cons, hq, hfa, List.find?_cons, ih]

theorem ite_forked {c : Prop} [Decidable c] (a b : PayerState) (h : a.forked = b.forked) :
    Option.map (·.forked) (if c then none else some a) = Option.map (·.forked) (if c then none else some b) := by
  split <;> simp [h]

theorem storeCheckpoint_slice {c : Crypto} {s : PayerState} {bytes : Bytes} {x : SignedCheckpoint}
    {q : Stored → Bool} (hx : decodeCheckpoint bytes = some x)
    (hq : ∀ a, forks ⟨c.hash x.header, x.checkpoint, bytes⟩ a = true → q a = true) :
    (storeCheckpoint c { s with checkpoints := s.checkpoints.filter q } bytes).map (·.forked) =
      (storeCheckpoint c s bytes).map (·.forked) := by
  unfold storeCheckpoint
  rw [hx]
  dsimp only
  by_cases hs : (s.certs.any fun e => e.tenantId == x.checkpoint.tenantId && e.epoch == x.checkpoint.epoch &&
      c.sigOk e.publicKey x.header x.signature) = true
  · simp only [hs, if_true]
    rw [find?_filter_of_imp s.checkpoints q _ hq]
    cases hfd : s.checkpoints.find? (forks ⟨c.hash x.header, x.checkpoint, bytes⟩) with
    | some old => simp
    | none => exact ite_forked _ _ rfl
  · simp [hs]

theorem filter_lookup {α β : Type} [BEq α] [LawfulBEq α] (l : List (α × β)) (k : α) :
    (l.filter (·.1 == k)).lookup k = l.lookup k := by
  induction l with
  | nil => rfl
  | cons a t ih =>
    obtain ⟨a1, a2⟩ := a
    by_cases h : a1 = k
    · subst h
      simp [List.filter_cons, List.lookup_cons]
    · have h2 : (a1 == k) = false := beq_eq_false_iff_ne.mpr h
      have h3 : (k == a1) = false := beq_eq_false_iff_ne.mpr (Ne.symm h)
      simp [List.filter_cons, List.lookup_cons, h2, h3, ih]

theorem verifyToken_slice {c : Crypto} {s : PayerState} {p : Payment} {bytes : Bytes} {t : Token}
    (ht : decodeToken bytes = some t) : verifyToken c (slice s t) p bytes = verifyToken c s p bytes := by
  unfold verifyToken
  rw [ht]
  dsimp only
  have hb : batchOf (slice s t) t = batchOf s t := by
    cases hbo : batchOf s t with
    | none =>
      show List.find? (fun x => x.digest == t.checkpointDigest) (batchOf s t).toList = none
      rw [hbo]
      rfl
    | some st =>
      have hm := List.find?_some (show List.find? (fun x : Stored => x.digest == t.checkpointDigest) s.checkpoints = some st from hbo)
      show List.find? (fun x => x.digest == t.checkpointDigest) (batchOf s t).toList = some st
      rw [hbo]
      exact List.find?_cons_of_pos hm
  rw [hb]
  cases batchOf s t with
  | none => rfl
  | some st =>
    dsimp only
    by_cases hpm : paymentMatches c p t = true
    · have hpt : p.tenantId = t.leaf.tenantId := by
        unfold paymentMatches at hpm
        simp only [Bool.and_eq_true, beq_iff_eq] at hpm
        exact hpm.1.1.1.1.1.1.1.1.symm
      have hr : routed c (slice s t) p t = routed c s p t := by
        have hsc : shardCountOf (slice s t) t.leaf.tenantId = shardCountOf s t.leaf.tenantId := by
          unfold shardCountOf slice
          dsimp only
          rw [find?_filter_of_imp s.certs _ _ (fun _ h => h)]
        unfold routed
        rw [hpt, hsc]
      have hg : granted (slice s t) t = granted s t := by
        unfold granted slice
        simp only [List.any_filter]
        congr 1
        funext a
        generalize (a.grantId == t.leaf.grantId) = P
        cases P <;> simp
      have hu : unreleased (slice s t) t = unreleased s t := by
        unfold unreleased slice
        simp [List.contains_filter]
      have hn : unforked (slice s t) t = unforked s t := by
        unfold unforked blocked slice
        simp [List.any_filter]
      have hk : keyPinned (slice s t) t = keyPinned s t := by
        unfold keyPinned slice
        simp only []
        exact congrArg (· == some t.leaf.memberKey) (filter_lookup s.pins (payKey t))
      rw [hr, hg, hu, hn, hk]
      rfl
    · simp [hpm]

theorem firstFailure_none {c : Crypto} {s : PayerState} {p : Payment} {bytes : Bytes} :
    firstFailure c s p bytes = none ↔ verifyToken c s p bytes = true := by
  unfold firstFailure verifyToken
  rcases decodeToken bytes with _ | t
  · simp
  · dsimp only
    rcases batchOf s t with _ | st
    · simp
    · dsimp only
      generalize inBatch c st.checkpoint t = b1
      generalize aboveFence s t = b2
      generalize unexpired s t = b3
      generalize paymentMatches c p t = b4
      generalize routed c s p t = b5
      generalize allows t = b6
      generalize granted s t = b7
      generalize unreleased s t = b8
      generalize unforked s t = b9
      generalize keyPinned s t = b10
      revert b1 b2 b3 b4 b5 b6 b7 b8 b9 b10
      decide

end BlindLedger.Gate
