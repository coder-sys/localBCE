import BlindLedger.Gate.Verify
import BlindLedger.Gate.Payer
import BlindLedger.Gate.Producer
import BlindLedger.Gate.ProducerTheorems
import BlindLedger.Gate.Theorems

/-! payer-batch-release-v1 goals (design, 2026-10-01).  Definitions are final text for the builder; every
    `sorry` is a proof the builder owes.  Home in the product tree: `Gate/Batch.lean` (imports Verify, Payer,
    Producer; imported by VerifyCli only at step B4, so B1-B3 leave the pinned exe's sources untouched):
      §A  RELEASE-BATCH: install certificates and verify each checkpoint once, then decide every item
      §B  one-tree PUBLISH (`publishOkTree`), checked against `publishOk`
      theorems: `Gate/BatchTheorems.lean` (both sections).
    Base: branch gate-producer (worktree rightrail-gateprod, G2 commit b961c0a + Spec/Verify/Payer/Producer
    as committed).  They share one namespace here only so this file type-checks alone. -/

namespace BlindLedger.Gate

/-! ## §A  RELEASE-BATCH -/

/-- The payment a DECIDE-REQUEST asks about (moved out of `VerifyCli.release`, which built it inline). -/
def Request.payment (r : Request) : Payment :=
  { tenantId := r.tenantId, programId := r.programId, flow := r.flow, paymentId := r.paymentId,
    memberKey := r.memberKey, payeeRef := r.payeeRef, amountCents := r.amountCents, period := r.period,
    lines := r.lines }

/-- One payment of a payer run: the payer's own request, the token it holds for it, and the two rows the
    adapter reads inside the run's transaction (released already; the pinned member key). -/
structure Item where
  payment : Payment
  token : Bytes
  released : Bool
  pin : Option Bytes

/-- What a RELEASE-BATCH frame carries once for all its items.  Bytes only, except fork evidence, which the
    frame parser decodes (an undecodable one is a FRAME error: dropping it could only unblock). -/
structure ReleaseRun where
  certs : List Bytes
  evidence : List Stored
  checkpoints : List Bytes
  now : Nat
  grants : List Grant

/-- The installed certificates: `installCert` on each that decodes, in order.  Replaces `VerifyCli.certState`,
    which refused the whole frame on one undecodable certificate; such a certificate can never pass
    `rootSigned`, so skipping it is exactly an `installCert` that refuses. -/
def certsInstalled (c : Crypto) (certs : List Bytes) : PayerState :=
  (certs.filterMap decodeKeyCert).foldl (fun s e => (installCert c s e).1) emptyState

/-- The signature step for one checkpoint: ML-DSA-87 under an installed certificate of its tenant and epoch
    (`storeCheckpoint`'s check 2), against no stored checkpoint.  Fork detection is STORE's job, done when
    the payer stored it; RELEASE reads the recorded forks from `evidence`. -/
def verified (c : Crypto) (s0 : PayerState) (b : Bytes) : Option Stored :=
  (storeCheckpoint c { s0 with checkpoints := [], forked := [], equivocations := [] } b).bind
    (·.checkpoints.head?)

/-- The state one item is decided on: certificates, fence and equivocations from the frame's certificates,
    the given verified checkpoints, the frame's fork evidence, clock and grants, and the item's own rows. -/
def itemState (s0 : PayerState) (cps : List Stored) (r : ReleaseRun) (it : Item) : PayerState :=
  { s0 with checkpoints := cps, forked := r.evidence.map (fun f => (f, f)), now := r.now, grants := r.grants,
            released := if it.released then [it.payment.key] else [],
            pins := it.pin.toList.map fun m => (it.payment.key, m) }

/-- The single-token RELEASE (mode 0x04 today) as a function: install the certificates, verify the one
    checkpoint, decide the one item.  Kept only as the specification `releaseBatch` is proved against. -/
def releaseOne (c : Crypto) (r : ReleaseRun) (cp : Bytes) (it : Item) : Option Failure :=
  let s0 := certsInstalled c r.certs
  firstFailure c (itemState s0 (verified c s0 cp).toList r it) it.payment it.token

/-- Every checkpoint of the frame that verifies, each verified once. -/
def verifiedAll (c : Crypto) (r : ReleaseRun) : List Stored :=
  r.checkpoints.filterMap (verified c (certsInstalled c r.certs))

/-- RELEASE-BATCH: one answer per item, in item order; `none` is ACCEPT, `some f` is HOLD f. -/
def releaseBatch (c : Crypto) (r : ReleaseRun) (items : List Item) : List (Option Failure) :=
  let s0 := certsInstalled c r.certs
  let cps := verifiedAll c r
  items.map fun it => firstFailure c (itemState s0 cps r it) it.payment it.token

/-- The digests (hash of the signed header) of the frame's checkpoints. -/
def cpDigests (c : Crypto) (cps : List Bytes) : List Bytes :=
  cps.filterMap fun b => (decodeCheckpoint b).map fun x => c.hash x.header

/-- The frame checkpoint an item's token names, or the empty bytes (which never verify). -/
def cpFor (c : Crypto) (cps : List Bytes) (it : Item) : Bytes :=
  ((decodeToken it.token).bind fun t =>
    cps.find? fun b => (decodeCheckpoint b).any fun x => c.hash x.header == t.checkpointDigest).getD []

/-- The frame's canonical order, checked by the parser (else FRAME): every checkpoint decodes and their
    digests strictly ascend, so each is present once; 1..1,000 items whose payment ids strictly ascend (the
    parser also requires every request's tenant and program to equal the frame's), so each payment is
    present once.  Canonical order also makes the frame digest a function of the run's content. -/
def frameOrdered (c : Crypto) (cps : List Bytes) (items : List Item) : Bool :=
  (cps.all fun b => (decodeCheckpoint b).isSome) && ascending (cpDigests c cps) &&
    0 < items.length && items.length ≤ maxBatch && ascending (items.map (·.payment.paymentId))

/-- Bridge from the parser's check to the theorems' hypotheses (`ascending_nodup`). -/
theorem frameOrdered_nodup {c : Crypto} {cps : List Bytes} {items : List Item}
    (h : frameOrdered c cps items = true) :
    (cpDigests c cps).Nodup ∧ (items.map (·.payment.paymentId)).Nodup := by
  unfold frameOrdered at h
  simp only [Bool.and_eq_true, decide_eq_true_eq] at h
  obtain ⟨⟨⟨⟨-, h1⟩, -⟩, -⟩, h2⟩ := h
  exact ⟨ascending_nodup _ h1, ascending_nodup _ h2⟩

private theorem pCheckpoint_ne_nil {rest : Bytes} {cp : Checkpoint}
    (h : pCheckpoint.run [] = some (cp, rest)) : False := by
  simp only [pCheckpoint, StateT.run_bind] at h
  obtain ⟨a1, h1, -⟩ := bind_some h
  simp only [expect, StateT.run_bind] at h1
  obtain ⟨a, ha, -⟩ := bind_some h1
  simp [take, StateT.run, domain] at ha

private theorem decodeCheckpoint_nil : decodeCheckpoint [] = none := by
  have hs : pSignedCheckpoint.run [] = none := by
    rcases hr : pSignedCheckpoint.run [] with _ | ⟨y, rest⟩
    · rfl
    · exfalso
      simp only [pSignedCheckpoint, StateT.run_bind] at hr
      obtain ⟨c, hc, -⟩ := bind_some hr
      exact pCheckpoint_ne_nil (consumed_run hc)
  unfold decodeCheckpoint parse
  simp [hs]

private theorem verified_some {c : Crypto} {s0 : PayerState} {b : Bytes} {st : Stored}
    (h : verified c s0 b = some st) :
    ∃ x, decodeCheckpoint b = some x ∧ st = ⟨c.hash x.header, x.checkpoint, b⟩ ∧
      ∃ e ∈ s0.certs, e.tenantId = x.checkpoint.tenantId ∧ e.epoch = x.checkpoint.epoch ∧
        c.keyUsable e = true ∧ c.sigOk e.publicKey x.header x.signature = true := by
  unfold verified storeCheckpoint at h
  rcases hd : decodeCheckpoint b with _ | x
  · simp [hd] at h
  · simp only [hd] at h
    try dsimp only at h
    split at h
    · rename_i hs
      simp [blocked] at h
      refine ⟨x, rfl, by first | exact h.symm | exact h, ?_⟩
      simpa [List.any_eq_true, Bool.and_eq_true, beq_iff_eq, and_assoc] using hs
    · simp at h

private theorem unique_of_nodup {α β : Type} (f : α → Option β) :
    ∀ (L : List α), (L.filterMap f).Nodup → ∀ a ∈ L, ∀ b ∈ L, ∀ y, f a = some y → f b = some y → a = b := by
  intro L
  induction L with
  | nil => intro _ a ha; simp at ha
  | cons a0 rest ih =>
    intro hn a ha b hb y hfa hfb
    rw [List.mem_cons] at ha hb
    rcases h0 : f a0 with _ | y0
    · rw [List.filterMap_cons_none h0] at hn
      rcases ha with ha | ha
      · rw [ha, h0] at hfa; cases hfa
      rcases hb with hb | hb
      · rw [hb, h0] at hfb; cases hfb
      exact ih hn a ha b hb y hfa hfb
    · rw [List.filterMap_cons_some h0, List.nodup_cons] at hn
      have key : ∀ z ∈ rest, f z = some y0 → False :=
        fun z hz hfz => hn.1 (List.mem_filterMap.2 ⟨z, hz, hfz⟩)
      rcases ha with ha | ha <;> rcases hb with hb | hb
      · rw [ha, hb]
      · have hy : y0 = y := by rw [ha, h0] at hfa; exact Option.some.inj hfa
        exact (key b hb (by rw [hfb, hy])).elim
      · have hy : y0 = y := by rw [hb, h0] at hfb; exact Option.some.inj hfb
        exact (key a ha (by rw [hfa, hy])).elim
      · exact ih hn.2 a ha b hb y hfa hfb

/-- Verified checkpoints, found by digest, are the one frame checkpoint `cpFor` picks. -/
private theorem find_verified {c : Crypto} {cps : List Bytes} (s0 : PayerState)
    (hd : (cpDigests c cps).Nodup) (d : Bytes) :
    (cps.filterMap (verified c s0)).find? (·.digest == d) =
      (verified c s0 ((cps.find? fun b => (decodeCheckpoint b).any fun x => c.hash x.header == d).getD [])).toList.find?
        (·.digest == d) := by
  rw [List.find?_filterMap]
  have hP : ∀ b, ((verified c s0 b).any (·.digest == d)) = true →
      ((decodeCheckpoint b).any fun x => c.hash x.header == d) = true := by
    intro b hb
    rcases hv : verified c s0 b with _ | st
    · simp [hv] at hb
    · obtain ⟨x, hx, hst, -⟩ := verified_some hv
      simp only [hv, Option.any_some] at hb
      rw [hst] at hb
      simpa [hx] using hb
  have uniq : ∀ b ∈ cps, ∀ b' ∈ cps, ((decodeCheckpoint b).any fun x => c.hash x.header == d) = true →
      ((decodeCheckpoint b').any fun x => c.hash x.header == d) = true → b = b' := by
    intro b hb b' hb' h1 h2
    have hd' : (cps.filterMap fun b => (decodeCheckpoint b).map fun x => c.hash x.header).Nodup := hd
    refine unique_of_nodup (fun b => (decodeCheckpoint b).map fun x => c.hash x.header) cps hd' b hb b' hb' d ?_ ?_
    · rcases hx : decodeCheckpoint b with _ | x
      · simp [hx] at h1
      · simp only [hx, Option.any_some, beq_iff_eq] at h1
        simp [h1]
    · rcases hx : decodeCheckpoint b' with _ | x
      · simp [hx] at h2
      · simp only [hx, Option.any_some, beq_iff_eq] at h2
        simp [h2]
  have hv0 : verified c s0 [] = none := by
    unfold verified storeCheckpoint
    simp [decodeCheckpoint_nil]
  rcases hf : cps.find? (fun b => (decodeCheckpoint b).any fun x => c.hash x.header == d) with _ | b
  · have h1 : cps.find? (fun b => (verified c s0 b).any (·.digest == d)) = none := by
      apply List.find?_eq_none.2
      intro b hb hcon
      have h3 := hP b hcon
      have := List.find?_eq_none.1 hf b hb
      rw [h3] at this
      exact this rfl
    simp only [hf, Option.getD_none]
    simp [h1, hv0]
  · have hb : b ∈ cps := List.mem_of_find?_eq_some hf
    have hPb := List.find?_some hf
    simp only [hf, Option.getD_some]
    rcases hv : (verified c s0 b).any (·.digest == d) with _ | _
    · have h1 : cps.find? (fun b => (verified c s0 b).any (·.digest == d)) = none := by
        apply List.find?_eq_none.2
        intro b' hb' hcon
        have := uniq b' hb' b hb (hP b' hcon) hPb
        subst this
        rw [hv] at hcon
        cases hcon
      rw [h1]
      rcases hvb : verified c s0 b with _ | st
      · rfl
      · have hv' := hv
        simp [hvb] at hv'
        simp [hvb, hv']
    · have h1 : cps.find? (fun b => (verified c s0 b).any (·.digest == d)) = some b := by
        rcases hf1 : cps.find? (fun b => (verified c s0 b).any (·.digest == d)) with _ | b'
        · have := List.find?_eq_none.1 hf1 b hb
          rw [hv] at this
          simp at this
        · have hb' : b' ∈ cps := List.mem_of_find?_eq_some hf1
          have hPb' := List.find?_some hf1
          have := uniq b' hb' b hb (hP b' hPb') hPb
          subst this
          exact hf1
      rw [h1]
      rcases hvb : verified c s0 b with _ | st
      · simp [hvb] at hv
      · have hv' := hv
        simp [hvb] at hv'
        simp [hvb, hv']

private theorem firstFailure_itemState {c : Crypto} {s0 : PayerState} {A B : List Stored} {r : ReleaseRun}
    {it : Item}
    (h : ∀ t, decodeToken it.token = some t →
      A.find? (·.digest == t.checkpointDigest) = B.find? (·.digest == t.checkpointDigest)) :
    firstFailure c (itemState s0 A r it) it.payment it.token =
      firstFailure c (itemState s0 B r it) it.payment it.token := by
  unfold firstFailure
  rcases ht : decodeToken it.token with _ | t
  · rfl
  · dsimp only
    have hb : batchOf (itemState s0 A r it) t = batchOf (itemState s0 B r it) t := h t ht
    rw [hb]
    rfl

/-- Verify once = verify per token: with each checkpoint present once, the batch answers exactly what the
    single-token RELEASE answers for each item, given that item's own checkpoint. -/
theorem releaseBatch_eq {c : Crypto} {r : ReleaseRun} {items : List Item}
    (hd : (cpDigests c r.checkpoints).Nodup) :
    releaseBatch c r items = items.map fun it => releaseOne c r (cpFor c r.checkpoints it) it := by
  simp only [releaseBatch, releaseOne]
  apply List.map_congr_left
  intro it _
  apply firstFailure_itemState
  intro t ht
  have hcp : cpFor c r.checkpoints it =
      (r.checkpoints.find? fun b => (decodeCheckpoint b).any fun x => c.hash x.header == t.checkpointDigest).getD [] := by
    unfold cpFor
    rw [ht]
    rfl
  rw [hcp]
  exact find_verified _ hd _

/-- ACCEPT is exactly the payer's twelve checks (`verifyToken`) on the item's state. -/
theorem releaseBatch_spec {c : Crypto} {r : ReleaseRun} {items : List Item} {i : Nat} {it : Item}
    (hi : items[i]? = some it) :
    (releaseBatch c r items)[i]? = some none ↔
      verifyToken c (itemState (certsInstalled c r.certs) (verifiedAll c r) r it) it.payment it.token = true := by
  have : (releaseBatch c r items)[i]? =
      some (firstFailure c (itemState (certsInstalled c r.certs) (verifiedAll c r) r it) it.payment it.token) := by
    simp [releaseBatch, List.getElem?_map, hi]
  rw [this]
  exact Option.some_inj.trans firstFailure_none

/-- Isolation, items: replacing any other item (a bad token, a forged one, garbage) leaves an item's answer
    unchanged. -/
theorem releaseBatch_isolation {c : Crypto} {r : ReleaseRun} {items : List Item} {i j : Nat} (it : Item)
    (hij : i ≠ j) : (releaseBatch c r (items.set j it))[i]? = (releaseBatch c r items)[i]? := by
  simp [releaseBatch, List.getElem?_map, List.getElem?_set_ne hij.symm]

/-- Isolation, checkpoints: a checkpoint no item names (bad signature, wrong tenant, extra) changes no
    answer. -/
theorem releaseBatch_cp_isolation {c : Crypto} {r r' : ReleaseRun} {items : List Item}
    (hd : (cpDigests c r.checkpoints).Nodup) (hd' : (cpDigests c r'.checkpoints).Nodup)
    (hs : { r with checkpoints := [] } = { r' with checkpoints := [] })
    (hc : ∀ it ∈ items, cpFor c r.checkpoints it = cpFor c r'.checkpoints it) :
    releaseBatch c r items = releaseBatch c r' items := by
  have e1 : r.certs = r'.certs := by have h := congrArg ReleaseRun.certs hs; exact h
  have e2 : r.evidence = r'.evidence := by have h := congrArg ReleaseRun.evidence hs; exact h
  have e3 : r.now = r'.now := by have h := congrArg ReleaseRun.now hs; exact h
  have e4 : r.grants = r'.grants := by have h := congrArg ReleaseRun.grants hs; exact h
  rw [releaseBatch_eq hd, releaseBatch_eq hd']
  apply List.map_congr_left
  intro it hit
  rw [hc it hit]
  simp only [releaseOne, itemState, e1, e2, e3, e4]

private theorem foldl_certs (c : Crypto) : ∀ (es : List EpochCert) (s : PayerState) (e : EpochCert),
    e ∈ (es.foldl (fun s e => (installCert c s e).1) s).certs → e ∈ s.certs ∨ (e ∈ es ∧ c.rootSigned e = true)
  | [], s, e, h => Or.inl h
  | e' :: es, s, e, h => by
    rcases foldl_certs c es (installCert c s e').1 e h with h1 | h1
    · unfold installCert at h1
      split at h1
      · rename_i hc
        dsimp only at h1
        split at h1
        · rcases List.mem_cons.1 h1 with rfl | h1
          · exact Or.inr ⟨List.mem_cons_self, hc⟩
          · exact Or.inl h1
        · exact Or.inl h1
      · exact Or.inl h1
    · exact Or.inr ⟨List.mem_cons_of_mem _ h1.1, h1.2⟩

/-- Every installed certificate came from the frame and its root signature verified in this call. -/
theorem certsInstalled_mem {c : Crypto} {certs : List Bytes} {e : EpochCert}
    (h : e ∈ (certsInstalled c certs).certs) :
    c.rootSigned e = true ∧ ∃ b ∈ certs, decodeKeyCert b = some e := by
  rcases foldl_certs c _ emptyState e h with h1 | h1
  · simp [emptyState] at h1
  · exact ⟨h1.2, List.mem_filterMap.1 h1.1⟩

/-- No stored "verified" flag: an ACCEPT was earned in this call.  The token's checkpoint is among the
    frame's bytes, its ML-DSA-87 signature verified here under a certificate of the same tenant and epoch,
    and that certificate's chain to the root verified here.  The inputs are bytes; nothing the adapter
    stored stands in for either check. -/
theorem releaseBatch_accept_verified {c : Crypto} {r : ReleaseRun} {items : List Item} {i : Nat} {it : Item}
    (hi : items[i]? = some it) (ha : (releaseBatch c r items)[i]? = some none) :
    ∃ t b x e, decodeToken it.token = some t ∧ b ∈ r.checkpoints ∧ decodeCheckpoint b = some x ∧
      c.hash x.header = t.checkpointDigest ∧ (∃ cb ∈ r.certs, decodeKeyCert cb = some e) ∧
      c.certChainOk e = true ∧ e.tenantId = x.checkpoint.tenantId ∧ e.epoch = x.checkpoint.epoch ∧
      c.sigOk e.publicKey x.header x.signature = true := by
  have hF : (releaseBatch c r items)[i]? =
      some (firstFailure c (itemState (certsInstalled c r.certs) (verifiedAll c r) r it) it.payment it.token) := by
    simp [releaseBatch, List.getElem?_map, hi]
  rw [hF] at ha
  have hv := firstFailure_none.1 (Option.some_inj.1 ha)
  unfold verifyToken at hv
  rcases ht : decodeToken it.token with _ | t
  · simp [ht] at hv
  · rcases hb : batchOf (itemState (certsInstalled c r.certs) (verifiedAll c r) r it) t with _ | st
    · simp [ht, hb] at hv
    · have hmem := List.mem_of_find?_eq_some hb
      have hdig := List.find?_some hb
      simp only [itemState, verifiedAll, List.mem_filterMap] at hmem
      obtain ⟨b, hbm, hvb⟩ := hmem
      obtain ⟨x, hx, hst, e, he, het, hee, hku, hes⟩ := verified_some hvb
      obtain ⟨hroot, cb, hcb, hdec⟩ := certsInstalled_mem he
      have hchain : c.certChainOk e = true := by simp [Crypto.certChainOk, hroot, hku]
      refine ⟨t, b, x, e, rfl, hbm, hx, ?_, ⟨cb, hcb, hdec⟩, hchain, het, hee, hes⟩
      subst hst
      simpa using hdig

private theorem zip_map_self {α β : Type} (f : α → β) : ∀ l : List α, l.zip (l.map f) = l.map fun a => (a, f a)
  | [] => rfl
  | a :: l => by simp [zip_map_self f l]

private theorem verifyToken_unreleased {c : Crypto} {s : PayerState} {p : Payment} {bytes : Bytes}
    (h : verifyToken c s p bytes = true) :
    ∃ t, decodeToken bytes = some t ∧ payKey t = p.key ∧ s.released.contains (payKey t) = false := by
  unfold verifyToken at h
  rcases ht : decodeToken bytes with _ | t
  · simp [ht] at h
  · rcases hb : batchOf s t with _ | st
    · simp [ht, hb] at h
    · simp only [ht, hb, Bool.and_eq_true] at h
      obtain ⟨⟨⟨⟨⟨⟨⟨⟨⟨-, -⟩, -⟩, h4⟩, -⟩, -⟩, -⟩, h8⟩, -⟩, -⟩ := h
      unfold paymentMatches at h4
      simp only [Bool.and_eq_true, beq_iff_eq] at h4
      obtain ⟨⟨⟨⟨⟨⟨⟨⟨e1, e2⟩, -⟩, e4⟩, -⟩, -⟩, -⟩, -⟩, -⟩ := h4
      refine ⟨t, rfl, by simp [payKey, Payment.key, e1, e2, e4], ?_⟩
      unfold unreleased at h8
      simpa using h8

/-- At most once: in an ordered frame of one tenant and program, the accepted items' payment keys are
    distinct, and an item the payer already released never accepts (check 10, or check 6 first). -/
theorem releaseBatch_once {c : Crypto} {r : ReleaseRun} {items : List Item} {tenant program : Bytes}
    (ho : frameOrdered c r.checkpoints items = true)
    (ht : ∀ it ∈ items, it.payment.tenantId = tenant ∧ it.payment.programId = program) :
    (((items.zip (releaseBatch c r items)).filter (·.2.isNone)).map (·.1.payment.key)).Nodup ∧
      ∀ p ∈ items.zip (releaseBatch c r items), p.1.released = true → p.2.isSome = true := by
  have hrb : releaseBatch c r items = items.map (fun it =>
      firstFailure c (itemState (certsInstalled c r.certs) (verifiedAll c r) r it) it.payment it.token) := rfl
  refine ⟨?_, ?_⟩
  · have hkeys : (items.map (·.payment.key)).Nodup := by
      have h1 : items.map (·.payment.key) =
          (items.map (·.payment.paymentId)).map (fun i => (tenant, program, i)) := by
        rw [List.map_map]
        apply List.map_congr_left
        intro it hit
        simp [Payment.key, (ht it hit).1, (ht it hit).2]
      rw [h1]
      exact List.Pairwise.map _ (fun a b h hab => h (by simpa using hab)) (frameOrdered_nodup ho).2
    have hz : (items.zip (releaseBatch c r items)).map (fun p => p.1.payment.key) = items.map (·.payment.key) := by
      rw [hrb, zip_map_self, List.map_map]
      rfl
    have hn2 : ((items.zip (releaseBatch c r items)).map (fun p => p.1.payment.key)).Nodup := by
      rw [hz]; exact hkeys
    exact List.Nodup.sublist (List.Sublist.map _ List.filter_sublist) hn2
  · intro p hp hrel
    rw [hrb, zip_map_self] at hp
    obtain ⟨a, ha, rfl⟩ := List.mem_map.1 hp
    dsimp only at hrel ⊢
    cases hF : firstFailure c (itemState (certsInstalled c r.certs) (verifiedAll c r) r a) a.payment a.token with
    | some f => rfl
    | none =>
      exfalso
      obtain ⟨t, -, hk, hu⟩ := verifyToken_unreleased (firstFailure_none.1 hF)
      rw [hk] at hu
      simp [itemState, hrel] at hu

/-! ## §B  One-tree PUBLISH -/

/-- The levels of a Merkle tree, leaf hashes first, each the `pairUp` of the one below, ending at the root
    level (or at the level where fuel ran out, which `publishOkTree` refuses: it is not a singleton). -/
def levels (H : Bytes → Bytes) (d : Bytes) : Nat → List Bytes → List (List Bytes)
  | _, [x] => [[x]]
  | 0, xs => [xs]
  | fuel + 1, xs => xs :: levels H d fuel (pairUp H d xs)

/-- The siblings the token at `index` must carry, read off the levels: none where it is a carried odd last
    node (`pathRoot`'s rule), else its pair's node. -/
def pathOf : List (List Bytes) → Nat → List Bytes
  | [], _ => []
  | lvl :: rest, i =>
    if lvl.length ≤ 1 then []
    else if i % 2 == 0 && i + 1 == lvl.length then pathOf rest (i / 2)
    else lvl.getD (if i % 2 == 0 then i + 1 else i - 1) [] :: pathOf rest (i / 2)

/-- `tokenFits` on a decoded token, with the Merkle path compared to the batch's one tree instead of
    re-hashed. -/
def tokenFitsTree (c : Crypto) (k : Nat) (x : Stored) (lv : List (List Bytes)) (i : Nat) (t : Token) : Bool :=
  let cp := x.checkpoint
  t.checkpointDigest == x.digest && t.leaf.seq == cp.seqFrom + i &&
    cp.tenantId == t.leaf.tenantId && cp.programId == t.leaf.programId && cp.shardId == t.leaf.shardId &&
    cp.epoch == t.leaf.epoch && t.siblings == pathOf lv i &&
    t.leaf.shardId == shardOf c.hash t.leaf.tenantId t.leaf.memberKey k

/-- `publishOk` with each token decoded once and the tree built once: about 2k hashes per 1,000 tokens
    instead of about 11k.  The exe runs this; `publishOk` stays the specification. -/
def publishOkTree (rootPk cert : Bytes) (last : Option Bytes) (new : Bytes) (tokens : List Bytes) : Bool :=
  match decodeKeyCert cert, storedOf sha3 new, tokens.mapM decodeToken with
  | some e, some n, some ts =>
    let d := domain "MERKLE-NODE"
    let lv := levels sha3 d treeFuel (ts.map fun t => leafHash sha3 d t.leafBytes)
    accepts rootPk cert new && last.all (fun b => (storedOf sha3 b).isSome) &&
      follows (last.bind (storedOf sha3)) n && ts.length == n.checkpoint.count &&
      lv.getLast? == some [n.checkpoint.tokenRoot] &&
      (ts.zipIdx.all fun (t, i) =>
        tokenFitsTree (realCrypto [(n.checkpoint.tenantId, rootPk)]) e.shardCount n lv i t) &&
      ascending (ts.map (·.leaf.paymentId))
  | _, _, _ => false

private theorem pairUp_length (H : Bytes → Bytes) (d : Bytes) :
    ∀ xs : List Bytes, (pairUp H d xs).length = (xs.length + 1) / 2
  | a :: b :: rest => by
    simp only [pairUp, List.length_cons]
    rw [pairUp_length H d rest]
    omega
  | [] => by simp [pairUp]
  | [_] => by simp [pairUp]

private theorem pairUp_getD (H : Bytes → Bytes) (d : Bytes) :
    ∀ (xs : List Bytes) (j : Nat), j < (xs.length + 1) / 2 →
      (pairUp H d xs).getD j [] = if 2 * j + 1 < xs.length then
        nodeHash H d (xs.getD (2 * j) []) (xs.getD (2 * j + 1) []) else xs.getD (2 * j) []
  | a :: b :: rest, 0, _ => by simp [pairUp]
  | a :: b :: rest, j + 1, hj => by
    have ih := pairUp_getD H d rest j (by simp only [List.length_cons] at hj; omega)
    have e1 : 2 * (j + 1) = 2 * j + 1 + 1 := by omega
    rw [e1]
    simp only [pairUp, List.getD_cons_succ, List.length_cons]
    rw [ih]
    by_cases hc : 2 * j + 1 < rest.length
    · have : 2 * j + 1 + 1 + 1 < rest.length + 1 + 1 := by omega
      simp [hc, this]
    · have : ¬ 2 * j + 1 + 1 + 1 < rest.length + 1 + 1 := by omega
      simp [hc, this]
  | [], j, hj => by simp at hj
  | [a], 0, _ => by simp [pairUp]
  | [a], j + 1, hj => by simp at hj

private theorem levels_ne_nil (H : Bytes → Bytes) (d : Bytes) (f : Nat) (xs : List Bytes) :
    levels H d f xs ≠ [] := by
  rcases xs with _ | ⟨x, _ | ⟨y, rest⟩⟩
  · cases f <;> simp [levels]
  · simp [levels]
  · cases f <;> simp [levels]

private theorem levels_succ {H : Bytes → Bytes} {d : Bytes} {f : Nat} {xs : List Bytes} (h : 2 ≤ xs.length) :
    levels H d (f + 1) xs = xs :: levels H d f (pairUp H d xs) := by
  rcases xs with _ | ⟨x, _ | ⟨y, rest⟩⟩
  · simp at h
  · simp at h
  · first | rfl | simp [levels]

private theorem levels_zero {H : Bytes → Bytes} {d : Bytes} {xs : List Bytes} (h : 2 ≤ xs.length) :
    levels H d 0 xs = [xs] := by
  rcases xs with _ | ⟨x, _ | ⟨y, rest⟩⟩
  · simp at h
  · simp at h
  · first | rfl | simp [levels]

private theorem path_single {H : Bytes → Bytes} {d r : Bytes} {f g : Nat} {xs : List Bytes} {i : Nat}
    (hi : i < xs.length) (hlt : xs.length < 2) (hr : (levels H d f xs).getLast? = some [r]) :
    pathRoot H d (g + 1) i xs.length (xs.getD i []) (pathOf (levels H d f xs) i) = some r := by
  rcases xs with _ | ⟨x, _ | ⟨y, rest⟩⟩
  · simp at hi
  · have hi0 : i = 0 := by simp at hi; omega
    subst hi0
    simp [levels] at hr
    subst hr
    simp [levels, pathOf, pathRoot]
  · simp only [List.length_cons] at hlt; omega

private theorem pathRoot_skip {H : Bytes → Bytes} {d node : Bytes} {f index count : Nat} {path : List Bytes}
    (h1 : ¬ count ≤ 1) (h2 : (index % 2 == 0 && index + 1 == count) = true) :
    pathRoot H d (f + 1) index count node path = pathRoot H d f (index / 2) ((count + 1) / 2) node path := by
  show (if count ≤ 1 then (if path.isEmpty then some node else none)
    else if index % 2 == 0 && index + 1 == count then pathRoot H d f (index / 2) ((count + 1) / 2) node path
    else match path with
      | [] => none
      | s :: rest => pathRoot H d f (index / 2) ((count + 1) / 2) (H (stepInput d index node s)) rest) = _
  rw [if_neg h1, if_pos h2]

private theorem pathRoot_step {H : Bytes → Bytes} {d node s : Bytes} {f index count : Nat} {rest : List Bytes}
    (h1 : ¬ count ≤ 1) (h2 : ¬ (index % 2 == 0 && index + 1 == count) = true) :
    pathRoot H d (f + 1) index count node (s :: rest) =
      pathRoot H d f (index / 2) ((count + 1) / 2) (H (stepInput d index node s)) rest := by
  show (if count ≤ 1 then (if (s :: rest).isEmpty then some node else none)
    else if index % 2 == 0 && index + 1 == count then pathRoot H d f (index / 2) ((count + 1) / 2) node (s :: rest)
    else match s :: rest with
      | [] => none
      | s :: rest => pathRoot H d f (index / 2) ((count + 1) / 2) (H (stepInput d index node s)) rest) = _
  rw [if_neg h1, if_neg h2]

private theorem path_ok {H : Bytes → Bytes} {d r : Bytes} (f : Nat) : ∀ (g : Nat) (xs : List Bytes) (i : Nat),
    i < xs.length → xs.length ≤ 2 ^ g → (levels H d f xs).getLast? = some [r] →
    pathRoot H d (g + 1) i xs.length (xs.getD i []) (pathOf (levels H d f xs) i) = some r := by
  induction f with
  | zero =>
    intro g xs i hi hg hr
    rcases Nat.lt_or_ge xs.length 2 with hlt | hge
    · exact path_single hi hlt hr
    · rw [levels_zero hge] at hr
      simp at hr
      subst hr
      simp at hge
  | succ f ih =>
    intro g xs i hi hg hr
    rcases Nat.lt_or_ge xs.length 2 with hlt | hge
    · exact path_single hi hlt hr
    · rw [levels_succ hge] at hr ⊢
      obtain ⟨a, l, hl⟩ := List.exists_cons_of_ne_nil (levels_ne_nil H d f (pairUp H d xs))
      have hr' : (levels H d f (pairUp H d xs)).getLast? = some [r] := by
        rw [hl] at hr ⊢
        simpa using hr
      rcases g with _ | g
      · simp at hg; omega
      have hlen := pairUp_length H d xs
      have hpow : 2 ^ (g + 1) = 2 * 2 ^ g := by rw [Nat.pow_succ]; omega
      have hj : i / 2 < (xs.length + 1) / 2 := by omega
      have hi' : i / 2 < (pairUp H d xs).length := by omega
      have hg' : (pairUp H d xs).length ≤ 2 ^ g := by omega
      have ih' := ih g (pairUp H d xs) (i / 2) hi' hg' hr'
      rw [hlen] at ih'
      simp only [pathOf]
      rw [if_neg (show ¬ xs.length ≤ 1 by omega)]
      by_cases hc : (i % 2 == 0 && i + 1 == xs.length) = true
      · rw [if_pos hc, pathRoot_skip (by omega) hc]
        simp only [Bool.and_eq_true, beq_iff_eq] at hc
        have e : 2 * (i / 2) = i := by omega
        have hnode : (pairUp H d xs).getD (i / 2) [] = xs.getD i [] := by
          rw [pairUp_getD H d xs (i / 2) hj, e, if_neg (by omega)]
        rw [hnode] at ih'
        exact ih'
      · rw [if_neg hc, pathRoot_step (by omega) hc]
        have hc' : ¬ (i % 2 = 0 ∧ i + 1 = xs.length) := by
          rintro ⟨h1, h2⟩
          apply hc
          simp [h1, h2]
        have hnode : (pairUp H d xs).getD (i / 2) [] = H (stepInput d i (xs.getD i [])
            (xs.getD (if i % 2 == 0 then i + 1 else i - 1) [])) := by
          rw [pairUp_getD H d xs (i / 2) hj]
          by_cases hpar : i % 2 = 0
          · have e : 2 * (i / 2) = i := by omega
            rw [e, if_pos (by omega)]
            simp [nodeHash, stepInput, hpar]
          · have e : 2 * (i / 2) + 1 = i := by omega
            have e' : 2 * (i / 2) = i - 1 := by omega
            rw [e, e', if_pos (by omega)]
            simp [nodeHash, stepInput, hpar]
        rw [hnode] at ih'
        exact ih'

/-- The expected path verifies to the tree's root (needs at most 2^16 leaves, which `maxBatch` gives). -/
theorem pathOf_verifies {H : Bytes → Bytes} {d : Bytes} {hs : List Bytes} {i : Nat} {r : Bytes}
    (hi : i < hs.length) (hn : hs.length ≤ maxBatch) (hr : (levels H d treeFuel hs).getLast? = some [r]) :
    pathRoot H d treeFuel i hs.length (hs.getD i []) (pathOf (levels H d treeFuel hs) i) = some r :=
  path_ok treeFuel 16 hs i hi (Nat.le_trans hn (by decide)) hr

private theorem pCheckpoint_count {b rest : Bytes} {cp : Checkpoint}
    (h : pCheckpoint.run b = some (cp, rest)) : 1 ≤ cp.count ∧ cp.count ≤ maxBatch := by
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
  obtain ⟨a16, -, h⟩ := bind_some h
  obtain ⟨a17, -, h⟩ := bind_some h
  obtain ⟨a18, -, h⟩ := bind_some h
  have c13 := nat_ok hc
  simp only [StateT.run_pure, Option.pure_def, Option.some.injEq, Prod.mk.injEq] at h
  obtain ⟨rfl, -⟩ := h
  exact c13

private theorem pSigned_count {b rest : Bytes} {y : SignedCheckpoint}
    (h : pSignedCheckpoint.run b = some (y, rest)) : 1 ≤ y.checkpoint.count ∧ y.checkpoint.count ≤ maxBatch := by
  simp only [pSignedCheckpoint, StateT.run_bind] at h
  obtain ⟨c, hc, h⟩ := bind_some h
  obtain ⟨s, -, h⟩ := bind_some h
  simp only [StateT.run_pure, Option.pure_def, Option.some.injEq, Prod.mk.injEq] at h
  obtain ⟨rfl, -⟩ := h
  exact pCheckpoint_count (consumed_run hc)

private theorem storedOf_count {H : Bytes → Bytes} {b : Bytes} {x : Stored} (h : storedOf H b = some x) :
    1 ≤ x.checkpoint.count ∧ x.checkpoint.count ≤ maxBatch := by
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
          exact pSigned_count hr
        | cons a l => simp [hr] at hd

private theorem mapM_decode : ∀ (tokens : List Bytes) (ts : List Token), tokens.mapM decodeToken = some ts →
    tokens.filterMap decodeToken = ts ∧ ts.length = tokens.length ∧
      ∀ (i : Nat) (b : Bytes), tokens[i]? = some b → ∃ t : Token, ts[i]? = some t ∧ decodeToken b = some t
  | [], ts, h => by
    simp at h
    subst h
    simp
  | b :: bs, ts, h => by
    rcases hb : decodeToken b with _ | t
    · simp [List.mapM_cons, hb] at h
    · rcases hbs : bs.mapM decodeToken with _ | ts'
      · simp [List.mapM_cons, hb, hbs] at h
      · simp [List.mapM_cons, hb, hbs] at h
        subst h
        obtain ⟨h1, h2, h3⟩ := mapM_decode bs ts' hbs
        refine ⟨by simp [hb, h1], by simp [h2], ?_⟩
        intro i b' hi
        cases i with
        | zero =>
          simp at hi
          subst hi
          exact ⟨t, by simp, hb⟩
        | succ i => simpa using h3 i b' (by simpa using hi)

private theorem path_leaf {H : Bytes → Bytes} {d r : Bytes} {ts : List Token} {i : Nat} {t : Token}
    (hti : ts[i]? = some t) (hn : ts.length ≤ maxBatch)
    (hr : (levels H d treeFuel (ts.map fun t => leafHash H d t.leafBytes)).getLast? = some [r]) :
    pathRoot H d treeFuel i ts.length (leafHash H d t.leafBytes)
      (pathOf (levels H d treeFuel (ts.map fun t => leafHash H d t.leafBytes)) i) = some r := by
  have hi : i < ts.length := (List.getElem?_eq_some_iff.1 hti).1
  have h := pathOf_verifies (H := H) (d := d) (hs := ts.map fun t => leafHash H d t.leafBytes) (i := i) (r := r)
    (by simpa using hi) (by simpa using hn) hr
  have hget : (ts.map fun t => leafHash H d t.leafBytes).getD i [] = leafHash H d t.leafBytes := by
    simp [List.getD_eq_getElem?_getD, List.getElem?_map, hti]
  rw [hget, List.length_map] at h
  exact h

/-- Soundness, the only direction safety needs: the one-tree check never publishes what `publishOk`
    refuses, so `publishOk_sound` and `publish_payer_local` carry over unchanged. -/
theorem publishOkTree_sound {rootPk cert new : Bytes} {last : Option Bytes} {tokens : List Bytes}
    (h : publishOkTree rootPk cert last new tokens = true) : publishOk rootPk cert last new tokens = true := by
  unfold publishOkTree at h
  rcases hk : decodeKeyCert cert with _ | e
  · simp [hk] at h
  rcases hn : storedOf sha3 new with _ | n
  · simp [hk, hn] at h
  rcases hm : tokens.mapM decodeToken with _ | ts
  · simp [hk, hn, hm] at h
  simp only [hk, hn, hm, Bool.and_eq_true, beq_iff_eq] at h
  obtain ⟨⟨⟨⟨⟨⟨ha, hl⟩, hf⟩, hlen⟩, hlv⟩, hall⟩, hasc⟩ := h
  obtain ⟨hfm, hlenE, hpt⟩ := mapM_decode tokens ts hm
  have hcount := storedOf_count hn
  unfold publishOk
  simp only [hk, hn, Bool.and_eq_true, beq_iff_eq]
  refine ⟨⟨⟨⟨⟨ha, hl⟩, hf⟩, by omega⟩, ?_⟩, by rw [hfm]; exact hasc⟩
  rw [List.all_eq_true]
  rintro ⟨b, i⟩ hmem
  dsimp only
  have hbi := List.mk_mem_zipIdx_iff_getElem?.1 hmem
  obtain ⟨t, hti, hdec⟩ := hpt i b hbi
  have hfit := List.all_eq_true.1 hall (t, i) (List.mk_mem_zipIdx_iff_getElem?.2 hti)
  dsimp only at hfit
  obtain ⟨hi, -⟩ := List.getElem?_eq_some_iff.1 hti
  unfold tokenFitsTree at hfit
  simp only [Bool.and_eq_true, beq_iff_eq] at hfit
  obtain ⟨⟨⟨⟨⟨⟨⟨hdig, hseq⟩, htn⟩, hpg⟩, hsh⟩, hep⟩, hsib⟩, hshard⟩ := hfit
  have hpath := path_leaf (H := sha3) (d := domain "MERKLE-NODE") hti (by omega) hlv
  rw [hlen, ← hsib] at hpath
  unfold tokenFits
  rw [hdec]
  dsimp only
  unfold inBatch
  simp only [Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq]
  refine ⟨⟨⟨hdig, hseq⟩, ⟨⟨⟨⟨⟨htn, hpg⟩, hsh⟩, hep⟩, by omega⟩, ?_⟩⟩, hshard⟩
  have hidx : t.leaf.seq - n.checkpoint.seqFrom = i := by omega
  simp only [verifyPath, Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq]
  refine ⟨by omega, ?_⟩
  rw [hidx]
  exact hpath

/-! ### Completeness: a batch `publishOk` accepts and `publishOkTree` refuses names a SHA3 collision -/

/-- The hash inputs `pathRoot` folds on the way to its root, in order (its own recursion). -/
def pathInputs (H : Bytes → Bytes) (d : Bytes) : Nat → Nat → Nat → Bytes → List Bytes → List Bytes
  | 0, _, _, _, _ => []
  | fuel + 1, index, count, node, path =>
    if count ≤ 1 then []
    else if index % 2 == 0 && index + 1 == count then pathInputs H d fuel (index / 2) ((count + 1) / 2) node path
    else match path with
      | [] => []
      | s :: rest => stepInput d index node s ::
          pathInputs H d fuel (index / 2) ((count + 1) / 2) (H (stepInput d index node s)) rest

/-- Every hash input `publishOk` folds for the batch's token paths. -/
def publishInputs (tokens : List Bytes) : List Bytes :=
  let d := domain "MERKLE-NODE"
  let ts := tokens.filterMap decodeToken
  ts.zipIdx.flatMap fun (t, i) => pathInputs sha3 d treeFuel i ts.length (leafHash sha3 d t.leafBytes) t.siblings

/-- The first colliding pair among those inputs. -/
def publishCollision (tokens : List Bytes) : Option (Bytes × Bytes) :=
  let xs := publishInputs tokens
  (xs.flatMap fun x => xs.map (x, ·)).find? fun (x, y) => x != y && sha3 x == sha3 y

private theorem sha3_len (x : Bytes) : (sha3 x).length = digestBytes := Semantic.sha3_512_toList_length _

private theorem many_digest_len : ∀ (k : Nat) (b : Bytes) (r : List Bytes × Bytes),
    (many digest k).run b = some r → ∀ s ∈ r.1, s.length = digestBytes
  | 0, b, r, h => by
    simp only [many, StateT.run_pure, Option.pure_def, Option.some.injEq] at h
    subst h
    simp
  | k + 1, b, r, h => by
    simp only [many, StateT.run_bind] at h
    obtain ⟨a, hx, h⟩ := bind_some h
    obtain ⟨c, hxs, h⟩ := bind_some h
    simp only [StateT.run_pure, Option.pure_def, Option.some.injEq] at h
    subst h
    have hx' : a.1.length = digestBytes := by
      simp only [digest, take, StateT.run] at hx
      split at hx
      · cases hx
        simp only [List.length_take]
        omega
      · cases hx
    intro s hs
    simp only [List.mem_cons] at hs
    rcases hs with rfl | hs
    · exact hx'
    · exact many_digest_len k a.2 c hxs s hs

private theorem decodeToken_siblings {b : Bytes} {t : Token} (h : decodeToken b = some t) :
    ∀ s ∈ t.siblings, s.length = digestBytes := by
  unfold decodeToken parse at h
  split at h
  · cases h
  · split at h
    · rename_i x hr
      cases h
      simp only [pToken, StateT.run_bind] at hr
      obtain ⟨⟨⟨leaf, lb⟩, s1⟩, -, hr⟩ := bind_some hr
      try dsimp only at hr
      try simp only [StateT.run_bind] at hr
      obtain ⟨a2, -, hr⟩ := bind_some hr
      obtain ⟨a3, h3, hr⟩ := bind_some hr
      obtain ⟨a4, -, hr⟩ := bind_some hr
      simp only [StateT.run_pure, Option.pure_def, Option.some.injEq, Prod.mk.injEq] at hr
      obtain ⟨rfl, -⟩ := hr
      exact many_digest_len _ _ _ h3
    · cases h

private theorem mapM_some {tokens : List Bytes} (h : ∀ b ∈ tokens, (decodeToken b).isSome) :
    ∃ ts, tokens.mapM decodeToken = some ts := by
  induction tokens with
  | nil => exact ⟨[], rfl⟩
  | cons b bs ih =>
    obtain ⟨t, ht⟩ := Option.isSome_iff_exists.1 (h b (by simp))
    obtain ⟨ts, hts⟩ := ih (fun b' hb' => h b' (by simp [hb']))
    exact ⟨t :: ts, by simp [List.mapM_cons, ht, hts]⟩

private theorem pathRoot_one {H : Bytes → Bytes} {d node : Bytes} {f index count : Nat} {path : List Bytes}
    (h1 : count ≤ 1) : pathRoot H d (f + 1) index count node path = if path.isEmpty then some node else none := by
  simp only [pathRoot, if_pos h1]

private theorem pathRoot_nil {H : Bytes → Bytes} {d node : Bytes} {f index count : Nat}
    (h1 : ¬ count ≤ 1) (h2 : ¬ (index % 2 == 0 && index + 1 == count) = true) :
    pathRoot H d (f + 1) index count node [] = none := by
  simp only [pathRoot, if_neg h1, if_neg h2]

private theorem pathInputs_skip {H : Bytes → Bytes} {d node : Bytes} {f index count : Nat} {path : List Bytes}
    (h1 : ¬ count ≤ 1) (h2 : (index % 2 == 0 && index + 1 == count) = true) :
    pathInputs H d (f + 1) index count node path = pathInputs H d f (index / 2) ((count + 1) / 2) node path := by
  simp only [pathInputs, if_neg h1, if_pos h2]

private theorem pathInputs_step {H : Bytes → Bytes} {d node s : Bytes} {f index count : Nat} {rest : List Bytes}
    (h1 : ¬ count ≤ 1) (h2 : ¬ (index % 2 == 0 && index + 1 == count) = true) :
    pathInputs H d (f + 1) index count node (s :: rest) =
      stepInput d index node s :: pathInputs H d f (index / 2) ((count + 1) / 2) (H (stepInput d index node s)) rest := by
  simp only [pathInputs, if_neg h1, if_neg h2]

private theorem step_inj {d a b s t : Bytes} {i : Nat} (ha : a.length = b.length) (hs : s.length = t.length)
    (h : stepInput d i a s = stepInput d i b t) : a = b ∧ s = t := by
  unfold stepInput at h
  have h' := (List.cons.inj (List.append_cancel_left h)).2
  by_cases hp : (i % 2 == 0) = true
  · simp only [if_pos hp] at h'
    exact List.append_inj h' ha
  · simp only [if_neg hp] at h'
    exact (List.append_inj h' hs).symm

private theorem pair_inj {d a b s t : Bytes} {j : Nat} (ha : a.length = t.length)
    (h : stepInput d (2 * j) a s = stepInput d (2 * j + 1) b t) : t = a ∧ s = b := by
  unfold stepInput at h
  have h' := (List.cons.inj (List.append_cancel_left h)).2
  have e0 : (2 * j % 2 == 0) = true := by simp only [beq_iff_eq]; omega
  have e1 : ¬ ((2 * j + 1) % 2 == 0) = true := by simp only [beq_iff_eq]; omega
  simp only [if_pos e0, if_neg e1] at h'
  obtain ⟨h1, h2⟩ := List.append_inj h' ha
  exact ⟨h1.symm, h2⟩

/-- Two folds from one position to one root, with `H` injective on every input they hash, start from one node
    and carry one path. -/
private theorem path_inj {H : Bytes → Bytes} {d r : Bytes} {S : Bytes → Prop}
    (hl : ∀ x, (H x).length = digestBytes) (hinj : ∀ x y, S x → S y → H x = H y → x = y) (f : Nat) :
    ∀ (i n : Nat) (a b : Bytes) (p q : List Bytes), a.length = b.length →
      (∀ s ∈ p, s.length = digestBytes) → (∀ s ∈ q, s.length = digestBytes) →
      (∀ z ∈ pathInputs H d f i n a p, S z) → (∀ z ∈ pathInputs H d f i n b q, S z) →
      pathRoot H d f i n a p = some r → pathRoot H d f i n b q = some r → a = b ∧ p = q := by
  induction f with
  | zero => intro i n a b p q _ _ _ _ _ ha; simp [pathRoot] at ha
  | succ f ih =>
    intro i n a b p q hab hp hq hSa hSb ha hb
    by_cases h1 : n ≤ 1
    · rw [pathRoot_one h1] at ha hb
      cases p with
      | cons _ _ => simp at ha
      | nil =>
        cases q with
        | cons _ _ => simp at hb
        | nil => simp at ha hb; exact ⟨ha.trans hb.symm, rfl⟩
    · by_cases h2 : (i % 2 == 0 && i + 1 == n) = true
      · rw [pathRoot_skip h1 h2] at ha hb
        rw [pathInputs_skip h1 h2] at hSa hSb
        exact ih _ _ _ _ _ _ hab hp hq hSa hSb ha hb
      · cases p with
        | nil => rw [pathRoot_nil h1 h2] at ha; cases ha
        | cons s ps =>
          cases q with
          | nil => rw [pathRoot_nil h1 h2] at hb; cases hb
          | cons t qs =>
            rw [pathRoot_step h1 h2] at ha hb
            rw [pathInputs_step h1 h2] at hSa hSb
            obtain ⟨e, hpq⟩ := ih _ _ _ _ ps qs (by rw [hl, hl])
              (fun x hx => hp x (List.mem_cons_of_mem _ hx)) (fun x hx => hq x (List.mem_cons_of_mem _ hx))
              (fun z hz => hSa z (List.mem_cons_of_mem _ hz)) (fun z hz => hSb z (List.mem_cons_of_mem _ hz)) ha hb
            obtain ⟨e1, e2⟩ := step_inj hab (by rw [hp s (by simp), hq t (by simp)])
              (hinj _ _ (hSa _ (by simp)) (hSb _ (by simp)) e)
            exact ⟨e1, by rw [e2, hpq]⟩

/-- Every position of a level folding to `r`, with `H` injective on every input hashed, forces the level's tree:
    its root is `r` and each position's path is the tree's own. -/
private theorem tree_unique {H : Bytes → Bytes} {d r : Bytes} {S : Bytes → Prop}
    (hl : ∀ x, (H x).length = digestBytes) (hinj : ∀ x y, S x → S y → H x = H y → x = y) (f : Nat) :
    ∀ (xs : List Bytes) (ps : Nat → List Bytes), xs ≠ [] →
      (∀ i < xs.length, (xs.getD i []).length = digestBytes) →
      (∀ i < xs.length, ∀ s ∈ ps i, s.length = digestBytes) →
      (∀ i < xs.length, ∀ z ∈ pathInputs H d f i xs.length (xs.getD i []) (ps i), S z) →
      (∀ i < xs.length, pathRoot H d f i xs.length (xs.getD i []) (ps i) = some r) →
      (levels H d f xs).getLast? = some [r] ∧ ∀ i < xs.length, ps i = pathOf (levels H d f xs) i := by
  induction f with
  | zero =>
    intro xs ps hne _ _ _ hr
    cases xs with
    | nil => exact absurd rfl hne
    | cons x _ => have := hr 0 (by simp); simp [pathRoot] at this
  | succ f ih =>
    intro xs ps hne hx hp hS hr
    rcases Nat.lt_or_ge xs.length 2 with hlt | hge
    · obtain ⟨x, rfl⟩ : ∃ x, xs = [x] := by
        rcases xs with _ | ⟨x, _ | ⟨y, rest⟩⟩
        · exact absurd rfl hne
        · exact ⟨x, rfl⟩
        · simp only [List.length_cons] at hlt; omega
      have h0 : pathRoot H d (f + 1) 0 1 x (ps 0) = some r := hr 0 (by simp)
      rw [pathRoot_one (Nat.le_refl 1)] at h0
      cases hps : ps 0 with
      | cons _ _ => rw [hps] at h0; simp at h0
      | nil =>
        rw [hps] at h0
        simp at h0
        subst h0
        refine ⟨by simp [levels], fun i hi => ?_⟩
        obtain rfl : i = 0 := by simp at hi; omega
        simp [levels, pathOf, hps]
    · have h1 : ¬ xs.length ≤ 1 := by omega
      have hm := pairUp_length H d xs
      obtain ⟨ps', hps'⟩ : ∃ g : Nat → List Bytes,
          ∀ j, g j = if 2 * j + 1 < xs.length then (ps (2 * j)).tail else ps (2 * j) := ⟨_, fun _ => rfl⟩
      have hpair : ∀ j, 2 * j + 1 < xs.length → ∃ rest, ps (2 * j) = xs.getD (2 * j + 1) [] :: rest ∧
          ps (2 * j + 1) = xs.getD (2 * j) [] :: rest ∧
          pathRoot H d f j ((xs.length + 1) / 2) (nodeHash H d (xs.getD (2 * j) []) (xs.getD (2 * j + 1) []))
            rest = some r ∧
          ∀ z ∈ pathInputs H d f j ((xs.length + 1) / 2)
            (nodeHash H d (xs.getD (2 * j) []) (xs.getD (2 * j + 1) [])) rest, S z := by
        intro j hj
        have c0 : ¬ (2 * j % 2 == 0 && 2 * j + 1 == xs.length) = true := by
          simp only [Bool.and_eq_true, beq_iff_eq]; omega
        have c1 : ¬ ((2 * j + 1) % 2 == 0 && 2 * j + 1 + 1 == xs.length) = true := by
          simp only [Bool.and_eq_true, beq_iff_eq]; omega
        have d0 : 2 * j / 2 = j := by omega
        have d1 : (2 * j + 1) / 2 = j := by omega
        have ev : (2 * j % 2 == 0) = true := by simp only [beq_iff_eq]; omega
        have r0 := hr (2 * j) (by omega)
        have r1 := hr (2 * j + 1) hj
        have S0 := hS (2 * j) (by omega)
        have S1 := hS (2 * j + 1) hj
        have p0 := hp (2 * j) (by omega)
        have p1 := hp (2 * j + 1) hj
        have l0 := hx (2 * j) (by omega)
        rcases hq0 : ps (2 * j) with _ | ⟨s0, rest0⟩
        · rw [hq0, pathRoot_nil h1 c0] at r0; cases r0
        rcases hq1 : ps (2 * j + 1) with _ | ⟨s1, rest1⟩
        · rw [hq1, pathRoot_nil h1 c1] at r1; cases r1
        rw [hq0, pathRoot_step h1 c0, d0] at r0
        rw [hq1, pathRoot_step h1 c1, d1] at r1
        rw [hq0, pathInputs_step h1 c0, d0] at S0
        rw [hq1, pathInputs_step h1 c1, d1] at S1
        rw [hq0] at p0
        rw [hq1] at p1
        obtain ⟨e, hrest⟩ := path_inj hl hinj f j _ _ _ rest0 rest1 (by rw [hl, hl])
          (fun s hs => p0 s (List.mem_cons_of_mem _ hs)) (fun s hs => p1 s (List.mem_cons_of_mem _ hs))
          (fun z hz => S0 z (List.mem_cons_of_mem _ hz)) (fun z hz => S1 z (List.mem_cons_of_mem _ hz)) r0 r1
        obtain ⟨e1, e2⟩ := pair_inj (by rw [l0, p1 s1 (by simp)])
          (hinj _ _ (S0 _ (by simp)) (S1 _ (by simp)) e)
        have hnode : nodeHash H d (xs.getD (2 * j) []) (xs.getD (2 * j + 1) []) =
            H (stepInput d (2 * j) (xs.getD (2 * j) []) s0) := by
          rw [e2]
          unfold nodeHash stepInput
          rw [if_pos ev]
        refine ⟨rest0, by simp [e2], by simp [e1, hrest], ?_, ?_⟩
        · rw [hnode]; exact r0
        · rw [hnode]; exact fun z hz => S0 z (List.mem_cons_of_mem _ hz)
      have hcarry : ∀ j, 2 * j + 1 = xs.length →
          pathRoot H d f j ((xs.length + 1) / 2) (xs.getD (2 * j) []) (ps (2 * j)) = some r ∧
          ∀ z ∈ pathInputs H d f j ((xs.length + 1) / 2) (xs.getD (2 * j) []) (ps (2 * j)), S z := by
        intro j hj
        have c0 : (2 * j % 2 == 0 && 2 * j + 1 == xs.length) = true := by
          simp only [Bool.and_eq_true, beq_iff_eq]; omega
        have d0 : 2 * j / 2 = j := by omega
        have r0 := hr (2 * j) (by omega)
        have S0 := hS (2 * j) (by omega)
        rw [pathRoot_skip h1 c0, d0] at r0
        rw [pathInputs_skip h1 c0, d0] at S0
        exact ⟨r0, S0⟩
      have hy : ∀ j < (pairUp H d xs).length, (pairUp H d xs).getD j [] =
          if 2 * j + 1 < xs.length then nodeHash H d (xs.getD (2 * j) []) (xs.getD (2 * j + 1) [])
          else xs.getD (2 * j) [] :=
        fun j hj => pairUp_getD H d xs j (by omega)
      obtain ⟨hlast, hpath⟩ := ih (pairUp H d xs) ps' (List.ne_nil_of_length_pos (by omega))
        (by
          intro j hj
          rw [hy j hj]
          by_cases hc : 2 * j + 1 < xs.length
          · rw [if_pos hc]; unfold nodeHash; exact hl _
          · rw [if_neg hc]; exact hx _ (by omega))
        (by
          intro j hj s hs
          rw [hps'] at hs
          by_cases hc : 2 * j + 1 < xs.length
          · rw [if_pos hc] at hs
            obtain ⟨rest, h0, -, -, -⟩ := hpair j hc
            rw [h0, List.tail_cons] at hs
            exact hp (2 * j) (by omega) s (by rw [h0]; exact List.mem_cons_of_mem _ hs)
          · rw [if_neg hc] at hs
            exact hp (2 * j) (by omega) s hs)
        (by
          intro j hj z hz
          rw [hy j hj, hm, hps'] at hz
          by_cases hc : 2 * j + 1 < xs.length
          · simp only [if_pos hc] at hz
            obtain ⟨rest, h0, -, -, hS'⟩ := hpair j hc
            rw [h0, List.tail_cons] at hz
            exact hS' z hz
          · simp only [if_neg hc] at hz
            exact (hcarry j (by omega)).2 z hz)
        (by
          intro j hj
          rw [hy j hj, hm, hps']
          by_cases hc : 2 * j + 1 < xs.length
          · simp only [if_pos hc]
            obtain ⟨rest, h0, -, hr', -⟩ := hpair j hc
            rw [h0, List.tail_cons]
            exact hr'
          · simp only [if_neg hc]
            exact (hcarry j (by omega)).1)
      rw [levels_succ hge]
      refine ⟨?_, fun i hi => ?_⟩
      · obtain ⟨a, l, hal⟩ := List.exists_cons_of_ne_nil (levels_ne_nil H d f (pairUp H d xs))
        rw [hal] at hlast ⊢
        simpa using hlast
      · simp only [pathOf]
        rw [if_neg (show ¬ xs.length ≤ 1 by omega)]
        have hj : i / 2 < (pairUp H d xs).length := by omega
        have this := hpath (i / 2) hj
        by_cases hc : (i % 2 == 0 && i + 1 == xs.length) = true
        · rw [if_pos hc]
          simp only [Bool.and_eq_true, beq_iff_eq] at hc
          have e : 2 * (i / 2) = i := by omega
          have hn : ¬ 2 * (i / 2) + 1 < xs.length := by omega
          rw [hps', if_neg hn, e] at this
          exact this
        · rw [if_neg hc]
          have hlt : 2 * (i / 2) + 1 < xs.length := by
            simp only [Bool.and_eq_true, beq_iff_eq] at hc; omega
          obtain ⟨rest, h0, h1', -, -⟩ := hpair (i / 2) hlt
          rw [hps', if_pos hlt, h0, List.tail_cons] at this
          by_cases hpar : i % 2 = 0
          · have ev : (i % 2 == 0) = true := by simp only [beq_iff_eq]; omega
            have e : 2 * (i / 2) = i := by omega
            rw [e] at h0
            rw [if_pos ev, h0, this]
          · have od : ¬ (i % 2 == 0) = true := by simp only [beq_iff_eq]; omega
            have e : 2 * (i / 2) + 1 = i := by omega
            have e' : 2 * (i / 2) = i - 1 := by omega
            rw [e, e'] at h1'
            rw [if_neg od, h1', this]

/-- Completeness up to a named collision (liveness only; the honest-batch case is also pinned by tests): a batch
    `publishOk` accepts passes `publishOkTree`, or `publishCollision` returns two distinct inputs that `publishOk`
    itself hashed to one SHA3 output.  The pair is the batch's own, not the pigeonhole triviality. -/
theorem publishOkTree_complete {rootPk cert new : Bytes} {last : Option Bytes} {tokens : List Bytes}
    (h : publishOk rootPk cert last new tokens = true) :
    publishOkTree rootPk cert last new tokens = true ∨
      ∃ x y, publishCollision tokens = some (x, y) ∧ x ≠ y ∧ sha3 x = sha3 y := by
  cases hc : publishCollision tokens with
  | some p =>
    right
    obtain ⟨x, y⟩ := p
    refine ⟨x, y, rfl, ?_⟩
    simp only [publishCollision] at hc
    have := List.find?_some hc
    simp only [Bool.and_eq_true, bne_iff_ne, ne_eq, beq_iff_eq] at this
    exact this
  | none =>
  left
  have hinj : ∀ x y, x ∈ publishInputs tokens → y ∈ publishInputs tokens → sha3 x = sha3 y → x = y := by
    intro x y hx hy e
    by_cases hne : x = y
    · exact hne
    simp only [publishCollision] at hc
    exact (List.find?_eq_none.1 hc (x, y) (List.mem_flatMap.2 ⟨x, hx, List.mem_map.2 ⟨y, hy, rfl⟩⟩)
      (by simp [hne, e])).elim
  unfold publishOk at h
  rcases hk : decodeKeyCert cert with _ | e
  · simp [hk] at h
  rcases hn : storedOf sha3 new with _ | n
  · simp [hk, hn] at h
  simp only [hk, hn, Bool.and_eq_true, beq_iff_eq] at h
  obtain ⟨⟨⟨⟨⟨ha, hl⟩, hf⟩, hlen⟩, hall⟩, hasc⟩ := h
  have hcount := storedOf_count hn
  have hfit : ∀ (i : Nat) (b : Bytes), tokens[i]? = some b →
      tokenFits (realCrypto [(n.checkpoint.tenantId, rootPk)]) e.shardCount n i b = true :=
    fun i b hb => List.all_eq_true.1 hall (b, i) (List.mk_mem_zipIdx_iff_getElem?.2 hb)
  obtain ⟨ts, hm⟩ : ∃ ts, tokens.mapM decodeToken = some ts := by
    apply mapM_some
    intro b hb
    obtain ⟨i, hi⟩ := List.mem_iff_getElem?.1 hb
    have := hfit i b hi
    unfold tokenFits at this
    cases hd : decodeToken b with
    | none => simp [hd] at this
    | some _ => rfl
  obtain ⟨hfm, hlenE, hpt⟩ := mapM_decode tokens ts hm
  have htok : ∀ (i : Nat) (t : Token), ts[i]? = some t → ∃ b, decodeToken b = some t ∧
      tokenFits (realCrypto [(n.checkpoint.tenantId, rootPk)]) e.shardCount n i b = true := by
    intro i t hti
    have hi : i < tokens.length := by have := (List.getElem?_eq_some_iff.1 hti).1; omega
    obtain ⟨t', ht', hdec⟩ := hpt i tokens[i] (List.getElem?_eq_getElem hi)
    rw [hti] at ht'
    cases ht'
    exact ⟨_, hdec, hfit i _ (List.getElem?_eq_getElem hi)⟩
  have hpath : ∀ (i : Nat) (t : Token), ts[i]? = some t → pathRoot sha3 (domain "MERKLE-NODE") treeFuel i ts.length
      (leafHash sha3 (domain "MERKLE-NODE") t.leafBytes) t.siblings = some n.checkpoint.tokenRoot := by
    intro i t hti
    obtain ⟨b, hdec, hfit'⟩ := htok i t hti
    unfold tokenFits at hfit'
    rw [hdec] at hfit'
    dsimp only at hfit'
    unfold inBatch verifyPath at hfit'
    simp only [Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at hfit'
    obtain ⟨⟨⟨-, hseq⟩, ⟨⟨⟨⟨⟨-, -⟩, -⟩, -⟩, -⟩, -, hpr⟩⟩, -⟩ := hfit'
    have hidx : t.leaf.seq - n.checkpoint.seqFrom = i := by omega
    rw [hidx, ← hlen, ← hlenE] at hpr
    exact hpr
  have hd : ∀ (i : Nat) (t : Token), ts[i]? = some t → (ts.map fun t => leafHash sha3 (domain "MERKLE-NODE") t.leafBytes).getD i [] =
      leafHash sha3 (domain "MERKLE-NODE") t.leafBytes := by
    intro i t hti
    simp [List.getD_eq_getElem?_getD, List.getElem?_map, hti]
  have hps : ∀ (i : Nat) (t : Token), ts[i]? = some t → (ts[i]?.map Token.siblings).getD [] = t.siblings := by
    intro i t hti
    simp [hti]
  have hget : ∀ i, i < ts.length → ∃ t, ts[i]? = some t := fun i hi => ⟨ts[i], List.getElem?_eq_getElem hi⟩
  obtain ⟨hlast, hsibs⟩ := tree_unique (S := fun z => z ∈ publishInputs tokens) (r := n.checkpoint.tokenRoot)
    (d := domain "MERKLE-NODE") sha3_len hinj treeFuel
    (ts.map fun t => leafHash sha3 (domain "MERKLE-NODE") t.leafBytes) (fun i => (ts[i]?.map Token.siblings).getD [])
    (List.ne_nil_of_length_pos (by simp only [List.length_map]; omega))
    (by
      intro i hi
      simp only [List.length_map] at hi
      obtain ⟨t, hti⟩ := hget i hi
      rw [hd i t hti]
      exact sha3_len _)
    (by
      intro i hi s hs
      simp only [List.length_map] at hi
      obtain ⟨t, hti⟩ := hget i hi
      rw [hps i t hti] at hs
      obtain ⟨b, hdec, -⟩ := htok i t hti
      exact decodeToken_siblings hdec s hs)
    (by
      intro i hi z hz
      simp only [List.length_map] at hi hz
      obtain ⟨t, hti⟩ := hget i hi
      rw [hd i t hti, hps i t hti] at hz
      simp only [publishInputs, hfm]
      exact List.mem_flatMap.2 ⟨(t, i), List.mk_mem_zipIdx_iff_getElem?.2 hti, hz⟩)
    (by
      intro i hi
      simp only [List.length_map] at hi ⊢
      obtain ⟨t, hti⟩ := hget i hi
      rw [hd i t hti, hps i t hti]
      exact hpath i t hti)
  unfold publishOkTree
  simp only [hk, hn, hm, Bool.and_eq_true, beq_iff_eq]
  refine ⟨⟨⟨⟨⟨⟨ha, hl⟩, hf⟩, by omega⟩, hlast⟩, ?_⟩, by rw [← hfm]; exact hasc⟩
  rw [List.all_eq_true]
  rintro ⟨t, i⟩ hmem
  dsimp only
  have hti := List.mk_mem_zipIdx_iff_getElem?.1 hmem
  obtain ⟨b, hdec, hfit'⟩ := htok i t hti
  unfold tokenFits at hfit'
  rw [hdec] at hfit'
  dsimp only at hfit'
  unfold inBatch at hfit'
  simp only [Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at hfit'
  obtain ⟨⟨⟨hdig, hseq⟩, ⟨⟨⟨⟨⟨htn, hpg⟩, hsh⟩, hep⟩, -⟩, -⟩⟩, hshard⟩ := hfit'
  unfold tokenFitsTree
  simp only [Bool.and_eq_true, beq_iff_eq]
  refine ⟨⟨⟨⟨⟨⟨⟨hdig, hseq⟩, htn⟩, hpg⟩, hsh⟩, hep⟩, ?_⟩, hshard⟩
  have := hsibs i (by simp only [List.length_map]; exact (List.getElem?_eq_some_iff.1 hti).1)
  rw [hps i t hti] at this
  exact this

end BlindLedger.Gate
