import BlindLedger.Gate.Batch
import BlindLedger.Gate.ProducerTheorems

/-! Theorems of payer-batch-release-v1 (§A RELEASE-BATCH, §B one-tree PUBLISH).  Statements: the design's
    `payer-batch-release-goals.lean`, fixed. -/
namespace BlindLedger.Gate

/-! ## §A  RELEASE-BATCH -/

/-- Bridge from the parser's check to the theorems' hypotheses (`ascending_nodup`). -/
theorem frameOrdered_nodup {c : Crypto} {cps : List Bytes} {items : List Item}
    (h : frameOrdered c cps items = true) :
    (cpDigests c cps).Nodup ∧ (items.map (·.payment.paymentId)).Nodup := by
  simp only [frameOrdered, Bool.and_eq_true] at h
  exact ⟨ascending_nodup _ h.1.1.1.2, ascending_nodup _ h.2⟩

/-- `firstFailure` reads the checkpoints only through `batchOf`. -/
private theorem firstFailure_cps {c : Crypto} {s0 : PayerState} {cps cps' : List Stored} {r : ReleaseRun}
    {it : Item} (h : ∀ t, decodeToken it.token = some t →
      cps.find? (·.digest == t.checkpointDigest) = cps'.find? (·.digest == t.checkpointDigest)) :
    firstFailure c (itemState s0 cps r it) it.payment it.token =
      firstFailure c (itemState s0 cps' r it) it.payment it.token := by
  unfold firstFailure
  cases ht : decodeToken it.token with
  | none => rfl
  | some t =>
    have hb : batchOf (itemState s0 cps r it) t = batchOf (itemState s0 cps' r it) t := h t ht
    dsimp only
    rw [hb]
    rfl

/-- `verified` without the store: the checkpoint decodes and verifies under an installed usable certificate of
    its tenant and epoch. -/
private theorem verified_eq (c : Crypto) (s0 : PayerState) (b : Bytes) :
    verified c s0 b = (decodeCheckpoint b).bind fun x =>
      if s0.certs.any (fun e => e.tenantId == x.checkpoint.tenantId && e.epoch == x.checkpoint.epoch &&
          (c.keyUsable e && c.sigOk e.publicKey x.header x.signature)) then
        some ⟨c.hash x.header, x.checkpoint, b⟩
      else none := by
  unfold verified storeCheckpoint
  cases decodeCheckpoint b with
  | none => rfl
  | some x =>
    dsimp only
    split <;> simp_all [blocked]

private theorem verified_digest {c : Crypto} {s0 : PayerState} {b : Bytes} {st : Stored}
    (h : verified c s0 b = some st) : ∃ x, decodeCheckpoint b = some x ∧ st.digest = c.hash x.header := by
  rw [verified_eq] at h
  cases hx : decodeCheckpoint b with
  | none => simp [hx] at h
  | some x =>
    simp only [hx, Option.bind_some] at h
    split at h
    · simp only [Option.some.injEq] at h
      exact ⟨x, rfl, by rw [← h]⟩
    · simp at h

private theorem decodeCheckpoint_nil : decodeCheckpoint [] = none := by
  cases h : decodeCheckpoint [] with
  | none => rfl
  | some x =>
    exfalso
    have hr := parse_run h
    simp only [pSignedCheckpoint, StateT.run_bind] at hr
    obtain ⟨y, hc, -⟩ := bind_some hr
    have hp := consumed_run hc
    simp only [pCheckpoint, StateT.run_bind] at hp
    obtain ⟨u, he, -⟩ := bind_some hp
    have := expect_run he
    simp [domain] at this

/-- Looking a digest up among the verified checkpoints is verifying the one frame checkpoint carrying it. -/
private theorem find_verified (c : Crypto) (s0 : PayerState) (d : Bytes) :
    ∀ L : List Bytes, (cpDigests c L).Nodup →
      (L.filterMap (verified c s0)).find? (·.digest == d) =
        (L.find? fun b => (decodeCheckpoint b).any fun x => c.hash x.header == d).bind (verified c s0)
  | [], _ => rfl
  | b :: L, hn => by
    have hmem : ∀ st ∈ L.filterMap (verified c s0), st.digest ∈ cpDigests c L := by
      intro st hst
      obtain ⟨b', hb', hv⟩ := List.mem_filterMap.1 hst
      obtain ⟨x, hx, hd⟩ := verified_digest hv
      exact List.mem_filterMap.2 ⟨b', hb', by simp [hx, hd]⟩
    cases hx : decodeCheckpoint b with
    | none =>
      have hv : verified c s0 b = none := by simp [verified_eq, hx]
      have hn' : (cpDigests c L).Nodup := by simpa [cpDigests, hx] using hn
      simp only [List.filterMap_cons, hv, List.find?_cons, hx, Option.any_none]
      exact find_verified c s0 d L hn'
    | some x =>
      have hn' : c.hash x.header ∉ cpDigests c L ∧ (cpDigests c L).Nodup := by
        simpa [cpDigests, hx] using hn
      by_cases hd : c.hash x.header = d
      · simp only [List.find?_cons, hx, Option.any_some, hd, beq_self_eq_true, Option.bind_some]
        cases hv : verified c s0 b with
        | none =>
          simp only [List.filterMap_cons, hv]
          exact List.find?_eq_none.2 fun st hst he =>
            hn'.1 (by rw [hd, ← (beq_iff_eq.1 he)]; exact hmem st hst)
        | some st =>
          obtain ⟨x', hx', hd'⟩ := verified_digest hv
          rw [hx] at hx'
          cases hx'
          simp only [List.filterMap_cons, hv, List.find?_cons, hd', hd, beq_self_eq_true]
      · have hfalse : (c.hash x.header == d) = false := by simpa using hd
        simp only [List.find?_cons, hx, Option.any_some, hfalse]
        rw [← find_verified c s0 d L hn'.2]
        cases hv : verified c s0 b with
        | none => simp only [List.filterMap_cons, hv]
        | some st =>
          obtain ⟨x', hx', hd'⟩ := verified_digest hv
          rw [hx] at hx'
          cases hx'
          simp only [List.filterMap_cons, hv, List.find?_cons, hd', hfalse]

/-- The one frame checkpoint named, verified alone, is found exactly when it verifies. -/
private theorem find_verified_one (c : Crypto) (s0 : PayerState) (d : Bytes) (o : Option Bytes)
    (ho : ∀ b, o = some b → (decodeCheckpoint b).any (fun x => c.hash x.header == d) = true) :
    (verified c s0 (o.getD [])).toList.find? (·.digest == d) = o.bind (verified c s0) := by
  cases o with
  | none => simp [verified_eq, decodeCheckpoint_nil]
  | some b =>
    simp only [Option.getD_some, Option.bind_some]
    cases hv : verified c s0 b with
    | none => rfl
    | some st =>
      obtain ⟨x, hx, hd'⟩ := verified_digest hv
      have h := ho b rfl
      simp only [hx, Option.any_some] at h
      simp [hd', h]

/-- Verify once = verify per token: with each checkpoint present once, the batch answers exactly what the
    single-token RELEASE answers for each item, given that item's own checkpoint. -/
theorem releaseBatch_eq {c : Crypto} {r : ReleaseRun} {items : List Item}
    (hd : (cpDigests c r.checkpoints).Nodup) :
    releaseBatch c r items = items.map fun it => releaseOne c r (cpFor c r.checkpoints it) it := by
  unfold releaseBatch releaseOne
  apply List.map_congr_left
  intro it _
  apply firstFailure_cps
  intro t ht
  simp only [cpFor, ht, Option.bind_some]
  rw [find_verified_one c _ _ _ fun b h => by have h' := List.find?_some h; exact h']
  exact find_verified c _ _ _ hd

/-- ACCEPT is exactly the payer's twelve checks (`verifyToken`) on the item's state. -/
theorem releaseBatch_spec {c : Crypto} {r : ReleaseRun} {items : List Item} {i : Nat} {it : Item}
    (hi : items[i]? = some it) :
    (releaseBatch c r items)[i]? = some none ↔
      verifyToken c (itemState (certsInstalled c r.certs) (verifiedAll c r) r it) it.payment it.token = true := by
  simp only [releaseBatch, List.getElem?_map, hi, Option.map_some, Option.some.injEq]
  exact firstFailure_none

/-- Isolation, items: replacing any other item (a bad token, a forged one, garbage) leaves an item's answer
    unchanged. -/
theorem releaseBatch_isolation {c : Crypto} {r : ReleaseRun} {items : List Item} {i j : Nat} (it : Item)
    (hij : i ≠ j) : (releaseBatch c r (items.set j it))[i]? = (releaseBatch c r items)[i]? := by
  simp [releaseBatch, List.map_set, Ne.symm hij]

/-- Isolation, checkpoints: a checkpoint no item names (bad signature, wrong tenant, extra) changes no
    answer. -/
theorem releaseBatch_cp_isolation {c : Crypto} {r r' : ReleaseRun} {items : List Item}
    (hd : (cpDigests c r.checkpoints).Nodup) (hd' : (cpDigests c r'.checkpoints).Nodup)
    (hs : { r with checkpoints := [] } = { r' with checkpoints := [] })
    (hc : ∀ it ∈ items, cpFor c r.checkpoints it = cpFor c r'.checkpoints it) :
    releaseBatch c r items = releaseBatch c r' items := by
  rw [releaseBatch_eq hd, releaseBatch_eq hd']
  apply List.map_congr_left
  intro it hit
  rw [hc it hit]
  cases r
  cases r'
  simp only [ReleaseRun.mk.injEq, true_and] at hs
  obtain ⟨rfl, rfl, rfl, rfl⟩ := hs
  rfl

/-- Installed certificates came from the frame, each root-signed (what `installCert` checks). -/
private theorem foldl_install_certs (c : Crypto) :
    ∀ (es : List EpochCert) (s : PayerState) (e : EpochCert),
      e ∈ (es.foldl (fun s e => (installCert c s e).1) s).certs → e ∈ s.certs ∨ (e ∈ es ∧ c.rootSigned e = true)
  | [], _, _, h => Or.inl h
  | a :: es, s, e, h => by
    rcases foldl_install_certs c es _ e h with h | h
    · rw [installCert_certs] at h
      split at h
      · rename_i ha
        rcases List.mem_cons.1 h with rfl | h
        · simp only [Bool.and_eq_true] at ha
          exact Or.inr ⟨List.mem_cons_self, ha.1⟩
        · exact Or.inl h
      · exact Or.inl h
    · exact Or.inr ⟨List.mem_cons_of_mem _ h.1, h.2⟩

private theorem certsInstalled_rootSigned {c : Crypto} {certs : List Bytes} {e : EpochCert}
    (h : e ∈ (certsInstalled c certs).certs) :
    c.rootSigned e = true ∧ ∃ b ∈ certs, decodeKeyCert b = some e := by
  rcases foldl_install_certs c _ _ e h with h | ⟨hm, hr⟩
  · simp [emptyState] at h
  · exact ⟨hr, List.mem_filterMap.1 hm⟩

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
  have hv := (releaseBatch_spec hi).1 ha
  unfold verifyToken at hv
  cases ht : decodeToken it.token with
  | none => simp [ht] at hv
  | some t =>
    simp only [ht] at hv
    cases hbt : batchOf (itemState (certsInstalled c r.certs) (verifiedAll c r) r it) t with
    | none => simp [hbt] at hv
    | some st =>
      have hf : (verifiedAll c r).find? (·.digest == t.checkpointDigest) = some st := hbt
      have hst := List.mem_of_find?_eq_some hf
      have hdig : st.digest = t.checkpointDigest := by
        have h := List.find?_some hf
        simpa using h
      obtain ⟨b, hb, hvb⟩ := List.mem_filterMap.1 hst
      rw [verified_eq] at hvb
      cases hx : decodeCheckpoint b with
      | none => simp [hx] at hvb
      | some x =>
        simp only [hx, Option.bind_some] at hvb
        split at hvb
        · rename_i hany
          simp only [Option.some.injEq] at hvb
          subst hvb
          obtain ⟨e, he, hm⟩ := List.any_eq_true.1 hany
          simp only [Bool.and_eq_true, beq_iff_eq] at hm
          obtain ⟨hrs, hcb⟩ := certsInstalled_rootSigned he
          exact ⟨t, b, x, e, rfl, hb, hx, hdig, hcb, by simp [Crypto.certChainOk, hrs, hm.2.1], hm.1.1,
            hm.1.2, hm.2.2⟩
        · simp at hvb

private theorem zip_map_self {α β : Type} (f : α → β) :
    ∀ l : List α, l.zip (l.map f) = l.map fun a => (a, f a)
  | [] => rfl
  | a :: l => by simp [zip_map_self f l]

/-- At most once: in an ordered frame of one tenant and program, the accepted items' payment keys are
    distinct, and an item the payer already released never accepts (check 10, or check 6 first). -/
theorem releaseBatch_once {c : Crypto} {r : ReleaseRun} {items : List Item} {tenant program : Bytes}
    (ho : frameOrdered c r.checkpoints items = true)
    (ht : ∀ it ∈ items, it.payment.tenantId = tenant ∧ it.payment.programId = program) :
    (((items.zip (releaseBatch c r items)).filter (·.2.isNone)).map (·.1.payment.key)).Nodup ∧
      ∀ p ∈ items.zip (releaseBatch c r items), p.1.released = true → p.2.isSome = true := by
  have hids := (frameOrdered_nodup ho).2
  have hkeys : (items.map (·.payment.key)).Nodup :=
    nodup_of_map (fun k : PayKey => k.2.2) (by rw [List.map_map]; exact hids)
  unfold releaseBatch
  rw [zip_map_self]
  refine ⟨?_, ?_⟩
  · rw [List.filter_map, List.map_map]
    exact hkeys.sublist ((List.filter_sublist).map _)
  · intro p hp hrel
    obtain ⟨it, -, rfl⟩ := List.mem_map.1 hp
    dsimp only at hrel ⊢
    cases hff : firstFailure c (itemState (certsInstalled c r.certs) (verifiedAll c r) r it) it.payment
        it.token with
    | some f => rfl
    | none =>
      exfalso
      have hv := firstFailure_none.1 hff
      unfold verifyToken at hv
      cases htk : decodeToken it.token with
      | none => simp [htk] at hv
      | some t =>
        simp only [htk] at hv
        cases hbt : batchOf (itemState (certsInstalled c r.certs) (verifiedAll c r) r it) t with
        | none => simp [hbt] at hv
        | some st =>
          simp only [hbt, Bool.and_eq_true] at hv
          have hpm := hv.1.1.1.1.1.1.2
          have hun := hv.1.1.2
          simp only [paymentMatches, Bool.and_eq_true, beq_iff_eq] at hpm
          obtain ⟨⟨⟨⟨⟨⟨⟨⟨h1, h2⟩, -⟩, h3⟩, -⟩, -⟩, -⟩, -⟩, -⟩ := hpm
          simp [unreleased, itemState, hrel, payKey, Payment.key, h1, h2, h3] at hun

end BlindLedger.Gate
