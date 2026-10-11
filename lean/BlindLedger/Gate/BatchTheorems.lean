import BlindLedger.Gate.Batch
import BlindLedger.Gate.ProducerTheorems
import BlindLedger.Gate.ApprovalLaws
import BlindLedger.Gate.Theorems
import BlindLedger.Sha3FastEq

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

theorem certsInstalled_mem {c : Crypto} {certs : List Bytes} {e : EpochCert}
    (h : e ∈ (certsInstalled c certs).certs) :
    c.certChainOk e = true ∧ ∃ b ∈ certs, decodeKeyCert b = some e := by
  obtain ⟨h, hc⟩ := List.mem_filter.1 h
  rcases foldl_install_certs c _ _ e h with h | ⟨hm, -⟩
  · simp [emptyState] at h
  · exact ⟨hc, List.mem_filterMap.1 hm⟩

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
          obtain ⟨hco, hcb⟩ := certsInstalled_mem he
          exact ⟨t, b, x, e, rfl, hb, hx, hdig, hcb, hco, hm.1.1, hm.1.2, hm.2.2⟩
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

/-- Check 9 in a batch: an accepted item was approved by a frame grant of its payment's tenant, which is its
    token's tenant, under its token's grant id. -/
theorem releaseBatch_grant_tenant {c : Crypto} {r : ReleaseRun} {items : List Item} {i : Nat} {it : Item}
    (hi : items[i]? = some it) (ha : (releaseBatch c r items)[i]? = some none) :
    ∃ t, decodeToken it.token = some t ∧ ∃ g ∈ r.grants,
      g.tenantId = it.payment.tenantId ∧ g.tenantId = t.leaf.tenantId ∧ g.grantId = t.leaf.grantId := by
  have hv := (releaseBatch_spec hi).1 ha
  obtain ⟨t, hd⟩ : ∃ t, decodeToken it.token = some t := by
    cases hd : decodeToken it.token with
    | none => unfold verifyToken at hv; simp [hd] at hv
    | some t => exact ⟨t, rfl⟩
  obtain ⟨g, hgs, hten, hp, hid, -⟩ := verifyToken_grant_tenant hv hd
  exact ⟨t, hd, g, hgs, hp, hten, hid⟩

/-! ## §B  One-tree PUBLISH -/

private theorem eq_single {hs : List Bytes} (h0 : 0 < hs.length) (h1 : hs.length ≤ 1) : ∃ x, hs = [x] := by
  match hs, h0, h1 with
  | [x], _, _ => exact ⟨x, rfl⟩
  | [], h0, _ => simp at h0
  | _ :: _ :: _, _, h1 => simp only [List.length_cons] at h1; omega

private theorem pathOf_single {H : Bytes → Bytes} {d r : Bytes} (x : Bytes) (g f i : Nat) (hi : i < 1)
    (hr : (levels H d f [x]).getLast? = some [r]) :
    pathRoot H d (g + 1) i 1 ([x].getD i []) (pathOf (levels H d f [x]) i) = some r := by
  have hl : levels H d f [x] = [[x]] := by cases f <;> rfl
  obtain rfl : i = 0 := by omega
  rw [hl] at hr ⊢
  simp at hr
  subst hr
  simp [pathOf, pathRoot]

private theorem levels_ne_nil {H : Bytes → Bytes} {d : Bytes} (f : Nat) (xs : List Bytes) :
    levels H d f xs ≠ [] := by
  unfold levels; split <;> simp

private theorem levels_succ {H : Bytes → Bytes} {d : Bytes} {f : Nat} :
    ∀ {hs : List Bytes}, 2 ≤ hs.length → levels H d (f + 1) hs = hs :: levels H d f (pairUp H d hs)
  | _ :: _ :: _, _ => rfl
  | [], h => absurd h (by simp)
  | [_], h => absurd h (by simp)

private theorem levels_zero {H : Bytes → Bytes} {d : Bytes} :
    ∀ {hs : List Bytes}, 2 ≤ hs.length → levels H d 0 hs = [hs]
  | _ :: _ :: _, _ => rfl
  | [], h => absurd h (by simp)
  | [_], h => absurd h (by simp)

private theorem getLast?_cons_of_ne {a : List Bytes} :
    ∀ {l : List (List Bytes)}, l ≠ [] → (a :: l).getLast? = l.getLast?
  | _ :: _, _ => List.getLast?_cons_cons
  | [], h => absurd rfl h

private theorem pairUp_length {H : Bytes → Bytes} {d : Bytes} :
    ∀ hs : List Bytes, (pairUp H d hs).length = (hs.length + 1) / 2
  | [] => rfl
  | [a] => by simp [show pairUp H d [a] = [a] from rfl]
  | a :: b :: rest => by
    simp only [pairUp, List.length_cons, pairUp_length rest]; omega

private theorem pairUp_getD {H : Bytes → Bytes} {d : Bytes} :
    ∀ (hs : List Bytes) (j : Nat), (pairUp H d hs).getD j [] =
      if 2 * j + 1 < hs.length then nodeHash H d (hs.getD (2 * j) []) (hs.getD (2 * j + 1) [])
      else hs.getD (2 * j) []
  | [], j => by simp [show pairUp H d [] = [] from rfl]
  | [a], 0 => by simp [show pairUp H d [a] = [a] from rfl]
  | [a], j + 1 => by
    rw [show 2 * (j + 1) = 2 * j + 1 + 1 by omega]
    simp [show pairUp H d [a] = [a] from rfl]
  | a :: b :: rest, 0 => by simp [pairUp]
  | a :: b :: rest, j + 1 => by
    rw [show 2 * (j + 1) = 2 * j + 1 + 1 by omega]
    simp only [pairUp, List.getD_cons_succ, List.length_cons, pairUp_getD rest j]
    by_cases hlt : 2 * j + 1 < rest.length
    · rw [if_pos hlt, if_pos (by omega)]
    · rw [if_neg hlt, if_neg (by omega)]

/-- A carried odd last node is its own parent. -/
private theorem carry_node {H : Bytes → Bytes} {d : Bytes} {hs : List Bytes} {i : Nat}
    (hc : i % 2 = 0 ∧ i + 1 = hs.length) : (pairUp H d hs).getD (i / 2) [] = hs.getD i [] := by
  rw [pairUp_getD, if_neg (by omega), show 2 * (i / 2) = i by omega]

/-- A path step with the right sibling lands on the parent node. -/
private theorem step_node {H : Bytes → Bytes} {d : Bytes} {hs : List Bytes} {i : Nat} (hi : i < hs.length)
    (hc : ¬(i % 2 = 0 ∧ i + 1 = hs.length)) :
    H (stepInput d i (hs.getD i []) (hs.getD (if i % 2 == 0 then i + 1 else i - 1) [])) =
      (pairUp H d hs).getD (i / 2) [] := by
  rw [pairUp_getD, if_pos (show 2 * (i / 2) + 1 < hs.length by omega)]
  simp only [nodeHash, stepInput]
  by_cases he : i % 2 = 0
  · have hb2 : (i % 2 == 0) = true := by simp [he]
    simp only [hb2, ↓reduceIte]
    rw [show 2 * (i / 2) = i by omega]
  · have hb2 : ¬(i % 2 == 0) = true := by simpa using he
    simp only [hb2, Bool.false_eq_true, ↓reduceIte]
    rw [show 2 * (i / 2) = i - 1 by omega, show i - 1 + 1 = i by omega]

private theorem pathOf_root {H : Bytes → Bytes} {d r : Bytes} (g : Nat) :
    ∀ (f : Nat) (hs : List Bytes) (i : Nat), i < hs.length → hs.length ≤ 2 ^ g →
      (levels H d f hs).getLast? = some [r] →
      pathRoot H d (g + 1) i hs.length (hs.getD i []) (pathOf (levels H d f hs) i) = some r := by
  induction g with
  | zero =>
    intro f hs i hi hn hr
    obtain ⟨x, rfl⟩ := eq_single (hs := hs) (by omega) (by simpa using hn)
    exact pathOf_single x 0 f i hi hr
  | succ g ih =>
    intro f hs i hi hn hr
    by_cases h1 : hs.length ≤ 1
    · obtain ⟨x, rfl⟩ := eq_single (hs := hs) (by omega) h1
      exact pathOf_single x (g + 1) f i hi hr
    have h2 : 2 ≤ hs.length := by omega
    cases f with
    | zero =>
      simp [levels_zero h2] at hr
      subst hr
      simp at h2
    | succ f =>
      rw [levels_succ h2] at hr ⊢
      have hr' := (getLast?_cons_of_ne (levels_ne_nil f (pairUp H d hs))).symm.trans hr
      have hlen := pairUp_length (H := H) (d := d) hs
      have hm : (hs.length + 1) / 2 ≤ 2 ^ g := by
        rw [Nat.pow_succ] at hn; generalize 2 ^ g = m at hn ⊢; omega
      have hih := ih f (pairUp H d hs) (i / 2) (by rw [hlen]; omega) (by rw [hlen]; exact hm) hr'
      rw [hlen] at hih
      rw [pathRoot.eq_def]
      simp only [pathOf, h1, ↓reduceIte]
      by_cases hc : i % 2 = 0 ∧ i + 1 = hs.length
      · have hb : (i % 2 == 0 && i + 1 == hs.length) = true := by simp [hc]
        simp only [hb, ↓reduceIte]
        rw [carry_node hc] at hih
        exact hih
      · have hb : ¬(i % 2 == 0 && i + 1 == hs.length) = true := by simpa using hc
        simp only [hb, Bool.false_eq_true, ↓reduceIte]
        rw [step_node (H := H) (d := d) hi hc]
        exact hih

/-- The expected path verifies to the tree's root (needs at most 2^16 leaves, which `maxBatch` gives). -/
theorem pathOf_verifies {H : Bytes → Bytes} {d : Bytes} {hs : List Bytes} {i : Nat} {r : Bytes}
    (hi : i < hs.length) (hn : hs.length ≤ maxBatch) (hr : (levels H d treeFuel hs).getLast? = some [r]) :
    pathRoot H d treeFuel i hs.length (hs.getD i []) (pathOf (levels H d treeFuel hs) i) = some r :=
  pathOf_root 16 treeFuel hs i hi (Nat.le_trans hn (by decide)) hr

private theorem pCheckpointFields_count {b rest : Bytes} {cp : Checkpoint}
    (h : pCheckpointFields.run b = some (cp, rest)) : 1 ≤ cp.count ∧ cp.count ≤ maxBatch := by
  simp only [pCheckpointFields, StateT.run_bind] at h
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
  simp only [StateT.run_pure, Option.pure_def, Option.some.injEq, Prod.mk.injEq] at h
  obtain ⟨rfl, -⟩ := h
  exact nat_ok hc

private theorem storedOf_count {b : Bytes} {x : Stored} (h : storedOf sha3 b = some x) :
    1 ≤ x.checkpoint.count ∧ x.checkpoint.count ≤ maxBatch := by
  unfold storedOf at h
  cases hd : decodeCheckpoint b with
  | none => simp [hd] at h
  | some y =>
    simp only [hd, Option.map_some, Option.some.injEq] at h
    subst h
    have hr := parse_run (p := pSignedCheckpoint) hd
    simp only [pSignedCheckpoint, StateT.run_bind] at hr
    obtain ⟨c, hc, hr⟩ := bind_some hr
    obtain ⟨s, -, hr⟩ := bind_some hr
    simp only [StateT.run_pure, Option.pure_def, Option.some.injEq, Prod.mk.injEq] at hr
    obtain ⟨rfl, -⟩ := hr
    have hp := consumed_run hc
    simp only [pCheckpoint, StateT.run_bind] at hp
    obtain ⟨a1, -, hp⟩ := bind_some hp
    obtain ⟨a2, -, hp⟩ := bind_some hp
    exact pCheckpointFields_count hp

private theorem mapM_decode : ∀ {tokens : List Bytes} {ts : List Token}, tokens.mapM decodeToken = some ts →
    tokens.length = ts.length ∧ tokens.filterMap decodeToken = ts ∧
      ∀ (i : Nat) (b : Bytes), tokens[i]? = some b → decodeToken b = ts[i]?
  | [], ts, h => by
    simp at h
    subst h
    simp
  | a :: l, ts, h => by
    cases ha : decodeToken a with
    | none => simp [ha] at h
    | some t =>
      cases hl : l.mapM decodeToken with
      | none => simp [ha, hl] at h
      | some ts' =>
        simp [ha, hl] at h
        subst h
        obtain ⟨h1, h2, h3⟩ := mapM_decode hl
        refine ⟨by simp [h1], by simp [ha, h2], ?_⟩
        intro i b hb
        cases i with
        | zero =>
          simp at hb
          subst hb
          simp [ha]
        | succ i =>
          simp at hb
          simpa using h3 i b hb

/-- Soundness, the only direction safety needs: the one-tree check never publishes what `publishOk`
    refuses, so `publishOk_sound` and `publish_payer_local` carry over unchanged. -/
theorem publishOkTree_sound {rootPk cert new : Bytes} {last : Option Bytes} {tokens : List Bytes}
    (h : publishOkTree rootPk cert last new tokens = true) : publishOk rootPk cert last new tokens = true := by
  unfold publishOkTree at h
  cases he : decodeKeyCert cert with
  | none => simp [he] at h
  | some e =>
    cases hn : storedOf sha3 new with
    | none => simp [he, hn] at h
    | some n =>
      cases hm : tokens.mapM decodeToken with
      | none => simp [he, hn, hm] at h
      | some ts =>
        simp only [he, hn, hm, Bool.and_eq_true, beq_iff_eq] at h
        obtain ⟨⟨⟨⟨⟨⟨hacc, hlast⟩, hfol⟩, hlen⟩, hroot⟩, hall⟩, hasc⟩ := h
        obtain ⟨hl1, hfm, hget⟩ := mapM_decode hm
        have hcnt := storedOf_count hn
        unfold publishOk
        simp only [he, hn, Bool.and_eq_true, beq_iff_eq]
        refine ⟨⟨⟨⟨⟨hacc, hlast⟩, hfol⟩, by rw [hl1]; exact hlen⟩, ?_⟩, by rw [hfm]; exact hasc⟩
        rw [List.all_eq_true]
        rintro ⟨b, i⟩ hbi
        have hi : tokens[i]? = some b := List.mem_zipIdx_iff_getElem?.1 hbi
        obtain ⟨hlt, -⟩ := List.getElem?_eq_some_iff.1 hi
        have hit : i < ts.length := by omega
        have hd : decodeToken b = some ts[i] := by rw [hget i b hi]; exact List.getElem?_eq_getElem hit
        have hmem : (ts[i], i) ∈ ts.zipIdx := List.mem_zipIdx_iff_getElem?.2 (List.getElem?_eq_getElem hit)
        have hft := List.all_eq_true.1 hall _ hmem
        simp only [tokenFitsTree, Bool.and_eq_true, beq_iff_eq] at hft
        obtain ⟨⟨⟨⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, h5⟩, h6⟩, h7⟩, h8⟩ := hft
        have hpv := pathOf_verifies (by simpa using hit) (by rw [List.length_map]; omega) hroot
        have e1 : (ts.map fun t => leafHash sha3 (domain "MERKLE-NODE") t.leafBytes).length =
            n.checkpoint.count := by rw [List.length_map]; omega
        have e2 : (ts.map fun t => leafHash sha3 (domain "MERKLE-NODE") t.leafBytes).getD i [] =
            leafHash sha3 (domain "MERKLE-NODE") ts[i].leafBytes := by
          simp [List.getD_eq_getElem?_getD, hit]
        rw [e1, e2] at hpv
        show tokenFits (realCrypto [(n.checkpoint.tenantId, rootPk)]) e.shardCount n i b = true
        unfold tokenFits
        rw [hd]
        simp only [inBatch, verifyPath, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq]
        refine ⟨⟨⟨h1, h2⟩, ⟨⟨⟨⟨⟨h3, h4⟩, h5⟩, h6⟩, by omega⟩, ?_⟩⟩, h8⟩
        rw [h2, Nat.add_sub_cancel_left, h7]
        exact ⟨by omega, hpv⟩

/-! ### Completeness up to a SHA3 collision -/

theorem sha3_length (x : Bytes) : (sha3 x).length = digestBytes := by
  unfold sha3
  rw [← Semantic.sha3_512_eq]
  exact Semantic.sha3_512_toList_length _

private theorem getD_len {hs : List Bytes} {i : Nat} (h : ∀ x ∈ hs, x.length = digestBytes)
    (hi : i < hs.length) : (hs.getD i []).length = digestBytes := by
  rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hi]
  exact h _ (by simp)

private theorem pairUp_len {H : Bytes → Bytes} {d : Bytes} (hlen : ∀ z, (H z).length = digestBytes) :
    ∀ hs : List Bytes, (∀ x ∈ hs, x.length = digestBytes) → ∀ x ∈ pairUp H d hs, x.length = digestBytes
  | [], h => h
  | [_], h => h
  | a :: b :: rest, h => by
    intro x hx
    simp only [pairUp, List.mem_cons] at hx
    rcases hx with rfl | hx
    · exact hlen _
    · exact pairUp_len hlen rest (fun y hy => h y (by simp [hy])) x hx

/-- `pathCollision`'s pair is drawn from the two folds' hash inputs. -/
private theorem pathCollision_mem {H : Bytes → Bytes} {d : Bytes} (fuel : Nat) :
    ∀ (i n : Nat) (a b : Bytes) (p q : List Bytes) (x y : Bytes),
      pathCollision H d fuel i n a b p q = some (x, y) →
        x ∈ pathInputs H d fuel i n a p ∧ y ∈ pathInputs H d fuel i n b q := by
  induction fuel with
  | zero => intro i n a b p q x y h; simp [pathCollision] at h
  | succ fuel ih =>
    intro i n a b p q x y h
    simp only [pathCollision] at h
    simp only [pathInputs]
    by_cases hn : n ≤ 1
    · rw [if_pos hn] at h
      exact absurd h (by simp)
    simp only [if_neg hn] at h ⊢
    by_cases hc : (i % 2 == 0 && i + 1 == n) = true
    · simp only [if_pos hc] at h ⊢
      exact ih _ _ _ _ _ _ _ _ h
    simp only [if_neg hc] at h ⊢
    cases p with
    | nil => simp at h
    | cons s ps =>
    cases q with
    | nil => simp at h
    | cons t qs =>
    simp only at h ⊢
    by_cases hx : stepInput d i a s ≠ stepInput d i b t ∧
        H (stepInput d i a s) = H (stepInput d i b t)
    · rw [if_pos hx] at h
      obtain ⟨rfl, rfl⟩ := Prod.mk.inj (Option.some.inj h)
      exact ⟨by simp, by simp⟩
    · rw [if_neg hx] at h
      obtain ⟨h1, h2⟩ := ih _ _ _ _ _ _ _ _ h
      exact ⟨List.mem_cons_of_mem _ h1, List.mem_cons_of_mem _ h2⟩

/-- Two equal-length nodes folding to one root at one position are equal, unless two hash inputs of the folds
    collide. -/
private theorem fold_eq {H : Bytes → Bytes} {d : Bytes} (hlen : ∀ z, (H z).length = digestBytes)
    {S : Bytes → Prop} (hS : ∀ x y, S x → S y → H x = H y → x = y) {f k m : Nat} {a b R : Bytes}
    {p q : List Bytes} (hl : a.length = b.length) (ha : pathRoot H d f k m a p = some R)
    (hb : pathRoot H d f k m b q = some R) (hsa : ∀ x ∈ pathInputs H d f k m a p, S x)
    (hsb : ∀ x ∈ pathInputs H d f k m b q, S x) : a = b := by
  refine Classical.byContradiction fun hne => ?_
  cases hc : pathCollision H d f k m a b p q with
  | none => exact pathCollision_complete hlen f k m a b p q R hne hl ha hb hc
  | some xy =>
    obtain ⟨x, y⟩ := xy
    obtain ⟨hxy, hh⟩ := pathCollision_sound f k m a b p q x y hc
    obtain ⟨hx, hy⟩ := pathCollision_mem f k m a b p q x y hc
    exact hxy (hS _ _ (hsa _ hx) (hsb _ hy) hh)

private theorem decodeToken_siblings {b : Bytes} {t : Token} (h : decodeToken b = some t) :
    ∀ s ∈ t.siblings, s.length = digestBytes := by
  have hr := parse_run (p := pToken) h
  obtain ⟨⟨leaf, lb⟩, r1, -, hr⟩ := Approval.bind_run hr
  obtain ⟨k, r2, -, hr⟩ := Approval.bind_run hr
  obtain ⟨sibs, r3, hs, hr⟩ := Approval.bind_run hr
  obtain ⟨cd, r4, -, hr⟩ := Approval.bind_run hr
  obtain ⟨rfl, -⟩ := Approval.pure_run hr
  exact (Approval.many_run (e := id) (Q := fun x : Bytes => x.length = digestBytes)
    (fun hd => Approval.take_run hd) k hs).2.2

private theorem mapM_some : ∀ {l : List Bytes}, (∀ b ∈ l, (decodeToken b).isSome) →
    l.mapM decodeToken = some (l.filterMap decodeToken)
  | [], _ => by simp
  | a :: l, h => by
    obtain ⟨t, ht⟩ := Option.isSome_iff_exists.1 (h a (by simp))
    simp [ht, mapM_some (l := l) fun b hb => h b (List.mem_cons_of_mem _ hb)]

/-- One tree level at a time: if every position of `hs` holds a path (`W`) folding to `R` with no colliding
    hash inputs, the tree of `hs` has root `R` and every such path is the tree's own path. -/
private theorem tree_agrees {H : Bytes → Bytes} {d : Bytes} (hlen : ∀ z, (H z).length = digestBytes)
    {S : Bytes → Prop} (hS : ∀ x y, S x → S y → H x = H y → x = y) {R : Bytes} :
    ∀ (f : Nat) (hs : List Bytes) (W : Nat → List Bytes → Prop), 0 < hs.length →
      (∀ x ∈ hs, x.length = digestBytes) → (∀ j < hs.length, ∃ p, W j p) →
      (∀ i p, W i p → i < hs.length ∧ (∀ s ∈ p, s.length = digestBytes) ∧
        pathRoot H d f i hs.length (hs.getD i []) p = some R ∧
        ∀ x ∈ pathInputs H d f i hs.length (hs.getD i []) p, S x) →
      (levels H d f hs).getLast? = some [R] ∧ ∀ i p, W i p → p = pathOf (levels H d f hs) i := by
  intro f
  induction f with
  | zero =>
    intro hs W h0 _ hcov hW
    obtain ⟨p, hp⟩ := hcov 0 h0
    have hr := (hW 0 p hp).2.2.1
    simp [pathRoot] at hr
  | succ f ih =>
    intro hs W h0 hhs hcov hW
    by_cases h1 : hs.length ≤ 1
    · obtain ⟨x, rfl⟩ := eq_single h0 h1
      have hone : ∀ i p, W i p → p = [] ∧ x = R := by
        intro i p hp
        obtain ⟨hi, -, hr, -⟩ := hW i p hp
        obtain rfl : i = 0 := by simp at hi; omega
        cases p with
        | nil => simpa [pathRoot] using hr
        | cons s rest => simp [pathRoot] at hr
      obtain ⟨p, hp⟩ := hcov 0 (by simp)
      obtain ⟨-, rfl⟩ := hone 0 p hp
      refine ⟨rfl, fun i p hp => ?_⟩
      rw [(hone i p hp).1]
      rfl
    have h2 : 2 ≤ hs.length := by omega
    -- A path not carried here starts with a sibling; its first hash input is in `S`.
    have hstep : ∀ i p, W i p → ¬(i % 2 = 0 ∧ i + 1 = hs.length) → ∃ s rest, p = s :: rest ∧
        pathRoot H d f (i / 2) ((hs.length + 1) / 2) (H (stepInput d i (hs.getD i []) s)) rest = some R ∧
        S (stepInput d i (hs.getD i []) s) ∧
        ∀ x ∈ pathInputs H d f (i / 2) ((hs.length + 1) / 2) (H (stepInput d i (hs.getD i []) s)) rest, S x := by
      intro i p hp hc
      obtain ⟨-, -, hr, hx⟩ := hW i p hp
      have hb : ¬(i % 2 == 0 && i + 1 == hs.length) = true := by simpa using hc
      simp only [pathRoot] at hr
      simp only [pathInputs] at hx
      rw [if_neg h1, if_neg hb] at hr hx
      cases p with
      | nil => simp at hr
      | cons s rest =>
        simp only at hr hx
        exact ⟨s, rest, rfl, hr, hx _ (by simp), fun x h => hx x (List.mem_cons_of_mem _ h)⟩
    -- Its sibling is the partner's node: the partner's path folds to `R` from the same parent position.
    have hpart : ∀ i p, W i p → ¬(i % 2 = 0 ∧ i + 1 = hs.length) → ∃ rest,
        p = hs.getD (if i % 2 == 0 then i + 1 else i - 1) [] :: rest ∧
        pathRoot H d f (i / 2) ((hs.length + 1) / 2) ((pairUp H d hs).getD (i / 2) []) rest = some R ∧
        ∀ x ∈ pathInputs H d f (i / 2) ((hs.length + 1) / 2) ((pairUp H d hs).getD (i / 2) []) rest, S x := by
      intro i p hp hc
      obtain ⟨hi, hsl, -, -⟩ := hW i p hp
      obtain ⟨s, rest, rfl, hr, hsx, hx⟩ := hstep i p hp hc
      suffices hs' : s = hs.getD (if i % 2 == 0 then i + 1 else i - 1) [] by
        subst hs'
        rw [step_node (H := H) (d := d) hi hc] at hr hx
        exact ⟨rest, rfl, hr, hx⟩
      have hsl' : s.length = digestBytes := hsl s (by simp)
      by_cases he : i % 2 = 0
      · obtain ⟨q, hq⟩ := hcov (i + 1) (by omega)
        obtain ⟨t, rest', rfl, hr', htx, hx'⟩ := hstep (i + 1) q hq (by omega)
        have htl : t.length = digestBytes := (hW _ _ hq).2.1 t (by simp)
        rw [show (i + 1) / 2 = i / 2 by omega] at hr' hx'
        have hin := hS _ _ hsx htx (fold_eq hlen hS ((hlen _).trans (hlen _).symm) hr hr' hx hx')
        have hb2 : (i % 2 == 0) = true := by rw [beq_iff_eq]; exact he
        have hb3 : ¬((i + 1) % 2 == 0) = true := by rw [beq_iff_eq]; omega
        unfold stepInput at hin
        rw [if_pos hb2, if_neg hb3] at hin
        rw [if_pos hb2]
        exact (List.append_inj (List.cons.inj (List.append_cancel_left hin)).2
          ((getD_len hhs hi).trans htl.symm)).2
      · obtain ⟨q, hq⟩ := hcov (i - 1) (by omega)
        obtain ⟨t, rest', rfl, hr', htx, hx'⟩ := hstep (i - 1) q hq (by omega)
        rw [show (i - 1) / 2 = i / 2 by omega] at hr' hx'
        have hin := hS _ _ hsx htx (fold_eq hlen hS ((hlen _).trans (hlen _).symm) hr hr' hx hx')
        have hb2 : ¬(i % 2 == 0) = true := by rw [beq_iff_eq]; exact he
        have hb3 : ((i - 1) % 2 == 0) = true := by rw [beq_iff_eq]; omega
        unfold stepInput at hin
        rw [if_neg hb2, if_pos hb3] at hin
        rw [if_neg hb2]
        exact (List.append_inj (List.cons.inj (List.append_cancel_left hin)).2
          (hsl'.trans (getD_len hhs (by omega : i - 1 < hs.length)).symm)).1
    have hlp := pairUp_length (H := H) (d := d) hs
    rw [levels_succ h2, getLast?_cons_of_ne (levels_ne_nil f (pairUp H d hs))]
    obtain ⟨hroot, hpaths⟩ := ih (pairUp H d hs)
      (fun j p' => ∃ i p, W i p ∧ i / 2 = j ∧ p' = if i % 2 = 0 ∧ i + 1 = hs.length then p else p.tail)
      (by rw [hlp]; omega) (pairUp_len hlen hs hhs)
      (fun j hj => by
        rw [hlp] at hj
        obtain ⟨p, hp⟩ := hcov (2 * j) (by omega)
        exact ⟨_, 2 * j, p, hp, by omega, rfl⟩)
      (fun j p' hp' => by
        obtain ⟨i, p, hp, rfl, rfl⟩ := hp'
        obtain ⟨hi, hsl, hr, hx⟩ := hW i p hp
        rw [hlp]
        by_cases hc : i % 2 = 0 ∧ i + 1 = hs.length
        · have hb : (i % 2 == 0 && i + 1 == hs.length) = true := by simp [hc]
          rw [if_pos hc, carry_node hc]
          simp only [pathRoot] at hr
          simp only [pathInputs] at hx
          rw [if_neg h1, if_pos hb] at hr hx
          exact ⟨by omega, hsl, hr, hx⟩
        · rw [if_neg hc]
          obtain ⟨rest, rfl, hr', hx'⟩ := hpart i p hp hc
          exact ⟨by omega, fun s hs' => hsl s (List.mem_cons_of_mem _ hs'), hr', hx'⟩)
    refine ⟨hroot, fun i p hp => ?_⟩
    simp only [pathOf, h1, ↓reduceIte]
    by_cases hc : i % 2 = 0 ∧ i + 1 = hs.length
    · have hb : (i % 2 == 0 && i + 1 == hs.length) = true := by simp [hc]
      simp only [hb, ↓reduceIte]
      exact hpaths (i / 2) p ⟨i, p, hp, rfl, by rw [if_pos hc]⟩
    · have hb : ¬(i % 2 == 0 && i + 1 == hs.length) = true := by simpa using hc
      simp only [hb, Bool.false_eq_true, ↓reduceIte]
      obtain ⟨rest, rfl, -, -⟩ := hpart i p hp hc
      exact congrArg (List.cons _) (hpaths (i / 2) _ ⟨i, _, hp, rfl, by rw [if_neg hc, List.tail_cons]⟩)

/-- Completeness: whatever `publishOk` accepts, the one-tree check accepts too, unless the batch's tokens
    carry a SHA3-512 collision, which `publishCollision` returns. -/
theorem publishOkTree_complete {rootPk cert new : Bytes} {last : Option Bytes} {tokens : List Bytes}
    (h : publishOk rootPk cert last new tokens = true) :
    publishOkTree rootPk cert last new tokens = true ∨
      ∃ x y, publishCollision tokens = some (x, y) ∧ x ≠ y ∧ sha3 x = sha3 y := by
  unfold publishOk at h
  cases he : decodeKeyCert cert with
  | none => simp [he] at h
  | some e =>
  cases hn : storedOf sha3 new with
  | none => simp [he, hn] at h
  | some n =>
  simp only [he, hn, Bool.and_eq_true, beq_iff_eq] at h
  obtain ⟨⟨⟨⟨⟨hacc, hlast⟩, hfol⟩, hlen⟩, hall⟩, hasc⟩ := h
  rw [List.all_eq_true] at hall
  have hdec : ∀ b ∈ tokens, (decodeToken b).isSome := by
    intro b hb
    obtain ⟨i, hi⟩ := List.mem_iff_getElem?.1 hb
    have hf : tokenFits (realCrypto [(n.checkpoint.tenantId, rootPk)]) e.shardCount n i b = true :=
      hall (b, i) (List.mem_zipIdx_iff_getElem?.2 hi)
    unfold tokenFits at hf
    cases hd : decodeToken b with
    | none => simp [hd] at hf
    | some _ => rfl
  obtain ⟨ts, hm⟩ : ∃ ts, tokens.mapM decodeToken = some ts := ⟨_, mapM_some hdec⟩
  obtain ⟨hl1, hfm, hget⟩ := mapM_decode hm
  have hcnt : ts.length = n.checkpoint.count := by omega
  have hc1 := (storedOf_count hn).1
  -- Each decoded token: digest-length siblings, a path folding to the root, and every other check.
  have htok : ∀ t i, (t, i) ∈ ts.zipIdx → (∀ s ∈ t.siblings, s.length = digestBytes) ∧ i < n.checkpoint.count ∧
      pathRoot sha3 (domain "MERKLE-NODE") treeFuel i n.checkpoint.count
        (leafHash sha3 (domain "MERKLE-NODE") t.leafBytes) t.siblings = some n.checkpoint.tokenRoot ∧
      ∀ lv, t.siblings = pathOf lv i →
        tokenFitsTree (realCrypto [(n.checkpoint.tenantId, rootPk)]) e.shardCount n lv i t = true := by
    intro t i hti
    have hit : ts[i]? = some t := List.mem_zipIdx_iff_getElem?.1 hti
    have hlt : i < ts.length := (List.getElem?_eq_some_iff.1 hit).1
    obtain ⟨b, hb⟩ : ∃ b, tokens[i]? = some b := ⟨tokens[i]'(by omega), List.getElem?_eq_getElem (by omega)⟩
    have hd : decodeToken b = some t := by rw [hget i b hb, hit]
    have hf : tokenFits (realCrypto [(n.checkpoint.tenantId, rootPk)]) e.shardCount n i b = true :=
      hall (b, i) (List.mem_zipIdx_iff_getElem?.2 hb)
    unfold tokenFits at hf
    rw [hd] at hf
    simp only [inBatch, verifyPath, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at hf
    obtain ⟨⟨⟨h1, h2⟩, ⟨⟨⟨⟨⟨h3, h4⟩, h5⟩, h6⟩, -⟩, hlt2, hpr⟩⟩, h8⟩ := hf
    rw [h2, Nat.add_sub_cancel_left] at hlt2 hpr
    refine ⟨decodeToken_siblings hd, hlt2, hpr, fun lv hp => ?_⟩
    simp only [tokenFitsTree, Bool.and_eq_true, beq_iff_eq]
    exact ⟨⟨⟨⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, h5⟩, h6⟩, hp⟩, h8⟩
  cases hpc : publishCollision tokens with
  | some xy =>
    right
    obtain ⟨x, y⟩ := xy
    refine ⟨x, y, rfl, ?_⟩
    simp only [publishCollision] at hpc
    simpa using List.find?_some hpc
  | none =>
    left
    simp only [publishCollision, hfm, List.find?_eq_none] at hpc
    have hS : ∀ x y, x ∈ batchInputs ts → y ∈ batchInputs ts → sha3 x = sha3 y → x = y := by
      intro x y hx hy hxy
      refine Classical.byContradiction fun hne =>
        hpc (x, y) (List.mem_flatMap.2 ⟨x, hx, List.mem_map.2 ⟨y, hy, rfl⟩⟩) ?_
      simp [hne, hxy]
    obtain ⟨hroot, hpath⟩ := tree_agrees (H := sha3) (d := domain "MERKLE-NODE") (S := (· ∈ batchInputs ts))
      (R := n.checkpoint.tokenRoot) sha3_length hS treeFuel
      (ts.map fun t => leafHash sha3 (domain "MERKLE-NODE") t.leafBytes)
      (fun i p => ∃ t, (t, i) ∈ ts.zipIdx ∧ p = t.siblings) (by rw [List.length_map]; omega)
      (fun x hx => by
        obtain ⟨t, -, rfl⟩ := List.mem_map.1 hx
        exact sha3_length _)
      (fun j hj => by
        rw [List.length_map] at hj
        exact ⟨ts[j].siblings, ts[j], List.mem_zipIdx_iff_getElem?.2 (List.getElem?_eq_getElem hj), rfl⟩)
      (fun i p hp => by
        obtain ⟨t, hti, rfl⟩ := hp
        obtain ⟨hsib, hlt, hpr, -⟩ := htok t i hti
        have hit : ts[i]? = some t := List.mem_zipIdx_iff_getElem?.1 hti
        have hg : (ts.map fun t => leafHash sha3 (domain "MERKLE-NODE") t.leafBytes).getD i [] =
            leafHash sha3 (domain "MERKLE-NODE") t.leafBytes := by
          simp [List.getD_eq_getElem?_getD, hit]
        rw [List.length_map, hg, hcnt]
        refine ⟨hlt, hsib, hpr, fun x hx => ?_⟩
        exact List.mem_flatMap.2 ⟨(t, i), hti, by rw [hcnt]; exact hx⟩)
    unfold publishOkTree
    simp only [he, hn, hm, Bool.and_eq_true, beq_iff_eq]
    refine ⟨⟨⟨⟨⟨⟨hacc, hlast⟩, hfol⟩, hcnt⟩, hroot⟩, ?_⟩, by rw [← hfm]; exact hasc⟩
    rw [List.all_eq_true]
    rintro ⟨t, i⟩ hti
    exact (htok t i hti).2.2.2 _ (hpath i t.siblings ⟨t, hti, rfl⟩)

end BlindLedger.Gate
