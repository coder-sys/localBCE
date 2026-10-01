import BlindLedger.Gate.Verify
import BlindLedger.Gate.Theorems
import BlindLedger.Gate.MlDsa87Laws

/-! ML-DSA-87 non-bypass and totality: the fixed theorem STATEMENTS of lean-expansion-plan item 11
    (design: C:\Users\neers\rrb\designs\mldsa-theorems-v1.md).  Proved: the non-bypass group, useHint_lt, verify_true_checks, sig_canonical;
    rejNtt_stable and sampleInBall_stable modulo `sponge_prefix`.
    Still `sorry`: sponge_prefix, invNtt_ntt, invNtt_pointwise.
    This file is outside `lean/`, so no executable, library target, TCB report or pin manifest sees it.
    Check: from `lean/`, `lake build BlindLedger.Gate.Theorems BlindLedger.Gate.Verify`, then
    `lake env lean ../tools/mldsa87_goals.lean`.  A prover moves each statement, unchanged, into
    `lean/BlindLedger/Gate/` with its proof and an axiom pin, and deletes it here. -/

namespace BlindLedger.Gate

/-! Parser lemmas for the non-bypass group (`P := StateT Bytes Option`). -/

theorem P.bind_eq {α β : Type} {p : P α} {f : α → P β} {b : Bytes} {y : β} {r : Bytes} :
    (p >>= f) b = some (y, r) ↔ ∃ x m, p b = some (x, m) ∧ f x m = some (y, r) := by
  simp [bind, StateT.bind, Option.bind_eq_some_iff]

theorem P.pure_eq {α : Type} {x y : α} {b r : Bytes} : (pure x : P α) b = some (y, r) ↔ x = y ∧ b = r := by
  simp [pure, StateT.pure]

theorem take_eq {n : Nat} {b r rest : Bytes} :
    take n b = some (r, rest) ↔ n ≤ b.length ∧ r = b.take n ∧ rest = b.drop n := by
  unfold take
  by_cases hn : n ≤ b.length
  · simp only [hn, if_true, Option.some.injEq, Prod.mk.injEq, true_and]
    constructor <;> rintro ⟨h1, h2⟩ <;> exact ⟨h1.symm, h2.symm⟩
  · simp [hn]

theorem need_eq {ok : Bool} {b r : Bytes} {u : Unit} : need ok b = some (u, r) ↔ ok = true ∧ r = b := by
  unfold need
  cases ok <;> simp [eq_comm]

theorem natBE2 {bs : Bytes} (h : bs.length = 2) : natBE 2 (beNat bs) = bs := by
  match bs, h with
  | [a, b], _ =>
    have := a.toNat_lt; have := b.toNat_lt
    have h1 : (a.toNat * 256 + b.toNat) / 256 % 256 = a.toNat := by omega
    have h2 : (a.toNat * 256 + b.toNat) % 256 = b.toNat := by omega
    have e : List.range 2 = [0, 1] := rfl
    simp [natBE, beNat, e, h1, h2]

theorem beNat4 {bs : Bytes} (h : bs.length = 4) : beNat bs < 2 ^ 32 := by
  match bs, h with
  | [a, b, c, d], _ =>
    have := a.toNat_lt; have := b.toNat_lt; have := c.toNat_lt; have := d.toNat_lt
    simp [beNat]; omega

theorem nat_eq {w lo hi : Nat} {b : Bytes} {v : Nat} {r : Bytes} (h : nat w lo hi b = some (v, r)) :
    w ≤ b.length ∧ v = beNat (b.take w) ∧ lo ≤ v ∧ v ≤ hi ∧ r = b.drop w := by
  unfold nat at h
  obtain ⟨bs, m, h1, h2⟩ := P.bind_eq.1 h
  obtain ⟨hl, rfl, rfl⟩ := take_eq.1 h1
  obtain ⟨u, m', h3, h4⟩ := P.bind_eq.1 h2
  obtain ⟨ho, rfl⟩ := need_eq.1 h3
  obtain ⟨rfl, rfl⟩ := P.pure_eq.1 h4
  simp only [Bool.and_eq_true, decide_eq_true_eq] at ho
  exact ⟨hl, rfl, ho.1, ho.2, rfl⟩

theorem consumed_eq {α : Type} {p : P α} {b : Bytes} {v : α × Bytes} {rest : Bytes}
    (h : consumed p b = some (v, rest)) :
    ∃ x, p b = some (x, rest) ∧ v = (x, b.take (b.length - rest.length)) := by
  cases hp : p.run b with
  | none => simp [consumed, hp] at h
  | some r =>
    obtain ⟨x, m⟩ := r
    simp only [consumed, hp] at h
    cases h
    exact ⟨x, hp, rfl⟩

theorem parse_eq {α : Type} {p : P α} {lim : Nat} {b : Bytes} {x : α} (h : parse p lim b = some x) :
    p b = some (x, []) ∧ b.length ≤ lim := by
  unfold parse at h
  split at h
  · simp at h
  · rename_i hl
    split at h
    · rename_i y hr
      cases h
      exact ⟨hr, by omega⟩
    · simp at h

/-- The parser only ever advances: what is left is a suffix of the input. -/
def Adv {α : Type} (p : P α) : Prop := ∀ b x rest, p b = some (x, rest) → rest <:+ b

theorem Adv.bind {α β : Type} {p : P α} {f : α → P β} (hp : Adv p) (hf : ∀ x, Adv (f x)) :
    Adv (p >>= f) := by
  intro b y r h
  obtain ⟨x, m, h1, h2⟩ := P.bind_eq.1 h
  exact (hf x m y r h2).trans (hp b x m h1)

theorem adv_take (n : Nat) : Adv (take n) := fun b _ _ h => by
  obtain ⟨-, -, rfl⟩ := take_eq.1 h
  exact ⟨b.take n, List.take_append_drop n b⟩

theorem adv_pure {α : Type} (x : α) : Adv (pure x : P α) := fun _ _ _ h => by
  obtain ⟨-, rfl⟩ := P.pure_eq.1 h
  exact List.suffix_refl _

theorem adv_need (ok : Bool) : Adv (need ok) := fun _ _ _ h => by
  obtain ⟨-, rfl⟩ := need_eq.1 h
  exact List.suffix_refl _

theorem adv_nat (w lo hi : Nat) : Adv (nat w lo hi) := by
  unfold nat
  exact Adv.bind (adv_take w) fun _ => Adv.bind (adv_need _) fun _ => adv_pure _

theorem adv_expect (d : Bytes) : Adv (expect d) := by
  unfold expect
  exact Adv.bind (adv_take _) fun _ => adv_need _

theorem adv_blob (lo hi : Nat) : Adv (blob lo hi) := by
  unfold blob
  exact Adv.bind (adv_nat _ _ _) fun _ => adv_take _

theorem adv_ident : Adv ident := by
  unfold ident
  exact Adv.bind (adv_blob _ _) fun _ => Adv.bind (adv_need _) fun _ => adv_pure _

theorem adv_pCheckpoint : Adv pCheckpoint := by
  unfold pCheckpoint
  repeat' first
    | exact adv_expect _ | exact adv_nat _ _ _ | exact adv_ident | exact adv_take _
    | exact adv_need _ | exact adv_pure _ | refine Adv.bind ?_ fun _ => ?_

/-- A length-4627 blob: the length as u16 BE, then the bytes. -/
theorem blob_sig {b x rest : Bytes} (h : blob mlDsa87Signature mlDsa87Signature b = some (x, rest)) :
    b = natBE 2 mlDsa87Signature ++ x ++ rest ∧ x.length = mlDsa87Signature := by
  unfold blob at h
  obtain ⟨n, m, h1, h2⟩ := P.bind_eq.1 h
  obtain ⟨hl, hn, hlo, hhi, rfl⟩ := nat_eq h1
  obtain ⟨hl2, rfl, rfl⟩ := take_eq.1 h2
  have hn' : n = mlDsa87Signature := by omega
  subst hn'
  have hlen : (b.take 2).length = 2 := by rw [List.length_take]; omega
  have h3 := natBE2 hlen
  rw [← hn] at h3
  refine ⟨?_, ?_⟩
  · rw [h3, List.append_assoc, List.take_append_drop, List.take_append_drop]
  · rw [List.length_take]; omega

theorem keycert_spec {b : Bytes} {e : EpochCert} (h : decodeKeyCert b = some e) :
    e.signed = b ∧ 0 < e.shardCount ∧ e.shardCount < 2 ^ 32 ∧ e.publicKey.length = mlDsa87Key ∧ ∃ body sig,
      b = body ++ natBE 2 mlDsa87Signature ++ sig ∧ sig.length = mlDsa87Signature ∧ e.publicKey <:+ body := by
  obtain ⟨hr, -⟩ := parse_eq h
  unfold pKeyCert at hr
  obtain ⟨⟨⟨ep, tn, sc, pk⟩, sg⟩, m, h1, h2⟩ := P.bind_eq.1 hr
  obtain ⟨he, rfl⟩ := P.pure_eq.1 h2
  subst he
  obtain ⟨x, hi, hv⟩ := consumed_eq h1
  obtain ⟨hx, hsg⟩ := Prod.mk.inj hv
  subst hx
  obtain ⟨_, m1, g1, hi⟩ := P.bind_eq.1 hi
  obtain ⟨_, m2, g2, hi⟩ := P.bind_eq.1 hi
  obtain ⟨_, m3, g3, hi⟩ := P.bind_eq.1 hi
  obtain ⟨_, m4, g4, hi⟩ := P.bind_eq.1 hi
  obtain ⟨sc0, m5, g5, hi⟩ := P.bind_eq.1 hi
  obtain ⟨pk0, m6, g6, hi⟩ := P.bind_eq.1 hi
  obtain ⟨sg0, m7, g7, hi⟩ := P.bind_eq.1 hi
  obtain ⟨hq, rfl⟩ := P.pure_eq.1 hi
  cases hq
  obtain ⟨hl5, hv5, hlo5, -, -⟩ := nat_eq g5
  obtain ⟨hl6, hpk, hm6⟩ := take_eq.1 g6
  obtain ⟨hb7, hl7⟩ := blob_sig g7
  obtain ⟨pre, hpre⟩ : m5 <:+ b :=
    (adv_nat _ _ _ _ _ _ g5).trans ((adv_nat _ _ _ _ _ _ g4).trans ((adv_ident _ _ _ g3).trans
      ((adv_nat _ _ _ _ _ _ g2).trans (adv_expect _ _ _ _ g1))))
  have hm5 : m5 = pk ++ m6 := by rw [hpk, hm6]; exact (List.take_append_drop _ _).symm
  simp at hsg
  refine ⟨hsg, by show 0 < sc; omega, ?_, ?_, pre ++ pk, sg0, ?_, hl7, ⟨pre, rfl⟩⟩
  · show sc < 2 ^ 32
    rw [hv5]; exact beNat4 (by rw [List.length_take]; omega)
  · show pk.length = mlDsa87Key
    rw [hpk, List.length_take]; omega
  · rw [← hpre, hm5, hb7]; simp

/-- A decoded signed checkpoint is exactly its signed header, the length 4627 as u16 BE, and the signature. -/
theorem decodeCheckpoint_bytes {b : Bytes} {x : SignedCheckpoint} (h : decodeCheckpoint b = some x) :
    b = x.header ++ natBE 2 mlDsa87Signature ++ x.signature ∧ x.signature.length = mlDsa87Signature := by
  obtain ⟨hr, -⟩ := parse_eq h
  unfold pSignedCheckpoint at hr
  obtain ⟨⟨cp, hdr⟩, m, h1, h2⟩ := P.bind_eq.1 hr
  obtain ⟨cp', hp, hv⟩ := consumed_eq h1
  obtain ⟨-, hhdr⟩ := Prod.mk.inj hv
  obtain ⟨sg, m2, h3, h4⟩ := P.bind_eq.1 h2
  obtain ⟨hb, hl⟩ := blob_sig h3
  obtain ⟨rfl, rfl⟩ := P.pure_eq.1 h4
  obtain ⟨pre, hpre⟩ := adv_pCheckpoint _ _ _ hp
  have hh : hdr = pre := by
    rw [hhdr, ← hpre]; simp
  refine ⟨?_, hl⟩
  show b = hdr ++ natBE 2 mlDsa87Signature ++ sg
  rw [hh, ← hpre, hb]
  simp

/-- A decoded KEY-CERT is the whole input: a root-signed body ending in the epoch key, then the root signature. -/
theorem decodeKeyCert_bytes {b : Bytes} {e : EpochCert} (h : decodeKeyCert b = some e) :
    e.signed = b ∧ e.publicKey.length = mlDsa87Key ∧ ∃ body sig,
      b = body ++ natBE 2 mlDsa87Signature ++ sig ∧ sig.length = mlDsa87Signature ∧ e.publicKey <:+ body := by
  obtain ⟨hs, -, -, hpk, body, sig, hb, hsg, hsuf⟩ := keycert_spec h
  exact ⟨hs, hpk, body, sig, hb, hsg, hsuf⟩

/-- On decodable inputs `accepts` is the chain check of the certificate and the checkpoint's signature check. -/
theorem accepts_eq {rootPk cert checkpoint : Bytes} {x : SignedCheckpoint} {e : EpochCert}
    (hx : decodeCheckpoint checkpoint = some x) (he : decodeKeyCert cert = some e) :
    accepts rootPk cert checkpoint = ((realCrypto [(x.checkpoint.tenantId, rootPk)]).certChainOk e &&
      (e.tenantId == x.checkpoint.tenantId && e.epoch == x.checkpoint.epoch &&
        mlDsaOk e.publicKey x.header x.signature)) := by
  obtain ⟨-, h1, h2, -⟩ := keycert_spec he
  have hf : fits emptyState e = true := by simp [fits, emptyState, h1, h2]
  unfold accepts
  simp only [hx, he, installCert]
  cases hc : (realCrypto [(x.checkpoint.tenantId, rootPk)]).certChainOk e
  · simp [hc]
  · simp only [hc, hf, ↓reduceIte]
    simp [storeCheckpoint, hx, blocked, emptyState, realCrypto]
    by_cases hC : (e.tenantId = x.checkpoint.tenantId ∧ e.epoch = x.checkpoint.epoch) ∧
        mlDsaOk e.publicKey x.header x.signature = true
    · rw [if_pos hC]
      simp [hC.1.1, hC.1.2, hC.2]
    · rw [if_neg hC]
      symm
      rw [Bool.eq_false_iff, ne_eq, Bool.and_eq_true, Bool.and_eq_true, beq_iff_eq, beq_iff_eq]
      exact hC

theorem accepts_chain {rootPk cert : Bytes} {x : SignedCheckpoint} {e : EpochCert}
    (he : decodeKeyCert cert = some e) :
    (realCrypto [(x.checkpoint.tenantId, rootPk)]).certChainOk e = true ↔ x.checkpoint.tenantId = e.tenantId ∧
      mlDsaOk rootPk (cert.take (cert.length - 2 - mlDsa87Signature)) (cert.drop (cert.length - mlDsa87Signature)) = true := by
  obtain ⟨hs, -⟩ := keycert_spec he
  simp [realCrypto, hs, he]

/-- gate_verify's whole decision: ACCEPT exactly when both inputs decode, the certificate names the checkpoint's
    tenant and epoch, the root key signed the certificate body and the certified key signed the header. -/
theorem accepts_iff (rootPk cert checkpoint : Bytes) :
    accepts rootPk cert checkpoint = true ↔ ∃ x e, decodeCheckpoint checkpoint = some x ∧
      decodeKeyCert cert = some e ∧ e.tenantId = x.checkpoint.tenantId ∧ e.epoch = x.checkpoint.epoch ∧
      mlDsaOk rootPk (cert.take (cert.length - 2 - mlDsa87Signature)) (cert.drop (cert.length - mlDsa87Signature)) = true ∧
      mlDsaOk e.publicKey x.header x.signature = true := by
  constructor
  · intro h
    cases hx : decodeCheckpoint checkpoint with
    | none => simp [accepts, hx] at h
    | some x =>
      cases he : decodeKeyCert cert with
      | none => simp [accepts, hx, he] at h
      | some e =>
        rw [accepts_eq hx he] at h
        simp only [Bool.and_eq_true, beq_iff_eq] at h
        obtain ⟨hc, ⟨ht, hep⟩, hsig⟩ := h
        exact ⟨x, e, rfl, rfl, ht, hep, ((accepts_chain (rootPk := rootPk) (x := x) he).1 hc).2, hsig⟩
  · rintro ⟨x, e, hx, he, ht, hep, hroot, hsig⟩
    rw [accepts_eq hx he]
    simp only [Bool.and_eq_true, beq_iff_eq]
    exact ⟨(accepts_chain (rootPk := rootPk) (x := x) he).2 ⟨ht.symm, hroot⟩, ⟨ht, hep⟩, hsig⟩

/-- Non-bypass on the raw input bytes: gate_verify accepts only if ML-DSA-87 `verify` returned true for the root key
    on `00 00 ‖ body` and for a key inside that body on `00 00 ‖ header`, where `body` and `header` are the exact
    bytes of the two inputs before their signatures. -/
theorem accepts_nonbypass {rootPk cert checkpoint : Bytes} (h : accepts rootPk cert checkpoint = true) :
    ∃ body certSig pk header sig : Bytes,
      cert = body ++ natBE 2 mlDsa87Signature ++ certSig ∧ checkpoint = header ++ natBE 2 mlDsa87Signature ++ sig ∧
      pk <:+ body ∧ pk.length = mlDsa87Key ∧
      MlDsa87.verify rootPk.toByteArray ([0, 0] ++ body).toByteArray certSig.toByteArray = true ∧
      MlDsa87.verify pk.toByteArray ([0, 0] ++ header).toByteArray sig.toByteArray = true := by
  obtain ⟨x, e, hx, he, -, -, hroot, hsig⟩ := (accepts_iff rootPk cert checkpoint).1 h
  obtain ⟨hcb, -⟩ := decodeCheckpoint_bytes hx
  obtain ⟨-, hpk, body, sig, hcert, hsl, hsuf⟩ := decodeKeyCert_bytes he
  have hl : (natBE 2 mlDsa87Signature).length = 2 := by simp [natBE]
  have hlen : cert.length = body.length + 2 + mlDsa87Signature := by
    rw [hcert, List.length_append, List.length_append, hl, hsl]
  have h1 : cert.take (cert.length - 2 - mlDsa87Signature) = body := by
    rw [show cert.length - 2 - mlDsa87Signature = body.length by omega, hcert]; simp
  have h2 : cert.drop (cert.length - mlDsa87Signature) = sig := by
    rw [show cert.length - mlDsa87Signature = (body ++ natBE 2 mlDsa87Signature).length by
      rw [List.length_append, hl]; omega, hcert]
    exact List.drop_left' rfl
  rw [h1, h2] at hroot
  exact ⟨body, sig, e.publicKey, x.header, x.signature, hcert, hcb, hsuf, hpk, hroot, hsig⟩

/-- Every installed certificate passed its chain check; every stored checkpoint is the decoding of its own bytes,
    filed under the hash of its signed header, and signed by an installed key of its tenant and epoch. -/
def Verified (c : Crypto) (s : PayerState) : Prop :=
  (∀ e ∈ s.certs, c.certChainOk e = true) ∧
    ∀ st ∈ s.checkpoints, ∃ x, decodeCheckpoint st.bytes = some x ∧ st.checkpoint = x.checkpoint ∧
      st.digest = c.hash x.header ∧ ∃ e ∈ s.certs, e.tenantId = x.checkpoint.tenantId ∧
        e.epoch = x.checkpoint.epoch ∧ c.sigOk e.publicKey x.header x.signature = true

theorem Steps.verified {c : Crypto} {s s' : PayerState} (h : Steps c s s') (hs : Verified c s) : Verified c s' := by
  induction h with
  | refl => exact hs
  | tail _ hstep ih =>
    cases hstep with
    | install =>
      rename_i e
      unfold Verified at ih ⊢
      unfold installCert
      split
      · rename_i hc
        refine ⟨fun e' he' => ?_, fun st hst => ?_⟩
        · dsimp only at he'
          split at he'
          · rcases List.mem_cons.1 he' with rfl | he'
            · exact hc
            · exact ih.1 _ he'
          · exact ih.1 _ he'
        · obtain ⟨x, hd, hcp, hdg, e', he', h1, h2, h3⟩ := ih.2 st hst
          refine ⟨x, hd, hcp, hdg, e', ?_, h1, h2, h3⟩
          dsimp only
          split
          · exact List.mem_cons_of_mem _ he'
          · exact he'
      · exact ih
    | store =>
      rename_i b hsc
      unfold storeCheckpoint at hsc
      cases hd : decodeCheckpoint b with
      | none => rw [hd] at hsc; simp at hsc
      | some x =>
        rw [hd] at hsc
        dsimp only at hsc
        split at hsc
        · rename_i hany
          split at hsc
          · obtain rfl := Option.some.inj hsc
            exact ih
          · split at hsc
            · simp at hsc
            · obtain rfl := Option.some.inj hsc
              unfold Verified at ih ⊢
              refine ⟨ih.1, fun y hy => ?_⟩
              rcases List.mem_cons.1 hy with rfl | hy
              · obtain ⟨e, he, hm⟩ := List.any_eq_true.1 hany
                simp only [Bool.and_eq_true, beq_iff_eq] at hm
                exact ⟨x, hd, rfl, rfl, e, he, hm.1.1, hm.1.2, hm.2⟩
              · exact ih.2 y hy
        · simp at hsc
    | send =>
      rename_i p hp
      unfold send at hp
      split at hp
      · cases hp; exact ih
      · split at hp
        · cases hp; exact ih
        · cases hp
    | pay =>
      rename_i p b hp
      unfold release at hp
      split at hp
      · simp at hp
      · split at hp
        · obtain rfl := Option.some.inj hp; exact ih
        · simp at hp
    | context => exact ih

/-- Payer non-bypass for every `Crypto`: a released payment's token names, by the hash of its signed header, a stored
    checkpoint whose signature verified under a chain-checked key of the token's tenant and epoch. -/
theorem release_signed {c : Crypto} {s s' : PayerState} {p : Payment} {bytes : Bytes} (hs : Verified c s)
    (h : release c s p bytes = some s') :
    ∃ t st x e, decodeToken bytes = some t ∧ st ∈ s.checkpoints ∧ decodeCheckpoint st.bytes = some x ∧
      t.checkpointDigest = c.hash x.header ∧ e ∈ s.certs ∧ c.certChainOk e = true ∧
      e.tenantId = t.leaf.tenantId ∧ e.epoch = t.leaf.epoch ∧ c.sigOk e.publicKey x.header x.signature = true := by
  unfold release at h
  cases hd : decodeToken bytes with
  | none => rw [hd] at h; simp at h
  | some t =>
    rw [hd] at h
    dsimp only at h
    split at h
    · rename_i hv
      obtain ⟨t', st, hd', hb, hin, -⟩ := (verifyToken_iff c s p bytes).1 hv
      obtain rfl : t' = t := Option.some.inj (hd'.symm.trans hd)
      have hst := List.mem_of_find?_eq_some hb
      have hdg : st.digest = t'.checkpointDigest := by simpa using List.find?_some hb
      obtain ⟨hc, hk⟩ := hs
      obtain ⟨x, hx, hcp, hdig, e, he, ht, hep, hsig⟩ := hk st hst
      simp only [inBatch, Bool.and_eq_true, beq_iff_eq] at hin
      refine ⟨t', st, x, e, rfl, hst, hx, hdg.symm.trans hdig, he, hc e he, ?_, ?_, hsig⟩
      · rw [ht, ← hcp]; exact hin.1.1.1.1.1
      · rw [hep, ← hcp]; exact hin.1.1.2
    · simp at h

end BlindLedger.Gate

namespace BlindLedger.Keccak

/-- A shorter squeeze is a prefix of a longer one (FIPS 202's SHAKE is an extendable-output function). -/
theorem sponge_prefix (rate : Nat) (suffix : UInt8) (data : ByteArray) {m n : Nat} (h : m ≤ n) :
    (sponge rate suffix data n).extract 0 m = sponge rate suffix data m := by
  sorry

end BlindLedger.Keccak

namespace BlindLedger.Gate.MlDsa87

open BlindLedger.Keccak

section


theorem foldOr_testBit (f : Nat → Nat) (hf : ∀ i, f i ≤ 1) (w t : Nat) :
    ((List.range w).foldl (fun a i => a ||| (f i <<< i)) 0).testBit t = (decide (t < w) && decide (f t = 1)) := by
  induction w with
  | zero => simp
  | succ n ih =>
    rw [List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil, Nat.testBit_or, ih,
      Nat.testBit_shiftLeft]
    have h1 := hf n
    rcases Nat.lt_trichotomy t n with h | h | h
    · simp [h, show t < n + 1 by omega, show ¬ n ≤ t by omega]
    · subst h
      rcases Nat.le_one_iff_eq_zero_or_eq_one.1 h1 with h0 | h0 <;> simp [h0, Nat.testBit_zero]
    · have h2 : (f n).testBit (t - n) = false := by
        rcases Nat.le_one_iff_eq_zero_or_eq_one.1 h1 with h0 | h0 <;> rw [h0]
        · simp
        · exact Bool.eq_false_iff.2 fun hc => by have := Nat.testBit_one_eq_true_iff_self_eq_zero.1 hc; omega
      simp [h2, show ¬ t < n + 1 by omega, show ¬ t < n by omega]

theorem unpack_bit {b b' : ByteArray} {off : Nat} (h : unpack b off 20 = unpack b' off 20) {p : Nat} (hp : p < 5120) :
    bitAt b (8 * off + p) = bitAt b' (8 * off + p) := by
  have h1 := congrArg (fun a : Array Nat => a[p / 20]?) h
  have hj : p / 20 < 256 := by omega
  simp [unpack, hj] at h1
  have h2 := congrArg (fun n => n.testBit (p % 20)) h1
  have hb : ∀ c : ByteArray, ∀ i, bitAt c i ≤ 1 := fun c i => Nat.and_le_right
  simp only [foldOr_testBit _ (fun i => hb b _) , foldOr_testBit _ (fun i => hb b' _)] at h2
  have e : 8 * off + p / 20 * 20 + p % 20 = 8 * off + p := by omega
  simp only [e, show p % 20 < 20 by omega, decide_true, Bool.true_and, decide_eq_decide] at h2
  have := hb b (8 * off + p); have := hb b' (8 * off + p)
  omega

theorem byte_ext {x y : UInt8} (h : ∀ c < 8, (x.toNat >>> c) &&& 1 = (y.toNat >>> c) &&& 1) : x = y := by
  have hx := x.toNat_lt; have hy := y.toNat_lt
  apply UInt8.toNat_inj.1
  apply Nat.eq_of_testBit_eq
  intro i
  by_cases hi : i < 8
  · have := h i hi
    show ((1 &&& (x.toNat >>> i)) != 0) = ((1 &&& (y.toNat >>> i)) != 0)
    rw [Nat.and_comm 1, Nat.and_comm 1, this]
  · have h8 : 256 ≤ 2 ^ i := calc 256 = 2 ^ 8 := rfl
      _ ≤ 2 ^ i := Nat.pow_le_pow_right (by omega) (by omega)
    rw [Nat.testBit_lt_two_pow (by omega), Nat.testBit_lt_two_pow (by omega)]

theorem bytes_eq_of_bits {b b' : ByteArray} {n : Nat} (h : ∀ c < 8, bitAt b (8 * n + c) = bitAt b' (8 * n + c)) :
    b.get! n = b'.get! n :=
  byte_ext fun c hc => by
    have := h c hc
    unfold bitAt at this
    rwa [show (8 * n + c) / 8 = n by omega, show (8 * n + c) % 8 = c by omega] at this

theorem get!_extract {b : ByteArray} {s e n : Nat} (h : n < e - s) (he : e ≤ b.size) :
    (b.extract s e).get! n = b.get! (s + n) := by
  have h1 : n < (b.extract s e).size := by rw [ByteArray.size_extract]; omega
  have h2 : s + n < b.size := by omega
  show (b.extract s e).data[n]! = b.data[s + n]!
  rw [getElem!_pos (b.extract s e).data n (by simpa using h1), getElem!_pos b.data (s + n) (by simpa using h2)]
  exact ByteArray.getElem_extract h1


theorem smono {b : Nat → Nat} {p q : Nat} (h : ∀ t, p < t → t < q → b (t - 1) < b t) :
    ∀ u t, p ≤ u → u < t → t < q → b u < b t := by
  intro u t hu hut htq
  induction t with
  | zero => omega
  | succ t ih =>
    have h1 := h (t + 1) (by omega) htq
    rw [Nat.add_sub_cancel] at h1
    by_cases hc : u < t
    · have := ih hc (by omega)
      omega
    · obtain rfl : u = t := by omega
      exact h1

theorem seg_ext {b b' : Nat → Nat} : ∀ (n n' p : Nat),
    (∀ t, p < t → t < p + n → b (t - 1) < b t) → (∀ t, p < t → t < p + n' → b' (t - 1) < b' t) →
    (∀ v, (∃ t, p ≤ t ∧ t < p + n ∧ b t = v) ↔ (∃ t, p ≤ t ∧ t < p + n' ∧ b' t = v)) →
    n = n' ∧ ∀ t, p ≤ t → t < p + n → b t = b' t := by
  intro n
  induction n with
  | zero =>
    intro n' p _ _ hs
    cases n' with
    | zero => exact ⟨rfl, fun t h1 h2 => by omega⟩
    | succ n' =>
      obtain ⟨t, h1, h2, h3⟩ := (hs (b' p)).2 ⟨p, Nat.le_refl _, by omega, rfl⟩
      omega
  | succ n ih =>
    intro n' p hb hb' hs
    obtain ⟨t', ht1, ht2, ht3⟩ := (hs (b p)).1 ⟨p, Nat.le_refl _, by omega, rfl⟩
    obtain ⟨t, hu1, hu2, hu3⟩ := (hs (b' p)).2 ⟨p, Nat.le_refl _, by omega, rfl⟩
    have hbp : b p ≤ b t := by
      rcases Nat.eq_or_lt_of_le hu1 with e | e
      · rw [← e]; exact Nat.le_refl _
      · exact Nat.le_of_lt (smono hb p t (Nat.le_refl _) e hu2)
    have hbp' : b' p ≤ b' t' := by
      rcases Nat.eq_or_lt_of_le ht1 with e | e
      · rw [← e]; exact Nat.le_refl _
      · exact Nat.le_of_lt (smono hb' p t' (Nat.le_refl _) e ht2)
    have hpp : b p = b' p := by omega
    obtain ⟨n'', rfl⟩ : ∃ n'', n' = n'' + 1 := ⟨n' - 1, by omega⟩
    have key := ih n'' (p + 1) (fun t h1 h2 => hb t (by omega) (by omega)) (fun t h1 h2 => hb' t (by omega) (by omega))
      (fun v => by
        constructor
        · rintro ⟨t, h1, h2, h3⟩
          obtain ⟨t2, g1, g2, g3⟩ := (hs v).1 ⟨t, by omega, by omega, h3⟩
          by_cases e : t2 = p
          · rw [e] at g3
            have := smono hb p t (Nat.le_refl _) (by omega) (by omega)
            omega
          · exact ⟨t2, by omega, by omega, g3⟩
        · rintro ⟨t, h1, h2, h3⟩
          obtain ⟨t2, g1, g2, g3⟩ := (hs v).2 ⟨t, by omega, by omega, h3⟩
          by_cases e : t2 = p
          · rw [e] at g3
            have := smono hb' p t (Nat.le_refl _) (by omega) (by omega)
            omega
          · exact ⟨t2, by omega, by omega, g3⟩)
    refine ⟨by have := key.1; omega, fun t h1 h2 => ?_⟩
    by_cases ht : t = p
    · rw [ht]; exact hpp
    · exact key.2 t (by omega) (by omega)

open Classical

private def hiIn (y : ByteArray) (i first t : Nat) (s : Option (Option (Array Poly)) × Array Poly) :
    Id (ForInStep (Option (Option (Array Poly)) × Array Poly)) :=
  if (decide (t > first) && decide ((y.get! (t - 1)).toNat ≥ (y.get! t).toNat)) = true then
    pure (ForInStep.done (some none, s.2))
  else pure (ForInStep.yield (none, s.2.modify i fun x => x.set! (y.get! t).toNat 1))

private def hiOut (y : ByteArray) (i : Nat) (s : Option (Option (Array Poly)) × Array Poly × Nat) :
    Id (ForInStep (Option (Option (Array Poly)) × Array Poly × Nat)) :=
  if (decide ((y.get! (omega + i)).toNat < s.2.2) || decide ((y.get! (omega + i)).toNat > omega)) = true then
    pure (ForInStep.done (some none, s.2.1, s.2.2))
  else do
    let s1 ← forIn (List.range' s.2.2 ((y.get! (omega + i)).toNat - s.2.2) 1) (none, s.2.1) (hiIn y i s.2.2)
    Break.runK s1.1 (fun _ => pure (ForInStep.yield (none, s1.2, (y.get! (omega + i)).toNat)))
      (fun r => pure (ForInStep.done (some r, s1.2, s.2.2)))

private def hiPad (y : ByteArray) (i : Nat) (_ : Option (Option (Array Poly)) × Unit) :
    Id (ForInStep (Option (Option (Array Poly)) × Unit)) :=
  if y.get! i ≠ 0 then pure (ForInStep.done (some none, ())) else pure (ForInStep.yield (none, ()))

private theorem hint_eq (y : ByteArray) : hintUnpack y =
    (let S := forIn (m := Id) (List.range' 0 k 1)
        ((none : Option (Option (Array Poly))), Array.replicate k (Array.replicate 256 0), 0) (hiOut y)
     Break.runK S.1 (fun _ =>
       let P := forIn (m := Id) (List.range' S.2.2 (omega - S.2.2) 1) ((none : Option (Option (Array Poly))), ()) (hiPad y)
       Break.runK P.1 (fun _ => some S.2.1) (fun r => r)) (fun r => r)) := by
  unfold hintUnpack
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.add_sub_cancel, Nat.sub_zero, Nat.div_one]
  rfl


private def sOf (y : ByteArray) : Nat → Nat
  | 0 => 0
  | j + 1 => (y.get! (omega + j)).toNat

private theorem ite_or {P Q R : Prop} [Decidable P] [Decidable Q] [Decidable R] (h : R ↔ P ∨ Q) :
    (if P then (1 : Nat) else if Q then 1 else 0) = if R then 1 else 0 := by
  by_cases hp : P <;> by_cases hq : Q <;> simp_all

private theorem set!_entry (x : Array Nat) (w v : Nat) (hw : w < x.size) :
    (x.set! w 1)[v]! = if v = w then 1 else x[v]! := by
  by_cases h : v = w
  · subst h
    rw [if_pos rfl]
    simp [Array.set!_eq_setIfInBounds, hw]
  · rw [if_neg h]
    rcases Nat.lt_or_ge v x.size with hv | hv
    · have hv' : v < (x.setIfInBounds w 1).size := by simpa using hv
      rw [Array.set!_eq_setIfInBounds, getElem!_pos (x.setIfInBounds w 1) v hv', getElem!_pos x v hv, Array.getElem_setIfInBounds,
        if_neg (Ne.symm h)]
    · rw [Array.set!_eq_setIfInBounds, getElem!_neg _ _ (by show ¬ v < _; simp only [Array.size_setIfInBounds]; omega),
        getElem!_neg _ _ (by show ¬ v < _; omega)]

private theorem modify_get (acc : Array Poly) (i j : Nat) (hj : j < acc.size) (f : Poly → Poly) :
    (acc.modify i f)[j]! = if j = i then f acc[j]! else acc[j]! := by
  by_cases h : j = i
  · subst h
    simp [hj, Array.getElem_modify]
  · simp [hj, Array.getElem_modify, h, Ne.symm h]

private theorem rep_get (v : Nat) : (Array.replicate 256 (0 : Nat))[v]! = 0 := by
  rcases Nat.lt_or_ge v 256 with hv | hv
  · rw [getElem!_pos _ _ (by simpa using hv)]
    simp
  · rw [getElem!_neg _ _ (by show ¬ v < _; simp only [Array.size_replicate]; omega)]
    rfl

private theorem modify_entry {acc : Array Poly} (i w : Nat) (hs : acc.size = 8)
    (hsz : ∀ j, j < 8 → (acc[j]!).size = 256) (hw : w < 256) :
    (acc.modify i fun x => x.set! w 1).size = 8 ∧
    (∀ j, j < 8 → ((acc.modify i fun x => x.set! w 1)[j]!).size = 256) ∧
    ∀ j, j < 8 → ∀ v, ((acc.modify i fun x => x.set! w 1)[j]!)[v]! = if j = i ∧ v = w then 1 else (acc[j]!)[v]! := by
  have key : ∀ j, j < 8 → (acc.modify i fun x => x.set! w 1)[j]! = if j = i then (acc[j]!).set! w 1 else acc[j]! :=
    fun j hj => modify_get acc i j (by omega) _
  refine ⟨by simp [hs], fun j hj => ?_, fun j hj v => ?_⟩
  · rw [key j hj]
    by_cases e : j = i
    · rw [if_pos e]
      simp [hsz j hj]
    · rw [if_neg e]
      exact hsz j hj
  · rw [key j hj]
    by_cases e : j = i
    · rw [if_pos e, set!_entry _ _ _ (by rw [hsz j hj]; exact hw)]
      by_cases e2 : v = w <;> simp [e, e2]
    · rw [if_neg e, if_neg (fun h => e h.1)]

private theorem hint_inner (y : ByteArray) (i first : Nat) : ∀ (m a : Nat) (acc : Array Poly),
    acc.size = 8 → (∀ j, j < 8 → (acc[j]!).size = 256) → ∀ R,
    forIn (m := Id) (List.range' a m 1) ((none : Option (Option (Array Poly))), acc) (hiIn y i first) = R →
    (R.1 = none ∨ R.1 = some none) ∧ (R.1 = none →
      (∀ t, a ≤ t → t < a + m → first < t → (y.get! (t - 1)).toNat < (y.get! t).toNat) ∧ R.2.size = 8 ∧
      (∀ j, j < 8 → (R.2[j]!).size = 256) ∧
      ∀ j, j < 8 → ∀ v, (R.2[j]!)[v]! =
        if j = i ∧ v < 256 ∧ (∃ t, a ≤ t ∧ t < a + m ∧ (y.get! t).toNat = v) then 1 else (acc[j]!)[v]!) := by
  intro m
  induction m with
  | zero =>
    intro a acc h1 h2 R hR
    have hR' : R = (none, acc) := by rw [← hR]; rfl
    subst hR'
    refine ⟨Or.inl rfl, fun _ => ⟨fun t h1 h2 _ => by omega, h1, h2, fun j hj v => ?_⟩⟩
    rw [if_neg]
    rintro ⟨-, -, t, h3, h4, -⟩
    omega
  | succ m ih =>
    intro a acc h1 h2 R hR
    rw [List.range'_succ] at hR
    by_cases hc : (decide (a > first) && decide ((y.get! (a - 1)).toNat ≥ (y.get! a).toNat)) = true
    · have e : hiIn y i first a (none, acc) = pure (ForInStep.done (some none, acc)) := by
        unfold hiIn; rw [if_pos hc]
      simp only [List.forIn_cons, e, pure_bind] at hR
      subst hR
      exact ⟨Or.inr rfl, fun h => by cases h⟩
    · have e : hiIn y i first a (none, acc) =
          pure (ForInStep.yield (none, acc.modify i fun x => x.set! (y.get! a).toNat 1)) := by
        unfold hiIn; rw [if_neg hc]
      simp only [List.forIn_cons, e, pure_bind] at hR
      have hw : (y.get! a).toNat < 256 := (y.get! a).toNat_lt
      obtain ⟨m1, m2, m3⟩ := modify_entry i _ h1 h2 hw
      obtain ⟨hd, hp⟩ := ih (a + 1) _ m1 m2 R hR
      refine ⟨hd, fun hn => ?_⟩
      obtain ⟨p1, p2, p3, p4⟩ := hp hn
      refine ⟨fun t ht1 ht2 ht3 => ?_, p2, p3, fun j hj v => ?_⟩
      · by_cases hta : t = a
        · subst hta
          simp only [Bool.and_eq_true, decide_eq_true_eq, not_and, ge_iff_le] at hc
          exact Nat.lt_of_not_le (hc ht3)
        · exact p1 t (by omega) (by omega) ht3
      · rw [p4 j hj v, m3 j hj v]
        by_cases hq : j = i ∧ v < 256 ∧ ∃ t, a + 1 ≤ t ∧ t < a + 1 + m ∧ (y.get! t).toNat = v
        · rw [if_pos hq, if_pos]
          obtain ⟨t, h3, h4, h5⟩ := hq.2.2
          exact ⟨hq.1, hq.2.1, t, by omega, by omega, h5⟩
        · rw [if_neg hq]
          by_cases hq2 : j = i ∧ v = (y.get! a).toNat
          · rw [if_pos hq2, if_pos]
            exact ⟨hq2.1, by omega, a, Nat.le_refl _, by omega, hq2.2.symm⟩
          · rw [if_neg hq2, if_neg]
            rintro ⟨g1, g2, t, g3, g4, g5⟩
            by_cases hta : t = a
            · subst hta; exact hq2 ⟨g1, g5.symm⟩
            · exact hq ⟨g1, g2, t, by omega, by omega, g5⟩

private def HInv (y : ByteArray) (i : Nat) (acc : Array Poly) (idx : Nat) : Prop :=
  idx = sOf y i ∧ i ≤ 8 ∧ acc.size = 8 ∧ (∀ j, j < 8 → (acc[j]!).size = 256) ∧
  (∀ j, j < i → sOf y j ≤ sOf y (j + 1) ∧ sOf y (j + 1) ≤ 75 ∧
    ∀ t, sOf y j < t → t < sOf y (j + 1) → (y.get! (t - 1)).toNat < (y.get! t).toNat) ∧
  (∀ j, j < 8 → ∀ v, (acc[j]!)[v]! =
    if j < i ∧ v < 256 ∧ ∃ t, sOf y j ≤ t ∧ t < sOf y (j + 1) ∧ (y.get! t).toNat = v then 1 else 0)

private theorem hint_outer (y : ByteArray) : ∀ (m i : Nat) (acc : Array Poly) (idx : Nat), HInv y i acc idx → i + m ≤ 8 →
    ∀ R, forIn (m := Id) (List.range' i m 1) ((none : Option (Option (Array Poly))), acc, idx) (hiOut y) = R →
    (R.1 = none ∨ R.1 = some none) ∧ (R.1 = none → HInv y (i + m) R.2.1 R.2.2) := by
  intro m
  induction m with
  | zero =>
    intro i acc idx hI _ R hR
    have hR' : R = (none, acc, idx) := by rw [← hR]; rfl
    subst hR'
    exact ⟨Or.inl rfl, fun _ => hI⟩
  | succ m ih =>
    intro i acc idx hI hm R hR
    obtain ⟨i1, i2, i3, i4, i5, i6⟩ := hI
    rw [List.range'_succ] at hR
    by_cases hc : (decide ((y.get! (omega + i)).toNat < idx) || decide ((y.get! (omega + i)).toNat > omega)) = true
    · have e : hiOut y i (none, acc, idx) = pure (ForInStep.done (some none, acc, idx)) := by
        unfold hiOut; rw [if_pos hc]
      simp only [List.forIn_cons, e, pure_bind] at hR
      subst hR
      exact ⟨Or.inr rfl, fun h => by cases h⟩
    · obtain ⟨R1, hR1⟩ : ∃ R1, forIn (m := Id)
          (List.range' idx ((y.get! (omega + i)).toNat - idx) 1) ((none : Option (Option (Array Poly))), acc)
          (hiIn y i idx) = R1 := ⟨_, rfl⟩
      have e : hiOut y i (none, acc, idx) = Break.runK R1.1
          (fun _ => pure (ForInStep.yield (none, R1.2, (y.get! (omega + i)).toNat)))
          (fun r => pure (ForInStep.done (some r, R1.2, idx))) := by
        unfold hiOut; rw [if_neg hc]; dsimp only; rw [hR1]; rfl
      simp only [List.forIn_cons, e] at hR
      simp only [Bool.or_eq_true, decide_eq_true_eq, not_or, Nat.not_lt, gt_iff_lt] at hc
      have hom : omega = 75 := rfl
      obtain ⟨hd, hp⟩ := hint_inner y i idx _ idx acc i3 i4 R1 hR1
      rcases hd with h0 | h0
      · simp only [h0, Break.runK, pure_bind] at hR
        obtain ⟨p1, p2, p3, p4⟩ := hp h0
        have hs1 : sOf y (i + 1) = (y.get! (omega + i)).toNat := rfl
        have hI' : HInv y (i + 1) R1.2 (y.get! (omega + i)).toNat := by
          refine ⟨hs1.symm, by omega, p2, p3, fun j hj => ?_, fun j hj v => ?_⟩
          · by_cases hji : j < i
            · exact i5 j hji
            · have hj2 : j = i := by omega
              rw [hj2]
              exact ⟨by omega, by omega, fun t g1 g2 => p1 t (by omega) (by omega) (by omega)⟩
          · rw [p4 j hj v, i6 j hj v]
            apply ite_or
            constructor
            · rintro ⟨g1, g2, t, g3, g4, g5⟩
              by_cases hji : j < i
              · exact Or.inr ⟨hji, g2, t, g3, g4, g5⟩
              · have hj2 : j = i := by omega
                rw [hj2] at g3 g4
                exact Or.inl ⟨hj2, g2, t, by omega, by omega, g5⟩
            · rintro (⟨g1, g2, t, g3, g4, g5⟩ | ⟨g1, g2, t, g3, g4, g5⟩)
              · rw [g1]
                exact ⟨by omega, g2, t, by omega, by omega, g5⟩
              · exact ⟨by omega, g2, t, g3, g4, g5⟩
        obtain ⟨hd', hp'⟩ := ih (i + 1) R1.2 _ hI' (by omega) R hR
        exact ⟨hd', fun hn => by have := hp' hn; rwa [show i + 1 + m = i + (m + 1) by omega] at this⟩
      · simp only [h0, Break.runK, pure_bind] at hR
        subst hR
        exact ⟨Or.inr rfl, fun h => by cases h⟩

private theorem hint_pad (y : ByteArray) : ∀ (m a : Nat) R,
    forIn (m := Id) (List.range' a m 1) ((none : Option (Option (Array Poly))), ()) (hiPad y) = R →
    (R.1 = none ∨ R.1 = some none) ∧ (R.1 = none → ∀ t, a ≤ t → t < a + m → y.get! t = 0) := by
  intro m
  induction m with
  | zero =>
    intro a R hR
    have hR' : R = (none, ()) := by rw [← hR]; rfl
    subst hR'
    exact ⟨Or.inl rfl, fun _ t h1 h2 => by omega⟩
  | succ m ih =>
    intro a R hR
    rw [List.range'_succ] at hR
    by_cases hc : y.get! a ≠ 0
    · have e : hiPad y a (none, ()) = pure (ForInStep.done (some none, ())) := by
        unfold hiPad; rw [if_pos hc]
      simp only [List.forIn_cons, e, pure_bind] at hR
      subst hR
      exact ⟨Or.inr rfl, fun h => by cases h⟩
    · have e : hiPad y a (none, ()) = pure (ForInStep.yield (none, ())) := by
        unfold hiPad; rw [if_neg hc]
      simp only [List.forIn_cons, e, pure_bind] at hR
      obtain ⟨hd, hp⟩ := ih (a + 1) R hR
      refine ⟨hd, fun hn t h1 h2 => ?_⟩
      by_cases hta : t = a
      · subst hta; exact not_not.1 hc
      · exact hp hn t (by omega) (by omega)

private theorem hint_spec {y : ByteArray} {h : Array Poly} (hy : hintUnpack y = some h) :
    HInv y 8 h (sOf y 8) ∧ ∀ t, sOf y 8 ≤ t → t < 75 → y.get! t = 0 := by
  rw [hint_eq] at hy
  obtain ⟨S, hS⟩ : ∃ S, forIn (m := Id) (List.range' 0 k 1)
      ((none : Option (Option (Array Poly))), Array.replicate k (Array.replicate 256 0), 0) (hiOut y) = S := ⟨_, rfl⟩
  have hI0 : HInv y 0 (Array.replicate k (Array.replicate 256 (0 : Nat))) 0 := by
    refine ⟨rfl, by omega, by simp [k], fun j hj => by simp [k, hj], fun j hj => by omega, fun j hj v => ?_⟩
    have e : (Array.replicate k (Array.replicate 256 (0 : Nat)))[j]! = Array.replicate 256 0 := by
      rw [getElem!_pos _ _ (by simpa [k] using hj)]
      simp
    rw [if_neg (fun h => absurd h.1 (Nat.not_lt_zero _)), e]
    simp [rep_get]
  obtain ⟨hd, hp⟩ := hint_outer y k 0 _ 0 hI0 (by simp [k]) S hS
  dsimp only at hy
  rw [hS] at hy
  rcases hd with h0 | h0
  case inr =>
    simp only [h0, Break.runK] at hy
    cases hy
  case inl =>
    simp only [h0, Break.runK] at hy
    obtain ⟨P, hP⟩ : ∃ P, forIn (m := Id) (List.range' S.2.2 (omega - S.2.2) 1)
        ((none : Option (Option (Array Poly))), ()) (hiPad y) = P := ⟨_, rfl⟩
    rw [hP] at hy
    obtain ⟨hd2, hp2⟩ := hint_pad y _ _ P hP
    rcases hd2 with h2 | h2
    · simp only [h2] at hy
      have hI := hp h0
      obtain rfl : S.2.1 = h := Option.some.inj hy
      have e : sOf y (0 + k) = sOf y 8 := rfl
      have hb := (hI.2.2.2.2.1 7 (by show 7 < 0 + k; decide)).2.1
      have h1 := hI.1
      refine ⟨⟨rfl, hI.2⟩, fun t ht1 ht2 => hp2 h2 t ?_ ?_⟩
      · omega
      · have hom : omega = 75 := rfl
        have e8 : sOf y 8 ≤ 75 := hb
        omega
    · simp only [h2] at hy
      cases hy

private theorem ite_iff {P Q : Prop} [Decidable P] [Decidable Q]
    (h : (if P then (1 : Nat) else 0) = if Q then 1 else 0) : P ↔ Q := by
  by_cases hp : P <;> by_cases hq : Q <;> simp_all

private theorem hint_inj {y y' : ByteArray} {h : Array Poly} (hy : hintUnpack y = some h)
    (hy' : hintUnpack y' = some h) : ∀ t, t < 83 → y.get! t = y'.get! t := by
  obtain ⟨⟨-, -, -, -, hseg, hent⟩, hpad⟩ := hint_spec hy
  obtain ⟨⟨-, -, -, -, hseg', hent'⟩, hpad'⟩ := hint_spec hy'
  have main : ∀ i, i ≤ 8 → sOf y i = sOf y' i ∧ ∀ t, t < sOf y i → (y.get! t).toNat = (y'.get! t).toNat := by
    intro i
    induction i with
    | zero => intro _; exact ⟨rfl, fun t ht => absurd ht (Nat.not_lt_zero _)⟩
    | succ i ih =>
      intro hi
      obtain ⟨e1, e2⟩ := ih (by omega)
      obtain ⟨a1, a2, a3⟩ := hseg i (by omega)
      obtain ⟨b1, b2, b3⟩ := hseg' i (by omega)
      have hs := seg_ext (b := fun t => (y.get! t).toNat) (b' := fun t => (y'.get! t).toNat)
        (sOf y (i + 1) - sOf y i) (sOf y' (i + 1) - sOf y' i) (sOf y i)
        (fun t g1 g2 => a3 t g1 (by omega))
        (fun t g1 g2 => b3 t (by omega) (by omega))
        (fun v => by
          have key := ite_iff ((hent i (by omega) v).symm.trans (hent' i (by omega) v))
          constructor
          · rintro ⟨t, g1, g2, g3⟩
            have hv : v < 256 := by rw [← g3]; exact (y.get! t).toNat_lt
            obtain ⟨-, -, t', g4, g5, g6⟩ := key.1 ⟨by omega, hv, t, g1, by omega, g3⟩
            exact ⟨t', by omega, by omega, g6⟩
          · rintro ⟨t, g1, g2, g3⟩
            have hv : v < 256 := by rw [← g3]; exact (y'.get! t).toNat_lt
            obtain ⟨-, -, t', g4, g5, g6⟩ := key.2 ⟨by omega, hv, t, by omega, by omega, g3⟩
            exact ⟨t', by omega, by omega, g6⟩)
      obtain ⟨hn, hb⟩ := hs
      refine ⟨by omega, fun t ht => ?_⟩
      by_cases ht1 : t < sOf y i
      · exact e2 t ht1
      · exact hb t (by omega) (by omega)
  obtain ⟨m1, m2⟩ := main 8 (Nat.le_refl _)
  intro t ht
  apply UInt8.toNat_inj.1
  by_cases h1 : t < sOf y 8
  · exact m2 t h1
  by_cases h2 : t < 75
  · have g1 := hpad t (by omega) h2
    have g2 := hpad' t (by omega) h2
    rw [g1, g2]
  · obtain ⟨i, hi, rfl⟩ : ∃ i, i < 8 ∧ t = 75 + i := ⟨t - 75, by omega, by omega⟩
    exact (main (i + 1) (by omega)).1

theorem all_of_not_not {X : Bool} (h : ¬ (!X) = true) : X = true := by cases X <;> simp_all
theorem ite_false_true {c : Prop} {i : Decidable c} {b : Bool} (h : (if c then false else b) = true) : ¬c ∧ b = true := by
  by_cases hc : c
  · rw [if_pos hc] at h; exact absurd h Bool.false_ne_true
  · rw [if_neg hc] at h; exact ⟨hc, h⟩


theorem norm_of_all {sig : ByteArray}
    (hn : ¬ (!(((Array.range l).map fun s => unpack sig (64 + 640 * s) 20).all
      (·.all fun x => Int.natAbs ((gamma1 : Int) - x) < gamma1 - beta))) = true) :
    ∀ s < l, ∀ j < 256, Int.natAbs ((gamma1 : Int) - ((unpack sig (64 + 640 * s) 20)[j]! : Nat)) < gamma1 - beta := by
  have hX := all_of_not_not hn
  intro s hs j hj
  have h1 := Array.all_eq_true.1 hX s (by simp [hs])
  simp only [Array.getElem_map, Array.getElem_range] at h1
  have hsz : (unpack sig (64 + 640 * s) 20).size = 256 := by simp [unpack]
  have h2 := Array.all_eq_true.1 h1 j (by omega)
  rw [getElem!_pos _ _ (by omega)]
  exact of_decide_eq_true h2
end
/-- ACCEPT implies every check of FIPS 204 Algorithm 8 before the final hash comparison passed: key and signature
    sizes, a well-formed hint, `‖z‖∞ < γ1 - β`, and both samplers finished within Table 3's XOF bytes. -/
theorem verify_true_checks {pk msg sig : ByteArray} (h : verify pk msg sig = true) :
    pk.size = 2592 ∧ sig.size = 4627 ∧ (hintUnpack (sig.extract (64 + 7 * 640) 4627)).isSome ∧
      (∀ s < l, ∀ j < 256, Int.natAbs ((gamma1 : Int) - ((unpack sig (64 + 640 * s) 20)[j]! : Nat)) < gamma1 - beta) ∧
      (sampleInBall (sig.extract 0 64)).isSome ∧ (expandA (pk.extract 0 32)).isSome := by
  unfold verify at h
  generalize hu : hintUnpack (sig.extract (64 + 7 * 640) 4627) = U at h
  generalize h1 : sampleInBall (sig.extract 0 64) = S at h
  generalize h2 : expandA (pk.extract 0 32) = A at h
  by_cases hsz : (pk.size != 2592 || sig.size != 4627) = true
  · rw [if_pos hsz] at h
    exact absurd h Bool.false_ne_true
  rw [if_neg hsz] at h
  simp only [Bool.or_eq_true, bne_iff_ne, ne_eq, not_or, Decidable.not_not] at hsz
  cases U with
  | none => exact absurd h Bool.false_ne_true
  | some hv =>
    obtain ⟨hn, hb⟩ := ite_false_true h
    cases S with
    | none => exact absurd hb Bool.false_ne_true
    | some c =>
      cases A with
      | none => exact absurd hb Bool.false_ne_true
      | some a => exact ⟨hsz.1, hsz.2, rfl, norm_of_all hn, rfl, rfl⟩

/-- Within Table 3's bound the bounded RejNTTPoly is the standard's unbounded one: every longer SHAKE128 stream
    gives the same polynomial. -/
theorem rejNtt_stable {seed : ByteArray} {a : Poly} (h : rejNtt seed = some a) {n : Nat} (hn : rejNttBytes ≤ n) :
    rejNttFrom (shake128 seed n) = some a := by
  have h1 : (shake128 seed n).extract 0 rejNttBytes = shake128 seed rejNttBytes := sponge_prefix 168 0x1F seed hn
  have h2 : rejNttFrom ((shake128 seed n).extract 0 rejNttBytes) = some a := by rw [h1]; exact h
  have h3 := rejNttFrom_append (t := (shake128 seed n).extract rejNttBytes (shake128 seed n).size) h2
  rwa [ByteArray.extract_append_extract, Nat.zero_min, ByteArray.extract_zero_max_size] at h3

/-- The same for SampleInBall over SHAKE256. -/
theorem sampleInBall_stable {seed : ByteArray} {c : Poly} (h : sampleInBall seed = some c) {n : Nat}
    (hn : sampleInBallBytes ≤ n) : sampleInBallFrom (shake256 seed n) = some c := by
  have h1 : (shake256 seed n).extract 0 sampleInBallBytes = shake256 seed sampleInBallBytes :=
    sponge_prefix 136 0x1F seed hn
  have h2 : sampleInBallFrom ((shake256 seed n).extract 0 sampleInBallBytes) = some c := by rw [h1]; exact h
  have h3 := sampleInBallFrom_append (t := (shake256 seed n).extract sampleInBallBytes (shake256 seed n).size) h2
  rwa [ByteArray.extract_append_extract, Nat.zero_min, ByteArray.extract_zero_max_size] at h3

/-- The signature encoding is canonical (FIPS 204 Algorithms 27 and 21): two 4627-byte signatures with the same c~,
    the same z and the same decoded hint are the same bytes, so no signature byte can change without changing what
    `verify` checks (the non-malleability half of strong unforgeability). -/
theorem sig_canonical {sig sig' : ByteArray} {hint : Array Poly} (hs : sig.size = 4627) (hs' : sig'.size = 4627)
    (hc : sig.extract 0 64 = sig'.extract 0 64)
    (hz : ∀ s < l, unpack sig (64 + 640 * s) 20 = unpack sig' (64 + 640 * s) 20)
    (hh : hintUnpack (sig.extract (64 + 7 * 640) 4627) = some hint)
    (hh' : hintUnpack (sig'.extract (64 + 7 * 640) 4627) = some hint) : sig = sig' := by
  have hk : ∀ n < 4627, sig.get! n = sig'.get! n := by
    intro n hn
    by_cases h1 : n < 64
    · have e := congrArg (fun b : ByteArray => b.get! n) hc
      have g1 := get!_extract (b := sig) (s := 0) (e := 64) (n := n) (by omega) (by omega)
      have g2 := get!_extract (b := sig') (s := 0) (e := 64) (n := n) (by omega) (by omega)
      rw [g1, g2] at e
      simpa using e
    by_cases h2 : n < 64 + 7 * 640
    · obtain ⟨s, hs7⟩ : ∃ s, s = (n - 64) / 640 := ⟨_, rfl⟩
      obtain ⟨r, hr⟩ : ∃ r, r = (n - 64) % 640 := ⟨_, rfl⟩
      apply bytes_eq_of_bits
      intro c hcc
      have := unpack_bit (hz s (by show s < 7; omega)) (p := 8 * r + c) (by omega)
      rwa [show 8 * (64 + 640 * s) + (8 * r + c) = 8 * n + c by omega] at this
    · have e := hint_inj hh hh' (n - (64 + 7 * 640)) (by omega)
      have e2 : 64 + 7 * 640 + (n - (64 + 7 * 640)) = n := by omega
      have g1 := get!_extract (b := sig) (s := 64 + 7 * 640) (e := 4627) (n := n - (64 + 7 * 640)) (by omega) (by omega)
      have g2 := get!_extract (b := sig') (s := 64 + 7 * 640) (e := 4627) (n := n - (64 + 7 * 640)) (by omega) (by omega)
      rw [g1, g2, e2] at e
      exact e
  apply ByteArray.ext
  apply Array.ext (show sig.size = sig'.size by omega)
  intro i h1 h2
  have e : sig.data[i]! = sig'.data[i]! := hk i (by have : i < sig.size := h1; omega)
  rwa [getElem!_pos sig.data i h1, getElem!_pos sig'.data i h2] at e

/-- UseHint (Algorithm 40) gives a 4-bit value on reduced input, so verify's `p[2i] + 16 p[2i+1]` byte packing is
    FIPS 204's w1Encode (Algorithm 28, SimpleBitPack with b = 15) and never wraps. -/
theorem useHint_lt (h : Nat) {r : Nat} (hr : r < q) : useHint h r < 16 := by
  have hq : q = 8380417 := rfl
  have hg : gamma2 = 261888 := rfl
  unfold useHint
  simp only [hq, hg] at hr ⊢
  repeat' split
  all_goals (try simp only [beq_iff_eq] at *)
  all_goals omega

/-- NTT round trip (Algorithms 41 and 42) on reduced polynomials. -/
theorem invNtt_ntt {p : Poly} (hs : p.size = 256) (hq : ∀ x ∈ p, x < q) : invNtt (ntt p) = p := by
  sorry

/-- Schoolbook product in Z_q[X]/(X^256 + 1): the reference that the NTT-domain product must equal. -/
def negacyclic (a b : Poly) : Poly :=
  (Array.range 256).map fun i => (List.range 256).foldl (fun acc j =>
    if j ≤ i then (acc + a[j]! * b[i - j]!) % q else (acc + (q - a[j]! * b[i + 256 - j]! % q)) % q) 0

/-- The pointwise NTT product is the negacyclic product, so verify's `A z - c t1 2^d` is the standard's. -/
theorem invNtt_pointwise {a b : Poly} (ha : a.size = 256) (hb : b.size = 256) :
    invNtt ((Array.range 256).map fun j => (ntt a)[j]! * (ntt b)[j]! % q) = negacyclic a b := by
  sorry

end BlindLedger.Gate.MlDsa87

/-! Axiom pins for the proved theorems (rejNtt_stable and sampleInBall_stable are proved but depend on
    `sponge_prefix`, still `sorry`, so they are not pinned). -/
/-- info: 'BlindLedger.Gate.decodeCheckpoint_bytes' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.decodeCheckpoint_bytes
/-- info: 'BlindLedger.Gate.decodeKeyCert_bytes' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.decodeKeyCert_bytes
/-- info: 'BlindLedger.Gate.accepts_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.accepts_iff
/-- info: 'BlindLedger.Gate.accepts_nonbypass' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.accepts_nonbypass
/-- info: 'BlindLedger.Gate.Steps.verified' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.Steps.verified
/-- info: 'BlindLedger.Gate.release_signed' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.release_signed
/-- info: 'BlindLedger.Gate.MlDsa87.useHint_lt' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.MlDsa87.useHint_lt
/-- info: 'BlindLedger.Gate.MlDsa87.verify_true_checks' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.MlDsa87.verify_true_checks
/-- info: 'BlindLedger.Gate.MlDsa87.sig_canonical' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.MlDsa87.sig_canonical
