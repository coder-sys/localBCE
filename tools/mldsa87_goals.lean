import BlindLedger.Gate.Verify
import BlindLedger.Gate.Theorems
import BlindLedger.Gate.MlDsa87Laws

/-! ML-DSA-87 non-bypass and totality: the fixed theorem STATEMENTS of lean-expansion-plan item 11
    (design: C:\Users\neers\rrb\designs\mldsa-theorems-v1.md).  Proved: the non-bypass group, useHint_lt; rejNtt_stable and sampleInBall_stable modulo `sponge_prefix`.
    Still `sorry`: sponge_prefix, verify_true_checks, sig_canonical, invNtt_ntt, invNtt_pointwise.
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

/-- ACCEPT implies every check of FIPS 204 Algorithm 8 before the final hash comparison passed: key and signature
    sizes, a well-formed hint, `‖z‖∞ < γ1 - β`, and both samplers finished within Table 3's XOF bytes. -/
theorem verify_true_checks {pk msg sig : ByteArray} (h : verify pk msg sig = true) :
    pk.size = 2592 ∧ sig.size = 4627 ∧ (hintUnpack (sig.extract (64 + 7 * 640) 4627)).isSome ∧
      (∀ s < l, ∀ j < 256, Int.natAbs ((gamma1 : Int) - ((unpack sig (64 + 640 * s) 20)[j]! : Nat)) < gamma1 - beta) ∧
      (sampleInBall (sig.extract 0 64)).isSome ∧ (expandA (pk.extract 0 32)).isSome := by
  sorry

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
  sorry

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
