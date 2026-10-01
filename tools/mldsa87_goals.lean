import Lean
import BlindLedger.Gate.Verify
import BlindLedger.Gate.Theorems
import BlindLedger.Gate.MlDsa87Laws

/-! ML-DSA-87 non-bypass and totality: the fixed theorem STATEMENTS of lean-expansion-plan item 11
    (design: C:\Users\neers\rrb\designs\mldsa-theorems-v1.md).  Proved: the non-bypass group, useHint_lt, verify_true_checks, sig_canonical, sponge_prefix,
    rejNtt_stable, sampleInBall_stable, invNtt_ntt, invNtt_pointwise (layer-wise NTT algebra, then the convolution theorem).
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

namespace BlindLedger.Semantic

/- The sponge is private to `Sha3.lean` (making it public would change the exe symbols); these two commands name it
    through its private name so `sponge_prefix` keeps the statement about the one implementation. -/
open Lean Elab Tactic Meta in
elab "spongeP" : term => return mkConst (mkPrivateNameCore `BlindLedger.Sha3 `BlindLedger.Semantic.sponge)
open Lean Elab Tactic Meta in
elab "unfold_sponge" : tactic => liftMetaTactic fun g => do
  return [← unfoldTarget g (mkPrivateNameCore `BlindLedger.Sha3 `BlindLedger.Semantic.sponge)]

private def rep (K : Array UInt64 → Array UInt64) : Nat → Array UInt64 → Array UInt64
  | 0, s => s
  | b + 1, s => K (rep K b s)

private def fb (K : Array UInt64 → Array UInt64) (rate : Nat) (st : Array UInt64) (g : Nat) : UInt8 :=
  ((rep K (g / rate) st)[g % rate / 8]! >>> UInt64.ofNat (8 * (g % rate % 8))).toUInt8

private def ofF (f : Nat → UInt8) (N : Nat) : ByteArray := ⟨(Array.range N).map f⟩

private def sqIn (n : Nat) (st : Array UInt64) (j : Nat) (out : ByteArray) : Id (ForInStep ByteArray) :=
  if out.size < n then pure (ForInStep.yield (out.push (st[j / 8]! >>> UInt64.ofNat (8 * (j % 8))).toUInt8))
  else pure (ForInStep.yield out)

private def sqOut (K : Array UInt64 → Array UInt64) (rate n blk : Nat) (s : Array UInt64 × ByteArray) :
    Id (ForInStep (Array UInt64 × ByteArray)) :=
  if blk > 0 then do
    let s1 ← forIn (List.range' 0 rate) s.2 (sqIn n (K s.1))
    pure (ForInStep.yield (K s.1, s1))
  else do
    let s1 ← forIn (List.range' 0 rate) s.2 (sqIn n s.1)
    pure (ForInStep.yield (s.1, s1))

private def Fq (K : Array UInt64 → Array UInt64) (rate n : Nat) (st : Array UInt64) : ByteArray :=
  (forIn (m := Id) (List.range' 0 ((n + rate - 1) / rate)) (st, ByteArray.empty) (sqOut K rate n)).2

private theorem ofF_push (f : Nat → UInt8) (N : Nat) : (ofF f N).push (f N) = ofF f (N + 1) := by
  unfold ofF
  simp [Array.range_succ, ByteArray.push]

private theorem ofF_size (f : Nat → UInt8) (N : Nat) : (ofF f N).size = N := by
  show ((Array.range N).map f).size = N
  simp

private theorem sq_inner (n : Nat) (stc : Array UInt64) (f : Nat → UInt8) (c : Nat) :
    ∀ (t a : Nat), (∀ j, a ≤ j → j < a + t → (stc[j / 8]! >>> UInt64.ofNat (8 * (j % 8))).toUInt8 = f (c + j)) →
    forIn (m := Id) (List.range' a t) (ofF f (min n (c + a))) (sqIn n stc) = ofF f (min n (c + a + t)) := by
  intro t
  induction t with
  | zero => intro a _; exact rfl
  | succ t ih =>
    intro a h
    rw [List.range'_succ, List.forIn_cons]
    by_cases hlt : c + a < n
    · have e : sqIn n stc a (ofF f (min n (c + a))) = pure (ForInStep.yield (ofF f (min n (c + a + 1)))) := by
        unfold sqIn
        rw [if_pos (by rw [ofF_size]; omega), h a (Nat.le_refl _) (by omega), Nat.min_eq_right (Nat.le_of_lt hlt),
          ofF_push, Nat.min_eq_right (by omega)]
      simp only [e, pure_bind]
      have := ih (a + 1) (fun j h1 h2 => h j (by omega) (by omega))
      rw [show c + (a + 1) + t = c + a + (t + 1) by omega] at this
      exact this
    · have e : sqIn n stc a (ofF f (min n (c + a))) = pure (ForInStep.yield (ofF f (min n (c + a)))) := by
        unfold sqIn
        rw [if_neg (by rw [ofF_size]; omega)]
      simp only [e, pure_bind]
      have := ih (a + 1) (fun j h1 h2 => h j (by omega) (by omega))
      rw [show c + (a + 1) + t = c + a + (t + 1) by omega, show min n (c + (a + 1)) = min n (c + a) by omega] at this
      exact this


private theorem sqOut_eq (K : Array UInt64 → Array UInt64) (rate n b : Nat) (s : Array UInt64 × ByteArray)
    (st : Array UInt64) (hs : s.1 = rep K (b - 1) st) :
    sqOut K rate n b s = (do
      let s1 ← forIn (m := Id) (List.range' 0 rate) s.2 (sqIn n (rep K b st))
      pure (ForInStep.yield (rep K b st, s1))) := by
  unfold sqOut
  cases b with
  | zero => rw [if_neg (by omega), hs]
  | succ b => rw [if_pos (by omega), hs, Nat.add_sub_cancel]; rfl

private theorem sq_outer (K : Array UInt64 → Array UInt64) (rate n : Nat) (hr : 0 < rate) (st : Array UInt64) :
    ∀ (k b : Nat), b + k ≤ (n + rate - 1) / rate →
    forIn (m := Id) (List.range' b k) (rep K (b - 1) st, ofF (fb K rate st) (min n (rate * b))) (sqOut K rate n)
      = (rep K (b + k - 1) st, ofF (fb K rate st) (min n (rate * (b + k)))) := by
  intro k
  induction k with
  | zero => intro b _; exact rfl
  | succ k ih =>
    intro b hb
    have hlt : rate * b < n := by
      have h1 : b + 1 ≤ (n + rate - 1) / rate := by omega
      have h2 := (Nat.le_div_iff_mul_le hr).1 h1
      rw [Nat.add_mul, Nat.one_mul, Nat.mul_comm] at h2
      omega
    rw [List.range'_succ, List.forIn_cons, sqOut_eq K rate n b _ st rfl]
    have hin := sq_inner n (rep K b st) (fb K rate st) (rate * b) rate 0 (fun j _ hj => by
      have e1 : (rate * b + j) / rate = b := by rw [Nat.mul_add_div hr, Nat.div_eq_of_lt (by omega)]; rfl
      have e2 : (rate * b + j) % rate = j := by rw [Nat.mul_add_mod, Nat.mod_eq_of_lt (by omega)]
      unfold fb; rw [e1, e2])
    simp only [Nat.add_zero] at hin
    simp only [hin, bind_assoc, pure_bind]
    have := ih (b + 1) (by omega)
    rw [show b + 1 + k = b + (k + 1) by omega, Nat.mul_add rate b 1, Nat.mul_one] at this
    exact this

private theorem sq_eq (K : Array UInt64 → Array UInt64) (rate n : Nat) (hr : 0 < rate) (st : Array UInt64) :
    Fq K rate n st = ofF (fb K rate st) n := by
  have h := sq_outer K rate n hr st ((n + rate - 1) / rate) 0 (by omega)
  have h2 : min n (rate * (0 + (n + rate - 1) / rate)) = n := by
    have := Nat.div_add_mod (n + rate - 1) rate
    have := Nat.mod_lt (n + rate - 1) hr
    rw [Nat.zero_add]
    omega
  rw [h2] at h
  unfold Fq
  have h0 : (st, ByteArray.empty) = (rep K (0 - 1) st, ofF (fb K rate st) (min n (rate * 0))) := by
    simp [rep, ofF]
    exact ByteArray.ext (by simp)
  rw [h0, h]

private theorem ofF_prefix (f : Nat → UInt8) {m n : Nat} (h : m ≤ n) : (ofF f n).extract 0 m = ofF f m := by
  apply ByteArray.ext
  rw [ByteArray.data_extract]
  show ((Array.range n).map f).extract 0 m = (Array.range m).map f
  apply Array.ext
  · simp; omega
  · intro i h1 h2
    simp

private theorem sq_prefix (K : Array UInt64 → Array UInt64) (rate : Nat) {m n : Nat} (h : m ≤ n) (st : Array UInt64) :
    (Fq K rate n st).extract 0 m = Fq K rate m st := by
  by_cases hr : 0 < rate
  · rw [sq_eq K rate n hr st, sq_eq K rate m hr st]; exact ofF_prefix _ h
  · have : rate = 0 := by omega
    subst this
    simp [Fq]
    show ByteArray.empty.extract 0 m = ByteArray.empty
    rw [ByteArray.extract_eq_empty_iff]
    simp

/-- A shorter squeeze is a prefix of a longer one (FIPS 202's SHAKE is an extendable-output function). -/
theorem sponge_prefix (rate : Nat) (suffix : UInt8) (data : ByteArray) {m n : Nat} (h : m ≤ n) :
    (spongeP rate suffix data n).extract 0 m = spongeP rate suffix data m := by
  unfold_sponge
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.add_sub_cancel, Nat.sub_zero, Nat.div_one]
  exact sq_prefix _ rate h _

end BlindLedger.Semantic

namespace BlindLedger.Gate.MlDsa87

open BlindLedger.Semantic

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

private theorem q_eq : q = 8380417 := rfl
private instance : NeZero q := ⟨by unfold q; omega⟩
private def cf (a : Nat) : Fin q := ⟨a % q, Nat.mod_lt _ (by unfold q; omega)⟩
private def tf (w : Poly) (i : Nat) : Fin q := cf w[i]!

private theorem cf_add (a b : Nat) : cf (a + b) = cf a + cf b :=
  Fin.ext (by show (a + b) % q = (a % q + b % q) % q; exact Nat.add_mod ..)
private theorem cf_mul (a b : Nat) : cf (a * b) = cf a * cf b :=
  Fin.ext (by show (a * b) % q = (a % q * (b % q)) % q; exact Nat.mul_mod ..)
private theorem cf_mod (a : Nat) : cf (a % q) = cf a :=
  Fin.ext (by show a % q % q = a % q; exact Nat.mod_mod ..)
private theorem cf_zero : cf 0 = 0 := by decide
private theorem cf_one : cf 1 = 1 := by decide
private theorem cf_q : cf q = 0 := by decide
private theorem cf_sub {a b : Nat} (hb : b ≤ q) : cf (a + q - b) = cf a - cf b := by
  have h : cf (a + q - b) + cf b = cf a := by
    rw [← cf_add, show a + q - b + b = a + q by omega, cf_add, cf_q]; simp
  grind
private theorem cf_neg {a : Nat} (ha : a ≤ q) : cf (q - a) = - cf a := by
  have := cf_sub (a := 0) ha
  rw [Nat.zero_add, cf_zero] at this; grind
private theorem mod_le (x : Nat) : x % q ≤ q := Nat.le_of_lt (Nat.mod_lt x (show q > 0 by unfold q; omega))
private theorem mod_lt' (x : Nat) : x % q < q := Nat.mod_lt x (show q > 0 by unfold q; omega)

private theorem ite_swap {α : Type} (c d : Prop) [Decidable c] [Decidable d] (h : ¬(c ∧ d)) (A B C : α) :
    (if c then A else if d then B else C) = (if d then B else if c then A else C) := by
  by_cases hc : c
  · by_cases hd : d
    · exact absurd ⟨hc, hd⟩ h
    · simp [hc, hd]
  · simp [hc]
private theorem lt8 (ℓ : Nat) (h : ℓ < 8) : ℓ = 0 ∨ ℓ = 1 ∨ ℓ = 2 ∨ ℓ = 3 ∨ ℓ = 4 ∨ ℓ = 5 ∨ ℓ = 6 ∨ ℓ = 7 := by omega

private theorem tf_set (w : Poly) (j v : Nat) (hj : j < w.size) (i : Nat) :
    tf (w.set! j v) i = if i = j then cf v else tf w i := by
  unfold tf
  by_cases h : i = j
  · subst h; rw [Array.getElem!_set!_self w i v hj, if_pos rfl]
  · rw [Array.getElem!_set!_ne w j i v (Ne.symm h), if_neg h]

private abbrev InvQ (w : Poly) : Prop := ∀ i : Nat, w[i]! < q
private abbrev IQ (w0 w : Poly) : Prop := InvQ w0 → InvQ w

private theorem invQ_set {w : Poly} (hw : InvQ w) {j v : Nat} (hj : j < w.size) (hv : v < q) : InvQ (w.set! j v) := by
  intro i
  by_cases h : i = j
  · subst h; rw [Array.getElem!_set!_self w i v hj]; exact hv
  · rw [Array.getElem!_set!_ne w j i v (Ne.symm h)]; exact hw i

private def stF (len z j : Nat) (w : Poly) : Poly :=
  let t := z * w[j + len]! % q
  let w := w.set! (j + len) ((w[j]! + q - t) % q)
  w.set! j ((w[j]! + t) % q)

private theorem stF_spec (len z j : Nat) (w : Poly) (hw : w.size = 256) (hj : j + len < 256) (hl : 0 < len) :
    (stF len z j w).size = 256 ∧ (InvQ w → InvQ (stF len z j w)) ∧ ∀ i, tf (stF len z j w) i =
      if i = j then tf w j + cf z * tf w (j + len)
      else if i = j + len then tf w j - cf z * tf w (j + len) else tf w i := by
  have hq := mod_le (z * w[j + len]!)
  have h1 : (w.set! (j + len) ((w[j]! + q - z * w[j + len]! % q) % q))[j]! = w[j]! :=
    Array.getElem!_set!_ne w (j + len) j _ (by omega)
  refine ⟨by simp only [stF, Array.size_set!, hw], fun hI => ?_, fun i => ?_⟩
  · exact invQ_set (invQ_set hI (by omega) (mod_lt' _)) (by simp only [Array.size_set!]; omega) (mod_lt' _)
  simp only [stF]
  rw [tf_set _ _ _ (by simp only [Array.size_set!]; omega), h1, tf_set _ _ _ (by omega)]
  have e1 : cf ((w[j]! + z * w[j + len]! % q) % q) = tf w j + cf z * tf w (j + len) := by
    rw [cf_mod, cf_add, cf_mod, cf_mul]; rfl
  have e2 : cf ((w[j]! + q - z * w[j + len]! % q) % q) = tf w j - cf z * tf w (j + len) := by
    rw [cf_mod, cf_sub hq, cf_mod, cf_mul]; rfl
  rw [e1, e2]

private def stI (len z j : Nat) (w : Poly) : Poly :=
  let t := w[j]!
  let w := w.set! j ((t + w[j + len]!) % q)
  w.set! (j + len) (z * ((t + q - w[j + len]!) % q) % q)

private theorem stI_spec (len z j : Nat) (w : Poly) (hw : w.size = 256) (hI : InvQ w) (hj : j + len < 256) (hl : 0 < len) :
    (stI len z j w).size = 256 ∧ InvQ (stI len z j w) ∧ ∀ i, tf (stI len z j w) i =
      if i = j then tf w j + tf w (j + len)
      else if i = j + len then cf z * (tf w j - tf w (j + len)) else tf w i := by
  have h1 : (w.set! j ((w[j]! + w[j + len]!) % q))[j + len]! = w[j + len]! :=
    Array.getElem!_set!_ne w j (j + len) _ (by omega)
  have hb : w[j + len]! ≤ q := Nat.le_of_lt (hI _)
  refine ⟨by simp only [stI, Array.size_set!, hw], ?_, fun i => ?_⟩
  · intro i
    simp only [stI]
    by_cases hi : i = j + len
    · subst hi; rw [Array.getElem!_set!_self _ _ _ (by simp only [Array.size_set!]; omega)]; exact mod_lt' _
    · rw [Array.getElem!_set!_ne _ _ _ _ (Ne.symm hi)]
      by_cases hi2 : i = j
      · subst hi2; rw [Array.getElem!_set!_self _ _ _ (by omega)]; exact mod_lt' _
      · rw [Array.getElem!_set!_ne _ _ _ _ (Ne.symm hi2)]; exact hI i
  simp only [stI]
  rw [tf_set _ _ _ (by simp only [Array.size_set!]; omega), h1, tf_set _ _ _ (by omega)]
  have e1 : cf ((w[j]! + w[j + len]!) % q) = tf w j + tf w (j + len) := by
    rw [cf_mod, cf_add]; rfl
  have e2 : cf (z * ((w[j]! + q - w[j + len]!) % q) % q) = cf z * (tf w j - tf w (j + len)) := by
    rw [cf_mod, cf_mul, cf_mod, cf_sub hb]; rfl
  rw [e1, e2]; exact ite_swap _ _ (by omega) _ _ _

private theorem inner_loop (len s : Nat) (stp : Nat → Poly → Poly) (Inv : Poly → Prop)
    (P Q : Fin q → Fin q → Fin q) (hl : 0 < len)
    (hst : ∀ j w, w.size = 256 → Inv w → j + len < 256 → (stp j w).size = 256 ∧ Inv (stp j w) ∧
      ∀ i, tf (stp j w) i =
        if i = j then P (tf w j) (tf w (j + len))
        else if i = j + len then Q (tf w j) (tf w (j + len)) else tf w i)
    (hs : s + 2 * len ≤ 256) (w : Poly) (hw : w.size = 256) (hi : Inv w) :
    ∀ t, t ≤ len → ((List.range' s t).foldl (fun w j => stp j w) w).size = 256 ∧
      Inv ((List.range' s t).foldl (fun w j => stp j w) w) ∧
      ∀ i, tf ((List.range' s t).foldl (fun w j => stp j w) w) i =
        if s ≤ i ∧ i < s + t then P (tf w i) (tf w (i + len))
        else if s + len ≤ i ∧ i < s + len + t then Q (tf w (i - len)) (tf w i) else tf w i := by
  intro t
  induction t with
  | zero => intro _; refine ⟨hw, hi, fun i => ?_⟩; simp only [List.range'_zero, List.foldl_nil]; rw [if_neg (by omega), if_neg (by omega)]
  | succ t ih =>
    intro ht
    obtain ⟨h1, h2, h3⟩ := ih (by omega)
    rw [List.range'_concat, List.foldl_append, List.foldl_cons, List.foldl_nil]
    obtain ⟨g1, g2, g3⟩ := hst (s + 1 * t) _ h1 h2 (by omega)
    refine ⟨g1, g2, fun i => ?_⟩
    rw [g3 i, h3 (s + 1 * t), h3 (s + 1 * t + len), h3 i]
    simp only [Nat.one_mul]
    grind


private abbrev Fq := Nat → Fin q
private def Zt (m : Nat) : Fin q := cf zetas[m]!
private def Cl (f : Fq) : Prop := ∀ i, 256 ≤ i → f i = 0

private def fwdL (ℓ : Nat) (f : Fq) : Fq := fun i =>
  if i < 256 then
    (if i % (2 * (128 >>> ℓ)) < 128 >>> ℓ then f i + Zt ((1 <<< ℓ) + i / (2 * (128 >>> ℓ))) * f (i + (128 >>> ℓ))
     else f (i - (128 >>> ℓ)) - Zt ((1 <<< ℓ) + i / (2 * (128 >>> ℓ))) * f i)
  else 0

private def invL (ℓ : Nat) (f : Fq) : Fq := fun i =>
  if i < 256 then
    (if i % (2 * (1 <<< ℓ)) < 1 <<< ℓ then f i + f (i + (1 <<< ℓ))
     else (- Zt (2 * (128 >>> ℓ) - (i / (2 * (1 <<< ℓ)) + 1))) * (f (i - (1 <<< ℓ)) - f i))
  else 0

private def Tw (ℓ p : Nat) : Fin q := if ℓ = 0 then -1 else (if p % 2 = 0 then (1 : Fin q) else -1) * Zt ((1 <<< ℓ) / 2 + p / 2)
private def Sh (n : Nat) (tw : Nat → Fin q) (f : Fq) : Fq := fun i =>
  if i < 256 then (if i % n = 0 then tw (i / n) * f (i + n - 1) else f (i - 1)) else 0
private def ShL (ℓ : Nat) : Fq → Fq := Sh (256 >>> ℓ) (Tw ℓ)

-- table facts
private theorem tabA : ∀ l, l < 8 → ∀ b, b < 1 <<< l →
    (zetas[2 * (1 <<< l) - (b + 1)]! * zetas[(1 <<< l) + b]! + 1) % q = 0 := by decide +kernel
private theorem tabB0 : (1 + zetas[1]! * zetas[1]!) % q = 0 := by decide +kernel
private theorem tabB1 : ∀ l, l < 8 → ∀ p, p < 1 <<< l → 1 ≤ l → p % 2 = 0 →
    zetas[(1 <<< l) / 2 + p / 2]! % q = zetas[(1 <<< l) + p]! * zetas[(1 <<< l) + p]! % q := by decide +kernel
private theorem tabB2 : ∀ l, l < 8 → ∀ p, p < 1 <<< l → 1 ≤ l → p % 2 = 1 →
    (zetas[(1 <<< l) / 2 + p / 2]! + zetas[(1 <<< l) + p]! * zetas[(1 <<< l) + p]!) % q = 0 := by decide +kernel
private theorem tabC : 256 * 8347681 % q = 1 := by decide
private theorem tabD : ∀ m, m < 256 → zetas[m]! < q := by decide +kernel

private theorem zetas_le (m : Nat) : zetas[m]! ≤ q := by
  by_cases h : m < 256
  · exact Nat.le_of_lt (tabD m h)
  · have : ¬ m < zetas.size := by unfold zetas; simpa using h
    simp [getElem!_neg, this]

private theorem zinv (ℓ : Nat) (hℓ : ℓ < 8) (b : Nat) (hb : b < 1 <<< ℓ) :
    Zt (2 * (1 <<< ℓ) - (b + 1)) * Zt ((1 <<< ℓ) + b) = -1 := by
  have h := congrArg cf (tabA ℓ hℓ b hb)
  rw [cf_mod, cf_add, cf_mul, cf_zero, cf_one] at h
  unfold Zt; grind

private theorem tw_sq (ℓ : Nat) (hℓ : ℓ < 8) (p : Nat) (hp : p < 1 <<< ℓ) :
    Zt ((1 <<< ℓ) + p) * Zt ((1 <<< ℓ) + p) = Tw ℓ p := by
  unfold Tw
  by_cases h0 : ℓ = 0
  · subst h0
    have h := congrArg cf tabB0
    rw [cf_mod, cf_add, cf_mul, cf_zero, cf_one] at h
    have : p = 0 := by simp at hp; omega
    subst this; simp; unfold Zt; grind
  · simp only [h0, if_false]
    by_cases h2 : p % 2 = 0
    · have h := congrArg cf (tabB1 ℓ hℓ p hp (by omega) h2)
      rw [cf_mod, cf_mod, cf_mul] at h
      simp only [h2, if_true]; unfold Zt; grind
    · have h := congrArg cf (tabB2 ℓ hℓ p hp (by omega) (by omega))
      rw [cf_mod, cf_add, cf_mul, cf_zero] at h
      simp only [h2, if_false]; unfold Zt; grind

private theorem blk_lt (ℓ : Nat) (hℓ : ℓ < 8) (i : Nat) (hi : i < 256) : i / (2 * (128 >>> ℓ)) < 1 <<< ℓ := by
  rcases lt8 ℓ hℓ with rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl <;> simp only [Nat.reduceShiftRight, Nat.reduceShiftLeft, Nat.reduceMul] <;> omega

private theorem fwdL_Cl (ℓ : Nat) (f : Fq) : Cl (fwdL ℓ f) := fun i hi => by simp [fwdL, Nat.not_lt.2 hi]
private theorem invL_Cl (ℓ : Nat) (f : Fq) : Cl (invL ℓ f) := fun i hi => by simp [invL, Nat.not_lt.2 hi]

private theorem invL_smul (ℓ : Nat) (c : Fin q) (f : Fq) :
    invL ℓ (fun i => c * f i) = fun i => c * invL ℓ f i := by
  funext i; unfold invL
  by_cases h1 : i < 256 <;> by_cases h2 : i % (2 * (1 <<< ℓ)) < 1 <<< ℓ <;> simp [h1, h2] <;> grind

private theorem inv_fwd (ℓ : Nat) (hℓ : ℓ < 8) (f : Fq) (hf : Cl f) :
    invL (7 - ℓ) (fwdL ℓ f) = fun i => cf 2 * f i := by
  funext i
  by_cases hi : i < 256
  · have hz := zinv ℓ hℓ (i / (2 * (128 >>> ℓ))) (blk_lt ℓ hℓ i hi)
    have hc : cf 2 = 2 := by decide
    rcases lt8 ℓ hℓ with rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl <;> (simp only [invL, fwdL, hi, if_true] at hz ⊢; simp at hz ⊢; grind)
  · have := hf i (by omega); simp [invL, hi, this]; grind


private theorem idrun {α : Type} (x : α) : Id.run (x : Id α) = x := rfl

private theorem tf_big (w : Poly) (hw : w.size = 256) (i : Nat) (hi : 256 ≤ i) : tf w i = 0 := by
  unfold tf; rw [getElem!_neg w i (by simp [hw]; omega)]; exact cf_zero

private theorem shl_succ (k : Nat) : 1 <<< (k + 1) = 2 * (1 <<< k) := by
  simp only [Nat.shiftLeft_eq, Nat.pow_succ]; omega
private theorem shl_pos (k : Nat) : 0 < 1 <<< k := by
  simp only [Nat.shiftLeft_eq]; exact Nat.mul_pos (by omega) (Nat.two_pow_pos k)
private theorem shr_pos (ℓ : Nat) (hℓ : ℓ < 8) : 0 < 128 >>> ℓ := by
  rcases lt8 ℓ hℓ with rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl <;> simp only [Nat.reduceShiftRight] <;> omega
private theorem shr_ar (ℓ : Nat) (hℓ : ℓ < 8) : 256 >>> ℓ = 2 * (128 >>> ℓ) ∧ 256 >>> (ℓ + 1) = 128 >>> ℓ := by
  rcases lt8 ℓ hℓ with rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl <;> decide

-- block arithmetic: len is the butterfly span, 2 * len * t the start of block t
private theorem blk_ar (len nb : Nat) (hn : 2 * len * nb = 256) (t : Nat) (ht : t < nb) :
    2 * len * (t + 1) ≤ 256 ∧ 2 * len * (t + 1) = 2 * len * t + 2 * len ∧
    ∀ i, 2 * len * t ≤ i → i < 2 * len * t + 2 * len →
      i / (2 * len) = t ∧ (i % (2 * len) < len ↔ i < 2 * len * t + len) := by
  have e : 2 * len * (t + 1) = 2 * len * t + 2 * len := Nat.mul_succ ..
  have e2 : 2 * len * (t + 1) ≤ 2 * len * nb := Nat.mul_le_mul_left _ ht
  refine ⟨by omega, e, fun i h1 h2 => ?_⟩
  have c1 := Nat.mul_comm t (2 * len)
  have c2 := Nat.mul_comm (t + 1) (2 * len)
  have hd : i / (2 * len) = t := Nat.div_eq_of_lt_le (by omega) (by omega)
  refine ⟨hd, ?_⟩
  have := Nat.div_add_mod i (2 * len)
  rw [hd] at this
  constructor <;> intro h <;> omega

private theorem full_ar (ℓ : Nat) (hℓ : ℓ < 8) : 2 * (128 >>> ℓ) * (1 <<< ℓ) = 256 ∧ 2 * (1 <<< ℓ) * (128 >>> ℓ) = 256 := by
  rcases lt8 ℓ hℓ with rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl <;> decide


private def nttBlk (ℓ : Nat) (st : Poly × Nat) (b : Nat) : Poly × Nat :=
  ((List.range' (2 * (128 >>> ℓ) * b) (128 >>> ℓ)).foldl (fun w j => stF (128 >>> ℓ) zetas[st.2 + 1]! j w) st.1, st.2 + 1)
private def nttBlks (ℓ : Nat) (st : Poly × Nat) (t : Nat) : Poly × Nat :=
  (List.range' 0 t).foldl (fun st b => nttBlk ℓ st b) st
private def nttRun (w : Poly) (k : Nat) : Poly × Nat :=
  (List.range' 0 k).foldl (fun st ℓ => nttBlks ℓ st (1 <<< ℓ)) (w, 0)

private theorem ntt_eq (w : Poly) : ntt w = (nttRun w 8).1 := by
  have h : ntt w = Id.run (nttRun w 8).1 := by
    simp [ntt, nttRun, nttBlks, nttBlk, stF]
  exact h

private theorem nttBlks_succ (ℓ : Nat) (st : Poly × Nat) (t : Nat) :
    nttBlks ℓ st (t + 1) = nttBlk ℓ (nttBlks ℓ st t) t := by
  simp [nttBlks, List.range'_concat]

private theorem fwd_blocks (ℓ : Nat) (hℓ : ℓ < 8) (w0 w : Poly) (hw : w.size = 256) (hi : IQ w0 w) (m : Nat)
    (hm : m + 1 = 1 <<< ℓ) : ∀ t, t ≤ 1 <<< ℓ →
    (nttBlks ℓ (w, m) t).1.size = 256 ∧ IQ w0 (nttBlks ℓ (w, m) t).1 ∧ (nttBlks ℓ (w, m) t).2 = m + t ∧
    ∀ i, tf (nttBlks ℓ (w, m) t).1 i = if i < 2 * (128 >>> ℓ) * t then fwdL ℓ (tf w) i else tf w i := by
  intro t
  induction t with
  | zero => intro _; refine ⟨hw, hi, rfl, fun i => ?_⟩; simp [nttBlks]
  | succ t ih =>
    intro ht
    obtain ⟨h1, h2, h3, h4⟩ := ih (by omega)
    obtain ⟨a1, a2, a3⟩ := blk_ar (128 >>> ℓ) (1 <<< ℓ) (full_ar ℓ hℓ).1 t (by omega)
    have hl := shr_pos ℓ hℓ
    rw [nttBlks_succ]
    generalize nttBlks ℓ (w, m) t = st at h1 h2 h3 h4 ⊢
    obtain ⟨g1, g2, g3⟩ := inner_loop (128 >>> ℓ) (2 * (128 >>> ℓ) * t)
      (fun j v => stF (128 >>> ℓ) zetas[st.2 + 1]! j v) (IQ w0)
      (fun x y => x + cf zetas[st.2 + 1]! * y) (fun x y => x - cf zetas[st.2 + 1]! * y) hl
      (fun j v hv hI hj => let ⟨s1, s2, s3⟩ := stF_spec _ _ j v hv hj hl; ⟨s1, fun hq => s2 (hI hq), s3⟩)
      (by omega) st.1 h1 h2 (128 >>> ℓ) (Nat.le_refl _)
    simp only [nttBlk]
    refine ⟨g1, g2, by omega, fun i => ?_⟩
    have hZ : ∀ i, 2 * (128 >>> ℓ) * t ≤ i → i < 2 * (128 >>> ℓ) * t + 2 * (128 >>> ℓ) →
        Zt ((1 <<< ℓ) + i / (2 * (128 >>> ℓ))) = cf zetas[st.2 + 1]! := fun i hi hi' => by
      unfold Zt; rw [(a3 i hi hi').1]; congr 2; omega
    rw [g3 i, a2]
    by_cases c1 : 2 * (128 >>> ℓ) * t ≤ i ∧ i < 2 * (128 >>> ℓ) * t + (128 >>> ℓ)
    · have hd := a3 i c1.1 (by omega)
      have hlt : i < 256 := by omega
      have hm1 := hd.2.mpr c1.2
      have n1 : ¬ i < 2 * (128 >>> ℓ) * t := by omega
      have n2 : ¬ i + 128 >>> ℓ < 2 * (128 >>> ℓ) * t := by omega
      have p1 : i < 2 * (128 >>> ℓ) * t + 2 * (128 >>> ℓ) := by omega
      rw [if_pos c1, h4 i, h4 (i + 128 >>> ℓ), if_neg n1, if_neg n2, if_pos p1]
      have hz := hZ i c1.1 p1; rw [hd.1] at hz
      simp only [fwdL, if_pos hlt, if_pos hm1, hd.1, hz]
    · by_cases c2 : 2 * (128 >>> ℓ) * t + (128 >>> ℓ) ≤ i ∧ i < 2 * (128 >>> ℓ) * t + (128 >>> ℓ) + (128 >>> ℓ)
      · have p1 : i < 2 * (128 >>> ℓ) * t + 2 * (128 >>> ℓ) := by omega
        have hd := a3 i (by omega) p1
        have hlt : i < 256 := by omega
        have hm1 : ¬ i % (2 * (128 >>> ℓ)) < 128 >>> ℓ := fun h => by have := hd.2.mp h; omega
        have n1 : ¬ i - 128 >>> ℓ < 2 * (128 >>> ℓ) * t := by omega
        have n2 : ¬ i < 2 * (128 >>> ℓ) * t := by omega
        rw [if_neg c1, if_pos c2, h4 (i - 128 >>> ℓ), h4 i, if_neg n1, if_neg n2, if_pos p1]
        have hz := hZ i (by omega) p1; rw [hd.1] at hz
        simp only [fwdL, if_pos hlt, if_neg hm1, hd.1, hz]
      · rw [if_neg c1, if_neg c2, h4 i]
        by_cases c3 : i < 2 * (128 >>> ℓ) * t
        · have p1 : i < 2 * (128 >>> ℓ) * t + 2 * (128 >>> ℓ) := by omega
          rw [if_pos c3, if_pos p1]
        · have p1 : ¬ i < 2 * (128 >>> ℓ) * t + 2 * (128 >>> ℓ) := by omega
          rw [if_neg c3, if_neg p1]


private def NTTk (f : Fq) : Nat → Fq
  | 0 => f
  | k + 1 => fwdL k (NTTk f k)

private theorem nttRun_succ (w : Poly) (k : Nat) : nttRun w (k + 1) = nttBlks k (nttRun w k) (1 <<< k) := by
  simp [nttRun, List.range'_concat]

private theorem fwd_layers (w0 w : Poly) (hw : w.size = 256) (hi : IQ w0 w) :
    ∀ k, k ≤ 8 → (nttRun w k).1.size = 256 ∧ IQ w0 (nttRun w k).1 ∧ (nttRun w k).2 + 1 = 1 <<< k ∧
      ∀ i, tf (nttRun w k).1 i = NTTk (tf w) k i := by
  intro k
  induction k with
  | zero => intro _; exact ⟨hw, hi, by simp [nttRun], fun i => by simp [nttRun, NTTk]⟩
  | succ k ih =>
    intro hk
    obtain ⟨h1, h2, h3, h4⟩ := ih (by omega)
    rw [nttRun_succ]
    obtain ⟨g1, g2, g3, g4⟩ := fwd_blocks k (by omega) w0 _ h1 h2 _ h3 (1 <<< k) (Nat.le_refl _)
    refine ⟨g1, g2, by rw [g3, shl_succ]; omega, fun i => ?_⟩
    rw [g4 i, (full_ar k (by omega)).1]
    have e : tf (nttRun w k).1 = NTTk (tf w) k := funext h4
    rw [e]
    by_cases hi : i < 256
    · rw [if_pos hi]; rfl
    · rw [if_neg hi, ← h4 i, tf_big _ h1 i (by omega)]; exact (fwdL_Cl k _ i (by omega)).symm

private theorem ntt_spec (w : Poly) (hw : w.size = 256) :
    (ntt w).size = 256 ∧ (InvQ w → InvQ (ntt w)) ∧ ∀ i, tf (ntt w) i = NTTk (tf w) 8 i := by
  rw [ntt_eq]
  obtain ⟨h1, h2, _, h4⟩ := fwd_layers w w hw id 8 (Nat.le_refl _)
  exact ⟨h1, h2, h4⟩


private def invBlk (ℓ : Nat) (st : Poly × Nat) (b : Nat) : Poly × Nat :=
  ((List.range' (2 * (1 <<< ℓ) * b) (1 <<< ℓ)).foldl (fun w j => stI (1 <<< ℓ) (q - zetas[st.2 - 1]!) j w) st.1, st.2 - 1)
private def invBlks (ℓ : Nat) (st : Poly × Nat) (t : Nat) : Poly × Nat :=
  (List.range' 0 t).foldl (fun st b => invBlk ℓ st b) st
private def invRun (w : Poly) (k : Nat) : Poly × Nat :=
  (List.range' 0 k).foldl (fun st ℓ => invBlks ℓ st (128 >>> ℓ)) (w, 256)

private theorem invNtt_eq (w : Poly) : invNtt w = (invRun w 8).1.map fun x => x * 8347681 % q := by
  have h : invNtt w = Id.run ((invRun w 8).1.map fun x => x * 8347681 % q) := by
    simp only [invNtt, invRun, invBlks, invBlk, stI, Array.set!_eq_setIfInBounds, Std.Legacy.Range.forIn_eq_forIn_range',
      Std.Legacy.Range.size, Nat.add_sub_cancel_left, Nat.add_one_sub_one, Nat.div_one, List.forIn_pure_yield_eq_foldl,
      bind_pure_comp, map_pure, Nat.sub_zero, Nat.reduceAdd, pure_bind]
  rw [h]; exact idrun _

private theorem invBlks_succ (ℓ : Nat) (st : Poly × Nat) (t : Nat) :
    invBlks ℓ st (t + 1) = invBlk ℓ (invBlks ℓ st t) t := by
  simp [invBlks, List.range'_concat]

private theorem inv_blocks (ℓ : Nat) (hℓ : ℓ < 8) (w : Poly) (hw : w.size = 256) (hi : InvQ w) (m : Nat)
    (hm : m = 2 * (128 >>> ℓ)) : ∀ t, t ≤ 128 >>> ℓ →
    (invBlks ℓ (w, m) t).1.size = 256 ∧ InvQ (invBlks ℓ (w, m) t).1 ∧ (invBlks ℓ (w, m) t).2 = m - t ∧
    ∀ i, tf (invBlks ℓ (w, m) t).1 i = if i < 2 * (1 <<< ℓ) * t then invL ℓ (tf w) i else tf w i := by
  intro t
  induction t with
  | zero => intro _; refine ⟨hw, hi, rfl, fun i => ?_⟩; simp [invBlks]
  | succ t ih =>
    intro ht
    obtain ⟨h1, h2, h3, h4⟩ := ih (by omega)
    obtain ⟨a1, a2, a3⟩ := blk_ar (1 <<< ℓ) (128 >>> ℓ) (full_ar ℓ hℓ).2 t (by omega)
    have hl := shl_pos ℓ
    have hz := zetas_le (m - t - 1)
    rw [invBlks_succ]
    generalize invBlks ℓ (w, m) t = st at h1 h2 h3 h4 ⊢
    obtain ⟨g1, g2, g3⟩ := inner_loop (1 <<< ℓ) (2 * (1 <<< ℓ) * t)
      (fun j v => stI (1 <<< ℓ) (q - zetas[st.2 - 1]!) j v) InvQ
      (fun x y => x + y) (fun x y => cf (q - zetas[st.2 - 1]!) * (x - y)) hl
      (fun j v hv hI hj => stI_spec _ _ j v hv hI hj hl)
      (by omega) st.1 h1 h2 (1 <<< ℓ) (Nat.le_refl _)
    simp only [invBlk]
    refine ⟨g1, g2, by omega, fun i => ?_⟩
    have hZ : ∀ i, 2 * (1 <<< ℓ) * t ≤ i → i < 2 * (1 <<< ℓ) * t + 2 * (1 <<< ℓ) →
        cf (q - zetas[st.2 - 1]!) = - Zt (2 * (128 >>> ℓ) - (i / (2 * (1 <<< ℓ)) + 1)) := fun i hi hi' => by
      rw [cf_neg (zetas_le _)]; unfold Zt; rw [(a3 i hi hi').1]; congr 3; omega
    rw [g3 i, a2]
    by_cases c1 : 2 * (1 <<< ℓ) * t ≤ i ∧ i < 2 * (1 <<< ℓ) * t + (1 <<< ℓ)
    · have hd := a3 i c1.1 (by omega)
      have hm1 := hd.2.mpr c1.2
      have n1 : ¬ i < 2 * (1 <<< ℓ) * t := by omega
      have n2 : ¬ i + 1 <<< ℓ < 2 * (1 <<< ℓ) * t := by omega
      have p1 : i < 2 * (1 <<< ℓ) * t + 2 * (1 <<< ℓ) := by omega
      have hlt : i < 256 := by omega
      rw [if_pos c1, h4 i, h4 (i + 1 <<< ℓ), if_neg n1, if_neg n2, if_pos p1]
      simp only [invL, if_pos hlt, if_pos hm1]
    · by_cases c2 : 2 * (1 <<< ℓ) * t + (1 <<< ℓ) ≤ i ∧ i < 2 * (1 <<< ℓ) * t + (1 <<< ℓ) + (1 <<< ℓ)
      · have p1 : i < 2 * (1 <<< ℓ) * t + 2 * (1 <<< ℓ) := by omega
        have hd := a3 i (by omega) p1
        have hm1 : ¬ i % (2 * (1 <<< ℓ)) < 1 <<< ℓ := fun h => by have := hd.2.mp h; omega
        have n1 : ¬ i - 1 <<< ℓ < 2 * (1 <<< ℓ) * t := by omega
        have n2 : ¬ i < 2 * (1 <<< ℓ) * t := by omega
        have hlt : i < 256 := by omega
        rw [if_neg c1, if_pos c2, h4 (i - 1 <<< ℓ), h4 i, if_neg n1, if_neg n2, if_pos p1]
        simp only [invL, if_pos hlt, if_neg hm1, hZ i (by omega) p1]
      · rw [if_neg c1, if_neg c2, h4 i]
        by_cases c3 : i < 2 * (1 <<< ℓ) * t
        · have p1 : i < 2 * (1 <<< ℓ) * t + 2 * (1 <<< ℓ) := by omega
          rw [if_pos c3, if_pos p1]
        · have p1 : ¬ i < 2 * (1 <<< ℓ) * t + 2 * (1 <<< ℓ) := by omega
          rw [if_neg c3, if_neg p1]

private def INVk (f : Fq) : Nat → Fq
  | 0 => f
  | k + 1 => invL k (INVk f k)

private theorem invRun_succ (w : Poly) (k : Nat) : invRun w (k + 1) = invBlks k (invRun w k) (128 >>> k) := by
  simp [invRun, List.range'_concat]

private theorem inv_layers (w : Poly) (hw : w.size = 256) (hi : InvQ w) :
    ∀ k, k ≤ 8 → (invRun w k).1.size = 256 ∧ InvQ (invRun w k).1 ∧ (invRun w k).2 = 256 >>> k ∧
      ∀ i, tf (invRun w k).1 i = INVk (tf w) k i := by
  intro k
  induction k with
  | zero => intro _; exact ⟨hw, hi, by simp [invRun], fun i => by simp [invRun, INVk]⟩
  | succ k ih =>
    intro hk
    obtain ⟨h1, h2, h3, h4⟩ := ih (by omega)
    obtain ⟨s1, s2⟩ := shr_ar k (by omega)
    rw [invRun_succ]
    obtain ⟨g1, g2, g3, g4⟩ := inv_blocks k (by omega) _ h1 h2 (invRun w k).2 (by omega) (128 >>> k) (Nat.le_refl _)
    refine ⟨g1, g2, by rw [g3]; omega, fun i => ?_⟩
    rw [g4 i, (full_ar k (by omega)).2]
    have e : tf (invRun w k).1 = INVk (tf w) k := funext h4
    rw [e]
    by_cases hi : i < 256
    · rw [if_pos hi]; rfl
    · rw [if_neg hi, ← h4 i, tf_big _ h1 i (by omega)]; exact (invL_Cl k _ i (by omega)).symm

private theorem map_get (a : Poly) (f : Nat → Nat) (i : Nat) (hi : i < a.size) : (a.map f)[i]! = f a[i]! := by
  rw [getElem!_pos (a.map f) i (by simpa using hi), Array.getElem_map, ← getElem!_pos a i hi]

private theorem invNtt_spec (w : Poly) (hw : w.size = 256) (hq : InvQ w) :
    (invNtt w).size = 256 ∧ InvQ (invNtt w) ∧ ∀ i, tf (invNtt w) i = cf 8347681 * INVk (tf w) 8 i := by
  rw [invNtt_eq]
  obtain ⟨h1, h2, _, h4⟩ := inv_layers w hw hq 8 (Nat.le_refl _)
  refine ⟨by simp [h1], fun i => ?_, fun i => ?_⟩
  · by_cases hi : i < 256
    · rw [map_get (invRun w 8).1 _ i (by omega)]; exact mod_lt' _
    · rw [getElem!_neg _ i (by simp [h1]; omega)]; show 0 < q; unfold q; omega
  · by_cases hi : i < 256
    · have e : tf ((invRun w 8).1.map fun x => x * 8347681 % q) i = tf (invRun w 8).1 i * cf 8347681 := by
        unfold tf; rw [map_get (invRun w 8).1 _ i (by omega), cf_mod, cf_mul]
      rw [e, h4 i]; grind
    · rw [← h4 i, tf_big _ h1 i (by omega), tf_big _ (by simp [h1]) i (by omega)]; grind

private theorem mz (x : Fin q) : x * 0 = 0 := Fin.mul_zero x

-- linearity
private def ad (f g : Fq) : Fq := fun i => f i + g i
private def sc (c : Fin q) (f : Fq) : Fq := fun i => c * f i
private theorem fwdL_add (ℓ : Nat) (f g : Fq) : fwdL ℓ (ad f g) = ad (fwdL ℓ f) (fwdL ℓ g) := by
  funext i; unfold fwdL ad
  by_cases h1 : i < 256 <;> by_cases h2 : i % (2 * (128 >>> ℓ)) < 128 >>> ℓ <;> simp [h1, h2] <;> grind
private theorem fwdL_sc (ℓ : Nat) (c : Fin q) (f : Fq) : fwdL ℓ (sc c f) = sc c (fwdL ℓ f) := by
  funext i; unfold fwdL sc
  by_cases h1 : i < 256 <;> by_cases h2 : i % (2 * (128 >>> ℓ)) < 128 >>> ℓ <;> simp [h1, h2] <;> grind
private theorem fwdL_zero (ℓ : Nat) : fwdL ℓ (fun _ => 0) = fun _ => 0 := by
  funext i; unfold fwdL
  by_cases h1 : i < 256
  · by_cases h2 : i % (2 * (128 >>> ℓ)) < 128 >>> ℓ
    · simp only [h1, h2, if_true, mz]; decide
    · simp only [h1, h2, if_true, if_false, mz]; decide
  · simp only [h1, if_false]

private theorem NTTk_add (f g : Fq) : ∀ k, NTTk (ad f g) k = ad (NTTk f k) (NTTk g k)
  | 0 => rfl
  | k + 1 => by show fwdL k (NTTk (ad f g) k) = _; rw [NTTk_add f g k, fwdL_add]; rfl
private theorem NTTk_sc (c : Fin q) (f : Fq) : ∀ k, NTTk (sc c f) k = sc c (NTTk f k)
  | 0 => rfl
  | k + 1 => by show fwdL k (NTTk (sc c f) k) = _; rw [NTTk_sc c f k, fwdL_sc]; rfl
private theorem NTTk_zero : ∀ k, NTTk (fun _ => 0) k = fun _ => 0
  | 0 => rfl
  | k + 1 => by show fwdL k (NTTk (fun _ => 0) k) = _; rw [NTTk_zero k, fwdL_zero]

private theorem Cl_NTTk (f : Fq) (hf : Cl f) (k : Nat) : Cl (NTTk f k) := by
  cases k with
  | zero => exact hf
  | succ k => exact fwdL_Cl k _

-- NTT of a product by X is a twist
private theorem tw_next (ℓ p : Nat) : Tw (ℓ + 1) p = (if p % 2 = 0 then (1 : Fin q) else -1) * Zt ((1 <<< ℓ) + p / 2) := by
  have h : (1 <<< (ℓ + 1)) / 2 = 1 <<< ℓ := by rw [shl_succ]; omega
  unfold Tw; simp [h]

private theorem blk_lt2 (ℓ : Nat) (hℓ : ℓ < 8) (i : Nat) (hi : i < 256) : i / (256 >>> ℓ) < 1 <<< ℓ := by
  rcases lt8 ℓ hℓ with rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl <;> simp only [Nat.reduceShiftRight, Nat.reduceShiftLeft] <;> omega

private theorem interw (ℓ : Nat) (hℓ : ℓ < 8) (f : Fq) : fwdL ℓ (ShL ℓ f) = ShL (ℓ + 1) (fwdL ℓ f) := by
  funext i
  by_cases hi : i < 256
  · have e1 := tw_next ℓ (i / (256 >>> (ℓ + 1)))
    have e2 := tw_sq ℓ hℓ (i / (256 >>> ℓ)) (blk_lt2 ℓ hℓ i hi)
    rcases lt8 ℓ hℓ with rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl <;>
      (simp only [fwdL, ShL, Sh, Nat.reduceShiftLeft, Nat.reduceShiftRight, Nat.reduceMul, Nat.reduceAdd, hi, if_true] at e1 e2 ⊢; grind)
  · simp [fwdL, ShL, Sh, hi]

private def ShN : Nat → Fq → Fq
  | 0, f => f
  | j + 1, f => ShL 0 (ShN j f)

private theorem ShL_Cl (ℓ : Nat) (f : Fq) : Cl (ShL ℓ f) := fun i hi => by simp [ShL, Sh, Nat.not_lt.2 hi]
private theorem ShN_Cl (g : Fq) (hg : Cl g) : ∀ j, Cl (ShN j g)
  | 0 => hg
  | j + 1 => ShL_Cl 0 _

private theorem NTT_sh (f : Fq) : ∀ k, k ≤ 8 → NTTk (ShL 0 f) k = ShL k (NTTk f k)
  | 0, _ => rfl
  | k + 1, hk => by
    show fwdL k (NTTk (ShL 0 f) k) = ShL (k + 1) (fwdL k (NTTk f k))
    rw [NTT_sh f k (by omega)]; exact interw k (by omega) _

private theorem ShL8 (g : Fq) (hg : Cl g) : ShL 8 g = fun i => Tw 8 i * g i := by
  funext i
  by_cases hi : i < 256
  · simp [ShL, Sh, hi, Nat.mod_one]
  · have := hg i (by omega); simp only [ShL, Sh, hi, if_false, this]; grind

private def tp : Nat → Nat → Fin q
  | 0, _ => 1
  | j + 1, i => Tw 8 i * tp j i

private theorem NTT_ShN (g : Fq) (hg : Cl g) : ∀ j i, NTTk (ShN j g) 8 i = tp j i * NTTk g 8 i
  | 0, i => by simp only [ShN, tp]; grind
  | j + 1, i => by
    show NTTk (ShL 0 (ShN j g)) 8 i = tp (j + 1) i * NTTk g 8 i
    rw [NTT_sh _ 8 (Nat.le_refl _), ShL8 _ (Cl_NTTk _ (ShN_Cl g hg j) 8)]
    show Tw 8 i * NTTk (ShN j g) 8 i = _
    rw [NTT_ShN g hg j i]
    simp only [tp]; grind

-- the unit
private def e0 : Fq := fun i => if i = 0 then 1 else 0
private theorem e0_Cl : Cl e0 := fun i hi => by simp [e0]; omega

private theorem fwdL_pat (ℓ : Nat) (hℓ : ℓ < 8) :
    fwdL ℓ (fun i => if i < 256 ∧ i % (256 >>> ℓ) = 0 then 1 else 0) = fun i => if i < 256 ∧ i % (256 >>> (ℓ + 1)) = 0 then 1 else 0 := by
  funext i
  by_cases hi : i < 256
  · rcases lt8 ℓ hℓ with rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl <;>
      (simp only [fwdL, Nat.reduceShiftLeft, Nat.reduceShiftRight, Nat.reduceMul, Nat.reduceAdd, hi, if_true]; grind)
  · simp [fwdL, hi]

private theorem NTT_e0 : ∀ k, k ≤ 8 → NTTk e0 k = fun i => if i < 256 ∧ i % (256 >>> k) = 0 then 1 else 0
  | 0, _ => by
    funext i
    show e0 i = _
    by_cases h : i = 0
    · subst h; simp [e0]
    · have : ¬ (i < 256 ∧ i % (256 >>> 0) = 0) := by simp only [Nat.reduceShiftRight]; omega
      rw [if_neg this]; simp [e0, h]
  | k + 1, hk => by
    show fwdL k (NTTk e0 k) = _
    rw [NTT_e0 k (by omega), fwdL_pat k (by omega)]

private theorem NTT_e0' (i : Nat) : NTTk e0 8 i = if i < 256 then 1 else 0 := by
  rw [NTT_e0 8 (Nat.le_refl _)]; simp [Nat.mod_one]


-- schoolbook product as an X-adic sum
private theorem ShL0_pt (f : Fq) (i : Nat) (hi : i < 256) : ShL 0 f i = if i = 0 then - f 255 else f (i - 1) := by
  by_cases h : i = 0 <;> simp [ShL, Sh, Tw, hi, h, Nat.mod_eq_of_lt hi] <;> grind

private theorem ShN_pt (g : Fq) : ∀ j, j ≤ 256 → ∀ i, i < 256 →
    ShN j g i = if j ≤ i then g (i - j) else - g (i + 256 - j)
  | 0, _, i, hi => by simp [ShN]
  | j + 1, hj, i, hi => by
    show ShL 0 (ShN j g) i = _
    rw [ShL0_pt _ i hi]
    by_cases h0 : i = 0
    · subst h0
      rw [if_pos rfl, ShN_pt g j (by omega) 255 (by omega), if_pos (show j ≤ 255 by omega),
        if_neg (show ¬ (j + 1 ≤ 0) by omega), show 0 + 256 - (j + 1) = 255 - j by omega]
    · rw [if_neg h0, ShN_pt g j (by omega) (i - 1) (by omega)]
      by_cases h1 : j + 1 ≤ i
      · rw [if_pos (show j ≤ i - 1 by omega), if_pos h1, show i - 1 - j = i - (j + 1) by omega]
      · rw [if_neg (show ¬ (j ≤ i - 1) by omega), if_neg h1, show i - 1 + 256 - j = i + 256 - (j + 1) by omega]

private def tm (f g : Fq) (i j : Nat) : Fin q := if j ≤ i then f j * g (i - j) else - (f j * g (i + 256 - j))
private def cvS (n : Nat) (f g : Fq) : Fq := fun i =>
  if i < 256 then (List.range n).foldl (fun acc j => acc + tm f g i j) 0 else 0

private theorem cvS_Cl (n : Nat) (f g : Fq) : Cl (cvS n f g) := fun i hi => by simp [cvS, Nat.not_lt.2 hi]

private theorem cvS_succ (n : Nat) (hn : n < 256) (f g : Fq) (hg : Cl g) :
    cvS (n + 1) f g = ad (cvS n f g) (sc (f n) (ShN n g)) := by
  funext i
  show cvS (n + 1) f g i = cvS n f g i + f n * ShN n g i
  by_cases hi : i < 256
  · rw [ShN_pt g n (by omega) i hi]
    simp only [cvS, hi, if_true, List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil, tm]
    by_cases h : n ≤ i
    · simp only [h, if_true]
    · simp only [h, if_false]; grind
  · have h1 : ShN n g i = 0 := by
      cases n with
      | zero => exact hg i (by omega)
      | succ n => exact ShL_Cl 0 _ i (by omega)
    simp only [cvS, hi, if_false, h1, mz]; try decide

private theorem NTT_cvS (f g : Fq) (hg : Cl g) : ∀ n, n ≤ 256 →
    NTTk (cvS n f g) 8 = fun i => NTTk (cvS n f e0) 8 i * NTTk g 8 i
  | 0, _ => by
    have h0 : ∀ g, cvS 0 f g = fun _ => 0 := fun g => by funext i; simp [cvS]
    rw [h0, h0, NTTk_zero]; funext i
    show (0 : Fin q) = 0 * NTTk g 8 i; grind
  | n + 1, hn => by
    rw [cvS_succ n (by omega) f g hg, cvS_succ n (by omega) f e0 e0_Cl, NTTk_add, NTTk_sc, NTTk_add, NTTk_sc,
      NTT_cvS f g hg n (by omega)]
    funext i
    show NTTk (cvS n f e0) 8 i * NTTk g 8 i + f n * NTTk (ShN n g) 8 i =
      (NTTk (cvS n f e0) 8 i + f n * NTTk (ShN n e0) 8 i) * NTTk g 8 i
    rw [NTT_ShN g hg n i, NTT_ShN e0 e0_Cl n i, NTT_e0']
    by_cases hi : i < 256
    · rw [if_pos hi]; grind
    · rw [if_neg hi, Cl_NTTk g hg 8 i (by omega)]; simp only [mz]; try decide

private theorem fold_single (T : Nat → Fin q) (i : Nat) (hT : ∀ j, j ≠ i → T j = 0) :
    ∀ n, (List.range n).foldl (fun acc j => acc + T j) 0 = if i < n then T i else 0
  | 0 => by simp
  | n + 1 => by
    rw [List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil, fold_single T i hT n]
    by_cases h : i < n
    · have := hT n (by omega); rw [if_pos h, if_pos (by omega)]; grind
    · by_cases h2 : i = n
      · subst h2; rw [if_neg h, if_pos (by omega)]; grind
      · have := hT n (fun h3 => h2 h3.symm); rw [if_neg h, if_neg (by omega)]; grind

private theorem cvS_e0 (f : Fq) (hf : Cl f) : cvS 256 f e0 = f := by
  funext i
  by_cases hi : i < 256
  · simp only [cvS, hi, if_true]
    rw [fold_single (tm f e0 i) i (fun j hj => by
      unfold tm e0
      by_cases h : j ≤ i
      · rw [if_pos h, if_neg (by omega)]; grind
      · rw [if_neg h]
        by_cases h' : i + 256 - j = 0
        · rw [if_pos h', hf j (by omega)]; grind
        · rw [if_neg h']; grind) 256, if_pos hi]
    unfold tm e0
    rw [if_pos (Nat.le_refl i), Nat.sub_self, if_pos rfl]; grind
  · simp only [cvS, hi, if_false]; exact (hf i (by omega)).symm

private theorem INV_NTT (f : Fq) (hf : Cl f) : INVk (NTTk f 8) 8 = fun i => cf 256 * f i := by
  have key : ∀ k, k ≤ 8 → INVk (NTTk f 8) k = fun i => cf (2 ^ k) * NTTk f (8 - k) i := by
    intro k
    induction k with
    | zero =>
      intro _; funext i
      show NTTk f 8 i = cf (2 ^ 0) * NTTk f 8 i
      rw [show cf (2 ^ 0) = 1 from by decide]; grind
    | succ k ih =>
      intro hk
      show invL k (INVk (NTTk f 8) k) = _
      rw [ih (by omega), invL_smul]
      have e8 : 8 - k = (7 - k) + 1 := by omega
      have e7 : 7 - (7 - k) = k := by omega
      have hi := inv_fwd (7 - k) (by omega) (NTTk f (7 - k)) (Cl_NTTk f hf _)
      rw [e7] at hi
      funext i
      rw [e8]
      show cf (2 ^ k) * invL k (fwdL (7 - k) (NTTk f (7 - k))) i = _
      rw [hi, show 7 - k = 8 - (k + 1) by omega, Nat.pow_succ, cf_mul]
      grind
  rw [key 8 (Nat.le_refl _)]; funext i; rfl

private theorem NTT_cv (f g : Fq) (hf : Cl f) (hg : Cl g) :
    NTTk (cvS 256 f g) 8 = fun i => NTTk f 8 i * NTTk g 8 i := by
  rw [NTT_cvS f g hg 256 (Nat.le_refl _), cvS_e0 f hf]

private theorem scal (x : Fin q) : cf 8347681 * (cf 256 * x) = x := by
  have h : cf 8347681 * cf 256 = 1 := by
    rw [← cf_mul, Nat.mul_comm, ← cf_mod, tabC, cf_one]
  grind


private theorem arr_eq (a b : Poly) (ha : a.size = 256) (hb : b.size = 256) (qa : InvQ a) (qb : InvQ b)
    (h : ∀ i, tf a i = tf b i) : a = b := by
  have hx : ∀ i, a[i]! = b[i]! := fun i => by
    have h1 : a[i]! % q = b[i]! % q := congrArg Fin.val (h i)
    rwa [Nat.mod_eq_of_lt (qa i), Nat.mod_eq_of_lt (qb i)] at h1
  apply Array.ext (by omega)
  intro i h1 h2
  have := hx i
  rwa [getElem!_pos a i h1, getElem!_pos b i h2] at this

private theorem range_get (i : Nat) (hi : i < 256) : (Array.range 256)[i]! = i := by
  rw [getElem!_pos (Array.range 256) i (by simp; omega)]; simp

/-- NTT round trip (Algorithms 41 and 42) on reduced polynomials. -/
theorem invNtt_ntt {p : Poly} (hs : p.size = 256) (hq : ∀ x ∈ p, x < q) : invNtt (ntt p) = p := by
  have hQ : InvQ p := fun i => by
    by_cases h : i < p.size
    · rw [getElem!_pos p i h]; exact hq _ (Array.getElem_mem h)
    · rw [getElem!_neg p i h]; show 0 < q; unfold q; omega
  obtain ⟨n1, n2, n3⟩ := ntt_spec p hs
  obtain ⟨v1, v2, v3⟩ := invNtt_spec (ntt p) n1 (n2 hQ)
  apply arr_eq _ _ v1 hs v2 hQ
  intro i
  rw [v3 i, show tf (ntt p) = NTTk (tf p) 8 from funext n3, INV_NTT _ (fun j hj => tf_big p hs j hj)]
  exact scal _

/-- Schoolbook product in Z_q[X]/(X^256 + 1): the reference that the NTT-domain product must equal. -/
def negacyclic (a b : Poly) : Poly :=
  (Array.range 256).map fun i => (List.range 256).foldl (fun acc j =>
    if j ≤ i then (acc + a[j]! * b[i - j]!) % q else (acc + (q - a[j]! * b[i + 256 - j]! % q)) % q) 0


private theorem fold_lt (F : Nat → Nat → Nat) (hF : ∀ acc j, F acc j < q) (l : List Nat) (acc : Nat) (ha : acc < q) :
    l.foldl F acc < q := by
  induction l generalizing acc with
  | nil => exact ha
  | cons j l ih => exact ih _ (hF acc j)

private theorem neg_size (a b : Poly) : (negacyclic a b).size = 256 := by simp [negacyclic]

private theorem neg_lt (a b : Poly) : InvQ (negacyclic a b) := by
  intro i
  by_cases hi : i < 256
  · unfold negacyclic
    rw [map_get (Array.range 256) _ i (by simp; omega), range_get i hi]
    refine fold_lt _ (fun acc j => ?_) _ 0 (by unfold q; omega)
    by_cases h : j ≤ i
    · simp only [h, if_true]; exact mod_lt' _
    · simp only [h, if_false]; exact mod_lt' _
  · rw [getElem!_neg _ i (by simp [negacyclic]; omega)]; show 0 < q; unfold q; omega

private theorem neg_tf (a b : Poly) (i : Nat) : tf (negacyclic a b) i = cvS 256 (tf a) (tf b) i := by
  by_cases hi : i < 256
  · have key : ∀ n, cf ((List.range n).foldl (fun acc j =>
        if j ≤ i then (acc + a[j]! * b[i - j]!) % q else (acc + (q - a[j]! * b[i + 256 - j]! % q)) % q) 0) =
        (List.range n).foldl (fun acc j => acc + tm (tf a) (tf b) i j) 0 := by
      intro n
      induction n with
      | zero => simp [cf_zero]
      | succ n ih =>
        simp only [List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil]
        rw [← ih]
        generalize (List.range n).foldl _ 0 = X
        by_cases h : n ≤ i
        · simp only [h, if_true, tm]
          rw [cf_mod, cf_add, cf_mul]; rfl
        · simp only [h, if_false, tm]
          rw [cf_mod, cf_add, cf_neg (mod_le _), cf_mod, cf_mul]; rfl
    have e : tf (negacyclic a b) i = cf ((List.range 256).foldl (fun acc j =>
        if j ≤ i then (acc + a[j]! * b[i - j]!) % q else (acc + (q - a[j]! * b[i + 256 - j]! % q)) % q) 0) := by
      unfold tf negacyclic
      rw [map_get (Array.range 256) _ i (by simp; omega), range_get i hi]
    rw [e, key 256]; simp only [cvS, hi, if_true]
  · rw [tf_big _ (neg_size a b) i (by omega)]; exact (cvS_Cl 256 _ _ i (by omega)).symm

/-- The pointwise NTT product is the negacyclic product, so verify's `A z - c t1 2^d` is the standard's. -/
theorem invNtt_pointwise {a b : Poly} (ha : a.size = 256) (hb : b.size = 256) :
    invNtt ((Array.range 256).map fun j => (ntt a)[j]! * (ntt b)[j]! % q) = negacyclic a b := by
  obtain ⟨a1, _, a3⟩ := ntt_spec a ha
  obtain ⟨b1, _, b3⟩ := ntt_spec b hb
  have hsz : ((Array.range 256).map fun j => (ntt a)[j]! * (ntt b)[j]! % q).size = 256 := by simp
  have hQ : InvQ ((Array.range 256).map fun j => (ntt a)[j]! * (ntt b)[j]! % q) := fun i => by
    by_cases hi : i < 256
    · rw [map_get (Array.range 256) _ i (by simp; omega)]; exact mod_lt' _
    · rw [getElem!_neg _ i (by simp; omega)]; show 0 < q; unfold q; omega
  have ht : tf ((Array.range 256).map fun j => (ntt a)[j]! * (ntt b)[j]! % q) =
      fun i => NTTk (tf a) 8 i * NTTk (tf b) 8 i := by
    funext i
    by_cases hi : i < 256
    · have e : tf ((Array.range 256).map fun j => (ntt a)[j]! * (ntt b)[j]! % q) i = tf (ntt a) i * tf (ntt b) i := by
        unfold tf
        rw [map_get (Array.range 256) _ i (by simp; omega), range_get i hi, cf_mod, cf_mul]
      rw [e, a3 i, b3 i]
    · rw [tf_big _ hsz i (by omega), Cl_NTTk (tf a) (tf_big a ha) 8 i (by omega)]; grind
  obtain ⟨c1, c2, c3⟩ := invNtt_spec _ hsz hQ
  apply arr_eq _ _ c1 (neg_size a b) c2 (neg_lt a b)
  intro i
  rw [c3 i, ht, ← NTT_cv _ _ (tf_big a ha) (tf_big b hb), INV_NTT _ (cvS_Cl 256 _ _), neg_tf]
  exact scal _

end BlindLedger.Gate.MlDsa87

/-! Axiom pins for the proved theorems. -/
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
/-- info: 'BlindLedger.Semantic.sponge_prefix' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Semantic.sponge_prefix
/-- info: 'BlindLedger.Gate.MlDsa87.rejNtt_stable' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.MlDsa87.rejNtt_stable
/-- info: 'BlindLedger.Gate.MlDsa87.sampleInBall_stable' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.MlDsa87.sampleInBall_stable
/-- info: 'BlindLedger.Gate.MlDsa87.invNtt_ntt' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.MlDsa87.invNtt_ntt
/-- info: 'BlindLedger.Gate.MlDsa87.invNtt_pointwise' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms BlindLedger.Gate.MlDsa87.invNtt_pointwise
