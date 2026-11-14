import BlindLedger.Gate.Cosign.Codec
import BlindLedger.Gate.CheckpointTheorems
import BlindLedger.Gate.ParseLaws

/-! KEY-CERT/v2 codec laws: the decoder accepts exactly the encodings of well-formed certificates and returns the
    certificate encoded (`decode_iff`), so it inverts the encoder (`decode_encode`), every accepted input is canonical
    (`encode_decode`) and every other input is refused (`decode_total`).  Its size bound refuses no certificate with
    ML-DSA-87 signatures (`mlDsa87_decodes`). -/
namespace BlindLedger.Gate.Cosign

open BlindLedger.Gate

def Key.Wf (k : Key) : Prop := keyBytes k.scheme = some k.pk.length

/-- What the decoder checks of each field. -/
def KeyCert.FieldsOk (x : KeyCert) : Prop :=
  identOk x.tenantId = true ∧ x.epoch ≤ maxNat ∧ x.link.length = digestBytes ∧ chainOk x.chain = true ∧
    x.key.Wf ∧ x.verifierKey.Wf

/-- A well-formed certificate: its fields pass, and its encoding is within the decoder's bound. -/
def KeyCert.Wf (x : KeyCert) : Prop := x.FieldsOk ∧ x.encode.length ≤ maxCertBytes

theorem keyBytes_some {s n : Nat} (h : keyBytes s = some n) : s = 1 ∧ n = mlDsa87Key := by
  unfold keyBytes at h
  split at h
  · exact ⟨rfl, (Option.some.inj h).symm⟩
  · cases h

/-! ### Keys -/

theorem pKey_app {k : Key} {r : Bytes} (h : k.Wf) : pKey.run (k.enc ++ r) = some (k, r) := by
  rcases k with ⟨s, pk⟩
  obtain ⟨hs, hn⟩ := keyBytes_some h
  dsimp only at hs hn
  have hl : pk.length < 256 ^ 2 := by rw [hn]; decide
  have h1 : (nat 1).run (natBE 1 s ++ (natBE 2 pk.length ++ (pk ++ r))) = some (s, natBE 2 pk.length ++ (pk ++ r)) :=
    nat_app (by rw [hs]; decide) (Nat.zero_le _) (by rw [hs]; decide)
  have h2 := blob_app (lo := 0) (hi := 65535) (s := pk) (r := r) hl (Nat.zero_le _) (by rw [hn]; decide)
  have h3 : (keyBytes s == some pk.length) = true := by rw [show keyBytes s = some pk.length from h]; exact beq_self_eq_true _
  simp [pKey, Key.enc, StateT.run_bind, List.append_assoc, h1, h2, h3, need_true]

theorem pKey_inv {b r : Bytes} {k : Key} (h : pKey.run b = some (k, r)) : b = k.enc ++ r ∧ k.Wf := by
  simp only [pKey, StateT.run_bind] at h
  obtain ⟨⟨s, m1⟩, h1, h⟩ := bind_some h
  obtain ⟨⟨pk, m2⟩, h2, h⟩ := bind_some h
  obtain ⟨⟨u, m3⟩, h3, h⟩ := bind_some h
  have hok := need_ok h3
  have e3 := need_rest h3
  simp only [StateT.run_pure, Option.pure_def, Option.some.injEq, Prod.mk.injEq] at h
  obtain ⟨rfl, rfl⟩ := h
  have e1 := (nat_inv h1).1
  have e2 := (blob_inv h2).1
  subst e1 e2 e3
  exact ⟨by simp only [Key.enc, List.append_assoc], eq_of_beq hok⟩

/-! ### The shard-count chain -/

theorem chainOk_bounds {c : List Nat} (h : chainOk c = true) : c.length ≤ maxChain ∧ ∀ n ∈ c, n < 2 ^ 32 := by
  simp only [chainOk, Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true] at h
  exact ⟨h.1.1.2, fun n hn => (h.1.2 n hn).2⟩

theorem chain_length (c : List Nat) : (c.flatMap (natBE 4)).length = 4 * c.length := by
  induction c with
  | nil => rfl
  | cons n c ih => simp only [List.flatMap_cons, List.length_append, natBE_length, ih, List.length_cons]; omega

theorem chain_app : ∀ (c : List Nat) (r : Bytes), (∀ n ∈ c, n < 2 ^ 32) →
    (many (nat 4) c.length).run (c.flatMap (natBE 4) ++ r) = some (c, r)
  | [], _, _ => rfl
  | n :: c, r, h => by
    have hn : n < 2 ^ 32 := h n (List.mem_cons_self ..)
    have ih := chain_app c r fun m hm => h m (List.mem_cons_of_mem _ hm)
    have h1 : (nat 4).run (natBE 4 n ++ (c.flatMap (natBE 4) ++ r)) = some (n, c.flatMap (natBE 4) ++ r) :=
      nat_app (by rw [show (256 : Nat) ^ 4 = 2 ^ 32 by decide]; exact hn) (Nat.zero_le _)
        (Nat.le_trans (Nat.le_of_lt hn) (by decide))
    simp [many, StateT.run_bind, List.append_assoc, h1, ih]

/-! ### The certificate -/

theorem pKeyCert_app {x : KeyCert} {r : Bytes} (hw : x.FieldsOk) (hr : x.rootSig.length ≤ 65535)
    (hc : x.coSig.length ≤ 65535) : pKeyCert.run (x.encode ++ r) = some (x, r) := by
  rcases x with ⟨tn, ep, lk, ch, k, vk, rs, cs⟩
  obtain ⟨hTn, hEp, hLk, hCh, hK, hVk⟩ := hw
  dsimp only at hTn hEp hLk hCh hK hVk hr hc
  obtain ⟨hg, hAll⟩ := chainOk_bounds hCh
  have m8 : maxNat < 256 ^ 8 := by decide
  have hG : ch.length < 256 ^ 1 := Nat.lt_of_le_of_lt hg (by decide)
  simp [pKeyCert, KeyCert.encode, KeyCert.body, digest, StateT.run_bind, List.append_assoc, expect_app,
    show ∀ r, ident.run (identField tn ++ r) = some (tn, r) from fun _ => ident_app hTn, nat_app (Nat.lt_of_le_of_lt hEp m8) (Nat.zero_le _) hEp, take_app hLk,
    nat_app hG (Nat.zero_le _) (Nat.le_trans (Nat.le_of_lt hG) (by decide : 256 ^ 1 ≤ maxNat)), chain_app ch _ hAll,
    hCh, need_true, pKey_app hK, pKey_app hVk,
    blob_app (lo := 0) (hi := 65535) (Nat.lt_of_le_of_lt hr (by decide)) (Nat.zero_le _) hr,
    blob_app (lo := 0) (hi := 65535) (Nat.lt_of_le_of_lt hc (by decide)) (Nat.zero_le _) hc]

theorem pKeyCert_inv {b r : Bytes} {x : KeyCert} (h : pKeyCert.run b = some (x, r)) :
    b = x.encode ++ r ∧ x.FieldsOk := by
  simp only [pKeyCert, StateT.run_bind] at h
  obtain ⟨⟨u0, m0⟩, h0, h⟩ := bind_some h
  obtain ⟨⟨tn, m1⟩, h1, h⟩ := bind_some h
  obtain ⟨⟨ep, m2⟩, h2, h⟩ := bind_some h
  obtain ⟨⟨lk, m3⟩, h3, h⟩ := bind_some h
  obtain ⟨⟨g, m4⟩, h4, h⟩ := bind_some h
  obtain ⟨⟨ch, m5⟩, h5, h⟩ := bind_some h
  obtain ⟨⟨u6, m6⟩, h6, h⟩ := bind_some h
  obtain ⟨⟨k, m7⟩, h7, h⟩ := bind_some h
  obtain ⟨⟨vk, m8⟩, h8, h⟩ := bind_some h
  obtain ⟨⟨rs, m9⟩, h9, h⟩ := bind_some h
  obtain ⟨⟨cs, m10⟩, h10, h⟩ := bind_some h
  simp only [StateT.run_pure, Option.pure_def, Option.some.injEq, Prod.mk.injEq] at h
  obtain ⟨rfl, rfl⟩ := h
  have e0 := expect_run h0
  obtain ⟨e1, hTn⟩ := ident_inv h1
  obtain ⟨e2, -, hEp⟩ := nat_inv h2
  obtain ⟨e3, hLk⟩ := take_inv h3
  have e4 := (nat_inv h4).1
  obtain ⟨e5, hg, -⟩ := ParseLaws.many_run (p := nat 4) (e := natBE 4) (Q := fun _ => True)
    (fun hh => ⟨(nat_inv hh).1.symm, trivial⟩) g h5
  have hCh := need_ok h6
  have e6 := need_rest h6
  obtain ⟨e7, hK⟩ := pKey_inv h7
  obtain ⟨e8, hVk⟩ := pKey_inv h8
  have e9 := (blob_inv h9).1
  have e10 := (blob_inv h10).1
  subst e0 e1 e2 e3 e4 hg e5 e6 e7 e8 e9 e10
  exact ⟨by simp only [KeyCert.encode, KeyCert.body, identField, identBytes, List.append_assoc],
    hTn, hEp, hLk, hCh, hK, hVk⟩

/-- Nothing over the size bound decodes. -/
theorem decode_too_long {b : Bytes} (h : maxCertBytes < b.length) : decode b = none := by
  unfold decode parse
  rw [if_pos h]

/-- An accepted input is the encoding of the certificate returned, and that certificate is well formed. -/
theorem encode_decode {b : Bytes} {x : KeyCert} (h : decode b = some x) : x.encode = b ∧ x.Wf := by
  obtain ⟨e, hf⟩ := pKeyCert_inv (parse_run h)
  rw [List.append_nil] at e
  exact ⟨e.symm, hf, by rw [← e]; exact Nat.le_of_not_lt fun hl => by rw [decode_too_long hl] at h; cases h⟩

/-- The decoder inverts the encoder. -/
theorem decode_encode {x : KeyCert} (hw : x.Wf) : decode x.encode = some x := by
  have hl : x.encode.length ≤ 16384 := hw.2
  have hs : x.rootSig.length ≤ 65535 ∧ x.coSig.length ≤ 65535 := by
    simp only [KeyCert.encode, List.length_append] at hl
    omega
  have hp := pKeyCert_app (r := []) hw.1 hs.1 hs.2
  rw [List.append_nil] at hp
  unfold decode parse
  rw [if_neg (Nat.not_lt.mpr hw.2), hp]

/-- The decoder accepts exactly the encodings of well-formed certificates. -/
theorem decode_iff {b : Bytes} {x : KeyCert} : decode b = some x ↔ x.Wf ∧ x.encode = b :=
  ⟨fun h => ⟨(encode_decode h).2, (encode_decode h).1⟩, fun ⟨hw, e⟩ => e ▸ decode_encode hw⟩

/-- The decoder decides every input: it returns the one well-formed certificate the input encodes, or the input
    encodes none and is refused. -/
theorem decode_total (b : Bytes) :
    (∃ x, decode b = some x ∧ x.Wf ∧ x.encode = b) ∨ (decode b = none ∧ ∀ x : KeyCert, x.Wf → x.encode ≠ b) := by
  cases h : decode b with
  | some x => exact .inl ⟨x, rfl, decode_iff.1 h⟩
  | none => exact .inr ⟨rfl, fun x hw e => by rw [decode_iff.2 ⟨hw, e⟩] at h; cases h⟩

/-- Every certified key is ML-DSA-87, the scheme of checkpoint signatures and cosignatures.  Registering a second
    scheme breaks this theorem, so which schemes may sign checkpoints is decided then, not passed over. -/
theorem decode_schemes {b : Bytes} {x : KeyCert} (h : decode b = some x) :
    x.key.scheme = 1 ∧ x.verifierKey.scheme = 1 :=
  have hf := (encode_decode h).2.1
  ⟨(keyBytes_some hf.2.2.2.2.1).1, (keyBytes_some hf.2.2.2.2.2).1⟩

/-- Two well-formed certificates with the same bytes are the same certificate. -/
theorem encode_injective {x y : KeyCert} (hx : x.Wf) (hy : y.Wf) (h : x.encode = y.encode) : x = y :=
  Option.some.inj ((decode_encode hx).symm.trans (h ▸ decode_encode hy))

/-! ### Size -/

theorem encode_length {x : KeyCert} (h : x.FieldsOk) :
    x.encode.length = 5289 + x.tenantId.length + 4 * x.chain.length + x.rootSig.length + x.coSig.length := by
  obtain ⟨-, -, hLk, -, hK, hVk⟩ := h
  have hk := (keyBytes_some hK).2
  have hv := (keyBytes_some hVk).2
  have ht : "RR/GATE/KEY-CERT/v2".toUTF8.toList.length = 19 := by first | decide +kernel | rfl | simp
  simp only [KeyCert.encode, KeyCert.body, Key.enc, certTag, identField, List.length_append, natBE_length,
    chain_length, hLk, ht, hk, hv, digestBytes, mlDsa87Key, List.length_cons, List.length_nil]
  omega

/-- With ML-DSA-87 signatures a certificate is 14,548 to 14,799 bytes. -/
theorem mlDsa87_length {x : KeyCert} (h : x.FieldsOk) (hr : x.rootSig.length = mlDsa87Signature)
    (hc : x.coSig.length = mlDsa87Signature) : 14548 ≤ x.encode.length ∧ x.encode.length ≤ 14799 := by
  have ht := identOk_len h.1
  have hg := (chainOk_bounds h.2.2.2.1).1
  have h0 : 0 < x.chain.length := by
    have := h.2.2.2.1
    simp only [chainOk, Bool.and_eq_true, decide_eq_true_eq] at this
    exact this.1.1.1
  rw [encode_length h, hr, hc]
  simp only [mlDsa87Signature, maxChain] at hg ⊢
  omega

/-- The size bound refuses no certificate with ML-DSA-87 signatures. -/
theorem mlDsa87_decodes {x : KeyCert} (h : x.FieldsOk) (hr : x.rootSig.length = mlDsa87Signature)
    (hc : x.coSig.length = mlDsa87Signature) : decode x.encode = some x :=
  decode_encode ⟨h, Nat.le_trans (mlDsa87_length h hr hc).2 (by decide)⟩

end BlindLedger.Gate.Cosign
