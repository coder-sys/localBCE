import BlindLedger.Gate.Cosign.Link
import BlindLedger.Gate.Cosign.CodecLaws

/-! AUTHORITY-LINK/v1 codec laws: the decoder accepts exactly the encodings of well-formed links and returns the link
    encoded (`decodeLink_iff`), so every accepted input is canonical and every other input is refused
    (`decodeLink_total`).  Its size bound refuses no link with ML-DSA-87 signatures (`link_mlDsa87_decodes`). -/
namespace BlindLedger.Gate.Cosign

open BlindLedger.Gate

/-- What the decoder checks of each field. -/
def SignedLink.FieldsOk (x : SignedLink) : Prop :=
  identOk x.tenantId = true ∧ x.gen ≤ maxGen ∧ x.base ≤ x.gen ∧ x.prev.length = digestBytes ∧ x.root.Wf ∧
    x.rootNext.length = digestBytes ∧ x.witness.Wf ∧ x.witnessNext.length = digestBytes ∧
    x.closedThrough.getD 0 ≤ maxNat ∧ x.approval.length = digestBytes

/-- A well-formed link: its fields pass, and its encoding is within the decoder's bound. -/
def SignedLink.Wf (x : SignedLink) : Prop := x.FieldsOk ∧ x.encode.length ≤ maxLinkBytes

theorem Change.ofTag_tag (c : Change) : Change.ofTag c.tag = c := by cases c <;> rfl

theorem Change.tag_ofTag {t : Nat} (h : t ≤ 2) : (Change.ofTag t).tag = t := by
  match t, h with
  | 0, _ => rfl
  | 1, _ => rfl
  | 2, _ => rfl

theorem closedField_wire {flag epoch : Nat} (hf : flag ≤ 1) (hn : (flag == 1 || epoch == 0) = true) :
    closedField (if flag == 1 then some epoch else none) = natBE 1 flag ++ natBE 8 epoch := by
  match flag, hf with
  | 0, _ =>
    have he : epoch = 0 := by simpa using hn
    subst he
    rfl
  | 1, _ => rfl

theorem pLink_app {x : SignedLink} {r : Bytes} (hw : x.FieldsOk) (hs : x.selfSig.length ≤ 65535)
    (hc : x.coSig.length ≤ 65535) : pLink.run (x.encode ++ r) = some (x, r) := by
  rcases x with ⟨tn, gn, bs, pv, ch, rt, rn, wt, wn, cl, ap, ss, cs⟩
  obtain ⟨hTn, hGn, hBs, hPv, hRt, hRn, hWt, hWn, hCl, hAp⟩ := hw
  dsimp only at hTn hGn hBs hPv hRt hRn hWt hWn hCl hAp hs hc
  have g4 : gn < 256 ^ 4 := Nat.lt_of_le_of_lt hGn (by decide)
  have m8 : maxNat < 256 ^ 8 := by decide
  have hTag : ch.tag ≤ 2 := by cases ch <;> decide
  cases cl with
  | none =>
    simp [pLink, SignedLink.encode, SignedLink.body, closedField, digest, StateT.run_bind, List.append_assoc,
      expect_app, show ∀ r, ident.run (identField tn ++ r) = some (tn, r) from fun _ => ident_app hTn,
      nat_app (w := 4) (lo := 0) (hi := maxGen) g4 (Nat.zero_le _) hGn,
      nat_app (w := 4) (lo := 0) (hi := gn) (Nat.lt_of_le_of_lt hBs g4) (Nat.zero_le _) hBs,
      take_app hPv, take_app hRn, take_app hWn, take_app hAp,
      nat_app (w := 1) (lo := 0) (hi := 2) (Nat.lt_of_le_of_lt hTag (by decide)) (Nat.zero_le _) hTag,
      Change.ofTag_tag, pKey_app hRt, pKey_app hWt,
      nat_app (w := 1) (lo := 0) (hi := 1) (v := 0) (by decide) (Nat.le_refl _) (by decide),
      nat_app (w := 8) (lo := 0) (hi := maxNat) (v := 0) (by decide) (Nat.le_refl _) (Nat.zero_le _), need_true,
      blob_app (lo := 0) (hi := 65535) (Nat.lt_of_le_of_lt hs (by decide)) (Nat.zero_le _) hs,
      blob_app (lo := 0) (hi := 65535) (Nat.lt_of_le_of_lt hc (by decide)) (Nat.zero_le _) hc]
  | some e =>
    have he : e ≤ maxNat := hCl
    simp [pLink, SignedLink.encode, SignedLink.body, closedField, digest, StateT.run_bind, List.append_assoc,
      expect_app, show ∀ r, ident.run (identField tn ++ r) = some (tn, r) from fun _ => ident_app hTn,
      nat_app (w := 4) (lo := 0) (hi := maxGen) g4 (Nat.zero_le _) hGn,
      nat_app (w := 4) (lo := 0) (hi := gn) (Nat.lt_of_le_of_lt hBs g4) (Nat.zero_le _) hBs,
      take_app hPv, take_app hRn, take_app hWn, take_app hAp,
      nat_app (w := 1) (lo := 0) (hi := 2) (Nat.lt_of_le_of_lt hTag (by decide)) (Nat.zero_le _) hTag,
      Change.ofTag_tag, pKey_app hRt, pKey_app hWt,
      nat_app (w := 1) (lo := 0) (hi := 1) (v := 1) (by decide) (Nat.zero_le _) (Nat.le_refl _),
      nat_app (w := 8) (lo := 0) (hi := maxNat) (Nat.lt_of_le_of_lt he m8) (Nat.zero_le _) he, need_true,
      blob_app (lo := 0) (hi := 65535) (Nat.lt_of_le_of_lt hs (by decide)) (Nat.zero_le _) hs,
      blob_app (lo := 0) (hi := 65535) (Nat.lt_of_le_of_lt hc (by decide)) (Nat.zero_le _) hc]

theorem pLink_inv {b r : Bytes} {x : SignedLink} (h : pLink.run b = some (x, r)) :
    b = x.encode ++ r ∧ x.FieldsOk := by
  simp only [pLink, StateT.run_bind] at h
  obtain ⟨⟨u0, m0⟩, h0, h⟩ := bind_some h
  obtain ⟨⟨tn, m1⟩, h1, h⟩ := bind_some h
  obtain ⟨⟨gn, m2⟩, h2, h⟩ := bind_some h
  obtain ⟨⟨bs, m3⟩, h3, h⟩ := bind_some h
  obtain ⟨⟨pv, m4⟩, h4, h⟩ := bind_some h
  obtain ⟨⟨tg, m5⟩, h5, h⟩ := bind_some h
  obtain ⟨⟨rt, m6⟩, h6, h⟩ := bind_some h
  obtain ⟨⟨rn, m7⟩, h7, h⟩ := bind_some h
  obtain ⟨⟨wt, m8⟩, h8, h⟩ := bind_some h
  obtain ⟨⟨wn, m9⟩, h9, h⟩ := bind_some h
  obtain ⟨⟨fl, m10⟩, h10, h⟩ := bind_some h
  obtain ⟨⟨ep, m11⟩, h11, h⟩ := bind_some h
  obtain ⟨⟨u12, m12⟩, h12, h⟩ := bind_some h
  obtain ⟨⟨ap, m13⟩, h13, h⟩ := bind_some h
  obtain ⟨⟨ss, m14⟩, h14, h⟩ := bind_some h
  obtain ⟨⟨cs, m15⟩, h15, h⟩ := bind_some h
  simp only [StateT.run_pure, Option.pure_def, Option.some.injEq, Prod.mk.injEq] at h
  obtain ⟨rfl, rfl⟩ := h
  have e0 := expect_run h0
  obtain ⟨e1, hTn⟩ := ident_inv h1
  obtain ⟨e2, -, hGn⟩ := nat_inv h2
  obtain ⟨e3, -, hBs⟩ := nat_inv h3
  obtain ⟨e4, hPv⟩ := take_inv h4
  obtain ⟨e5, -, hTg⟩ := nat_inv h5
  obtain ⟨e6, hRt⟩ := pKey_inv h6
  obtain ⟨e7, hRn⟩ := take_inv h7
  obtain ⟨e8, hWt⟩ := pKey_inv h8
  obtain ⟨e9, hWn⟩ := take_inv h9
  obtain ⟨e10, -, hFl⟩ := nat_inv h10
  obtain ⟨e11, -, hEp⟩ := nat_inv h11
  have hNeed := need_ok h12
  have e12 := need_rest h12
  obtain ⟨e13, hAp⟩ := take_inv h13
  have e14 := (blob_inv h14).1
  have e15 := (blob_inv h15).1
  subst e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 e10 e11 e12 e13 e14 e15
  refine ⟨?_, hTn, hGn, hBs, hPv, hRt, hRn, hWt, hWn, ?_, hAp⟩
  · simp only [SignedLink.encode, SignedLink.body, identField, identBytes, List.append_assoc,
      Change.tag_ofTag hTg, closedField_wire hFl hNeed]
  · show (if fl == 1 then some ep else none).getD 0 ≤ maxNat
    split
    · exact hEp
    · exact Nat.zero_le _

/-- Nothing over the size bound decodes. -/
theorem decodeLink_too_long {b : Bytes} (h : maxLinkBytes < b.length) : decodeLink b = none := by
  unfold decodeLink parse
  rw [if_pos h]

/-- An accepted input is the encoding of the link returned, and that link is well formed. -/
theorem encode_decodeLink {b : Bytes} {x : SignedLink} (h : decodeLink b = some x) : x.encode = b ∧ x.Wf := by
  obtain ⟨e, hf⟩ := pLink_inv (parse_run h)
  rw [List.append_nil] at e
  exact ⟨e.symm, hf, by rw [← e]; exact Nat.le_of_not_lt fun hl => by rw [decodeLink_too_long hl] at h; cases h⟩

/-- The decoder inverts the encoder. -/
theorem decodeLink_encode {x : SignedLink} (hw : x.Wf) : decodeLink x.encode = some x := by
  have hl : x.encode.length ≤ 16384 := hw.2
  have hs : x.selfSig.length ≤ 65535 ∧ x.coSig.length ≤ 65535 := by
    simp only [SignedLink.encode, List.length_append] at hl
    omega
  have hp := pLink_app (r := []) hw.1 hs.1 hs.2
  rw [List.append_nil] at hp
  unfold decodeLink parse
  rw [if_neg (Nat.not_lt.mpr hw.2), hp]

/-- The decoder accepts exactly the encodings of well-formed links. -/
theorem decodeLink_iff {b : Bytes} {x : SignedLink} : decodeLink b = some x ↔ x.Wf ∧ x.encode = b :=
  ⟨fun h => ⟨(encode_decodeLink h).2, (encode_decodeLink h).1⟩, fun ⟨hw, e⟩ => e ▸ decodeLink_encode hw⟩

/-- The decoder decides every input: it returns the one well-formed link the input encodes, or the input encodes
    none and is refused. -/
theorem decodeLink_total (b : Bytes) :
    (∃ x, decodeLink b = some x ∧ x.Wf ∧ x.encode = b) ∨
      (decodeLink b = none ∧ ∀ x : SignedLink, x.Wf → x.encode ≠ b) := by
  cases h : decodeLink b with
  | some x => exact .inl ⟨x, rfl, decodeLink_iff.1 h⟩
  | none => exact .inr ⟨rfl, fun x hw e => by rw [decodeLink_iff.2 ⟨hw, e⟩] at h; cases h⟩

/-- A link's identity covers every field but the two signatures: two well-formed links with the same body differ
    at most in their signatures. -/
theorem body_injective {x y : SignedLink} (hx : x.Wf) (hy : y.Wf) (h : x.body = y.body) :
    { y with selfSig := x.selfSig, coSig := x.coSig } = x := by
  have hy' : ({ y with selfSig := x.selfSig, coSig := x.coSig } : SignedLink).FieldsOk := hy.1
  have he : ({ y with selfSig := x.selfSig, coSig := x.coSig } : SignedLink).encode = x.encode := by
    have hb : ({ y with selfSig := x.selfSig, coSig := x.coSig } : SignedLink).body = y.body := rfl
    unfold SignedLink.encode
    rw [hb, h]
  have hw : ({ y with selfSig := x.selfSig, coSig := x.coSig } : SignedLink).Wf := ⟨hy', by rw [he]; exact hx.2⟩
  exact Option.some.inj ((decodeLink_encode hw).symm.trans (he ▸ decodeLink_encode hx))

/-! ### Size -/

theorem link_encode_length {x : SignedLink} (h : x.FieldsOk) :
    x.encode.length = 5496 + x.tenantId.length + x.selfSig.length + x.coSig.length := by
  obtain ⟨-, -, -, hPv, hRt, hRn, hWt, hWn, -, hAp⟩ := h
  have hr := (keyBytes_some hRt).2
  have hw := (keyBytes_some hWt).2
  have ht : "RR/GATE/AUTHORITY-LINK/v1".toUTF8.toList.length = 25 := by first | decide +kernel | rfl | simp
  have hcl : (closedField x.closedThrough).length = 9 := by
    cases x.closedThrough <;> simp only [closedField, List.length_append, natBE_length]
  simp only [SignedLink.encode, SignedLink.body, Key.enc, linkTag, identField, List.length_append, natBE_length,
    hPv, hRn, hWn, hAp, ht, hr, hw, hcl, digestBytes, mlDsa87Key, List.length_cons, List.length_nil]
  omega

/-- The size bound refuses no link with ML-DSA-87 signatures. -/
theorem link_mlDsa87_decodes {x : SignedLink} (h : x.FieldsOk) (hs : x.selfSig.length = mlDsa87Signature)
    (hc : x.coSig.length = mlDsa87Signature) : decodeLink x.encode = some x := by
  refine decodeLink_encode ⟨h, ?_⟩
  have ht := identOk_len h.1
  rw [link_encode_length h, hs, hc]
  simp only [mlDsa87Signature, maxLinkBytes]
  omega

end BlindLedger.Gate.Cosign
