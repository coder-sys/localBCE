import BlindLedger.Gate.Authority
import BlindLedger.Gate.ParseLaws
import BlindLedger.Gate.CheckpointTheorems

namespace BlindLedger.Gate.Authority

open BlindLedger.Gate

/-! APPROVAL/v2 laws: the codec round-trips exactly on well-formed frames, and admission mints a `Grant` or `Bypass`
    only from bytes that decode, name the batch's state and tenant, lie in their window and carry the quorum. -/

def EntryWf (e : Entry) : Prop :=
  identOk e.program = true ∧ 1 ≤ e.flows ∧ e.flows ≤ 31 ∧ e.holds < reasonMask ∧
    ((e.authority == .HOLD) == (e.holds != 0)) = true

def BodyWf : Body → Prop
  | .grant s es => s ≤ maxNat ∧ 1 ≤ es.length ∧ es.length ≤ 32 ∧ (∀ e ∈ es, EntryWf e) ∧ okEntries es = true
  | .bypass p q r o => identOk p = true ∧ identOk q = true ∧ r.length = digestBytes ∧ 1 ≤ o ∧ o < reasonMask

def DocWf (a : Doc) : Prop :=
  a.state.length = digestBytes ∧ identOk a.tenantId = true ∧ spanOk a.notBefore a.notAfter = true ∧ BodyWf a.body

def Frame.Wf (f : Frame) : Prop := DocWf f.a ∧ Keyset.SigsWf f.sigs

theorem reasonMask_eq : reasonMask = 16777216 := rfl

theorem lt32_maxNat {n : Nat} (h : n < 256 ^ 4) : n ≤ maxNat := by unfold maxNat; omega

theorem identField_eq (s : Bytes) : identField s = identBytes s := rfl

theorem authOf_authByte (a : Gate.Authority) : SnapshotV2.authOf (SnapshotV2.authByte a) = some a := by
  cases a <;> rfl

theorem authOf_eq {n : Nat} {a : Gate.Authority} (h : SnapshotV2.authOf n = some a) : n = SnapshotV2.authByte a := by
  cases a <;> rcases n with _ | _ | _ | _ | n <;> simp_all [SnapshotV2.authOf, SnapshotV2.authByte]

theorem validDate_lt {d : Nat} (h : Rules.validDate d = true) : d < 256 ^ 4 := by
  unfold Rules.validDate at h
  simp only [Bool.and_eq_true, decide_eq_true_eq] at h
  omega

theorem spanOk_lt {nb na : Nat} (h : spanOk nb na = true) : nb < 256 ^ 4 ∧ na < 256 ^ 4 := by
  simp only [spanOk, Bool.and_eq_true, decide_eq_true_eq] at h
  exact ⟨validDate_lt h.1.1.1, validDate_lt h.1.1.2⟩

/-! ### Decoded bytes are canonical -/

theorem pEntry_inv {b r : Bytes} {e : Entry} (h : pEntry.run b = some (e, r)) : b = encEntry e ++ r ∧ EntryWf e := by
  simp only [pEntry, StateT.run_bind] at h
  obtain ⟨⟨p, m1⟩, h1, h⟩ := bind_some h
  obtain ⟨⟨fl, m2⟩, h2, h⟩ := bind_some h
  obtain ⟨⟨ab, m3⟩, h3, h⟩ := bind_some h
  obtain ⟨⟨ho, m4⟩, h4, h⟩ := bind_some h
  rcases hau : SnapshotV2.authOf ab with _ | au
  · simp only [hau] at h
    change (none : Option (Entry × Bytes)) = some (e, r) at h
    cases h
  · simp only [hau, StateT.run_bind] at h
    obtain ⟨⟨u, m5⟩, h5, h⟩ := bind_some h
    simp only [StateT.run_pure, Option.pure_def, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    dsimp only at *
    obtain ⟨e1, i1⟩ := ident_inv h1
    obtain ⟨e2, f1, f2⟩ := nat_inv h2
    obtain ⟨e3, a1, a2⟩ := nat_inv h3
    obtain ⟨e4, -, h4'⟩ := nat_inv h4
    have e5 := need_rest h5
    have ok := need_ok h5
    have hab := authOf_eq hau
    subst e1 e2 e3 e4 e5 hab
    have hm := reasonMask_eq
    exact ⟨by simp [encEntry, identField_eq], i1, f1, f2, (by show ho < reasonMask; omega), ok⟩

theorem pGrant_inv {b r : Bytes} {x : Body} (h : pGrant.run b = some (x, r)) :
    (∃ s es, x = .grant s es) ∧ b = encBody x ++ r ∧ BodyWf x := by
  simp only [pGrant, StateT.run_bind] at h
  obtain ⟨⟨s, m1⟩, h1, h⟩ := bind_some h
  obtain ⟨⟨n, m2⟩, h2, h⟩ := bind_some h
  obtain ⟨⟨es, m3⟩, h3, h⟩ := bind_some h
  obtain ⟨⟨u, m4⟩, h4, h⟩ := bind_some h
  simp only [StateT.run_pure, Option.pure_def, Option.some.injEq, Prod.mk.injEq] at h
  obtain ⟨rfl, rfl⟩ := h
  dsimp only at *
  obtain ⟨e1, -, s2⟩ := nat_inv h1
  obtain ⟨e2, n1, n2⟩ := nat_inv h2
  obtain ⟨e3, hl, hq⟩ := ParseLaws.many_run (e := encEntry) (Q := EntryWf)
    (fun h => ⟨((pEntry_inv h).1).symm, (pEntry_inv h).2⟩) n h3
  have e4 := need_rest h4
  have ok := need_ok h4
  subst e1 e2 e4 hl
  refine ⟨⟨_, _, rfl⟩, ?_, s2, n1, n2, hq, ok⟩
  rw [← e3]; simp [encBody, List.append_assoc]

theorem pBypass_inv {b r : Bytes} {x : Body} (h : pBypass.run b = some (x, r)) :
    (∃ p q d o, x = .bypass p q d o) ∧ b = encBody x ++ r ∧ BodyWf x := by
  simp only [pBypass, StateT.run_bind] at h
  obtain ⟨⟨p, m1⟩, h1, h⟩ := bind_some h
  obtain ⟨⟨q, m2⟩, h2, h⟩ := bind_some h
  obtain ⟨⟨d, m3⟩, h3, h⟩ := bind_some h
  obtain ⟨⟨o, m4⟩, h4, h⟩ := bind_some h
  simp only [StateT.run_pure, Option.pure_def, Option.some.injEq, Prod.mk.injEq] at h
  obtain ⟨rfl, rfl⟩ := h
  dsimp only at *
  obtain ⟨e1, i1⟩ := ident_inv h1
  obtain ⟨e2, i2⟩ := ident_inv h2
  obtain ⟨e3, l3⟩ := take_inv h3
  obtain ⟨e4, o1, o2⟩ := nat_inv h4
  subst e1 e2 e3 e4
  have hm := reasonMask_eq
  exact ⟨⟨_, _, _, _, rfl⟩, by simp [encBody, identField_eq, List.append_assoc], i1, i2, l3, o1, by omega⟩

theorem pDoc_inv {b r : Bytes} {a : Doc} (h : pDoc.run b = some (a, r)) : b = encDoc a ++ r ∧ DocWf a := by
  simp only [pDoc, StateT.run_bind] at h
  obtain ⟨⟨u0, m0⟩, h0, h⟩ := bind_some h
  obtain ⟨⟨k, m1⟩, h1, h⟩ := bind_some h
  obtain ⟨⟨st, m2⟩, h2, h⟩ := bind_some h
  obtain ⟨⟨tn, m3⟩, h3, h⟩ := bind_some h
  obtain ⟨⟨nb, m4⟩, h4, h⟩ := bind_some h
  obtain ⟨⟨na, m5⟩, h5, h⟩ := bind_some h
  obtain ⟨⟨u6, m6⟩, h6, h⟩ := bind_some h
  obtain ⟨⟨bd, m7⟩, h7, h⟩ := bind_some h
  simp only [StateT.run_pure, Option.pure_def, Option.some.injEq, Prod.mk.injEq] at h
  obtain ⟨rfl, rfl⟩ := h
  dsimp only at *
  have e0 := expect_run h0
  obtain ⟨e1, k1, k2⟩ := nat_inv h1
  obtain ⟨e2, l2⟩ := take_inv h2
  obtain ⟨e3, i3⟩ := ident_inv h3
  obtain ⟨e4, -⟩ := nat_inv h4
  obtain ⟨e5, -⟩ := nat_inv h5
  have e6 := need_rest h6
  have ok := need_ok h6
  subst e0 e1 e2 e3 e4 e5 e6
  by_cases hk : k = 1
  · subst hk
    simp only [if_true] at h7
    obtain ⟨⟨s, es, rfl⟩, e7, w7⟩ := pGrant_inv h7
    subst e7
    exact ⟨by simp [encDoc, kindByte, identField_eq, List.append_assoc], l2, i3, ok, w7⟩
  · have hk2 : k = 2 := by omega
    subst hk2
    have hn : ¬ ((2 : Nat) = 1) := by decide
    simp only [hn, if_false] at h7
    obtain ⟨⟨p, q, d, o, rfl⟩, e7, w7⟩ := pBypass_inv h7
    subst e7
    exact ⟨by simp [encDoc, kindByte, identField_eq, List.append_assoc], l2, i3, ok, w7⟩

theorem decode_wf {x : Bytes} {f : Frame} (h : decode x = some f) : Frame.Wf f := by
  unfold decode at h
  rcases hp : pDoc.run x with _ | ⟨a, rest⟩
  · simp [hp] at h
  · simp only [hp] at h
    rcases hs : Keyset.decodeSigBlock rest with _ | ss
    · simp [hs] at h
    · simp only [hs, Option.map_some, Option.some.injEq] at h
      subst h
      exact ⟨(pDoc_inv hp).2, (Keyset.decodeSigBlock_spec hs).2⟩

theorem encode_decode {x : Bytes} {f : Frame} (h : decode x = some f) : encode f = x := by
  unfold decode at h
  rcases hp : pDoc.run x with _ | ⟨a, rest⟩
  · simp [hp] at h
  · simp only [hp] at h
    rcases hs : Keyset.decodeSigBlock rest with _ | ss
    · simp [hs] at h
    · simp only [hs, Option.map_some, Option.some.injEq] at h
      subst h
      obtain ⟨e, -⟩ := pDoc_inv hp
      rw [(Keyset.decodeSigBlock_spec hs).1] at e
      simpa [encode, Frame.unsigned] using e.symm

/-! ### Well-formed frames decode -/

theorem pEntry_app {e : Entry} (h : EntryWf e) (r : Bytes) : pEntry.run (encEntry e ++ r) = some (e, r) := by
  obtain ⟨h1, h2, h3, h4, h5⟩ := h
  have hm := reasonMask_eq
  have n1 := @nat_app 1 1 31 e.flows (natBE 1 (SnapshotV2.authByte e.authority) ++ (natBE 4 e.holds ++ r)) (by omega)
    (by omega) (by omega)
  have hab : 1 ≤ SnapshotV2.authByte e.authority ∧ SnapshotV2.authByte e.authority ≤ 3 := by
    cases e.authority <;> simp [SnapshotV2.authByte]
  have n2 := @nat_app 1 1 3 (SnapshotV2.authByte e.authority) (natBE 4 e.holds ++ r) (by omega) hab.1 hab.2
  have n3 := @nat_app 4 0 (reasonMask - 1) e.holds r (by omega) (by omega) (by omega)
  simp [pEntry, StateT.run_bind, encEntry, identField_eq, List.append_assoc, ident_app h1, n1, n2, n3, authOf_authByte,
    h5, need_true]

theorem many_app {α : Type} {p : P α} {e : α → Bytes} :
    ∀ (xs : List α), (∀ x ∈ xs, ∀ r, p.run (e x ++ r) = some (x, r)) → ∀ r,
      (many p xs.length).run (xs.flatMap e ++ r) = some (xs, r)
  | [], _, r => by simp [many]
  | x :: xs, hp, r => by
    have h1 := hp x (List.mem_cons_self ..) (xs.flatMap e ++ r)
    have h2 := many_app xs (fun y hy => hp y (List.mem_cons_of_mem _ hy)) r
    simp [many, List.flatMap_cons, List.append_assoc, StateT.run_bind, h1, h2]

theorem pGrant_app {s : Nat} {es : List Entry} (h : BodyWf (.grant s es)) (r : Bytes) :
    pGrant.run (encBody (.grant s es) ++ r) = some (.grant s es, r) := by
  obtain ⟨h1, h2, h3, h4, h5⟩ := h
  have n1 := @nat_app 8 0 maxNat s (natBE 1 es.length ++ (es.flatMap encEntry ++ r)) (by unfold maxNat at h1; omega)
    (by omega) h1
  have n2 := @nat_app 1 1 32 es.length (es.flatMap encEntry ++ r) (by omega) h2 h3
  have n3 := many_app (p := pEntry) (e := encEntry) es (fun x hx r => pEntry_app (h4 x hx) r) r
  simp [pGrant, StateT.run_bind, encBody, List.append_assoc, n1, n2, n3, h5, need_true]

theorem pBypass_app {p q d : Bytes} {o : Nat} (h : BodyWf (.bypass p q d o)) (r : Bytes) :
    pBypass.run (encBody (.bypass p q d o) ++ r) = some (.bypass p q d o, r) := by
  obtain ⟨h1, h2, h3, h4, h5⟩ := h
  have hm := reasonMask_eq
  have n3 := @take_app digestBytes d (natBE 4 o ++ r) h3
  have n4 := @nat_app 4 1 (reasonMask - 1) o r (by omega) h4 (by omega)
  simp [pBypass, StateT.run_bind, encBody, identField_eq, List.append_assoc, ident_app h1, ident_app h2, digest, n3, n4]

theorem pDoc_app {a : Doc} (h : DocWf a) (r : Bytes) : pDoc.run (encDoc a ++ r) = some (a, r) := by
  obtain ⟨h1, h2, h3, h4⟩ := h
  obtain ⟨hb, ha⟩ := spanOk_lt h3
  obtain ⟨st, tn, nb, na, bd⟩ := a
  simp only at h1 h2 h3 h4 hb ha
  have hb' := lt32_maxNat hb
  have ha' := lt32_maxNat ha
  cases bd with
  | grant s es =>
    have g := pGrant_app h4 r
    simp [pDoc, StateT.run_bind, encDoc, kindByte, identField_eq, List.append_assoc, expect_app, nat_app, hb, ha, hb',
      ha', h3, g, ident_app h2, take_app (n := digestBytes) h1, digest, need_true]
  | bypass p q d o =>
    have g := pBypass_app h4 r
    simp [pDoc, StateT.run_bind, encDoc, kindByte, identField_eq, List.append_assoc, expect_app, nat_app, hb, ha, hb',
      ha', h3, g, ident_app h2, take_app (n := digestBytes) h1, digest, need_true]

theorem decode_encode {f : Frame} (h : f.Wf) : decode (encode f) = some f := by
  obtain ⟨h1, h2⟩ := h
  have hs := Keyset.decodeSigBlock_encode h2
  simp [decode, encode, Frame.unsigned, pDoc_app h1, hs]

/-! ### Admission is sound -/

variable {verify : Bytes → Bytes → Bytes → Bool} {H : SnapshotV2.Head} {t : Bytes} {floor : Nat} {x : Bytes}

theorem admitGrant_sound {g : Grant} (h : admitGrant verify H t floor x = .ok g) :
    ∃ f, decode x = some f ∧ g.id = sha3 f.unsigned ∧ f.a.state = H.ks.state ∧ f.a.tenantId = t ∧
      Rules.dayNum f.a.notBefore ≤ Rules.dayNum H.day ∧ Rules.dayNum H.day ≤ Rules.dayNum f.a.notAfter ∧
      floor ≤ g.serial ∧
      Keyset.quorum verify (Keyset.rosterOk H.day) (·.employee) H.ks H.ks.kRoster (msgOf f) f.sigs = true := by
  unfold admitGrant at h
  rcases hd : decode x with _ | f
  · simp only [hd] at h; cases h
  · simp only [hd] at h
    rcases hb : f.a.body with ⟨s, es⟩ | ⟨p, q, d, o⟩
    · simp only [hb] at h
      by_cases c1 : (f.a.state != H.ks.state || f.a.tenantId != t) = true
      · rw [if_pos c1] at h; cases h
      rw [if_neg c1] at h
      by_cases c2 : (!windowOk f.a.notBefore f.a.notAfter H.day) = true
      · rw [if_pos c2] at h; cases h
      rw [if_neg c2] at h
      by_cases c3 : s < floor
      · rw [if_pos c3] at h; cases h
      rw [if_neg c3] at h
      by_cases c4 : (!Keyset.quorum verify (Keyset.rosterOk H.day) (·.employee) H.ks H.ks.kRoster (msgOf f) f.sigs) = true
      · rw [if_pos c4] at h; cases h
      rw [if_neg c4] at h
      cases h
      have s1 : f.a.state = H.ks.state := Classical.byContradiction fun hne => c1 (by simp [hne])
      have s2 : f.a.tenantId = t := Classical.byContradiction fun hne => c1 (by simp [hne])
      have w1 : Rules.dayNum f.a.notBefore ≤ Rules.dayNum H.day :=
        Classical.byContradiction fun hne => c2 (by simp [windowOk]; omega)
      have w2 : Rules.dayNum H.day ≤ Rules.dayNum f.a.notAfter :=
        Classical.byContradiction fun hne => c2 (by simp [windowOk]; omega)
      have q : Keyset.quorum verify (Keyset.rosterOk H.day) (·.employee) H.ks H.ks.kRoster (msgOf f) f.sigs = true :=
        Classical.byContradiction fun hne => c4 (by simp [hne])
      exact ⟨f, rfl, rfl, s1, s2, w1, w2, (by show floor ≤ s; omega), q⟩
    · simp only [hb] at h; cases h

theorem admitGrant_superseded {f : Frame} {s : Nat} {es : List Entry} (hd : decode x = some f)
    (hs : f.a.body = .grant s es) (hl : s < floor) : ∀ g, admitGrant verify H t floor x ≠ .ok g := by
  intro g h
  unfold admitGrant at h
  simp only [hd, hs] at h
  by_cases c1 : (f.a.state != H.ks.state || f.a.tenantId != t) = true
  · rw [if_pos c1] at h; cases h
  rw [if_neg c1] at h
  by_cases c2 : (!windowOk f.a.notBefore f.a.notAfter H.day) = true
  · rw [if_pos c2] at h; cases h
  rw [if_neg c2] at h
  rw [if_pos hl] at h
  cases h

theorem admitBypass_sound {b : Bypass} (h : admitBypass verify H t x = some b) :
    ∃ f, decode x = some f ∧ b.id = sha3 f.unsigned ∧ f.a.state = H.ks.state ∧ f.a.tenantId = t ∧
      Rules.dayNum f.a.notBefore ≤ Rules.dayNum H.day ∧ Rules.dayNum H.day ≤ Rules.dayNum f.a.notAfter ∧
      Keyset.quorum verify (approverOk H.day) (·.employee) H.ks 2 (msgOf f) f.sigs = true ∧
      Keyset.quorum verify (approverOk H.day) (·.idp) H.ks 2 (msgOf f) f.sigs = true ∧
      (∀ r ∈ Rules.reasons, Keyset.bit b.overrides r.idx = true → Rules.bypassable r = true) := by
  unfold admitBypass at h
  rcases hd : decode x with _ | f
  · simp only [hd] at h; cases h
  · simp only [hd] at h
    rcases hb : f.a.body with ⟨s, es⟩ | ⟨p, q, d, o⟩
    · simp only [hb] at h; cases h
    · simp only [hb] at h
      by_cases c : (f.a.state == H.ks.state && f.a.tenantId == t && windowOk f.a.notBefore f.a.notAfter H.day &&
          overridesOk o && Keyset.quorum verify (approverOk H.day) (·.employee) H.ks 2 (msgOf f) f.sigs &&
          Keyset.quorum verify (approverOk H.day) (·.idp) H.ks 2 (msgOf f) f.sigs) = true
      · rw [if_pos c] at h
        cases h
        simp only [Bool.and_eq_true, beq_iff_eq, windowOk, decide_eq_true_eq] at c
        obtain ⟨⟨⟨⟨⟨c1, c2⟩, c3, c4⟩, c5⟩, c6⟩, c7⟩ := c
        refine ⟨f, rfl, rfl, c1, c2, c3, c4, c6, c7, ?_⟩
        intro r hr hbit
        have := List.all_eq_true.1 c5 r hr
        simpa [hbit] using this
      · rw [if_neg c] at h; cases h

theorem admitBypassR_ok_iff {b : Bypass} :
    admitBypassR verify H t x = .ok b ↔ admitBypass verify H t x = some b := by
  unfold admitBypassR admitBypass
  cases decode x with
  | none => simp
  | some f =>
    rcases hb : f.a.body with ⟨s, es⟩ | ⟨p, q, r, o⟩
    · simp [hb]
    · simp only [hb]
      by_cases c : (f.a.state == H.ks.state && f.a.tenantId == t && windowOk f.a.notBefore f.a.notAfter H.day &&
          overridesOk o && Keyset.quorum verify (approverOk H.day) (·.employee) H.ks 2 (msgOf f) f.sigs &&
          Keyset.quorum verify (approverOk H.day) (·.idp) H.ks 2 (msgOf f) f.sigs) = true
      · have c' := c
        simp only [Bool.and_eq_true, beq_iff_eq] at c'
        obtain ⟨⟨⟨⟨⟨c1, c2⟩, c3⟩, c4⟩, c5⟩, c6⟩ := c'
        simp [c, c1, c2, c3, c4, c5, c6]
      · rw [if_neg c]
        simp only [reduceCtorEq, iff_false]
        intro h
        apply c
        split at h
        · cases h
        split at h
        · cases h
        split at h
        · cases h
        split at h
        · cases h
        simp_all

/-- Two or more distinct values of `key` give two entries that differ in it. -/
theorem two_apart {key : Keyset.Entry → Bytes} {es : List Keyset.Entry} (h : 2 ≤ Keyset.nDistinct key es) :
    ∃ a ∈ es, ∃ b ∈ es, key a ≠ key b := by
  refine Classical.byContradiction fun hn => ?_
  simp only [not_exists, not_and, ne_eq, Decidable.not_not] at hn
  cases es with
  | nil => simp [Keyset.nDistinct] at h
  | cons a t =>
    have := (Keyset.dedup_nodup (((a :: t)).map key)).length_le_of_subset (l₂ := [key a]) (fun x hx => by
      obtain ⟨e, he, rfl⟩ := List.mem_map.1 (List.mem_eraseDups.1 hx)
      simp [hn e he a (by simp)])
    unfold Keyset.nDistinct at h
    have h2 := Nat.le_trans h this
    simp only [List.length_singleton] at h2
    omega

/-- An admitted bypass has one signer pair that differs in employee and in identity-provider subject at once: the two
    quorums are over the same signers, and no admitted set can satisfy both with every pair sharing one of the two. -/
theorem admitBypass_pair {b : Bypass} (h : admitBypass verify H t x = some b) :
    ∃ f, decode x = some f ∧ ∃ u ∈ Keyset.signers verify (approverOk H.day) H.ks (msgOf f) f.sigs,
      ∃ v ∈ Keyset.signers verify (approverOk H.day) H.ks (msgOf f) f.sigs, u.employee ≠ v.employee ∧ u.idp ≠ v.idp := by
  obtain ⟨f, hd, -, -, -, -, -, he, hi, -⟩ := admitBypass_sound h
  refine ⟨f, hd, ?_⟩
  unfold Keyset.quorum at he hi
  simp only [Bool.and_eq_true, decide_eq_true_eq] at he hi
  obtain ⟨a, ha, b', hb, hab⟩ := two_apart he.2
  obtain ⟨c, hc, d, hd', hcd⟩ := two_apart hi.2
  by_cases hi1 : a.idp = b'.idp
  · have hz : ∃ z ∈ Keyset.signers verify (approverOk H.day) H.ks (msgOf f) f.sigs, z.idp ≠ a.idp := by
      by_cases hca : c.idp = a.idp
      · exact ⟨d, hd', fun e => hcd (hca.trans e.symm)⟩
      · exact ⟨c, hc, hca⟩
    obtain ⟨z, hz, hza⟩ := hz
    by_cases hze : z.employee = a.employee
    · exact ⟨b', hb, z, hz, fun e => hab (hze.symm.trans e.symm), fun e => hza (e.symm.trans hi1.symm)⟩
    · exact ⟨a, ha, z, hz, fun e => hze e.symm, fun e => hza e.symm⟩
  · exact ⟨a, ha, b', hb, hab, hi1⟩

/-! ### Witnesses
    Heads come only from `admitBatchHead`, so the vectors admit a key set (stub verify: a record verifies when it is
    present, so counting, liveness and scope decide).  Roster keys r1 (employee 1), r2 and r2b (employee 2, two keys),
    r3 (revoked); approver keys a1 (employee 1, subject 1), a2 (2, 2), a3 (3, subject 1: shares a1's subject),
    a4 (employee 1, subject 4: shares a1's employee), a5 (revoked).  Day 20261022.  Mutants and what kills them:
    `<` for `<=` on the window (the two window ends equal to the day), and `(·.keyId)` for `(·.employee)` in the
    roster quorum (one employee with two keys). -/

def vKey (b : UInt8) (role : Nat) (emp idp : UInt8) (rev : Nat := Keyset.live) : Keyset.Entry :=
  ⟨sha3 (Keyset.keyTag ++ Keyset.vecPk b), List.replicate 64 emp, List.replicate 64 idp, role, 0, 0, 20260101,
    20271231, rev, 0, 0, Keyset.vecPk b⟩

def r1 := vKey 21 Keyset.roster 1 1
def r2 := vKey 22 Keyset.roster 2 2
def r2b := vKey 23 Keyset.roster 2 2
def r3 := vKey 24 Keyset.roster 3 3 20261010
def a1 := vKey 31 Keyset.approver 1 1
def a2 := vKey 32 Keyset.approver 2 2
def a3 := vKey 33 Keyset.approver 3 1
def a4 := vKey 34 Keyset.approver 1 4
def a5 := vKey 35 Keyset.approver 5 5 20261010

def vGen : Keyset.Frame := Keyset.vecGen [r1, r2, r2b, r3, a1, a2, a3, a4, a5] [r1, r2]
def vPin : Bytes := Keyset.digestOf vGen.ks
def stub : Bytes → Bytes → Bytes → Bool := fun _ _ _ => true

def vHead : Option SnapshotV2.Head :=
  (SnapshotV2.admitBatchHead stub vPin 20261022 (Keyset.Ratchet.init vPin) (Keyset.encode vGen) []).map (·.1)

#guard vHead.isSome

def vSt : Bytes := List.replicate 64 7
def vTen : Bytes := "t1".toUTF8.toList
def vProg : Bytes := "p1".toUTF8.toList

def vEnt (flows : Nat) (au : Gate.Authority) (holds : Nat) (prog : Bytes := vProg) : Entry := ⟨prog, flows, au, holds⟩

def vGrant (st ten : Bytes) (nb na serial : Nat) (es : List Entry) (sg : List Keyset.Entry) : Bytes :=
  encode ⟨⟨st, ten, nb, na, .grant serial es⟩, Keyset.vecRecs sg⟩

/-- none: no head; some none: admitted; some (some e): refused for e. -/
def gv (floor : Nat) (x : Bytes) : Option (Option Refusal) :=
  vHead.map fun H => match admitGrant stub H vTen floor x with | .ok _ => none | .error e => some e

def g0 (es : List Entry := [vEnt 3 .TRANSFER 0]) (sg : List Keyset.Entry := [r1, r2]) (nb : Nat := 20261020)
    (na : Nat := 20261120) (serial : Nat := 5) (st : Bytes := vSt) (ten : Bytes := vTen) : Bytes :=
  vGrant st ten nb na serial es sg

-- admitted; wrong state; wrong tenant
#guard gv 5 g0 == some none
#guard gv 5 (g0 (st := List.replicate 64 8)) == some (some .SCOPE)
#guard gv 5 (g0 (ten := "t2".toUTF8.toList)) == some (some .SCOPE)
-- window ends: the day itself is inside, one day outside is not
#guard gv 5 (g0 (nb := 20261022)) == some none
#guard gv 5 (g0 (nb := 20261023)) == some (some .EXPIRED)
#guard gv 5 (g0 (nb := 20261001) (na := 20261022)) == some none
#guard gv 5 (g0 (nb := 20261001) (na := 20261021)) == some (some .EXPIRED)
-- serial equal to the floor is admitted, one below is superseded
#guard gv 5 (g0 (serial := 5)) == some none
#guard gv 5 (g0 (serial := 4)) == some (some .SUPERSEDED)
#guard gv 4 (g0 (serial := 4)) == some none
-- quorum: one employee short, one employee with two keys, a revoked key, wrong role; two distinct employees pass
#guard gv 5 (g0 (sg := [r1])) == some (some .UNSIGNED)
#guard gv 5 (g0 (sg := [r2, r2b])) == some (some .UNSIGNED)
#guard gv 5 (g0 (sg := [r1, r3])) == some (some .UNSIGNED)
#guard gv 5 (g0 (sg := [a1, a2])) == some (some .UNSIGNED)
#guard gv 5 (g0 (sg := [r1, r2b])) == some none
#guard gv 5 (g0 (sg := [r1, r2, r2b])) == some none
-- malformed: overlapping flow masks, unordered masks, unordered programs, HOLD without holds, holds without HOLD
#guard gv 5 (g0 (es := [vEnt 1 .OBSERVE 0, vEnt 3 .OBSERVE 0])) == some (some .MALFORMED)
#guard gv 5 (g0 (es := [vEnt 3 .OBSERVE 0, vEnt 2 .OBSERVE 0])) == some (some .MALFORMED)
#guard gv 5 (g0 (es := [vEnt 1 .OBSERVE 0, vEnt 6 .HOLD 1])) == some none
#guard gv 5 (g0 (es := [vEnt 1 .OBSERVE 0 "p2".toUTF8.toList, vEnt 1 .OBSERVE 0])) == some (some .MALFORMED)
#guard gv 5 (g0 (es := [vEnt 1 .HOLD 0])) == some (some .MALFORMED)
#guard gv 5 (g0 (es := [vEnt 1 .OBSERVE 1])) == some (some .MALFORMED)
#guard gv 5 (g0 (es := [])) == some (some .MALFORMED)
#guard gv 5 (g0 (es := [vEnt 32 .OBSERVE 0])) == some (some .MALFORMED)
-- the codec round-trips and refuses truncation and trailing bytes
#guard (decode g0).map encode == some g0
#guard (decode (g0.dropLast)).isNone
#guard (decode (g0 ++ [0])).isNone

def vReq : Bytes := List.replicate 64 9

def bx (o : Nat) (sg : List Keyset.Entry) : Bytes :=
  encode ⟨⟨vSt, vTen, 20261020, 20261120, .bypass vProg "pay1".toUTF8.toList vReq o⟩, Keyset.vecRecs sg⟩

def bv (x : Bytes) : Bool := match vHead with
  | some H => (admitBypass stub H vTen x).isSome
  | none => false

def deceased : Nat := 2 ^ Rules.Reason.idx .MEMBER_DECEASED
def dup : Nat := 2 ^ Rules.Reason.idx .ALREADY_DECIDED

#guard Rules.Reason.idx .MEMBER_DECEASED == 7 && Rules.Reason.idx .STALE_UNRESOLVED == 23
-- a mask has one bit per reason: a new reason's number widens the masks with it
#guard reasonMask == 2 ^ Rules.reasons.length
#guard (Rules.reasons.filter Rules.bypassable).length == 15
-- two approvers of distinct employees and distinct subjects
#guard bv (bx deceased [a1, a2])
#guard bv (bx deceased [a2, a3])
#guard !bv (bx deceased [a1])
#guard !bv (bx deceased [a1, a4])
#guard !bv (bx deceased [a1, a3])
#guard !bv (bx deceased [a1, a5])
#guard !bv (bx deceased [r1, r2])
-- overrides: a bit outside the bypassable set, a mix, nothing, a bit beyond the 24 reasons
#guard !bv (bx dup [a1, a2])
#guard !bv (bx (deceased + dup) [a1, a2])
#guard !bv (bx 0 [a1, a2])
#guard !bv (bx (2 ^ 24) [a1, a2])
#guard !bv (g0)

/-- Mutant: `<` for `<=` on the window. -/
def windowOkM1 (nb na day : Nat) : Bool := Rules.dayNum nb < Rules.dayNum day && Rules.dayNum day < Rules.dayNum na

#guard windowOk 20261022 20261120 20261022 && !windowOkM1 20261022 20261120 20261022
#guard windowOk 20261001 20261022 20261022 && !windowOkM1 20261001 20261022 20261022

/-- Mutant: `(·.keyId)` for `(·.employee)` in the roster quorum. -/
def quorumM2 (x : Bytes) : Bool := match vHead, decode x with
  | some H, some f =>
    Keyset.quorum stub (Keyset.rosterOk H.day) (·.keyId) H.ks H.ks.kRoster (msgOf f) f.sigs
  | _, _ => false

#guard quorumM2 (g0 (sg := [r2, r2b])) && gv 5 (g0 (sg := [r2, r2b])) == some (some .UNSIGNED)

end BlindLedger.Gate.Authority
