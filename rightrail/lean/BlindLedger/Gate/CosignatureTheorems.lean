import BlindLedger.Gate.ProducerTheorems
import BlindLedger.Gate.Cosign.Link

/-! The verifier's cosignature at the payer and at the producer, for every `Crypto`.  A checkpoint is stored only
    when its own signature and the verifier's cosignature both verify under one installed certificate of its
    tenant and epoch (`storeCheckpoint_cosigned`); every step keeps that true of every stored checkpoint
    (`Steps.cosigned`), so every release names a cosigned checkpoint (`verifyToken_cosigned`).  A fork is recorded
    whatever cosignature record the bytes carry (`storeCheckpoint_fork_needs_no_cosign`).  What the producer
    publishes is cosigned under its own certificate (`publishOk_cosigned`).  The batch release proves the same of
    its own inputs in `releaseBatch_accept_verified`. -/
namespace BlindLedger.Gate

/-- `st` keeps the bytes of a signed checkpoint whose signature and whose verifier cosignature both verify under
    one installed certificate of its tenant and epoch. -/
def CosignedBy (c : Crypto) (s : PayerState) (st : Stored) : Prop :=
  ∃ x v, decodeCheckpoint st.bytes = some x ∧ st.digest = c.hash x.header ∧ st.checkpoint = x.checkpoint ∧
    x.cosign = some v ∧ ∃ e ∈ s.certs, e.tenantId = st.checkpoint.tenantId ∧ e.epoch = st.checkpoint.epoch ∧
      c.verify e.key x.header x.signature = true ∧ cosignOk c e st.digest v = true

/-- Every stored checkpoint is cosigned. -/
def Cosigned (c : Crypto) (s : PayerState) : Prop := ∀ st ∈ s.checkpoints, CosignedBy c s st

theorem CosignedBy.mono {c : Crypto} {s s' : PayerState} {st : Stored} (hs : ∀ e ∈ s.certs, e ∈ s'.certs)
    (h : CosignedBy c s st) : CosignedBy c s' st := by
  obtain ⟨x, v, hx, hd, hcp, hv, e, he, r⟩ := h
  exact ⟨x, v, hx, hd, hcp, hv, e, hs e he, r⟩

/-- What a `some` answer of `storeCheckpoint` did: it recorded a fork against a stored checkpoint, or it stored
    the checkpoint, cosigned. -/
theorem storeCheckpoint_cases {c : Crypto} {s s' : PayerState} {b : Bytes} (h : storeCheckpoint c s b = some s') :
    ∃ x, decodeCheckpoint b = some x ∧
      ((∃ old ∈ s.checkpoints, s' = { s with forked := (old, ⟨c.hash x.header, x.checkpoint, b⟩) :: s.forked }) ∨
        (s' = { s with checkpoints := ⟨c.hash x.header, x.checkpoint, b⟩ :: s.checkpoints } ∧
          CosignedBy c s ⟨c.hash x.header, x.checkpoint, b⟩)) := by
  unfold storeCheckpoint at h
  cases hd : decodeCheckpoint b with
  | none => rw [hd] at h; simp at h
  | some x =>
    rw [hd] at h
    dsimp only at h
    refine ⟨x, rfl, ?_⟩
    split at h
    · split at h
      · rename_i old hf
        obtain rfl := Option.some.inj h
        exact .inl ⟨old, List.mem_of_find?_eq_some hf, rfl⟩
      · split at h
        · simp at h
        · split at h
          case isFalse => simp at h
          rename_i hany
          obtain rfl := Option.some.inj h
          obtain ⟨e, he, hm⟩ := List.any_eq_true.1 hany
          simp only [Bool.and_eq_true, beq_iff_eq] at hm
          cases hcx : x.cosign with
          | none => rw [hcx] at hm; simp at hm
          | some v =>
            rw [hcx] at hm
            exact .inr ⟨rfl, x, v, hd, rfl, rfl, hcx, e, he, hm.1.1.1, hm.1.1.2, hm.1.2, hm.2⟩
    · simp at h

/-- A checkpoint that a store added is cosigned: no checkpoint enters the stored set without the verifier's
    cosignature under the certificate that verified its signature. -/
theorem storeCheckpoint_cosigned {c : Crypto} {s s' : PayerState} {b : Bytes} {st : Stored}
    (h : storeCheckpoint c s b = some s') (hn : st ∈ s'.checkpoints) (ho : st ∉ s.checkpoints) :
    CosignedBy c s st := by
  obtain ⟨x, -, ⟨old, -, rfl⟩ | ⟨rfl, hc⟩⟩ := storeCheckpoint_cases h
  · exact absurd hn ho
  · rcases List.mem_cons.1 hn with rfl | hn
    · exact hc
    · exact absurd hn ho

theorem storeCheckpoint_keeps_cosigned {c : Crypto} {s s' : PayerState} {b : Bytes} (hc : Cosigned c s)
    (h : storeCheckpoint c s b = some s') : Cosigned c s' := by
  obtain ⟨x, -, ⟨old, -, rfl⟩ | ⟨rfl, hn⟩⟩ := storeCheckpoint_cases h
  · exact hc
  · intro st hst
    rcases List.mem_cons.1 hst with rfl | hst
    · exact hn
    · exact hc st hst

theorem installCert_keeps_cosigned {c : Crypto} {s : PayerState} (b : Bytes) (hc : Cosigned c s) :
    Cosigned c (installCert c s b).1 := by
  intro st hst
  exact (hc st hst).mono (Cosign.installCert_keeps c s.toAuth b).2.2.2.1

theorem installLink_keeps_cosigned {c : Crypto} {s : PayerState} (pin : Bytes) (n : Cosign.SignedLink)
    (hc : Cosigned c s) : Cosigned c (installLink c pin s n).1 := by
  intro st hst
  exact (hc st hst).mono fun e he => by
    show e ∈ (Cosign.installLink c pin s.toAuth n).1.certs
    rw [(Cosign.installLink_keeps c pin s.toAuth n).1]
    exact he

/-- Every step sequence keeps every stored checkpoint cosigned. -/
theorem Steps.cosigned {c : Crypto} {s s' : PayerState} (h : Steps c s s') (hs : Cosigned c s) : Cosigned c s' := by
  induction h with
  | refl => exact hs
  | tail _ step ih =>
    cases step with
    | link pin n => exact installLink_keeps_cosigned pin n ih
    | install b => exact installCert_keeps_cosigned b ih
    | store h => exact storeCheckpoint_keeps_cosigned ih h
    | send h =>
      unfold send at h
      split at h
      · cases h; exact ih
      · split at h
        · cases h; exact ih
        · cases h
    | pay h =>
      unfold release at h
      split at h
      · simp at h
      · split at h
        · obtain rfl := Option.some.inj h
          exact ih
        · simp at h
    | context => exact ih

/-- A release names a stored checkpoint that carries the verifier's cosignature: on a `Cosigned` state no token
    is accepted against a checkpoint the verifier did not cosign. -/
theorem verifyToken_cosigned {c : Crypto} {s : PayerState} {p : Payment} {b : Bytes} {t : Token}
    (hc : Cosigned c s) (hv : verifyToken c s p b = true) (ht : decodeToken b = some t) :
    ∃ st ∈ s.checkpoints, st.digest = t.checkpointDigest ∧ CosignedBy c s st := by
  unfold verifyToken at hv
  simp only [ht] at hv
  cases hb : batchOf s t with
  | none => simp [hb] at hv
  | some st =>
    have hf : s.checkpoints.find? (·.digest == t.checkpointDigest) = some st := hb
    have hm := List.mem_of_find?_eq_some hf
    exact ⟨st, hm, by simpa using List.find?_some hf, hc st hm⟩

/-- A fork is recorded exactly when the checkpoint's signature verifies under the installed certificate of
    its tenant and epoch and a stored checkpoint forks it.  The cosignature record is not read. -/
theorem storeCheckpoint_fork_iff {c : Crypto} {s : PayerState} {b : Bytes} {x : SignedCheckpoint}
    (hx : decodeCheckpoint b = some x) (old : Stored) :
    storeCheckpoint c s b = some { s with forked := (old, ⟨c.hash x.header, x.checkpoint, b⟩) :: s.forked } ↔
      (s.certs.any fun e => e.tenantId == x.checkpoint.tenantId && e.epoch == x.checkpoint.epoch &&
        c.verify e.key x.header x.signature) = true ∧
      s.checkpoints.find? (forks ⟨c.hash x.header, x.checkpoint, b⟩) = some old := by
  unfold storeCheckpoint
  rw [hx]
  dsimp only
  constructor
  · intro h
    split at h
    · rename_i hany
      refine ⟨hany, ?_⟩
      cases hf : s.checkpoints.find? (forks ⟨c.hash x.header, x.checkpoint, b⟩) with
      | some o =>
        rw [hf] at h
        have h1 := congrArg PayerState.forked (Option.some.inj h)
        dsimp only at h1
        have h2 : o = old := congrArg Prod.fst (List.cons.inj h1).1
        rw [h2]
      | none =>
        rw [hf] at h
        dsimp only at h
        split at h
        · simp at h
        · split at h
          · have h1 := congrArg PayerState.forked (Option.some.inj h)
            dsimp only at h1
            exact absurd (congrArg List.length h1) (by simp only [List.length_cons]; omega)
          · simp at h
    · simp at h
  · rintro ⟨hany, hf⟩
    rw [if_pos hany, hf]

/-- Fork evidence never needs a cosignature.  Of two byte strings that decode to the same checkpoint, header and
    signature and differ only in the cosignature record (present, absent or another), one is recorded as a fork
    against a stored checkpoint exactly when the other is: withholding or stripping the cosignature hides no
    fork. -/
theorem storeCheckpoint_fork_needs_no_cosign {c : Crypto} {s : PayerState} {b b' : Bytes} {x : SignedCheckpoint}
    {o : Option VCosign} (hx : decodeCheckpoint b = some x) (hy : decodeCheckpoint b' = some { x with cosign := o })
    (old : Stored) :
    storeCheckpoint c s b = some { s with forked := (old, ⟨c.hash x.header, x.checkpoint, b⟩) :: s.forked } ↔
      storeCheckpoint c s b' = some { s with forked := (old, ⟨c.hash x.header, x.checkpoint, b'⟩) :: s.forked } := by
  have hfk : forks ⟨c.hash x.header, x.checkpoint, b'⟩ = forks ⟨c.hash x.header, x.checkpoint, b⟩ := rfl
  have h' := storeCheckpoint_fork_iff (c := c) (s := s) hy old
  rw [hfk] at h'
  exact (storeCheckpoint_fork_iff hx old).trans h'.symm

/-- The checkpoint `accepts` takes carries the verifier's cosignature, valid under the certificate it was given. -/
theorem accepts_cosigned {link : Cosign.Link} {cert cp : Bytes} {e : Cosign.KeyCert}
    (ha : accepts link cert cp = true) (he : Cosign.decode cert = some e) :
    ∃ x v, decodeCheckpoint cp = some x ∧ x.cosign = some v ∧
      cosignOk realCrypto e (sha3 x.header) v = true := by
  unfold accepts at ha
  cases hi : installCert realCrypto (linkState link) cert with
  | mk s a =>
    rw [hi] at ha
    cases a with
    | installed =>
      cases hst : storeCheckpoint realCrypto s cp with
      | none => simp [hst] at ha
      | some s' =>
        obtain ⟨x, hx, ⟨old, -, rfl⟩ | ⟨rfl, y, v, hy, -, -, hv, k, hk, -, -, -, hco⟩⟩ := storeCheckpoint_cases hst
        · simp [hst] at ha
        · have hy' : decodeCheckpoint cp = some y := hy
          rw [hx] at hy'
          obtain rfl := Option.some.inj hy'
          have hc : s.certs = (Cosign.installCert realCrypto (linkState link).toAuth cert).1.certs :=
            (congrArg (fun r => r.1.certs) hi).symm
          rw [hc] at hk
          rcases Cosign.installCert_adds realCrypto (linkState link).toAuth cert with h0 | ⟨e', hd, h1, -⟩
          · rw [h0] at hk
            cases hk
          · rw [h1] at hk
            obtain rfl : e' = e := Option.some.inj (hd.symm.trans he)
            have hk' : k ∈ [e'] := hk
            obtain rfl := List.mem_singleton.1 hk'
            exact ⟨x, v, hx, hv, hco⟩
    | _ => simp at ha

/-- What the producer publishes is cosigned: `publishOk` accepts a checkpoint only with the verifier's
    cosignature of its header digest, valid under the verifier key of the epoch certificate. -/
theorem publishOk_cosigned {link : Cosign.Link} {cert new : Bytes} {last : Option Bytes} {tokens : List Bytes}
    {tpm : Nat} (h : publishOk link cert last new tokens tpm = true) :
    ∃ e x v, Cosign.decode cert = some e ∧ decodeCheckpoint new = some x ∧ x.cosign = some v ∧
      cosignOk realCrypto e (sha3 x.header) v = true := by
  obtain ⟨ha, -, e, -, he, -⟩ := publishOk_sound h
  obtain ⟨x, v, hx, hv, hc⟩ := accepts_cosigned ha he
  exact ⟨e, x, v, he, hx, hv, hc⟩

/-- What the verifier signs is never a checkpoint header, a key certificate body or an authority link body.  A
    certificate keeps its two keys apart from each other and from the keys of the held links
    (`Cosign.keysApart`), not from the keys of other certificates; this is what stops a signature made in another
    role from serving as a cosignature, and a cosignature from serving in another role, whatever key is reused. -/
theorem vcosignMsg_apart {b : Bytes} {x : SignedCheckpoint} (hx : decodeCheckpoint b = some x) (d vrel : Bytes)
    (e : Cosign.KeyCert) (n : Cosign.SignedLink) :
    vcosignMsg d vrel ≠ x.header ∧ vcosignMsg d vrel ≠ e.body ∧ vcosignMsg d vrel ≠ n.body := by
  have he : domain "VCOSIGN" = "RR/GATE/VCOSIGN/v1".toUTF8.toList ++ [0] := by
    first | rfl | decide +kernel | simp [domain]
  have dv : (vcosignMsg d vrel)[8]? = some 86 := by
    simp only [vcosignMsg, List.append_assoc]
    exact idx_append (by rw [he]; first | decide +kernel | rfl | simp)
  obtain ⟨t, ht⟩ := checkpoint_header_domain hx
  refine ⟨fun h => ?_, fun h => ?_, fun h => ?_⟩
  · have d1 : x.header[8]? = some 67 := by
      rw [ht]; exact idx_append (by first | decide +kernel | rfl | simp)
    rw [h, d1] at dv
    first | exact absurd dv (by decide) | simp at dv
  · have d2 : e.body[8]? = some 75 := by
      simp only [Cosign.KeyCert.body, List.append_assoc]
      exact idx_append (by first | decide +kernel | rfl | simp [Cosign.certTag])
    rw [h, d2] at dv
    first | exact absurd dv (by decide) | simp at dv
  · have d3 : n.body[8]? = some 65 := by
      simp only [Cosign.SignedLink.body, List.append_assoc]
      exact idx_append (by first | decide +kernel | rfl | simp [Cosign.linkTag])
    rw [h, d3] at dv
    first | exact absurd dv (by decide) | simp at dv


namespace Cosign

/-- A certificate body is never a checkpoint header, so a signature made for one cannot serve for the other. -/
theorem body_ne_checkpoint_header {b : Bytes} {x : SignedCheckpoint} (hx : decodeCheckpoint b = some x) (e : KeyCert) :
    e.body ≠ x.header := by
  obtain ⟨t, ht⟩ := checkpoint_header_domain hx
  intro h
  have d1 : x.header[8]? = some 67 := by
    rw [ht]; exact idx_append (by first | decide +kernel | rfl | simp)
  have d2 : e.body[8]? = some 75 := by
    simp only [KeyCert.body, List.append_assoc]
    exact idx_append (by first | decide +kernel | rfl | simp [certTag])
  rw [h, d1] at d2
  first | exact absurd d2 (by decide) | simp at d2


end Cosign

end BlindLedger.Gate
