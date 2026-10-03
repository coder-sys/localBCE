import BlindLedger.Gate.AnchorTheorems

/-! CHECKPOINT/v2 decoder theorems (multi-shard-runtime-v1 §A3), stated against the any-version names of
    step 1c ruling 1: `decodeCheckpoint` is v1 alone, `decodeCheckpoint2` is v2 alone.  The encoder lives
    only here: Python is the producer, so no exe links it. -/
namespace BlindLedger.Gate

/-! ### Disjoint magics -/

theorem decodeCheckpoint_magic {b : Bytes} {x : SignedCheckpoint} (h : decodeCheckpoint b = some x) :
    ∃ m, b = domain "CHECKPOINT" ++ m := by
  have hr := parse_run h
  simp only [pSignedCheckpoint, StateT.run_bind] at hr
  obtain ⟨c, hc, -⟩ := bind_some hr
  have h2 := consumed_run hc
  simp only [pCheckpoint, StateT.run_bind] at h2
  obtain ⟨⟨u, m⟩, he, -⟩ := bind_some h2
  exact ⟨m, expect_run he⟩

theorem decodeCheckpoint_disjoint (b : Bytes) : decodeCheckpoint b = none ∨ decodeCheckpoint2 b = none := by
  cases h1 : decodeCheckpoint b with
  | none => exact Or.inl rfl
  | some x =>
    cases h2 : decodeCheckpoint2 b with
    | none => exact Or.inr rfl
    | some r =>
      exfalso
      obtain ⟨t, ht⟩ := decodeCheckpoint_magic h1
      obtain ⟨m, hm⟩ := decodeCheckpoint2_magic h2
      have h20 := congrArg (fun l => l[20]?) (ht.symm.trans hm)
      have e1 : (domain "CHECKPOINT" ++ t)[20]? = some 49 :=
        idx_append (by first | decide +kernel | rfl | simp [domain])
      have e2 : (("RR/GATE/CHECKPOINT/v2".toUTF8.toList ++ [0]) ++ m)[20]? = some 50 :=
        idx_append (by first | decide +kernel | rfl | simp)
      simp only [e1, e2] at h20
      simp at h20

/-! ### Primitive parsers on exact bytes -/

theorem natBE_length (w v : Nat) : (natBE w v).length = w := by simp [natBE]

theorem take_app {n : Nat} {a r : Bytes} (h : a.length = n) : (take n).run (a ++ r) = some (a, r) := by
  subst h
  simp [StateT.run, take]

theorem take_inv {n : Nat} {b a r : Bytes} (h : (take n).run b = some (a, r)) :
    b = a ++ r ∧ a.length = n := by
  by_cases hn : n ≤ b.length
  · simp only [StateT.run, take, hn, if_true, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    exact ⟨(List.take_append_drop n b).symm, by simp; omega⟩
  · simp [StateT.run, take, hn] at h

theorem need_true (b : Bytes) : (need true).run b = some ((), b) := rfl

theorem nat_app {w lo hi v : Nat} {r : Bytes} (hv : v < 256 ^ w) (hlo : lo ≤ v) (hhi : v ≤ hi) :
    (nat w lo hi).run (natBE w v ++ r) = some (v, r) := by
  simp [nat, StateT.run_bind, take_app (natBE_length w v), beNat_natBE w v hv, hlo, hhi, need_true]

theorem nat_inv {w lo hi v : Nat} {b r : Bytes} (h : (nat w lo hi).run b = some (v, r)) :
    b = natBE w v ++ r ∧ lo ≤ v ∧ v ≤ hi := by
  simp only [nat, StateT.run_bind] at h
  obtain ⟨⟨a, m⟩, h1, h⟩ := bind_some h
  obtain ⟨⟨u, m2⟩, h2, h⟩ := bind_some h
  have hok := need_ok h2
  simp only [Bool.and_eq_true, decide_eq_true_eq] at hok
  obtain ⟨hb, hl⟩ := take_inv h1
  simp only [StateT.run, need, hok.1, hok.2, Bool.and_self] at h2
  simp only [StateT.run_pure, Option.pure_def, Option.some.injEq, Prod.mk.injEq] at h
  obtain ⟨rfl, rfl⟩ := h
  obtain ⟨-, rfl⟩ := h2
  refine ⟨?_, hok⟩
  rw [← hl, natBE_beNat, hb]

theorem blob_app {lo hi : Nat} {s r : Bytes} (hl : s.length < 256 ^ 2) (h1 : lo ≤ s.length) (h2 : s.length ≤ hi) :
    (blob lo hi).run (natBE 2 s.length ++ (s ++ r)) = some (s, r) := by
  simp [blob, StateT.run_bind, nat_app hl h1 h2, take_app (r := r) rfl]

theorem blob_inv {lo hi : Nat} {b s r : Bytes} (h : (blob lo hi).run b = some (s, r)) :
    b = natBE 2 s.length ++ (s ++ r) ∧ lo ≤ s.length ∧ s.length ≤ hi := by
  simp only [blob, StateT.run_bind] at h
  obtain ⟨⟨n, m⟩, h1, h⟩ := bind_some h
  obtain ⟨hb, hlo, hhi⟩ := nat_inv h1
  obtain ⟨hm, hl⟩ := take_inv h
  subst hl hm
  exact ⟨hb, hlo, hhi⟩

theorem identOk_len {s : Bytes} (h : identOk s = true) : 1 ≤ s.length ∧ s.length ≤ 128 := by
  cases s with
  | nil => simp [identOk] at h
  | cons c rest =>
    simp only [identOk, Bool.and_eq_true, decide_eq_true_eq] at h
    simp
    omega

def identBytes (s : Bytes) : Bytes := natBE 2 s.length ++ s

theorem ident_app {s r : Bytes} (h : identOk s = true) : ident.run (identBytes s ++ r) = some (s, r) := by
  obtain ⟨h1, h2⟩ := identOk_len h
  have hb := blob_app (lo := 1) (hi := 65535) (r := r) (s := s) (by omega) h1 (by omega)
  simp [ident, StateT.run_bind, identBytes, hb, h, need_true]

theorem ident_inv {b s r : Bytes} (h : ident.run b = some (s, r)) : b = identBytes s ++ r ∧ identOk s = true := by
  simp only [ident, StateT.run_bind] at h
  obtain ⟨⟨bs, m⟩, h1, h⟩ := bind_some h
  obtain ⟨⟨u, m2⟩, h2, h⟩ := bind_some h
  have hok := need_ok h2
  simp only [StateT.run, need, hok, if_true, Option.some.injEq, Prod.mk.injEq] at h2
  simp only [StateT.run_pure, Option.pure_def, Option.some.injEq, Prod.mk.injEq] at h
  obtain ⟨rfl, rfl⟩ := h
  obtain ⟨-, rfl⟩ := h2
  exact ⟨by rw [(blob_inv h1).1, identBytes, List.append_assoc], hok⟩

theorem need_rest {ok : Bool} {b m : Bytes} {u : Unit} (h : (need ok).run b = some (u, m)) : m = b := by
  by_cases hok : ok = true
  · simp only [StateT.run, need, hok, if_true, Option.some.injEq, Prod.mk.injEq] at h
    exact h.2.symm
  · simp [StateT.run, need, hok] at h

/-! ### The encoder -/

def checkpointFieldBytes (cp : Checkpoint) : Bytes :=
  identBytes cp.tenantId ++ identBytes cp.programId ++ natBE 4 cp.shardId ++ natBE 8 cp.seqFrom ++
  natBE 8 cp.seqTo ++ natBE 8 cp.epoch ++ cp.prevCheckpoint ++ cp.eventHead ++ cp.tokenRoot ++
  cp.evidenceRoot ++ cp.stateDigest ++ natBE 2 cp.count ++ natBE 8 cp.createdAt

def checkpoint2Header (cp : Checkpoint) (head : Bytes) : Bytes :=
  ("RR/GATE/CHECKPOINT/v2".toUTF8.toList ++ [0]) ++ natBE 1 1 ++ checkpointFieldBytes cp ++ head

/-- Exactly what `pCheckpoint2` checks (each `nat` width and bound, `identOk`, 64-byte digests, the three v1
    `need`s, a 64-byte non-zero head).  The size bound `maxCheckpointBytes` follows from `identOk`. -/
def Checkpoint.Wf2 (cp : Checkpoint) (head : Bytes) : Prop :=
  identOk cp.tenantId = true ∧ identOk cp.programId = true ∧ cp.shardId < 256 ^ 4 ∧
  cp.seqFrom ≤ maxNat ∧ cp.seqTo ≤ maxNat ∧ cp.epoch ≤ maxNat ∧
  cp.prevCheckpoint.length = digestBytes ∧ cp.eventHead.length = digestBytes ∧
  cp.tokenRoot.length = digestBytes ∧ cp.evidenceRoot.length = digestBytes ∧
  cp.stateDigest.length = digestBytes ∧ 1 ≤ cp.count ∧ cp.count ≤ maxBatch ∧ cp.createdAt ≤ maxNat ∧
  cp.stateDigest ≠ zeroDigest ∧ cp.seqTo + 1 = cp.seqFrom + cp.count ∧
  (cp.seqFrom = 0 ↔ cp.prevCheckpoint = zeroDigest) ∧ head.length = digestBytes ∧ head ≠ zeroDigest

theorem pCheckpointFields_inv {b rest : Bytes} {cp : Checkpoint} (h : pCheckpointFields.run b = some (cp, rest)) :
    b = checkpointFieldBytes cp ++ rest := by
  simp only [pCheckpointFields, StateT.run_bind] at h
  obtain ⟨⟨a1, m1⟩, h1, h⟩ := bind_some h
  obtain ⟨⟨a2, m2⟩, h2, h⟩ := bind_some h
  obtain ⟨⟨a3, m3⟩, h3, h⟩ := bind_some h
  obtain ⟨⟨a4, m4⟩, h4, h⟩ := bind_some h
  obtain ⟨⟨a5, m5⟩, h5, h⟩ := bind_some h
  obtain ⟨⟨a6, m6⟩, h6, h⟩ := bind_some h
  obtain ⟨⟨a7, m7⟩, h7, h⟩ := bind_some h
  obtain ⟨⟨a8, m8⟩, h8, h⟩ := bind_some h
  obtain ⟨⟨a9, m9⟩, h9, h⟩ := bind_some h
  obtain ⟨⟨a10, m10⟩, h10, h⟩ := bind_some h
  obtain ⟨⟨a11, m11⟩, h11, h⟩ := bind_some h
  obtain ⟨⟨a12, m12⟩, h12, h⟩ := bind_some h
  obtain ⟨⟨a13, m13⟩, h13, h⟩ := bind_some h
  obtain ⟨⟨u1, m14⟩, h14, h⟩ := bind_some h
  obtain ⟨⟨u2, m15⟩, h15, h⟩ := bind_some h
  obtain ⟨⟨u3, m16⟩, h16, h⟩ := bind_some h
  simp only [StateT.run_pure, Option.pure_def, Option.some.injEq, Prod.mk.injEq] at h
  obtain ⟨rfl, rfl⟩ := h
  have e1 := (ident_inv h1).1
  have e2 := (ident_inv h2).1
  have e3 := (nat_inv h3).1
  have e4 := (nat_inv h4).1
  have e5 := (nat_inv h5).1
  have e6 := (nat_inv h6).1
  have e7 := (take_inv h7).1
  have e8 := (take_inv h8).1
  have e9 := (take_inv h9).1
  have e10 := (take_inv h10).1
  have e11 := (take_inv h11).1
  have e12 := (nat_inv h12).1
  have e13 := (nat_inv h13).1
  subst e1 e2 e3 e4 e5 e6 e7 e8 e9 e10 e11 e12 e13
  have e14 := need_rest h14
  have e15 := need_rest h15
  have e16 := need_rest h16
  subst e14 e15 e16
  simp only [checkpointFieldBytes, List.append_assoc]

theorem pCheckpoint2_inv {b rest : Bytes} {cp : Checkpoint} {head : Bytes}
    (h : pCheckpoint2.run b = some ((cp, head), rest)) :
    b = checkpoint2Header cp head ++ rest ∧ head.length = digestBytes ∧ head ≠ zeroDigest := by
  simp only [pCheckpoint2, StateT.run_bind] at h
  obtain ⟨⟨u0, m0⟩, h0, h⟩ := bind_some h
  obtain ⟨⟨u1, m1⟩, h1, h⟩ := bind_some h
  obtain ⟨⟨c, m2⟩, h2, h⟩ := bind_some h
  obtain ⟨⟨hd, m3⟩, h3, h⟩ := bind_some h
  obtain ⟨⟨u4, m4⟩, h4, h⟩ := bind_some h
  simp only [StateT.run_pure, Option.pure_def, Option.some.injEq, Prod.mk.injEq] at h
  obtain ⟨⟨rfl, rfl⟩, rfl⟩ := h
  have e0 := expect_run h0
  obtain ⟨e1, hl1, hh1⟩ := nat_inv h1
  have e2 := pCheckpointFields_inv h2
  obtain ⟨e3, hl3⟩ := take_inv h3
  have e4 := need_rest h4
  have ok := need_ok h4
  have hu : u1 = 1 := by omega
  subst e0 e1 e2 e3 e4 hu
  refine ⟨?_, hl3, by simpa using ok⟩
  simp only [checkpoint2Header, List.append_assoc]

theorem decodeCheckpoint2_inv {b : Bytes} {x : SignedCheckpoint} {head : Bytes}
    (h : decodeCheckpoint2 b = some (x, head)) :
    b = x.header ++ natBE 2 mlDsa87Signature ++ x.signature ∧
      x.header = checkpoint2Header x.checkpoint head ∧ head.length = digestBytes ∧ head ≠ zeroDigest := by
  have hr := parse_run h
  simp only [StateT.run_bind] at hr
  obtain ⟨⟨⟨⟨c, hd⟩, hdr⟩, m⟩, hc, h⟩ := bind_some hr
  obtain ⟨⟨s, m2⟩, hs, h⟩ := bind_some h
  simp only [StateT.run_pure, Option.pure_def, Option.some.injEq, Prod.mk.injEq] at h
  obtain ⟨⟨rfl, rfl⟩, rfl⟩ := h
  have ht := consumed_take hc
  dsimp only at ht
  obtain ⟨e, hl, hh⟩ := pCheckpoint2_inv (consumed_run hc)
  obtain ⟨e2, hlo, hhi⟩ := blob_inv hs
  have hsl : s.length = mlDsa87Signature := by omega
  have hH : hdr = checkpoint2Header c hd := by
    rw [ht, e, List.length_append, Nat.add_sub_cancel, List.take_left' rfl]
  dsimp only at hH ⊢
  rw [hH]
  refine ⟨?_, rfl, hl, hh⟩
  rw [e, e2, hsl]
  simp

theorem decodeCheckpoint2_canonical {b : Bytes} {x : SignedCheckpoint} {head : Bytes}
    (h : decodeCheckpoint2 b = some (x, head)) : x.header = checkpoint2Header x.checkpoint head :=
  (decodeCheckpoint2_inv h).2.1

/-- The boot check's fixed suffix read is the signed head. -/
theorem decodeCheckpoint2_head {b : Bytes} {x : SignedCheckpoint} {head : Bytes}
    (h : decodeCheckpoint2 b = some (x, head)) :
    x.header.drop (x.header.length - digestBytes) = head ∧ head ≠ zeroDigest ∧
      b = x.header ++ natBE 2 mlDsa87Signature ++ x.signature := by
  obtain ⟨hb, hh, hl, hz⟩ := decodeCheckpoint2_inv h
  refine ⟨?_, hz, hb⟩
  rw [hh, checkpoint2Header, List.length_append, hl, Nat.add_sub_cancel, List.drop_left' rfl]

/-! ### Round trip -/

theorem expect_app {d r : Bytes} : (expect d).run (d ++ r) = some ((), r) := by
  simp [expect, StateT.run_bind, take_app (r := r) rfl, need_true]

theorem pCheckpointFields_app {cp : Checkpoint} {head r : Bytes} (hw : cp.Wf2 head) :
    pCheckpointFields.run (checkpointFieldBytes cp ++ r) = some (cp, r) := by
  rcases cp with ⟨tn, pn, sh, sf, st, ep, pv, eh, tr, er, sd, ct, ca⟩
  simp only [Checkpoint.Wf2] at hw
  obtain ⟨hTn, hPn, hSh, hSf, hSt, hEp, hPv, hEh, hTr, hEr, hSd, hC1, hC2, hCa, hSz, hSeq, hZ, -, -⟩ := hw
  have m8 : maxNat < 256 ^ 8 := by decide
  have m4 : 256 ^ 4 ≤ maxNat := by decide
  have mb : maxBatch < 256 ^ 2 := by decide
  have n1 : (sd != zeroDigest) = true := by simpa using hSz
  have n2 : (st + 1 == sf + ct) = true := by simpa using hSeq
  have n3 : ((sf == 0) == (pv == zeroDigest)) = true := by
    by_cases h : sf = 0
    · have := hZ.mp h
      rw [beq_iff_eq.mpr h, beq_iff_eq.mpr this]
      rfl
    · have : ¬ pv = zeroDigest := fun h' => h (hZ.mpr h')
      rw [beq_eq_false_iff_ne.mpr h, beq_eq_false_iff_ne.mpr this]
      rfl
  simp [pCheckpointFields, digest, checkpointFieldBytes, StateT.run_bind, List.append_assoc, ident_app hTn,
    ident_app hPn, nat_app hSh (Nat.zero_le _) (Nat.le_trans (Nat.le_of_lt hSh) m4),
    nat_app (Nat.lt_of_le_of_lt hSf m8) (Nat.zero_le _) hSf, nat_app (Nat.lt_of_le_of_lt hSt m8) (Nat.zero_le _) hSt,
    nat_app (Nat.lt_of_le_of_lt hEp m8) (Nat.zero_le _) hEp, take_app hPv, take_app hEh, take_app hTr,
    take_app hEr, take_app hSd, nat_app (Nat.lt_of_le_of_lt hC2 mb) hC1 hC2,
    nat_app (Nat.lt_of_le_of_lt hCa m8) (Nat.zero_le _) hCa, need_true, n1, n2, n3]

theorem pCheckpoint2_app {cp : Checkpoint} {head r : Bytes} (hw : cp.Wf2 head) :
    pCheckpoint2.run (checkpoint2Header cp head ++ r) = some ((cp, head), r) := by
  obtain ⟨-, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, -, hl, hz⟩ := id hw
  have n : (head != zeroDigest) = true := by simpa using hz
  unfold pCheckpoint2 checkpoint2Header
  generalize ("RR/GATE/CHECKPOINT/v2".toUTF8.toList ++ [0]) = M
  simp [digest, StateT.run_bind, List.append_assoc, expect_app,
    nat_app (by decide : 1 < 256 ^ 1) (Nat.le_refl 1) (Nat.le_refl 1), pCheckpointFields_app hw,
    take_app hl, need_true, n]

theorem decodeCheckpoint2_encode {cp : Checkpoint} {head sig : Bytes} (hw : cp.Wf2 head)
    (hs : sig.length = mlDsa87Signature) :
    decodeCheckpoint2 (checkpoint2Header cp head ++ natBE 2 mlDsa87Signature ++ sig) =
      some ({ checkpoint := cp, header := checkpoint2Header cp head, signature := sig }, head) := by
  have hp := pCheckpoint2_app hw (r := natBE 2 mlDsa87Signature ++ sig)
  obtain ⟨hTn, hPn, -, -, -, -, hPv, hEh, hTr, hEr, hSd, -, -, -, -, -, -, hHl, -⟩ := id hw
  have h1 := identOk_len hTn
  have h2 := identOk_len hPn
  have hlen : ¬ ((checkpoint2Header cp head ++ (natBE 2 mlDsa87Signature ++ sig)).length > maxCheckpointBytes) := by
    simp only [checkpoint2Header, checkpointFieldBytes, identBytes, List.length_append, natBE_length, hs, hPv, hEh,
      hTr, hEr, hSd, hHl, List.length_cons, List.length_nil]
    have hm : "RR/GATE/CHECKPOINT/v2".toUTF8.toList.length = 21 := by first | decide +kernel | rfl | simp
    simp only [digestBytes, maxCheckpointBytes, mlDsa87Signature, hm]
    omega
  have hb : (blob mlDsa87Signature mlDsa87Signature).run (natBE 2 mlDsa87Signature ++ sig) = some (sig, []) := by
    have := blob_app (lo := mlDsa87Signature) (hi := mlDsa87Signature) (s := sig) (r := [])
      (by rw [hs]; decide) (by rw [hs]; exact Nat.le_refl _) (by rw [hs]; exact Nat.le_refl _)
    rwa [List.append_nil, hs] at this
  have hc : (consumed pCheckpoint2).run (checkpoint2Header cp head ++ (natBE 2 mlDsa87Signature ++ sig)) =
      some (((cp, head), checkpoint2Header cp head), natBE 2 mlDsa87Signature ++ sig) := by
    show consumed pCheckpoint2 _ = _
    simp only [consumed, hp, List.length_append, Nat.add_sub_cancel]
    rw [List.take_left' rfl]
  rw [List.append_assoc]
  simp only [decodeCheckpoint2, parse, if_neg hlen]
  simp [StateT.run_bind, hc, hb]

end BlindLedger.Gate
