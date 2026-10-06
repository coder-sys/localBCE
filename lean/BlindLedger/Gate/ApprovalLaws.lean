import BlindLedger.Gate.Approval

namespace BlindLedger.Gate.Approval

open BlindLedger.Gate

/-! Codec laws for APPROVAL/v1 (slice S2).  Whatever the decoder accepts is
    exactly the canonical encoding of what it returns, and every decoded move
    carries a 64-byte `lineDigest`: a 32- or 65-byte digest field has no
    accepted encoding. -/

theorem bind_run {α β : Type} {p : P α} {f : α → P β} {b r : Bytes} {y : β}
    (h : (p >>= f).run b = some (y, r)) : ∃ x r1, p.run b = some (x, r1) ∧ (f x).run r1 = some (y, r) := by
  rw [StateT.run_bind] at h
  cases hp : p.run b with
  | none => simp [hp] at h
  | some q => rw [hp] at h; exact ⟨q.1, q.2, rfl, h⟩

theorem pure_run {α : Type} {x y : α} {b r : Bytes} (h : (pure x : P α).run b = some (y, r)) : x = y ∧ b = r := by
  cases h; exact ⟨rfl, rfl⟩

theorem take_run {n : Nat} {b x r : Bytes} (h : (take n).run b = some (x, r)) : x ++ r = b ∧ x.length = n := by
  change (if n ≤ b.length then some (b.take n, b.drop n) else none) = some (x, r) at h
  split at h
  · cases h
    exact ⟨List.take_append_drop n b, by rw [List.length_take]; omega⟩
  · simp at h

theorem need_run {ok : Bool} {b r : Bytes} {u : Unit} (h : (need ok).run b = some (u, r)) : ok = true ∧ r = b := by
  change (if ok then some ((), b) else none) = some (u, r) at h
  split at h
  · cases h; exact ⟨‹_›, rfl⟩
  · simp at h

theorem natBE_succ (w v : Nat) : natBE (w + 1) v = natBE w (v / 256) ++ [UInt8.ofNat (v % 256)] := by
  have hd : ∀ i, v / 256 ^ (i + 1) = v / 256 / 256 ^ i := fun i => by
    rw [Nat.div_div_eq_div_mul, Nat.pow_succ, Nat.mul_comm]
  simp only [natBE, List.range_succ_eq_map, List.reverse_cons, List.map_append, List.map_reverse, List.map_map,
    Function.comp_def, hd, Nat.pow_zero, Nat.div_one, List.map_cons, List.map_nil]

theorem beNat_snoc (bs : Bytes) (x : UInt8) : beNat (bs ++ [x]) = beNat bs * 256 + x.toNat := by
  simp [beNat, List.foldl_append]

theorem natBE_beNat_rev : ∀ rs : Bytes, natBE rs.length (beNat rs.reverse) = rs.reverse
  | [] => by simp [natBE]
  | x :: rs => by
    have hx : x.toNat < 256 := x.toNat_lt_size
    have h1 : (beNat rs.reverse * 256 + x.toNat) / 256 = beNat rs.reverse := by omega
    have h2 : (beNat rs.reverse * 256 + x.toNat) % 256 = x.toNat := by omega
    rw [List.length_cons, natBE_succ, List.reverse_cons, beNat_snoc, h1, h2, natBE_beNat_rev rs, UInt8.ofNat_toNat]

theorem natBE_beNat (bs : Bytes) : natBE bs.length (beNat bs) = bs := by
  simpa using natBE_beNat_rev bs.reverse

theorem nat_run {w lo hi v : Nat} {b r : Bytes} (h : (nat w lo hi).run b = some (v, r)) :
    natBE w v ++ r = b ∧ lo ≤ v ∧ v ≤ hi := by
  obtain ⟨bs, r1, h1, h⟩ := bind_run h
  obtain ⟨hb, hl⟩ := take_run h1
  obtain ⟨_, r2, h2, h3⟩ := bind_run h
  obtain ⟨ok, rfl⟩ := need_run h2
  obtain ⟨rfl, rfl⟩ := pure_run h3
  simp only [Bool.and_eq_true, decide_eq_true_eq] at ok
  subst hl
  rw [natBE_beNat]
  exact ⟨hb, ok⟩

theorem blob_run {lo hi : Nat} {b x r : Bytes} (h : (blob lo hi).run b = some (x, r)) :
    identField x ++ r = b ∧ lo ≤ x.length ∧ x.length ≤ hi := by
  obtain ⟨n, r1, h1, h⟩ := bind_run h
  obtain ⟨hn, hlo, hhi⟩ := nat_run h1
  obtain ⟨hx, hl⟩ := take_run h
  subst hl; subst hx; subst hn
  exact ⟨by simp [identField], hlo, hhi⟩

theorem ident_run {b x r : Bytes} (h : ident.run b = some (x, r)) : identField x ++ r = b := by
  obtain ⟨bs, r1, h1, h⟩ := bind_run h
  obtain ⟨_, r2, h2, h3⟩ := bind_run h
  obtain ⟨-, rfl⟩ := need_run h2
  obtain ⟨rfl, rfl⟩ := pure_run h3
  exact (blob_run h1).1

theorem expect_run {d b r : Bytes} {u : Unit} (h : (expect d).run b = some (u, r)) : d ++ r = b := by
  obtain ⟨x, r1, h1, h⟩ := bind_run h
  obtain ⟨hx, -⟩ := take_run h1
  obtain ⟨ok, rfl⟩ := need_run h
  rw [beq_iff_eq] at ok
  subst ok
  exact hx

theorem tag_run {b r : Bytes} {k : Kind} (h : (tag kinds).run b = some (k, r)) : natBE 1 k.num ++ r = b := by
  obtain ⟨v, r1, h1, h⟩ := bind_run h
  obtain ⟨hv, hlo, hhi⟩ := nat_run h1
  cases hx : kinds[v - 1]? with
  | none => simp [hx, fail, StateT.run] at h
  | some x =>
    simp only [hx] at h
    obtain ⟨rfl, rfl⟩ := pure_run h
    have h7 : kinds.length = 7 := rfl
    rcases (by omega : v = 1 ∨ v = 2 ∨ v = 3 ∨ v = 4 ∨ v = 5 ∨ v = 6 ∨ v = 7) with
      rfl | rfl | rfl | rfl | rfl | rfl | rfl <;> simp [kinds] at hx <;> subst hx <;> exact hv

theorem many_run {α : Type} {p : P α} {e : α → Bytes} {Q : α → Prop}
    (hp : ∀ {b x r}, p.run b = some (x, r) → e x ++ r = b ∧ Q x) :
    ∀ k {b xs r}, (many p k).run b = some (xs, r) → xs.flatMap e ++ r = b ∧ xs.length = k ∧ ∀ x ∈ xs, Q x
  | 0, b, xs, r, h => by
    simp only [many] at h
    obtain ⟨rfl, rfl⟩ := pure_run h
    exact ⟨rfl, rfl, by simp⟩
  | k + 1, b, xs, r, h => by
    simp only [many] at h
    obtain ⟨x, r1, h1, h⟩ := bind_run h
    obtain ⟨ys, r2, h2, h⟩ := bind_run h
    obtain ⟨rfl, rfl⟩ := pure_run h
    obtain ⟨he, hq⟩ := hp h1
    obtain ⟨hes, hl, hqs⟩ := many_run hp k h2
    refine ⟨?_, by simp [hl], List.forall_mem_cons.2 ⟨hq, hqs⟩⟩
    rw [List.flatMap_cons, List.append_assoc, hes, he]

theorem pMove_run {b r : Bytes} {m : Move} (h : pMove.run b = some (m, r)) :
    encMove m ++ r = b ∧ m.lineDigest.length = 64 := by
  obtain ⟨cell, r1, h1, h⟩ := bind_run h
  obtain ⟨pid, r2, h2, h⟩ := bind_run h
  obtain ⟨ck, r3, h3, h⟩ := bind_run h
  obtain ⟨pk, r4, h4, h⟩ := bind_run h
  obtain ⟨c, r5, h5, h⟩ := bind_run h
  obtain ⟨ld, r6, h6, h⟩ := bind_run h
  obtain ⟨rfl, rfl⟩ := pure_run h
  obtain ⟨e1, -⟩ := take_run h1
  have e2 := (blob_run h2).1
  have e3 := (blob_run h3).1
  have e4 := (blob_run h4).1
  have e5 := (nat_run h5).1
  obtain ⟨e6, l6⟩ := take_run h6
  subst e1; subst e2; subst e3; subst e4; subst e5; subst e6
  exact ⟨by simp [encMove], l6⟩

theorem pMoves_run {b r : Bytes} {ms : List Move} (h : pMoves.run b = some (ms, r)) :
    encMoves ms ++ r = b ∧ (∀ m ∈ ms, m.lineDigest.length = 64) ∧ ascending (ms.map (·.cell)) = true := by
  obtain ⟨_, r1, h1, h⟩ := bind_run h
  obtain ⟨k, r2, h2, h⟩ := bind_run h
  obtain ⟨xs, r3, h3, h⟩ := bind_run h
  obtain ⟨_, r4, h4, h⟩ := bind_run h
  obtain ⟨rfl, rfl⟩ := pure_run h
  obtain ⟨asc, rfl⟩ := need_run h4
  have e1 := expect_run h1
  have e2 := (nat_run h2).1
  obtain ⟨e3, hl, hq⟩ :=
    many_run (e := encMove) (Q := fun m => m.lineDigest.length = 64) (fun h => pMove_run h) k h3
  subst hl; subst e1; subst e2; subst e3
  exact ⟨by simp [encMoves], hq, asc⟩

theorem pApproval_run {b r : Bytes} {a : Approval} (h : pApproval.run b = some (a, r)) : encApproval a ++ r = b := by
  obtain ⟨_, r0, h0, h⟩ := bind_run h
  obtain ⟨kind, r1, h1, h⟩ := bind_run h
  obtain ⟨subject, r2, h2, h⟩ := bind_run h
  obtain ⟨arg, r3, h3, h⟩ := bind_run h
  obtain ⟨md, r4, h4, h⟩ := bind_run h
  obtain ⟨owner, r5, h5, h⟩ := bind_run h
  obtain ⟨mode, r6, h6, h⟩ := bind_run h
  obtain ⟨pack, r7, h7, h⟩ := bind_run h
  obtain ⟨na, r8, h8, h⟩ := bind_run h
  obtain ⟨rfl, rfl⟩ := pure_run h
  have e0 := expect_run h0
  have e1 := tag_run h1
  obtain ⟨e2, -⟩ := take_run h2
  have e3 := (blob_run h3).1
  obtain ⟨e4, -⟩ := take_run h4
  have e5 := ident_run h5
  have e6 := ident_run h6
  obtain ⟨e7, -⟩ := take_run h7
  have e8 := (nat_run h8).1
  subst e0; subst e1; subst e2; subst e3; subst e4; subst e5; subst e6; subst e7; subst e8
  simp [encApproval]

theorem parse_run {α : Type} {p : P α} {limit : Nat} {b : Bytes} {x : α} (h : parse p limit b = some x) :
    p.run b = some (x, []) := by
  unfold parse at h
  split at h
  · simp at h
  · split at h
    · cases h; assumption
    · simp at h

/-- The moves decoder accepts only canonical bytes: re-encoding what it returns gives back the input. -/
theorem decodeMoves_canonical {b : Bytes} {ms : List Move} (h : decodeMoves b = some ms) : encMoves ms = b := by
  simpa using (pMoves_run (parse_run h)).1

/-- Every decoded move's `lineDigest` is exactly 64 bytes, so 32- and 65-byte digests are refused. -/
theorem decodeMoves_lineDigest {b : Bytes} {ms : List Move} (h : decodeMoves b = some ms) :
    ∀ m ∈ ms, m.lineDigest.length = 64 :=
  (pMoves_run (parse_run h)).2.1

/-- Decoded moves are in strictly ascending cell order: one move per cell. -/
theorem decodeMoves_ascending {b : Bytes} {ms : List Move} (h : decodeMoves b = some ms) :
    ascending (ms.map (·.cell)) = true :=
  (pMoves_run (parse_run h)).2.2

theorem decodeApproval_canonical {b : Bytes} {a : Approval} (h : decodeApproval b = some a) : encApproval a = b := by
  simpa using pApproval_run (parse_run h)

end BlindLedger.Gate.Approval
