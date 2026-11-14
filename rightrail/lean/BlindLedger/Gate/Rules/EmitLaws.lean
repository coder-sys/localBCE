import BlindLedger.Gate.AuthorityLaws
import BlindLedger.Gate.Rules.Run
import BlindLedger.Gate.Rules.Theorems

namespace BlindLedger.Gate.Rules.Run

open BlindLedger.Gate.Rules

/-! What a leaf says about its authority and its bypass.  Every statement is about `emit`, which reads the grant only
    through `Authority.entryFor` and a bypass only through an admitted `Authority.Bypass`. -/

/-- The shape of every leaf `emit` makes. -/
theorem emit_shape {hsh : Bytes → Bytes} {g : Authority.Grant} {bps : List Authority.Bypass} {c : Ctx}
    {ds : List Decision} {unf : Nat → Bool} {e : Req} {m : Pay} (h : emit hsh g bps c ds unf e = some m) :
    ∃ en, Authority.entryFor g e.r.programId e.r.flow = some en ∧ m.authority = en.authority ∧ m.grantId = g.id ∧
      m.outcome = (if unf e.q then Outcome.HOLD else if m.bypass != Gate.zeroDigest then .ALLOW
        else limited en (c.redo.contains e.q) ds e.q (payOutcome c ds e.q)) ∧
      (m.bypass = Gate.zeroDigest ∨ ∃ b, bps.filter (fun b => b.program == e.r.programId && b.payment == e.r.paymentId) = [b] ∧
        m.bypass = b.id ∧ unf e.q = false ∧ bypassed c ds e.q = true ∧ b.request = hsh e.x.toList) := by
  unfold emit emitWith at h
  obtain ⟨en, he, h⟩ := Option.bind_eq_some_iff.mp h
  injection h with h
  refine ⟨en, he, ?_⟩
  subst h
  refine ⟨rfl, rfl, rfl, ?_⟩
  dsimp only
  split
  · rename_i b hb
    split
    · rename_i hc
      simp only [Bool.and_eq_true, Bool.not_eq_true', bne_iff_ne, ne_eq, beq_iff_eq] at hc
      exact Or.inr ⟨b, hb, rfl, hc.1.1.1, hc.1.1.2, hc.1.2⟩
    · exact Or.inl rfl
  · exact Or.inl rfl

theorem emit_authority {hsh : Bytes → Bytes} {g : Authority.Grant} {bps : List Authority.Bypass} {c : Ctx}
    {ds : List Decision} {unf : Nat → Bool} {e : Req} {m : Pay} (h : emit hsh g bps c ds unf e = some m) :
    ∃ en ∈ g.entries, Authority.covers en e.r.programId e.r.flow = true ∧ m.authority = en.authority ∧ m.grantId = g.id := by
  obtain ⟨en, he, ha, hg, -⟩ := emit_shape h
  have hf : g.entries.find? (fun x => Authority.covers x e.r.programId e.r.flow) = some en := he
  exact ⟨en, List.mem_of_find?_eq_some hf, (by have := List.find?_some hf; simpa using this), ha, hg⟩

/-- Leaf authority is at most the covering entry's. -/
theorem emit_authority_le {hsh : Bytes → Bytes} {g : Authority.Grant} {bps : List Authority.Bypass} {c : Ctx}
    {ds : List Decision} {unf : Nat → Bool} {e : Req} {m : Pay} (h : emit hsh g bps c ds unf e = some m) :
    ∃ en ∈ g.entries, Authority.covers en e.r.programId e.r.flow = true ∧ m.authority.rank ≤ en.authority.rank := by
  obtain ⟨en, hm, hc, ha, -⟩ := emit_authority h
  exact ⟨en, hm, hc, by rw [ha]; exact Nat.le_refl _⟩

theorem no_transfer_without_grant {hsh : Bytes → Bytes} {g : Authority.Grant} {bps : List Authority.Bypass} {c : Ctx}
    {ds : List Decision} {unf : Nat → Bool} {e : Req} {m : Pay} (h : emit hsh g bps c ds unf e = some m)
    (ht : m.authority = .TRANSFER) :
    ∃ en ∈ g.entries, Authority.covers en e.r.programId e.r.flow = true ∧ en.authority = .TRANSFER := by
  obtain ⟨en, hm, hc, ha, -⟩ := emit_authority h
  exact ⟨en, hm, hc, ha ▸ ht⟩

theorem observe_never_transfer {hsh : Bytes → Bytes} {g : Authority.Grant} {bps : List Authority.Bypass} {c : Ctx}
    {ds : List Decision} {unf : Nat → Bool} {e : Req} {m : Pay} (h : emit hsh g bps c ds unf e = some m)
    (ho : ∀ en ∈ g.entries, Authority.covers en e.r.programId e.r.flow = true → en.authority = .OBSERVE) :
    m.authority ≠ .TRANSFER := by
  intro ht
  obtain ⟨en, hm, hc, he⟩ := no_transfer_without_grant h ht
  have := ho en hm hc
  rw [he] at this
  exact absurd this (by decide)

/-- At HOLD level a leaf with decided lines that is not ALLOW, and not a re-decision, holds for a reason the grant names,
    or for one no grant lifts (not bypassable: a line decided already, a duplicate, an invalid service date).  A
    re-decision keeps the rules' outcome (`redo_never_lifted`). -/
theorem hold_within_grant {hsh : Bytes → Bytes} {g : Authority.Grant} {bps : List Authority.Bypass} {c : Ctx}
    {ds : List Decision} {unf : Nat → Bool} {e : Req} {m : Pay} (h : emit hsh g bps c ds unf e = some m)
    (hh : m.authority = .HOLD) (hn : m.outcome ≠ .ALLOW) (hu : unf e.q = false) (hl : ∃ d ∈ ds, d.line.pay = e.q)
    (hrd : c.redo.contains e.q = false) :
    ∃ en ∈ g.entries, Authority.covers en e.r.programId e.r.flow = true ∧
      ∃ d ∈ ds, d.line.pay = e.q ∧ ∃ r ∈ d.reasons, Keyset.bit en.holds r.idx = true ∨ bypassable r = false := by
  obtain ⟨en, he, ha, -, ho, -⟩ := emit_shape h
  have hf : g.entries.find? (fun x => Authority.covers x e.r.programId e.r.flow) = some en := he
  refine ⟨en, List.mem_of_find?_eq_some hf, (by have := List.find?_some hf; simpa using this), ?_⟩
  rw [hu] at ho
  by_cases hb : (m.bypass != Gate.zeroDigest) = true
  · simp [hb] at ho; rw [ho] at hn; exact absurd rfl hn
  · simp only [hb, Bool.false_eq_true, if_false] at ho
    rw [ho] at hn
    unfold limited at hn
    have hhold : (en.authority == .HOLD) = true := by simp [← ha, hh]
    refine Classical.byContradiction fun hno => hn ?_
    by_cases hoo : payOutcome c ds e.q = .ALLOW
    · split <;> first | rfl | exact hoo
    · have hlift : lifts en.holds ds e.q (payOutcome c ds e.q) = true := lifts_iff.mpr ⟨hoo, hl, fun d hd hp r hr => by
        have hx : ¬(Keyset.bit en.holds r.idx = true ∨ bypassable r = false) := fun hx => hno ⟨d, hd, hp, r, hr, hx⟩
        unfold Keyset.bit at hx
        revert hx
        cases bypassable r <;> cases (en.holds >>> r.idx % 2 == 1) <;> simp⟩
      rw [if_pos (by rw [hrd]; simp [hhold, hlift])]

/-- A leaf whose request has no decided lines is never ALLOW, under any grant and any bypass: the rules' outcome for it is
    HUMAN_REVIEW, `limited` needs decided lines, and `bypassed` needs an unresolved line of the payment. -/
theorem no_lines_not_allow {hsh : Bytes → Bytes} {g : Authority.Grant} {bps : List Authority.Bypass} {c : Ctx}
    {ds : List Decision} {unf : Nat → Bool} {e : Req} {m : Pay} (h : emit hsh g bps c ds unf e = some m)
    (hn : ∀ d ∈ ds, d.line.pay ≠ e.q) : m.outcome ≠ .ALLOW := by
  have hf : ds.filter (·.line.pay == e.q) = [] := List.filter_eq_nil_iff.mpr fun d hd => by simpa using hn d hd
  obtain ⟨en, -, -, -, ho, hz⟩ := emit_shape h
  rw [ho]
  by_cases hu : unf e.q = true
  · simp [hu]
  · have hu' : unf e.q = false := by simpa using hu
    have hb : m.bypass = Gate.zeroDigest := by
      rcases hz with hz | ⟨b, -, -, -, hbp, -⟩
      · exact hz
      · exfalso
        unfold bypassed at hbp
        split at hbp
        · simp at hbp
        · simp only [Bool.and_eq_true] at hbp
          obtain ⟨-, hany⟩ := hbp.1
          obtain ⟨d, hd, hd2⟩ := List.any_eq_true.mp hany
          exact hn d hd (by simp at hd2; exact hd2.1)
    have hany : ds.any (·.line.pay == e.q) = false := List.any_eq_false.mpr fun d hd h => hn d hd (by simpa using h)
    simp only [hu', hb, bne_self_eq_false, Bool.false_eq_true, if_false]
    unfold limited lifts payOutcome
    simp [hf, hany]

/-- At TRANSFER, an unbypassed ALLOW is the rules' ALLOW. -/
theorem transfer_allow_is_rules {hsh : Bytes → Bytes} {g : Authority.Grant} {bps : List Authority.Bypass} {c : Ctx}
    {ds : List Decision} {unf : Nat → Bool} {e : Req} {m : Pay} (h : emit hsh g bps c ds unf e = some m)
    (ht : m.authority = .TRANSFER) (ha : m.outcome = .ALLOW) (hb : m.bypass = Gate.zeroDigest) :
    payOutcome c ds e.q = .ALLOW := by
  obtain ⟨en, -, hat, -, ho, -⟩ := emit_shape h
  rw [hb] at ho
  have hne : en.authority ≠ .HOLD := by rw [← hat, ht]; decide
  by_cases hu : unf e.q = true
  · simp [hu] at ho; rw [ho] at ha; exact absurd ha (by decide)
  · simp only [hu, Bool.false_eq_true, if_false, bne_self_eq_false] at ho
    unfold limited at ho
    have : (en.authority == .HOLD) = false := by simpa using hne
    simp only [this, Bool.false_and, Bool.false_eq_true, if_false] at ho
    rwa [ho] at ha

/-- A leaf sent ALLOW with no bypass, for a payment the rules do not allow, went at HOLD authority: its lines are ones the
    batch releases (`limitedPay`), when the batch's `lim` gives the covering entry's mask for its payment (`lookup_limOf`).
    A later batch then decides them `ALREADY_DECIDED` under any grant, so no authority releases them again
    (`one_payment_per_line`). -/
theorem hold_allow_limited {hsh : Bytes → Bytes} {g : Authority.Grant} {bps : List Authority.Bypass} {c : Ctx}
    {ds : List Decision} {unf : Nat → Bool} {e : Req} {m : Pay} (h : emit hsh g bps c ds unf e = some m)
    (ha : m.outcome = .ALLOW) (hb : m.bypass = Gate.zeroDigest) (hr : payOutcome c ds e.q ≠ .ALLOW)
    (hl : ∀ en, Authority.entryFor g e.r.programId e.r.flow = some en → en.authority = .HOLD →
      c.lim.lookup e.q = some en.holds) :
    limitedPay c ds e.q = true := by
  obtain ⟨en, he, -, -, ho, -⟩ := emit_shape h
  rw [hb] at ho
  by_cases hu : unf e.q = true
  · simp [hu] at ho; rw [ho] at ha; exact absurd ha (by decide)
  · simp only [hu, Bool.false_eq_true, if_false, bne_self_eq_false] at ho
    unfold limited at ho
    rw [ho] at ha
    split at ha
    · rename_i hc
      simp only [Bool.and_eq_true, beq_iff_eq, Bool.not_eq_true'] at hc
      unfold limitedPay
      rw [hl en he hc.1.1]
      show (!c.redo.contains e.q && lifts en.holds ds e.q (payOutcome c ds e.q)) = true
      rw [hc.1.2, hc.2]
      rfl
    · exact absurd ha hr

/-- A re-decision (a payment released before) is never lifted: no HOLD-level entry releases it (`limitedPay`), and its
    leaf, with no bypass (`bypassed` needs a payment that is not a re-decision), is the rules' outcome, or HOLD when the
    request is held as unfit. -/
theorem limitedPay_redo {c : Ctx} {ds : List Decision} {p : Nat} (hr : c.redo.contains p = true) :
    limitedPay c ds p = false := by
  unfold limitedPay
  split
  · rfl
  · rw [hr]; rfl

theorem redo_never_lifted {hsh : Bytes → Bytes} {g : Authority.Grant} {bps : List Authority.Bypass} {c : Ctx}
    {ds : List Decision} {unf : Nat → Bool} {e : Req} {m : Pay} (h : emit hsh g bps c ds unf e = some m)
    (hr : c.redo.contains e.q = true) :
    m.bypass = Gate.zeroDigest ∧ m.outcome = (if unf e.q then Outcome.HOLD else payOutcome c ds e.q) := by
  obtain ⟨en, -, -, -, ho, hz⟩ := emit_shape h
  have hb : m.bypass = Gate.zeroDigest := by
    rcases hz with hz | ⟨b, -, -, -, hbp, -⟩
    · exact hz
    · exfalso
      unfold bypassed at hbp
      split at hbp
      · cases hbp
      · rw [hr, Bool.not_true, Bool.false_and, Bool.false_and] at hbp
        exact Bool.false_ne_true hbp
  refine ⟨hb, ?_⟩
  rw [ho, hb, bne_self_eq_false]
  unfold limited
  rw [hr]
  simp only [Bool.not_true, Bool.and_false, Bool.false_and, Bool.false_eq_true, ↓reduceIte]

/-- The batch's `lim` (`limOf` over the frame's requests, one per payment number) gives a request's covering HOLD-level
    entry's mask. -/
theorem lookup_limOf {g : Authority.Grant} {e : Req} {en : Authority.Entry}
    (hen : Authority.entryFor g e.r.programId e.r.flow = some en) (hh : en.authority = .HOLD) :
    ∀ {reqs : List Req}, e ∈ reqs → (∀ e' ∈ reqs, e'.q = e.q → e' = e) → (limOf g reqs).lookup e.q = some en.holds
  | [], he, _ => by cases he
  | a :: rs, he, hq => by
    by_cases hae : a = e
    · subst hae
      simp [limOf, hen, hh]
    · have ht := lookup_limOf hen hh ((List.mem_cons.mp he).resolve_left (Ne.symm hae))
        fun e' h => hq e' (List.mem_cons_of_mem _ h)
      have hne : (e.q == a.q) = false := by simpa using fun h => hae (hq a List.mem_cons_self h.symm)
      simp only [limOf, List.filterMap_cons] at ht ⊢
      cases hx : Authority.entryFor g a.r.programId a.r.flow with
      | none => simpa [hx] using ht
      | some ea =>
        by_cases hea : ea.authority = .HOLD
        · simp only [hea, Option.bind_some, beq_self_eq_true, if_true, List.lookup, hne]
          exact ht
        · simpa [hx, hea] using ht

theorem mem_of_lookup : ∀ {l : List (Nat × Nat)} {p m : Nat}, l.lookup p = some m → (p, m) ∈ l
  | [], _, _, h => by cases h
  | (k, v) :: l, p, m, h => by
    unfold List.lookup at h
    split at h
    · rename_i hk
      injection h with h
      subst h
      rw [beq_iff_eq.mp hk]
      exact List.mem_cons_self
    · exact List.mem_cons_of_mem _ (mem_of_lookup h)

/-- A `lim` entry comes only from a HOLD-level entry of the admitted grant: the batch's `lim` (`limOf`) gives payment `p`
    mask `m` only when a request of the frame for payment `p` is covered by a HOLD-level entry whose holds mask is `m`. -/
theorem limOf_sound {g : Authority.Grant} {reqs : List Req} {p m : Nat} (h : (limOf g reqs).lookup p = some m) :
    ∃ e ∈ reqs, e.q = p ∧ ∃ en, Authority.entryFor g e.r.programId e.r.flow = some en ∧ en.authority = .HOLD ∧
      en.holds = m := by
  obtain ⟨e, he, hf⟩ := List.mem_filterMap.mp (mem_of_lookup h)
  obtain ⟨en, hen, hi⟩ := Option.bind_eq_some_iff.mp hf
  split at hi
  · rename_i hh
    simp only [Option.some.injEq, Prod.mk.injEq] at hi
    exact ⟨e, he, hi.1, en, hen, beq_iff_eq.mp hh, hi.2⟩
  · cases hi

/-- A bypassed leaf has exactly one admitted bypass, naming its payment and request digest. -/
theorem bypass_attributed {hsh : Bytes → Bytes} {g : Authority.Grant} {bps : List Authority.Bypass} {c : Ctx}
    {ds : List Decision} {unf : Nat → Bool} {e : Req} {m : Pay} (h : emit hsh g bps c ds unf e = some m)
    (hb : m.bypass ≠ Gate.zeroDigest)
    (_hu : (bps.map fun b => (b.program, b.payment)).Nodup) :
    ∃ b, bps.filter (fun b => b.program = e.r.programId ∧ b.payment = e.r.paymentId) = [b] ∧
      m.bypass = b.id ∧ b.request = hsh e.x.toList ∧ bypassed c ds e.q = true := by
  obtain ⟨-, -, -, -, -, hz | ⟨b, hf, hid, -, hbp, hr⟩⟩ := emit_shape h
  · exact absurd hz hb
  · exact ⟨b, (List.filter_congr fun b _ => Bool.eq_iff_iff.mpr (by simp)).trans hf, hid, hr, hbp⟩

/-- A frame never lowers the stored grant serial floor: the floor it asserts is the stored one or above (a lower one
    refuses). -/
theorem effFloor_ge {stored f : Nat} {fr : Option Nat} (h : effFloor stored fr = some f) : stored ≤ f := by
  cases fr with
  | none => simp [effFloor] at h; omega
  | some n =>
    unfold effFloor at h
    by_cases hn : n < stored
    · simp [hn] at h
    · simp [hn] at h; omega

/-- XI.2 (stored authority record).  After a commit the stored floor is the admitted grant's serial; it is never below the
    floor stored before, so a revoked grant (a lower serial) stays refused. -/
theorem floor_monotone {verify : Bytes → Bytes → Bytes → Bool} {H : SnapshotV2.Head} {t : Bytes} {stored f : Nat}
    {fr : Option Nat} {x : Bytes} {g : Authority.Grant} (hf : effFloor stored fr = some f)
    (hg : Authority.admitGrant verify H t f x = .ok g) : stored ≤ g.serial := by
  obtain ⟨-, -, -, -, -, -, -, hs, -⟩ := Authority.admitGrant_sound hg
  exact Nat.le_trans (effFloor_ge hf) hs

/-- A frame is admitted only under a key-set head at or past the epoch its `kfloor` asserts (the tenant's newest, which
    the host sends to every shard): a key set superseded on one shard of the tenant is refused on every shard. -/
theorem admit_keyset_floor {verify : Bytes → Bytes → Bytes → Bool} {pin : Bytes} {rat : Keyset.Ratchet} {stored : Nat}
    {st : St} {a : Admitted} (h : admit verify pin rat stored st = .ok a) {e : Nat} (he : st.kfloorIn = some e) :
    e ≤ a.ratchet.epoch := by
  unfold admit at h
  split at h
  · split at h
    · cases h
    · split at h
      · cases h
      · split at h
        · cases h
        · split at h
          · cases h
          · cases h
            simp_all
  · cases h

end BlindLedger.Gate.Rules.Run
