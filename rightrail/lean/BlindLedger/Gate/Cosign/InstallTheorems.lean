import BlindLedger.Gate.Cosign.Install
import BlindLedger.Gate.Cosign.Theorems

/-! What the two steps of the authority state guarantee, for every `Crypto`.  A link answered `same`, `stale` or
    `refused` changes nothing; an installed or conflicting link raises the fence to its generation; no step drops a
    certificate, an equivocation or a conflict.  A link is installed only when its keys are apart from every
    installed certificate's, and that is the only way certificates bear on a link's answer.  A certificate whose
    body is held is answered `same` before any verification; a certificate enters only verified against the tenant's
    chain and its retired links.  Together: every installed certificate keeps one key per purpose against every
    link held for its tenant, whichever arrived first (`Apart`). -/
namespace BlindLedger.Gate.Cosign

open BlindLedger.Gate

theorem Chain.start_spec {l : Link} {g : Chain} (h : Chain.start l = some g) : g.head = l ∧ g.earlier = [] := by
  unfold Chain.start at h
  split at h
  · cases h; exact ⟨rfl, rfl⟩
  · cases h

theorem Chain.push_spec {c g : Chain} {l : Link} (h : c.push l = some g) :
    g.head = l ∧ g.earlier = c.head :: c.earlier := by
  unfold Chain.push at h
  split at h
  · cases h; exact ⟨rfl, rfl⟩
  · cases h

theorem le_raiseFence (f : Bytes → Nat) (t : Bytes) (x : Nat) (u : Bytes) : f u ≤ raiseFence f t x u := by
  unfold raiseFence
  split
  · exact Nat.le_max_left _ _
  · exact Nat.le_refl _

theorem raiseFence_self (f : Bytes → Nat) (t : Bytes) (x : Nat) : x ≤ raiseFence f t x t := by
  unfold raiseFence
  rw [if_pos rfl]
  exact Nat.le_max_right _ _

/-! ### Links -/

/-- A link answered `same`, `stale` or `refused` has no effect. -/
theorem installLink_noop {c : Crypto} {pin : Bytes} {s : Auth} {n : SignedLink}
    (h : (installLink c pin s n).2 = .same ∨ (installLink c pin s n).2 = .stale ∨
      (installLink c pin s n).2 = .refused) : (installLink c pin s n).1 = s := by
  revert h
  unfold installLink
  repeat' split
  all_goals simp

/-- No link drops a certificate, an equivocation or a conflict, or lowers a fence. -/
theorem installLink_keeps (c : Crypto) (pin : Bytes) (s : Auth) (n : SignedLink) :
    (installLink c pin s n).1.certs = s.certs ∧ (installLink c pin s n).1.equivocations = s.equivocations ∧
      (∀ q ∈ s.conflicts, q ∈ (installLink c pin s n).1.conflicts) ∧
      ∀ t, s.fence t ≤ (installLink c pin s n).1.fence t := by
  unfold installLink
  repeat' split
  all_goals exact ⟨rfl, rfl, fun q hq => by first | exact hq | exact List.mem_cons_of_mem _ hq,
    fun t => by first | exact Nat.le_refl _ | exact le_raiseFence _ _ _ t⟩

/-- A genesis, an extending link and a conflicting link each raise the tenant's fence to the first epoch of the
    link's generation: a rotation is an epoch change. -/
theorem installLink_fence {c : Crypto} {pin : Bytes} {s : Auth} {n : SignedLink}
    (h : (installLink c pin s n).2 = .genesis ∨ (installLink c pin s n).2 = .extends ∨
      (installLink c pin s n).2 = .conflicts) :
    n.gen * genSpan ≤ (installLink c pin s n).1.fence n.tenantId := by
  revert h
  unfold installLink
  repeat' split
  all_goals simp [raiseFence_self]

/-- A link is installed only when its keys and commitments are apart from the keys of every installed certificate
    of its tenant, and the keys it brings into office have served in no held link of the tenant. -/
theorem installLink_keys {c : Crypto} {pin : Bytes} {s : Auth} {n : SignedLink}
    (h : (installLink c pin s n).2 = .genesis ∨ (installLink c pin s n).2 = .extends) :
    certsApart c s n = true ∧ freshKeys s n = true := by
  revert h
  unfold installLink
  repeat' split
  all_goals simp_all

/-- Installed certificates bear on a link's answer through their keys and in no other way: when the link's keys
    are apart from theirs, the answer is the answer of the same state holding no certificate at all. -/
theorem installLink_certs_only_by_key {c : Crypto} {pin : Bytes} {s : Auth} {n : SignedLink}
    (h : certsApart c s n = true) :
    (installLink c pin s n).2 = (installLink c pin { s with certs := [], equivocations := [] } n).2 := by
  have h0 : certsApart c { s with certs := [], equivocations := [] } n = true := by simp [certsApart]
  unfold installLink
  simp only [h, h0, linksOf, retiredLinks, freshKeys, Bool.and_true]
  repeat' split
  all_goals rfl

theorem linksOf_eq (s : Auth) (t : Bytes) :
    linksOf s t = ((s.chainOf t).toList ++ s.retired t).flatMap (·.links) := by
  unfold linksOf retiredLinks
  cases s.chainOf t <;> simp

theorem linksOf_congr {s s' : Auth} {t : Bytes} (h1 : s'.chainOf t = s.chainOf t) (h2 : s'.retired t = s.retired t) :
    linksOf s' t = linksOf s t := by
  unfold linksOf retiredLinks
  rw [h1, h2]

theorem linksOf_start {s s' : Auth} {t : Bytes} {g : Chain} {l : Link} (hs : Chain.start l = some g)
    (h1 : s'.chainOf t = some g) (h2 : s'.retired t = (s.chainOf t).toList ++ s.retired t) :
    linksOf s' t = l :: linksOf s t := by
  obtain ⟨hh, he⟩ := Chain.start_spec hs
  rw [linksOf_eq s t, ← h2]
  simp [linksOf, retiredLinks, h1, Chain.links, hh, he]

theorem linksOf_push {s s' : Auth} {t : Bytes} {ch ch' : Chain} {l : Link} (h0 : s.chainOf t = some ch)
    (hp : ch.push l = some ch') (h1 : s'.chainOf t = some ch') (h2 : s'.retired t = s.retired t) :
    linksOf s' t = l :: linksOf s t := by
  obtain ⟨hh, he⟩ := Chain.push_spec hp
  simp [linksOf, retiredLinks, h0, h1, h2, Chain.links, hh, he]

/-- A genesis leaves the tenant with the chain of that one link and retires the chain it held; no other tenant's
    chains move. -/
theorem installLink_genesis {c : Crypto} {pin : Bytes} {s : Auth} {n : SignedLink}
    (h : (installLink c pin s n).2 = .genesis) :
    ∃ g, Chain.start (n.link c.hash) = some g ∧ (installLink c pin s n).1.chainOf n.tenantId = some g ∧
      (installLink c pin s n).1.retired n.tenantId = (s.chainOf n.tenantId).toList ++ s.retired n.tenantId ∧
      ∀ t, t ≠ n.tenantId →
        (installLink c pin s n).1.chainOf t = s.chainOf t ∧ (installLink c pin s n).1.retired t = s.retired t := by
  revert h
  unfold installLink
  repeat' split
  all_goals first
    | (intro h; cases h; done)
    | (rename_i g hg _
       intro _
       exact ⟨g, hg, by simp, by simp, fun t ht => by simp [ht]⟩)

/-- Every link held for the tenant before a genesis is retired by it: it still counts for key reuse. -/
theorem genesis_retires {c : Crypto} {pin : Bytes} {s : Auth} {n : SignedLink}
    (h : (installLink c pin s n).2 = .genesis) :
    ∀ p ∈ linksOf s n.tenantId, p ∈ retiredLinks (installLink c pin s n).1 n.tenantId := by
  obtain ⟨g, -, -, h2, -⟩ := installLink_genesis h
  intro p hp
  unfold retiredLinks
  rw [h2, ← linksOf_eq]
  exact hp

/-- An extending link becomes the head of the tenant's chain, over the chain as it was; nothing is retired and no
    other tenant's chain moves. -/
theorem installLink_extends {c : Crypto} {pin : Bytes} {s : Auth} {n : SignedLink}
    (h : (installLink c pin s n).2 = .extends) :
    ∃ ch ch', s.chainOf n.tenantId = some ch ∧ ch.push (n.link c.hash) = some ch' ∧
      (installLink c pin s n).1.chainOf n.tenantId = some ch' ∧ (installLink c pin s n).1.retired = s.retired ∧
      ∀ t, t ≠ n.tenantId → (installLink c pin s n).1.chainOf t = s.chainOf t := by
  revert h
  unfold installLink
  repeat' split
  all_goals first
    | (intro h; cases h; done)
    | (rename_i ch hc _ _ ch' hp _
       intro _
       exact ⟨ch, ch', hc, hp, by simp, rfl, fun t ht => by simp [ht]⟩)

/-- Only a genesis and an extending link change a chain or retire one. -/
theorem installLink_chains {c : Crypto} {pin : Bytes} {s : Auth} {n : SignedLink}
    (hg : (installLink c pin s n).2 ≠ .genesis) (he : (installLink c pin s n).2 ≠ .extends) :
    (installLink c pin s n).1.chainOf = s.chainOf ∧ (installLink c pin s n).1.retired = s.retired := by
  revert hg he
  unfold installLink
  repeat' split
  all_goals simp

/-- A recorded conflict blocks every epoch of the tenant from the conflicting link's generation on. -/
theorem conflict_blocks {c : Crypto} {pin : Bytes} {s : Auth} {n : SignedLink} {epoch : Nat}
    (h : (installLink c pin s n).2 = .conflicts) (hg : n.gen ≤ genOf epoch) :
    linkBlocked (installLink c pin s n).1 n.tenantId epoch = true := by
  revert h
  unfold installLink
  repeat' split
  all_goals first
    | (intro h; cases h; done)
    | (rename_i ch hc _ _
       intro _
       simp [linkBlocked, hc, SignedLink.link, hg])

/-- Every link held for a tenant after a step was held before it, or is the link just installed, whose keys are
    apart from every installed certificate's. -/
theorem installLink_links {c : Crypto} {pin : Bytes} {s : Auth} {n : SignedLink} {t : Bytes} {p : Link}
    (hp : p ∈ linksOf (installLink c pin s n).1 t) :
    p ∈ linksOf s t ∨ (p = n.link c.hash ∧ t = n.tenantId ∧ certsApart c s n = true) := by
  by_cases hg : (installLink c pin s n).2 = .genesis
  · obtain ⟨g, hs, h1, h2, h3⟩ := installLink_genesis hg
    by_cases ht : t = n.tenantId
    · subst ht
      rw [linksOf_start hs h1 h2] at hp
      rcases List.mem_cons.1 hp with rfl | hp
      · exact .inr ⟨rfl, rfl, (installLink_keys (.inl hg)).1⟩
      · exact .inl hp
    · rw [linksOf_congr (h3 t ht).1 (h3 t ht).2] at hp
      exact .inl hp
  · by_cases he : (installLink c pin s n).2 = .extends
    · obtain ⟨ch, ch', h0, hpush, h1, h2, h3⟩ := installLink_extends he
      by_cases ht : t = n.tenantId
      · subst ht
        rw [linksOf_push h0 hpush h1 (congrFun h2 _)] at hp
        rcases List.mem_cons.1 hp with rfl | hp
        · exact .inr ⟨rfl, rfl, (installLink_keys (.inr he)).1⟩
        · exact .inl hp
      · rw [linksOf_congr (h3 t ht) (congrFun h2 t)] at hp
        exact .inl hp
    · obtain ⟨h1, h2⟩ := installLink_chains hg he
      rw [linksOf_congr (congrFun h1 t) (congrFun h2 t)] at hp
      exact .inl hp

/-! ### Certificates -/

/-- A certificate whose body is installed is answered `same` with no effect, before any verification: whatever the
    chain has become, and whatever signatures the copy carries. -/
theorem installCert_same {c : Crypto} {s : Auth} {b : Bytes} {e : KeyCert} (hd : decode b = some e)
    (hx : ∃ x ∈ s.certs, x.body = e.body) : installCert c s b = (s, .same) := by
  obtain ⟨x, hm, hb⟩ := hx
  have ha : s.certs.any (·.body == e.body) = true := List.any_eq_true.2 ⟨x, hm, by simp [hb]⟩
  unfold installCert install record held
  simp [hd, ha]

/-- A step ends in `record` of the decoded certificate, or leaves the state as it was with one of the answers
    `same`, `unknownTenant`, `belowFence` or a refusal. -/
theorem installCert_cases (c : Crypto) (s : Auth) (b : Bytes) :
    ((installCert c s b).1 = s ∧ ((installCert c s b).2 = .same ∨ (installCert c s b).2 = .unknownTenant ∨
      (installCert c s b).2 = .belowFence ∨ ∃ r, (installCert c s b).2 = .refused r)) ∨
    ∃ e, installCert c s b = record s e := by
  cases hd : decode b with
  | none => exact .inl ⟨by simp [installCert, hd], .inr (.inr (.inr ⟨.MALFORMED, by simp [installCert, hd]⟩))⟩
  | some e =>
    cases hh : held s e with
    | true => exact .inl ⟨by simp [installCert, install, hd, hh], .inl (by simp [installCert, install, hd, hh])⟩
    | false =>
      cases hc : s.chainOf e.tenantId with
      | none =>
        exact .inl ⟨by simp [installCert, install, hd, hh, hc], .inr (.inl (by simp [installCert, install, hd, hh, hc]))⟩
      | some ch =>
        cases hj : judge c ch (retiredLinks s e.tenantId) e with
        | error r =>
          exact .inl ⟨by simp [installCert, install, hd, hh, hc, hj],
            .inr (.inr (.inr ⟨r, by simp [installCert, install, hd, hh, hc, hj]⟩))⟩
        | ok v =>
          by_cases hf : late s ch.head e = true
          · exact .inl ⟨by simp [installCert, install, hd, hh, hc, hj, hf],
              .inr (.inr (.inl (by simp [installCert, install, hd, hh, hc, hj, hf])))⟩
          · exact .inr ⟨e, by simp [installCert, install, hd, hh, hc, hj, hf]⟩

theorem record_answer (s : Auth) (e : KeyCert) :
    (record s e).2 = .installed ∨ (record s e).2 = .unfit ∨ (record s e).2 = .equivocates := by
  unfold record
  split
  · exact .inr (.inr rfl)
  · split
    · exact .inl rfl
    · exact .inr (.inl rfl)

/-- A certificate answered `same`, `unknownTenant` or refused has no effect. -/
theorem installCert_noop {c : Crypto} {s : Auth} {b : Bytes}
    (h : (installCert c s b).2 = .same ∨ (installCert c s b).2 = .unknownTenant ∨
      ∃ r, (installCert c s b).2 = .refused r) : (installCert c s b).1 = s := by
  rcases installCert_cases c s b with ⟨h1, -⟩ | ⟨e, he⟩
  · exact h1
  · exfalso
    rw [he] at h
    rcases record_answer s e with h2 | h2 | h2 <;> rw [h2] at h <;> rcases h with h | h | ⟨r, h⟩ <;> cases h

/-- No certificate changes a chain, a retired chain or a conflict, drops a certificate or an equivocation, or
    lowers a fence. -/
theorem installCert_keeps (c : Crypto) (s : Auth) (b : Bytes) :
    (installCert c s b).1.chainOf = s.chainOf ∧ (installCert c s b).1.retired = s.retired ∧
      (installCert c s b).1.conflicts = s.conflicts ∧ (∀ x ∈ s.certs, x ∈ (installCert c s b).1.certs) ∧
      (∀ q ∈ s.equivocations, q ∈ (installCert c s b).1.equivocations) ∧
      ∀ t, s.fence t ≤ (installCert c s b).1.fence t := by
  rcases installCert_cases c s b with ⟨h1, -⟩ | ⟨e, he⟩
  · rw [h1]
    exact ⟨rfl, rfl, rfl, fun x hx => hx, fun q hq => hq, fun t => Nat.le_refl _⟩
  · rw [he]
    unfold record
    split <;> (try split) <;> exact ⟨rfl, rfl, rfl, fun x hx => by first | exact hx | exact List.mem_cons_of_mem _ hx,
      fun q hq => by first | exact hq | exact List.mem_append_right _ hq,
      fun t => by first | exact Nat.le_refl _ | exact le_raiseFence _ _ _ t⟩

theorem verify_decoded {c : Crypto} {ch : Chain} {r : List Link} {b : Bytes} {v e : KeyCert}
    (hv : verify c ch r b = .ok v) (hd : decode b = some e) : v = e := by
  have h := (verify_ok.1 hv).1
  rw [hd] at h
  exact (Option.some.inj h).symm

theorem judge_decoded {c : Crypto} {ch : Chain} {r : List Link} {e v : KeyCert} (h : judge c ch r e = .ok v) :
    v = e := by
  revert h
  unfold judge judgeWith
  repeat' split
  all_goals (intro h; first | (cases h; rfl) | cases h)

/-- A certificate answered `installed`, `unfit` or `equivocates` decoded, was not held, and passed every check
    against its tenant's chain and retired links; the step is then `record`. -/
theorem installCert_recorded {c : Crypto} {s : Auth} {b : Bytes}
    (h : (installCert c s b).2 = .installed ∨ (installCert c s b).2 = .unfit ∨ (installCert c s b).2 = .equivocates) :
    ∃ e ch, decode b = some e ∧ held s e = false ∧ s.chainOf e.tenantId = some ch ∧
      judge c ch (retiredLinks s e.tenantId) e = .ok e ∧ installCert c s b = record s e := by
  cases hd : decode b with
  | none => simp [installCert, hd] at h
  | some e =>
    cases hh : held s e with
    | true => simp [installCert, install, hd, hh] at h
    | false =>
      cases hc : s.chainOf e.tenantId with
      | none => simp [installCert, install, hd, hh, hc] at h
      | some ch =>
        cases hj : judge c ch (retiredLinks s e.tenantId) e with
        | error r => simp [installCert, install, hd, hh, hc, hj] at h
        | ok v =>
          have hv := judge_decoded hj
          subst hv
          by_cases hf : late s ch.head v = true
          · simp [installCert, install, hd, hh, hc, hj, hf] at h
          · exact ⟨v, ch, rfl, hh, hc, hj, by simp [installCert, install, hd, hh, hc, hj, hf]⟩

/-- A late certificate is refused: one that is not held and passes every check against its tenant's chain, but whose
    epoch is below the fence its head link set (generation times 2^32) and that no installed certificate holds, is
    answered `belowFence`, whoever signed it. -/
theorem installCert_belowFence_iff {c : Crypto} {s : Auth} {b : Bytes} :
    (installCert c s b).2 = .belowFence ↔
      ∃ e ch v, decode b = some e ∧ held s e = false ∧ s.chainOf e.tenantId = some ch ∧
        judge c ch (retiredLinks s e.tenantId) e = .ok v ∧ late s ch.head e = true := by
  constructor
  · intro h
    cases hd : decode b with
    | none => simp [installCert, hd] at h
    | some e =>
      cases hh : held s e with
      | true => simp [installCert, install, hd, hh] at h
      | false =>
        cases hc : s.chainOf e.tenantId with
        | none => simp [installCert, install, hd, hh, hc] at h
        | some ch =>
          cases hj : judge c ch (retiredLinks s e.tenantId) e with
          | error r => simp [installCert, install, hd, hh, hc, hj] at h
          | ok v =>
            by_cases hf : late s ch.head e = true
            · exact ⟨e, ch, v, rfl, hh, hc, hj, hf⟩
            · exfalso
              have hr : (installCert c s b).2 = (record s e).2 := by simp [installCert, install, hd, hh, hc, hj, hf]
              rw [hr] at h
              unfold record at h
              repeat' split at h
              all_goals simp at h
  · rintro ⟨e, ch, v, hd, hh, hc, hj, hf⟩
    simp [installCert, install, hd, hh, hc, hj, hf]

/-- The answer `belowFence` leaves the state as it was: no row, no fence, no equivocation. -/
theorem installCert_belowFence_noop {c : Crypto} {s : Auth} {b : Bytes} (h : (installCert c s b).2 = .belowFence) :
    (installCert c s b).1 = s := by
  rcases installCert_cases c s b with ⟨h1, -⟩ | ⟨e, he⟩
  · exact h1
  · exfalso
    rw [he] at h
    rcases record_answer s e with h2 | h2 | h2 <;> rw [h2] at h <;> cases h

/-- Any other answer leaves the state as it was. -/
theorem installCert_unrecorded {c : Crypto} {s : Auth} {b : Bytes} (h1 : (installCert c s b).2 ≠ .installed)
    (h2 : (installCert c s b).2 ≠ .unfit) (h3 : (installCert c s b).2 ≠ .equivocates) : (installCert c s b).1 = s := by
  rcases installCert_cases c s b with ⟨h, -⟩ | ⟨e, he⟩
  · exact h
  · exfalso
    rw [he] at h1 h2 h3
    rcases record_answer s e with h | h | h
    · exact h1 h
    · exact h2 h
    · exact h3 h

/-- A step adds at most one certificate: the decoded one, on the answer `installed`, when its tenant had none
    for its epoch and it fits. -/
theorem installCert_adds (c : Crypto) (s : Auth) (b : Bytes) :
    (installCert c s b).1.certs = s.certs ∨ ∃ e, decode b = some e ∧ (installCert c s b).1.certs = e :: s.certs ∧
      (s.certs.any fun x => x.tenantId == e.tenantId && x.epoch == e.epoch) = false ∧ fits s e = true ∧
      (installCert c s b).2 = .installed := by
  by_cases hr : (installCert c s b).2 = .installed ∨ (installCert c s b).2 = .unfit ∨
      (installCert c s b).2 = .equivocates
  · obtain ⟨e, ch, hd, -, -, -, heq⟩ := installCert_recorded hr
    rw [heq]
    unfold record
    by_cases h1 : (s.certs.any fun x => x.tenantId == e.tenantId && x.epoch == e.epoch) = true
    · rw [if_pos h1]; exact .inl rfl
    · rw [if_neg h1]
      by_cases h2 : fits s e = true
      · rw [if_pos h2]; exact .inr ⟨e, hd, rfl, by simpa using h1, h2, rfl⟩
      · rw [if_neg h2]; exact .inl rfl
  · rw [installCert_unrecorded (fun h1 => hr (.inl h1)) (fun h2 => hr (.inr (.inl h2)))
      (fun h3 => hr (.inr (.inr h3)))]
    exact .inl rfl

/-- A certificate is installed only verified against its tenant's chain and that tenant's retired links. -/
theorem installCert_verified {c : Crypto} {s : Auth} {b : Bytes} {e : KeyCert}
    (h : e ∈ (installCert c s b).1.certs) :
    e ∈ s.certs ∨ ∃ ch, s.chainOf e.tenantId = some ch ∧ verify c ch (retiredLinks s e.tenantId) b = .ok e := by
  by_cases hr : (installCert c s b).2 = .installed ∨ (installCert c s b).2 = .unfit ∨
      (installCert c s b).2 = .equivocates
  · obtain ⟨x, ch, hd, -, hc, hj, heq⟩ := installCert_recorded hr
    rw [heq] at h
    unfold record at h
    split at h
    · exact .inl h
    · split at h
      · rcases List.mem_cons.1 h with rfl | h
        · exact .inr ⟨ch, hc, by simp only [verify, hd]; exact hj⟩
        · exact .inl h
      · exact .inl h
  · rw [installCert_unrecorded (fun h1 => hr (.inl h1)) (fun h2 => hr (.inr (.inl h2)))
      (fun h3 => hr (.inr (.inr h3)))] at h
    exact .inl h

/-- A verified certificate with another body than an installed certificate of its tenant and epoch is recorded
    with it, and the pair blocks that tenant and epoch. -/
theorem installCert_equivocation {c : Crypto} {s : Auth} {b : Bytes} (h : (installCert c s b).2 = .equivocates) :
    ∃ e x, decode b = some e ∧ x ∈ s.certs ∧ x.tenantId = e.tenantId ∧ x.epoch = e.epoch ∧ x.body ≠ e.body ∧
      (x, e) ∈ (installCert c s b).1.equivocations ∧ certBlocked (installCert c s b).1 e.tenantId e.epoch = true := by
  obtain ⟨e, ch, hd, hh, -, -, heq⟩ := installCert_recorded (.inr (.inr h))
  rw [heq] at h ⊢
  by_cases hr : (s.certs.any fun x => x.tenantId == e.tenantId && x.epoch == e.epoch) = true
  · obtain ⟨x, hm, hx⟩ := List.any_eq_true.1 hr
    simp only [Bool.and_eq_true, beq_iff_eq] at hx
    have hne : x.body ≠ e.body := fun hb => by
      have : held s e = true := by
        simp only [held, Bool.or_eq_true]; exact .inl (List.any_eq_true.2 ⟨x, hm, by simp [hb]⟩)
      rw [hh] at this; cases this
    have hmem : (x, e) ∈ (s.certs.filter fun x => x.tenantId == e.tenantId && x.epoch == e.epoch).map (·, e) ++
        s.equivocations :=
      List.mem_append_left _ (List.mem_map.2 ⟨x, List.mem_filter.2 ⟨hm, by simp [hx.1, hx.2]⟩, rfl⟩)
    refine ⟨e, x, hd, hm, hx.1, hx.2, hne, ?_, ?_⟩
    · simp only [record, hr, ↓reduceIte]; exact hmem
    · simp only [record, hr, ↓reduceIte, certBlocked]
      exact List.any_eq_true.2 ⟨(x, e), hmem, by simp [hx.1, hx.2]⟩
  · unfold record at h
    rw [if_neg hr] at h
    split at h <;> cases h

/-! ### One key per purpose, whichever arrived first -/

/-- Every installed certificate's two keys are apart from every link held for its tenant: the chain since the
    latest genesis and every retired chain. -/
def Apart (c : Crypto) (s : Auth) : Prop := ∀ e ∈ s.certs, keysApart c.hash (linksOf s e.tenantId) e = true

theorem keysApart_of_mem {H : Bytes → Bytes} {a : List Link} {e : KeyCert} (hk : e.key ≠ e.verifierKey)
    (h : ∀ p ∈ a, keysApart H [p] e = true) : keysApart H a e = true := by
  rw [keysApart_iff]
  refine ⟨hk, fun p hp => ?_, fun p hp => ?_⟩
  · exact (keysApart_iff.1 (h p hp)).2.1 p (List.mem_singleton.2 rfl)
  · exact (keysApart_iff.1 (h p hp)).2.2 p (List.mem_singleton.2 rfl)

theorem keysApart_mem {H : Bytes → Bytes} {a : List Link} {e : KeyCert} (h : keysApart H a e = true) {p : Link}
    (hp : p ∈ a) : keysApart H [p] e = true := by
  rw [keysApart_iff] at h ⊢
  exact ⟨h.1, fun q hq => by rw [List.mem_singleton.1 hq]; exact h.2.1 p hp,
    fun q hq => by rw [List.mem_singleton.1 hq]; exact h.2.2 p hp⟩

theorem Apart.empty (c : Crypto) : Apart c Auth.empty := fun _ h => by cases h

/-- Installing a certificate keeps the keys apart: the new one was verified against every held link. -/
theorem installCert_apart {c : Crypto} {s : Auth} (b : Bytes) (ha : Apart c s) : Apart c (installCert c s b).1 := by
  intro e he
  obtain ⟨h1, h2, -⟩ := installCert_keeps c s b
  have hl : linksOf (installCert c s b).1 e.tenantId = linksOf s e.tenantId := by
    simp only [linksOf, retiredLinks, h1, h2]
  rw [hl]
  rcases installCert_verified he with h | ⟨ch, hch, hv⟩
  · exact ha e h
  · obtain ⟨-, -, -, -, -, -, hk, -⟩ := verify_ok.1 hv
    simpa [linksOf, hch] using hk

/-- Installing a link keeps the keys apart: a link whose keys match an installed certificate's is refused. -/
theorem installLink_apart {c : Crypto} {pin : Bytes} {s : Auth} (n : SignedLink) (ha : Apart c s) :
    Apart c (installLink c pin s n).1 := by
  intro e he
  rw [(installLink_keeps c pin s n).1] at he
  have hold := ha e he
  refine keysApart_of_mem (keysApart_iff.1 hold).1 fun p hp => ?_
  rcases installLink_links hp with h | ⟨rfl, ht, hc⟩
  · exact keysApart_mem hold h
  · have := (List.all_eq_true.1 hc) e he
    simpa [ht] using this

/-! ### Closing bounds -/

/-- A link that validly follows another closes only epochs of the generation before its own. -/
theorem succeeds_closed {c : Crypto} {p : Link} {base : Nat} {n : SignedLink} (h : succeeds c p base n = true)
    {e : Nat} (he : n.closedThrough = some e) : genOf e + 1 = n.gen := by
  simp only [succeeds, he, Option.all_some, Bool.and_eq_true, beq_iff_eq] at h
  obtain ⟨⟨⟨⟨⟨⟨-, hg⟩, -⟩, -⟩, -⟩, hc⟩, -⟩ := h
  omega

/-- A link is installed, or recorded as a conflict, only when its closing bound, if it has one, is an epoch of the
    generation before its own; a genesis has none.  So a bound outside that generation's range never enters the
    state, and no certificate of an older generation is accepted on the strength of one. -/
theorem installLink_closed {c : Crypto} {pin : Bytes} {s : Auth} {n : SignedLink}
    (h : (installLink c pin s n).2 = .genesis ∨ (installLink c pin s n).2 = .extends ∨
      (installLink c pin s n).2 = .conflicts) {e : Nat} (he : n.closedThrough = some e) : genOf e + 1 = n.gen := by
  generalize ha : (installLink c pin s n).2 = a at h
  unfold installLink at ha
  split at ha
  · subst ha; simp at h
  · split at ha
    · split at ha
      · subst ha; simp at h
      · split at ha
        · rename_i hok
          simp only [Bool.and_eq_true] at hok
          have hn := hok.1.1.1
          simp [genesisOk, he] at hn
        · subst ha; simp at h
    · split at ha
      · subst ha; simp at h
      · split at ha
        · rename_i hs
          exact succeeds_closed hs he
        · split at ha
          · rename_i hs
            obtain ⟨p, -, hp⟩ := List.any_eq_true.1 hs
            exact succeeds_closed hp he
          · split at ha <;> (subst ha; simp at h)

/-- Every link held for a tenant closes only epochs of the generation before its own. -/
def ClosedInRange (s : Auth) : Prop :=
  ∀ t, ∀ p ∈ linksOf s t, ∀ e, p.closedThrough = some e → genOf e + 1 = p.gen

theorem ClosedInRange.empty : ClosedInRange Auth.empty := fun t p h => by
  simp [linksOf, retiredLinks, Auth.empty] at h

theorem installLink_closedInRange {c : Crypto} {pin : Bytes} {s : Auth} (n : SignedLink) (hc : ClosedInRange s) :
    ClosedInRange (installLink c pin s n).1 := by
  intro t p hp e he
  by_cases hg : (installLink c pin s n).2 = .genesis
  · rcases installLink_links hp with hp | ⟨rfl, -, -⟩
    · exact hc t p hp e he
    · exact installLink_closed (.inl hg) he
  · by_cases hx : (installLink c pin s n).2 = .extends
    · rcases installLink_links hp with hp | ⟨rfl, -, -⟩
      · exact hc t p hp e he
      · exact installLink_closed (.inr (.inl hx)) he
    · obtain ⟨h1, h2⟩ := installLink_chains hg hx
      rw [linksOf_congr (congrFun h1 t) (congrFun h2 t)] at hp
      exact hc t p hp e he

theorem installCert_closedInRange {c : Crypto} {s : Auth} (b : Bytes) (hc : ClosedInRange s) :
    ClosedInRange (installCert c s b).1 := by
  obtain ⟨h1, h2, -⟩ := installCert_keeps c s b
  intro t p hp
  rw [linksOf_congr (congrFun h1 t) (congrFun h2 t)] at hp
  exact hc t p hp


/-! ### `record`, the step a verified certificate ends in -/

/-- `installed`: no installed certificate has its tenant and epoch, and its shard counts fit. -/
theorem record_installed {s : Auth} {e : KeyCert} : (record s e).2 = .installed ↔
    (s.certs.any fun x => x.tenantId == e.tenantId && x.epoch == e.epoch) = false ∧ fits s e = true := by
  unfold record
  split
  · rename_i h
    simp [h]
  · rename_i h
    split
    · rename_i hf
      exact ⟨fun _ => ⟨Bool.eq_false_iff.2 h, hf⟩, fun _ => rfl⟩
    · rename_i hf
      simp [hf]

/-- `equivocates`: an installed certificate has its tenant and epoch. -/
theorem record_equivocates {s : Auth} {e : KeyCert} : (record s e).2 = .equivocates ↔
    (s.certs.any fun x => x.tenantId == e.tenantId && x.epoch == e.epoch) = true := by
  unfold record
  split
  · rename_i h
    simp [h]
  · rename_i h
    split <;> simp [h]

theorem record_certs (s : Auth) (e : KeyCert) :
    (record s e).1.certs = if (record s e).2 = .installed then e :: s.certs else s.certs := by
  unfold record
  split
  · simp
  · split <;> simp

theorem record_equivocations (s : Auth) (e : KeyCert) :
    (record s e).1.equivocations = if (record s e).2 = .equivocates then
      (s.certs.filter fun x => x.tenantId == e.tenantId && x.epoch == e.epoch).map (·, e) ++ s.equivocations
      else s.equivocations := by
  unfold record
  split
  · simp
  · split <;> simp

theorem record_fence (s : Auth) (e : KeyCert) : (record s e).1.fence = raiseFence s.fence e.tenantId e.epoch := by
  unfold record
  split
  · rfl
  · split <;> rfl

/-- `record` leaves the chains and the link conflicts. -/
theorem record_links (s : Auth) (e : KeyCert) : (record s e).1.chainOf = s.chainOf ∧
    (record s e).1.retired = s.retired ∧ (record s e).1.conflicts = s.conflicts := by
  unfold record
  split
  · exact ⟨rfl, rfl, rfl⟩
  · split <;> exact ⟨rfl, rfl, rfl⟩

/-- `record`'s answer reads the installed certificates only through these two tests. -/
theorem record_congr {a b : Auth} {e : KeyCert}
    (h1 : (a.certs.any fun x => x.tenantId == e.tenantId && x.epoch == e.epoch) =
      (b.certs.any fun x => x.tenantId == e.tenantId && x.epoch == e.epoch))
    (h2 : (b.certs.any fun x => x.tenantId == e.tenantId && x.epoch == e.epoch) = false → fits a e = fits b e) :
    (record a e).2 = (record b e).2 := by
  cases hb : (b.certs.any fun x => x.tenantId == e.tenantId && x.epoch == e.epoch)
  · have h2' := h2 hb
    rw [hb] at h1
    unfold record
    simp only [h1, hb, h2', Bool.false_eq_true, if_false]
    cases hf : fits b e <;> simp
  · rw [hb] at h1
    rw [record_equivocates.2 h1, record_equivocates.2 hb]

/-- The key test over the links a filter keeps is the test over all of them, when no link it drops can fail it. -/
theorem keysApart_filter (H : Bytes → Bytes) (links : List Link) (e : KeyCert) (touch : Link → Bool)
    (ht : ∀ p, touch p = false → ∀ k, k = e.key ∨ k = e.verifierKey →
      (k != p.root && k != p.witness && H k.enc != p.rootNext && H k.enc != p.witnessNext) = true) :
    keysApart H (links.filter touch) e = keysApart H links e := by
  unfold keysApart
  congr 1
  apply Bool.eq_iff_iff.2
  simp only [List.all_eq_true, List.mem_filter, List.mem_cons, List.not_mem_nil, or_false]
  constructor
  · intro h k hk p hp
    cases htp : touch p
    · exact ht p htp k hk
    · exact h k hk p ⟨hp, htp⟩
  · intro h k hk p hp
    exact h k hk p hp.1

/-! ### Certificates of the tenant's current chain -/

/-- Without a chain (a replay that holds no links) every installed certificate counts for a fit. -/
theorem fits_chainless {s : Auth} {e : KeyCert} (h : s.chainOf e.tenantId = none) :
    fits s e = s.certs.all fun x => x.tenantId != e.tenantId ||
      (x.epoch != e.epoch && if x.epoch < e.epoch then x.chain.isPrefixOf e.chain else e.chain.isPrefixOf x.chain) := by
  unfold fits ownedBy
  rw [h]
  simp only [Option.all_none, Bool.not_true, Bool.or_false]

/-- A certificate the chain verifies is of a generation the chain holds, not above the head's, and in time. -/
theorem judge_ok {c : Crypto} {ch : Chain} {r : List Link} {e v : KeyCert} (h : judge c ch r e = .ok v) :
    (ch.linkAt (genOf e.epoch)).isSome = true ∧ genOf e.epoch ≤ ch.head.gen ∧ ch.inTime e = true := by
  revert h
  unfold judge judgeWith
  repeat' split
  all_goals first
    | (intro h; cases h; done)
    | (intro _; refine ⟨?_, ?_, ?_⟩ <;> simp_all <;> omega)

theorem judge_owned {c : Crypto} {ch : Chain} {r : List Link} {e v : KeyCert} (h : judge c ch r e = .ok v) :
    ownedBy (some ch) e = true := by
  obtain ⟨h1, -, h3⟩ := judge_ok h
  simp only [ownedBy, Option.all_some, h1, h3, Bool.and_self]

theorem Chain.push_gen {ch ch' : Chain} {l : Link} (h : ch.push l = some ch') :
    l.gen = ch.head.gen + 1 ∧ ch'.head = l := by
  unfold Chain.push at h
  split at h
  · rename_i hc; cases h; exact ⟨hc.2.1, rfl⟩
  · cases h

theorem Chain.linkAt_push {ch ch' : Chain} {l : Link} (h : ch.push l = some ch') (g : Nat) :
    ch'.linkAt g = if l.gen = g then some l else ch.linkAt g := by
  obtain ⟨h1, h2⟩ := Chain.push_spec h
  unfold Chain.linkAt Chain.links
  rw [h1, h2]
  by_cases hg : l.gen = g <;> simp [List.find?_cons, hg]

/-- A genesis chain owns only certificates of its own generation. -/
theorem owned_start {l : Link} {g : Chain} (h : Chain.start l = some g) {x : KeyCert}
    (ho : ownedBy (some g) x = true) : genOf x.epoch = l.gen := by
  obtain ⟨h1, h2⟩ := Chain.start_spec h
  unfold ownedBy Chain.linkAt Chain.links at ho
  rw [Option.all_some, h1, h2] at ho
  cases hb : (l.gen == genOf x.epoch)
  · simp [hb] at ho
  · exact (beq_iff_eq.1 hb).symm

/-- An extending link disowns nothing below its own generation that the chain did not already disown. -/
theorem owned_push {ch ch' : Chain} {l : Link} (h : ch.push l = some ch') {x : KeyCert}
    (hx : genOf x.epoch ≤ ch.head.gen) (ho : ownedBy (some ch') x = true) : ownedBy (some ch) x = true := by
  obtain ⟨hg, hh⟩ := Chain.push_gen h
  have h1 : ¬ l.gen = genOf x.epoch := by omega
  unfold ownedBy Chain.inTime at ho ⊢
  rw [Option.all_some] at ho ⊢
  rw [Chain.linkAt_push h (genOf x.epoch), Chain.linkAt_push h (genOf x.epoch + 1), if_neg h1, hh] at ho
  by_cases he : l.gen = genOf x.epoch + 1
  · simp only [Bool.and_eq_true, Bool.or_eq_true, decide_eq_true_eq] at ho ⊢
    exact ⟨ho.1, .inl (by omega)⟩
  · rw [if_neg he] at ho
    simp only [Bool.and_eq_true, Bool.or_eq_true, decide_eq_true_eq] at ho ⊢
    exact ⟨ho.1, .inr (ho.2.resolve_left (by omega))⟩

/-- A rotation link disowns the certificates of the generation it closes above its closing bound (all of them when
    it records none). -/
theorem rotation_disowns {c : Crypto} {pin : Bytes} {s : Auth} {n : SignedLink}
    (h : (installLink c pin s n).2 = .extends) {x : KeyCert} (hg : genOf x.epoch + 1 = n.gen)
    (hb : n.closedThrough.all (· < x.epoch) = true) :
    ownedBy ((installLink c pin s n).1.chainOf n.tenantId) x = false := by
  obtain ⟨ch, ch', -, hp, h1, -, -⟩ := installLink_extends h
  obtain ⟨-, hh⟩ := Chain.push_gen hp
  have hl : (n.link c.hash).gen = genOf x.epoch + 1 := hg.symm
  rw [h1]
  unfold ownedBy Chain.inTime
  rw [Option.all_some, Chain.linkAt_push hp (genOf x.epoch + 1), if_pos hl, hh, hl]
  have hc : (n.link c.hash).closedThrough = n.closedThrough := rfl
  cases hn : n.closedThrough with
  | none => simp [hc, hn]
  | some b =>
    rw [hn] at hb
    simp only [Option.all_some, decide_eq_true_eq] at hb
    simp [hc, hn]
    omega

/-- The steps keep: every installed certificate's tenant has a chain at or above the certificate's generation; one
    installed certificate per tenant and epoch; and the shard counts of the certificates the tenant's chain owns
    extend one another in epoch order. -/
structure CountsAgree (s : Auth) : Prop where
  gen : ∀ x ∈ s.certs, ∃ ch, s.chainOf x.tenantId = some ch ∧ genOf x.epoch ≤ ch.head.gen
  uniq : ∀ x ∈ s.certs, ∀ y ∈ s.certs, x.tenantId = y.tenantId → x.epoch = y.epoch → x = y
  ordered : ∀ x ∈ s.certs, ∀ y ∈ s.certs, x.tenantId = y.tenantId → ownedBy (s.chainOf x.tenantId) x = true →
    ownedBy (s.chainOf x.tenantId) y = true → x.epoch < y.epoch → x.chain.isPrefixOf y.chain = true

theorem CountsAgree.empty : CountsAgree Auth.empty :=
  ⟨fun _ h => (by simp [Auth.empty] at h), fun _ h => (by simp [Auth.empty] at h),
    fun _ h => (by simp [Auth.empty] at h)⟩

theorem CountsAgree.congr {s s' : Auth} (h1 : s'.certs = s.certs) (h2 : s'.chainOf = s.chainOf) (hs : CountsAgree s) :
    CountsAgree s' := by
  obtain ⟨g, u, o⟩ := hs
  exact ⟨by rw [h1, h2]; exact g, by rw [h1]; exact u, by rw [h1, h2]; exact o⟩

theorem genesis_above {c : Crypto} {pin : Bytes} {s : Auth} {n : SignedLink}
    (h : (installLink c pin s n).2 = .genesis) : ∀ p ∈ linksOf s n.tenantId, p.gen < n.gen := by
  revert h
  unfold installLink
  repeat' split
  all_goals first
    | (intro h; cases h; done)
    | (rename_i hc
       intro _
       simp only [Bool.and_eq_true, List.all_eq_true, decide_eq_true_eq] at hc
       exact hc.1.1.2)

/-- A re-genesis starts empty: the new chain owns no certificate held before it. -/
theorem genesis_disowns {c : Crypto} {pin : Bytes} {s : Auth} {n : SignedLink} (hs : CountsAgree s)
    (h : (installLink c pin s n).2 = .genesis) :
    ∀ x ∈ (installLink c pin s n).1.certs, x.tenantId = n.tenantId →
      ownedBy ((installLink c pin s n).1.chainOf n.tenantId) x = false := by
  obtain ⟨g, hst, h1, -, -⟩ := installLink_genesis h
  intro x hx hxt
  rw [(installLink_keeps c pin s n).1] at hx
  obtain ⟨ch, hch, hle⟩ := hs.gen x hx
  rw [hxt] at hch
  have hab := genesis_above h ch.head (by simp [linksOf, hch, Chain.links])
  rw [h1]
  cases ho : ownedBy (some g) x
  · rfl
  · have := owned_start hst ho
    have hn : (n.link c.hash).gen = n.gen := rfl
    omega

/-- After a genesis every certificate of the tenant fits. -/
theorem genesis_fits {c : Crypto} {pin : Bytes} {s : Auth} {n : SignedLink} (hs : CountsAgree s)
    (h : (installLink c pin s n).2 = .genesis) {e : KeyCert} (he : e.tenantId = n.tenantId) :
    fits (installLink c pin s n).1 e = true := by
  unfold fits
  rw [List.all_eq_true]
  intro x hx
  by_cases hxt : x.tenantId = e.tenantId
  · rw [he, genesis_disowns hs h x hx (hxt.trans he)]
    simp
  · simp [hxt]

theorem installLink_countsAgree (c : Crypto) (pin : Bytes) {s : Auth} (n : SignedLink) (hs : CountsAgree s) :
    CountsAgree (installLink c pin s n).1 := by
  have hc := (installLink_keeps c pin s n).1
  by_cases hg : (installLink c pin s n).2 = .genesis
  · obtain ⟨g, hst, h1, -, h3⟩ := installLink_genesis hg
    have hgh : g.head.gen = n.gen := by rw [(Chain.start_spec hst).1]; rfl
    refine ⟨fun x hx => ?_, fun x hx y hy => ?_, fun x hx y hy hxy hox hoy hlt => ?_⟩
    · have hx' := hx
      rw [hc] at hx'
      obtain ⟨ch, hch, hle⟩ := hs.gen x hx'
      by_cases hxt : x.tenantId = n.tenantId
      · rw [hxt] at hch
        have hab := genesis_above hg ch.head (by simp [linksOf, hch, Chain.links])
        exact ⟨g, by rw [hxt]; exact h1, by omega⟩
      · exact ⟨ch, by rw [(h3 _ hxt).1]; exact hch, hle⟩
    · rw [hc] at hx hy; exact hs.uniq x hx y hy
    · by_cases hxt : x.tenantId = n.tenantId
      · rw [hxt, genesis_disowns hs hg x hx hxt] at hox; cases hox
      · rw [(h3 _ hxt).1] at hox hoy
        rw [hc] at hx hy
        exact hs.ordered x hx y hy hxy hox hoy hlt
  · by_cases he : (installLink c pin s n).2 = .extends
    · obtain ⟨ch, ch', hch, hp, h1, -, h3⟩ := installLink_extends he
      obtain ⟨hgen, hhd⟩ := Chain.push_gen hp
      have hlex : ∀ z ∈ s.certs, z.tenantId = n.tenantId → genOf z.epoch ≤ ch.head.gen := by
        intro z hz hzt
        obtain ⟨ch0, hch0, hle⟩ := hs.gen z hz
        rw [hzt, hch] at hch0
        rw [Option.some.inj hch0]; exact hle
      refine ⟨fun x hx => ?_, fun x hx y hy => ?_, fun x hx y hy hxy hox hoy hlt => ?_⟩
      · rw [hc] at hx
        by_cases hxt : x.tenantId = n.tenantId
        · have := hlex x hx hxt
          exact ⟨ch', by rw [hxt]; exact h1, by rw [hhd]; omega⟩
        · obtain ⟨ch0, hch0, hle⟩ := hs.gen x hx
          exact ⟨ch0, by rw [h3 _ hxt]; exact hch0, hle⟩
      · rw [hc] at hx hy; exact hs.uniq x hx y hy
      · rw [hc] at hx hy
        by_cases hxt : x.tenantId = n.tenantId
        · rw [hxt, h1] at hox hoy
          refine hs.ordered x hx y hy hxy ?_ ?_ hlt
          · rw [hxt, hch]; exact owned_push hp (hlex x hx hxt) hox
          · rw [hxt, hch]; exact owned_push hp (hlex y hy (hxy.symm.trans hxt)) hoy
        · rw [h3 _ hxt] at hox hoy
          exact hs.ordered x hx y hy hxy hox hoy hlt
    · exact CountsAgree.congr hc (installLink_chains hg he).1 hs

theorem installCert_countsAgree (c : Crypto) {s : Auth} (b : Bytes) (hs : CountsAgree s) :
    CountsAgree (installCert c s b).1 := by
  have hk := (installCert_keeps c s b).1
  rcases installCert_adds c s b with h | ⟨e, hd, hc, hno, hf, hi⟩
  · exact CountsAgree.congr h hk hs
  · obtain ⟨e', ch, hd', -, hch, hj, -⟩ := installCert_recorded (.inl hi)
    have hee : e' = e := Option.some.inj (hd'.symm.trans hd)
    rw [hee] at hch hj
    obtain ⟨-, hgen, -⟩ := judge_ok hj
    have hmem : ∀ z ∈ (installCert c s b).1.certs, z = e ∨ z ∈ s.certs := fun z hz => by
      rw [hc] at hz; exact List.mem_cons.1 hz
    have hsame : ∀ y ∈ s.certs, e.tenantId = y.tenantId → e.epoch = y.epoch → False := fun y hy h1 h2 => by
      have := List.any_eq_false.1 hno y hy
      simp [h1, h2] at this
    refine ⟨fun x hx => ?_, fun x hx y hy hxy hxe => ?_, fun x hx y hy hxy hox hoy hlt => ?_⟩
    · rw [hk]
      rcases hmem x hx with h' | h'
      · rw [h']; exact ⟨ch, hch, hgen⟩
      · exact hs.gen x h'
    · rcases hmem x hx with h' | h' <;> rcases hmem y hy with h'' | h''
      · rw [h', h'']
      · rw [h'] at hxy hxe; exact (hsame y h'' hxy hxe).elim
      · rw [h''] at hxy hxe; exact (hsame x h' hxy.symm hxe.symm).elim
      · exact hs.uniq x h' y h'' hxy hxe
    · rw [hk] at hox hoy
      rcases hmem x hx with h' | h' <;> rcases hmem y hy with h'' | h''
      · rw [h', h''] at hlt; exact absurd hlt (Nat.lt_irrefl _)
      · rw [h'] at hxy hoy hlt ⊢
        have h1 := List.all_eq_true.1 hf y h''
        simp only [← hxy, bne_self_eq_false, hoy, Bool.not_true, Bool.false_or, Bool.and_eq_true,
          if_neg (Nat.not_lt.2 (Nat.le_of_lt hlt))] at h1
        exact h1.2
      · rw [h''] at hxy hlt ⊢
        rw [hxy] at hox
        have h1 := List.all_eq_true.1 hf x h'
        simp only [hxy, bne_self_eq_false, hox, Bool.not_true, Bool.false_or, Bool.and_eq_true, if_pos hlt] at h1
        exact h1.2
      · exact hs.ordered x h' y h'' hxy hox hoy hlt

/-- With the steps' invariant, a fit read on a state without links that holds, of the tenant, only certificates its
    chain owns, among them the nearest owned ones below and above the epoch, is the fit on the whole state. -/
theorem fits_neighbours {s a : Auth} {e : KeyCert} (hs : CountsAgree s) (ha : a.chainOf e.tenantId = none)
    (hW : ∀ x ∈ a.certs, x.tenantId = e.tenantId → x ∈ s.certs ∧ ownedBy (s.chainOf e.tenantId) x = true)
    (hlo : ∀ x ∈ s.certs, x.tenantId = e.tenantId → ownedBy (s.chainOf e.tenantId) x = true → x.epoch < e.epoch →
      ∃ y ∈ a.certs, y.tenantId = e.tenantId ∧ x.epoch ≤ y.epoch ∧ y.epoch < e.epoch)
    (hhi : ∀ x ∈ s.certs, x.tenantId = e.tenantId → ownedBy (s.chainOf e.tenantId) x = true → e.epoch < x.epoch →
      ∃ y ∈ a.certs, y.tenantId = e.tenantId ∧ e.epoch < y.epoch ∧ y.epoch ≤ x.epoch)
    (hno : (s.certs.any fun x => x.tenantId == e.tenantId && x.epoch == e.epoch) = false) :
    fits a e = fits s e := by
  have pt : ∀ {p q r : List Nat}, p.isPrefixOf q = true → q.isPrefixOf r = true → p.isPrefixOf r = true :=
    fun h1 h2 => List.isPrefixOf_iff_prefix.2 ((List.isPrefixOf_iff_prefix.1 h1).trans (List.isPrefixOf_iff_prefix.1 h2))
  have pr : ∀ p : List Nat, p.isPrefixOf p = true := fun p => List.isPrefixOf_iff_prefix.2 (List.prefix_refl _)
  rw [fits_chainless ha]
  apply Bool.eq_iff_iff.2
  unfold fits
  simp only [List.all_eq_true]
  constructor
  · intro hA x hx
    by_cases hxt : x.tenantId = e.tenantId
    · cases hxo : ownedBy (s.chainOf e.tenantId) x
      · simp
      · have hne : x.epoch ≠ e.epoch := fun h' => by
          have := List.any_eq_false.1 hno x hx
          simp [hxt, h'] at this
        rcases Nat.lt_or_gt_of_ne hne with hlt | hgt
        · obtain ⟨y, hy, hyt, hle, hye⟩ := hlo x hx hxt hxo hlt
          have h1 := hA y hy
          simp only [hyt, bne_self_eq_false, Bool.false_or, Bool.and_eq_true, if_pos hye] at h1
          obtain ⟨hyS, hyo⟩ := hW y hy hyt
          have hxy : x.chain.isPrefixOf y.chain = true := by
            rcases Nat.lt_or_eq_of_le hle with hl | he'
            · exact hs.ordered x hx y hyS (hxt.trans hyt.symm) (by rw [hxt]; exact hxo) (by rw [hxt]; exact hyo) hl
            · rw [hs.uniq x hx y hyS (hxt.trans hyt.symm) he']; exact pr _
          simp [hxt, hne, hlt, pt hxy h1.2]
        · obtain ⟨y, hy, hyt, hye, hle⟩ := hhi x hx hxt hxo hgt
          have h1 := hA y hy
          simp only [hyt, bne_self_eq_false, Bool.false_or, Bool.and_eq_true,
            if_neg (Nat.not_lt.2 (Nat.le_of_lt hye))] at h1
          obtain ⟨hyS, hyo⟩ := hW y hy hyt
          have hyx : y.chain.isPrefixOf x.chain = true := by
            rcases Nat.lt_or_eq_of_le hle with hl | he'
            · exact hs.ordered y hyS x hx (hyt.trans hxt.symm) (by rw [hyt]; exact hyo) (by rw [hyt]; exact hxo) hl
            · rw [hs.uniq y hyS x hx (hyt.trans hxt.symm) he']; exact pr _
          simp [hxt, hne, Nat.not_lt.2 (Nat.le_of_lt hgt), pt h1.2 hyx]
    · simp [hxt]
  · intro hS x hx
    by_cases hxt : x.tenantId = e.tenantId
    · obtain ⟨hxS, hxo⟩ := hW x hx hxt
      have h1 := hS x hxS
      simp only [hxt, bne_self_eq_false, hxo, Bool.not_true, Bool.false_or] at h1
      simp [hxt, h1]
    · simp [hxt]

end BlindLedger.Gate.Cosign
