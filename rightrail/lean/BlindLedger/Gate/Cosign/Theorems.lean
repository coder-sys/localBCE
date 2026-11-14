import BlindLedger.Gate.Cosign.Verify
import BlindLedger.Gate.ProducerTheorems

/-! What KEY-CERT/v2 verification guarantees, for every `Crypto`: the accepting condition, the exact condition of
    each refusal code, that a certificate valid for the link of its own generation is accepted however many newer
    links the chain holds, that no chain without a link of a certificate's generation accepts it, and that a signature
    made for a certificate cannot serve for a checkpoint. -/
namespace BlindLedger.Gate.Cosign

open BlindLedger.Gate

/-- Acceptance: the bytes decode to the certificate returned, which is its tenant's, of a generation up to the head's,
    names the chain's link of its own generation, keeps one key per purpose against every link of the chain and every
    retired link, was made
    before its generation closed, and carries both signatures over its body under that link's keys. -/
theorem verify_ok {c : Crypto} {ch : Chain} {r : List Link} {b : Bytes} {e : KeyCert} :
    verify c ch r b = .ok e ↔ decode b = some e ∧ e.tenantId = ch.head.tenantId ∧ ∃ l, ch.linkAt (genOf e.epoch) = some l ∧
      genOf e.epoch ≤ ch.head.gen ∧ e.link = l.digest ∧ keysApart c.hash (ch.links ++ r) e = true ∧ ch.inTime e = true ∧
      c.verify l.root e.body e.rootSig = true ∧ c.verify l.witness e.body e.coSig = true := by
  unfold verify
  cases hd : decode b with
  | none => simp
  | some x =>
    dsimp only
    simp only [Option.some.injEq]
    by_cases hxe : x = e
    · subst hxe
      repeat' split
      all_goals first | (simp_all; done) | (simp_all; intros; omega)
    · simp only [hxe, false_and, iff_false]
      repeat' split
      all_goals first | (intro h; cases h; exact hxe rfl) | (intro h; cases h)

theorem verify_malformed {c : Crypto} {ch : Chain} {r : List Link} {b : Bytes} :
    verify c ch r b = .error .MALFORMED ↔ decode b = none := by
  unfold verify
  cases hd : decode b with
  | none => simp
  | some x => dsimp only; repeat' split
              all_goals simp

theorem verify_wrong_tenant {c : Crypto} {ch : Chain} {r : List Link} {b : Bytes} :
    verify c ch r b = .error .WRONG_TENANT ↔ ∃ e, decode b = some e ∧ e.tenantId ≠ ch.head.tenantId := by
  unfold verify
  cases hd : decode b with
  | none => simp
  | some x => dsimp only; repeat' split
              all_goals simp_all

/-- A certificate of a generation above the head's: that link has not arrived. -/
theorem verify_ahead {c : Crypto} {ch : Chain} {r : List Link} {b : Bytes} :
    verify c ch r b = .error .GENERATION_AHEAD ↔
      ∃ e, decode b = some e ∧ e.tenantId = ch.head.tenantId ∧ ch.head.gen < genOf e.epoch := by
  unfold verify
  cases hd : decode b with
  | none => simp
  | some x =>
    dsimp only
    simp only [Option.some.injEq, exists_eq_left']
    repeat' split
    all_goals first | (simp_all; done) | (simp_all; intros; omega)

/-- A certificate of a generation the chain holds no link for is refused `STALE_KEYSET`; no signature is consulted. -/
theorem verify_stale {c : Crypto} {ch : Chain} {r : List Link} {b : Bytes} :
    verify c ch r b = .error .STALE_KEYSET ↔
      ∃ e, decode b = some e ∧ e.tenantId = ch.head.tenantId ∧ genOf e.epoch ≤ ch.head.gen ∧
        ch.linkAt (genOf e.epoch) = none := by
  unfold verify
  cases hd : decode b with
  | none => simp
  | some x =>
    dsimp only
    simp only [Option.some.injEq, exists_eq_left']
    repeat' split
    all_goals first | (simp_all; done) | (simp_all; intros; omega)

theorem verify_wrong_link {c : Crypto} {ch : Chain} {r : List Link} {b : Bytes} :
    verify c ch r b = .error .WRONG_LINK ↔
      ∃ e l, decode b = some e ∧ e.tenantId = ch.head.tenantId ∧ genOf e.epoch ≤ ch.head.gen ∧
        ch.linkAt (genOf e.epoch) = some l ∧ e.link ≠ l.digest := by
  unfold verify
  cases hd : decode b with
  | none => simp
  | some x =>
    dsimp only
    simp only [Option.some.injEq]
    repeat' split
    all_goals first | (simp_all; done) | (simp_all; intros; omega)

theorem verify_key_reuse {c : Crypto} {ch : Chain} {r : List Link} {b : Bytes} :
    verify c ch r b = .error .KEY_REUSE ↔
      ∃ e l, decode b = some e ∧ e.tenantId = ch.head.tenantId ∧ genOf e.epoch ≤ ch.head.gen ∧
        ch.linkAt (genOf e.epoch) = some l ∧ e.link = l.digest ∧ keysApart c.hash (ch.links ++ r) e = false := by
  unfold verify
  cases hd : decode b with
  | none => simp
  | some x =>
    dsimp only
    simp only [Option.some.injEq]
    repeat' split
    all_goals first | (simp_all; done) | (simp_all; intros; omega)

/-- A certificate of an older generation whose epoch is past the closing its generation's successor recorded; no
    signature is consulted. -/
theorem verify_after_rotation {c : Crypto} {ch : Chain} {r : List Link} {b : Bytes} :
    verify c ch r b = .error .AFTER_ROTATION ↔
      ∃ e l, decode b = some e ∧ e.tenantId = ch.head.tenantId ∧ genOf e.epoch ≤ ch.head.gen ∧
        ch.linkAt (genOf e.epoch) = some l ∧ e.link = l.digest ∧ keysApart c.hash (ch.links ++ r) e = true ∧
        ch.inTime e = false := by
  unfold verify
  cases hd : decode b with
  | none => simp
  | some x =>
    dsimp only
    simp only [Option.some.injEq]
    repeat' split
    all_goals first | (simp_all; done) | (simp_all; intros; omega)

theorem verify_bad_root {c : Crypto} {ch : Chain} {r : List Link} {b : Bytes} :
    verify c ch r b = .error .BAD_ROOT_SIGNATURE ↔
      ∃ e l, decode b = some e ∧ e.tenantId = ch.head.tenantId ∧ genOf e.epoch ≤ ch.head.gen ∧
        ch.linkAt (genOf e.epoch) = some l ∧ e.link = l.digest ∧ keysApart c.hash (ch.links ++ r) e = true ∧
        ch.inTime e = true ∧ c.verify l.root e.body e.rootSig = false := by
  unfold verify
  cases hd : decode b with
  | none => simp
  | some x =>
    dsimp only
    simp only [Option.some.injEq]
    repeat' split
    all_goals first | (simp_all; done) | (simp_all; intros; omega)

theorem verify_bad_witness {c : Crypto} {ch : Chain} {r : List Link} {b : Bytes} :
    verify c ch r b = .error .BAD_WITNESS_SIGNATURE ↔
      ∃ e l, decode b = some e ∧ e.tenantId = ch.head.tenantId ∧ genOf e.epoch ≤ ch.head.gen ∧
        ch.linkAt (genOf e.epoch) = some l ∧ e.link = l.digest ∧ keysApart c.hash (ch.links ++ r) e = true ∧
        ch.inTime e = true ∧ c.verify l.root e.body e.rootSig = true ∧ c.verify l.witness e.body e.coSig = false := by
  unfold verify
  cases hd : decode b with
  | none => simp
  | some x =>
    dsimp only
    simp only [Option.some.injEq]
    repeat' split
    all_goals first | (simp_all; done) | (simp_all; intros; omega)

/-- One key per purpose, spelled out. -/
theorem keysApart_iff {H : Bytes → Bytes} {links : List Link} {e : KeyCert} :
    keysApart H links e = true ↔ e.key ≠ e.verifierKey ∧
      (∀ p ∈ links, e.key ≠ p.root ∧ e.key ≠ p.witness ∧ H e.key.enc ≠ p.rootNext ∧
        H e.key.enc ≠ p.witnessNext) ∧
      (∀ p ∈ links, e.verifierKey ≠ p.root ∧ e.verifierKey ≠ p.witness ∧ H e.verifierKey.enc ≠ p.rootNext ∧
        H e.verifierKey.enc ≠ p.witnessNext) := by
  simp [keysApart, and_assoc]

/-- No accepted certificate's key is, was or is committed to become a link key: for every link of the chain and every
    retired link, neither certified key is that link's root or witness key or one of its committed next keys. -/
theorem verify_ok_keys {c : Crypto} {ch : Chain} {r : List Link} {b : Bytes} {e : KeyCert}
    (h : verify c ch r b = .ok e) {p : Link} (hp : p ∈ ch.links ++ r) :
    (e.key ≠ p.root ∧ e.key ≠ p.witness ∧ c.hash e.key.enc ≠ p.rootNext ∧
        c.hash e.key.enc ≠ p.witnessNext) ∧
      (e.verifierKey ≠ p.root ∧ e.verifierKey ≠ p.witness ∧ c.hash e.verifierKey.enc ≠ p.rootNext ∧
        c.hash e.verifierKey.enc ≠ p.witnessNext) := by
  obtain ⟨-, -, -, -, -, -, hk, -⟩ := verify_ok.1 h
  have ha := keysApart_iff.1 hk
  exact ⟨ha.2.1 p hp, ha.2.2 p hp⟩

/-- The link `linkAt` finds is a link of the chain and of that generation. -/
theorem linkAt_spec {ch : Chain} {g : Nat} {l : Link} (h : ch.linkAt g = some l) : l ∈ ch.links ∧ l.gen = g := by
  have := List.find?_some h
  exact ⟨List.mem_of_find?_eq_some h, by simpa using this⟩

/-- Every link after the first of a consecutive list is of an earlier generation. -/
private theorem consecutive_lt : ∀ {a : Link} {t : List Link}, Consecutive (a :: t) → ∀ x ∈ t, x.gen < a.gen
  | _, [], _, _, hx => by cases hx
  | a, b :: t, h, x, hx => by
    have hc : a.gen = b.gen + 1 ∧ Consecutive (b :: t) := by simpa only [Consecutive] using h
    obtain ⟨h1, h2⟩ := hc
    rcases List.mem_cons.1 hx with rfl | hx
    · omega
    · have := consecutive_lt h2 x hx; omega

/-- A link of the chain is the one found for its own generation: generations fall strictly, so each is held once. -/
theorem linkAt_of_mem {ch : Chain} {l : Link} (hl : l ∈ ch.links) : ch.linkAt l.gen = some l := by
  have key : ∀ (a : Link) (t : List Link), Consecutive (a :: t) → l ∈ a :: t →
      (a :: t).find? (·.gen == l.gen) = some l := by
    intro a t
    induction t generalizing a with
    | nil => intro _ h; rcases List.mem_singleton.1 h with rfl; simp
    | cons b t ih =>
      intro hc hm
      rcases List.mem_cons.1 hm with rfl | hm
      · simp
      · have hne : (a.gen == l.gen) = false := by have := consecutive_lt hc l hm; simp; omega
        have hc' : Consecutive (b :: t) := by simp only [Consecutive] at hc; exact hc.2
        simp [hne, ih b hc' hm]
  exact key _ _ ch.consecutive hl

/-- No gaps: the chain holds a link of every generation from any link it holds up to the head, in particular from its
    first link to the head. -/
theorem linkAt_between {ch : Chain} {p : Link} (hp : p ∈ ch.links) {g : Nat} (hlo : p.gen ≤ g)
    (hhi : g ≤ ch.head.gen) : ∃ l, ch.linkAt g = some l := by
  have key : ∀ (a : Link) (t : List Link), Consecutive (a :: t) → p ∈ a :: t → g ≤ a.gen →
      ∃ x ∈ a :: t, x.gen = g := by
    intro a t
    induction t generalizing a with
    | nil => intro _ h hg; rcases List.mem_singleton.1 h with rfl; exact ⟨p, by simp, by omega⟩
    | cons b t ih =>
      intro hc hm hg
      have hc' : a.gen = b.gen + 1 ∧ Consecutive (b :: t) := by simpa only [Consecutive] using hc
      obtain ⟨hab, hbt⟩ := hc'
      by_cases ha : g = a.gen
      · exact ⟨a, by simp, ha.symm⟩
      · rcases List.mem_cons.1 hm with rfl | hm
        · omega
        · obtain ⟨x, hx, hxg⟩ := ih b hbt hm (by omega)
          exact ⟨x, List.mem_cons_of_mem _ hx, hxg⟩
  obtain ⟨x, hx, hxg⟩ := key _ _ ch.consecutive hp hhi
  exact Option.isSome_iff_exists.1 (List.find?_isSome.2 ⟨x, hx, by simp [hxg]⟩)

/-- An accepted certificate lies in the epoch range of the link that signed it, and names that link. -/
theorem verify_ok_epoch {c : Crypto} {ch : Chain} {r : List Link} {b : Bytes} {e : KeyCert}
    (h : verify c ch r b = .ok e) :
    ∃ l ∈ ch.links, l.gen * genSpan ≤ e.epoch ∧ e.epoch < (l.gen + 1) * genSpan ∧ e.link = l.digest := by
  obtain ⟨-, -, l, hl, -, hlk, -⟩ := verify_ok.1 h
  obtain ⟨hm, hg⟩ := linkAt_spec hl
  refine ⟨l, hm, ?_, ?_, hlk⟩ <;> simp only [genOf, genSpan] at hg ⊢ <;> omega

/-- A certificate that is valid for the link of its own generation is accepted however many newer links the chain
    holds, as long as its keys are apart from every link of the chain. -/
theorem verify_own_generation {c : Crypto} {ch : Chain} {r : List Link} {b : Bytes} {e : KeyCert} {l : Link} (hl : l ∈ ch.links)
    (hd : decode b = some e) (ht : e.tenantId = ch.head.tenantId) (hg : genOf e.epoch = l.gen)
    (hk : e.link = l.digest) (hka : keysApart c.hash (ch.links ++ r) e = true) (hi : ch.inTime e = true)
    (hr : c.verify l.root e.body e.rootSig = true) (hw : c.verify l.witness e.body e.coSig = true) :
    verify c ch r b = .ok e := by
  have hat : ch.linkAt (genOf e.epoch) = some l := by rw [hg]; exact linkAt_of_mem hl
  refine verify_ok.2 ⟨hd, ht, l, hat, ?_, hk, hka, hi, hr, hw⟩
  rw [hg]
  rcases List.mem_cons.1 hl with rfl | hl
  · exact Nat.le_refl _
  · exact Nat.le_of_lt (consecutive_lt ch.consecutive l hl)

/-- The rotation closes the old generation: an accepted certificate of a generation below the head's has no epoch after
    the closing, the last epoch the next generation's link records as certified under it. -/
theorem verify_ok_closed {c : Crypto} {ch : Chain} {r : List Link} {b : Bytes} {e : KeyCert}
    (h : verify c ch r b = .ok e) (hg : genOf e.epoch < ch.head.gen) :
    ∃ n t, ch.linkAt (genOf e.epoch + 1) = some n ∧ n.closedThrough = some t ∧ e.epoch ≤ t := by
  obtain ⟨-, -, -, -, -, -, -, hi, -⟩ := verify_ok.1 h
  simp only [Chain.inTime, Bool.or_eq_true, decide_eq_true_eq] at hi
  rcases hi with hi | hi
  · omega
  · cases hn : ch.linkAt (genOf e.epoch + 1) with
    | none => simp [hn] at hi
    | some n =>
      cases ht : n.closedThrough with
      | none => simp [hn, ht] at hi
      | some t => exact ⟨n, t, rfl, ht, by simpa [hn, ht] using hi⟩

/-- A certificate of the head's generation is always in time: only a rotation closes a generation. -/
theorem inTime_head {ch : Chain} {e : KeyCert} (h : genOf e.epoch = ch.head.gen) : ch.inTime e = true := by
  simp [Chain.inTime, h]

/-- A refusal for a generation the chain holds no link for does not depend on the signatures, the hash or the retired
    links. -/
theorem stale_any_crypto {c c' : Crypto} {ch : Chain} {r r' : List Link} {b : Bytes}
    (h : verify c ch r b = .error .STALE_KEYSET) :
    verify c' ch r' b = .error .STALE_KEYSET :=
  verify_stale.2 (verify_stale.1 h)

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

end BlindLedger.Gate.Cosign
