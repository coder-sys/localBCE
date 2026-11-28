import BlindLedger.Gate.SnapshotV2

namespace BlindLedger.Gate.Scoped
open SnapshotV2 (Scope Kind Signed attachChain)
open Rules (Snapshot Death Exclusion Span Line Key Outcome Reason validDate dayNum)

/-! K3: scope typing (F1) and validity windows (F2(b)), see the scoped-facts design.  Beside v1, not in place of
    it: `Rules.usable`, `Rules.fires` and every v1 theorem are unchanged.  A K3 batch holds each reference kind as a
    `Signed` fact (private constructor: only `SnapshotV2.attachChain` builds one, on the batch's day, under its head
    keyset) and hands the v1 rule table the snapshot `present` gives: the fact's own when it `counts` for the slot's
    kind, else the same rows dated 0, so v1 `usable` is false, `STALE_<kind>` fires and, where those rows show R1, R3 or
    R5's fact, `<RULE>_UNVERIFIED` too: review, absorbed, never refused, no new reason code (wire enum unchanged).  K3
    only removes usability (`usable_tightens`).  Read-set pins come from the attached bytes (K2 manifest), never from
    `Ctx.rules`. -/

/-- Scopes that satisfy kind k: DMF and provider death IDV, exclusion ENR, enrollment ELIG.  SVC is reserved for the
    service-rendered rules; SELF is in no set (C8: a weaker class, reviewed, never refused). -/
def need : Kind → List Scope
  | .DMF => [.IDV] | .PROVIDER_DEATH => [.IDV] | .EXCLUSION => [.ENR] | .ENROLLMENT => [.ELIG]

/-- Ceiling in days for DMF: it may only be lowered, never above v1's 90. -/
def ceilDmf : Nat := 90
/-- Ceiling in days for provider deaths; never above v1's 90. -/
def ceilProviderDeath : Nat := 90
/-- Ceiling in days for exclusions; never above v1's 31. -/
def ceilExclusion : Nat := 31
/-- Placeholder ceiling (days) for enrollment (v1's 7, itself a placeholder for the state's own). -/
def ceilEnrollment : Nat := 7

/-- Ceiling of kind k in days. -/
def CEIL : Kind → Nat
  | .DMF => ceilDmf | .PROVIDER_DEATH => ceilProviderDeath | .EXCLUSION => ceilExclusion | .ENROLLMENT => ceilEnrollment

/-- What K3 reads of an attached fact: rows, kind, scope, signed validUntil, and the day and head-keyset digest it was
    attached under (`SnapshotV2.attachChain_binds`).  A view for the pure rule functions; a `Ctx` holds `Signed`. -/
structure Fact (α : Type) where
  snap : Snapshot α
  kind : Kind
  scope : Scope
  validUntil : Nat
  day : Nat
  keyset : Bytes

/-- The fact view of an attached snapshot. -/
def Fact.ofSigned {α : Type} (r : Signed α) : Fact α := ⟨r.toSnapshot, r.kind, r.scope, r.validUntil, r.day, r.keyset⟩

/-- Last usable DAY NUMBER (`Rules.dayNum`, not a CCYYMMDD date; review F4) of a kind-k fact: the earlier of its
    ceiling past asOf and its signed validUntil.  A `min`, so the window never runs past either bound; day numbers, so
    it crosses month ends.  K4's validThrough carries this unit. -/
def expDay (k : Kind) (asOf validUntil : Nat) : Nat := min (dayNum asOf + CEIL k) (dayNum validUntil)

/-- F1 + F2(b): the fact counts for kind k on `today` under head-keyset digest `ksd`.  It is of kind k, was attached
    today under that keyset, its scope is one kind k needs, asOf and validUntil are calendar dates (review F5) and
    today is within `expDay`.  Through an outage under one keyset the last fact re-attaches each day and counts until
    `expDay` (at most `CEIL k` days past asOf); an epoch change needs re-signing (sigMsg binds the keyset). -/
def counts {α : Type} (today : Nat) (ksd : Bytes) (k : Kind) (f : Fact α) : Bool :=
  f.kind == k && f.day == today && f.keyset == ksd && (need k).contains f.scope && validDate f.snap.asOf &&
    validDate f.validUntil && dayNum today ≤ expDay k f.snap.asOf f.validUntil

/-- The snapshot v1 reads for kind k: a fact that counts as is; any other present fact with asOf 0 (never a calendar
    date), so v1 `usable` is false while its rows stay visible to the `*_UNVERIFIED` reasons. -/
def present {α : Type} (today : Nat) (ksd : Bytes) (k : Kind) : Option (Fact α) → Option (Snapshot α)
  | none => none
  | some f => some (if counts today ksd k f then f.snap else { f.snap with asOf := 0 })

/-- The v1 read set K3 decides on, from fact views: `base` (its four reference fields ignored) with each slot
    `present` for the kind that slot's rule reads. -/
def kRules (base : Rules.Ctx) (ksd : Bytes) (dmf pd : Option (Fact Death)) (ex : Option (Fact Exclusion))
    (en : Option (Fact Span)) : Rules.Ctx :=
  { base with
    dmf := present base.today ksd .DMF dmf
    providerDeaths := present base.today ksd .PROVIDER_DEATH pd
    exclusions := present base.today ksd .EXCLUSION ex
    enrollment := present base.today ksd .ENROLLMENT en }

/-- The K3 read set (review F2): v1's, the head-keyset digest the batch decides under, and the four facts as
    `Signed` (only `attachChain` builds one), `none` if refused. -/
structure Ctx where
  base : Rules.Ctx
  keyset : Bytes
  dmf : Option (Signed Death)
  providerDeaths : Option (Signed Death)
  exclusions : Option (Signed Exclusion)
  enrollment : Option (Signed Span)

/-- What K3 decides on (`Rules.decideLine c.rules`). -/
def Ctx.rules (c : Ctx) : Rules.Ctx :=
  kRules c.base c.keyset (c.dmf.map Fact.ofSigned) (c.providerDeaths.map Fact.ofSigned)
    (c.exclusions.map Fact.ofSigned) (c.enrollment.map Fact.ofSigned)

/-- v1's read of the same rows, ignoring kind, scope, window, day and keyset (spec only, for `allow_tightens`). -/
def Ctx.plain (c : Ctx) : Rules.Ctx :=
  { c.base with
    dmf := c.dmf.map (·.toSnapshot)
    providerDeaths := c.providerDeaths.map (·.toSnapshot)
    exclusions := c.exclusions.map (·.toSnapshot)
    enrollment := c.enrollment.map (·.toSnapshot) }

/-- Kind k's fact is present and counts, stated plainly (both window bounds separately). -/
def Live {α : Type} (today : Nat) (ksd : Bytes) (k : Kind) (o : Option (Fact α)) : Prop :=
  ∃ f, o = some f ∧ f.kind = k ∧ f.day = today ∧ f.keyset = ksd ∧ f.scope ∈ need k ∧ validDate f.snap.asOf = true ∧
    validDate f.validUntil = true ∧ dayNum today ≤ dayNum f.snap.asOf + CEIL k ∧ dayNum today ≤ dayNum f.validUntil

/-- A slot that does not count for kind k: empty, or its fact does not count. -/
def Uncounted {α : Type} (today : Nat) (ksd : Bytes) (k : Kind) (o : Option (Signed α)) : Prop :=
  ∀ r, o = some r → counts today ksd k (Fact.ofSigned r) = false

/-- F2: the slot is empty or holds the ok result of an attach chain run under `verify` from genesis pin `pin` with
    read domain `d` and field list `fl` (any day, any kind number).  `Signed` has a private constructor, so in code
    every Ctx fact is one; this names it in the logic. -/
-- STMT-CHANGE r4 (review r3 MED): `d` and `fl` are parameters, no longer existential
def Attached {α : Type} (verify : Bytes → Bytes → Bytes → Bool) (pin : Bytes) (d : String)
    (fl : α → List (Nat × Nat)) : Option (Signed α) → Prop
  | none => True
  | some r => ∃ (now n : Nat) (st st' : Keyset.Ratchet) (m : SnapshotV2.Manifest) (g : Bytes)
      (steps : List (Nat × Bytes)) (s : Snapshot α) (x : Bytes),
      attachChain verify pin now st m g steps d n fl s x = (st', .ok r)

/-- k-of-n (design §0 with the 10-23 amendment): kSource, at least `Keyset.minSource`, distinct employees' SOURCE keys
    of `ks` on distinct keyIds (so no signature record counts twice), each never revoked (a revoked key counts toward
    no quorum, whatever asOf), authorised for v's scope and kind k, valid from v's asOf (not after `today`) through
    `today`, each with a record in v's signature block that `verify` accepts over `sigMsg` (ks's digest, v's header). -/
-- STMT-CHANGE r3 (review r2 F1): minSource floor and the signature clause; scope and asOf are v's header's
-- STMT-CHANGE r4 (review r3 LOW 2a, 2b): asOf ≤ today; keyId Nodup
def Quorum (verify : Bytes → Bytes → Bytes → Bool) (ks : Keyset.Keyset) (v : SnapshotV2.Snap) (k : Kind) (today : Nat) :
    Prop :=
  Keyset.minSource ≤ ks.kSource ∧ v.head.asOf ≤ today ∧ ∃ es : List Keyset.Entry, es.Sublist ks.entries ∧
    ks.kSource ≤ es.length ∧ (es.map (·.keyId)).Nodup ∧ (es.map (·.employee)).Nodup ∧
    ∀ e ∈ es, e.role = Keyset.source ∧ e.revokedFrom = Keyset.live ∧
      Keyset.bit e.scopes (v.head.scope.byte - 1) = true ∧ Keyset.bit e.kinds (k.byte - 1) = true ∧
      e.validFrom ≤ v.head.asOf ∧ today ≤ e.validUntil ∧
      ∃ q ∈ v.sigs, q.keyId = e.keyId ∧ verify e.pk (SnapshotV2.sigMsg (Keyset.digestOf ks) v.head) q.sig = true

/-- A quorum of `ks` signed r: some bytes decode to a header naming kind k and r's scope, asOf, validUntil and count,
    whose rows digest is `rowsDigest d k.byte fl` of r's snapshot (`Rules.pinInput`: domain d, kind byte, asOf, count
    and each row as `fl` encodes it, so it binds r's rows exactly as far as `fl` encodes them), and a `Quorum` signed
    it.  `allow_attached` fixes d and fl per kind to the read set's. -/
-- STMT-CHANGE r3 (review r2 F1): the signed header is tied to the fact
-- STMT-CHANGE r4 (review r3 MED, LOW 2c): `d` and `fl` are parameters, not `∃ d fl`; count tied
def Signs {α : Type} (verify : Bytes → Bytes → Bytes → Bool) (ks : Keyset.Keyset) (k : Kind) (today : Nat)
    (d : String) (fl : α → List (Nat × Nat)) (r : Signed α) : Prop :=
  ∃ (x : Bytes) (v : SnapshotV2.Snap), SnapshotV2.decode x = some v ∧ v.head.kind = k.byte ∧ v.head.scope = r.scope ∧
    v.head.asOf = r.asOf ∧ v.head.validUntil = r.validUntil ∧ v.head.count = r.count ∧
    SnapshotV2.rowsDigest d k.byte fl r.toSnapshot = some v.head.rows ∧ Quorum verify ks v k today

/-- Design allow_needs_scope: the slot holds a kind-k fact in a scope it needs, attached today through the verifier's
    own chain from `pin`, whose head is the batch keyset `ksd`, live today, and a quorum of it signed it (`Signs` under
    read domain `d` and field list `fl`). -/
-- STMT-CHANGE r3 (review r2 F1): `Signs` for the unsigned `Quorum ks r.scope k r.asOf today`
-- STMT-CHANGE r4 (review r3 MED): `d` and `fl` are parameters, passed to `Signs`
def Trusted {α : Type} (verify : Bytes → Bytes → Bytes → Bool) (pin : Bytes) (today : Nat) (ksd : Bytes) (k : Kind)
    (d : String) (fl : α → List (Nat × Nat)) (o : Option (Signed α)) : Prop :=
  ∃ r, o = some r ∧ r.kind = k ∧ r.scope ∈ need k ∧ r.day = today ∧
    ∃ (st st' : Keyset.Ratchet) (g : Bytes) (steps : List (Nat × Bytes)) (ks : Keyset.Keyset),
      Keyset.admitHead verify pin today st g steps = some (ks, st') ∧ ksd = Keyset.digestOf ks ∧
      Keyset.ksLive ks today = true ∧ Signs verify ks k today d fl r

/-! ### Proof helpers -/

private theorem usable_zero {α : Type} (today maxAge : Nat) (ok : Nat → α → Bool) (s : Snapshot α) :
    Rules.usable today maxAge ok (some { s with asOf := 0 }) = false := by
  simp [Rules.usable, Rules.validDate]

private theorem present_not_counts {α : Type} {today : Nat} {ksd : Bytes} {k : Kind} {f : Fact α}
    (h : counts today ksd k f = false) : present today ksd k (some f) = some { f.snap with asOf := 0 } := by
  simp [present, h]

private theorem present_eq {α : Type} {today maxAge : Nat} {ok : Nat → α → Bool} {ksd : Bytes} {k : Kind}
    {o : Option (Fact α)} (h : Rules.usable today maxAge ok (present today ksd k o) = true) :
    present today ksd k o = o.map (·.snap) := by
  cases o with
  | none => simp [present]
  | some f =>
    by_cases hc : counts today ksd k f = true
    · simp [present, hc]
    · have hc' : counts today ksd k f = false := by simpa using hc
      rw [present_not_counts hc', usable_zero] at h
      simp at h

private theorem usable_uncounted {α : Type} {today maxAge : Nat} {ok : Nat → α → Bool} {ksd : Bytes} {k : Kind}
    {o : Option (Signed α)} (h : Uncounted today ksd k o) :
    Rules.usable today maxAge ok (present today ksd k (o.map Fact.ofSigned)) = false := by
  cases o with
  | none => simp [present, Rules.usable]
  | some r => exact (present_not_counts (h r rfl)).symm ▸ usable_zero _ _ _ _

private theorem snap_ofSigned {α : Type} (o : Option (Signed α)) :
    (o.map Fact.ofSigned).map (·.snap) = o.map (·.toSnapshot) := by
  cases o <;> rfl

private theorem mem_reasons_of_fires (c : Rules.Ctx) (seen : List Key) (l : Line) {r : Reason}
    (hr : r ∈ Rules.reasons) (h : Rules.fires c seen l r = true) : r ∈ (Rules.decideLine c seen l).reasons := by
  simp only [Rules.decideLine, List.mem_filter]
  exact ⟨hr, h⟩

private theorem allow_reasons_nil {c : Rules.Ctx} {seen : List Key} {l : Line}
    (h : (Rules.decideLine c seen l).outcome = .ALLOW) : (Rules.decideLine c seen l).reasons = [] := by
  have h2 : Rules.outcomeOf (Rules.decideLine c seen l).reasons = .ALLOW := h
  cases hl : (Rules.decideLine c seen l).reasons with
  | nil => rfl
  | cons x xs =>
    exfalso
    rw [hl] at h2
    unfold Rules.outcomeOf at h2
    rw [if_neg (by simp)] at h2
    split at h2 <;> simp at h2

private theorem fires_false_of_allow {c : Rules.Ctx} {seen : List Key} {l : Line}
    (h : (Rules.decideLine c seen l).outcome = .ALLOW) {r : Reason} (hr : r ∈ Rules.reasons) :
    Rules.fires c seen l r = false := by
  cases hf : Rules.fires c seen l r with
  | false => rfl
  | true =>
    have := mem_reasons_of_fires c seen l hr hf
    rw [allow_reasons_nil h] at this
    simp at this

/-! ### Statements -/

/-- F1: a self-declared fact satisfies no rule (C8). -/
-- STMT-CHANGE r2
theorem self_never_satisfies (k : Kind) : Scope.SELF ∉ need k := by
  cases k <;> simp [need]

/-- F1 (review F1): a fact of another kind never counts toward kind k, whatever its rows, scope, window, day or
    keyset; so it never fills k's slot (R1 never reads a provider-death list as the DMF). -/
theorem other_kind_not_counts {α : Type} (today : Nat) (ksd : Bytes) (k : Kind) (f : Fact α) (h : f.kind ≠ k) :
    counts today ksd k f = false := by
  simp [counts, beq_false_of_ne h]

/-- F2(b): expDay is the min of the ceiling and signer bounds, so it never extends past either input's bound. -/
-- STMT-CHANGE r2
theorem le_expDay_iff (k : Kind) (a v t : Nat) : t ≤ expDay k a v ↔ t ≤ dayNum a + CEIL k ∧ t ≤ dayNum v := by
  unfold expDay
  omega

/-- Review r2 F4 pin: `Live` is `counts` stated plainly, both ways. -/
theorem live_iff_counts {α : Type} (today : Nat) (ksd : Bytes) (k : Kind) (o : Option (Fact α)) :
    Live today ksd k o ↔ ∃ f, o = some f ∧ counts today ksd k f = true := by
  constructor
  · rintro ⟨f, rfl, h1, h2, h3, h4, h5, h6, h7, h8⟩
    refine ⟨f, rfl, ?_⟩
    simp only [counts, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq]
    exact ⟨⟨⟨⟨⟨⟨h1, h2⟩, h3⟩, by simpa using h4⟩, h5⟩, h6⟩, (le_expDay_iff _ _ _ _).2 ⟨h7, h8⟩⟩
  · rintro ⟨f, rfl, hc⟩
    simp only [counts, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at hc
    obtain ⟨⟨⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, h5⟩, h6⟩, h7⟩ := hc
    exact ⟨f, rfl, h1, h2, h3, by simpa using h4, h5, h6, (le_expDay_iff _ _ _ _).1 h7⟩

/-- Review r2 F4 pin: K3 decides on `kRules` over the facts' views, nothing else. -/
theorem rules_eq (c : Ctx) : c.rules = kRules c.base c.keyset (c.dmf.map Fact.ofSigned)
    (c.providerDeaths.map Fact.ofSigned) (c.exclusions.map Fact.ofSigned) (c.enrollment.map Fact.ofSigned) := rfl

/-- F2(b), review F7: counting is monotone in validUntil (a fact counting under one validUntil counts under any later
    calendar date); contrapositive: shortening validUntil never extends usability. -/
-- STMT-CHANGE r2
theorem counts_lengthen {α : Type} (today : Nat) (ksd : Bytes) (k : Kind) (v : Nat) (f : Fact α)
    (hv : validDate v = true) (hle : dayNum f.validUntil ≤ dayNum v) (h : counts today ksd k f = true) :
    counts today ksd k { f with validUntil := v } = true := by
  simp only [counts, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at h ⊢
  obtain ⟨⟨⟨⟨⟨⟨h0, h1⟩, h2⟩, h3⟩, h4⟩, _⟩, h6⟩ := h
  refine ⟨⟨⟨⟨⟨⟨h0, h1⟩, h2⟩, h3⟩, h4⟩, hv⟩, ?_⟩
  unfold expDay at h6 ⊢
  omega

/-- K3 usable implies v1 usable on the same rows, and the fact counts: K3 only ever removes usability. -/
-- STMT-CHANGE r2
theorem usable_tightens {α : Type} (today maxAge : Nat) (ok : Nat → α → Bool) (ksd : Bytes) (k : Kind)
    (o : Option (Fact α)) (h : Rules.usable today maxAge ok (present today ksd k o) = true) :
    Rules.usable today maxAge ok (o.map (·.snap)) = true ∧ ∃ f, o = some f ∧ counts today ksd k f = true := by
  cases o with
  | none => simp [present, Rules.usable] at h
  | some f =>
    by_cases hc : counts today ksd k f = true
    · exact ⟨by simpa [present, hc] using h, f, rfl, hc⟩
    · have hc' : counts today ksd k f = false := by simpa using hc
      rw [present_not_counts hc', usable_zero] at h
      simp at h

private theorem live_of_usable {α : Type} {today maxAge : Nat} {ok : Nat → α → Bool} {ksd : Bytes} {k : Kind}
    {o : Option (Fact α)} (h : Rules.usable today maxAge ok (present today ksd k o) = true) : Live today ksd k o :=
  (live_iff_counts today ksd k o).2 (usable_tightens today maxAge ok ksd k o h).2

/-- F1 + F2(b) (design allow_facts_live): an ALLOW line read all four kinds live, each slot's fact of its own kind. -/
-- STMT-CHANGE r2
theorem allow_live (c : Ctx) (seen : List Key) (l : Line) (h : (Rules.decideLine c.rules seen l).outcome = .ALLOW) :
    Live c.base.today c.keyset .DMF (c.dmf.map Fact.ofSigned) ∧
      Live c.base.today c.keyset .PROVIDER_DEATH (c.providerDeaths.map Fact.ofSigned) ∧
      Live c.base.today c.keyset .EXCLUSION (c.exclusions.map Fact.ofSigned) ∧
      Live c.base.today c.keyset .ENROLLMENT (c.enrollment.map Fact.ofSigned) := by
  have hs : ∀ r, r ∈ Rules.reasons → Rules.fires c.rules seen l r = false := fun r hr => fires_false_of_allow h hr
  refine ⟨live_of_usable (ok := Rules.okDeath) (maxAge := 90) (by
    have := hs .STALE_DMF (by decide); simpa [Rules.fires, Ctx.rules, kRules] using this), ?_, ?_, ?_⟩
  · exact live_of_usable (ok := Rules.okDeath) (maxAge := 90) (by
      have := hs .STALE_PROVIDER_DEATH (by decide); simpa [Rules.fires, Ctx.rules, kRules] using this)
  · exact live_of_usable (ok := Rules.okExclusion) (maxAge := 31) (by
      have := hs .STALE_EXCLUSION (by decide); simpa [Rules.fires, Ctx.rules, kRules] using this)
  · exact live_of_usable (ok := Rules.okSpan) (maxAge := 7) (by
      have := hs .STALE_ENROLLMENT (by decide); simpa [Rules.fires, Ctx.rules, kRules] using this)

/-- An ALLOW under K3 reads exactly what v1 reads, so v1 allows it too (never the other way: vectors). -/
-- STMT-CHANGE r2
theorem allow_tightens (c : Ctx) (seen : List Key) (l : Line) (h : (Rules.decideLine c.rules seen l).outcome = .ALLOW) :
    c.rules = c.plain := by
  have hs : ∀ r, r ∈ Rules.reasons → Rules.fires c.rules seen l r = false := fun r hr => fires_false_of_allow h hr
  have e1 := present_eq (ok := Rules.okDeath) (maxAge := 90) (by
    have := hs .STALE_DMF (by decide); simpa [Rules.fires, Ctx.rules, kRules] using this)
  have e2 := present_eq (ok := Rules.okDeath) (maxAge := 90) (by
    have := hs .STALE_PROVIDER_DEATH (by decide); simpa [Rules.fires, Ctx.rules, kRules] using this)
  have e3 := present_eq (ok := Rules.okExclusion) (maxAge := 31) (by
    have := hs .STALE_EXCLUSION (by decide); simpa [Rules.fires, Ctx.rules, kRules] using this)
  have e4 := present_eq (ok := Rules.okSpan) (maxAge := 7) (by
    have := hs .STALE_ENROLLMENT (by decide); simpa [Rules.fires, Ctx.rules, kRules] using this)
  simp only [Ctx.rules, Ctx.plain, kRules, e1, e2, e3, e4, snap_ofSigned]

/-- Design untrusted_reviews_not_refuses: a slot that does not count (empty, or a fact that does not count) fires its
    kind's STALE review reason. -/
-- STMT-CHANGE r2
theorem uncounted_reviews (c : Ctx) (seen : List Key) (l : Line) :
    (Uncounted c.base.today c.keyset .DMF c.dmf → Reason.STALE_DMF ∈ (Rules.decideLine c.rules seen l).reasons) ∧
    (Uncounted c.base.today c.keyset .PROVIDER_DEATH c.providerDeaths →
      Reason.STALE_PROVIDER_DEATH ∈ (Rules.decideLine c.rules seen l).reasons) ∧
    (Uncounted c.base.today c.keyset .EXCLUSION c.exclusions →
      Reason.STALE_EXCLUSION ∈ (Rules.decideLine c.rules seen l).reasons) ∧
    (Uncounted c.base.today c.keyset .ENROLLMENT c.enrollment →
      Reason.STALE_ENROLLMENT ∈ (Rules.decideLine c.rules seen l).reasons) := by
  refine ⟨?_, ?_, ?_, ?_⟩ <;> intro hc <;> apply mem_reasons_of_fires _ _ _ (by decide) <;>
    simp [Rules.fires, Ctx.rules, kRules, usable_uncounted hc]

/-- C8, review F6: a slot that does not count (SELF scope, other kind, outside its window, another day or keyset, or
    empty) never yields R1, R3, R5 or enrollment's certain HOLD reason from it, and a CAP_MEMBER_MONTH_DUPLICATE then
    comes only from the batch's own keys, never the enrollment overlap.  Not every HOLD (review r2 F3): an uncounted
    enrollment makes `notEnrolled` false, so an unresolved CAP line claims its full `keys` (`claim`, `pending`) and
    DUPLICATE_OF_UNRESOLVED or COLLIDES_WITH_UNRESOLVED_NEAR may fire from it: conservative (more lines stopped, never
    an ALLOW), as v1 does for a stale enrollment. -/
theorem uncounted_not_certain (c : Ctx) (seen : List Key) (l : Line) :
    (Uncounted c.base.today c.keyset .DMF c.dmf → Reason.MEMBER_DECEASED ∉ (Rules.decideLine c.rules seen l).reasons) ∧
    (Uncounted c.base.today c.keyset .PROVIDER_DEATH c.providerDeaths →
      Reason.PROVIDER_DECEASED ∉ (Rules.decideLine c.rules seen l).reasons) ∧
    (Uncounted c.base.today c.keyset .EXCLUSION c.exclusions →
      Reason.PROVIDER_EXCLUDED ∉ (Rules.decideLine c.rules seen l).reasons) ∧
    (Uncounted c.base.today c.keyset .ENROLLMENT c.enrollment →
      Reason.MEMBER_NOT_ENROLLED ∉ (Rules.decideLine c.rules seen l).reasons ∧
      (Reason.CAP_MEMBER_MONTH_DUPLICATE ∈ (Rules.decideLine c.rules seen l).reasons →
        (Rules.isCap l && (seen.contains (Rules.exactKey l) || seen.contains (Rules.nearKey l))) = true)) := by
  refine ⟨?_, ?_, ?_, ?_⟩ <;> intro hc
  · intro hm
    simp only [Rules.decideLine, List.mem_filter] at hm
    simpa [Rules.fires, Rules.certain, Ctx.rules, kRules, usable_uncounted hc] using hm.2
  · intro hm
    simp only [Rules.decideLine, List.mem_filter] at hm
    simpa [Rules.fires, Rules.certain, Ctx.rules, kRules, usable_uncounted hc] using hm.2
  · intro hm
    simp only [Rules.decideLine, List.mem_filter] at hm
    simpa [Rules.fires, Rules.certain, Ctx.rules, kRules, usable_uncounted hc] using hm.2
  · refine ⟨?_, ?_⟩
    · intro hm
      simp only [Rules.decideLine, List.mem_filter] at hm
      simpa [Rules.fires, Rules.notEnrolled, Rules.certain, Ctx.rules, kRules, usable_uncounted hc] using hm.2
    · intro hm
      simp only [Rules.decideLine, List.mem_filter] at hm
      have := hm.2
      simpa [Rules.fires, Rules.certain, Ctx.rules, kRules, usable_uncounted hc] using this

/-- C8: self-declared enrollment rows that show no span reach review (UNVERIFIED), never the certain HOLD reason. -/
-- STMT-CHANGE r2
theorem self_reviews_not_holds (c : Ctx) (seen : List Key) (l : Line) (f : Signed Span) (he : c.enrollment = some f)
    (hs : f.scope = .SELF) (hd : validDate l.date = true) (hn : f.entries.any (Rules.covers l) = false) :
    Reason.MEMBER_NOT_ENROLLED_UNVERIFIED ∈ (Rules.decideLine c.rules seen l).reasons ∧
      Reason.MEMBER_NOT_ENROLLED ∉ (Rules.decideLine c.rules seen l).reasons := by
  have hc : counts c.base.today c.keyset .ENROLLMENT (Fact.ofSigned f) = false := by
    simp [counts, need, hs, Fact.ofSigned]
  have hp : c.rules.enrollment = some { (Fact.ofSigned f).snap with asOf := 0 } := by
    show present c.base.today c.keyset .ENROLLMENT (c.enrollment.map Fact.ofSigned) = _
    rw [he]
    exact present_not_counts hc
  refine ⟨mem_reasons_of_fires _ _ _ (by decide) ?_, ?_⟩
  · simp [Rules.fires, Rules.unverified, Rules.enrolled, hp, usable_zero, hd, Rules.entries, hn, Fact.ofSigned]
  · intro hm
    simp only [Rules.decideLine, List.mem_filter] at hm
    simpa [Rules.fires, Rules.notEnrolled, Rules.certain, hp, usable_zero] using hm.2

/-- F2(b) + amendment 10-23: the window never resurrects a revoked or expired key, nor fills a slot of another kind.
    A fact attached as kind number n that counts for kind k on `today` is of kind k (n is k's byte), was attached that
    day under the keyset `ksd` names, live that day, and a `Quorum` of it signed the fact's own header (`Signs`;
    bounds: validFrom ≤ asOf and today ≤ validUntil). -/
-- STMT-CHANGE r3 (review r2 F1): `Signs` for the unsigned `Quorum ks r.scope k r.asOf today`
-- STMT-CHANGE r4 (review r3 MED): `Signs` under the attach's own `d` and `fl`
theorem window_no_resurrect {α : Type} {verify : Bytes → Bytes → Bytes → Bool} {pin g x ksd : Bytes}
    {now today n : Nat} {k : Kind} {st st' : Keyset.Ratchet} {m : SnapshotV2.Manifest} {steps : List (Nat × Bytes)}
    {d : String} {fl : α → List (Nat × Nat)} {s : Snapshot α} {r : Signed α}
    (h : attachChain verify pin now st m g steps d n fl s x = (st', .ok r))
    (hc : counts today ksd k (Fact.ofSigned r) = true) :
    today = now ∧ n = k.byte ∧ r.kind = k ∧ r.scope ∈ need k ∧ ∃ ks, Keyset.admitHead verify pin now st g steps =
      some (ks, st') ∧ ksd = Keyset.digestOf ks ∧ Keyset.ksLive ks now = true ∧ Signs verify ks k today d fl r := by
  simp only [counts, Fact.ofSigned, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at hc
  obtain ⟨⟨⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, -⟩, -⟩, -⟩ := hc
  have h4' : r.scope ∈ need k := by simpa using h4
  obtain ⟨ks, hh, -, hw, -, -, -, -, -, -, hat⟩ := SnapshotV2.attachChain_sound h
  obtain ⟨b1, -, b3, ks', hh', b5⟩ := SnapshotV2.attachChain_binds h
  obtain rfl : ks = ks' := by
    rw [hh] at hh'
    exact (Prod.mk.inj (Option.some.inj hh')).1
  obtain ⟨v, -, -, hd, -, -, c2, c3, c4, -, c6, c7, -, c9, -, -, e1, e2, e3⟩ := SnapshotV2.attach_pinned hat
  obtain ⟨v', hd', -, -, hmin, es, hsub, hl, hn0, hn1, hes⟩ := SnapshotV2.attach_sound hw hat
  rw [hd] at hd'
  cases hd'
  have htn : today = now := h2.symm.trans b3
  have hnk : n = k.byte := by rw [← b1, h1]
  subst htn hnk
  refine ⟨rfl, rfl, h1, h4', ks, hh, h3.symm.trans b5, c9, x, v, hd, c2, e2.symm,
    ((congrArg (·.asOf) e1).trans c3.symm).symm, e3.symm, c6.trans (congrArg (·.count) e1).symm,
    by rw [e1]; exact c7, hmin, c4, es, hsub, hl, hn0, hn1, ?_⟩
  intro e he
  obtain ⟨r1, r2, r3, r4, r5, -, r7⟩ := hes e he
  simp only [Keyset.liveAt, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at r4 r5
  obtain ⟨⟨q1, q2⟩, -⟩ := r4
  obtain ⟨-, q4⟩ := r5
  exact ⟨r1, q1, r2, r3, q2, q4, r7⟩

private theorem trusted_of_live {α : Type} {verify : Bytes → Bytes → Bytes → Bool} {pin ksd : Bytes} {today : Nat}
    {k : Kind} {d : String} {fl : α → List (Nat × Nat)} {o : Option (Signed α)} (ha : Attached verify pin d fl o)
    (hl : Live today ksd k (o.map Fact.ofSigned)) : Trusted verify pin today ksd k d fl o := by
  obtain ⟨f, hf, hc⟩ := (live_iff_counts today ksd k _).1 hl
  cases o with
  | none => simp at hf
  | some r =>
    obtain rfl : Fact.ofSigned r = f := Option.some.inj hf
    obtain ⟨now, n, st, st', m, g, steps, s, x, h⟩ := ha
    obtain ⟨rfl, -, hk, hsc, ks, hh, hks, hlv, hs⟩ := window_no_resurrect h hc
    exact ⟨r, rfl, hk, hsc, (SnapshotV2.attachChain_binds h).2.2.1, st, st', g, steps, ks, hh, hks, hlv, hs⟩

/-- F1 + F2 (review F2, design allow_needs_scope): an ALLOW over attached slots relied only on facts live today (`Live`:
    both window bounds) of each slot's kind, in a scope it needs, attached today through the verifier's own chain from
    `pin` under the batch keyset, live today, each signed by a never-revoked k-of-n SOURCE quorum valid from asOf
    through today (`Signs`, under that kind's read domain and field list, the ones pinned per kind, so the
    signed rows digest is the READ digest of the slot's own rows).  The slots share the keyset digest `c.keyset`, the one the READ-MANIFEST pins (design F1)
    and every `sigMsg` binds, not one `Keyset` value: each slot is its own attach run, and equal digests give equal
    keysets only under SHA3-512 collision resistance, which the logic does not assume (no new axioms). -/
-- STMT-CHANGE r3 (review r2 F2): `Live` per slot
-- STMT-CHANGE r4 (review r3 MED): each slot's read domain and field list fixed
theorem allow_attached (c : Ctx) (seen : List Key) (l : Line) (verify : Bytes → Bytes → Bytes → Bool) (pin : Bytes)
    (ha : Attached verify pin "RR/GATE/READ-DMF/v2" Death.fields c.dmf ∧
      Attached verify pin "RR/GATE/READ-PROVIDER-DEATH/v2" Death.fields c.providerDeaths ∧
      Attached verify pin "RR/GATE/READ-EXCLUSION/v2" Exclusion.fields c.exclusions ∧
      Attached verify pin "RR/GATE/READ-ENROLLMENT/v2" Span.fields c.enrollment)
    (h : (Rules.decideLine c.rules seen l).outcome = .ALLOW) :
    (Live c.base.today c.keyset .DMF (c.dmf.map Fact.ofSigned) ∧
        Trusted verify pin c.base.today c.keyset .DMF "RR/GATE/READ-DMF/v2" Death.fields c.dmf) ∧
      (Live c.base.today c.keyset .PROVIDER_DEATH (c.providerDeaths.map Fact.ofSigned) ∧
        Trusted verify pin c.base.today c.keyset .PROVIDER_DEATH "RR/GATE/READ-PROVIDER-DEATH/v2" Death.fields
          c.providerDeaths) ∧
      (Live c.base.today c.keyset .EXCLUSION (c.exclusions.map Fact.ofSigned) ∧
        Trusted verify pin c.base.today c.keyset .EXCLUSION "RR/GATE/READ-EXCLUSION/v2" Exclusion.fields
          c.exclusions) ∧
      (Live c.base.today c.keyset .ENROLLMENT (c.enrollment.map Fact.ofSigned) ∧
        Trusted verify pin c.base.today c.keyset .ENROLLMENT "RR/GATE/READ-ENROLLMENT/v2" Span.fields
          c.enrollment) := by
  obtain ⟨l1, l2, l3, l4⟩ := allow_live c seen l h
  exact ⟨⟨l1, trusted_of_live ha.1 l1⟩, ⟨l2, trusted_of_live ha.2.1 l2⟩, ⟨l3, trusted_of_live ha.2.2.1 l3⟩,
    ⟨l4, trusted_of_live ha.2.2.2 l4⟩⟩

/-! ### Vectors (positive and negative per statement; mutants: `max` for `min` in expDay, `scope ∈ need` dropped, SELF
    added to need ENROLLMENT, kind check dropped, `validDate asOf` dropped).  Line: member 7, parties 8, service
    20261015, today 20261022; rows name id 99 only, the span covers member 7.  `Signed` cannot be built here, so the
    rule vectors run `kRules` on fact views; `vSig` runs the real attach. -/

def vK : Bytes := List.replicate 64 1
def vK2 : Bytes := List.replicate 64 2
def vKinds : List Kind := [.DMF, .PROVIDER_DEATH, .EXCLUSION, .ENROLLMENT]
def vD : Snapshot Death := ⟨20261020, 1, [⟨99, 20200101⟩]⟩
def vX : Snapshot Exclusion := ⟨20261020, 1, [⟨99, 20200101, 99991231⟩]⟩
def vE : Snapshot Span := ⟨20261020, 1, [⟨7, 5, 20260101, 20261231⟩]⟩
/-- The span is member 6's: member 7 shows no enrollment. -/
def vE6 : Snapshot Span := ⟨20261020, 1, [⟨6, 5, 20260101, 20261231⟩]⟩
def vSet : Snapshot Line := ⟨20261001, 0, []⟩
def vBase : Rules.Ctx :=
  { today := 20261022, dmf := none, providerDeaths := none, exclusions := none, enrollment := none,
    released := some vSet, unresolved := some vSet, releasedPrior := ⟨0, 0, []⟩, unresolvedPrior := ⟨0, 0, []⟩,
    anchor := 0, redo := [] }
def vL : Line :=
  { id := 1, pay := 1, flow := .FFS_CLAIM, member := 7, payee := 8, rendering := 8, date := 20261015, proc := 99213,
    units := 1, cents := 100 }
def vF {α : Type} (kd : Kind) (s : Snapshot α) (sc : Scope) (vu : Nat := 20261031) (day : Nat := 20261022)
    (ks : Bytes := vK) : Fact α := ⟨s, kd, sc, vu, day, ks⟩
/-- The K3 read (`kRules`) and v1's read of the same rows. -/
def vC (dm : Fact Death := vF .DMF vD .IDV) (pd : Fact Death := vF .PROVIDER_DEATH vD .IDV)
    (ex : Fact Exclusion := vF .EXCLUSION vX .ENR) (en : Fact Span := vF .ENROLLMENT vE .ELIG) :
    Rules.Ctx × Rules.Ctx :=
  (kRules vBase vK (some dm) (some pd) (some ex) (some en),
    { vBase with dmf := some dm.snap, providerDeaths := some pd.snap, exclusions := some ex.snap,
                 enrollment := some en.snap })
def vDec (c : Rules.Ctx × Rules.Ctx) : Rules.Decision := Rules.decideLine c.1 [] vL
def vV1 (c : Rules.Ctx × Rules.Ctx) : Rules.Decision := Rules.decideLine c.2 [] vL

-- ceilings never above v1's rule-table ages (so v1's own age check never binds before `expDay`)
#guard CEIL .DMF ≤ 90 && CEIL .PROVIDER_DEATH ≤ 90 && CEIL .EXCLUSION ≤ 31 && CEIL .ENROLLMENT ≤ 7
-- self_never_satisfies: every kind has a satisfying scope; SELF satisfies none (kills SELF added to need ENROLLMENT)
#guard vKinds.all fun k => !(need k).isEmpty
#guard vKinds.all fun k => !(need k).contains .SELF
-- le_expDay_iff: the ceiling binds (max would give validUntil), then the signer binds (max would give asOf + 90)
#guard expDay .ENROLLMENT 20261020 20261031 == dayNum 20261020 + 7
#guard expDay .DMF 20261020 20261031 == dayNum 20261031
-- counts: positive, then one fact changed each: scope, day, keyset, ceiling, signer window, invalid validUntil
#guard counts 20261022 vK .ENROLLMENT (vF .ENROLLMENT vE .ELIG)
#guard !counts 20261022 vK .ENROLLMENT (vF .ENROLLMENT vE .ENR) && !counts 20261022 vK .ENROLLMENT (vF .ENROLLMENT vE .SELF)
#guard !counts 20261022 vK .ENROLLMENT (vF .ENROLLMENT vE .ELIG (day := 20261021)) &&
  !counts 20261022 vK2 .ENROLLMENT (vF .ENROLLMENT vE .ELIG)
#guard counts 20261027 vK .ENROLLMENT (vF .ENROLLMENT vE .ELIG (day := 20261027)) &&
  !counts 20261028 vK .ENROLLMENT (vF .ENROLLMENT vE .ELIG (day := 20261028))
#guard counts 20261022 vK .DMF (vF .DMF vD .IDV 20261022) && !counts 20261022 vK .DMF (vF .DMF vD .IDV 20261021)
#guard !counts 20261022 vK .DMF (vF .DMF vD .IDV 20261399)
-- review F5 (kills `validDate asOf` dropped): asOf 20261099 inflates dayNum, so only validDate refuses it
#guard !counts 20261022 vK .ENROLLMENT (vF .ENROLLMENT { vE with asOf := 20261099 } .ELIG)
-- other_kind_not_counts (kills the kind check dropped): same rows, scope, window, day and keyset, kind 2 in kind 1
#guard counts 20261022 vK .PROVIDER_DEATH (vF .PROVIDER_DEATH vD .IDV) && !counts 20261022 vK .DMF (vF .PROVIDER_DEATH vD .IDV)
example : (vF .PROVIDER_DEATH vD .IDV).kind ≠ .DMF ∧ counts 20261022 vK .DMF (vF .PROVIDER_DEATH vD .IDV) = false := by
  decide
-- review F1: v1 allows a provider-death list in the DMF slot; K3 reviews it (STALE_DMF), never ALLOW
#guard (vV1 (vC (dm := vF .PROVIDER_DEATH vD .IDV))).outcome == Outcome.ALLOW
#guard (vDec (vC (dm := vF .PROVIDER_DEATH vD .IDV))).reasons == [Reason.STALE_DMF]
-- the window crosses a month end in calendar days: asOf 20261028 + 7 is 20261104
#guard counts 20261104 vK .ENROLLMENT (vF .ENROLLMENT { vE with asOf := 20261028 } .ELIG 20261130 20261104)
#guard !counts 20261105 vK .ENROLLMENT (vF .ENROLLMENT { vE with asOf := 20261028 } .ELIG 20261130 20261105)
-- bounded outage: a DMF fact 82 days old (signed through 20261231) still counts, 99 days old does not
#guard (vDec (vC (dm := vF .DMF { vD with asOf := 20260801 } .IDV 20261231))).outcome == Outcome.ALLOW
#guard (vDec (vC (dm := vF .DMF { vD with asOf := 20260715 } .IDV 20261231))).reasons.contains .STALE_DMF
-- counts_lengthen: a validUntil before today does not count, a longer one does
#guard !counts 20261022 vK .ENROLLMENT (vF .ENROLLMENT vE .ELIG 20261021) &&
  counts 20261022 vK .ENROLLMENT (vF .ENROLLMENT vE .ELIG 20261031)
-- allow_live, allow_tightens: all four count, ALLOW, same decision as v1
#guard (vDec vC).outcome == Outcome.ALLOW && vDec vC == vV1 vC
-- usable_tightens is one-way, allow_live needs scope (kills `scope ∈ need` dropped): v1 allows an ENR enrollment
-- fact, K3 reviews it; the same for a DMF fact past its signed window, and for a fact of another epoch
#guard (vV1 (vC (en := vF .ENROLLMENT vE .ENR))).outcome == Outcome.ALLOW
#guard (vDec (vC (en := vF .ENROLLMENT vE .ENR))).outcome == Outcome.HUMAN_REVIEW
#guard (vV1 (vC (dm := vF .DMF vD .IDV 20261021))).outcome == Outcome.ALLOW
#guard (vDec (vC (dm := vF .DMF vD .IDV 20261021))).reasons == [Reason.STALE_DMF]
#guard (vDec (vC (ex := vF .EXCLUSION vX .ENR (ks := vK2)))).reasons == [Reason.STALE_EXCLUSION]
-- uncounted_reviews, self_reviews_not_holds: SELF enrollment reviews; with no span it shows UNVERIFIED, while the same
-- rows at ELIG are the certain HOLD
#guard (vDec (vC (en := vF .ENROLLMENT vE .SELF))).reasons == [Reason.STALE_ENROLLMENT]
#guard (vDec (vC (en := vF .ENROLLMENT vE6 .SELF))).reasons ==
  [Reason.MEMBER_NOT_ENROLLED_UNVERIFIED, Reason.STALE_ENROLLMENT]
#guard (vDec (vC (en := vF .ENROLLMENT vE6 .SELF))).outcome == Outcome.HUMAN_REVIEW
#guard (vDec (vC (en := vF .ENROLLMENT vE6 .ELIG))).reasons == [Reason.MEMBER_NOT_ENROLLED]
#guard (vDec (vC (en := vF .ENROLLMENT vE6 .ELIG))).outcome == Outcome.HOLD
-- uncounted_not_certain (review F6): member 7 dead, provider 8 dead and excluded; counted, the certain HOLD reasons;
-- SELF-scoped, only their UNVERIFIED twins and STALE
def vDd : Snapshot Death := ⟨20261020, 1, [⟨7, 20200101⟩]⟩
def vPd : Snapshot Death := ⟨20261020, 1, [⟨8, 20200101⟩]⟩
def vXx : Snapshot Exclusion := ⟨20261020, 1, [⟨8, 20200101, 99991231⟩]⟩
#guard (vDec (vC (dm := vF .DMF vDd .IDV) (pd := vF .PROVIDER_DEATH vPd .IDV) (ex := vF .EXCLUSION vXx .ENR))).reasons ==
  [Reason.MEMBER_DECEASED, Reason.PROVIDER_DECEASED, Reason.PROVIDER_EXCLUDED]
#guard (vDec (vC (dm := vF .DMF vDd .SELF) (pd := vF .PROVIDER_DEATH vPd .SELF) (ex := vF .EXCLUSION vXx .SELF))).reasons ==
  [Reason.MEMBER_DECEASED_UNVERIFIED, Reason.PROVIDER_DECEASED_UNVERIFIED, Reason.PROVIDER_EXCLUDED_UNVERIFIED,
    Reason.STALE_DMF, Reason.STALE_EXCLUSION, Reason.STALE_PROVIDER_DEATH]
-- Uncounted is satisfiable by an empty slot (and by an attached fact on another day: vSig below, `some false`)
example : Uncounted 20261022 vK .DMF (none : Option (Signed Death)) := fun _ h => nomatch h
-- Attached is satisfiable by an empty slot (and by every `some` vSig result below)
example : Attached (fun _ _ _ => true) vK "RR/GATE/READ-DMF/v2" Death.fields (none : Option (Signed Death)) := trivial

/-- window_no_resurrect vectors: does SnapshotV2's vecH1 (kind 1, IDV, asOf 20261104, validUntil 20261110), signed by
    vecLong and vecLong2, attached as kind 1 on 20261105 through chain `ch` under head `hd`, count for kind `k` on
    `today` under `ksd`?  `none`: refused. -/
def vSig (ch : List (Nat × Keyset.Frame)) (hd : Keyset.Keyset) (today : Nat) (ksd : Bytes) (k : Kind := .DMF) :
    Option Bool :=
  (attachChain (fun _ _ _ => true) (Keyset.digestOf SnapshotV2.vecG.ks) 20261105 SnapshotV2.vecI
    (SnapshotV2.vecMan hd SnapshotV2.vecH1 20261105 (gen := Keyset.digestOf SnapshotV2.vecG.ks))
    (Keyset.encode SnapshotV2.vecG) (ch.map fun p => (p.1, Keyset.encode p.2)) "RR/GATE/READ-DMF/v2" 1
    Death.fields (SnapshotV2.vecS SnapshotV2.vecH1.asOf)
    (SnapshotV2.encode ⟨SnapshotV2.vecH1, Keyset.vecRecs [SnapshotV2.vecLong, SnapshotV2.vecLong2]⟩)).2.toOption.map
    fun r => counts today ksd k (Fact.ofSigned r)
-- attached under the genesis it counts that day under it; not the next day, not under the revoking epoch's digest,
-- not as another kind (Signed.kind is the attach kind)
#guard vSig [] SnapshotV2.vecG.ks 20261105 (Keyset.digestOf SnapshotV2.vecG.ks) == some true
#guard vSig [] SnapshotV2.vecG.ks 20261106 (Keyset.digestOf SnapshotV2.vecG.ks) == some false
#guard vSig [] SnapshotV2.vecG.ks 20261105 (Keyset.digestOf SnapshotV2.vecC3.ks) == some false
#guard vSig [] SnapshotV2.vecG.ks 20261105 (Keyset.digestOf SnapshotV2.vecG.ks) .PROVIDER_DEATH == some false
-- epoch 2 (vecLong live) attaches and counts; epoch 3 revokes vecLong: one employee left, refused
#guard vSig [(20261105, SnapshotV2.vecC1), (20261105, SnapshotV2.vecC2)] SnapshotV2.vecC2.ks 20261105
  (Keyset.digestOf SnapshotV2.vecC2.ks) == some true
#guard vSig [(20261105, SnapshotV2.vecC1), (20261105, SnapshotV2.vecC2), (20261105, SnapshotV2.vecC3)]
  SnapshotV2.vecC3.ks 20261105 (Keyset.digestOf SnapshotV2.vecC3.ks) == none


/-- Review r2 F4, allow_attached is not vacuous: four real attaches (stub verify, vecG's chain on 20261105, signed by
    vecLong and vecLong2) of one kind each, under one manifest pinning all four headers.  The Ctx they fill is
    `Attached` (proved) and its line is ALLOW (`#guard`: a proof would make the kernel evaluate SHA3-512, and
    native_decide is barred). -/
def vHd {α : Type} (k : Kind) (sc : Scope) (d : String) (fl : α → List (Nat × Nat)) (s : Snapshot α) :
    SnapshotV2.Header :=
  ⟨k.byte, sc, s.asOf, 20261110, s.count, (SnapshotV2.rowsDigest d k.byte fl s).getD []⟩
def vD4 : Snapshot Death := { vD with asOf := 20261104 }
def vX4 : Snapshot Exclusion := { vX with asOf := 20261104 }
def vE4 : Snapshot Span := { vE with asOf := 20261104 }
def vH4 : List SnapshotV2.Header :=
  [vHd .DMF .IDV "RR/GATE/READ-DMF/v2" Death.fields vD4,
    vHd .PROVIDER_DEATH .IDV "RR/GATE/READ-PROVIDER-DEATH/v2" Death.fields vD4,
    vHd .EXCLUSION .ENR "RR/GATE/READ-EXCLUSION/v2" Exclusion.fields vX4,
    vHd .ENROLLMENT .ELIG "RR/GATE/READ-ENROLLMENT/v2" Span.fields vE4]
def vMan4 : SnapshotV2.Manifest :=
  { SnapshotV2.vecMan SnapshotV2.vecG.ks SnapshotV2.vecH1 20261105 (gen := Keyset.digestOf SnapshotV2.vecG.ks) with
    pins := vH4.map SnapshotV2.digest,
    pre := SnapshotV2.setTag ++ (vH4.map fun h => 1 :: h.rows).flatten ++ natBE 4 0 ++ zeroDigest }
def vVer : Bytes → Bytes → Bytes → Bool := fun _ _ _ => true
def vPin : Bytes := Keyset.digestOf SnapshotV2.vecG.ks
/-- Kind k's slot: `vHd k sc d fl s` attached as k on 20261105 by a fresh node.  Irreducible, so checking a `vCtx`
    slot against `attached_run` never evaluates the attach in the kernel. -/
@[irreducible] def vRun {α : Type} (k : Kind) (sc : Scope) (d : String) (fl : α → List (Nat × Nat)) (s : Snapshot α) :
    Option (Signed α) :=
  (attachChain vVer vPin 20261105 SnapshotV2.vecI vMan4 (Keyset.encode SnapshotV2.vecG) [] d k.byte fl s
    (SnapshotV2.encode ⟨vHd k sc d fl s, Keyset.vecRecs [SnapshotV2.vecLong, SnapshotV2.vecLong2]⟩)).2.toOption
def vCtx : Ctx :=
  ⟨{ vBase with today := 20261105 }, vPin, vRun .DMF .IDV "RR/GATE/READ-DMF/v2" Death.fields vD4,
    vRun .PROVIDER_DEATH .IDV "RR/GATE/READ-PROVIDER-DEATH/v2" Death.fields vD4,
    vRun .EXCLUSION .ENR "RR/GATE/READ-EXCLUSION/v2" Exclusion.fields vX4,
    vRun .ENROLLMENT .ELIG "RR/GATE/READ-ENROLLMENT/v2" Span.fields vE4⟩

private theorem attached_run {α : Type} (k : Kind) (sc : Scope) (d : String) (fl : α → List (Nat × Nat))
    (s : Snapshot α) : Attached vVer vPin d fl (vRun k sc d fl s) := by
  unfold vRun
  rcases hp : attachChain vVer vPin 20261105 SnapshotV2.vecI vMan4 (Keyset.encode SnapshotV2.vecG) [] d k.byte fl s
    (SnapshotV2.encode ⟨vHd k sc d fl s, Keyset.vecRecs [SnapshotV2.vecLong, SnapshotV2.vecLong2]⟩) with ⟨st', _ | r⟩
  · exact trivial
  · exact ⟨_, _, _, st', _, _, _, _, _, hp⟩

example : Attached vVer vPin "RR/GATE/READ-DMF/v2" Death.fields vCtx.dmf ∧
    Attached vVer vPin "RR/GATE/READ-PROVIDER-DEATH/v2" Death.fields vCtx.providerDeaths ∧
    Attached vVer vPin "RR/GATE/READ-EXCLUSION/v2" Exclusion.fields vCtx.exclusions ∧
    Attached vVer vPin "RR/GATE/READ-ENROLLMENT/v2" Span.fields vCtx.enrollment :=
  ⟨attached_run _ _ _ _ _, attached_run _ _ _ _ _, attached_run _ _ _ _ _, attached_run _ _ _ _ _⟩
#guard vCtx.dmf.isSome && vCtx.providerDeaths.isSome && vCtx.exclusions.isSome && vCtx.enrollment.isSome &&
  (Rules.decideLine vCtx.rules [] vL).outcome == Outcome.ALLOW
-- the same attaches under another batch keyset digest: none counts, review
#guard (Rules.decideLine { vCtx with keyset := vK }.rules [] vL).outcome == Outcome.HUMAN_REVIEW
-- Python cross-vector (tests/test_right_rail_gate_snapshot.py LEAN_MAN4): the manifest pinning all four headers, so the
-- four READ-<kind>/v2 literals and field encodings, byte for byte
#guard Keyset.vecHex (sha3 (SnapshotV2.encodeMan vMan4)) ==
  "92d73bb8f89857a2d793dd5846cb3662c329d285281f6d98f675647202f1a9792bd7ccc0b27f1f6688c605fdbc9d2c83128be88593175315802f9ad88d45e1cb"

end BlindLedger.Gate.Scoped
