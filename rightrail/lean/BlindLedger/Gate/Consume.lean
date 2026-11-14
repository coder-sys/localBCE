import BlindLedger.Gate.Scoped
import BlindLedger.Gate.Rules.Theorems

namespace BlindLedger.Gate.Consume
open SnapshotV2 (Kind Scope Signed Head admitBatchHead attachAt)
open Rules (Snapshot Death Exclusion Span Line Reason Outcome)

/-! K3 consumer, pure layer (design rrb/designs/agi-k3-consumer-v1.md §2.2, slice S1).  A batch reads its four
    reference kinds as SNAPSHOT/v3 facts attached under ONE head, admitted once for the batch day from the node's own
    chain (`readAll`), and decides on `Scoped.Ctx.rules`.  A kind that is missing, refused or does not count reviews
    (its STALE reason), never ALLOWs and never refuses the batch (absorb, don't bounce).  The verifier is a parameter;
    S3a wires ML-DSA-87.  The `Cause` byte is a diagnostic only: it reads the decoded header and the head, verifies
    nothing and changes no decision. -/

/-- The READ-<kind>/v2 domain of kind k (as `Scoped.allow_attached` fixes them). -/
def dom : Kind → String
  | .DMF => "RR/GATE/READ-DMF/v2" | .PROVIDER_DEATH => "RR/GATE/READ-PROVIDER-DEATH/v2"
  | .EXCLUSION => "RR/GATE/READ-EXCLUSION/v2" | .ENROLLMENT => "RR/GATE/READ-ENROLLMENT/v2"

/-- FACTS/v1 decoded: the node's genesis pin and id, the keyset chain (genesis frame and dated steps) and each kind's
    SNAPSHOT/v3 bytes. -/
structure Offer where
  pin : Bytes
  node : Bytes
  g : Bytes
  steps : List (Nat × Bytes)
  dmf : Option Bytes
  pd : Option Bytes
  ex : Option Bytes
  en : Option Bytes

/-- The rows the frame declared for each kind. -/
structure Rows where
  dmf : Option (Snapshot Death)
  pd : Option (Snapshot Death)
  ex : Option (Snapshot Exclusion)
  en : Option (Snapshot Span)

/-- Why a kind counts or not.  COUNTED is exactly `Scoped.counts` (`cause_counted_iff`); the rest are diagnostics. -/
inductive Cause | ABSENT | COUNTED | SCOPE | AGE | DATE | CHAIN | BINDING | EXPIRED | FUTURE | QUORUM | REVOKED
  deriving DecidableEq, Repr

/-- READ-MANIFEST/v4 cause byte. -/
def Cause.byte : Cause → Nat
  | .ABSENT => 0 | .COUNTED => 1 | .SCOPE => 2 | .AGE => 3 | .DATE => 4 | .CHAIN => 16 | .BINDING => 17
  | .EXPIRED => 18 | .FUTURE => 19 | .QUORUM => 32 | .REVOKED => 33

/-- One kind: none unless both rows and bytes were offered, else the attach under the batch head (`.binding` if none
    was admitted). -/
def one {α : Type} (verify : Bytes → Bytes → Bytes → Bool) (H : Option Head) (k : Kind) (fl : α → List (Nat × Nat)) :
    Option (Snapshot α) → Option Bytes → Option (Except SnapshotV2.Refusal (Signed α))
  | some s, some x => some (H.elim (.error .binding) fun H => attachAt verify H (dom k) k.byte fl s x)
  | _, _ => none

/-- A batch's read: the ratchet to persist, the head, each kind's attach, and what was offered. -/
structure Read where
  to : Keyset.Ratchet
  head : Option Head
  dmf : Option (Except SnapshotV2.Refusal (Signed Death))
  pd : Option (Except SnapshotV2.Refusal (Signed Death))
  ex : Option (Except SnapshotV2.Refusal (Signed Exclusion))
  en : Option (Except SnapshotV2.Refusal (Signed Span))
  offer : Offer
  rows : Rows

/-- ONE admitted head for all four kinds (closes `Scoped.allow_attached`'s equal-digest caveat); the ratchet moves
    exactly when the head is admitted, whatever the snapshots. -/
def readAll (verify : Bytes → Bytes → Bytes → Bool) (o : Offer) (now : Nat) (st : Keyset.Ratchet) (r : Rows) : Read :=
  let a := admitBatchHead verify o.pin now st o.g o.steps
  let H := a.map (·.1)
  ⟨(a.map (·.2)).getD st, H, one verify H .DMF Death.fields r.dmf o.dmf, one verify H .PROVIDER_DEATH Death.fields r.pd o.pd,
    one verify H .EXCLUSION Exclusion.fields r.ex o.ex, one verify H .ENROLLMENT Span.fields r.en o.en, o, r⟩

/-- The head keyset's digest, zero without a head. -/
def Read.ksd (b : Read) : Bytes := (b.head.map (Keyset.digestOf ·.ks)).getD zeroDigest

def Read.ctx (b : Read) (base : Rules.Ctx) : Scoped.Ctx :=
  ⟨base, b.ksd, b.dmf.bind (·.toOption), b.pd.bind (·.toOption), b.ex.bind (·.toOption), b.en.bind (·.toOption)⟩

/-- Decide a batch on signed facts: the read, and v1's batch decision on the K3 read set. -/
def decideSigned (verify : Bytes → Bytes → Bytes → Bool) (o : Offer) (st : Keyset.Ratchet) (rows : Rows)
    (base : Rules.Ctx) (f : List Nat) (lines : List Line) : Read × Rules.Result :=
  let b := readAll verify o base.today st rows
  (b, Rules.decideBatchIn (b.ctx base).rules f lines)

/-- Kind k's fact r is live today under ks and a never-revoked k-of-n SOURCE quorum of ks signed its own rows. -/
def Good {α : Type} (verify : Bytes → Bytes → Bytes → Bool) (ks : Keyset.Keyset) (today : Nat) (k : Kind)
    (fl : α → List (Nat × Nat)) (r : Signed α) : Prop :=
  Scoped.Live today (Keyset.digestOf ks) k (some (Scoped.Fact.ofSigned r)) ∧ Scoped.Signs verify ks k today (dom k) fl r

def stale : Kind → Reason
  | .DMF => .STALE_DMF | .PROVIDER_DEATH => .STALE_PROVIDER_DEATH | .EXCLUSION => .STALE_EXCLUSION
  | .ENROLLMENT => .STALE_ENROLLMENT

/-- A refused slot: CHAIN without a head; else, from the decoded header, EXPIRED, FUTURE or BINDING for a binding
    refusal, and REVOKED if a signature record names a revoked key of the head, else QUORUM, for a quorum refusal. -/
def refusedCause (H : Option Head) (x : Option Bytes) (e : SnapshotV2.Refusal) : Cause :=
  match H, x.bind SnapshotV2.decode, e with
  | none, _, _ => .CHAIN
  | some H, some v, .binding =>
    if v.head.validUntil < H.day then .EXPIRED else if H.day < v.head.asOf then .FUTURE else .BINDING
  | some H, some v, .quorum =>
    if v.sigs.any fun q => H.ks.entries.any fun e => e.keyId == q.keyId && e.revokedFrom != Keyset.live then .REVOKED
    else .QUORUM
  | some _, none, .binding => .BINDING
  | some _, none, .quorum => .QUORUM

/-- What a cause reads of an attached fact: everything but the rows (their date and count kept). -/
def bare {α : Type} (r : Signed α) : Scoped.Fact Unit :=
  ⟨⟨r.asOf, r.count, []⟩, r.kind, r.scope, r.validUntil, r.day, r.keyset⟩

/-- An attached fact: COUNTED if it counts, else SCOPE, then DATE, then AGE. -/
def okCause (today : Nat) (ksd : Bytes) (k : Kind) (f : Scoped.Fact Unit) : Cause :=
  if Scoped.counts today ksd k f then .COUNTED
  else if !(Scoped.need k).contains f.scope then .SCOPE
  else if !(Rules.validDate f.snap.asOf && Rules.validDate f.validUntil) then .DATE else .AGE

/-- One slot's cause; `lone`: rows or bytes offered (an empty slot with either is a BINDING, with neither ABSENT). -/
def slotCause (H : Option Head) (today : Nat) (ksd : Bytes) (k : Kind) (lone : Bool) (x : Option Bytes) :
    Option (Except SnapshotV2.Refusal (Scoped.Fact Unit)) → Cause
  | none => if lone then .BINDING else .ABSENT
  | some (.ok f) => okCause today ksd k f
  | some (.error e) => refusedCause H x e

/-- One kind as the batch record shows it: attached, the attached header's digest (zero if not), and its cause. -/
structure KView where
  attached : Bool
  pin : Bytes
  cause : Cause
  deriving DecidableEq, Repr

/-- Kind k's view from its slot's row-free result under head `H` on `today`. -/
def KView.of (H : Option Head) (today : Nat) (k : Kind) (lone : Bool) (x : Option Bytes)
    (s : Option (Except SnapshotV2.Refusal (Scoped.Fact Unit))) : KView :=
  let att := match s with | some (.ok _) => true | _ => false
  ⟨att, if att then ((x.bind SnapshotV2.decode).map (SnapshotV2.digest ·.head)).getD zeroDigest else zeroDigest,
    slotCause H today ((H.map (Keyset.digestOf ·.ks)).getD zeroDigest) k lone x s⟩

/-- What a batch's read shows without its rows: the ratchet to persist, whether a head was admitted, each kind. -/
structure View where
  to : Keyset.Ratchet
  admitted : Bool
  dmf : KView
  pd : KView
  ex : KView
  en : KView

def Read.view (b : Read) (today : Nat) : View :=
  ⟨b.to, b.head.isSome,
    KView.of b.head today .DMF (b.offer.dmf.isSome || b.rows.dmf.isSome) b.offer.dmf (b.dmf.map (·.map bare)),
    KView.of b.head today .PROVIDER_DEATH (b.offer.pd.isSome || b.rows.pd.isSome) b.offer.pd (b.pd.map (·.map bare)),
    KView.of b.head today .EXCLUSION (b.offer.ex.isSome || b.rows.ex.isSome) b.offer.ex (b.ex.map (·.map bare)),
    KView.of b.head today .ENROLLMENT (b.offer.en.isSome || b.rows.en.isSome) b.offer.en (b.en.map (·.map bare))⟩

def Read.cause (b : Read) (today : Nat) : Kind → Cause
  | .DMF => (b.view today).dmf.cause
  | .PROVIDER_DEATH => (b.view today).pd.cause
  | .EXCLUSION => (b.view today).ex.cause
  | .ENROLLMENT => (b.view today).en.cause

/-- `allow_signed`'s conclusion for the read of `o` on `today` from `st`, with `to` the ratchet persisted. -/
def SignedOk (verify : Bytes → Bytes → Bytes → Bool) (o : Offer) (today : Nat) (st : Keyset.Ratchet) (rows : Rows)
    (to : Keyset.Ratchet) : Prop :=
  ∃ ks st', Keyset.admitHead verify o.pin today st o.g o.steps = some (ks, st') ∧
    Keyset.ksLive ks today = true ∧ to = st' ∧
    (∃ r, (readAll verify o today st rows).dmf = some (.ok r) ∧ Good verify ks today .DMF Death.fields r) ∧
    (∃ r, (readAll verify o today st rows).pd = some (.ok r) ∧ Good verify ks today .PROVIDER_DEATH Death.fields r) ∧
    (∃ r, (readAll verify o today st rows).ex = some (.ok r) ∧ Good verify ks today .EXCLUSION Exclusion.fields r) ∧
    (∃ r, (readAll verify o today st rows).en = some (.ok r) ∧ Good verify ks today .ENROLLMENT Span.fields r)

/-! ### Proof helpers -/

variable {verify : Bytes → Bytes → Bytes → Bool} {o : Offer} {st : Keyset.Ratchet} {rows : Rows} {base : Rules.Ctx}
  {f : List Nat} {lines : List Line} {d : Rules.Decision}

private theorem refusedCause_ne {H : Option Head} {x : Option Bytes} {e : SnapshotV2.Refusal} :
    refusedCause H x e ≠ .COUNTED := by
  intro h
  unfold refusedCause at h
  split at h <;> (try split at h) <;> (try split at h) <;> cases h

theorem slotCause_counted {α : Type} {H : Option Head} {today : Nat} {ksd : Bytes} {k : Kind} {lone : Bool}
    {x : Option Bytes} {s : Option (Except SnapshotV2.Refusal (Signed α))} :
    slotCause H today ksd k lone x (s.map (·.map bare)) = .COUNTED ↔ ∃ r, s = some (.ok r) ∧
      Scoped.counts today ksd k (Scoped.Fact.ofSigned r) = true := by
  rcases s with _ | _ | r
  · cases lone <;> simp [slotCause]
  · simp only [Option.map_some, Except.map, slotCause]
    exact ⟨fun h => absurd h refusedCause_ne, fun ⟨_, h, _⟩ => by simp at h⟩
  · simp only [Option.map_some, Except.map, slotCause]
    constructor
    · intro h
      unfold okCause at h
      split at h
      · rename_i hc
        exact ⟨r, rfl, hc⟩
      · split at h <;> (try split at h) <;> cases h
    · rintro ⟨r', hr, hc⟩
      cases hr
      exact if_pos hc

private theorem uncounted_of_cause {α : Type} {H : Option Head} {today : Nat} {ksd : Bytes} {k : Kind} {lone : Bool}
    {x : Option Bytes} {s : Option (Except SnapshotV2.Refusal (Signed α))}
    (h : slotCause H today ksd k lone x (s.map (·.map bare)) ≠ .COUNTED) :
    Scoped.Uncounted today ksd k (s.bind (·.toOption)) := by
  intro r hr
  have hs : s = some (.ok r) := by
    rcases s with _ | _ | r' <;> simp [Except.toOption] at hr ⊢
    exact hr
  cases hc : Scoped.counts today ksd k (Scoped.Fact.ofSigned r)
  · rfl
  · exact absurd (slotCause_counted.2 ⟨r, hs, hc⟩) h

private theorem mem_decide (hd : d ∈ (decideSigned verify o st rows base f lines).2.decisions) :
    ∃ seen l, d = Rules.decideLine ((readAll verify o base.today st rows).ctx base).rules seen l := by
  simp only [decideSigned, Rules.decideBatchIn] at hd
  obtain ⟨pre, l, rfl⟩ := Rules.mem_decideAll hd
  exact ⟨_, l, rfl⟩

private theorem head_some {now : Nat} {H : Head} (h : (readAll verify o now st rows).head = some H) :
    admitBatchHead verify o.pin now st o.g o.steps = some (H, (readAll verify o now st rows).to) := by
  simp only [readAll] at h ⊢
  cases hA : admitBatchHead verify o.pin now st o.g o.steps with
  | none => simp [hA] at h
  | some p =>
    obtain ⟨H', st'⟩ := p
    simp only [hA, Option.map_some, Option.some.injEq, Option.getD_some] at h ⊢
    rw [h]

private theorem head_wf {now : Nat} {H : Head} (h : (readAll verify o now st rows).head = some H) :
    Keyset.Wf H.ks ∧ H.day = now := by
  obtain ⟨hh, hday, -⟩ := SnapshotV2.admitBatchHead_eq.1 (head_some h)
  exact ⟨(Keyset.admitFold_wf (Keyset.admitHead_sound hh).1).1, hday⟩

/-- A slot live under the batch head's digest is an attach under that head, `Good`, with the head live today. -/
private theorem slot_good {α : Type} {Hd : Option Head} {today : Nat} {k : Kind} {fl : α → List (Nat × Nat)}
    {so : Option (Snapshot α)} {xo : Option Bytes} (hw : ∀ H, Hd = some H → Keyset.Wf H.ks ∧ H.day = today)
    (hl : Scoped.Live today ((Hd.map (Keyset.digestOf ·.ks)).getD zeroDigest) k
      (((one verify Hd k fl so xo).bind (·.toOption)).map Scoped.Fact.ofSigned)) :
    ∃ H, Hd = some H ∧ ∃ r, one verify Hd k fl so xo = some (.ok r) ∧ Good verify H.ks today k fl r ∧
      Keyset.ksLive H.ks today = true := by
  obtain ⟨fct, hf, hk, hday, hks, hsc, hv1, hv2, ha1, ha2⟩ := hl
  rcases so with _ | s
  · simp [one] at hf
  rcases xo with _ | x
  · simp [one] at hf
  rcases Hd with _ | H
  · simp [one, Option.elim, Except.toOption] at hf
  cases ha : attachAt verify H (dom k) k.byte fl s x with
  | error e => simp [one, Option.elim, ha, Except.toOption] at hf
  | ok r =>
    simp [one, Option.elim, ha, Except.toOption] at hf
    subst hf
    obtain ⟨hwf, hdy⟩ := hw H rfl
    subst hdy
    obtain ⟨v, hd, c1, c2, c3, c4, c5, c6, c7, e1, e3, e4, -, -, hmin, es, hsub, hl, hn1, hn2, hes⟩ :=
      SnapshotV2.attachAt_sound hwf ha
    refine ⟨H, rfl, r, by simp [one, Option.elim, ha], ⟨⟨_, rfl, hk, hday, by simpa using hks, hsc, hv1, hv2, ha1, ha2⟩,
      x, v, hd, c1, e3.symm, c2.trans (congrArg (·.asOf) e1).symm, e4.symm, c5.trans (congrArg (·.count) e1).symm,
      by rw [e1]; exact c6, hmin, c3, es, hsub, hl, hn1, hn2, ?_⟩, c7⟩
    intro e he
    obtain ⟨r1, r2, r3, r4, r5, -, r7⟩ := hes e he
    simp only [Keyset.liveAt, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at r4 r5
    obtain ⟨⟨q1, q2⟩, -⟩ := r4
    obtain ⟨-, q4⟩ := r5
    exact ⟨r1, q1, r2, r3, q2, q4, r7⟩

/-- All four slots live under the read's head digest: `SignedOk`, under that one head. -/
private theorem good_of_live {now : Nat}
    (l1 : Scoped.Live now (readAll verify o now st rows).ksd .DMF
      (((readAll verify o now st rows).dmf.bind (·.toOption)).map Scoped.Fact.ofSigned))
    (l2 : Scoped.Live now (readAll verify o now st rows).ksd .PROVIDER_DEATH
      (((readAll verify o now st rows).pd.bind (·.toOption)).map Scoped.Fact.ofSigned))
    (l3 : Scoped.Live now (readAll verify o now st rows).ksd .EXCLUSION
      (((readAll verify o now st rows).ex.bind (·.toOption)).map Scoped.Fact.ofSigned))
    (l4 : Scoped.Live now (readAll verify o now st rows).ksd .ENROLLMENT
      (((readAll verify o now st rows).en.bind (·.toOption)).map Scoped.Fact.ofSigned)) :
    SignedOk verify o now st rows (readAll verify o now st rows).to := by
  have hw : ∀ H, (readAll verify o now st rows).head = some H → Keyset.Wf H.ks ∧ H.day = now :=
    fun _ h => head_wf h
  obtain ⟨H, hH, r1, h1, g1, hlv⟩ := slot_good (Hd := (readAll verify o now st rows).head) hw l1
  obtain ⟨H2, hH2, r2, h2, g2, -⟩ := slot_good (Hd := (readAll verify o now st rows).head) hw l2
  obtain ⟨H3, hH3, r3, h3, g3, -⟩ := slot_good (Hd := (readAll verify o now st rows).head) hw l3
  obtain ⟨H4, hH4, r4, h4, g4, -⟩ := slot_good (Hd := (readAll verify o now st rows).head) hw l4
  obtain rfl : H2 = H := Option.some.inj (hH2.symm.trans hH)
  obtain rfl : H3 = H2 := Option.some.inj (hH3.symm.trans hH)
  obtain rfl : H4 = H3 := Option.some.inj (hH4.symm.trans hH)
  obtain ⟨hh, -, -⟩ := SnapshotV2.admitBatchHead_eq.1 (head_some hH)
  exact ⟨H4.ks, _, hh, hlv, rfl, ⟨r1, h1, g1⟩, ⟨r2, h2, g2⟩, ⟨r3, h3, g3⟩, ⟨r4, h4, g4⟩⟩

private theorem live_of {α : Type} {today : Nat} {ksd : Bytes} {k : Kind}
    {sl : Option (Except SnapshotV2.Refusal (Signed α))} {r : Signed α} (h1 : sl = some (.ok r))
    (hc : Scoped.counts today ksd k (Scoped.Fact.ofSigned r) = true) :
    Scoped.Live today ksd k ((sl.bind (·.toOption)).map Scoped.Fact.ofSigned) :=
  (Scoped.live_iff_counts _ _ _ _).2 ⟨_, by rw [h1]; rfl, hc⟩

/-! ### Statements -/

/-- MAIN. No line is ALLOW unless all four kinds were attached under ONE head admitted today from the node's own chain
    (live today), each counted (kind, scope, day, keyset, dates, both window bounds) and signed by a never-revoked
    k-of-n SOURCE quorum of that head over its own rows; the ratchet persisted is that admission's. -/
theorem allow_signed (verify : Bytes → Bytes → Bytes → Bool) (o : Offer) (st : Keyset.Ratchet) (rows : Rows)
    (base : Rules.Ctx) (f : List Nat) (lines : List Line) (d : Rules.Decision)
    (hd : d ∈ (decideSigned verify o st rows base f lines).2.decisions) (ha : d.outcome = .ALLOW) :
    ∃ ks st', Keyset.admitHead verify o.pin base.today st o.g o.steps = some (ks, st') ∧
      Keyset.ksLive ks base.today = true ∧ (decideSigned verify o st rows base f lines).1.to = st' ∧
      (∃ r, (decideSigned verify o st rows base f lines).1.dmf = some (.ok r) ∧
        Good verify ks base.today .DMF Death.fields r) ∧
      (∃ r, (decideSigned verify o st rows base f lines).1.pd = some (.ok r) ∧
        Good verify ks base.today .PROVIDER_DEATH Death.fields r) ∧
      (∃ r, (decideSigned verify o st rows base f lines).1.ex = some (.ok r) ∧
        Good verify ks base.today .EXCLUSION Exclusion.fields r) ∧
      (∃ r, (decideSigned verify o st rows base f lines).1.en = some (.ok r) ∧
        Good verify ks base.today .ENROLLMENT Span.fields r) := by
  obtain ⟨seen, l, rfl⟩ := mem_decide hd
  obtain ⟨l1, l2, l3, l4⟩ := Scoped.allow_live _ seen l ha
  exact good_of_live l1 l2 l3 l4

/-- COUNTED is exactly `Scoped.counts` of an attached fact under the read's head digest. -/
theorem cause_counted_iff (b : Read) (today : Nat) :
    (b.cause today .DMF = .COUNTED ↔ ∃ r, b.dmf = some (.ok r) ∧
        Scoped.counts today b.ksd .DMF (Scoped.Fact.ofSigned r) = true) ∧
      (b.cause today .PROVIDER_DEATH = .COUNTED ↔ ∃ r, b.pd = some (.ok r) ∧
        Scoped.counts today b.ksd .PROVIDER_DEATH (Scoped.Fact.ofSigned r) = true) ∧
      (b.cause today .EXCLUSION = .COUNTED ↔ ∃ r, b.ex = some (.ok r) ∧
        Scoped.counts today b.ksd .EXCLUSION (Scoped.Fact.ofSigned r) = true) ∧
      (b.cause today .ENROLLMENT = .COUNTED ↔ ∃ r, b.en = some (.ok r) ∧
        Scoped.counts today b.ksd .ENROLLMENT (Scoped.Fact.ofSigned r) = true) :=
  ⟨slotCause_counted, slotCause_counted, slotCause_counted, slotCause_counted⟩

/-- All four kinds COUNTED: `allow_signed`'s conclusion (one head admitted today from the node's own chain, live, each
    kind attached under it, counted and signed by a never-revoked k-of-n SOURCE quorum of it; that admission's ratchet
    persisted).  Whatever reads the causes (the flat index's feeds) inherits the money rule from here. -/
theorem counted_good {now : Nat} (h : ∀ k, (readAll verify o now st rows).cause now k = .COUNTED) :
    SignedOk verify o now st rows (readAll verify o now st rows).to := by
  obtain ⟨c1, c2, c3, c4⟩ := cause_counted_iff (readAll verify o now st rows) now
  obtain ⟨_, e1, k1⟩ := c1.1 (h .DMF)
  obtain ⟨_, e2, k2⟩ := c2.1 (h .PROVIDER_DEATH)
  obtain ⟨_, e3, k3⟩ := c3.1 (h .EXCLUSION)
  obtain ⟨_, e4, k4⟩ := c4.1 (h .ENROLLMENT)
  exact good_of_live (live_of e1 k1) (live_of e2 k2) (live_of e3 k3) (live_of e4 k4)

/-- Ratchet: unchanged without a head; else exactly admitHead's, never behind in day or epoch, cp carried. -/
theorem readAll_ratchet {now : Nat} :
    ((readAll verify o now st rows).head = none ∧ (readAll verify o now st rows).to = st) ∨
    (∃ H, (readAll verify o now st rows).head = some H ∧
      Keyset.admitHead verify o.pin now st o.g o.steps = some (H.ks, (readAll verify o now st rows).to) ∧
      st.day ≤ now ∧ (readAll verify o now st rows).to.day = now ∧ st.epoch ≤ (readAll verify o now st rows).to.epoch ∧
      (readAll verify o now st rows).to.cp = st.cp) := by
  cases hA : admitBatchHead verify o.pin now st o.g o.steps with
  | none => exact Or.inl (by simp [readAll, hA])
  | some p =>
    obtain ⟨H, st'⟩ := p
    have hh : (readAll verify o now st rows).head = some H := by simp [readAll, hA]
    have ht : (readAll verify o now st rows).to = st' := by simp [readAll, hA]
    obtain ⟨h1, -, -⟩ := SnapshotV2.admitBatchHead_eq.1 hA
    obtain ⟨-, hst, he, hd, -⟩ := Keyset.admitHead_sound h1
    rw [ht]
    subst hst
    exact Or.inr ⟨H, hh, h1, hd, rfl, he, rfl⟩

private theorem uncounted_slot (k : Kind) (hk : (readAll verify o base.today st rows).cause base.today k ≠ .COUNTED) :
    (k = .DMF → Scoped.Uncounted base.today (readAll verify o base.today st rows).ksd .DMF
      ((readAll verify o base.today st rows).ctx base).dmf) ∧
    (k = .PROVIDER_DEATH → Scoped.Uncounted base.today (readAll verify o base.today st rows).ksd .PROVIDER_DEATH
      ((readAll verify o base.today st rows).ctx base).providerDeaths) ∧
    (k = .EXCLUSION → Scoped.Uncounted base.today (readAll verify o base.today st rows).ksd .EXCLUSION
      ((readAll verify o base.today st rows).ctx base).exclusions) ∧
    (k = .ENROLLMENT → Scoped.Uncounted base.today (readAll verify o base.today st rows).ksd .ENROLLMENT
      ((readAll verify o base.today st rows).ctx base).enrollment) := by
  refine ⟨?_, ?_, ?_, ?_⟩ <;> rintro rfl <;> exact uncounted_of_cause hk

/-- Missing, refused, stale or uncounted evidence: the kind's STALE reason on every line, so never ALLOW
    (HUMAN_REVIEW, or HOLD if a certain reason fires); the cause byte names why. -/
theorem uncounted_signed (k : Kind) (hk : (readAll verify o base.today st rows).cause base.today k ≠ .COUNTED)
    (hd : d ∈ (decideSigned verify o st rows base f lines).2.decisions) : stale k ∈ d.reasons ∧ d.outcome ≠ .ALLOW := by
  obtain ⟨seen, l, rfl⟩ := mem_decide hd
  obtain ⟨u1, u2, u3, u4⟩ := Scoped.uncounted_reviews ((readAll verify o base.today st rows).ctx base) seen l
  obtain ⟨v1, v2, v3, v4⟩ := uncounted_slot k hk
  have hs : stale k ∈ (Rules.decideLine ((readAll verify o base.today st rows).ctx base).rules seen l).reasons := by
    cases k
    · exact u1 (v1 rfl)
    · exact u2 (v2 rfl)
    · exact u3 (v3 rfl)
    · exact u4 (v4 rfl)
  exact ⟨hs, Rules.line_complete (Rules.mem_decideLine.1 hs)⟩

/-- C8 carried through: an uncounted DMF never yields its certain HOLD reason (Scoped.uncounted_not_certain). -/
theorem uncounted_not_certain_signed (hk : (readAll verify o base.today st rows).cause base.today .DMF ≠ .COUNTED)
    (hd : d ∈ (decideSigned verify o st rows base f lines).2.decisions) : Reason.MEMBER_DECEASED ∉ d.reasons := by
  obtain ⟨seen, l, rfl⟩ := mem_decide hd
  exact (Scoped.uncounted_not_certain _ seen l).1 ((uncounted_slot .DMF hk).1 rfl)

/-- Absorb, don't bounce: whatever the offer (malformed, refused chain, no facts), every line is decided. -/
theorem decideSigned_total : ((decideSigned verify o st rows base f lines).2.decisions.map (·.line)).Perm lines := by
  simp only [decideSigned, Rules.decideBatchIn]
  rw [Rules.lines_decideAll]
  exact Rules.order_perm _ _

/-! ### Vectors (stub verify `Scoped.vVer`; SnapshotV2's vecG chain on 20261105; each kind's header `Scoped.vHd`
    signed by vecLong and vecLong2, as `Scoped.vCtx`, but all four attached under ONE head by `readAll`).  Mutants:
    COUNTED without `counts` (the stale twin), the ratchet moved without a head (the wrong-keyset twin). -/

def vX {α : Type} (k : Kind) (sc : Scope) (fl : α → List (Nat × Nat)) (s : Snapshot α) : Bytes :=
  SnapshotV2.encode ⟨Scoped.vHd k sc (dom k) fl s, Keyset.vecRecs [SnapshotV2.vecLong, SnapshotV2.vecLong2]⟩
def vO : Offer :=
  ⟨Scoped.vPin, [], Keyset.encode SnapshotV2.vecG, [], some (vX .DMF .IDV Death.fields Scoped.vD4),
    some (vX .PROVIDER_DEATH .IDV Death.fields Scoped.vD4), some (vX .EXCLUSION .ENR Exclusion.fields Scoped.vX4),
    some (vX .ENROLLMENT .ELIG Span.fields Scoped.vE4)⟩
def vR : Rows := ⟨some Scoped.vD4, some Scoped.vD4, some Scoped.vX4, some Scoped.vE4⟩
def vB : Rules.Ctx := { Scoped.vBase with today := 20261105 }
def vRead (o : Offer) (r : Rows) : Read := readAll Scoped.vVer o vB.today SnapshotV2.vecI r
def vCauses (o : Offer) (r : Rows) : List Cause :=
  [.DMF, .PROVIDER_DEATH, .EXCLUSION, .ENROLLMENT].map ((vRead o r).cause vB.today)
def vDec (o : Offer) (r : Rows) : List Rules.Decision :=
  (decideSigned Scoped.vVer o SnapshotV2.vecI r vB [] [Scoped.vL]).2.decisions
/-- Every decision carries reason `x` and none ALLOWs. -/
def vStale (o : Offer) (r : Rows) (x : Reason) : Bool :=
  !(vDec o r).isEmpty && (vDec o r).all fun d => d.reasons.contains x && d.outcome != .ALLOW

#guard [Cause.ABSENT, .COUNTED, .SCOPE, .AGE, .DATE, .CHAIN, .BINDING, .EXPIRED, .FUTURE, .QUORUM, .REVOKED].map
  Cause.byte == [0, 1, 2, 3, 4, 16, 17, 18, 19, 32, 33]
-- ALLOW: all four attached under one head, each carrying that head's digest, all COUNTED; the ratchet advanced
#guard vCauses vO vR == [.COUNTED, .COUNTED, .COUNTED, .COUNTED]
#guard (vDec vO vR).map (·.outcome) == [.ALLOW]
#guard (vRead vO vR).head.isSome && (vRead vO vR).ksd == Keyset.digestOf SnapshotV2.vecG.ks &&
  ((vRead vO vR).dmf.bind (·.toOption)).map (·.keyset) == some (vRead vO vR).ksd &&
  ((vRead vO vR).pd.bind (·.toOption)).map (·.keyset) == some (vRead vO vR).ksd &&
  ((vRead vO vR).ex.bind (·.toOption)).map (·.keyset) == some (vRead vO vR).ksd &&
  ((vRead vO vR).en.bind (·.toOption)).map (·.keyset) == some (vRead vO vR).ksd &&
  (vRead vO vR).to.day == 20261105
-- missing kind (neither rows nor bytes): ABSENT; bytes without rows: BINDING; STALE_ENROLLMENT, never ALLOW
#guard vCauses { vO with en := none } { vR with en := none } == [.COUNTED, .COUNTED, .COUNTED, .ABSENT]
#guard vStale { vO with en := none } { vR with en := none } .STALE_ENROLLMENT
#guard vCauses vO { vR with en := none } == [.COUNTED, .COUNTED, .COUNTED, .BINDING]
#guard vStale vO { vR with en := none } .STALE_ENROLLMENT
-- stale kind: exclusions asOf 20261002 (keys valid from 20261001) are past their 31-day ceiling on 20261105:
-- attached, AGE, STALE_EXCLUSION, never ALLOW
def vXOld : Snapshot Exclusion := { Scoped.vX4 with asOf := 20261002 }
def vOOld : Offer := { vO with ex := some (vX .EXCLUSION .ENR Exclusion.fields vXOld) }
#guard ((vRead vOOld { vR with ex := some vXOld }).ex.bind (·.toOption)).isSome
#guard vCauses vOOld { vR with ex := some vXOld } == [.COUNTED, .COUNTED, .AGE, .COUNTED]
#guard vStale vOOld { vR with ex := some vXOld } .STALE_EXCLUSION
-- revoked-key quorum: the chain to epoch 3 (vecC3 revokes vecLong) is admitted, one employee is left: REVOKED on
-- every kind, all four STALE, never ALLOW
def vORev : Offer := { vO with steps := [(20261105, Keyset.encode SnapshotV2.vecC1),
  (20261105, Keyset.encode SnapshotV2.vecC2), (20261105, Keyset.encode SnapshotV2.vecC3)] }
#guard (vRead vORev vR).head.isSome
#guard vCauses vORev vR == [.REVOKED, .REVOKED, .REVOKED, .REVOKED]
#guard [Reason.STALE_DMF, .STALE_PROVIDER_DEATH, .STALE_EXCLUSION, .STALE_ENROLLMENT].all (vStale vORev vR)
-- wrong-keyset head: the chain offered from another genesis pin admits no head: CHAIN on every kind, ratchet unchanged
def vOPin : Offer := { vO with pin := Scoped.vK }
#guard (vRead vOPin vR).head.isNone && (vRead vOPin vR).to == SnapshotV2.vecI
#guard vCauses vOPin vR == [.CHAIN, .CHAIN, .CHAIN, .CHAIN]
#guard [Reason.STALE_DMF, .STALE_PROVIDER_DEATH, .STALE_EXCLUSION, .STALE_ENROLLMENT].all (vStale vOPin vR)

end BlindLedger.Gate.Consume
