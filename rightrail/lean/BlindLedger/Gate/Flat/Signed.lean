import BlindLedger.Gate.Consume
import BlindLedger.Gate.Flat.Theorems

/-! Signed facts on the flat index (design rrb/designs/agi-k3-consumer-v1.md §6.2).  A batch's four reference feeds
    are tables the store builds once per snapshot (`Feed`: trailer and, per id, at most `capN + 1` facts); the batch
    reads them without their rows.  `readIdx` admits ONE head for the batch day and runs each kind's attach checks on
    the feed's trailer (`SnapshotV2.attachHdr`); it is `Consume.readAll`'s view (`readIdx_eq`).  The feeds the decider
    reads (`signedFeeds`) count a kind usable only if its cause is COUNTED, so an ALLOW carries `allow_signed`'s
    conclusion whatever the history index holds (`allow_signed_idx`), and on an uncapped batch over a faithful index the
    decisions are `Consume.decideSigned`'s (`decideSignedIdx_eq`).  Synthetic, nonpayment, non-PHI, activation=false. -/

namespace BlindLedger.Gate.Rules.Fast

/-- An indexed ALLOW needs all four feeds usable (each kind's STALE reason fires otherwise). -/
theorem Ix.allow_ok {x : Ix} {seen : Std.HashSet Key} {ls : List Line} {d : Decision} (hd : d ∈ x.decideAll seen ls)
    (ha : d.outcome = .ALLOW) : x.dmfOk = true ∧ x.pdOk = true ∧ x.exclOk = true ∧ x.spanOk = true := by
  have mem : ∀ (s : Std.HashSet Key) (ls : List Line), d ∈ x.decideAll s ls → ∃ s l, d = x.decideLine s l := by
    intro s ls
    induction ls generalizing s with
    | nil => intro h; simp [Ix.decideAll] at h
    | cons l ls ih =>
      intro h
      simp only [Ix.decideAll, List.mem_cons] at h
      rcases h with h | h
      · exact ⟨_, _, h⟩
      · exact ih _ h
  obtain ⟨s, l, rfl⟩ := mem seen ls hd
  have hnil : reasons.filter (x.fires s l) = [] := outcomeOf_allow.1 ha
  have hf : ∀ r ∈ reasons, x.fires s l r = false := by
    intro r hr
    cases h : x.fires s l r
    · rfl
    · have hm : r ∈ reasons.filter (x.fires s l) := List.mem_filter.2 ⟨hr, h⟩
      rw [hnil] at hm
      cases hm
  have h1 := hf .STALE_DMF (by simp [reasons])
  have h2 := hf .STALE_PROVIDER_DEATH (by simp [reasons])
  have h3 := hf .STALE_EXCLUSION (by simp [reasons])
  have h4 := hf .STALE_ENROLLMENT (by simp [reasons])
  exact ⟨by simpa [Ix.fires] using h1, by simpa [Ix.fires] using h2, by simpa [Ix.fires] using h3,
    by simpa [Ix.fires] using h4⟩

end BlindLedger.Gate.Rules.Fast

namespace BlindLedger.Gate.Flat

open BlindLedger.Gate.Rules BlindLedger.Gate.Rules.Fast
open BlindLedger.Gate.Consume (Offer Rows Read View KView readAll decideSigned SignedOk dom)
open BlindLedger.Gate.SnapshotV2 (Kind admitBatchHead attachHdr)

/-- One reference snapshot as the store holds it: date, declared count, rows held, rows digest (READ-<kind>/v2),
    whether every row is well formed, and per id its first `capN + 1` facts in row order. -/
structure Feed (α : Type) where
  asOf : Nat
  count : Nat
  rows : Nat
  digest : Option Bytes
  allOk : Bool
  get : Nat → List α

/-- `x` is kind k's table of `s`. -/
def FeedInv {α : Type} (k : Kind) (fl : α → List (Nat × Nat)) (ok : Nat → α → Bool) (key : α → Nat) (x : Feed α)
    (s : Snapshot α) : Prop :=
  x.asOf = s.asOf ∧ x.count = s.count ∧ x.rows = s.entries.length ∧
    x.digest = SnapshotV2.rowsDigest (dom k) k.byte fl s ∧ x.allOk = s.entries.all (ok s.asOf) ∧
    ∀ i, x.get i = (s.entries.filter (key · == i)).take (capN + 1)

structure FeedSet where
  dmf : Option (Feed Death)
  pd : Option (Feed Death)
  ex : Option (Feed Exclusion)
  en : Option (Feed Span)

/-- Each slot is that kind's table of the frame's rows, and present exactly when they are. -/
def FeedSetInv (fx : FeedSet) (rows : Rows) : Prop :=
  Option.Rel (FeedInv .DMF Death.fields okDeath (·.id)) fx.dmf rows.dmf ∧
  Option.Rel (FeedInv .PROVIDER_DEATH Death.fields okDeath (·.id)) fx.pd rows.pd ∧
  Option.Rel (FeedInv .EXCLUSION Exclusion.fields okExclusion (·.id)) fx.ex rows.ex ∧
  Option.Rel (FeedInv .ENROLLMENT Span.fields okSpan (·.member)) fx.en rows.en

/-- `Consume.one` on a feed: the attach checks with the trailer in place of the rows. -/
def oneIdx {α : Type} (verify : Bytes → Bytes → Bytes → Bool) (H : Option SnapshotV2.Head) (k : Kind) :
    Option (Feed α) → Option Bytes → Option (Except SnapshotV2.Refusal (Scoped.Fact Unit))
  | some t, some x => some (H.elim (.error .binding) fun H => attachHdr verify H.day H.ks k.byte t.asOf t.count t.digest x
      fun v kd => ⟨⟨t.asOf, t.count, []⟩, kd, v.head.scope, v.head.validUntil, H.day, Keyset.digestOf H.ks⟩)
  | _, _ => none

/-- `Consume.readAll`'s view, read from the feeds: one head admitted for the batch day, each kind's checks. -/
def readIdx (verify : Bytes → Bytes → Bytes → Bool) (o : Offer) (now : Nat) (st : Keyset.Ratchet) (fx : FeedSet) :
    View :=
  let a := admitBatchHead verify o.pin now st o.g o.steps
  let H := a.map (·.1)
  ⟨(a.map (·.2)).getD st, H.isSome,
    KView.of H now .DMF (o.dmf.isSome || fx.dmf.isSome) o.dmf (oneIdx verify H .DMF fx.dmf o.dmf),
    KView.of H now .PROVIDER_DEATH (o.pd.isSome || fx.pd.isSome) o.pd (oneIdx verify H .PROVIDER_DEATH fx.pd o.pd),
    KView.of H now .EXCLUSION (o.ex.isSome || fx.ex.isSome) o.ex (oneIdx verify H .EXCLUSION fx.ex o.ex),
    KView.of H now .ENROLLMENT (o.en.isSome || fx.en.isSome) o.en (oneIdx verify H .ENROLLMENT fx.en o.en)⟩

/-- `Rules.usable` on a feed's trailer. -/
def Feed.usable {α : Type} (today maxAge : Nat) : Option (Feed α) → Bool
  | none => false
  | some x => validDate today && validDate x.asOf && x.asOf ≤ today && dayNum today ≤ dayNum x.asOf + maxAge &&
      x.rows == x.count && 0 < x.count && x.allOk

/-- An attached feed's facts by id; none for a kind not attached. -/
def Feed.byId {α : Type} (att : Bool) : Option (Feed α) → Nat → List α
  | some x, i => if att then x.get i else []
  | none, _ => []

/-- What the decider reads: present = attached, usable = COUNTED and usable on the trailer. -/
def signedFeeds (v : View) (fx : FeedSet) (today : Nat) : Feeds :=
  { dmfSome := v.dmf.attached, pdSome := v.pd.attached, exclSome := v.ex.attached, spanSome := v.en.attached,
    dmfOk := v.dmf.cause == .COUNTED && Feed.usable today 90 fx.dmf,
    pdOk := v.pd.cause == .COUNTED && Feed.usable today 90 fx.pd,
    exclOk := v.ex.cause == .COUNTED && Feed.usable today 31 fx.ex,
    spanOk := v.en.cause == .COUNTED && Feed.usable today 7 fx.en,
    dmf := Feed.byId v.dmf.attached fx.dmf, pdeath := Feed.byId v.pd.attached fx.pd,
    excl := Feed.byId v.ex.attached fx.ex, span := Feed.byId v.en.attached fx.en }

/-- A batch on signed feeds: the read's view, then the indexed decision on the feeds it makes usable. -/
def decideSignedIdx (verify : Bytes → Bytes → Bytes → Bool) (s : St) (o : Offer) (st : Keyset.Ratchet) (fx : FeedSet)
    (today : Nat) (redo : List Nat) (byp lim : List (Nat × Nat)) (f : List Nat) (b : List Line) : View × List Decision × List Line × List Line :=
  let v := readIdx verify o today st fx
  (v, decideBatchIdx s ⟨today, redo, signedFeeds v fx today, byp, lim⟩ f b)

/-- Two feed views the decider cannot tell apart: it reads per id at most `capN + 1` facts. -/
def Feeds.Same (fd fd' : Feeds) : Prop :=
  fd.dmfSome = fd'.dmfSome ∧ fd.pdSome = fd'.pdSome ∧ fd.exclSome = fd'.exclSome ∧ fd.spanSome = fd'.spanSome ∧
    fd.dmfOk = fd'.dmfOk ∧ fd.pdOk = fd'.pdOk ∧ fd.exclOk = fd'.exclOk ∧ fd.spanOk = fd'.spanOk ∧
    (∀ i, (fd.dmf i).take (capN + 1) = (fd'.dmf i).take (capN + 1)) ∧
    (∀ i, (fd.pdeath i).take (capN + 1) = (fd'.pdeath i).take (capN + 1)) ∧
    (∀ i, (fd.excl i).take (capN + 1) = (fd'.excl i).take (capN + 1)) ∧
    (∀ i, (fd.span i).take (capN + 1) = (fd'.span i).take (capN + 1))

variable {verify : Bytes → Bytes → Bytes → Bool} {o : Offer} {st : Keyset.Ratchet} {rows : Rows} {fx : FeedSet}
  {now today : Nat} {redo f : List Nat} {byp : List (Nat × Nat)} {b : List Line} {s : St} {c : Ctx} {rel unr : Snapshot Line} {H : Bytes → Bytes}
  {d : Decision}

/-! ### Proof helpers -/

/-- The feeds of a rules context, as `FCtxInv` states them. -/
private def specFeeds (c : Ctx) : Feeds :=
  { dmfSome := c.dmf.isSome, pdSome := c.providerDeaths.isSome, exclSome := c.exclusions.isSome,
    spanSome := c.enrollment.isSome, dmfOk := usable c.today 90 okDeath c.dmf,
    pdOk := usable c.today 90 okDeath c.providerDeaths, exclOk := usable c.today 31 okExclusion c.exclusions,
    spanOk := usable c.today 7 okSpan c.enrollment, dmf := fun i => (entries c.dmf).filter (·.id == i),
    pdeath := fun i => (entries c.providerDeaths).filter (·.id == i),
    excl := fun i => (entries c.exclusions).filter (·.id == i),
    span := fun i => (entries c.enrollment).filter (·.member == i) }

private theorem specFeeds_inv (c : Ctx) : FCtxInv ⟨c.today, c.redo, specFeeds c, c.byp, c.lim⟩ c :=
  ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, fun _ => rfl, fun _ => rfl, fun _ => rfl, fun _ => rfl, rfl, rfl⟩

private theorem take_facts {α : Type} {xs ys : List α} (h : xs.take (capN + 1) = ys.take (capN + 1)) :
    facts xs = facts ys ∧ feedOver xs = feedOver ys := by
  constructor
  · have := congrArg (List.take capN) h
    simpa [facts, List.take_take, Nat.min_eq_left (Nat.le_succ capN), Nat.min_eq_right (Nat.le_succ capN)] using this
  · have := congrArg List.length h
    simp only [List.length_take, Nat.min_def] at this
    simp only [feedOver, decide_eq_decide]
    split at this <;> split at this <;> omega

private theorem over_same {fd fd' : Feeds} (h : Feeds.Same fd fd') :
    (∀ i, feedOver (fd.dmf i) = feedOver (fd'.dmf i)) ∧ (∀ i, feedOver (fd.pdeath i) = feedOver (fd'.pdeath i)) ∧
      (∀ i, feedOver (fd.excl i) = feedOver (fd'.excl i)) ∧ (∀ i, feedOver (fd.span i) = feedOver (fd'.span i)) := by
  obtain ⟨-, -, -, -, -, -, -, -, f1, f2, f3, f4⟩ := h
  exact ⟨fun i => (take_facts (f1 i)).2, fun i => (take_facts (f2 i)).2, fun i => (take_facts (f3 i)).2,
    fun i => (take_facts (f4 i)).2⟩

private theorem uncapped_same {fe : Fetched} {fd fd' : Feeds} (h : Feeds.Same fd fd') (hb : Uncapped fe fd b) :
    Uncapped fe fd' b := by
  obtain ⟨o1, o2, o3, o4⟩ := over_same h
  intro l hl
  have := hb l hl
  simpa only [capped, hotKeys, feedCapped, o1, o2, o3, o4] using this

private theorem one_rows {α : Type} {Hd : Option SnapshotV2.Head} {k : Kind} {fl : α → List (Nat × Nat)}
    {so : Option (Snapshot α)} {xo : Option Bytes} {r : SnapshotV2.Signed α}
    (h : Consume.one verify Hd k fl so xo = some (.ok r)) : so = some r.toSnapshot := by
  rcases so with _ | s <;> rcases xo with _ | x <;> simp [Consume.one] at h
  rcases Hd with _ | H <;> simp [Option.elim] at h
  rw [SnapshotV2.attachAt_rows h]

/-- One kind: the signed feed agrees with the feed of `Scoped.present` on presence, usability and facts. -/
private theorem same_slot {α : Type} {k : Kind} {fl : α → List (Nat × Nat)} {okf : Nat → α → Bool} {key : α → Nat}
    {maxAge : Nat} {Hd : Option SnapshotV2.Head} {t : Nat} {lone : Bool} {x : Option Bytes}
    {sl : Option (Except SnapshotV2.Refusal (SnapshotV2.Signed α))} {ft : Option (Feed α)} {so : Option (Snapshot α)}
    (hR : Option.Rel (FeedInv k fl okf key) ft so) (hs : ∀ r, sl = some (.ok r) → so = some r.toSnapshot) :
    (KView.of Hd t k lone x (sl.map (·.map Consume.bare))).attached = (Scoped.present t
        ((Hd.map (Keyset.digestOf ·.ks)).getD zeroDigest) k ((sl.bind (·.toOption)).map Scoped.Fact.ofSigned)).isSome ∧
      ((KView.of Hd t k lone x (sl.map (·.map Consume.bare))).cause == .COUNTED && Feed.usable t maxAge ft) =
        usable t maxAge okf (Scoped.present t ((Hd.map (Keyset.digestOf ·.ks)).getD zeroDigest) k
          ((sl.bind (·.toOption)).map Scoped.Fact.ofSigned)) ∧
      ∀ i, (Feed.byId (KView.of Hd t k lone x (sl.map (·.map Consume.bare))).attached ft i).take (capN + 1) =
        ((entries (Scoped.present t ((Hd.map (Keyset.digestOf ·.ks)).getD zeroDigest) k
          ((sl.bind (·.toOption)).map Scoped.Fact.ofSigned))).filter (key · == i)).take (capN + 1) := by
  have hc := Consume.slotCause_counted (H := Hd) (today := t) (ksd := (Hd.map (Keyset.digestOf ·.ks)).getD zeroDigest)
    (k := k) (lone := lone) (x := x) (s := sl)
  rcases sl with _ | _ | r
  · have hn : (KView.of Hd t k lone x none).cause ≠ .COUNTED := fun h => by simpa using hc.1 h
    refine ⟨rfl, ?_, fun i => ?_⟩
    · simp [Scoped.present, usable]
      exact fun h => absurd h hn
    · cases ft <;> simp [KView.of, Feed.byId, Scoped.present, entries]
  · have hn : (KView.of Hd t k lone x (some (.error ‹_›))).cause ≠ .COUNTED := fun h => by simpa using hc.1 h
    refine ⟨rfl, ?_, fun i => ?_⟩
    · simp [Scoped.present, usable, Except.toOption]
      exact fun h => absurd h hn
    · cases ft <;> simp [KView.of, Feed.byId, Scoped.present, entries, Except.toOption, Except.map]
  · obtain ⟨fd, s, hinv⟩ : ∃ fd s, ft = some fd ∧ so = some s ∧ FeedInv k fl okf key fd s := by
      cases hR with
      | none => cases hs r rfl
      | some h => exact ⟨_, _, rfl, rfl, h⟩
    obtain ⟨rfl, rfl, e1, e2, e3, -, e5, e6⟩ := hinv
    obtain rfl : s = r.toSnapshot := Option.some.inj (hs r rfl)
    have hent : entries (Scoped.present t ((Hd.map (Keyset.digestOf ·.ks)).getD zeroDigest) k
        (((some (Except.ok r) : Option (Except SnapshotV2.Refusal (SnapshotV2.Signed α))).bind (·.toOption)).map Scoped.Fact.ofSigned)) = r.toSnapshot.entries := by
      simp only [Option.bind, Except.toOption, Option.map_some, Scoped.present, entries]
      split <;> rfl
    refine ⟨rfl, ?_, fun i => ?_⟩
    · by_cases hk : Scoped.counts t ((Hd.map (Keyset.digestOf ·.ks)).getD zeroDigest) k (Scoped.Fact.ofSigned r) = true
      · have hq : (KView.of Hd t k lone x ((some (.ok r) : Option (Except SnapshotV2.Refusal (SnapshotV2.Signed α))).map
            (·.map Consume.bare))).cause = .COUNTED := hc.2 ⟨r, rfl, hk⟩
        rw [hq]
        simp only [beq_self_eq_true, Bool.true_and, Option.bind, Except.toOption, Option.map_some, Scoped.present, hk,
          if_true, Feed.usable, usable, e1, e2, e3, e5]
        (try rfl)
      · have hn : ((KView.of Hd t k lone x ((some (.ok r) : Option (Except SnapshotV2.Refusal (SnapshotV2.Signed α))).map
            (·.map Consume.bare))).cause == .COUNTED) = false :=
          beq_eq_false_iff_ne.2 fun h => by obtain ⟨_, h1, h2⟩ := hc.1 h; cases h1; exact hk h2
        have hv0 : validDate 0 = false := by decide
        rw [hn]
        simp [Option.bind, Except.toOption, Scoped.present, hk, usable, hv0]
    · rw [hent]
      simp only [KView.of, Feed.byId, Option.map_some, Except.map, ↓reduceIte, e6,
        List.take_take, Nat.min_self]
      (try rfl)

private theorem same_all (hx : FeedSetInv fx rows) :
    Feeds.Same (signedFeeds ((readAll verify o c.today st rows).view c.today) fx c.today)
      (specFeeds ((readAll verify o c.today st rows).ctx c).rules) := by
  obtain ⟨x1, x2, x3, x4⟩ := hx
  have d1 := same_slot (Hd := (readAll verify o c.today st rows).head) (t := c.today) (maxAge := 90)
    (lone := o.dmf.isSome || rows.dmf.isSome) (x := o.dmf) (sl := (readAll verify o c.today st rows).dmf) x1
    fun _ h => one_rows (verify := verify) (Hd := (readAll verify o c.today st rows).head) (k := .DMF)
      (fl := Death.fields) (xo := o.dmf) h
  have d2 := same_slot (Hd := (readAll verify o c.today st rows).head) (t := c.today) (maxAge := 90)
    (lone := o.pd.isSome || rows.pd.isSome) (x := o.pd) (sl := (readAll verify o c.today st rows).pd) x2
    fun _ h => one_rows (verify := verify) (Hd := (readAll verify o c.today st rows).head) (k := .PROVIDER_DEATH)
      (fl := Death.fields) (xo := o.pd) h
  have d3 := same_slot (Hd := (readAll verify o c.today st rows).head) (t := c.today) (maxAge := 31)
    (lone := o.ex.isSome || rows.ex.isSome) (x := o.ex) (sl := (readAll verify o c.today st rows).ex) x3
    fun _ h => one_rows (verify := verify) (Hd := (readAll verify o c.today st rows).head) (k := .EXCLUSION)
      (fl := Exclusion.fields) (xo := o.ex) h
  have d4 := same_slot (Hd := (readAll verify o c.today st rows).head) (t := c.today) (maxAge := 7)
    (lone := o.en.isSome || rows.en.isSome) (x := o.en) (sl := (readAll verify o c.today st rows).en) x4
    fun _ h => one_rows (verify := verify) (Hd := (readAll verify o c.today st rows).head) (k := .ENROLLMENT)
      (fl := Span.fields) (xo := o.en) h
  exact ⟨d1.1, d2.1, d3.1, d4.1, d1.2.1, d2.2.1, d3.2.1, d4.2.1, d1.2.2, d2.2.2, d3.2.2, d4.2.2⟩

private theorem oneIdx_eq {α : Type} {k : Kind} {fl : α → List (Nat × Nat)} {okf : Nat → α → Bool} {key : α → Nat}
    {Hd : Option SnapshotV2.Head} {ft : Option (Feed α)} {so : Option (Snapshot α)} {xo : Option Bytes}
    (h : Option.Rel (FeedInv k fl okf key) ft so) :
    oneIdx verify Hd k ft xo = (Consume.one verify Hd k fl so xo).map (·.map Consume.bare) ∧
      ft.isSome = so.isSome := by
  cases h with
  | none => exact ⟨by cases xo <;> rfl, rfl⟩
  | @some t s hinv =>
    obtain ⟨e1, e2, -, e4, -, -⟩ := hinv
    refine ⟨?_, rfl⟩
    cases xo with
    | none => rfl
    | some x =>
      cases Hd with
      | none => rfl
      | some H =>
        simp only [oneIdx, Consume.one, Option.elim, Option.map_some]
        congr 1
        have hc : (SnapshotV2.attachAt verify H (dom k) k.byte fl s x).map Consume.bare =
            ((SnapshotV2.attachAt verify H (dom k) k.byte fl s x).map fun r =>
              (r.toSnapshot, r.kind, r.scope, r.validUntil, r.day, r.keyset)).map fun p =>
                (⟨⟨p.1.asOf, p.1.count, []⟩, p.2.1, p.2.2.1, p.2.2.2.1, p.2.2.2.2.1, p.2.2.2.2.2⟩ : Scoped.Fact Unit) := by
          cases SnapshotV2.attachAt verify H (dom k) k.byte fl s x <;> rfl
        rw [hc, SnapshotV2.attachAt_hdr, SnapshotV2.attachHdr_map, e1, e2, e4]

/-! ### Statements -/

/-- The signed read set commutes with carrying the history sets (it sets only the four reference slots). -/
theorem rules_carried {r : Read} : (r.ctx (carried c rel unr)).rules = carried (r.ctx c).rules rel unr := rfl

/-- The feeds' read is the rows' read: same head, ratchet and, per kind, attach result, header digest and cause. -/
theorem readIdx_eq (hx : FeedSetInv fx rows) : readIdx verify o now st fx = (readAll verify o now st rows).view now := by
  obtain ⟨x1, x2, x3, x4⟩ := hx
  simp only [readIdx, Read.view, readAll, (oneIdx_eq (verify := verify) (Hd := none) (xo := none) x1).2,
    (oneIdx_eq (verify := verify) (Hd := none) (xo := none) x2).2, (oneIdx_eq (verify := verify) (Hd := none) (xo := none) x3).2,
    (oneIdx_eq (verify := verify) (Hd := none) (xo := none) x4).2]
  rw [(oneIdx_eq x1).1, (oneIdx_eq x2).1, (oneIdx_eq x3).1, (oneIdx_eq x4).1]

/-- The decider and its work count read the feeds only up to `capN + 1` facts per id. -/
theorem fetched_feeds {a u : Head} {fe : Fetched} {fc fc' : FCtx} (h : Feeds.Same fc.feeds fc'.feeds)
    (ht : fc.today = fc'.today) (hr : fc.redo = fc'.redo) (hy : fc.byp = fc'.byp)
    (hl : fc.lim = fc'.lim) :
    decideFetched a u fe fc f b = decideFetched a u fe fc' f b ∧ work fe fc.feeds b = work fe fc'.feeds b := by
  obtain ⟨t, r, fd, y, l⟩ := fc
  obtain ⟨t', r', fd', y', l'⟩ := fc'
  dsimp only at h ht hr hy hl ⊢
  subst ht hr hy hl
  obtain ⟨o1, o2, o3, o4⟩ := over_same h
  obtain ⟨e1, e2, e3, e4, e5, e6, e7, e8, f1, f2, f3, f4⟩ := h
  have g1 : ∀ i, facts (fd.dmf i) = facts (fd'.dmf i) := fun i => (take_facts (f1 i)).1
  have g2 : ∀ i, facts (fd.pdeath i) = facts (fd'.pdeath i) := fun i => (take_facts (f2 i)).1
  have g3 : ∀ i, facts (fd.excl i) = facts (fd'.excl i) := fun i => (take_facts (f3 i)).1
  have g4 : ∀ i, facts (fd.span i) = facts (fd'.span i) := fun i => (take_facts (f4 i)).1
  constructor
  · have hx : localIx a u fe (localRows fe.rel) (localRows fe.unr) ⟨t, r, fd, y, l⟩ b =
        localIx a u fe (localRows fe.rel) (localRows fe.unr) ⟨t, r, fd', y, l⟩ b := by
      simp only [localIx, idMap, e1, e2, e3, e4, e5, e6, e7, e8, g1, g2, g3, g4]
    have hh : hotKeys fe fd b = hotKeys fe fd' b := by simp only [hotKeys, o4]
    have hc : cappedWith (idCapped fe) (hotKeys fe fd b) fd = cappedWith (idCapped fe) (hotKeys fe fd' b) fd' :=
      funext fun l => by simp only [hh, cappedWith, feedCapped, o1, o2, o3, o4]
    simp only [decideFetched]
    rw [hx, hc]
  · simp only [work, factWork, g1, g2, g3, g4]

/-- On a batch no cap touches, over an index of the carried sets and tables of the frame's rows, the signed flat batch
    is `Consume.decideSigned` on the carried state: its view, its decisions, the rows it appends. -/
theorem decideSignedIdx_eq (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr) (hx : FeedSetInv fx rows)
    (hb : Uncapped (fetch s c.redo b) (signedFeeds (readIdx verify o c.today st fx) fx c.today) b) :
    decideSignedIdx verify s o st fx c.today c.redo c.byp c.lim f b =
      let r := decideSigned verify o st rows (carried c rel unr) f b
      (r.1.view c.today, r.2.decisions, batchFresh (r.1.ctx (carried c rel unr)).rules r.2) := by
  have hv := readIdx_eq (verify := verify) (o := o) (now := c.today) (st := st) hx
  have hS := same_all (verify := verify) (o := o) (st := st) (c := c) hx
  rw [hv] at hb
  have hd := decideBatchIdx_eq H s ⟨c.today, c.redo, specFeeds ((readAll verify o c.today st rows).ctx c).rules, c.byp, c.lim⟩
    ((readAll verify o c.today st rows).ctx c).rules rel unr f b hr hu (specFeeds_inv ((readAll verify o c.today st rows).ctx c).rules) (uncapped_same hS hb)
  have he : decideBatchIdx s ⟨c.today, c.redo, signedFeeds ((readAll verify o c.today st rows).view c.today) fx c.today, c.byp, c.lim⟩
      f b = decideBatchIdx s ⟨c.today, c.redo, specFeeds ((readAll verify o c.today st rows).ctx c).rules, c.byp, c.lim⟩ f b := by
    unfold decideBatchIdx
    exact (fetched_feeds (fc := ⟨c.today, c.redo, _, c.byp, c.lim⟩) (fc' := ⟨c.today, c.redo, _, c.byp, c.lim⟩) hS rfl rfl rfl rfl).1
  have ht : (carried c rel unr).today = c.today := rfl
  simp only [decideSignedIdx, decideSigned, ht, hv, he, hd, rules_carried]

/-- MONEY: any history index contents, capped or not.  No line is ALLOW unless `allow_signed`'s conclusion holds for
    the read of the frame's rows, with the ratchet the batch persists. -/
theorem allow_signed_idx (hx : FeedSetInv fx rows) (hd : d ∈ (decideSignedIdx verify s o st fx today redo byp lim f b).2.1)
    (ha : d.outcome = .ALLOW) : SignedOk verify o today st rows (decideSignedIdx verify s o st fx today redo byp lim f b).1.to := by
  simp only [decideSignedIdx, decideBatchIdx, decideFetched, List.mem_map] at hd ⊢
  obtain ⟨d0, hd0, rfl⟩ := hd
  split at ha
  · rw [(OnepIndex.capD_rel d0).1] at ha
    cases ha
  · obtain ⟨o1, o2, o3, o4⟩ := Ix.allow_ok hd0 ha
    simp only [localIx, signedFeeds, Bool.and_eq_true, beq_iff_eq] at o1 o2 o3 o4
    rw [readIdx_eq hx] at o1 o2 o3 o4 ⊢
    exact Consume.counted_good fun k => by
      cases k <;> first | exact o1.1 | exact o2.1 | exact o3.1 | exact o4.1

/-! ### Vectors (`Consume`'s ALLOW frame as feeds).  Mutants and the vector that kills each: `Ok` ignoring `counted`
    (`signedFeeds` without the cause test): the bad-digest vector; `take capN` for `take (capN + 1)` in `vFeed`: the
    1,025-fact vector; the count unchecked (`x.rows == x.count` dropped from `Feed.usable`): the short-count vector. -/

/-- Kind k's table of `s`, as the store builds it (`FeedInv`). -/
def vFeed {α : Type} (k : Kind) (fl : α → List (Nat × Nat)) (ok : Nat → α → Bool) (key : α → Nat) (s : Snapshot α) :
    Feed α :=
  ⟨s.asOf, s.count, s.entries.length, SnapshotV2.rowsDigest (dom k) k.byte fl s, s.entries.all (ok s.asOf),
    fun i => (s.entries.filter (key · == i)).take (capN + 1)⟩
def vFx (dm : Snapshot Death := Scoped.vD4) : FeedSet :=
  ⟨some (vFeed .DMF Death.fields okDeath (·.id) dm), some (vFeed .PROVIDER_DEATH Death.fields okDeath (·.id) Scoped.vD4),
    some (vFeed .EXCLUSION Exclusion.fields okExclusion (·.id) Scoped.vX4),
    some (vFeed .ENROLLMENT Span.fields okSpan (·.member) Scoped.vE4)⟩
def vSt : St := ⟨⟨⟨20261001, 0, 0⟩, fun _ => Entry.empty, fun _ => 0⟩, ⟨⟨20261001, 0, 0⟩, fun _ => Entry.empty, fun _ => 0⟩⟩
def vIdx (o : Offer) (fx : FeedSet) : View × List Decision × List Line × List Line :=
  decideSignedIdx Scoped.vVer vSt o SnapshotV2.vecI fx Consume.vB.today [] [] [] [] [Scoped.vL]
def vKinds (v : View) : List KView := [v.dmf, v.pd, v.ex, v.en]
def vOut (ds : List Decision) : List (Outcome × List Reason) := ds.map fun d => (d.outcome, d.reasons)
/-- The feeds' read and decisions are the rows' for DMF rows `dm` (offer `o`). -/
def vSame (o : Offer) (dm : Snapshot Death) : Bool :=
  vKinds (vIdx o (vFx dm)).1 == vKinds ((readAll Scoped.vVer o Consume.vB.today SnapshotV2.vecI
      { Consume.vR with dmf := some dm }).view Consume.vB.today) &&
    vOut (vIdx o (vFx dm)).2.1 == vOut (Consume.vDec o { Consume.vR with dmf := some dm })

-- feed read = row read: ALLOW, all four counted
#guard vSame Consume.vO Scoped.vD4 && vOut (vIdx Consume.vO (vFx)).2.1 == [(.ALLOW, [])]
#guard vKinds (vIdx Consume.vO (vFx)).1 |>.all (·.cause == .COUNTED)
-- a bad digest (rows other than the signed ones) is BINDING and STALE_DMF, as for rows
def vBad : Snapshot Death := { Scoped.vD4 with entries := [⟨99, 20200102⟩] }
#guard vSame Consume.vO vBad && (vKinds (vIdx Consume.vO (vFx vBad)).1).map (·.cause) == [.BINDING, .COUNTED, .COUNTED, .COUNTED]
#guard (vIdx Consume.vO (vFx vBad)).2.1.all fun d => d.reasons.contains .STALE_DMF && d.outcome != .ALLOW
-- a count the rows do not meet (signed as it is): attached and COUNTED, but unusable, STALE_DMF, as for rows
def vShort : Snapshot Death := { Scoped.vD4 with count := 2 }
def vOShort : Offer := { Consume.vO with dmf := some (Consume.vX .DMF .IDV Death.fields vShort) }
#guard vSame vOShort vShort && (vIdx vOShort (vFx vShort)).2.1.all fun d => d.reasons.contains .STALE_DMF
-- 1,025 facts for the member: POSTING_CAP, HOLD (1,024 are within the cap)
def vBig (n : Nat) : Snapshot Death := ⟨20261104, n, List.replicate n ⟨7, 20200101⟩⟩
def vOBig (n : Nat) : Offer := { Consume.vO with dmf := some (Consume.vX .DMF .IDV Death.fields (vBig n)) }
#guard (vIdx (vOBig 1025) (vFx (vBig 1025))).2.1.all fun d => d.reasons.contains .POSTING_CAP && d.outcome == .HOLD
#guard (vIdx (vOBig 1024) (vFx (vBig 1024))).2.1.all fun d => !d.reasons.contains .POSTING_CAP

end BlindLedger.Gate.Flat
