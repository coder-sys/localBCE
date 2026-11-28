import BlindLedger.Gate.Flat.Theorems
import BlindLedger.Gate.Flat.Worker
import BlindLedger.Gate.Rules.AnswerEq

/-! What each `RULES_PAY` line of a flat commit says (`Worker.commitFlat`).  The worker prints, for payment `p`,
    `Run.leafOutcome (x.payOutcome ds) unfit p` and `Run.leafReasons ds unfit p`, with `ds` the decisions of
    `decideFetched` and `x` the index it decides on (`localIx` over the fetched rows), on the feeds `Worker.feedsOf`
    makes of the pinned context.  `pay_line`: on a batch no cap touches, over an index faithful to the released and
    unresolved snapshots, that outcome is the Spec's `payOutcome` for `p` and those reasons are the reason codes of the
    Spec's decided lines of `p`, each once, in increasing order.  `pay_capped`: a payment with a capped line is HOLD
    in any batch.  `leaf_allow_fresh`: a payment is ALLOW only when every fact the rules read is present and fresh at
    the batch's clock (`Fresh`).  Synthetic, nonpayment, non-PHI, activation=false. -/

namespace BlindLedger.Gate.Flat

open BlindLedger.Gate.Rules BlindLedger.Gate.Rules.Fast
open Std (HashMap)

private theorem group_getD {α : Type} (k : α → Nat) : ∀ (xs : List α) (i : Nat),
    (xs.foldr (fun x m => m.insert (k x) (x :: m.getD (k x) [])) (∅ : HashMap Nat (List α))).getD i [] =
      xs.filter (k · == i)
  | [], i => by simp
  | x :: xs, i => by
    simp only [List.foldr_cons, Std.HashMap.getD_insert, group_getD k xs, List.filter_cons]
    by_cases h : k x = i
    · subst h; simp
    · simp [h]

/-- The worker's feeds are the pinned context's, as `FCtxInv` states them. -/
theorem feedsOf_inv (c : Ctx) : FCtxInv ⟨c.today, c.redo, Worker.feedsOf c, c.byp, c.lim⟩ c :=
  ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, group_getD (fun x : Death => x.id) (entries c.dmf),
    group_getD (fun x : Death => x.id) (entries c.providerDeaths),
    group_getD (fun x : Exclusion => x.id) (entries c.exclusions),
    group_getD (fun x : Span => x.member) (entries c.enrollment), rfl, rfl⟩

private theorem fetched_lines (hr hu : Head) (fe : Fetched) (fc : FCtx) (f : List Nat) (b : List Line) :
    ∀ d ∈ (decideFetched hr hu fe fc f b).1, d.line ∈ b := by
  intro d hd
  simp only [decideFetched, List.mem_map] at hd
  obtain ⟨d0, hd0, rfl⟩ := hd
  split <;> exact order_mem _ (decideAll_line _ _ _ d0 hd0)

private theorem strict_eraseDups : ∀ (n : Nat) (l : List String), l.length ≤ n →
    l.Pairwise (fun a b => (decide (a < b) || a == b) = true) → l.eraseDups.Pairwise (· < ·)
  | _, [], _, _ => List.Pairwise.nil
  | 0, _ :: _, hn, _ => absurd hn (by simp)
  | n + 1, a :: as, hn, h => by
    rw [List.eraseDups_cons]
    have h' := List.pairwise_cons.mp h
    refine List.pairwise_cons.mpr ⟨fun x hx => ?_, strict_eraseDups n _
      (Nat.le_trans (List.length_filter_le _ _) (by simp at hn; omega)) (h'.2.sublist List.filter_sublist)⟩
    obtain ⟨hx1, hx2⟩ := List.mem_filter.mp (List.mem_eraseDups.mp hx)
    have hle := h'.1 x hx1
    simp only [Bool.or_eq_true, decide_eq_true_eq, beq_iff_eq] at hle
    simp at hx2
    rcases hle with hle | hle
    · exact hle
    · exact absurd hle.symm hx2

/-- The reason codes a token carries (`Run.leafReasons`): `-` or the comma-joined list `rs`, strictly increasing (so
    each code once); for a payment with an unfit line just UNENCODABLE_PAYMENT, else exactly the names of the reasons
    of the payment's decided lines. -/
theorem leafReasons_codes (ds : List Decision) (u : Nat → Bool) (p : Nat) :
    ∃ rs : List String, Run.leafReasons ds u p = (if rs.isEmpty then "-" else ",".intercalate rs) ∧
      rs.Pairwise (· < ·) ∧ (u p = true → rs = ["UNENCODABLE_PAYMENT"]) ∧
      (u p = false → ∀ r, r ∈ rs ↔ ∃ d ∈ ds, d.line.pay = p ∧ ∃ y ∈ d.reasons, Run.name y = r) := by
  cases hu : u p
  · let xs := (ds.filter (·.line.pay == p)).flatMap fun d => d.reasons.map Run.name
    have hs : (Run.sorted xs).Pairwise (fun a b => (decide (a < b) || a == b) = true) := by
      refine List.pairwise_mergeSort (fun a b c h1 h2 => ?_) (fun a b => ?_) xs
      · simp only [Bool.or_eq_true, decide_eq_true_eq, beq_iff_eq] at h1 h2 ⊢
        rcases h1 with h1 | rfl <;> rcases h2 with h2 | rfl
        · exact Or.inl (String.lt_trans h1 h2)
        · exact Or.inl h1
        · exact Or.inl h2
        · exact Or.inr rfl
      · simp only [Bool.or_eq_true, decide_eq_true_eq, beq_iff_eq]
        rcases String.le_total a b with h | h
        · by_cases e : a = b
          · exact Or.inl (Or.inr e)
          · exact Or.inl (Or.inl (Std.lt_of_le_of_ne h e))
        · by_cases e : b = a
          · exact Or.inr (Or.inr e)
          · exact Or.inr (Or.inl (Std.lt_of_le_of_ne h e))
    refine ⟨(Run.sorted xs).eraseDups, by simp [Run.leafReasons, hu, xs], strict_eraseDups _ _ (Nat.le_refl _) hs,
      by simp, fun _ r => ?_⟩
    rw [List.mem_eraseDups, Run.sorted, (List.mergeSort_perm _ _).mem_iff]
    simp only [xs, List.mem_flatMap, List.mem_filter, List.mem_map, beq_iff_eq]
    constructor
    · rintro ⟨d, ⟨hd, hp⟩, y, hy, rfl⟩; exact ⟨d, hd, hp, y, hy, rfl⟩
    · rintro ⟨d, hd, hp, y, hy, rfl⟩; exact ⟨d, ⟨hd, hp⟩, y, hy, rfl⟩
  · exact ⟨["UNENCODABLE_PAYMENT"], by simp [Run.leafReasons, hu], by simp, fun _ => rfl, fun h => by simp at h⟩

/-- On a batch no cap touches, over an index faithful to `rel` and `unr`, the worker's decisions are the Spec's and its
    payment outcome is the Spec's `payOutcome`. -/
private theorem pay_eq (H : Bytes → Bytes) (s : St) (c : Ctx) (rel unr : Snapshot Line) (f : List Nat) (b : List Line)
    (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr) (hb : Uncapped (fetch s c.redo b) (Worker.feedsOf c) b) :
    let fc : FCtx := ⟨c.today, c.redo, Worker.feedsOf c, c.byp, c.lim⟩
    let fe := fetch s fc.redo b
    let ds := (decideFetched s.rel.head s.unr.head fe fc f b).1
    let x := localIx s.rel.head s.unr.head fe (localRows fe.rel) (localRows fe.unr) fc b
    let spec := (decideBatchIn (carried c rel unr) f b).decisions
    ds = spec ∧ x.payOutcome ds = payOutcome (carried c rel unr) spec := by
  intro fc fe ds x spec
  have hc : FCtxInv fc c := feedsOf_inv c
  have hds : ds = spec := congrArg Prod.fst (decideBatchIdx_eq H s fc c rel unr f b hr hu hc hb)
  refine ⟨hds, funext fun q => ?_⟩
  rw [show x = locIx s fc b from rfl,
    payOutcome_loc (unr := unr) (ds := ds) hr hc hb (fetched_lines s.rel.head s.unr.head fe fc f b) q, payOutcome_eq, hds]

/-- Each `RULES_PAY` line of a commit: on a batch no cap touches, over an index faithful to the snapshots `rel` and
    `unr`, the outcome the worker prints for payment `p` (its index `x`, its decisions `ds`, its feeds) is the Spec's
    `payOutcome` for `p` on the state the index holds, and the reason codes it prints are those of the Spec's decided
    lines of `p` (`leafReasons_codes`). -/
theorem pay_line (H : Bytes → Bytes) (s : St) (c : Ctx) (rel unr : Snapshot Line) (f : List Nat) (b : List Line)
    (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr) (hb : Uncapped (fetch s c.redo b) (Worker.feedsOf c) b)
    (u : Nat → Bool) (p : Nat) :
    let fc : FCtx := ⟨c.today, c.redo, Worker.feedsOf c, c.byp, c.lim⟩
    let fe := fetch s fc.redo b
    let ds := (decideFetched s.rel.head s.unr.head fe fc f b).1
    let x := localIx s.rel.head s.unr.head fe (localRows fe.rel) (localRows fe.unr) fc b
    let spec := (decideBatchIn (carried c rel unr) f b).decisions
    Run.leafOutcome (x.payOutcome ds) u p = Run.leafOutcome (payOutcome (carried c rel unr) spec) u p ∧
    ∃ rs : List String, Run.leafReasons ds u p = (if rs.isEmpty then "-" else ",".intercalate rs) ∧
      rs.Pairwise (· < ·) ∧ (u p = true → rs = ["UNENCODABLE_PAYMENT"]) ∧
      (u p = false → ∀ r, r ∈ rs ↔ ∃ d ∈ spec, d.line.pay = p ∧ ∃ y ∈ d.reasons, Run.name y = r) := by
  intro fc fe ds x spec
  obtain ⟨hds, hx⟩ : ds = spec ∧ x.payOutcome ds = payOutcome (carried c rel unr) spec := pay_eq H s c rel unr f b hr hu hb
  exact ⟨by rw [hx], hds ▸ leafReasons_codes spec u p⟩

/-- A payment with a capped line is HOLD, in any batch (`cap_hold`). -/
theorem pay_capped (hr hu : Head) (fe : Fetched) (fc : FCtx) (f : List Nat) (b : List Line) (u : Nat → Bool)
    {d : Decision} (hd : d ∈ (decideFetched hr hu fe fc f b).1)
    (hcap : capped (hotKeys fe fc.feeds b) fe fc.feeds d.line = true) :
    Run.leafOutcome ((localIx hr hu fe (localRows fe.rel) (localRows fe.unr) fc b).payOutcome
      (decideFetched hr hu fe fc f b).1) u d.line.pay = .HOLD := by
  have hh := (cap_hold hr hu fe fc f b d hd hcap).1
  unfold Run.leafOutcome Ix.payOutcome
  split
  · rfl
  · have : ((decideFetched hr hu fe fc f b).1.filter (·.line.pay == d.line.pay)).any (·.outcome == .HOLD) = true :=
      List.any_eq_true.mpr ⟨d, List.mem_filter.mpr ⟨hd, by simp⟩, by simp [hh]⟩
    simp [this]

/-! ## The exact-duplicate answer over the fetched rows

    The worker reads the released rows under a decided line's exact key from the entry it fetched for the key: the
    head's rows, in row order, while the key has at most `capN` postings, else none (`Worker.relRows`, which
    `Worker.commitBin` passes to `Run.answering`).  `answer_eq`: on a batch no cap touches the reading is the Spec's, so the answered set is
    `Run.answering_eq`'s.  `answer_cap`: a line held for an exact repeat under a key past `capN` postings is held with
    `POSTING_CAP`, and its payment is decided contested, never answered, and HOLD. -/

private theorem relM_getD (g : Key → Entry) (ks : List Key) (key : Key) :
    (HashMap.ofList (ks.map fun k => (k, g k))).getD key Entry.empty = if key ∈ ks then g key else Entry.empty := by
  simp only [Std.HashMap.getD_eq_getD_getElem?, Std.HashMap.ofList_eq_insertMany_empty,
    Std.HashMap.getElem?_insertMany_list, Std.HashMap.getElem?_empty, Option.or_none,
    List.findSomeRev?_eq_findSome?_reverse, ← List.map_reverse, List.findSome?_map]
  simp only [← List.mem_reverse (as := ks)]
  generalize ks.reverse = L
  induction L with
  | nil => simp
  | cons a L ih =>
    by_cases h : a = key
    · subst h; simp
    · simpa [List.findSome?_cons, h, Ne.symm h] using ih

/-- Only a line's own exact key among its keys is an exact key. -/
private theorem keys_exact (x l : Line) : (keys x).contains (exactKey l) = (exactKey x == exactKey l) := by
  have hn : exactKey l ≠ nearKey x := by
    intro h
    have := congrArg List.head? h
    by_cases hl : isCap l <;> by_cases hx : isCap x <;> simp [exactKey, nearKey, hl, hx] at this
  have hi : exactKey l ≠ idKey x := by
    intro h
    have := congrArg List.head? h
    by_cases hl : isCap l <;> simp [exactKey, idKey, hl] at this
  apply Bool.eq_iff_iff.mpr
  simp only [keys, List.contains_iff_mem, List.mem_cons, List.not_mem_nil, or_false, beq_iff_eq]
  exact ⟨fun h => h.elim Eq.symm fun h => h.elim (absurd · hn) (absurd · hi), fun h => Or.inl h.symm⟩

private theorem postings_exact (l : Line) : ∀ (rows : List Line) (i : Nat),
    (postingsFrom (exactKey l) i rows).map (·.row) = rows.filter (exactKey · == exactKey l)
  | [], _ => rfl
  | x :: rows, i => by
    rw [postingsFrom, keys_exact, List.filter_cons]
    cases exactKey x == exactKey l <;> simp [postings_exact l rows]

/-- On a batch no cap touches, the worker's reading under a batch line's exact key is the released set's rows under
    that key, in set order. -/
private theorem rows_read {H : Bytes → Bytes} {s : St} {rel : Snapshot Line} {redo : List Nat} {fd : Feeds}
    {b : List Line} (hr : IdxInv H s.rel rel) (hb : Uncapped (fetch s redo b) fd b) {l : Line} (hl : l ∈ b) :
    Worker.relRows (HashMap.ofList (fetch s redo b).rel) (exactKey l) =
      some (rel.entries.filter (exactKey · == exactKey l)) := by
  have hk : exactKey l ∈ ksR s redo b := mem_ksR_of_probe (mem_probeKeys.mpr ⟨l, hl, by simp [keys]⟩)
  have hc := cnt_rel hb hl _ hk
  show (if capN < ((HashMap.ofList (fetch s redo b).rel).getD (exactKey l) Entry.empty).count then none else
    some ((heads ((HashMap.ofList (fetch s redo b).rel).getD (exactKey l) Entry.empty)).map (·.row))) = _
  rw [fetch_rel', relM_getD, if_pos hk, if_neg (Nat.not_lt.mpr hc), heads_eq hr hc, postings_exact]

/-- The worker's answered set (`Worker.commitBin`): on a batch no cap touches, over an index faithful to `rel` and
    `unr`, it answers a payment exactly when `ExactDuplicate.answered` does on the Spec's decisions at the contested
    payments `k`, unless a line of it is already decided or its earlier list cannot be written (`Run.answering_eq`). -/
theorem answer_eq (H : Bytes → Bytes) (s : St) (c : Ctx) (rel unr : Snapshot Line) (b : List Line)
    (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr) (hb : Uncapped (fetch s c.redo b) (Worker.feedsOf c) b)
    (k : List Nat) (p : Nat) :
    let fc : FCtx := ⟨c.today, c.redo, Worker.feedsOf c, c.byp, c.lim⟩
    let fe := fetch s fc.redo b
    let ds := (decideFetched s.rel.head s.unr.head fe fc [] b).1
    let relM : HashMap Key Entry := HashMap.ofList fe.rel
    let ax := Run.answering c (Worker.relRows relM) k ds
    let sc := carried c rel unr
    let spec := (decideBatchIn sc [] b).decisions
    ax.pays.contains p = (answered sc k spec p &&
      !(spec.any fun d => d.line.pay == p && d.reasons.contains .ALREADY_DECIDED) &&
      (Run.earlierBody sc spec p).isSome) := by
  intro fc fe ds relM ax sc spec
  have hds : ds = spec := (pay_eq H s c rel unr [] b hr hu hb).1
  have hl : ∀ d ∈ ds, d.line ∈ b := fetched_lines _ _ _ _ _ _
  exact (Run.answering_eq (c := sc) (c' := c) (b := b) (hds.trans rfl) rfl
    (fun d hd rs h => ((Option.some.inj ((rows_read hr hb (hl d hd)).symm.trans h)).symm).trans
      (congrArg (List.filter _) (carried_rel c rel unr).symm))
    (fun d hd => (congrArg Option.isSome (rows_read hr hb (hl d hd))).trans rfl) p).trans (by rw [hds])

/-- A line held for an exact repeat whose exact key has more than `capN` released postings: the worker cannot read the
    key whole, so the line is held with `POSTING_CAP` and its payment is decided contested (never answered, its leaf
    as before the amendment) and is HOLD, in any batch. -/
theorem answer_cap (s : St) (c : Ctx) (b : List Line) (k : List Nat) (u : Nat → Bool) :
    let fc : FCtx := ⟨c.today, c.redo, Worker.feedsOf c, c.byp, c.lim⟩
    let fe := fetch s fc.redo b
    let ds := (decideFetched s.rel.head s.unr.head fe fc [] b).1
    let relM : HashMap Key Entry := HashMap.ofList fe.rel
    let ax := Run.answering c (Worker.relRows relM) k ds
    ∀ d ∈ ds, (Reason.FFS_DUPLICATE_LINE ∈ d.reasons ∨ Reason.CAP_MEMBER_MONTH_DUPLICATE ∈ d.reasons) →
      capN < (relM.getD (exactKey d.line) Entry.empty).count →
      ax.k.contains d.line.pay = true ∧ ax.pays.contains d.line.pay = false ∧
      (∀ unf o, answerLeaf ax.c ax.k ax.ds unf o d.line.pay = if unf d.line.pay then .HOLD else .ofOutcome o) ∧
      d.outcome = .HOLD ∧ Reason.POSTING_CAP ∈ d.reasons ∧
      Run.leafOutcome ((localIx s.rel.head s.unr.head fe (localRows fe.rel) (localRows fe.unr) fc b).payOutcome ds)
        u d.line.pay = .HOLD := by
  intro fc fe ds relM ax d hd hr hc
  obtain ⟨h1, h2, -, h4, -⟩ := Run.unread_contested c c (k := k) (rowsFor := Worker.relRows relM) hd hr (if_pos hc)
  have hc' : capN < (if exactKey d.line ∈ ksR s fc.redo b then s.rel.get (exactKey d.line) else Entry.empty).count := by
    rw [← relM_getD (fun k => s.rel.get k) (ksR s fc.redo b) (exactKey d.line)]
    exact hc
  by_cases hm : exactKey d.line ∈ ksR s fc.redo b
  · rw [if_pos hm] at hc'
    have hmem : (exactKey d.line, s.rel.get (exactKey d.line)) ∈ fe.rel := by
      rw [show fe.rel = _ from fetch_rel' s fc.redo b]
      exact List.mem_map.mpr ⟨_, hm, rfl⟩
    have hhot := hot_count (fd := fc.feeds) (b := b) (List.mem_append_left _ hmem) hc'
    have hcap : capped (hotKeys fe fc.feeds b) fe fc.feeds d.line = true := by
      have : (keys d.line).any (hotKeys fe fc.feeds b).contains = true :=
        List.any_eq_true.mpr ⟨exactKey d.line, by simp [keys], hhot⟩
      simp only [capped, this, Bool.or_true, Bool.true_or]
    obtain ⟨h5, h6⟩ := cap_hold _ _ _ _ _ _ d hd hcap
    exact ⟨h1, h2, h4, h5, h6, pay_capped _ _ _ _ _ _ u hd hcap⟩
  · rw [if_neg hm] at hc'
    exact absurd hc' (by simp [Entry.empty])

/-! ## A payment none of whose lines is capped, in a batch where other lines are

    A cap cuts short only what is read for a hot key or a hot feed id; a line none of whose keys is hot and whose feeds
    are whole reads exactly what the Spec reads.  The decisions of the other lines reach it only through the keys they
    claim, and a claim differs from the Spec's only where all of the line's keys are hot (`claim_part`). -/

section Part

open Std (HashSet)
open BlindLedger.Gate.OnepIndex (capD)

variable {H : Bytes → Bytes} {s : St} {fc : FCtx} {c₀ : Ctx} {rel unr : Snapshot Line} {b : List Line}

private theorem heads_post {S : SetIdx} {snap : Snapshot Line} (hS : IdxInv H S snap) (k : Key) :
    heads (S.get k) = (postingsFrom k 0 snap.entries).take capN := by
  rw [hS.2 k]
  obtain ⟨-, h2⟩ := entryOf_count H snap.entries k
  unfold heads
  rw [h2, List.take_take, Nat.min_self]

/-- Whatever keys are fetched, the local rows are strictly rising real rows, and hold every row of a key whose entry is
    whole. -/
private theorem rows_props {S : SetIdx} {snap : Snapshot Line} (hS : IdxInv H S snap) (ks : List Key) :
    (localRows (ks.map fun k => (k, S.get k))).Pairwise (fun p q => p.seq < q.seq) ∧
    (∀ p ∈ localRows (ks.map fun k => (k, S.get k)), snap.entries[p.seq]? = some p.row) ∧
    (∀ k ∈ ks, (S.get k).count ≤ capN → ∀ q ∈ postingsFrom k 0 snap.entries,
      q ∈ localRows (ks.map fun k => (k, S.get k))) := by
  obtain ⟨L, hL⟩ : ∃ L, L = (ks.map fun k => (k, S.get k)).flatMap fun ke => heads ke.2 := ⟨_, rfl⟩
  have hLm : ∀ p, p ∈ L ↔ ∃ k ∈ ks, p ∈ heads (S.get k) := by
    intro p
    rw [hL]
    simp only [List.mem_flatMap, List.mem_map]
    constructor
    · rintro ⟨ke, ⟨k, hk, rfl⟩, hp⟩; exact ⟨k, hk, hp⟩
    · rintro ⟨k, hk, hp⟩; exact ⟨(k, S.get k), ⟨k, hk, rfl⟩, hp⟩
  have hR : ∀ p, p ∈ L → snap.entries[p.seq]? = some p.row := by
    intro p hp
    obtain ⟨k, -, hk⟩ := (hLm p).mp hp
    rw [heads_post hS k] at hk
    obtain ⟨j, h1, h2, -⟩ := (mem_postingsFrom _ 0 p).mp (List.mem_of_mem_take hk)
    rw [h2]; simpa using h1
  have hM := List.pairwise_mergeSort (le := fun p q : Posting => decide (p.seq ≤ q.seq))
    (fun a b c h1 h2 => by simp at *; omega) (fun a b => by simp; omega) L
  have hM' : (L.mergeSort fun p q : Posting => decide (p.seq ≤ q.seq)).Pairwise (fun p q => p.seq ≤ q.seq) :=
    hM.imp (fun h => by simpa using h)
  have hMm : ∀ p, p ∈ L.mergeSort (fun p q : Posting => decide (p.seq ≤ q.seq)) ↔ p ∈ L := fun p =>
    (List.mergeSort_perm L _).mem_iff
  obtain ⟨i1, i2, i3⟩ := dedupSeq_spec _ hM'
  unfold localRows
  rw [← hL]
  refine ⟨i2, fun p hp => hR p ((hMm p).mp (i1 p hp)), fun k hk hc q hq => ?_⟩
  have hqh : q ∈ heads (S.get k) := by rw [heads_eq hS hc]; exact hq
  have hqL : q ∈ L := (hLm q).mpr ⟨k, hk, hqh⟩
  obtain ⟨u, hu, hs⟩ := i3 q ((hMm q).mpr hqL)
  have hu' := hR u ((hMm u).mp (i1 u hu))
  have hq' := hR q hqL
  have := posting_eq hu' hq' hs
  rwa [this] at hu

private theorem postMap_part {S : SetIdx} {snap : Snapshot Line} (hS : IdxInv H S snap) (ks : List Key)
    {k : Key} (hk : k ∈ ks) (hc : (S.get k).count ≤ capN) (i : Nat) :
    i ∈ (postMap (localRows (ks.map fun k => (k, S.get k))) (ks.map fun k => (k, S.get k))).getD k [] ↔
      ∃ q ∈ postingsFrom k 0 snap.entries, (localRows (ks.map fun k => (k, S.get k)))[i]? = some q := by
  obtain ⟨hpw, hRr, -⟩ := rows_props hS ks
  generalize hL : localRows (ks.map fun k => (k, S.get k)) = rr at hpw hRr ⊢
  unfold postMap
  rw [List.foldl_map, foldl_insert_getD (fun k => (heads (S.get k)).filterMap fun p =>
    (rr.foldl (fun (acc : Std.HashMap Nat Nat × Nat) p => (acc.1.insert p.seq acc.2, acc.2 + 1)) (∅, 0)).1.get? p.seq) ks]
  rw [if_pos hk, heads_eq hS hc]
  simp only [List.mem_filterMap, Std.HashMap.get?_eq_getElem?]
  constructor
  · rintro ⟨p, hp, hpos⟩
    rw [pos_foldl rr ∅ 0 hpw] at hpos
    simp only [Nat.sub_zero, Nat.zero_le, true_and] at hpos
    rcases hpos with ⟨q, h2, h3⟩ | ⟨h, -⟩
    · refine ⟨p, hp, ?_⟩
      have hp' : snap.entries[p.seq]? = some p.row := by
        obtain ⟨j, h1, h2', -⟩ := (mem_postingsFrom _ 0 p).mp hp
        rw [h2']; simpa using h1
      have hq := hRr q (List.mem_of_getElem? h2)
      have := posting_eq hq hp' h3
      rw [← this]; exact h2
    · simp at h
  · rintro ⟨q, hq, h2⟩
    refine ⟨q, hq, ?_⟩
    rw [pos_foldl rr ∅ 0 hpw]
    simp only [Nat.sub_zero, Nat.zero_le, true_and]
    left; exact ⟨q, h2, rfl⟩

private theorem probe_part {S : SetIdx} {snap : Snapshot Line} (hS : IdxInv H S snap) (ks : List Key)
    {k : Key} (hk : k ∈ ks) (hc : (S.get k).count ≤ capN) (P : Line → Bool) :
    (((postMap (localRows (ks.map fun k => (k, S.get k))) (ks.map fun k => (k, S.get k))).getD k []).any
      fun i => decide (i < (localRows (ks.map fun k => (k, S.get k))).length) &&
        ((localRows (ks.map fun k => (k, S.get k))).map (·.row)).toArray[i]?.any P) = true ↔
      ∃ y ∈ snap.entries, k ∈ keys y ∧ P y = true := by
  obtain ⟨hpw, hRr, hcov⟩ := rows_props hS ks
  have hpm := fun i => postMap_part hS ks hk hc i
  have hcov' := hcov k hk hc
  generalize localRows (ks.map fun k => (k, S.get k)) = rr at hpw hRr hcov' hpm ⊢
  generalize postMap rr (ks.map fun k => (k, S.get k)) = post at hpm ⊢
  simp only [List.any_eq_true, Bool.and_eq_true, decide_eq_true_eq, List.getElem?_toArray, Option.any_eq_true]
  constructor
  · rintro ⟨i, hi, -, y, h1, h2⟩
    obtain ⟨q, hq, h3⟩ := (hpm i).mp hi
    simp only [List.getElem?_map, h3, Option.map_some, Option.some.injEq] at h1
    subst h1
    obtain ⟨j, h4, -, h5⟩ := (mem_postingsFrom _ 0 q).mp hq
    exact ⟨q.row, List.mem_of_getElem? h4, h5, h2⟩
  · rintro ⟨y, hy, hky, hP⟩
    obtain ⟨j, hj⟩ := List.mem_iff_getElem?.mp hy
    have hq : (⟨j, y⟩ : Posting) ∈ postingsFrom k 0 snap.entries :=
      (mem_postingsFrom _ 0 _).mpr ⟨j, hj, by simp, hky⟩
    have hq' : (⟨j, y⟩ : Posting) ∈ rr := hcov' _ hq
    obtain ⟨i, hi⟩ := List.mem_iff_getElem?.mp hq'
    exact ⟨i, (hpm i).mpr ⟨_, hq, hi⟩, (List.getElem?_eq_some_iff.mp hi).1, y, by simp [hi], hP⟩

private theorem hits_part {S : SetIdx} {snap : Snapshot Line} (hS : IdxInv H S snap) (ks : List Key)
    (ks' : List Key) (hsub : ∀ k ∈ ks', k ∈ ks) (hfull : ∀ k ∈ ks', (S.get k).count ≤ capN) (p : Line → Bool) :
    hits ((localRows (ks.map fun k => (k, S.get k))).map (·.row)).toArray
      (postMap (localRows (ks.map fun k => (k, S.get k))) (ks.map fun k => (k, S.get k))) ks' p =
    ((snap.entries.filter (fun y => ks'.any (keys y).contains)).filter p).map (·.id) := by
  obtain ⟨hpw, hRr, hcov⟩ := rows_props hS ks
  have hpm := fun k hk i => postMap_part hS ks (hsub k hk) (hfull k hk) i
  have hrf : ((localRows (ks.map fun k => (k, S.get k))).map (·.row)).filter (fun y => ks'.any (keys y).contains) =
      snap.entries.filter (fun y => ks'.any (keys y).contains) := by
    rw [← map_row_pf (ks := ks') snap.entries 0]
    have h1 : ((localRows (ks.map fun k => (k, S.get k))).map (·.row)).filter (fun y => ks'.any (keys y).contains) =
        ((localRows (ks.map fun k => (k, S.get k))).filter (fun q => ks'.any (keys q.row).contains)).map (·.row) := by
      rw [List.filter_map]; rfl
    rw [h1]
    congr 1
    refine sorted_postings_eq (hpw.filter _) (pairwise_pf _ _) fun q => ?_
    rw [List.mem_filter, mem_pf_iff]
    constructor
    · rintro ⟨hq, hm⟩
      obtain ⟨k, hk, hc⟩ := List.any_eq_true.mp hm
      exact ⟨k, hk, (mem_postingsFrom _ 0 q).mpr ⟨q.seq, by simpa using hRr q hq, by simp, List.contains_iff_mem.mp hc⟩⟩
    · rintro ⟨k, hk, hq⟩
      refine ⟨hcov k (hsub k hk) (hfull k hk) q hq, List.any_eq_true.mpr ⟨k, hk, ?_⟩⟩
      obtain ⟨j, -, -, h3⟩ := (mem_postingsFrom _ 0 q).mp hq
      exact List.contains_iff_mem.mpr h3
  generalize localRows (ks.map fun k => (k, S.get k)) = rr at hpw hRr hcov hpm hrf ⊢
  generalize postMap rr (ks.map fun k => (k, S.get k)) = post at hpm ⊢
  have hM := List.pairwise_mergeSort (le := fun i j : Nat => decide (i ≤ j))
    (fun a b c h1 h2 => by simp at *; omega) (fun a b => by simp; omega) (ks'.flatMap (post.getD · []))
  have hM' : ((ks'.flatMap (post.getD · [])).mergeSort fun i j : Nat => decide (i ≤ j)).Pairwise (· ≤ ·) :=
    hM.imp (fun h => by simpa using h)
  obtain ⟨d1, d2⟩ := dedup_spec _ hM'
  have hT : ∀ i, i ∈ dedup ((ks'.flatMap (post.getD · [])).mergeSort fun i j : Nat => decide (i ≤ j)) ↔
      ∃ y, (rr.map (·.row))[i]? = some y ∧ ks'.any (keys y).contains = true := by
    intro i
    rw [d1, (List.mergeSort_perm _ _).mem_iff, List.mem_flatMap]
    constructor
    · rintro ⟨k, hk, hi⟩
      obtain ⟨q, hq, h2⟩ := (hpm k hk i).mp hi
      refine ⟨q.row, by simp [h2], List.any_eq_true.mpr ⟨k, hk, ?_⟩⟩
      obtain ⟨j, -, -, h3⟩ := (mem_postingsFrom _ 0 q).mp hq
      exact List.contains_iff_mem.mpr h3
    · rintro ⟨y, h1, h2⟩
      obtain ⟨k, hk, hc⟩ := List.any_eq_true.mp h2
      simp only [List.getElem?_map, Option.map_eq_some_iff] at h1
      obtain ⟨q, h3, rfl⟩ := h1
      refine ⟨k, hk, (hpm k hk i).mpr ⟨q, ?_, h3⟩⟩
      exact (mem_postingsFrom _ 0 q).mpr ⟨q.seq, by simpa using hRr q (List.mem_of_getElem? h3), by simp,
        List.contains_iff_mem.mp hc⟩
  have hT' : dedup ((ks'.flatMap (post.getD · [])).mergeSort fun i j : Nat => decide (i ≤ j)) =
      (List.range' 0 (rr.map (·.row)).length).filter (fun i => ((rr.map (·.row))[i - 0]?).any (fun y => ks'.any (keys y).contains)) := by
    refine sorted_nat_eq d2 (List.Pairwise.filter _ List.pairwise_lt_range') fun i => ?_
    rw [hT, List.mem_filter, List.mem_range'_1]
    simp only [Nat.sub_zero, Option.any_eq_true]
    constructor
    · rintro ⟨y, h1, h2⟩
      have := (List.getElem?_eq_some_iff.mp h1).1
      exact ⟨⟨Nat.zero_le _, by omega⟩, y, h1, h2⟩
    · rintro ⟨-, y, h1, h2⟩; exact ⟨y, h1, h2⟩
  unfold hits
  rw [hT']
  simp only [List.getElem?_toArray, Nat.sub_zero]
  have := filterMap_range (fun y => ks'.any (keys y).contains) p (rr.map (·.row)) 0
  simp only [Nat.sub_zero] at this
  rw [this, hrf]

private theorem row_part {S : SetIdx} {snap : Snapshot Line} (hS : IdxInv H S snap) (ks : List Key)
    {k : Key} (hk : k ∈ ks) (hc : (S.get k).count ≤ capN) {y : Line} (hy : y ∈ snap.entries) (hky : k ∈ keys y) :
    ∃ q ∈ localRows (ks.map fun k => (k, S.get k)), q.row = y ∧ q ∈ postingsFrom k 0 snap.entries := by
  obtain ⟨j, hj⟩ := List.mem_iff_getElem?.mp hy
  have hq : (⟨j, y⟩ : Posting) ∈ postingsFrom k 0 snap.entries :=
    (mem_postingsFrom _ 0 _).mpr ⟨j, hj, by simp, hky⟩
  exact ⟨⟨j, y⟩, (rows_props hS ks).2.2 k hk hc _ hq, rfl, hq⟩

/-! Hot keys, counts and the lines no cap touches. -/

private theorem part_hot {fe : Fetched} {fd : Feeds} {b : List Line} {l : Line}
    (h : capped (hotKeys fe fd b) fe fd l = false) {k : Key} (hk : k ∈ keys l) :
    (hotKeys fe fd b).contains k = false := by
  unfold capped at h
  simp only [Bool.or_eq_false_iff] at h
  cases hc : (hotKeys fe fd b).contains k
  · rfl
  · have : (keys l).any (hotKeys fe fd b).contains = true := List.any_eq_true.mpr ⟨k, hk, hc⟩
    rw [this] at h; exact absurd h.1.2 (by simp)

private theorem part_id {fe : Fetched} {fd : Feeds} {b : List Line} {l : Line}
    (h : capped (hotKeys fe fd b) fe fd l = false) : idCapped fe = false := by
  unfold capped at h
  simp only [Bool.or_eq_false_iff] at h
  exact h.1.1

private theorem part_feed {fe : Fetched} {fd : Feeds} {b : List Line} {l : Line}
    (h : capped (hotKeys fe fd b) fe fd l = false) :
    feedOver (fd.dmf l.member) = false ∧ feedOver (fd.span l.member) = false ∧ feedOver (fd.pdeath l.payee) = false ∧
    feedOver (fd.excl l.payee) = false ∧ feedOver (fd.pdeath l.rendering) = false ∧ feedOver (fd.excl l.rendering) = false := by
  unfold capped feedCapped at h
  simp only [Bool.or_eq_false_iff, List.any_cons, List.any_nil, Bool.or_false] at h
  obtain ⟨-, ⟨⟨h1, h2⟩, ⟨h3, h4⟩⟩⟩ := h
  exact ⟨h1, h2, h3.1, h3.2, h4.1, h4.2⟩

private theorem hot_cap {fe : Fetched} {fd : Feeds} {b : List Line} {l : Line} (hl : l ∈ b) (hc : isCap l = true)
    (hov : feedOver (fd.span l.member) = true) {k : Key} (hk : k ∈ keys l) :
    (hotKeys fe fd b).contains k = true := by
  unfold hotKeys
  rw [HashSet.contains_ofList]
  apply List.contains_iff_mem.mpr
  simp only [List.mem_append, List.mem_map, List.mem_filter, List.mem_flatMap]
  exact Or.inr ⟨l, ⟨hl, by simp [hc, hov]⟩, hk⟩

private theorem cntR_part {k : Key} (hk : k ∈ ksR s fc.redo b)
    (hn : (hotKeys (fetch s fc.redo b) fc.feeds b).contains k = false) : (s.rel.get k).count ≤ capN := by
  refine Nat.le_of_not_lt fun hc => ?_
  have hmem : (k, s.rel.get k) ∈ (fetch s fc.redo b).rel := by
    rw [fetch_rel']; exact List.mem_map.mpr ⟨k, hk, rfl⟩
  have := hot_count (fe := fetch s fc.redo b) (fd := fc.feeds) (b := b) (ke := (k, s.rel.get k))
    (List.mem_append_left _ hmem) (by simpa using hc)
  rw [hn] at this
  exact absurd this (by simp)

private theorem cntU_part {k : Key} (hk : k ∈ probeKeys b)
    (hn : (hotKeys (fetch s fc.redo b) fc.feeds b).contains k = false) : (s.unr.get k).count ≤ capN := by
  refine Nat.le_of_not_lt fun hc => ?_
  have := hot_count (fe := fetch s fc.redo b) (fd := fc.feeds) (b := b) (ke := (k, s.unr.get k))
    (List.mem_append_right _ (by rw [fetch_unr']; exact List.mem_map.mpr ⟨k, hk, rfl⟩)) (by simpa using hc)
  rw [hn] at this
  exact absurd this (by simp)

private theorem cntId_part {k : Key} (hid : idCapped (fetch s fc.redo b) = false) (hk : k ∈ ksR s fc.redo b)
    (h4 : k.head? = some 4) : (s.rel.get k).count ≤ capN := by
  refine Nat.le_of_not_lt fun hc => ?_
  have hmem : (k, s.rel.get k) ∈ (fetch s fc.redo b).rel := by
    rw [fetch_rel']; exact List.mem_map.mpr ⟨k, hk, rfl⟩
  have : (fetch s fc.redo b).rel.any (fun ke => ke.1.head? == some 4 && capN < ke.2.count) = true :=
    List.any_eq_true.mpr ⟨_, hmem, by simp [h4]; omega⟩
  unfold idCapped at hid
  rw [hid] at this
  exact absurd this (by simp)

private theorem probeR' (hr : IdxInv H s.rel rel) {k : Key} (hk : k ∈ ksR s fc.redo b)
    (hcnt : (s.rel.get k).count ≤ capN) (P : Line → Bool) :
    (((locIx s fc b).relPost.getD k []).any fun i => decide (i < (locIx s fc b).relN) && (locIx s fc b).rel[i]?.any P) = true ↔
      ∃ y ∈ rel.entries, k ∈ keys y ∧ P y = true :=
  probe_part hr (ksR s fc.redo b) hk hcnt P

private theorem probeU' (hu : IdxInv H s.unr unr) {k : Key} (hk : k ∈ probeKeys b)
    (hcnt : (s.unr.get k).count ≤ capN) (P : Line → Bool) :
    (((locIx s fc b).unrPost.getD k []).any fun i => decide (i < (locIx s fc b).unrN) && (locIx s fc b).unr[i]?.any P) = true ↔
      ∃ y ∈ unr.entries, k ∈ keys y ∧ P y = true :=
  probe_part hu (probeKeys b) hk hcnt P

/-- `own` reads only the line's id key, whole unless `idCapped`. -/
private theorem own_part (hr : IdxInv H s.rel rel) (hc : FCtxInv fc c₀) (hid : idCapped (fetch s fc.redo b) = false)
    {y : Line} (hy : fc.redo.contains y.pay = true → idKey y ∈ ksR s fc.redo b) :
    (locIx s fc b).own y = own (carried c₀ rel unr) y := by
  unfold Ix.own own
  have hrd : (locIx s fc b).redo.contains y.pay = fc.redo.contains y.pay := by
    simp [locIx, localIx, HashSet.contains_ofList]
  have hrd2 : (carried c₀ rel unr).redo = fc.redo := hc.2.1.symm
  rw [hrd, hrd2, carried_rel]
  by_cases hred : fc.redo.contains y.pay = true
  · rw [hred, Bool.true_and, Bool.true_and, Bool.eq_iff_iff,
      probeR' hr (hy hred) (cntId_part hid (hy hred) (by simp [idKey])) (· == y)]
    simp only [List.contains_iff_mem, beq_iff_eq]
    constructor
    · rintro ⟨y', hy', _, rfl⟩; exact hy'
    · intro h; exact ⟨y, h, idKey_mem, rfl⟩
  · have : fc.redo.contains y.pay = false := by simpa using hred
    rw [this, Bool.false_and, Bool.false_and]

private theorem own_b' (hr : IdxInv H s.rel rel) (hc : FCtxInv fc c₀) (hid : idCapped (fetch s fc.redo b) = false)
    {l : Line} (hl : l ∈ b) : (locIx s fc b).own l = own (carried c₀ rel unr) l :=
  own_part hr hc hid fun _ => mem_ksR_of_probe (mem_probeKeys.mpr ⟨l, hl, idKey_mem⟩)

private theorem own_xy' (hr : IdxInv H s.rel rel) (hc : FCtxInv fc c₀) (hid : idCapped (fetch s fc.redo b) = false)
    {l : Line} (hl : l ∈ b) : (locIx s fc b).own l = (Ix.build (carried c₀ rel unr) b).own l :=
  (own_b' hr hc hid hl).trans own_eq.symm

private theorem ixclaim_sub (x : Ix) (l : Line) {k : Key} (h : k ∈ x.claim l) : k ∈ keys l := by
  unfold Ix.claim at h
  split at h
  · simp only [List.mem_cons, List.not_mem_nil, or_false] at h
    rcases h with rfl | rfl <;> simp [keys]
  · exact h

/-- The claim of a line of the batch is the Spec's on every key that is not hot: where the line's own span feed is cut
    short, a `CAP_820` line's keys are all hot. -/
private theorem claim_part (hr : IdxInv H s.rel rel) (hc : FCtxInv fc c₀) (hid : idCapped (fetch s fc.redo b) = false)
    {l : Line} (hl : l ∈ b) {k : Key} (hn : (hotKeys (fetch s fc.redo b) fc.feeds b).contains k = false) :
    ((locIx s fc b).claim l).contains k = ((Ix.build (carried c₀ rel unr) b).claim l).contains k := by
  by_cases hov : isCap l = true ∧ feedOver (fc.feeds.span l.member) = true
  · have hf : ∀ x : Ix, (x.claim l).contains k = false := fun x => by
      cases h : (x.claim l).contains k
      · rfl
      · have := hot_cap (fe := fetch s fc.redo b) (fd := fc.feeds) (b := b) hl hov.1 hov.2
          (ixclaim_sub x l (List.contains_iff_mem.mp h))
        rw [hn] at this
        exact absurd this (by simp)
    rw [hf, hf]
  · have : (locIx s fc b).claim l = (Ix.build (carried c₀ rel unr) b).claim l := by
      rw [claim_eq]
      by_cases hcap : isCap l = true
      · have hov' : feedOver (fc.feeds.span l.member) = false := by
          cases h : feedOver (fc.feeds.span l.member)
          · rfl
          · exact absurd ⟨hcap, h⟩ hov
        unfold Ix.claim claim
        rw [notEnrolled_loc hc (mem_spanIds hl _) hov', own_b' hr hc hid hl]
      · have : isCap l = false := by simpa using hcap
        unfold Ix.claim claim
        simp [this]
    rw [this]

private theorem claim_part_u (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr) (hc : FCtxInv fc c₀)
    (hid : idCapped (fetch s fc.redo b) = false) {y : Line} (hy : y ∈ unr.entries)
    {k : Key} (hk : k ∈ probeKeys b) (hn : (hotKeys (fetch s fc.redo b) fc.feeds b).contains k = false)
    (hky : k ∈ keys y) : (locIx s fc b).claim y = claim (carried c₀ rel unr) y := by
  have hcu := cntU_part (s := s) (fc := fc) hk hn
  obtain ⟨q, hq, hqy, hqp⟩ := row_part hu (probeKeys b) hk hcu hy hky
  have hhead : q ∈ heads (s.unr.get k) := by rw [heads_eq hu hcu]; exact hqp
  have hke : (k, s.unr.get k) ∈ (fetch s fc.redo b).unr := by
    rw [fetch_unr']; exact List.mem_map.mpr ⟨k, hk, rfl⟩
  by_cases hcap : isCap y = true
  · have hy' : fc.redo.contains y.pay = true → idKey y ∈ ksR s fc.redo b := by
      intro hred
      have := round2_cover (redo := fc.redo) (ks := probeKeys b) (u := uEs s b) (ke := (k, s.unr.get k))
        (by exact List.mem_map.mpr ⟨k, hk, rfl⟩) hhead (by rw [hqy]; exact hcap) (by rw [hqy]; exact hred)
      rw [hqy] at this
      rcases this with h | h
      · exact List.mem_append_left _ h
      · exact List.mem_append_right _ h
    have hov : feedOver (fc.feeds.span y.member) = false := by
      cases hh : feedOver (fc.feeds.span y.member)
      · rfl
      · exfalso
        have := hot_span (fe := fetch s fc.redo b) (fd := fc.feeds) (b := b) hke hhead (by rw [hqy]; exact hcap)
          (by rw [hqy]; exact hh)
        rw [hn] at this
        exact absurd this (by simp)
    have hmem : y.member ∈ spanIds b (localRows (fetch s fc.redo b).unr) :=
      List.mem_append_right _ (List.mem_map.mpr ⟨q, by rw [fetch_unr']; exact hq, by rw [hqy]⟩)
    unfold Ix.claim claim
    rw [notEnrolled_loc hc hmem hov, own_part hr hc hid hy']
  · have : isCap y = false := by simpa using hcap
    unfold Ix.claim claim
    simp [this]

private theorem seen0_part (hr : IdxInv H s.rel rel) (hc : FCtxInv fc c₀)
    (hid : idCapped (fetch s fc.redo b) = false) {k : Key} (hk : k ∈ probeKeys b)
    (hn : (hotKeys (fetch s fc.redo b) fc.feeds b).contains k = false) :
    (locIx s fc b).seen0 k = (Ix.build (carried c₀ rel unr) b).seen0 k := by
  rw [seen0_eq, Bool.eq_iff_iff]
  unfold Ix.seen0 seen0
  rw [probeR' hr (mem_ksR_of_probe hk) (cntR_part (mem_ksR_of_probe hk) hn)]
  simp only [List.contains_iff_mem, List.mem_flatMap, List.mem_filter, carried_rel]
  have hP : ∀ y, (!((locIx s fc b).own y && (locIx s fc b).batch.contains y)) =
      !(own (carried c₀ rel unr) y && b.contains y) := by
    intro y
    have hbt : (locIx s fc b).batch.contains y = b.contains y := by
      simp [locIx, localIx, HashSet.contains_ofList]
    rw [hbt]
    cases hb' : b.contains y
    · simp
    · rw [own_b' hr hc hid (List.contains_iff_mem.mp hb')]
  constructor
  · rintro ⟨y, hy, hky, hp⟩; exact ⟨y, ⟨hy, by rw [← hP]; exact hp⟩, hky⟩
  · rintro ⟨y, ⟨hy, hp⟩, hky⟩; exact ⟨y, hy, hky, by rw [hP]; exact hp⟩

private theorem pending_part (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr) (hc : FCtxInv fc c₀)
    (hid : idCapped (fetch s fc.redo b) = false) {l : Line} {k : Key} (hk : k ∈ probeKeys b)
    (hn : (hotKeys (fetch s fc.redo b) fc.feeds b).contains k = false) :
    (locIx s fc b).pending l k = (Ix.build (carried c₀ rel unr) b).pending l k := by
  rw [pending_eq, Bool.eq_iff_iff]
  unfold Ix.pending
  rw [probeU' hu hk (cntU_part hk hn), List.contains_iff_mem, mem_pending, byp_loc (rel := rel) (unr := unr) hc]
  simp only [Bool.and_eq_true, List.contains_iff_mem, carried_unr]
  constructor
  · rintro ⟨y, hy, hky, hp, hn'⟩
    exact ⟨y, hy, fun h => by simp [h.1, h.2] at hn', by rw [← claim_part_u hr hu hc hid hy hk hn hky]; exact hp⟩
  · rintro ⟨y, hy, hn', hp⟩
    have hky := claim_sub hp
    exact ⟨y, hy, hky, by rw [claim_part_u hr hu hc hid hy hk hn hky]; exact hp, keep_row hn'⟩

private theorem counterparts_part (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr) (hc : FCtxInv fc c₀)
    (hid : idCapped (fetch s fc.redo b) = false) {l : Line} (hl : l ∈ b)
    (hcl : capped (hotKeys (fetch s fc.redo b) fc.feeds b) (fetch s fc.redo b) fc.feeds l = false) :
    (locIx s fc b).counterparts l = (Ix.build (carried c₀ rel unr) b).counterparts l := by
  have hsubR : ∀ k ∈ keys l, k ∈ ksR s fc.redo b := fun k hk => mem_ksR_of_probe (mem_probeKeys.mpr ⟨l, hl, hk⟩)
  have hsubU : ∀ k ∈ keys l, k ∈ probeKeys b := fun k hk => mem_probeKeys.mpr ⟨l, hl, hk⟩
  have hn : ∀ k ∈ keys l, (hotKeys (fetch s fc.redo b) fc.feeds b).contains k = false := fun k hk => part_hot hcl hk
  have e1 : hits (locIx s fc b).rel (locIx s fc b).relPost (keys l) (fun _ => true) =
      ((rel.entries.filter fun y => (keys l).any (keys y).contains).filter fun _ => true).map (·.id) :=
    hits_part hr (ksR s fc.redo b) (keys l) hsubR (fun k hk => cntR_part (hsubR k hk) (hn k hk)) (fun _ => true)
  have e2 : hits (locIx s fc b).unr (locIx s fc b).unrPost (keys l)
      (fun y => (keys l).any ((locIx s fc b).claim y).contains) =
      ((unr.entries.filter fun y => (keys l).any (keys y).contains).filter
        fun y => (keys l).any ((locIx s fc b).claim y).contains).map (·.id) :=
    hits_part hu (probeKeys b) (keys l) hsubU (fun k hk => cntU_part (hsubU k hk) (hn k hk)) _
  have hU : (unr.entries.filter fun y => (keys l).any (keys y).contains).filter
        (fun y => (keys l).any ((locIx s fc b).claim y).contains) =
      unr.entries.filter fun y => (keys l).any (claim (carried c₀ rel unr) y).contains := by
    rw [List.filter_filter]
    refine List.filter_congr fun y hy => ?_
    cases h : (keys l).any (claim (carried c₀ rel unr) y).contains
    · cases hk : (keys l).any (keys y).contains
      · simp
      · obtain ⟨k, hk1, hk2⟩ := List.any_eq_true.mp hk
        have := claim_part_u hr hu hc hid hy (hsubU k hk1) (hn k hk1) (List.contains_iff_mem.mp hk2)
        rw [this, h]; simp
    · obtain ⟨k, hk1, hk2⟩ := List.any_eq_true.mp h
      have hky := claim_sub (List.contains_iff_mem.mp hk2)
      have := claim_part_u hr hu hc hid hy (hsubU k hk1) (hn k hk1) hky
      have hkk : (keys l).any (keys y).contains = true := List.any_eq_true.mpr ⟨k, hk1, List.contains_iff_mem.mpr hky⟩
      rw [hkk, this, h]; simp
  have l1 : loose (carried c₀ rel unr).today (carried c₀ rel unr).releasedPrior (carried c₀ rel unr).released = [] :=
    loose_carried _ _
  have l2 : loose (carried c₀ rel unr).today (carried c₀ rel unr).unresolvedPrior (carried c₀ rel unr).unresolved = [] :=
    loose_carried _ _
  rw [counterparts_eq]
  unfold Ix.counterparts
  rw [e1, e2, hU, l1, l2, List.append_nil, List.append_nil, carried_rel, carried_unr, List.map_append]
  simp

private theorem fires_part (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr) (hc : FCtxInv fc c₀)
    (hid : idCapped (fetch s fc.redo b) = false) {l : Line} (hl : l ∈ b)
    (hcl : capped (hotKeys (fetch s fc.redo b) fc.feeds b) (fetch s fc.redo b) fc.feeds l = false)
    (s1 s2 : HashSet Key)
    (hag : ∀ k, (hotKeys (fetch s fc.redo b) fc.feeds b).contains k = false → s1.contains k = s2.contains k)
    (r : Reason) :
    (locIx s fc b).fires s1 l r = (Ix.build (carried c₀ rel unr) b).fires s2 l r := by
  have hk : ∀ k ∈ keys l, k ∈ probeKeys b := fun k hk => mem_probeKeys.mpr ⟨l, hl, hk⟩
  have hn : ∀ k ∈ keys l, (hotKeys (fetch s fc.redo b) fc.feeds b).contains k = false := fun k hk => part_hot hcl hk
  have hs : ∀ k ∈ keys l, (locIx s fc b).seen s1 k = (Ix.build (carried c₀ rel unr) b).seen s2 k := fun k hk' => by
    unfold Ix.seen; rw [seen0_part hr hc hid (hk k hk') (hn k hk'), hag k (hn k hk')]
  have hp : ∀ k ∈ keys l, (locIx s fc b).pending l k = (Ix.build (carried c₀ rel unr) b).pending l k := fun k hk' =>
    pending_part hr hu hc hid (hk k hk') (hn k hk')
  have hid' : idKey l ∈ keys l := idKey_mem
  have hex : exactKey l ∈ keys l := by simp [keys]
  have hne : nearKey l ∈ keys l := by simp [keys]
  obtain ⟨f1, f2, f3, f4, f5, f6⟩ := part_feed hcl
  obtain ⟨hpay, hrend⟩ := mem_parties hl
  have hmd : (locIx s fc b).memberDead l = (Ix.build (carried c₀ rel unr) b).memberDead l :=
    (memberDead_loc (s := s) (b := b) (rel := rel) (unr := unr) hc (mem_members hl) f1).trans memberDead_eq.symm
  have hpd : (locIx s fc b).providerDead l = (Ix.build (carried c₀ rel unr) b).providerDead l :=
    (providerDead_loc (s := s) (b := b) (rel := rel) (unr := unr) hc hpay hrend f3 f5).trans providerDead_eq.symm
  have hex' : (locIx s fc b).excluded l = (Ix.build (carried c₀ rel unr) b).excluded l :=
    (excluded_loc (s := s) (b := b) (rel := rel) (unr := unr) hc hpay hrend f4 f6).trans excluded_eq.symm
  have hov : (locIx s fc b).overlap l = (Ix.build (carried c₀ rel unr) b).overlap l :=
    (overlap_loc (s := s) (b := b) (rel := rel) (unr := unr) hc (mem_spanIds hl _) f2).trans overlap_eq.symm
  have hne' : (locIx s fc b).notEnrolled l = (Ix.build (carried c₀ rel unr) b).notEnrolled l :=
    (notEnrolled_loc (s := s) (b := b) (rel := rel) (unr := unr) hc (mem_spanIds hl _) f2).trans notEnrolled_eq.symm
  have hen : (locIx s fc b).enrolled l = (Ix.build (carried c₀ rel unr) b).enrolled l :=
    (enrolled_loc (s := s) (b := b) (rel := rel) (unr := unr) hc (mem_spanIds hl _) f2).trans enrolled_eq.symm
  have l1 : loose (carried c₀ rel unr).today (carried c₀ rel unr).releasedPrior (carried c₀ rel unr).released = [] :=
    loose_carried _ _
  have l2 : loose (carried c₀ rel unr).today (carried c₀ rel unr).unresolvedPrior (carried c₀ rel unr).unresolved = [] :=
    loose_carried _ _
  have hlk : (locIx s fc b).looseKeys.contains (exactKey l) =
      (Ix.build (carried c₀ rel unr) b).looseKeys.contains (exactKey l) := by
    have : looseKeys (carried c₀ rel unr) = [] := by unfold looseKeys; rw [l1, l2]; rfl
    show (∅ : HashSet Key).contains (exactKey l) = _
    rw [looseKeys_eq, this]; simp
  have hrc := relChained_loc (b := b) (unr := unr) hr hc
  have huc := unrChained_loc (b := b) (rel := rel) hu hc
  obtain ⟨hT, -, hDS, hPS, hES, hSS, hDO, hPO, hEO, hSO, -, -, -, -⟩ := hc
  have hto : (locIx s fc b).today = (Ix.build (carried c₀ rel unr) b).today := hT
  have hds : (locIx s fc b).dmfSome = (Ix.build (carried c₀ rel unr) b).dmfSome := hDS
  have hps : (locIx s fc b).pdSome = (Ix.build (carried c₀ rel unr) b).pdSome := hPS
  have hes : (locIx s fc b).exclSome = (Ix.build (carried c₀ rel unr) b).exclSome := hES
  have hss : (locIx s fc b).spanSome = (Ix.build (carried c₀ rel unr) b).spanSome := hSS
  have hdo : (locIx s fc b).dmfOk = (Ix.build (carried c₀ rel unr) b).dmfOk := hDO
  have hpo : (locIx s fc b).pdOk = (Ix.build (carried c₀ rel unr) b).pdOk := hPO
  have heo : (locIx s fc b).exclOk = (Ix.build (carried c₀ rel unr) b).exclOk := hEO
  have hso : (locIx s fc b).spanOk = (Ix.build (carried c₀ rel unr) b).spanOk := hSO
  cases r <;> simp only [Ix.fires, hs _ hex, hs _ hne, hs _ hid', hp _ hex, hp _ hne, hp _ hid', hlk, hmd, hpd, hex',
    hov, hne', hen, hrc, huc, hto, hds, hps, hes, hss, hdo, hpo, heo, hso]

private theorem decideLine_part (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr) (hc : FCtxInv fc c₀)
    (hid : idCapped (fetch s fc.redo b) = false) {l : Line} (hl : l ∈ b)
    (hcl : capped (hotKeys (fetch s fc.redo b) fc.feeds b) (fetch s fc.redo b) fc.feeds l = false)
    (s1 s2 : HashSet Key)
    (hag : ∀ k, (hotKeys (fetch s fc.redo b) fc.feeds b).contains k = false → s1.contains k = s2.contains k) :
    (locIx s fc b).decideLine s1 l = (Ix.build (carried c₀ rel unr) b).decideLine s2 l := by
  unfold Ix.decideLine
  have : reasons.filter ((locIx s fc b).fires s1 l) = reasons.filter ((Ix.build (carried c₀ rel unr) b).fires s2 l) :=
    List.filter_congr fun r _ => fires_part hr hu hc hid hl hcl s1 s2 hag r
  rw [this, counterparts_part hr hu hc hid hl hcl]

private theorem ite_line (c : Bool) (d : Decision) : (if c = true then capD d else d).line = d.line := by
  split <;> rfl

/-- Over the lines of the batch in any order, the decisions of the lines of payment `p`, none of them capped, are the
    Spec's, whatever the other lines do: they reach `p` only through the keys they claim. -/
private theorem decideAll_part (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr) (hc : FCtxInv fc c₀)
    (hid : idCapped (fetch s fc.redo b) = false) (p : Nat)
    (hp : ∀ l ∈ b, l.pay = p → capped (hotKeys (fetch s fc.redo b) fc.feeds b) (fetch s fc.redo b) fc.feeds l = false) :
    ∀ (ls : List Line) (s1 s2 : HashSet Key), (∀ l ∈ ls, l ∈ b) →
      (∀ k, (hotKeys (fetch s fc.redo b) fc.feeds b).contains k = false → s1.contains k = s2.contains k) →
      (((locIx s fc b).decideAll s1 ls).map (fun d =>
        if capped (hotKeys (fetch s fc.redo b) fc.feeds b) (fetch s fc.redo b) fc.feeds d.line then capD d else d)).filter
          (·.line.pay == p) =
      ((Ix.build (carried c₀ rel unr) b).decideAll s2 ls).filter (·.line.pay == p)
  | [], _, _, _, _ => rfl
  | l :: ls, s1, s2, h, hag => by
    have hl : l ∈ b := h l (by simp)
    have ih := decideAll_part hr hu hc hid p hp ls
      (s1.insertMany ((locIx s fc b).claim l)) (s2.insertMany ((Ix.build (carried c₀ rel unr) b).claim l))
      (fun l' hl' => h l' (List.mem_cons_of_mem _ hl')) (fun k hk => by
        rw [HashSet.contains_insertMany_list, HashSet.contains_insertMany_list, hag k hk,
          claim_part hr hc hid hl hk])
    simp only [Ix.decideAll, List.map_cons]
    by_cases hpl : l.pay = p
    · have hcl := hp l hl hpl
      have hd := decideLine_part hr hu hc hid hl hcl s1 s2 hag
      have hif : (if capped (hotKeys (fetch s fc.redo b) fc.feeds b) (fetch s fc.redo b) fc.feeds
            ((locIx s fc b).decideLine s1 l).line = true then capD ((locIx s fc b).decideLine s1 l)
          else (locIx s fc b).decideLine s1 l) = (locIx s fc b).decideLine s1 l := by
        have h0 : capped (hotKeys (fetch s fc.redo b) fc.feeds b) (fetch s fc.redo b) fc.feeds
            ((locIx s fc b).decideLine s1 l).line = false := hcl
        rw [h0]; rfl
      rw [hif, List.filter_cons_of_pos (by simp [Ix.decideLine, hpl]),
        List.filter_cons_of_pos (by simp [Ix.decideLine, hpl]), hd, ih]
    · rw [List.filter_cons_of_neg (by rw [ite_line]; simp [Ix.decideLine, hpl]),
        List.filter_cons_of_neg (by simp [Ix.decideLine, hpl]), ih]

private theorem order_part (hr : IdxInv H s.rel rel) (hc : FCtxInv fc c₀) (hid : idCapped (fetch s fc.redo b) = false) :
    (locIx s fc b).order b = (Ix.build (carried c₀ rel unr) b).order b := by
  unfold Ix.order
  have h1 : b.filter (locIx s fc b).own = b.filter (Ix.build (carried c₀ rel unr) b).own :=
    List.filter_congr fun l hl => own_xy' hr hc hid hl
  have h2 : b.filter (fun y => !(locIx s fc b).own y) = b.filter (fun y => !(Ix.build (carried c₀ rel unr) b).own y) :=
    List.filter_congr fun l hl => by rw [own_xy' hr hc hid hl]
  rw [h1, h2]

private theorem payOutcome_part (hr : IdxInv H s.rel rel) (hc : FCtxInv fc c₀)
    (hid : idCapped (fetch s fc.redo b) = false) {ds : List Decision} (hds : ∀ d ∈ ds, d.line ∈ b) (p : Nat) :
    (locIx s fc b).payOutcome ds p = (Ix.build (carried c₀ rel unr) b).payOutcome ds p := by
  unfold Ix.payOutcome
  rw [redo_loc (rel := rel) (unr := unr) (b := b) hc]
  have key : ∀ (ls : List Decision), (∀ d ∈ ls, d ∈ ds) →
      ls.all (fun d => d.outcome == .ALLOW && (!(Ix.build (carried c₀ rel unr) b).redo.contains p || (locIx s fc b).own d.line)) =
      ls.all (fun d => d.outcome == .ALLOW && (!(Ix.build (carried c₀ rel unr) b).redo.contains p ||
        (Ix.build (carried c₀ rel unr) b).own d.line)) := by
    intro ls hls
    induction ls with
    | nil => rfl
    | cons d t ih =>
      simp only [List.all_cons, own_xy' (unr := unr) hr hc hid (hds d (hls d (by simp))),
        ih (fun e he => hls e (List.mem_cons_of_mem _ he))]
  dsimp only
  rw [key (ds.filter (·.line.pay == p)) (fun d hd => (List.mem_filter.mp hd).1)]

end Part

/-- Each `RULES_PAY` line of a commit, for a payment none of whose lines is capped, in a batch where other lines may be:
    as `pay_line`, the outcome the worker prints for `p` is the Spec's `payOutcome` and its reason codes are the Spec's
    (`leafReasons_codes`).  The other lines' caps change nothing `p` reads: `p`'s lines read only keys and feed ids that
    are whole, the order is fixed by `own` (whole unless `idCapped`, which caps every line), and the keys another line
    claims reach `p` only where they are not hot. -/
theorem pay_line_part (H : Bytes → Bytes) (s : St) (c : Ctx) (rel unr : Snapshot Line) (f : List Nat) (b : List Line)
    (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr) (u : Nat → Bool) (p : Nat)
    (hp : ∀ l ∈ b, l.pay = p → capped (hotKeys (fetch s c.redo b) (Worker.feedsOf c) b) (fetch s c.redo b) (Worker.feedsOf c) l = false) :
    let fc : FCtx := ⟨c.today, c.redo, Worker.feedsOf c, c.byp, c.lim⟩
    let fe := fetch s fc.redo b
    let ds := (decideFetched s.rel.head s.unr.head fe fc f b).1
    let x := localIx s.rel.head s.unr.head fe (localRows fe.rel) (localRows fe.unr) fc b
    let spec := (decideBatchIn (carried c rel unr) f b).decisions
    Run.leafOutcome (x.payOutcome ds) u p = Run.leafOutcome (payOutcome (carried c rel unr) spec) u p ∧
    ∃ rs : List String, Run.leafReasons ds u p = (if rs.isEmpty then "-" else ",".intercalate rs) ∧
      rs.Pairwise (· < ·) ∧ (u p = true → rs = ["UNENCODABLE_PAYMENT"]) ∧
      (u p = false → ∀ r, r ∈ rs ↔ ∃ d ∈ spec, d.line.pay = p ∧ ∃ y ∈ d.reasons, Run.name y = r) := by
  intro fc fe ds x spec
  have hc : FCtxInv fc c := feedsOf_inv c
  have hp' : ∀ l ∈ b, l.pay = p → capped (hotKeys fe fc.feeds b) fe fc.feeds l = false := hp
  have hspec : spec = (Ix.build (carried c rel unr) b).decideAll (Std.HashSet.ofList (idSeen f))
      ((Ix.build (carried c rel unr) b).order b) := by
    show (decideBatchIn (carried c rel unr) f b).decisions = _
    rw [← decideBatchFIn_eq]; rfl
  have hspecb : ∀ d ∈ spec, d.line ∈ b := fun d hd => by
    rw [hspec] at hd; exact order_mem _ (decideAll_line _ _ _ d hd)
  have hdsdef : ds = (((locIx s fc b).decideAll (Std.HashSet.ofList (idSeen f)) ((locIx s fc b).order b)).map
      (fun d => if capped (hotKeys fe fc.feeds b) fe fc.feeds d.line then BlindLedger.Gate.OnepIndex.capD d else d)) := rfl
  have hdsb : ∀ d ∈ ds, d.line ∈ b := fun d hd => by
    rw [hdsdef] at hd
    obtain ⟨d0, hd0, rfl⟩ := List.mem_map.mp hd
    rw [ite_line]
    exact order_mem _ (decideAll_line _ _ _ d0 hd0)
  have hf : ds.filter (·.line.pay == p) = spec.filter (·.line.pay == p) ∧
      x.payOutcome spec p = payOutcome (carried c rel unr) spec p := by
    by_cases hid : idCapped fe = false
    · have hord : (locIx s fc b).order b = (Ix.build (carried c rel unr) b).order b := order_part hr hc hid
      have hF := decideAll_part hr hu hc hid p hp' ((locIx s fc b).order b) (Std.HashSet.ofList (idSeen f))
        (Std.HashSet.ofList (idSeen f)) (fun l hl => order_mem _ hl) (fun _ _ => rfl)
      rw [hord, ← hspec] at hF
      refine ⟨?_, ?_⟩
      · rw [hdsdef, hord]; exact hF
      · rw [show x = locIx s fc b from rfl, payOutcome_part hr hc hid hspecb, payOutcome_eq]
    · have hnil : ∀ ys : List Decision, (∀ d ∈ ys, d.line ∈ b) → ys.filter (·.line.pay == p) = [] := by
        intro ys hys
        refine List.filter_eq_nil_iff.mpr fun d hd => ?_
        simp only [beq_iff_eq]
        intro hpd
        have := hp' d.line (hys d hd) hpd
        have hcl : capped (hotKeys fe fc.feeds b) fe fc.feeds d.line = true := by
          unfold capped
          have : idCapped fe = true := by simpa using hid
          simp [this]
        rw [hcl] at this
        exact absurd this (by simp)
      refine ⟨by rw [hnil ds hdsb, hnil spec hspecb], ?_⟩
      simp [Ix.payOutcome, payOutcome, hnil spec hspecb]
  obtain ⟨hf, hpx⟩ := hf
  have hpo : x.payOutcome ds p = payOutcome (carried c rel unr) spec p := by
    have : x.payOutcome ds p = x.payOutcome spec p := by simp only [Ix.payOutcome, hf]
    rw [this, hpx]
  have hlr : Run.leafReasons ds u p = Run.leafReasons spec u p := by simp only [Run.leafReasons, hf]
  obtain ⟨rs, h1, h2, h3, h4⟩ := leafReasons_codes spec u p
  exact ⟨by simp only [Run.leafOutcome, hpo], rs, by rw [hlr]; exact h1, h2, h3, h4⟩

/-! ## Requests: a token's lines and fields are its own request's (K1 review H1)

    With requests in the frame (`req HEX`, `Run.addReq`), each entry of `Run.St.reqs` is a request Lean decoded from
    the frame's bytes, its payment number and the lines it read from it (`ReqsOk`, kept by every `req`: `addReq_ok`).
    The commit decides `Run.St.lines`; the lines of a request's payment there are exactly that request's (`lines_req`),
    and its leaf before release by cause and the exact-repeat answer (`Run.emitWith`) is the Spec's `Run.emit` (`pay_req`);
    the leaf written, with both, is the Spec's (`commit_leaves`).  The frame carries no pairing of a request with other lines, so none can be signed. -/

/-- The batch's requests: each payment once; each entry a decoded request, its payment number (`payNat`) and the lines
    `linesOf` reads from it (none for a flow with no rules). -/
def ReqsOk (rs : Array Run.Req) : Prop :=
  (rs.toList.map (·.q)).Nodup ∧ ∀ e ∈ rs.toList, (∃ x, decodeRequest x = some e.r) ∧
    e.q = payNat e.r.programId e.r.paymentId ∧ (if e.r.flow.ruled then linesOf e.r else pure []) = some e.ls

theorem reqsOk_empty : ReqsOk #[] := by simp [ReqsOk]

/-- `req HEX` adds the request its bytes decode to, only to a batch with no `line` lines, and keeps `ReqsOk`. -/
theorem addReq_ok {st st' : Run.St} {h : String} (hok : ReqsOk st.reqs) (hs : Run.addReq st h = some st') :
    ∃ x e, Run.unhexFast h = some x ∧ decodeRequest x.toList = some e.r ∧ st'.reqs = st.reqs.push e ∧
      st.batch.isEmpty = true ∧ ReqsOk st'.reqs := by
  unfold Run.addReq at hs
  obtain ⟨x, hx, hs⟩ := Option.bind_eq_some_iff.mp hs
  obtain ⟨e, he, hs⟩ := Option.bind_eq_some_iff.mp hs
  obtain ⟨u, hg, hs⟩ := Option.bind_eq_some_iff.mp hs
  unfold Run.reqOf at he
  obtain ⟨r, hr, he⟩ := Option.bind_eq_some_iff.mp he
  obtain ⟨ls, hl, he⟩ := Option.bind_eq_some_iff.mp he
  injection he with he
  have hc : (st.batch.isEmpty && st.reqs.all fun o => o.q != e.q && o.r.tenantId == e.r.tenantId && o.r.programId == e.r.programId) = true := by
    unfold guard at hg
    split at hg
    · assumption
    · cases hg
  subst he
  injection hs with hs
  subst hs
  simp only [Bool.and_eq_true, Array.all_eq_true_iff_forall_mem, bne_iff_ne, ne_eq, beq_iff_eq] at hc
  refine ⟨x, ⟨payNat r.programId r.paymentId, .ofModel r, ls, x⟩, hx, by simpa [Run.Req.r] using hr, rfl, hc.1, ?_, ?_⟩
  · simp only [Array.toList_push, List.map_append, List.map_cons, List.map_nil]
    refine List.nodup_append.mpr ⟨hok.1, List.pairwise_singleton _ _, fun a ha b hb => ?_⟩
    obtain ⟨e, he, rfl⟩ := List.mem_map.mp ha
    rw [List.mem_singleton.mp hb]
    exact (hc.2 e (Array.mem_toList_iff.mp he)).1.1
  · intro e he
    simp only [Array.toList_push, List.mem_append, List.mem_singleton] at he
    rcases he with he | rfl
    · exact hok.2 e he
    · simp only [Run.Req.r, Frame.Fast.toModel_ofModel]
      exact ⟨⟨_, hr⟩, trivial, hl⟩

private theorem mapM_pay {f : Bytes → Option Line} {q : Nat} (hf : ∀ x l, f x = some l → l.pay = q) :
    ∀ (xs : List Bytes) (ls : List Line), xs.mapM f = some ls → ∀ l ∈ ls, l.pay = q
  | [], ls, h, l, hl => by simp [List.mapM_nil] at h; subst h; simp at hl
  | x :: xs, ls, h, l, hl => by
    simp only [List.mapM_cons] at h
    cases hx : f x with
    | none => simp [hx] at h
    | some a =>
      cases hm : xs.mapM f with
      | none => simp [hx, hm] at h
      | some bs =>
        simp [hx, hm] at h
        subst h
        rcases List.mem_cons.mp hl with rfl | hl
        · exact hf x _ hx
        · exact mapM_pay hf xs bs hm l hl

/-- Every line `linesOf` reads from a request is that request's payment's. -/
theorem linesOf_pay (r : Request) (ls : List Line) (h : linesOf r = some ls) :
    ∀ l ∈ ls, l.pay = payNat r.programId r.paymentId := by
  unfold linesOf at h
  refine mapM_pay (fun x l hx => ?_) _ _ h
  obtain ⟨wl, _, hlo⟩ := Option.bind_eq_some_iff.mp hx
  unfold lineOf at hlo
  obtain ⟨_, _, ha⟩ := Option.map_eq_some_iff.mp hlo
  have hp := congrArg Line.pay ha
  simp only at hp
  exact hp.symm

private theorem reqsOk_pay {rs : Array Run.Req} (hok : ReqsOk rs) : ∀ e ∈ rs.toList, ∀ l ∈ e.ls, l.pay = e.q := by
  intro e he l hl
  obtain ⟨_, hq, hls⟩ := hok.2 e he
  rw [hq]
  split at hls
  · exact linesOf_pay e.r e.ls hls l hl
  · rw [← Option.some.inj hls] at hl
    simp at hl

private theorem filter_own : ∀ (xs : List Run.Req) {e : Run.Req}, (xs.map (·.q)).Nodup →
    (∀ e ∈ xs, ∀ l ∈ e.ls, l.pay = e.q) → e ∈ xs → (xs.flatMap (·.ls)).filter (·.pay == e.q) = e.ls
  | [], _, _, _, he => by simp at he
  | a :: xs, e, hnd, hl, he => by
    rw [List.map_cons, List.nodup_cons] at hnd
    rw [List.flatMap_cons, List.filter_append]
    rcases List.mem_cons.mp he with rfl | he
    · rw [List.filter_eq_self.mpr (fun l hl' => by simp [hl _ (by simp) l hl']), List.filter_eq_nil_iff.mpr ?_,
        List.append_nil]
      intro l hl'
      obtain ⟨b, hb, hlb⟩ := List.mem_flatMap.mp hl'
      rw [hl b (by simp [hb]) l hlb]
      simp only [beq_iff_eq]
      intro h
      exact hnd.1 (by rw [← h]; exact List.mem_map.mpr ⟨b, hb, rfl⟩)
    · rw [List.filter_eq_nil_iff.mpr ?_, List.nil_append]
      · exact filter_own xs hnd.2 (fun b hb => hl b (by simp [hb])) he
      · intro l hl'
        rw [hl a (by simp) l hl']
        simp only [beq_iff_eq]
        intro h
        exact hnd.1 (by rw [h]; exact List.mem_map.mpr ⟨e, he, rfl⟩)

/-- With requests in the batch, the lines its commit decides for a covered request's payment are exactly that request's. -/
theorem lines_req {st : Run.St} {cov : Run.Req → Bool} (hok : ReqsOk st.reqs) (hn : st.reqs.isEmpty = false)
    {e : Run.Req} (he : e ∈ st.reqs.toList) (hc : cov e = true) : (st.lines cov).filter (·.pay == e.q) = e.ls := by
  simp only [Run.St.lines, hn]
  exact filter_own _ (hok.1.sublist ((List.filter_sublist).map _)) (fun e he' => reqsOk_pay hok e (List.mem_filter.mp he').1)
    (List.mem_filter.mpr ⟨he, hc⟩)

/-- A request's leaf before release by cause and the exact-repeat answer: on a batch no cap touches, over an index
    faithful to `rel` and `unr`, `Run.emitWith` over the index's payment outcome, bypass test and re-decision test and
    all the batch's decisions is the Spec's `Run.emit` over the Spec's decisions, so the authority laws of `Run.emit`
    (`EmitLaws`) hold of it.  The leaf the worker writes is `Run.causeLeaf` of it, answered or not as
    `ExactDuplicate.answerLeaf` says (`commit_leaves`). -/
theorem pay_req (H : Bytes → Bytes) (s : St) (c : Ctx) (rel unr : Snapshot Line) (f : List Nat) (b : List Line)
    (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr) (hb : Uncapped (fetch s c.redo b) (Worker.feedsOf c) b)
    (hsh : Bytes → Bytes) (g : Authority.Grant) (bps : List Authority.Bypass) (u : Nat → Bool) (e : Run.Req) :
    let fc : FCtx := ⟨c.today, c.redo, Worker.feedsOf c, c.byp, c.lim⟩
    let fe := fetch s fc.redo b
    let ds := (decideFetched s.rel.head s.unr.head fe fc f b).1
    let x := localIx s.rel.head s.unr.head fe (localRows fe.rel) (localRows fe.unr) fc b
    let spec := (decideBatchIn (carried c rel unr) f b).decisions
    Run.emitWith hsh g bps (x.payOutcome ds) (x.bypassed ds) x.redo.contains ds u e =
      Run.emit hsh g bps (carried c rel unr) spec u e := by
  intro fc fe ds x spec
  obtain ⟨hds, hx⟩ : ds = spec ∧ x.payOutcome ds = payOutcome (carried c rel unr) spec := pay_eq H s c rel unr f b hr hu hb
  have hc : FCtxInv fc c := feedsOf_inv c
  have hpb : x.bypassed ds = bypassed (carried c rel unr) spec := funext fun q => by
    rw [show x = locIx s fc b from rfl, bypassed_loc hu hc hb (fetched_lines s.rel.head s.unr.head fe fc f b) q,
      bypassed_eq]
    exact congrArg (fun d => bypassed (carried c rel unr) d q) hds
  have hrd : x.redo.contains = (carried c rel unr).redo.contains := funext fun q => by
    rw [show x = locIx s fc b from rfl, redo_loc (rel := rel) (unr := unr) (b := b) hc, redo_contains]
  unfold Run.emit
  rw [hx, hpb, hrd, hds]

/-! ## A commit's leaves, records and notes over `ExactDuplicate.decideBatchX`

    `Worker.commitBin` decides a batch with requests once and reads each payment's own decisions (`Worker.byPay`).  It
    writes for each request `Worker.leafAt` of `Worker.payOf` (`Run.emitWith`, then `Run.causeLeaf`), for each decided
    line a record whose set is `Worker.ruleOf`, the unresolved lines less those of the payments `Run.answering` answers
    (it decides the payments of the requests that contest, `Worker.contested`, as before), and the approval notes
    (`Run.bypNotes`, `Run.causeNotes`).  `commit_leaves`: on a batch no cap touches, over an index faithful to `rel` and
    `unr`, each of these is the Spec's over `ExactDuplicate.decideBatchX`'s decisions at the payments `Run.answering`
    decides as contested, and a payment whose sender contests is never answered.  `contested_mem`: those are exactly the
    payments of the requests that contest.  `causeLeaf_cases`: release by cause changes a leaf only to ALLOW with its
    record's id, for a payment the record lists, with no unfit line, that the rules release for an approval
    (`bypassed`: held here, not decided again, and every reason left on its lines one the approval overrides; a held
    payment whose facts have since cleared has none left).  `approvals_id`: that id is the id of an admitted record
    that lists the request and judges it, and whose cause pair is the one the rules read for the payment.
    `leaf_capped`: in any batch, capped or not, a payment with a capped line is neither released for an approval nor
    lifted at HOLD authority, and the leaf written for its request is not ALLOW and names no approval.

    Mutants and what kills them: `causeLeafM1` (`Run.causeLeaf` without the test that the rules release the payment for
    an approval) gives ALLOW in its `#guard`, where `Run.causeLeaf` gives HOLD, and the `example` after it shows that
    `causeLeaf_cases`'s statement is false of it; `contestedM1` (the contest flag inverted) fails `contested_mem` and its
    `#guard`.  A `Run.causeLeaf` that never releases fails the positive `#guard`; a `Worker.leafAt` body edit, or one
    that answers when the earlier list cannot be written, fails the leaf pins (the outcome `leafAt` gives
    `answerLeaf` does not change whether it answers, its `example`); a `Worker.ruleOf` that drops a test of its first
    three branches, or swaps two of its sets, fails its `#guard`, except the second branch's `!own`, which decides
    nothing (its `example`). -/

private theorem any_pay (ds : List Decision) (p : Nat) (g : Decision → Bool) :
    (ds.filter (·.line.pay == p)).any (fun d => d.line.pay == p && g d) = ds.any (fun d => d.line.pay == p && g d) := by
  induction ds with
  | nil => rfl
  | cons d ds ih => cases h : d.line.pay == p <;> simp [h, ih]

private theorem all_pay (ds : List Decision) (p : Nat) (g : Decision → Bool) :
    (ds.filter (·.line.pay == p)).all (fun d => d.line.pay != p || g d) = ds.all (fun d => d.line.pay != p || g d) := by
  induction ds with
  | nil => rfl
  | cons d ds ih => cases h : d.line.pay == p <;> simp [h, bne]

private theorem payOutcome_filter (c : Ctx) (ds : List Decision) (p : Nat) :
    payOutcome c (ds.filter (·.line.pay == p)) p = payOutcome c ds p := by
  simp only [payOutcome, List.filter_filter, Bool.and_self]

private theorem bypassed_filter (c : Ctx) (ds : List Decision) (p : Nat) :
    bypassed c (ds.filter (·.line.pay == p)) p = bypassed c ds p := by
  unfold bypassed
  cases c.byp.lookup p with
  | none => rfl
  | some m => simp only [any_pay, all_pay]

private theorem lifts_filter (m : Nat) (ds : List Decision) (p : Nat) (o : Outcome) :
    lifts m (ds.filter (·.line.pay == p)) p o = lifts m ds p o := by
  simp only [lifts, all_pay, List.any_filter, Bool.and_self]

private theorem limitedPay_filter (c : Ctx) (ds : List Decision) (p : Nat) :
    limitedPay c (ds.filter (·.line.pay == p)) p = limitedPay c ds p := by
  unfold limitedPay
  cases c.lim.lookup p with
  | none => rfl
  | some m => simp only [payOutcome_filter, lifts_filter]

private theorem leafReasons_filter (ds : List Decision) (u : Nat → Bool) (p : Nat) :
    Run.leafReasons (ds.filter (·.line.pay == p)) u p = Run.leafReasons ds u p := by
  simp only [Run.leafReasons, List.filter_filter, Bool.and_self]

/-- `Run.emitWith` reads only the decisions of the request's own payment. -/
private theorem emitWith_filter (hsh : Bytes → Bytes) (g : Authority.Grant) (bps : List Authority.Bypass)
    (out : Nat → Outcome) (byd rdo : Nat → Bool) (ds : List Decision) (unf : Nat → Bool) (e : Run.Req) :
    Run.emitWith hsh g bps out byd rdo (ds.filter (·.line.pay == e.q)) unf e = Run.emitWith hsh g bps out byd rdo ds unf e := by
  simp only [Run.emitWith, Run.limited, lifts_filter, leafReasons_filter]

private theorem payOf_eq {hsh : Bytes → Bytes} {g : Authority.Grant} {bps : List Authority.Bypass} {ap : Run.Approvals}
    {out : Nat → Outcome} {byd rdo : Nat → Bool} {grp : Nat → List Decision} {unf : Nat → Bool} {e : Run.Req}
    {c : Ctx} {ds : List Decision} (ho : out = payOutcome c ds) (hb : byd = bypassed c ds) (hr : rdo = c.redo.contains)
    (hg : grp e.q = ds.filter (·.line.pay == e.q)) :
    Worker.payOf hsh g bps ap out byd rdo grp unf e =
      Run.causeLeaf ap (bypassed c ds) unf ((Run.emit hsh g (Run.bypsFor hsh bps e) c ds unf e).getD (Run.uncovered g e)) := by
  subst ho hb hr
  unfold Worker.payOf Run.emit
  rw [hg, emitWith_filter]

private theorem leafAt_eq {c c' : Ctx} {k : List Nat} {ds ds' : List Decision} {unf : Nat → Bool} {m : Run.Pay}
    {rq : ByteArray} (ha : answered c k ds m.q = answered c' k ds' m.q)
    (he : Run.earlierBody c ds m.q = Run.earlierBody c' ds' m.q) :
    Worker.leafAt c k ds unf m rq = Worker.leafAt c' k ds' unf m rq := by
  unfold Worker.leafAt answerLeaf
  rw [ha, he]

private theorem rule_unres (al pa rd byd lim own ad ownU ans : Bool) :
    ((if al && !rd && pa then Frame.Rule.released else if byd || lim && !own then Frame.Rule.bypassed
      else if !al && !ad && !own && !ownU && !ans then Frame.Rule.unresolved else Frame.Rule.decided) ==
        Frame.Rule.unresolved) = (!ans && (!al && !ad && !own && !ownU && !byd && !lim)) := by
  cases al <;> cases pa <;> cases rd <;> cases byd <;> cases lim <;> cases own <;> cases ad <;> cases ownU <;>
    cases ans <;> rfl

private theorem ruleOf_unres {x : Ix} {grp : Nat → List Decision} {ans : Std.HashSet Nat} {c : Ctx} {k : List Nat}
    {ds : List Decision} {d : Decision}
    (hrd : x.redo.contains d.line.pay = c.redo.contains d.line.pay)
    (ho : x.payOutcome (grp d.line.pay) d.line.pay = payOutcome c ds d.line.pay)
    (hb : x.bypassed (grp d.line.pay) d.line.pay = bypassed c ds d.line.pay)
    (hl : x.limitedPay (grp d.line.pay) d.line.pay = limitedPay c ds d.line.pay)
    (hw : x.own d.line = own c d.line) (hu : x.ownU d.line = ownU c d.line)
    (ha : ans.contains d.line.pay = answered c k ds d.line.pay) :
    (Worker.ruleOf x grp ans d == .unresolved) = (!answered c k ds d.line.pay && (d.outcome != .ALLOW &&
      !d.reasons.contains .ALREADY_DECIDED && !own c d.line && !ownU c d.line && !bypassed c ds d.line.pay &&
      !limitedPay c ds d.line.pay)) := by
  unfold Worker.ruleOf
  rw [hrd, ho, hb, hl, hw, hu, ha]
  exact rule_unres (d.outcome == .ALLOW) (payOutcome c ds d.line.pay == .ALLOW) _ _ _ _ _ _ _

/-- The payments `Worker.commitBin` passes to `Run.answering` as contested are those of the requests that contest. -/
theorem contested_mem (reqs : List Run.Req) (p : Nat) :
    p ∈ Worker.contested reqs ↔ ∃ e ∈ reqs, e.ra.contest = true ∧ e.q = p := by
  unfold Worker.contested
  simp only [List.mem_filterMap]
  constructor
  · rintro ⟨e, he, h⟩
    by_cases hc : e.ra.contest = true
    · rw [if_pos hc] at h
      exact ⟨e, he, hc, Option.some.inj h⟩
    · rw [if_neg hc] at h
      cases h
  · rintro ⟨e, he, hc, rfl⟩
    exact ⟨e, he, if_pos hc⟩

/-- Release by cause changes a leaf only to ALLOW with the id of the record that lists its payment, and only for a
    payment with no unfit line that the rules release for an approval (`bypassed`, over the Spec's decisions in
    `commit_leaves`: held here, and every reason left on its lines overridden, or none left once its facts cleared);
    the id is never zero. -/
theorem causeLeaf_cases (a : Run.Approvals) (byd unf : Nat → Bool) (m : Run.Pay) :
    Run.causeLeaf a byd unf m = m ∨ ∃ id, a.ids.lookup m.q = some id ∧ unf m.q = false ∧ byd m.q = true ∧
      id ≠ Gate.zeroDigest ∧ Run.causeLeaf a byd unf m = { m with outcome := .ALLOW, bypass := id } := by
  cases h : a.ids.lookup m.q with
  | none => left; simp [Run.causeLeaf, h]
  | some id =>
    cases hu : unf m.q <;> cases hb : byd m.q
    all_goals first
      | (left; simp [Run.causeLeaf, h, hu, hb]; done)
      | skip
    by_cases hz : id = Gate.zeroDigest
    · left; simp [Run.causeLeaf, h, hu, hb, hz]
    · right; exact ⟨id, rfl, rfl, rfl, hz, by simp [Run.causeLeaf, h, hu, hb, hz]⟩

/-- A commit with requests (`Worker.commitBin`): on a batch no cap touches, over an index faithful to `rel` and `unr`,
    with the payments of the requests `reqs` that contest decided as contested (`Worker.contested`):
    the worker's decisions are `ExactDuplicate.decideBatchX`'s; the lines it adds to the released and unresolved sets
    (the unresolved less the answered payments') are that batch's; the decided lines its records name unresolved
    (`Worker.ruleOf`) are those lines; each request's leaf (`Worker.payOf`, `Worker.leafAt`) is the Spec's: `Run.causeLeaf`
    of `Run.emit` over those decisions, answered with its earlier list as `ExactDuplicate.answerLeaf` and
    `Run.earlierBody` say over them; its approval notes are the Spec's; and a payment whose sender contests is never
    answered. -/
theorem commit_leaves (H : Bytes → Bytes) (s : St) (c : Ctx) (rel unr : Snapshot Line) (b : List Line)
    (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr) (hb : Uncapped (fetch s c.redo b) (Worker.feedsOf c) b)
    (hsh : Bytes → Bytes) (g : Authority.Grant) (bps : List Authority.Bypass) (ap : Run.Approvals)
    (reqs : List Run.Req) (unf : Nat → Bool) :
    let fc : FCtx := ⟨c.today, c.redo, Worker.feedsOf c, c.byp, c.lim⟩
    let fe := fetch s fc.redo b
    let r := decideFetched s.rel.head s.unr.head fe fc [] b
    let x := Worker.leafIx s.rel.head s.unr.head fe fc b
    let grp := Worker.leafGrp (Worker.byPay r.1)
    let byd := Worker.leafByd x (Worker.byPay r.1)
    let ax := Run.answering c (Worker.relRows (HashMap.ofList fe.rel)) (Worker.contested reqs) r.1
    let sc := carried c rel unr
    let X := decideBatchX sc ax.k b
    r.1 = X.decisions ∧
    (r.2.1, r.2.2.filter fun l => !ax.pays.contains l.pay) = batchFresh sc X ∧
    (r.1.filter (Worker.ruleOf x grp ax.pays · == .unresolved)).map (·.line) = (batchFresh sc X).2 ∧
    (∀ e rq, Worker.leafAt ax.c ax.k ax.ds unf
        (Worker.payOf hsh g bps ap (fun p => x.payOutcome (grp p) p) byd x.redo.contains grp unf e) rq =
      Worker.leafAt sc ax.k X.decisions unf (Run.causeLeaf ap (bypassed sc X.decisions) unf
        ((Run.emit hsh g (Run.bypsFor hsh bps e) sc X.decisions unf e).getD (Run.uncovered g e))) rq) ∧
    Run.bypNotes hsh bps reqs byd ++ Run.causeNotes ap byd =
      Run.bypNotes hsh bps reqs (bypassed sc X.decisions) ++ Run.causeNotes ap (bypassed sc X.decisions) ∧
    ∀ e ∈ reqs, e.ra.contest = true → ∀ o,
      answerLeaf sc ax.k X.decisions unf o e.q = if unf e.q then .HOLD else .ofOutcome o := by
  intro fc fe r x grp byd ax sc X
  have hc : FCtxInv fc c := feedsOf_inv c
  have hR : r = ((decideBatchIn sc [] b).decisions, batchFresh sc (decideBatchIn sc [] b)) :=
    decideBatchIdx_eq H s fc c rel unr [] b hr hu hc hb
  have hds : r.1 = X.decisions := congrArg Prod.fst hR
  have hdsA : r.1 = decideAll sc (seen0 sc b) (order sc b) := hds
  have hl : ∀ d ∈ r.1, d.line ∈ b := fetched_lines _ _ _ _ _ _
  have hl' : ∀ d ∈ X.decisions, d.line ∈ b := fun d hd => hl d (hds ▸ hd)
  have hgrp : ∀ p, grp p = X.decisions.filter (·.line.pay == p) := fun p =>
    (group_getD (fun d : Decision => d.line.pay) r.1 p).trans (by rw [hds])
  have hlg : ∀ p, ∀ d ∈ grp p, d.line ∈ b := fun p d hd => by
    rw [hgrp p] at hd
    exact hl' d (List.mem_filter.mp hd).1
  have hx : x = locIx s fc b := rfl
  have hrdo : x.redo.contains = sc.redo.contains := funext fun q => by
    show x.redo.contains q = (carried c rel unr).redo.contains q
    rw [hx, redo_loc (rel := rel) (unr := unr) (b := b) hc, redo_contains]
  have hout : (fun p => x.payOutcome (grp p) p) = payOutcome sc X.decisions := funext fun p => by
    show x.payOutcome (grp p) p = payOutcome (carried c rel unr) X.decisions p
    rw [hx, payOutcome_loc (unr := unr) hr hc hb (hlg p) p, payOutcome_eq, hgrp p, payOutcome_filter]
  have hbyd : byd = bypassed sc X.decisions := funext fun p => by
    show x.bypassed (grp p) p = bypassed (carried c rel unr) X.decisions p
    rw [hx, bypassed_loc (rel := rel) hu hc hb (hlg p) p, bypassed_eq, hgrp p, bypassed_filter]
  have hlim : ∀ p, x.limitedPay (grp p) p = limitedPay (carried c rel unr) X.decisions p := fun p => by
    rw [hx, limitedPay_loc (unr := unr) hr hc hb (hlg p) p, limitedPay_eq, hgrp p, limitedPay_filter]
  have hrows : ∀ d ∈ r.1, ∀ rs, Worker.relRows (HashMap.ofList fe.rel) (exactKey d.line) = some rs →
      rs = (releasedSet sc).filter (exactKey · == exactKey d.line) := fun d hd rs h =>
    ((Option.some.inj ((rows_read hr hb (hl d hd)).symm.trans h)).symm).trans
      (congrArg (List.filter _) (carried_rel c rel unr).symm)
  have hall : ∀ d ∈ r.1, (Worker.relRows (HashMap.ofList fe.rel) (exactKey d.line)).isSome = true := fun d hd =>
    (congrArg Option.isSome (rows_read hr hb (hl d hd))).trans rfl
  have hpays : ∀ p, ax.pays.contains p = answered sc ax.k X.decisions p := fun p =>
    (Run.answering_pays (c' := c) (k := Worker.contested reqs) hdsA rfl hrows p).1.trans (congrArg (answered sc ax.k · p) hds)
  have hfx : (batchFresh sc X).2 = unresolvedLinesX sc ax.k X.decisions := by
    show List.drop (unresolvedSet sc).length (unresolvedSet sc ++ unresolvedLinesX sc ax.k X.decisions) = _
    exact List.drop_left
  have hfu : r.2.2 = unresolvedLines sc X.decisions := by
    rw [hR]
    show List.drop (unresolvedSet sc).length (unresolvedSet sc ++ unresolvedLines sc X.decisions) = _
    exact List.drop_left
  have hfr : r.2.1 = (batchFresh sc X).1 := (congrArg (·.2.1) hR).trans rfl
  refine ⟨hds, Prod.ext hfr ?_, ?_, fun e rq => ?_, by rw [hbyd], fun e he hcon o => ?_⟩
  · show r.2.2.filter (fun l => !ax.pays.contains l.pay) = (batchFresh sc X).2
    rw [hfx, hfu]
    exact List.filter_congr fun l _ => by simp only [hpays]
  · rw [hfx, hds]
    unfold unresolvedLinesX unresolvedLines
    rw [List.filter_map, List.filter_filter]
    congr 1
    exact List.filter_congr fun d hd => ruleOf_unres (congrFun hrdo _) (congrFun hout _) (congrFun hbyd _) (hlim _)
      (own_b (unr := unr) hr hc hb (hl' d hd)) ((ownU_loc (rel := rel) hu hc hb (hl' d hd)).trans ownU_eq) (hpays _)
  · rw [payOf_eq (grp := grp) (e := e) hout hbyd hrdo (hgrp e.q)]
    refine leafAt_eq ?_ ?_
    · exact (Run.answering_pays (c' := c) (k := Worker.contested reqs) hdsA rfl hrows _).2.trans (congrArg (answered sc ax.k · _) hds)
    · exact (Run.answering_earlierBody (c' := c) (k := Worker.contested reqs) hdsA rfl hrows hall _).trans (congrArg (Run.earlierBody sc · _) hds)
  · have hk : ax.k.contains e.q = true :=
      List.contains_iff_mem.mpr (List.mem_append_left _ ((contested_mem reqs e.q).mpr ⟨e, he, hcon, rfl⟩))
    exact (contested_as_before hk unf o).1

/-- Mutant: `Run.causeLeaf` without the test that the rules release the payment for an approval. -/
def causeLeafM1 (a : Run.Approvals) (_byd unf : Nat → Bool) (p : Run.Pay) : Run.Pay :=
  match a.ids.lookup p.q with
  | some id => if !unf p.q && id != Gate.zeroDigest then { p with outcome := .ALLOW, bypass := id } else p
  | none => p

private def vPay : Run.Pay := ⟨5, .HOLD, "MEMBER_DECEASED", .HOLD, [], Gate.zeroDigest⟩
private def vAp : Run.Approvals := ⟨[], [], [(5, List.replicate 64 7)], []⟩

-- payment 5's record pair stands but the rules do not hold it for an approval: the real leaf stays HOLD
#guard (Run.causeLeaf vAp (fun _ => false) (fun _ => false) vPay).outcome == .HOLD
#guard (causeLeafM1 vAp (fun _ => false) (fun _ => false) vPay).outcome == .ALLOW
-- released for an approval: ALLOW with the record's id, every other field as it was; with an unfit line, as it was
#guard
  let p := Run.causeLeaf vAp (fun _ => true) (fun _ => false) vPay
  p.outcome == .ALLOW && p.bypass == List.replicate 64 7 && p.q == 5 && p.reasons == vPay.reasons && p.grantId == []
#guard (Run.causeLeaf vAp (fun _ => true) (fun _ => true) vPay).outcome == .HOLD

-- `causeLeaf_cases`'s statement is false of the mutant
example : ¬ ∀ (a : Run.Approvals) (byd unf : Nat → Bool) (m : Run.Pay), causeLeafM1 a byd unf m = m ∨
    ∃ id, a.ids.lookup m.q = some id ∧ unf m.q = false ∧ byd m.q = true ∧ id ≠ Gate.zeroDigest ∧
      causeLeafM1 a byd unf m = { m with outcome := .ALLOW, bypass := id } := by
  intro h
  rcases h vAp (fun _ => false) (fun _ => false) vPay with h | ⟨_, _, _, h, _⟩
  · exact absurd (congrArg Run.Pay.outcome h) (by decide)
  · cases h

/-- Mutant: the contest flag inverted. -/
def contestedM1 (reqs : List Run.Req) : List Nat := reqs.filterMap fun e => if !e.ra.contest then some e.q else none

private def vReq (q : Nat) (k : Bool) : Run.Req :=
  ⟨q, ⟨.empty, .empty, .FFS_CLAIM, .empty, .empty, .empty, .empty, 0, .empty, [], [], k⟩, [], .empty⟩

#guard Worker.contested [vReq 1 false, vReq 2 true] == [2]
#guard contestedM1 [vReq 1 false, vReq 2 true] == [1]

/-- Pins of `Worker.leafAt`: a payment one of whose lines repeats a paid line, its sender not contesting. -/
private def vTwin : Line := ⟨257, 265, .FFS_CLAIM, 1, 4, 5, 20270310, 99213, 1, 9200⟩
private def vAnsCtx : Ctx :=
  { today := 20270315, dmf := none, providerDeaths := none, exclusions := none, enrollment := none, released := none,
    unresolved := none, releasedPrior := ⟨0, 1, [vTwin]⟩, unresolvedPrior := ⟨0, 0, []⟩, anchor := 0, redo := [] }
private def vAnsDs : List Decision := [⟨{ vTwin with id := 258, pay := 261 }, .HOLD, [.FFS_DUPLICATE_LINE], []⟩]
private def vAnsPay : Run.Pay := ⟨261, .HOLD, "FFS_DUPLICATE_LINE", .TRANSFER, [], Gate.zeroDigest⟩
private def vRq : ByteArray := ⟨#[1, 2, 3]⟩

-- answered: ANSWERED (3) with its earlier list, every other field the payment's own leaf
#guard (Run.earlierBody vAnsCtx vAnsDs 261).isSome &&
  Worker.leafAt vAnsCtx [] vAnsDs (fun _ => false) vAnsPay vRq ==
    { Worker.leafOf vAnsPay vRq with outcome := 3, earlier := ((Run.earlierBody vAnsCtx vAnsDs 261).getD []).toByteArray }
-- contested, or with an unfit line: the payment's own leaf
#guard Worker.leafAt vAnsCtx [261] vAnsDs (fun _ => false) vAnsPay vRq == Worker.leafOf vAnsPay vRq
#guard Worker.leafAt vAnsCtx [] vAnsDs (fun _ => true) vAnsPay vRq == Worker.leafOf vAnsPay vRq
-- answered, but its earlier list names one line id twice and cannot be written: the payment's own leaf
#guard Rules.answerLeaf vAnsCtx [] (vAnsDs ++ vAnsDs) (fun _ => false) .HOLD 261 == .ANSWERED &&
  (Run.earlierBody vAnsCtx (vAnsDs ++ vAnsDs) 261).isNone &&
  Worker.leafAt vAnsCtx [] (vAnsDs ++ vAnsDs) (fun _ => false) vAnsPay vRq == Worker.leafOf vAnsPay vRq
-- `leafAt` reads only whether `answerLeaf` answers, which does not depend on the outcome it is given
example (c : Ctx) (k : List Nat) (ds : List Decision) (unf : Nat → Bool) (o : Outcome) (p : Nat) :
    Rules.answerLeaf c k ds unf o p = .ANSWERED ↔ Rules.answerLeaf c k ds unf .HOLD p = .ANSWERED := by
  unfold Rules.answerLeaf
  by_cases h1 : unf p <;> by_cases h2 : Rules.answered c k ds p <;> cases o <;>
    simp [h1, h2, Rules.AnswerOutcome.ofOutcome]

/-- A pin of `Worker.ruleOf`: payment 1 ALLOW; payment 2 held here, its approval overriding its one reason; payment 3
    held; payment 4 ALLOW and decided again, its line released before; payment 5 an ALLOW line beside a held one;
    payment 7 held and lifted at HOLD authority; payment 8 held as decided already; payment 9 held, decided again, its
    line released before; payment 10 held, its line held before, its approval not overriding its reason. -/
private def vL (id : Nat) : Line := ⟨id, id, .FFS_CLAIM, 1, 4, 5, 20270310, 99213, 1, 9200 + id⟩
private def vRuleCtx : Ctx :=
  { today := 20270315, dmf := none, providerDeaths := none, exclusions := none, enrollment := none, released := none,
    unresolved := none, releasedPrior := ⟨0, 2, [vL 4, vL 9]⟩, unresolvedPrior := ⟨0, 2, [vL 2, vL 10]⟩, anchor := 0,
    redo := [4, 9], byp := [(2, 2 ^ Reason.MEMBER_DECEASED.idx), (10, 2 ^ Reason.SERVICE_DATE_FUTURE.idx)],
    lim := [(7, 2 ^ Reason.SERVICE_DATE_FUTURE.idx)] }
private def vRuleDs : List Decision :=
  [⟨vL 1, .ALLOW, [], []⟩, ⟨vL 2, .HOLD, [.MEMBER_DECEASED], []⟩, ⟨vL 3, .HOLD, [.MEMBER_DECEASED], []⟩, ⟨vL 4, .ALLOW, [], []⟩,
    ⟨vL 5, .ALLOW, [], []⟩, ⟨{ vL 6 with pay := 5 }, .HOLD, [.MEMBER_DECEASED], []⟩, ⟨vL 7, .HOLD, [.MEMBER_DECEASED], []⟩,
    ⟨vL 8, .HOLD, [.ALREADY_DECIDED], []⟩, ⟨vL 9, .HOLD, [.MEMBER_DECEASED], []⟩, ⟨vL 10, .HOLD, [.MEMBER_DECEASED], []⟩]
private def vRuleIx : Ix := Ix.build vRuleCtx (vRuleDs.map (·.line))

#guard vRuleDs.map (Worker.ruleOf vRuleIx (fun p => vRuleDs.filter (·.line.pay == p)) ∅) ==
  [Frame.Rule.released, Frame.Rule.bypassed, Frame.Rule.unresolved, Frame.Rule.decided, Frame.Rule.decided,
    Frame.Rule.unresolved, Frame.Rule.bypassed, Frame.Rule.decided, Frame.Rule.decided, Frame.Rule.decided]
-- `!own` beside `limitedPay` in its second branch decides nothing: a lifted payment is never decided again
example (x : Ix) (ds : List Decision) (l : Line) : (x.limitedPay ds l.pay && !x.own l) = x.limitedPay ds l.pay := by
  unfold Ix.limitedPay Ix.own
  split <;> cases x.redo.contains l.pay <;> simp
-- an answered payment's held line joins no set
#guard vRuleDs.map (Worker.ruleOf vRuleIx (fun p => vRuleDs.filter (·.line.pay == p)) (Std.HashSet.ofList [3])) ==
  [Frame.Rule.released, Frame.Rule.bypassed, Frame.Rule.decided, Frame.Rule.decided, Frame.Rule.decided,
    Frame.Rule.unresolved, Frame.Rule.bypassed, Frame.Rule.decided, Frame.Rule.decided, Frame.Rule.decided]

/-! ## A capped line: its payment is never released for an approval or lifted

    `Uncapped` is a property of the whole batch, so `commit_leaves` says nothing of a batch a cap touches.  A capped
    line is HOLD with `POSTING_CAP` (`cap_hold`), a reason no approval overrides and no holds mask lifts (`bypassable`).
    `leaf_capped`: in any batch, the payment of a capped line is not released for an approval (so release by cause
    leaves its leaf alone) and not lifted at HOLD authority, and the leaf the worker writes for its request is not ALLOW
    and names no approval. -/

/-- A payment with a decided line carrying a reason no approval overrides is never released for an approval and never
    lifted at HOLD authority, whatever the masks. -/
theorem unbypassable_pay (x : Ix) {ds : List Decision} {d : Decision} (hd : d ∈ ds) {r : Reason} (hr : r ∈ d.reasons)
    (hb : bypassable r = false) : x.bypassed ds d.line.pay = false ∧ ∀ m o, lifts m ds d.line.pay o = false := by
  have key : ∀ t : Reason → Bool,
      (ds.all fun e => e.line.pay != d.line.pay || e.reasons.all fun r => bypassable r && t r) = true → False := by
    intro t h
    simp only [List.all_eq_true] at h
    have e := h d hd
    simp only [bne_self_eq_false, Bool.false_or, List.all_eq_true] at e
    have := e r hr
    simp [hb] at this
  refine ⟨?_, fun m o => ?_⟩
  · cases h : x.bypassed ds d.line.pay
    · rfl
    · exfalso
      unfold Ix.bypassed at h
      cases hm : x.byp.lookup d.line.pay with
      | none => simp [hm] at h
      | some m =>
        simp only [hm, Bool.and_eq_true] at h
        exact key (fun r => m >>> r.idx % 2 == 1) h.2
  · cases h : lifts m ds d.line.pay o
    · rfl
    · exfalso
      unfold lifts at h
      simp only [Bool.and_eq_true] at h
      exact key (fun r => !(m >>> r.idx % 2 == 1)) h.2

/-- A request's leaf before an exact-repeat answer, when its payment is not released for an approval, is not lifted
    and its rules outcome is not ALLOW: not ALLOW, and naming no approval. -/
private theorem payOf_unreleased {hsh : Bytes → Bytes} {g : Authority.Grant} {bps : List Authority.Bypass}
    {ap : Run.Approvals} {out : Nat → Outcome} {byd rdo : Nat → Bool} {grp : Nat → List Decision} {unf : Nat → Bool}
    {e : Run.Req} (hb : byd e.q = false) (hl : ∀ m, lifts m (grp e.q) e.q (out e.q) = false) (ho : out e.q ≠ .ALLOW) :
    (Worker.payOf hsh g bps ap out byd rdo grp unf e).outcome ≠ .ALLOW ∧
      (Worker.payOf hsh g bps ap out byd rdo grp unf e).bypass = Gate.zeroDigest := by
  have hpre : ((Run.emitWith hsh g (Run.bypsFor hsh bps e) out byd rdo (grp e.q) unf e).getD (Run.uncovered g e)).q = e.q ∧
      ((Run.emitWith hsh g (Run.bypsFor hsh bps e) out byd rdo (grp e.q) unf e).getD (Run.uncovered g e)).outcome ≠ .ALLOW ∧
      ((Run.emitWith hsh g (Run.bypsFor hsh bps e) out byd rdo (grp e.q) unf e).getD (Run.uncovered g e)).bypass =
        Gate.zeroDigest := by
    unfold Run.emitWith
    cases Authority.entryFor g e.r.programId e.r.flow with
    | none =>
      refine ⟨rfl, ?_, rfl⟩
      show (if e.r.flow.ruled then Outcome.HOLD else .HUMAN_REVIEW) ≠ .ALLOW
      split <;> simp
    | some en =>
      simp only [Option.bind_eq_bind, Option.bind_some, Option.getD_some, Option.pure_def]
      repeat' split
      all_goals simp_all [Run.limited]
  unfold Worker.payOf
  obtain ⟨hq, h1, h2⟩ := hpre
  generalize (Run.emitWith hsh g (Run.bypsFor hsh bps e) out byd rdo (grp e.q) unf e).getD (Run.uncovered g e) = p at hq h1 h2
  unfold Run.causeLeaf
  split
  · rw [hq, hb]; simp only [Bool.and_false, Bool.false_and, Bool.false_eq_true, if_false]; exact ⟨h1, h2⟩
  · exact ⟨h1, h2⟩

/-- A payment with a capped line, in any batch (`Uncapped` or not): the worker's bypass test is false for it and no
    holds mask lifts it, so the leaf written for its request (`Worker.payOf`, then `Worker.leafAt` over any answering
    context) is not ALLOW and names no approval; release by cause leaves it alone (`Run.causeLeaf` needs the bypass
    test). -/
theorem leaf_capped (hr hu : Head) (fe : Fetched) (fc : FCtx) (f : List Nat) (b : List Line) (hsh : Bytes → Bytes)
    (g : Authority.Grant) (bps : List Authority.Bypass) (ap : Run.Approvals) (unf : Nat → Bool) (e : Run.Req)
    (c : Ctx) (k : List Nat) (ds' : List Decision) (rq : ByteArray) :
    let ds := (decideFetched hr hu fe fc f b).1
    let x := Worker.leafIx hr hu fe fc b
    let grp := Worker.leafGrp (Worker.byPay ds)
    let byd := Worker.leafByd x (Worker.byPay ds)
    let m := Worker.payOf hsh g bps ap (fun p => x.payOutcome (grp p) p) byd x.redo.contains grp unf e
    ∀ d ∈ ds, d.line.pay = e.q → capped (hotKeys fe fc.feeds b) fe fc.feeds d.line = true →
      byd e.q = false ∧ (∀ h o, lifts h (grp e.q) e.q o = false) ∧ m.outcome ≠ .ALLOW ∧
      m.bypass = Gate.zeroDigest ∧ (Worker.leafAt c k ds' unf m rq).outcome ≠ Frame.outCode .ALLOW ∧
      (Worker.leafAt c k ds' unf m rq).bypass = Gate.zeroDigest.toByteArray := by
  intro ds x grp byd m d hd hp hcap
  obtain ⟨hh, hcp⟩ := cap_hold hr hu fe fc f b d hd hcap
  have hg' : grp e.q = ds.filter (·.line.pay == e.q) := group_getD (fun d : Decision => d.line.pay) ds e.q
  have hg : d ∈ grp e.q := by
    rw [hg']
    exact List.mem_filter.mpr ⟨hd, by simp [hp]⟩
  obtain ⟨hby, hli⟩ := unbypassable_pay x hg hcp rfl
  rw [hp] at hby hli
  have hout : x.payOutcome (grp e.q) e.q = .HOLD := by
    unfold Ix.payOutcome
    have : ((grp e.q).filter (·.line.pay == e.q)).any (·.outcome == .HOLD) = true :=
      List.any_eq_true.mpr ⟨d, List.mem_filter.mpr ⟨hg, by simp [hp]⟩, by simp [hh]⟩
    simp [this]
  obtain ⟨h1, h2⟩ := payOf_unreleased (hsh := hsh) (g := g) (bps := bps) (ap := ap) (rdo := x.redo.contains)
    (unf := unf) (out := fun p => x.payOutcome (grp p) p) (byd := byd) (grp := grp) (e := e) hby (fun h => hli h _)
    (by simp [hout])
  refine ⟨hby, hli, h1, h2, ?_⟩
  have h2' : m.bypass = Gate.zeroDigest := h2
  unfold Worker.leafAt Worker.leafOf
  split
  · exact ⟨by simp [Frame.outCode], by simp [h2']⟩
  · refine ⟨?_, by simp [h2']⟩
    show Frame.outCode m.outcome ≠ Frame.outCode .ALLOW
    exact fun heq => h1 (by revert heq; cases m.outcome <;> simp [Frame.outCode])

-- A batch where a line is capped, so `leaf_capped` and `cap_hold` are not vacuous: line 1's member has `capN + 1` death
-- facts in the feed, more than the decider may read.  The line is capped, and is decided HOLD with `POSTING_CAP`.
private def vCapFe : Fetched := ⟨[], [], fun _ => 0, fun _ => 0⟩
private def vCapFd : Feeds :=
  ⟨true, false, false, false, true, true, true, true, fun i => List.replicate (capN + 1) ⟨i, 20270101⟩, fun _ => [],
    fun _ => [], fun _ => []⟩
private def vCapFc : FCtx := ⟨20270315, [], vCapFd, [], []⟩

example : capped (hotKeys vCapFe vCapFd [vL 1]) vCapFe vCapFd (vL 1) = true := by
  have h : feedCapped vCapFd (vL 1) = true := by
    have h1 : feedOver (vCapFd.dmf (vL 1).member) = true := by decide +kernel
    unfold feedCapped
    rw [h1]
    rfl
  unfold capped
  rw [h, Bool.or_true]

#guard (decideFetched ⟨0, 0, 0⟩ ⟨0, 0, 0⟩ vCapFe vCapFc [] [vL 1]).1.map (fun d => (d.outcome, d.reasons.contains .POSTING_CAP)) ==
  [(.HOLD, true)]

/-! ## The record id on a leaf -/

/-- The id release by cause writes on a payment's leaf (`causeLeaf_cases`: the id `Run.Approvals.ids` gives it) is the
    id of an admitted record that lists a request of the batch with that payment number and judges it (`fits`), and
    that record's cause pair for the payment is the one the rules read (`Ctx.byp`, which `bypassed` reads). -/
theorem approvals_id (hsh : Bytes → Bytes) (g : Authority.Grant) (bps : List Authority.Bypass)
    (rs : List CauseRelease.Release) (reqs : List Run.Req) (redo : List Nat) {q : Nat} {id : Bytes}
    (h : (Run.approvals hsh g bps rs reqs redo).ids.lookup q = some id) :
    ∃ r ∈ rs, r.id = id ∧ (∃ e ∈ reqs, e.q = q ∧ CauseRelease.fits r.doc (Run.seenOf hsh g redo e) = true) ∧
      (q, 2 ^ r.doc.cause.idx) ∈ (Run.approvals hsh g bps rs reqs redo).byp := by
  have hm : (q, id) ∈ (Run.approvals hsh g bps rs reqs redo).ids := by
    obtain ⟨_, _, hl, -⟩ := List.lookup_eq_some_iff.mp h
    rw [hl]; simp
  have hne : rs.isEmpty = false := by
    cases hrs : rs.isEmpty
    · rfl
    · rw [List.isEmpty_iff.mp hrs] at hm; simp [Run.approvals] at hm
  simp only [Run.approvals, hne, Bool.false_eq_true, if_false, List.mem_filterMap] at hm ⊢
  obtain ⟨⟨id', q', j⟩, hj, hf⟩ := hm
  cases j with
  | error _ => cases hf
  | ok u =>
    simp only at hf
    split at hf
    · cases hf
    · rename_i hdup
      cases hf
      obtain ⟨r, hr, hrj⟩ := List.mem_flatMap.mp hj
      obtain ⟨s, hs, hl⟩ := List.mem_filterMap.mp hrj
      obtain ⟨en, hen, hp⟩ := Option.map_eq_some_iff.mp hl
      simp only [Prod.mk.injEq] at hp
      obtain ⟨rfl, rfl, hju⟩ := hp
      obtain ⟨e, he, rfl⟩ := List.mem_map.mp hs
      have hfit : CauseRelease.fits r.doc (Run.seenOf hsh g redo e) = true := by
        unfold CauseRelease.fits; rw [hen]; dsimp only; rw [hju]
      refine ⟨r, hr, rfl, ⟨e, he, rfl, hfit⟩, CauseRelease.mem_merge.mpr ⟨?_, ?_⟩⟩
      · refine List.mem_append_right _ (List.mem_flatMap.mpr ⟨r, hr, ?_⟩)
        unfold CauseRelease.pairs
        exact List.mem_map.mpr ⟨_, List.mem_filter.mpr ⟨List.mem_map_of_mem he, hfit⟩, rfl⟩
      · simpa using hdup

/-! ## Fresh facts: a missing or stale fact never lets a payment through -/

/-- Every fact the rules read is present and fresh at the batch's clock `c.today`.  A reference snapshot (member deaths,
    provider deaths, exclusions, enrollment) is fresh when it is dated by its own `asOf` (covered by its pin) on a valid
    day not after `today` and at most its maximum age before it (deaths 90 days, exclusions 31, enrollment 7), and holds
    exactly its declared, nonzero count of well-formed rows (`usable`).  The released and unresolved sets extend the
    gate's checkpoint of them (`chained`). -/
def Fresh (c : Ctx) : Prop :=
  usable c.today 90 okDeath c.dmf = true ∧ usable c.today 90 okDeath c.providerDeaths = true ∧
  usable c.today 31 okExclusion c.exclusions = true ∧ usable c.today 7 okSpan c.enrollment = true ∧
  chained c.today c.releasedPrior c.released = true ∧ chained c.today c.unresolvedPrior c.unresolved = true

/-- An ALLOW line was decided on fresh facts: a missing or stale one fires its `STALE_*` reason, a review reason. -/
theorem allow_fresh {c : Ctx} {seen : List Key} {l : Line} (h : (decideLine c seen l).outcome = .ALLOW) : Fresh c := by
  have no : ∀ r, fires c seen l r = false := fun r => by
    cases hf : fires c seen l r
    · rfl
    · exact (fires_blocks hf h).elim
  exact ⟨by simpa [fires] using no .STALE_DMF, by simpa [fires] using no .STALE_PROVIDER_DEATH,
    by simpa [fires] using no .STALE_EXCLUSION, by simpa [fires] using no .STALE_ENROLLMENT,
    by simpa [fires] using no .STALE_RELEASED, by simpa [fires] using no .STALE_UNRESOLVED⟩

theorem decideAll_allow_fresh {c : Ctx} : ∀ {seen : List Key} {ls : List Line} {d : Decision},
    d ∈ decideAll c seen ls → d.outcome = .ALLOW → Fresh c
  | _, [], _, hd, _ => by simp [decideAll] at hd
  | seen, l :: ls, d, hd, ha => by
    simp only [decideAll, List.mem_cons] at hd
    rcases hd with rfl | hd
    · exact allow_fresh ha
    · exact decideAll_allow_fresh hd ha

/-- A payment's token says ALLOW only on facts fresh at the batch's clock: with any fact missing or stale the payment
    is never ALLOW (its lines go to review, or HOLD where a certain reason also fires). -/
theorem leaf_allow_fresh {c : Ctx} {seen : List Key} {ls : List Line} {u : Nat → Bool} {p : Nat}
    (h : Run.leafOutcome (payOutcome c (decideAll c seen ls)) u p = .ALLOW) : Fresh c := by
  have hall := (Run.leafOutcome_allow h).2
  cases hf : List.filter (fun d => d.line.pay == p) (decideAll c seen ls) with
  | nil =>
    unfold Run.leafOutcome payOutcome at h
    revert h
    cases u p <;> simp [hf]
  | cons d t =>
    have hd : d ∈ List.filter (fun d => d.line.pay == p) (decideAll c seen ls) := by rw [hf]; simp
    have ⟨hm, hp⟩ := List.mem_filter.mp hd
    exact decideAll_allow_fresh hm (hall d hm (by simpa using hp))


/-! ## INPUT/v7: what a token's input and a batch's identity commit to (gate K2, III.3) -/

private theorem lp32_inj {x y r s : Bytes} (hx : x.length < 2 ^ 32) (hy : y.length < 2 ^ 32)
    (h : lp32 x ++ r = lp32 y ++ s) : x = y ∧ r = s := by
  have p : (256 : Nat) ^ 4 = 2 ^ 32 := rfl
  unfold lp32 at h
  simp only [List.append_assoc] at h
  obtain ⟨h1, h2⟩ := List.append_inj h (by simp [natBE])
  have hl : x.length = y.length := by
    have := congrArg beNat h1
    rwa [beNat_natBE' 4 _ (by omega), beNat_natBE' 4 _ (by omega)] at this
  exact List.append_inj h2 hl

/-- XI.2: INPUT/v5 becomes the batch context, `INPUT/v7` and the batch identity.  The context's preimage fixes the
    frame body before its request count. -/
theorem contextPre_inj (a b : Bytes) : contextPre a = contextPre b ↔ a = b := by
  simp [contextPre]

/-- A token's input fixes the batch context, the request's bytes before its lines (length-prefixed), the lines root
    and the bytes after the lines: everything the payment digest and `INPUT/v6` fixed together, in one preimage. -/
theorem inputV7Pre_inj {c c' h h' r r' t t' : Bytes} (hc : c.length = 64) (hc' : c'.length = 64)
    (hh : h.length < 2 ^ 32) (hh' : h'.length < 2 ^ 32) (hr : r.length = 64) (hr' : r'.length = 64) :
    inputV7Pre c h r t = inputV7Pre c' h' r' t' ↔ c = c' ∧ h = h' ∧ r = r' ∧ t = t' := by
  refine ⟨fun e => ?_, fun ⟨e1, e2, e3, e4⟩ => by rw [e1, e2, e3, e4]⟩
  unfold inputV7Pre at e
  simp only [List.append_assoc] at e
  obtain ⟨e1, e⟩ := List.append_inj (List.append_cancel_left (List.append_cancel_left e)) (hc.trans hc'.symm)
  obtain ⟨e2, e⟩ := lp32_inj hh hh' e
  obtain ⟨e3, e4⟩ := List.append_inj e (hr.trans hr'.symm)
  exact ⟨e1, e2, e3, e4⟩

private theorem flatten64_inj : ∀ {xs ys : List Bytes}, (∀ x ∈ xs, x.length = 64) → (∀ y ∈ ys, y.length = 64) →
    xs.flatten = ys.flatten → xs = ys
  | [], [], _, _, _ => rfl
  | [], y :: _, _, hy, h => by
    have := congrArg List.length h
    rw [List.flatten_nil, List.flatten_cons, List.length_append, List.length_nil, hy y (by simp)] at this
    omega
  | x :: _, [], hx, _, h => by
    have := congrArg List.length h
    rw [List.flatten_nil, List.flatten_cons, List.length_append, List.length_nil, hx x (by simp)] at this
    omega
  | x :: _, y :: _, hx, hy, h => by
    rw [List.flatten_cons, List.flatten_cons] at h
    obtain ⟨e1, e2⟩ := List.append_inj h ((hx x (by simp)).trans (hy y (by simp)).symm)
    rw [e1, flatten64_inj (fun z hz => hx z (by simp [hz])) (fun z hz => hy z (by simp [hz])) e2]

/-- A batch's identity fixes its context and each payment's input, in order: a retry with the same payments has the
    same identity, and any other batch another one (up to the hash). -/
theorem batchInputPre_inj {c c' : Bytes} {rs rs' : List Bytes} (hc : c.length = 64) (hc' : c'.length = 64)
    (hr : ∀ x ∈ rs, x.length = 64) (hr' : ∀ x ∈ rs', x.length = 64) :
    batchInputPre c rs = batchInputPre c' rs' ↔ c = c' ∧ rs = rs' := by
  refine ⟨fun e => ?_, fun ⟨e1, e2⟩ => by rw [e1, e2]⟩
  unfold batchInputPre at e
  simp only [List.append_assoc] at e
  obtain ⟨e1, e2⟩ := List.append_inj (List.append_cancel_left e) (hc.trans hc'.symm)
  exact ⟨e1, flatten64_inj hr hr' e2⟩

/-- The request bytes a token's input commits to are the frame's `req HEX` bytes, and they decode to the request the token
    prints. -/
theorem addReq_bytes {st st' : Run.St} {h : String} (hs : Run.addReq st h = some st') :
    ∃ x e, Run.unhexFast h = some x ∧ e.x = x ∧ decodeRequest e.x.toList = some e.r ∧ st'.reqs = st.reqs.push e := by
  unfold Run.addReq at hs
  obtain ⟨x, hx, hs⟩ := Option.bind_eq_some_iff.mp hs
  obtain ⟨e, he, hs⟩ := Option.bind_eq_some_iff.mp hs
  obtain ⟨u, hg, hs⟩ := Option.bind_eq_some_iff.mp hs
  unfold Run.reqOf at he
  obtain ⟨r, hr, he⟩ := Option.bind_eq_some_iff.mp he
  obtain ⟨ls, hl, he⟩ := Option.bind_eq_some_iff.mp he
  injection he with he
  subst he
  injection hs with hs
  subst hs
  exact ⟨x, ⟨_, .ofModel r, ls, x⟩, hx, rfl, by simpa [Run.Req.r] using hr, rfl⟩

end BlindLedger.Gate.Flat
