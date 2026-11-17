import BlindLedger.Gate.Flat.Theorems
import BlindLedger.Gate.Flat.Worker

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

/-- `Rules.budget`'s literal 32 is TOKEN/v1's `maxReasonCodes` (Gate/Spec.lean:32), which Rules.Theorems does not
    import. -/
private theorem budget_cap : 32 = BlindLedger.Gate.maxReasonCodes := rfl

/-- Codes as `leafReasons_codes` describes them, each the name of a reason allowed by one `Bits`, are at most
    `maxReasonCodes`: they are distinct, so no more than the allowed names (`Rules.budget`).  No name injectivity is
    needed. -/
private theorem codes_le (b : Bits) (ds : List Decision) (u : Nat → Bool) (p : Nat) (rs : List String)
    (hpw : rs.Pairwise (· < ·)) (h3 : u p = true → rs = ["UNENCODABLE_PAYMENT"])
    (h4 : u p = false → ∀ r, r ∈ rs ↔ ∃ d ∈ ds, d.line.pay = p ∧ ∃ y ∈ d.reasons, Run.name y = r)
    (h : ∀ d ∈ ds, ∀ r ∈ d.reasons, may b r = true) : rs.length ≤ BlindLedger.Gate.maxReasonCodes := by
  cases hu : u p
  · have hnd : rs.Nodup := List.nodup_iff_pairwise_ne.mpr
      (hpw.imp fun {x _} hxy e => by subst e; exact String.lt_irrefl x hxy)
    have hsub : rs ⊆ (reasons.filter (may b)).map Run.name := by
      intro x hx
      obtain ⟨d, hd, -, y, hy, rfl⟩ := (h4 hu x).mp hx
      exact List.mem_map.mpr ⟨y, List.mem_filter.mpr ⟨by cases y <;> decide, h d hd y hy⟩, rfl⟩
    calc rs.length ≤ ((reasons.filter (may b)).map Run.name).length := hnd.length_le_of_subset hsub
      _ = (reasons.filter (may b)).length := List.length_map ..
      _ ≤ 32 := budget b
      _ = BlindLedger.Gate.maxReasonCodes := budget_cap
  · rw [h3 hu, ← budget_cap]; decide

/-- The reason codes a token carries for payment `p` are at most `maxReasonCodes` (TOKEN/v1's limit) whenever every
    reason of every decision is allowed by one `Bits` (`Rules.decideAll_may` gives that for a batch's decisions).  The
    code list `rs` is `leafReasons_codes`' own (strictly increasing, with its members fixed), so it is the list printed,
    not just some list whose joining gives the printed text. -/
theorem leafReasons_le (b : Bits) (ds : List Decision) (u : Nat → Bool) (p : Nat)
    (h : ∀ d ∈ ds, ∀ r ∈ d.reasons, may b r = true) :
    ∃ rs : List String, Run.leafReasons ds u p = (if rs.isEmpty then "-" else ",".intercalate rs) ∧
      rs.Pairwise (· < ·) ∧ (u p = true → rs = ["UNENCODABLE_PAYMENT"]) ∧
      (u p = false → ∀ r, r ∈ rs ↔ ∃ d ∈ ds, d.line.pay = p ∧ ∃ y ∈ d.reasons, Run.name y = r) ∧
      rs.length ≤ BlindLedger.Gate.maxReasonCodes := by
  obtain ⟨rs, h1, h2, h3, h4⟩ := leafReasons_codes ds u p
  exact ⟨rs, h1, h2, h3, h4, codes_le b ds u p rs h2 h3 h4 h⟩

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

/-- Each `RULES_PAY` line fits one token: in `pay_line`'s setting (a batch no cap touches, an index faithful to `rel`
    and `unr`), the reason codes the worker prints for payment `p` (the list `pay_line` describes) are at most
    `maxReasonCodes`. -/
theorem pay_codes_le (H : Bytes → Bytes) (s : St) (c : Ctx) (rel unr : Snapshot Line) (f : List Nat) (b : List Line)
    (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr) (hb : Uncapped (fetch s c.redo b) (Worker.feedsOf c) b)
    (u : Nat → Bool) (p : Nat) :
    let fc : FCtx := ⟨c.today, c.redo, Worker.feedsOf c, c.byp, c.lim⟩
    let fe := fetch s fc.redo b
    let ds := (decideFetched s.rel.head s.unr.head fe fc f b).1
    let spec := (decideBatchIn (carried c rel unr) f b).decisions
    ∃ rs : List String, Run.leafReasons ds u p = (if rs.isEmpty then "-" else ",".intercalate rs) ∧
      rs.Pairwise (· < ·) ∧ (u p = true → rs = ["UNENCODABLE_PAYMENT"]) ∧
      (u p = false → ∀ r, r ∈ rs ↔ ∃ d ∈ spec, d.line.pay = p ∧ ∃ y ∈ d.reasons, Run.name y = r) ∧
      rs.length ≤ BlindLedger.Gate.maxReasonCodes := by
  intro fc fe ds spec
  obtain ⟨hds, -⟩ := pay_eq H s c rel unr f b hr hu hb
  have hm : ∀ d ∈ spec, ∀ r ∈ d.reasons, may (bitsOf (carried c rel unr)) r = true :=
    decideAll_may (carried c rel unr) (idSeen f ++ seen0 (carried c rel unr) b) (order (carried c rel unr) b)
  rw [show ds = spec from hds]
  exact leafReasons_le _ _ u p hm

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

/-- `pay_codes_le` for a payment none of whose lines is capped, in a batch where other lines may be (`pay_line_part`).
    A payment with a capped line is HOLD (`pay_capped`); its codes come from the capped index (`Ix.fires` and
    `capD`, which adds POSTING_CAP), not the Spec, and are not bounded here: no lemma yet ties them to `may`.  Until
    one does, the only check on `may`'s POSTING_CAP arm is the headroom pin in Rules/Theorems. -/
theorem pay_codes_le_part (H : Bytes → Bytes) (s : St) (c : Ctx) (rel unr : Snapshot Line) (f : List Nat)
    (b : List Line) (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr) (u : Nat → Bool) (p : Nat)
    (hp : ∀ l ∈ b, l.pay = p → capped (hotKeys (fetch s c.redo b) (Worker.feedsOf c) b) (fetch s c.redo b) (Worker.feedsOf c) l = false) :
    let fc : FCtx := ⟨c.today, c.redo, Worker.feedsOf c, c.byp, c.lim⟩
    let fe := fetch s fc.redo b
    let ds := (decideFetched s.rel.head s.unr.head fe fc f b).1
    let spec := (decideBatchIn (carried c rel unr) f b).decisions
    ∃ rs : List String, Run.leafReasons ds u p = (if rs.isEmpty then "-" else ",".intercalate rs) ∧
      rs.Pairwise (· < ·) ∧ (u p = true → rs = ["UNENCODABLE_PAYMENT"]) ∧
      (u p = false → ∀ r, r ∈ rs ↔ ∃ d ∈ spec, d.line.pay = p ∧ ∃ y ∈ d.reasons, Run.name y = r) ∧
      rs.length ≤ BlindLedger.Gate.maxReasonCodes := by
  intro fc fe ds spec
  obtain ⟨-, rs, h1, h2, h3, h4⟩ := pay_line_part H s c rel unr f b hr hu u p hp
  have hm : ∀ d ∈ spec, ∀ r ∈ d.reasons, may (bitsOf (carried c rel unr)) r = true :=
    decideAll_may (carried c rel unr) (idSeen f ++ seen0 (carried c rel unr) b) (order (carried c rel unr) b)
  exact ⟨rs, h1, h2, h3, h4, codes_le _ _ u p rs h2 h3 h4 hm⟩

/-! ## Requests: a token's lines and fields are its own request's (K1 review H1)

    With requests in the frame (`req HEX`, `Run.addReq`), each entry of `Run.St.reqs` is a request Lean decoded from
    the frame's bytes, its payment number and the lines it read from it (`ReqsOk`, kept by every `req`: `addReq_ok`).
    The commit decides `Run.St.lines`; the lines of a request's payment there are exactly that request's (`lines_req`),
    and its leaf (`Run.emitWith`) is the Spec's `Run.emit` (`pay_req`).  The frame carries no pairing of a request with other lines, so none can be signed. -/

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

/-- A request's leaf: on a batch no cap touches, over an index faithful to `rel` and `unr`, the leaf the worker builds
    (`Run.emitWith` over its index's payment outcome, bypass test and re-decision test) is the Spec's `Run.emit` over the Spec's decisions, so
    the authority laws of `Run.emit` (`EmitLaws`) hold of the worker's leaf. -/
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


/-! ## INPUT/v6: what a token's input and a batch's identity commit to (gate K2, III.3) -/

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

/-- XI.2: INPUT/v5 becomes the batch context, the payment digest, `INPUT/v6` and the batch identity.  The context's
    preimage fixes the frame body before its request count. -/
theorem contextPre_inj (a b : Bytes) : contextPre a = contextPre b ↔ a = b := by
  simp [contextPre]

/-- The payment digest's preimage fixes the request's bytes before its lines (length-prefixed), the lines root and the
    bytes after the lines. -/
theorem paymentPre_inj {h h' r r' t t' : Bytes} (hh : h.length < 2 ^ 32) (hh' : h'.length < 2 ^ 32)
    (hr : r.length = 64) (hr' : r'.length = 64) :
    paymentPre h r t = paymentPre h' r' t' ↔ h = h' ∧ r = r' ∧ t = t' := by
  refine ⟨fun e => ?_, fun ⟨e1, e2, e3⟩ => by rw [e1, e2, e3]⟩
  unfold paymentPre at e
  simp only [List.append_assoc] at e
  obtain ⟨e1, e⟩ := lp32_inj hh hh' (List.append_cancel_left e)
  obtain ⟨e2, e3⟩ := List.append_inj e (hr.trans hr'.symm)
  exact ⟨e1, e2, e3⟩

/-- A token's input fixes the batch context and the payment digest. -/
theorem inputV6Pre_inj {c c' d d' : Bytes} (hc : c.length = 64) (hc' : c'.length = 64) :
    inputV6Pre c d = inputV6Pre c' d' ↔ c = c' ∧ d = d' := by
  refine ⟨fun e => ?_, fun ⟨e1, e2⟩ => by rw [e1, e2]⟩
  unfold inputV6Pre at e
  simp only [List.append_assoc] at e
  exact List.append_inj (List.append_cancel_left (List.append_cancel_left e)) (hc.trans hc'.symm)

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
