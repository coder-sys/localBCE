import BlindLedger.Gate.Flat.DecideCut
import BlindLedger.Gate.Flat.PayTheorems
import BlindLedger.Gate.Engine3.Step

/-! The Engine3 lanes' reason bits are allowed by the feeds' bits.  `Engine3.StepH` (and the checker, `Engine3.Verify`)
    decides with `Rows.decideRows` on the layout it reads and builds a payment's mask as the OR of its decided lines'
    masks, from which `Engine3.leafBits` sets bit `Reason.idx` for each reason whose `Rows.bit` the OR has
    (`leafBits_eq`; `has`).  On a layout that is a cut (`DecideCut.Cut`) of `layout s fc f b`, over indexes faithful to
    real sets whose rows and lines fit the store widths (the hypotheses of `decideRows_eq` and `decideRows_cut`):
    every reason bit of every decision is allowed by the feeds' bits (`cut_mask_may`), so every reason a payment's OR
    has is (`rows_leaf_may`), and the reasons it has number at most `maxReasonCodes` (`rows_leaf_le`).
    The count is not yet a constraint: `reasons` has 24 members, so it holds for any OR, and the masks are `UInt32`
    (`reasons_len_le32`).  It is proved through `may` so that it keeps holding when the rule set outgrows 32 (step 5,
    with wider masks).  That `Hist.read` (engine) and `VMirror.read` (checker) read such a cut is argued in
    Engine3/Hist.lean and Engine3/VMirror.lean, not proved.  Synthetic, nonpayment, non-PHI, activation=false. -/

namespace BlindLedger.Gate.Flat.Rows

open BlindLedger.Gate.Rules BlindLedger.Gate.Rules.Fast BlindLedger.Gate.Flat
open BlindLedger.Gate.Engine3 (fitsLine2)

/-- Every reason bit on a decision of the full layout is allowed by the feeds' bits: through `decideRows_eq` it is a
    reason of a `decideFetched` decision (`decideFetched_may`). -/
theorem layout_mask_may (H : Bytes → Bytes) (s : St) (fc : FCtx) (f : List Nat) (b : List Line)
    (rel unr : Snapshot Line) (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr)
    (hw : ∀ l ∈ b ++ rel.entries ++ unr.entries, fitsLine2 l = true) :
    ∀ d ∈ (decideRows (layout s fc f b)).ds.toList, ∀ r, has d.mask r = true → may (feedBits fc.feeds) r = true := by
  intro d hd r hrd
  have hm := congrArg Prod.fst (decideRows_eq H s fc f b rel unr hr hu hw)
  have hin : ((layout s fc f b).src.getD d.line nilLine, outcomeOf8 d.out,
      reasons.filter (fun r => d.mask &&& bit r != 0), cpId (layout s fc f b) d.cp) ∈
      (project (decideBatchIdx s fc f b)).1 := by
    rw [← hm]
    simp only [Out.toRef]
    exact List.mem_map.mpr ⟨d, hd, rfl⟩
  simp only [project, List.mem_map] at hin
  obtain ⟨e, he, heq⟩ := hin
  simp only [Prod.mk.injEq] at heq
  have hre : r ∈ e.reasons := by
    rw [heq.2.2.1]
    exact List.mem_filter.mpr ⟨mem_all r, hrd⟩
  exact decideFetched_may s.rel.head s.unr.head (fetch s fc.redo b) fc f b e he r hre

/-- The same on a cut of the full layout: `decideRows_cut` gives each of its decisions a decision of the full layout
    with the same mask. -/
theorem cut_mask_may (H : Bytes → Bytes) (s : St) (fc : FCtx) (f : List Nat) (b : List Line)
    (rel unr : Snapshot Line) (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr)
    (hw : ∀ l ∈ b ++ rel.entries ++ unr.entries, fitsLine2 l = true) (x' : Lay) (C : Cut (layout s fc f b) x') :
    ∀ d ∈ (decideRows x').ds.toList, ∀ r, has d.mask r = true → may (feedBits fc.feeds) r = true := by
  intro d hd r hrd
  have hc := (decideRows_cut _ x' C).1
  have hin : ansOf x' d ∈ (decideRows (layout s fc f b)).ds.toList.map (ansOf (layout s fc f b)) := by
    rw [← hc]
    exact List.mem_map.mpr ⟨d, hd, rfl⟩
  obtain ⟨d0, hd0, h0⟩ := List.mem_map.mp hin
  simp only [ansOf, Prod.mk.injEq] at h0
  exact layout_mask_may H s fc f b rel unr hr hu hw d0 hd0 r (h0.2.1 ▸ hrd)

/-- A reason bit of an OR of masks is a bit of the start or of one of them. -/
private theorem fold_has (r : Reason) : ∀ (ds : List Dec) (acc : UInt32),
    has (ds.foldl (fun a d => a ||| d.mask) acc) r = true → has acc r = true ∨ ∃ d ∈ ds, has d.mask r = true
  | [], acc, h => Or.inl h
  | d :: ds, acc, h => by
    rcases fold_has r ds (acc ||| d.mask) h with h1 | ⟨e, he, h2⟩
    · rw [has_or, Bool.or_eq_true] at h1
      rcases h1 with h1 | h1
      · exact Or.inl h1
      · exact Or.inr ⟨d, List.mem_cons_self .., h1⟩
    · exact Or.inr ⟨e, List.mem_cons_of_mem _ he, h2⟩

/-- Every reason the OR of any of the cut layout's decisions' masks has (as `StepH` builds a payment's mask,
    `msk[p] ||| d.mask` from 0) is allowed by the feeds' bits. -/
theorem rows_leaf_may (H : Bytes → Bytes) (s : St) (fc : FCtx) (f : List Nat) (b : List Line)
    (rel unr : Snapshot Line) (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr)
    (hw : ∀ l ∈ b ++ rel.entries ++ unr.entries, fitsLine2 l = true) (x' : Lay) (C : Cut (layout s fc f b) x')
    (ds : List Dec) (hds : ∀ d ∈ ds, d ∈ (decideRows x').ds.toList) :
    ∀ r, has (ds.foldl (fun a d => a ||| d.mask) 0) r = true → may (feedBits fc.feeds) r = true := by
  intro r hr'
  rcases fold_has r ds 0 hr' with h0 | ⟨d, hd, hm⟩
  · rw [has_zero] at h0; exact absurd h0 (by simp)
  · exact cut_mask_may H s fc f b rel unr hr hu hw x' C d (hds d hd) r hm

/-- The reasons such an OR has number at most `maxReasonCodes`, through `rows_leaf_may` and `Rules.budget` (see the
    module note: with 24 reasons this does not yet constrain anything). -/
theorem rows_leaf_le (H : Bytes → Bytes) (s : St) (fc : FCtx) (f : List Nat) (b : List Line)
    (rel unr : Snapshot Line) (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr)
    (hw : ∀ l ∈ b ++ rel.entries ++ unr.entries, fitsLine2 l = true) (x' : Lay) (C : Cut (layout s fc f b) x')
    (ds : List Dec) (hds : ∀ d ∈ ds, d ∈ (decideRows x').ds.toList) :
    (reasons.filter (has (ds.foldl (fun a d => a ||| d.mask) 0))).length ≤ BlindLedger.Gate.maxReasonCodes := by
  rw [← List.countP_eq_length_filter]
  refine Nat.le_trans (List.countP_mono_left (q := may (feedBits fc.feeds))
    fun r _ hr' => rows_leaf_may H s fc f b rel unr hr hu hw x' C ds hds r hr') ?_
  · rw [List.countP_eq_length_filter]
    exact budget _

/-! ## The leaf Engine3 emits

    `Engine3.Run.leafIn` gives a covered request whose lines fit the reasons field `leafBits m` (`leafIn_reasons`).
    `leafBits m` has bit `i` exactly when some reason with `Reason.idx = i` is in `m` (`leafBits_testBit`), so it has
    no bit at or past the reason count (`leafBits_lt`); with `Rules.reasons_len_le` (at most 62 reasons) that excludes
    the leaf-only 62 and 63.
    Read from the code, not proved (the loops are inline in the `IO` batch of `StepH` and of `Verify`, with no
    definition a lemma could name): `m` is `msk[p]`, the OR from 0 of the masks of the `out.ds` whose line's payment
    (`lay.lines[d.line].pay`) is `p`; the leaf index `p` (`payIx`) numbers the requests as the layout numbers payments;
    a covered request with no ruled lines gets `m = 0` (the empty fold).  The `may` and no-leaf-only-bit conclusions
    of `leafIn_bits_may` do not depend on these: they hold for the OR of any of the layout's decisions.  Only the
    reading "these are exactly this payment's reasons" does. -/

private theorem fold_testBit (m : UInt32) (i : Nat) : ∀ (l : List Reason) (acc : Nat),
    (l.foldl (fun a r => if m &&& bit r != 0 then a ||| 2 ^ r.idx else a) acc).testBit i =
      (acc.testBit i || l.any fun r => has m r && r.idx == i)
  | [], acc => by simp
  | r :: l, acc => by
    rw [List.foldl_cons, fold_testBit m i l, List.any_cons]
    by_cases h : (m &&& bit r != 0) = true
    · have hh : has m r = true := h
      rw [if_pos h, Nat.testBit_or, Nat.testBit_two_pow, hh]
      cases acc.testBit i <;> by_cases e : r.idx = i <;> simp [e]
    · have hh : has m r = false := by simpa [has] using h
      rw [if_neg h, hh]
      simp

/-- `leafBits m` has bit `i` exactly when a reason numbered `i` is in `m`. -/
theorem leafBits_testBit (m : UInt32) (i : Nat) :
    (Engine3.Run.leafBits m).testBit i = reasons.any fun r => has m r && r.idx == i := by
  rw [Engine3.Run.leafBits_eq, fold_testBit]
  simp

/-- `leafBits m` sets no bit at or past the reason count: never a leaf-only code (62, 63). -/
theorem leafBits_lt (m : UInt32) : Engine3.Run.leafBits m < 2 ^ reasons.length := by
  refine Nat.lt_pow_two_of_testBit _ fun i hi => ?_
  rw [leafBits_testBit]
  simp only [List.any_eq_false, Bool.and_eq_true, beq_iff_eq, not_and]
  intro r _ _ e
  have := idx_len r
  omega

/-- `leafIn`'s reasons field: SCOPE when no entry covers the request, UNENCODABLE_PAYMENT when a line does not fit, else
    `leafBits` of the payment's mask. -/
theorem leafIn_reasons (a : Run.Admitted) (gid : ByteArray) (x : Run.Req) (ent : Option Authority.Entry) (unf : Bool)
    (f : UInt8) (m : UInt32) :
    (Engine3.Run.leafIn a gid x ent unf f m).1.reasons =
      match ent with
      | none => Frame.leafScope
      | some _ => if unf then Frame.leafUnencodable else Engine3.Run.leafBits m := by
  cases ent <;> rfl

/-- The leaf Engine3 emits for a covered payment whose lines fit, with its mask the OR of decisions of a cut of
    `layout s fc f b` (`rows_leaf_may`'s hypotheses): its reasons field has bit `i` exactly when a reason numbered `i` is
    in the mask, every such reason is allowed by the feeds' bits, and no leaf-only bit is set. -/
theorem leafIn_bits_may (H : Bytes → Bytes) (s : St) (fc : FCtx) (f : List Nat) (b : List Line)
    (rel unr : Snapshot Line) (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr)
    (hw : ∀ l ∈ b ++ rel.entries ++ unr.entries, fitsLine2 l = true) (x' : Lay) (C : Cut (layout s fc f b) x')
    (ds : List Dec) (hds : ∀ d ∈ ds, d ∈ (decideRows x').ds.toList)
    (a : Run.Admitted) (gid : ByteArray) (x : Run.Req) (en : Authority.Entry) (fl : UInt8) :
    let m := ds.foldl (fun a d => a ||| d.mask) 0
    let rs := (Engine3.Run.leafIn a gid x (some en) false fl m).1.reasons
    (∀ i, rs.testBit i = true ↔ ∃ r, r.idx = i ∧ has m r = true) ∧
    (∀ r, has m r = true → may (feedBits fc.feeds) r = true) ∧ rs < 2 ^ reasons.length := by
  intro m rs
  have hrs : rs = Engine3.Run.leafBits m := leafIn_reasons a gid x (some en) false fl m
  refine ⟨fun i => ?_, rows_leaf_may H s fc f b rel unr hr hu hw x' C ds hds, hrs ▸ leafBits_lt m⟩
  rw [hrs, leafBits_testBit]
  simp only [List.any_eq_true, Bool.and_eq_true, beq_iff_eq]
  constructor
  · rintro ⟨r, -, h1, h2⟩; exact ⟨r, h2, h1⟩
  · rintro ⟨r, h2, h1⟩; exact ⟨r, mem_all r, h1, h2⟩

end BlindLedger.Gate.Flat.Rows
