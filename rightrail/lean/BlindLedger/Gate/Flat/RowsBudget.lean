import BlindLedger.Gate.Flat.DecideCut
import BlindLedger.Gate.Flat.PayTheorems

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

end BlindLedger.Gate.Flat.Rows
