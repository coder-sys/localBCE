import BlindLedger.Gate.Flat.DecideCut
import BlindLedger.Gate.Flat.PayTheorems
import BlindLedger.Gate.Engine3.Step
import BlindLedger.Gate.Engine3.StepH
import BlindLedger.Gate.Engine3.Verify

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
    `m` is `msk[p]` of `Run.payFlags` (engine) or `Verify.payFlagsC` (checker): proved below to be the OR from 0 of
    the masks of exactly the decisions whose line's payment (`lay.lines[d.line].pay`) is `p` (`payFlags_msk`), and
    tied to the emitted leaf by `payFlags_leaf`.  Still read from the code, not proved: that the leaf index `p`
    (`payIx`, inline in `stepH`/`stepC`) numbers the requests as `Hist.read`/`VMirror.read` number the layout's
    payments (all three filter covered, fitting, ruled requests with lines, in request order), and that every such `p`
    is below `np` (the loop pushes `n` then increments it).  A covered request with no ruled lines gets `m = 0`.  The
    `may` and no-leaf-only-bit conclusions hold for the OR of any of the layout's decisions, so they do not depend on
    the numbering; only "exactly this payment's reasons" does. -/

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

/-! ## The payment mask the engine and the checker build

    `Engine3.Run.payFlags` (engine, `stepH`) and `Engine3.Verify.payFlagsC` (checker, `stepC`, its own copy) build, per
    payment, the OR of its decided lines' masks.  `payFlags_msk` and `payFlagsC_msk`: entry `p` (below `np`) is the OR
    from 0 of the masks of exactly the decisions whose line's payment is `p`.  `payFlags_leaf` then ties the leaf the
    engine emits for payment `p` to exactly the reasons of that payment's decisions. -/

/-- A reason is in an OR of masks exactly when it is in the start or in one of them. -/
theorem has_fold_iff (r : Reason) : ∀ (ds : List Dec) (acc : UInt32),
    has (ds.foldl (fun a d => a ||| d.mask) acc) r = true ↔ has acc r = true ∨ ∃ d ∈ ds, has d.mask r = true
  | [], acc => by simp
  | d :: ds, acc => by
    rw [List.foldl_cons, has_fold_iff r ds, has_or, Bool.or_eq_true]
    constructor
    · rintro ((h | h) | ⟨e, he, h⟩)
      · exact Or.inl h
      · exact Or.inr ⟨d, List.mem_cons_self .., h⟩
      · exact Or.inr ⟨e, List.mem_cons_of_mem _ he, h⟩
    · rintro (h | ⟨e, he, h⟩)
      · exact Or.inl (Or.inl h)
      · rcases List.mem_cons.mp he with rfl | he
        · exact Or.inl (Or.inr h)
        · exact Or.inr ⟨e, he, h⟩

/-- The OR loop: after setting entry `pay d` to itself OR `d.mask` for each `d` in turn, entry `p` is its start ORed
    with the masks of the `d` whose `pay` is `p`. -/
private theorem fold_msk_get (pay : Dec → Nat) (p : Nat) : ∀ (l : List Dec) (m : Array UInt32), p < m.size →
    (l.foldl (fun m d => m.set! (pay d) (m[pay d]! ||| d.mask)) m)[p]! =
      (l.filter (pay · == p)).foldl (fun a d => a ||| d.mask) m[p]!
  | [], m, _ => rfl
  | d :: l, m, hp => by
    have hs : (m.set! (pay d) (m[pay d]! ||| d.mask)).size = m.size := by simp
    rw [List.foldl_cons, fold_msk_get pay p l _ (hs ▸ hp)]
    have hget : (m.set! (pay d) (m[pay d]! ||| d.mask))[p]! = if pay d = p then m[p]! ||| d.mask else m[p]! := by
      simp only [Array.set!_eq_setIfInBounds, Array.getElem!_eq_getD, Array.getD_eq_getD_getElem?,
        Array.getElem?_setIfInBounds]
      by_cases h : pay d = p
      · subst h; simp [hp]
      · simp [h]
    rw [hget]
    by_cases h : pay d = p
    · simp [h, List.filter_cons]
    · simp [h, List.filter_cons]

/-- A loop each of whose steps yields, with its second component updated by `g`: that component is the fold of `g`,
    whatever the first component does. -/
private theorem forIn_snd {α β γ : Type} (F : α → β × γ → Id (ForInStep (β × γ))) (g : α → γ → γ)
    (h : ∀ a st, ∃ b, F a st = pure (ForInStep.yield (b, g a st.2))) :
    ∀ (l : List α) (st : β × γ), (forIn (m := Id) l st F).2 = l.foldl (fun c a => g a c) st.2
  | [], _ => rfl
  | a :: l, st => by
    obtain ⟨b, hb⟩ := h a st
    rw [List.forIn_cons, hb, List.foldl_cons]
    exact forIn_snd F g h l (b, g a st.2)

/-- One OR step of the mask: entry `pay d` ORed with `d.mask`. -/
private def mskStep (lay : Lay) (d : Dec) (m : Array UInt32) : Array UInt32 :=
  m.set! (lay.lines[d.line]!.pay) (m[lay.lines[d.line]!.pay]! ||| d.mask)

/-- The mask half of `payFlags` is the OR loop over the decisions in order. -/
theorem payFlags_snd (lay : Lay) (out : Out) (inRel : Array Bool) (np : Nat) :
    (Engine3.Run.payFlags lay out inRel np).2 = out.ds.toList.foldl
      (fun m d => m.set! (lay.lines[d.line]!.pay) (m[lay.lines[d.line]!.pay]! ||| d.mask)) (Array.replicate np 0) := by
  unfold Engine3.Run.payFlags
  simp only [Id.run, ← Array.forIn_toList, bind_pure]
  refine forIn_snd _ (mskStep lay) (fun d st => ?_) _ _
  simp only [mskStep]
  repeat' split
  all_goals exact ⟨_, rfl⟩

/-- The checker's copy, the same. -/
theorem payFlagsC_snd (lay : Lay) (out : Out) (inRel : Array Bool) (np : Nat) :
    (Engine3.Verify.payFlagsC lay out inRel np).2 = out.ds.toList.foldl
      (fun m d => m.set! (lay.lines[d.line]!.pay) (m[lay.lines[d.line]!.pay]! ||| d.mask)) (Array.replicate np 0) := by
  unfold Engine3.Verify.payFlagsC
  simp only [Id.run, ← Array.forIn_toList, bind_pure]
  refine forIn_snd _ (mskStep lay) (fun d st => ?_) _ _
  simp only [mskStep]
  repeat' split
  all_goals exact ⟨_, rfl⟩

/-- The engine's mask for payment `p`: the OR from 0 of the masks of exactly the decisions whose line's payment is
    `p`. -/
theorem payFlags_msk (lay : Lay) (out : Out) (inRel : Array Bool) (np p : Nat) (hp : p < np) :
    (Engine3.Run.payFlags lay out inRel np).2[p]! =
      (out.ds.toList.filter fun d => lay.lines[d.line]!.pay == p).foldl (fun a d => a ||| d.mask) 0 := by
  rw [payFlags_snd, fold_msk_get (fun d => lay.lines[d.line]!.pay) p _ _ (by simpa using hp)]
  simp [hp]

/-- The checker's mask for payment `p`, the same. -/
theorem payFlagsC_msk (lay : Lay) (out : Out) (inRel : Array Bool) (np p : Nat) (hp : p < np) :
    (Engine3.Verify.payFlagsC lay out inRel np).2[p]! =
      (out.ds.toList.filter fun d => lay.lines[d.line]!.pay == p).foldl (fun a d => a ||| d.mask) 0 := by
  rw [payFlagsC_snd, fold_msk_get (fun d => lay.lines[d.line]!.pay) p _ _ (by simpa using hp)]
  simp [hp]

/-- The leaf the engine emits for payment `p` (below `np`) of a covered request whose lines fit, on a cut `x'` of
    `layout s fc f b` decided by `decideRows` (as `stepH` does): its reasons field has bit `i` exactly when some
    decision of payment `p` has the reason numbered `i`; every such reason is allowed by the feeds' bits; and no
    leaf-only bit is set. -/
theorem payFlags_leaf (H : Bytes → Bytes) (s : St) (fc : FCtx) (f : List Nat) (b : List Line)
    (rel unr : Snapshot Line) (hr : IdxInv H s.rel rel) (hu : IdxInv H s.unr unr)
    (hw : ∀ l ∈ b ++ rel.entries ++ unr.entries, fitsLine2 l = true) (x' : Lay) (C : Cut (layout s fc f b) x')
    (inRel : Array Bool) (np p : Nat) (hp : p < np)
    (a : Run.Admitted) (gid : ByteArray) (x : Run.Req) (en : Authority.Entry) (fl : UInt8) :
    let m := (Engine3.Run.payFlags x' (decideRows x') inRel np).2[p]!
    let rs := (Engine3.Run.leafIn a gid x (some en) false fl m).1.reasons
    (∀ i, rs.testBit i = true ↔
      ∃ r, r.idx = i ∧ ∃ d ∈ (decideRows x').ds.toList, x'.lines[d.line]!.pay = p ∧ has d.mask r = true) ∧
    (∀ r, has m r = true → may (feedBits fc.feeds) r = true) ∧ rs < 2 ^ reasons.length := by
  intro m rs
  let ds := (decideRows x').ds.toList.filter fun d => x'.lines[d.line]!.pay == p
  have hm : m = ds.foldl (fun a d => a ||| d.mask) 0 := payFlags_msk x' (decideRows x') inRel np p hp
  have hds : ∀ d ∈ ds, d ∈ (decideRows x').ds.toList := fun d hd => (List.mem_filter.mp hd).1
  obtain ⟨h1, h2, h3⟩ := leafIn_bits_may H s fc f b rel unr hr hu hw x' C ds hds a gid x en fl
  rw [← hm] at h1 h2 h3
  refine ⟨fun i => ?_, h2, h3⟩
  rw [h1 i]
  constructor
  · rintro ⟨r, hi, hr'⟩
    rw [hm, has_fold_iff] at hr'
    rcases hr' with h0 | ⟨d, hd, hdr⟩
    · rw [has_zero] at h0; exact absurd h0 (by simp)
    · obtain ⟨hd1, hd2⟩ := List.mem_filter.mp hd
      exact ⟨r, hi, d, hd1, by simpa using hd2, hdr⟩
  · rintro ⟨r, hi, d, hd, hpd, hdr⟩
    refine ⟨r, hi, ?_⟩
    rw [hm, has_fold_iff]
    exact Or.inr ⟨d, List.mem_filter.mpr ⟨hd, by simpa using hpd⟩, hdr⟩

end BlindLedger.Gate.Flat.Rows
