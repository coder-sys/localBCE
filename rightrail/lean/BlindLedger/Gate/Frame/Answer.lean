import BlindLedger.Gate.Frame.Fast

/-! The answer written in one pass into one byte buffer from a decider's output shaped as the row decider's `Out`: a
    decision per line (`Dec`), the lines it adds to the released and unresolved sets, and the held lines.  A stored row
    is copied from the line's own bytes (`LineSrc`): a number is its zero padding, a 0x01 byte and the identifier's
    bytes, so no number is built.  Formats: conformance/FRAME_V1.md. -/

namespace BlindLedger.Gate.Frame.Fast

open BlindLedger.Gate.Rules

/-- A decision, as the row decider emits it: the line's position, its reason mask, outcome code, and the store position
    of its counterpart (0 none, `2j + 1` released row `j`, `2j + 2` unresolved row `j`). -/
structure Dec where
  line : Nat
  mask : UInt32
  out : UInt8
  cp : Nat

/-- A line held for width (`Rule.wide`) or for a sibling (`Rule.sibling`): its position and rule index. -/
structure Held where
  index : Nat
  rule : UInt8

/-- A line's bytes as the request carried them, and its payment's `payKey` (`RowsReq.payKey`). -/
structure LineSrc where
  payKey : ByteArray
  ln : ByteArray
  deriving Inhabited

def zeroPad : ByteArray := ⟨Array.replicate 261 0⟩

/-- `1 ‖ s[o, o + n)` as a number of `w` bytes, big-endian. -/
def putNum (b s : ByteArray) (w o n : Nat) : ByteArray :=
  let b := (zeroPad.copySlice 0 b b.size (w - 1 - n) false).push 1
  s.copySlice o b b.size n false

def putLE3 (b : ByteArray) (v : Nat) : ByteArray :=
  (b.push v.toUInt8).push (v >>> 8).toUInt8 |>.push (v >>> 16).toUInt8

def putLE4 (b : ByteArray) (v : UInt32) : ByteArray :=
  (((b.push v.toUInt8).push (v >>> 8).toUInt8).push (v >>> 16).toUInt8).push (v >>> 24).toUInt8

/-- The stored row (`Run.rowBytesFast`) of a line `decodeRows` accepted. -/
def putRow (b : ByteArray) (tag : UInt8) (s : LineSrc) : ByteArray :=
  let l := s.ln
  let ie := identEnd l 1 l.size
  let pe := identEnd l (ie + 32) l.size
  let re := identEnd l pe l.size
  let oe := identEnd l (re + 4) l.size
  let b := putNum (b.push tag) l 129 3 (ie - 3)
  let b := putNum b s.payKey 261 0 s.payKey.size
  let b := putNum (b.push (l.get! 0)) l 129 ie 32
  let b := putNum (putNum b l 129 (ie + 34) (pe - ie - 34)) l 129 (pe + 2) (re - pe - 2)
  let b := putNum (l.copySlice re b b.size 4 false) l 129 (re + 6) (oe - re - 6)
  l.copySlice oe b b.size 12 false

/-- `Frame.encodeAns` of the answer these give: the records (decided lines in order, then the held), the head and
    state root, and the extension.  Only for an answer with the word OK. -/
def encodeAnsOut (shard batch : Nat) (digest head root hold grant auth : ByteArray) (ds : Array Dec) (ruleOf : Dec → UInt8)
    (locOf : Nat → UInt32 × UInt32) (held : Array Held) (notes : Array ByteArray) (leaves : Array Leaf)
    (lines : Array LineSrc) (rel unr : Array Nat) : ByteArray :=
  let nr := ds.size + held.size
  let cap := 160 + 20 * nr + notes.foldl (fun n x => n + 2 + x.size) 4 +
    140 * leaves.size + 4 +
    930 * (rel.size + unr.size)
  let b := putL (ByteArray.emptyWithCapacity cap) magicAns
  let b := put (put (put (put (put b 2 ansVersion) 1 Word.OK.code) 4 shard) 8 batch) 4 nr
  let b := b ++ digest
  let b := ds.foldl (fun b d =>
    let (c, r) := if d.cp == 0 then (0xFFFFFFFF, 0xFFFFFF) else locOf d.cp
    putLE3 (putLE4 (put ((((putLE3 b d.line).push d.out).push (ruleOf d))) 8 d.mask.toNat) c) r.toNat) b
  let b := held.foldl (fun b h => putLE3 (putLE4 (put (((putLE3 b h.index).push 1).push h.rule) 8 0) 0xFFFFFFFF) 0xFFFFFF) b
  let b := b ++ head ++ root ++ hold ++ grant ++ auth
  let b := notes.foldl putBlob2 (put b 4 notes.size)
  let b := leaves.foldl putLeaf (put b 4 leaves.size)
  let b := put b 4 (rel.size + unr.size)
  let b := rel.foldl (fun b i => putRow (put b 2 924) 1 lines[i]!) b
  unr.foldl (fun b i => putRow (put b 2 924) 2 lines[i]!) b

/-- The stored row of a line by the rules' numbers. -/
def rowOfLine (tag : UInt8) (s : LineSrc) : ByteArray :=
  (Rules.Run.rowBytesFast tag (lineOfBytes (idNatA s.payKey) s.ln)).getD .empty

/-- The answer `encodeAnsOut` writes, as the codec's value. -/
def ansOfOut (shard batch : Nat) (digest head root hold grant auth : ByteArray) (ds : Array Dec) (ruleOf : Dec → UInt8)
    (locOf : Nat → UInt32 × UInt32) (held : Array Held) (notes : Array ByteArray) (leaves : Array Leaf)
    (lines : Array LineSrc) (rel unr : Array Nat) : AnsFrame :=
  ⟨.OK, shard, batch, digest,
    ds.toList.map (fun d => ⟨d.line, d.out.toNat, rules.getD (ruleOf d).toNat .decided, d.mask.toNat,
      if d.cp == 0 then none else some ((locOf d.cp).1.toNat, (locOf d.cp).2.toNat)⟩) ++
    held.toList.map (fun h => ⟨h.index, 1, rules.getD h.rule.toNat .decided, 0, none⟩),
    head, root, ⟨hold, grant, auth, notes.toList, leaves.toList, rel.toList.map (fun i => rowOfLine 1 lines[i]!) ++
      unr.toList.map (fun i => rowOfLine 2 lines[i]!)⟩⟩

/-! ### Proof of `encodeAnsOut_eq` -/
private theorem toList_push' (b : ByteArray) (c : UInt8) : (b.push c).toList = b.toList ++ [c] := by
  simp [Flat.Bin.toList_eq', ByteArray.data_push]

private theorem toList_put (b : ByteArray) (w n : Nat) :
    (put b w n).toList = b.toList ++ (List.range w).map (fun i => (n >>> (8 * i)).toUInt8) := by
  induction w generalizing b with
  | zero => simp [put]
  | succ w ih =>
    have : put b (w + 1) n = (put b w n).push (n >>> (8 * w)).toUInt8 := by
      simp [put, Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, List.range'_concat]
    rw [this, toList_push', ih, List.range_succ]
    simp

private theorem mod_toUInt8 (m : Nat) : (m % 256).toUInt8 = m.toUInt8 := by
  apply UInt8.toNat_inj.mp
  simp

private theorem le_put (b : ByteArray) (w n : Nat) (l : Bytes) (h : le w n = some l) :
    (put b w n).toList = b.toList ++ l := by
  unfold le at h
  split at h
  · cases h
    rw [toList_put]
    congr 1
    apply List.map_congr_left
    intro i _
    rw [div_256_pow, mod_toUInt8]
  · cases h

private theorem putLE3_eq (b : ByteArray) (v : Nat) : putLE3 b v = put b 3 v := by
  simp [put, putLE3, Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, List.range']

private theorem putLE4_eq (b : ByteArray) (v : UInt32) : putLE4 b v = put b 4 v.toNat := by
  simp [put, putLE4, Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, List.range']
  have e8 : (v >>> 8).toUInt8 = UInt8.ofNat (v.toNat >>> 8) := by
    apply UInt8.toNat_inj.mp; simp [UInt32.toNat_shiftRight]
  have e16 : (v >>> 16).toUInt8 = UInt8.ofNat (v.toNat >>> 16) := by
    apply UInt8.toNat_inj.mp; simp [UInt32.toNat_shiftRight]
  have e24 : (v >>> 24).toUInt8 = UInt8.ofNat (v.toNat >>> 24) := by
    apply UInt8.toNat_inj.mp; simp [UInt32.toNat_shiftRight]
  rw [e8, e16, e24]

private theorem leAll6 {w1 w2 w3 w4 w5 w6 n1 n2 n3 n4 n5 n6 : Nat} {bs : Bytes}
    (h : leAll [w1, w2, w3, w4, w5, w6] [n1, n2, n3, n4, n5, n6] = some bs) :
    ∃ b1 b2 b3 b4 b5 b6, le w1 n1 = some b1 ∧ le w2 n2 = some b2 ∧ le w3 n3 = some b3 ∧ le w4 n4 = some b4 ∧
      le w5 n5 = some b5 ∧ le w6 n6 = some b6 ∧ bs = b1 ++ (b2 ++ (b3 ++ (b4 ++ (b5 ++ b6)))) := by
  cases h1 : le w1 n1 <;> cases h2 : le w2 n2 <;> cases h3 : le w3 n3 <;> cases h4 : le w4 n4 <;>
    cases h5 : le w5 n5 <;> cases h6 : le w6 n6 <;> simp [leAll, List.mapM_cons, h1, h2, h3, h4, h5, h6] at h ⊢
  simp [guard] at h
  exact h.symm

private theorem push_eq_put (x : ByteArray) (u : UInt8) : x.push u = put x 1 u.toNat := by
  simp [put, Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size]

private def decRec (ruleOf : Dec → UInt8) (locOf : Nat → UInt32 × UInt32) (d : Dec) : Rec :=
  ⟨d.line, d.out.toNat, rules.getD (ruleOf d).toNat .decided, d.mask.toNat,
    if d.cp == 0 then none else some ((locOf d.cp).1.toNat, (locOf d.cp).2.toNat)⟩

private def heldRec (h : Held) : Rec := ⟨h.index, 1, rules.getD h.rule.toNat .decided, 0, none⟩

private theorem idxOf_getD (k : Nat) (hk : k < rules.length) : rules.idxOf (rules.getD k .decided) = k := by
  have : k < 6 := hk
  have : k = 0 ∨ k = 1 ∨ k = 2 ∨ k = 3 ∨ k = 4 ∨ k = 5 := by omega
  rcases this with rfl | rfl | rfl | rfl | rfl | rfl <;> decide

private theorem encRec_some (r : Rec) (bs : Bytes) (h : encRec r = some bs) :
    r.ok = true ∧ leAll [3, 1, 1, 8, 4, 3] [r.index, r.outcome, rules.idxOf r.rule, r.reasons,
      (r.ref.getD (noChunk, noRow)).1, (r.ref.getD (noChunk, noRow)).2] = some bs := by
  unfold encRec at h
  by_cases hok : r.ok = true
  · simp only [guard, hok, if_true] at h
    refine ⟨hok, ?_⟩
    generalize r.ref.getD (noChunk, noRow) = p at h ⊢
    exact h
  · have hf : (failure : Option Unit) = none := rfl
    simp [guard, hok, hf] at h

private def decStep (ruleOf : Dec → UInt8) (locOf : Nat → UInt32 × UInt32) (b : ByteArray) (d : Dec) : ByteArray :=
  let (c, r) := if d.cp == 0 then (0xFFFFFFFF, 0xFFFFFF) else locOf d.cp
  putLE3 (putLE4 (put ((((putLE3 b d.line).push d.out).push (ruleOf d))) 8 d.mask.toNat) c) r.toNat

private theorem decStep_eq (ruleOf : Dec → UInt8) (locOf : Nat → UInt32 × UInt32) (b : ByteArray) (d : Dec)
    (bs : Bytes) (hr : (ruleOf d).toNat < rules.length) (h : encRec (decRec ruleOf locOf d) = some bs) :
    (decStep ruleOf locOf b d).toList = b.toList ++ bs := by
  obtain ⟨-, hl⟩ := encRec_some _ _ h
  obtain ⟨c, r, hcr⟩ : ∃ c r, (if d.cp == 0 then ((0xFFFFFFFF : UInt32), (0xFFFFFF : UInt32)) else locOf d.cp) = (c, r) :=
    ⟨_, _, rfl⟩
  have hg : ((decRec ruleOf locOf d).ref.getD (noChunk, noRow)) = (c.toNat, r.toNat) := by
    unfold decRec
    by_cases hcp : (d.cp == 0) = true
    · rw [if_pos hcp] at hcr
      simp only [Prod.mk.injEq] at hcr
      obtain ⟨rfl, rfl⟩ := hcr
      simp [hcp, noChunk, noRow]
    · rw [if_neg hcp] at hcr
      have h1 : (locOf d.cp).1 = c := by rw [hcr]
      have h2 : (locOf d.cp).2 = r := by rw [hcr]
      simp [hcp, h1, h2]
  rw [hg] at hl
  obtain ⟨b1, b2, b3, b4, b5, b6, e1, e2, e3, e4, e5, e6, rfl⟩ := leAll6 hl
  simp only [decRec] at e1 e2 e3 e4 e5 e6
  rw [idxOf_getD _ hr] at e3
  unfold decStep
  simp only [hcr]
  rw [putLE3_eq, putLE4_eq, putLE3_eq, push_eq_put, push_eq_put, le_put _ _ _ _ e6, le_put _ _ _ _ e5,
    le_put _ _ _ _ e4, le_put _ _ _ _ e3, le_put _ _ _ _ e2, le_put _ _ _ _ e1]
  simp

private theorem heldRec_rule (h : Held) (bs : Bytes) (he : encRec (heldRec h) = some bs) :
    h.rule.toNat < rules.length := by
  refine Classical.byContradiction fun hn => ?_
  have hg : rules.getD h.rule.toNat .decided = .decided := by
    rw [List.getD_eq_getElem?_getD, List.getElem?_eq_none (by omega)]; rfl
  obtain ⟨hok, -⟩ := encRec_some _ _ he
  have hn' : rules[h.rule.toNat]? = none := List.getElem?_eq_none (by omega)
  simp [heldRec, Rec.ok, hn'] at hok

private def heldStep (b : ByteArray) (h : Held) : ByteArray :=
  putLE3 (putLE4 (put (((putLE3 b h.index).push 1).push h.rule) 8 0) 0xFFFFFFFF) 0xFFFFFF

private theorem heldStep_eq (b : ByteArray) (h : Held) (bs : Bytes) (he : encRec (heldRec h) = some bs) :
    (heldStep b h).toList = b.toList ++ bs := by
  have hr := heldRec_rule h bs he
  obtain ⟨-, hl⟩ := encRec_some _ _ he
  simp only [heldRec, Option.getD_none] at hl
  obtain ⟨b1, b2, b3, b4, b5, b6, e1, e2, e3, e4, e5, e6, rfl⟩ := leAll6 hl
  rw [idxOf_getD _ hr] at e3
  unfold heldStep
  have cN : (0xFFFFFFFF : UInt32).toNat = noChunk := rfl
  have rN : (16777215 : Nat) = noRow := rfl
  have u1 : (1 : UInt8).toNat = 1 := rfl
  rw [putLE3_eq, putLE4_eq, putLE3_eq, push_eq_put, push_eq_put, cN, u1, rN, le_put _ _ _ _ e6, le_put _ _ _ _ e5,
    le_put _ _ _ _ e4, le_put _ _ _ _ e3, le_put _ _ _ _ e2, le_put _ _ _ _ e1]
  simp

private theorem leAll3 {w1 w2 w3 n1 n2 n3 : Nat} {bs : Bytes} (h : leAll [w1, w2, w3] [n1, n2, n3] = some bs) :
    ∃ b1 b2 b3, le w1 n1 = some b1 ∧ le w2 n2 = some b2 ∧ le w3 n3 = some b3 ∧ bs = b1 ++ (b2 ++ b3) := by
  cases h1 : le w1 n1 <;> cases h2 : le w2 n2 <;> cases h3 : le w3 n3 <;>
    simp [leAll, List.mapM_cons, h1, h2, h3] at h ⊢
  simp [guard] at h
  exact h.symm

private theorem ba_beq_iff (a b : ByteArray) : (a == b) = true ↔ a = b := by
  show (a.data == b.data) = true ↔ a = b
  rw [beq_iff_eq]
  exact ⟨ByteArray.ext, fun h => h ▸ rfl⟩

private theorem bypass_beq (x : ByteArray) : (x == zero64B) = (x.toList == Gate.zeroDigest) := by
  have hz : zero64B.toList = Gate.zeroDigest := by
    simp [zero64B, Gate.zeroDigest, Gate.digestBytes, Flat.Bin.toList_eq']
  rw [Bool.eq_iff_iff, ba_beq_iff, beq_iff_eq]
  constructor
  · intro h; subst h; exact hz
  · intro hc
    apply ByteArray.ext
    apply Array.toList_inj.mp
    rw [← Flat.Bin.toList_eq' x, ← Flat.Bin.toList_eq' zero64B, hc, hz]

private theorem putLeaf_eq (b : ByteArray) (l : Leaf) (bs : Bytes) (h : encLeaf l = some bs) :
    (putLeaf b l).toList = b.toList ++ bs := by
  unfold encLeaf at h
  by_cases hg : (l.ok && l.bypass.size = 64 && l.input.size = 64) = true
  · simp only [guard, hg, if_true] at h
    cases hl : leAll [1, 8, 1] [l.outcome, l.reasons, l.authority] with
    | none => simp [hl] at h
    | some hb =>
      simp [hl] at h
      obtain ⟨b1, b2, b3, e1, e2, e3, rfl⟩ := leAll3 hl
      subst h
      unfold putLeaf
      simp only [bypass_beq]
      have p3 := le_put (put (put b 1 l.outcome) 8 l.reasons) 1 l.authority _ e3
      have p2 := le_put (put b 1 l.outcome) 8 l.reasons _ e2
      have p1 := le_put b 1 l.outcome _ e1
      split
      · rename_i hc
        have hc' : l.bypass.toList = Gate.zeroDigest := by simpa using hc
        simp [Flat.Bin.toList_append', toList_push', p3, p2, p1, hc']
      · rename_i hc
        have hc' : ¬ l.bypass.toList = Gate.zeroDigest := by simpa using hc
        simp [Flat.Bin.toList_append', toList_push', p3, p2, p1, hc']
  · have hf : (failure : Option Unit) = none := rfl
    simp [guard, hg, hf] at h

private theorem putBlob2_eq (b x : ByteArray) (bs : Bytes) (h : blob2 x.toList = some bs) :
    (putBlob2 b x).toList = b.toList ++ bs := by
  unfold blob2 at h
  cases hl : le 2 x.toList.length with
  | none => simp [hl] at h
  | some l =>
    simp [hl] at h
    subst h
    unfold putBlob2
    rw [Flat.Bin.toList_append', le_put b 2 x.size l (by simpa [Flat.Bin.size_eq_length'] using hl)]
    simp

private theorem foldl_mapM {α : Type} (f : ByteArray → α → ByteArray) (g : α → Option Bytes)
    (hf : ∀ (b : ByteArray) (x : α) (bs : Bytes), g x = some bs → (f b x).toList = b.toList ++ bs) :
    ∀ (l : List α) (b : ByteArray) (bss : List Bytes), l.mapM g = some bss →
      (l.foldl f b).toList = b.toList ++ bss.flatten := by
  intro l
  induction l with
  | nil => intro b bss h; simp [List.mapM_nil] at h; subst h; simp
  | cons x xs ih =>
    intro b bss h
    cases hx : g x with
    | none => simp [List.mapM_cons, hx] at h
    | some bx =>
      cases hxs : xs.mapM g with
      | none => simp [List.mapM_cons, hx, hxs] at h
      | some rest =>
        simp [List.mapM_cons, hx, hxs] at h
        subst h
        simp only [List.foldl_cons, List.flatten_cons]
        rw [ih _ _ hxs, hf b x bx hx]
        simp

private def RowGood (tag : UInt8) (s : LineSrc) : Prop :=
  (rowOfLine tag s).size = 924 ∧ ∀ b, (putRow b tag s).toList = b.toList ++ (rowOfLine tag s).toList

private theorem rowStep_eq (b : ByteArray) (tag : UInt8) (s : LineSrc) (bs : Bytes) (hg : RowGood tag s)
    (h : blob2 (rowOfLine tag s).toList = some bs) : (putRow (put b 2 924) tag s).toList = b.toList ++ bs := by
  obtain ⟨hs, hp⟩ := hg
  have := putBlob2_eq b (rowOfLine tag s) bs h
  unfold putBlob2 at this
  rw [hs, Flat.Bin.toList_append'] at this
  rw [hp, this]

private theorem encodeAns_ok (a : AnsFrame) (hw : a.word = .OK) (bs : Bytes) (h : encodeAns a = some bs) :
    a.digest.size = 64 ∧ a.head.size = 64 ∧ a.root.size = 64 ∧
    ∃ hv rv xv, leAll [2, 1, 4, 8, 4] [ansVersion, Word.OK.code, a.shard, a.batch, a.recs.length] = some hv ∧
      a.recs.mapM encRec = some rv ∧ encExt a.ext = some xv ∧
      bs = magicAns ++ (hv ++ (a.digest.toList ++ (rv.flatten ++ (a.head.toList ++ (a.root.toList ++ xv))))) := by
  have hf : (failure : Option Unit) = none := rfl
  unfold encodeAns at h
  rw [hw] at h
  simp [guard] at h
  have c1 : a.digest.size = 64 := by
    by_cases c : a.digest.size = 64
    · exact c
    · simp [c, hf] at h
  have c2 : (a.head.size = 64 ∧ a.root.size = 64) ∧
      ((List.map (fun x => x.index) a.recs).mergeSort fun i j => decide (i ≤ j)) = List.range a.recs.length := by
    by_cases c : (a.head.size = 64 ∧ a.root.size = 64) ∧
      ((List.map (fun x => x.index) a.recs).mergeSort fun i j => decide (i ≤ j)) = List.range a.recs.length
    · exact c
    · simp [c1, c, hf] at h
  simp only [if_pos c1, if_pos c2, Option.bind_some] at h
  cases hh : leAll [2, 1, 4, 8, 4] [ansVersion, Word.OK.code, a.shard, a.batch, a.recs.length] with
  | none => simp [hh] at h
  | some hv =>
    cases hr : List.mapM encRec a.recs with
    | none => simp [hh, hr] at h
    | some rv =>
      cases hx : encExt a.ext with
      | none => simp [hh, hr, hx] at h
      | some xv =>
        simp [hh, hr, hx] at h
        refine ⟨c1, c2.1.1, c2.1.2, hv, rv, xv, rfl, rfl, rfl, ?_⟩
        exact h.symm

private theorem encExt_ok (e : Ext) (xv : Bytes) (h : encExt e = some xv) :
    e.hold.size = 16 ∧ e.grant.size = 64 ∧ e.auth.size = 208 ∧ ∃ ns ls ad nl ll al,
      e.notes.mapM (fun x => blob2 x.toList) = some ns ∧
      e.leaves.mapM encLeaf = some ls ∧ e.adds.mapM (fun x => blob2 x.toList) = some ad ∧
      le 4 e.notes.length = some nl ∧ le 4 e.leaves.length = some ll ∧ le 4 e.adds.length = some al ∧
      xv = e.hold.toList ++ (e.grant.toList ++ (e.auth.toList ++
        (nl ++ (ns.flatten ++ (ll ++ (ls.flatten ++ (al ++ ad.flatten))))))) := by
  have hf : (failure : Option Unit) = none := rfl
  unfold encExt at h
  simp [guard] at h
  have c0 : (e.hold.size = 16 ∧ e.grant.size = 64) ∧ e.auth.size = 208 := by
    by_cases c : (e.hold.size = 16 ∧ e.grant.size = 64) ∧ e.auth.size = 208
    · exact c
    · exfalso
      rw [if_neg c] at h
      first | exact Option.noConfusion h | simp [hf] at h | cases h
  have c1 : e.hold.size = 16 ∧ e.grant.size = 64 ∧ e.auth.size = 208 := ⟨c0.1.1, c0.1.2, c0.2⟩
  simp only [if_pos c0, Option.bind_some] at h
  cases hn : List.mapM (fun x => blob2 x.toList) e.notes with
  | none => simp [hn] at h
  | some ns =>
    cases hl : List.mapM encLeaf e.leaves with
    | none => simp [hn, hl] at h
    | some ls =>
      cases ha : List.mapM (fun x => blob2 x.toList) e.adds with
      | none => simp [hn, hl, ha] at h
      | some ad =>
        cases h1 : le 4 e.notes.length with
        | none => simp [hn, hl, ha, h1] at h
        | some nl =>
          cases h2 : le 4 e.leaves.length with
          | none => simp [hn, hl, ha, h1, h2] at h
          | some ll =>
            cases h3 : le 4 e.adds.length with
            | none => simp [hn, hl, ha, h1, h2, h3] at h
            | some al =>
              simp [hn, hl, ha, h1, h2, h3] at h
              exact ⟨c1.1, c1.2.1, c1.2.2, ns, ls, ad, nl, ll, al, rfl, rfl, rfl, rfl, rfl, rfl, h.symm⟩

private theorem mapM_map {α β γ : Type} (f : α → β) (g : β → Option γ) :
    ∀ (l : List α), (l.map f).mapM g = l.mapM (fun x => g (f x))
  | [] => rfl
  | x :: xs => by simp [List.mapM_cons, mapM_map f g xs]

private theorem mapM_append_some {α β : Type} (g : α → Option β) :
    ∀ (l1 l2 : List α) (r : List β), (l1 ++ l2).mapM g = some r →
      ∃ r1 r2, l1.mapM g = some r1 ∧ l2.mapM g = some r2 ∧ r = r1 ++ r2
  | [], l2, r, h => ⟨[], r, rfl, by simpa using h, by simp⟩
  | x :: xs, l2, r, h => by
    cases hx : g x with
    | none => simp [List.mapM_cons, hx] at h
    | some bx =>
      cases hxs : (xs ++ l2).mapM g with
      | none => simp [List.mapM_cons, hx, hxs] at h
      | some rest =>
        simp [List.mapM_cons, hx, hxs] at h
        obtain ⟨r1, r2, h1, h2, h3⟩ := mapM_append_some g xs l2 rest hxs
        refine ⟨bx :: r1, r2, ?_, h2, ?_⟩
        · simp [List.mapM_cons, hx, h1]
        · rw [← h]; simp [h3]

private theorem foldl_mapM' {α : Type} (f : ByteArray → α → ByteArray) (g : α → Option Bytes) :
    ∀ (l : List α), (∀ (b : ByteArray) (x : α) (bs : Bytes), x ∈ l → g x = some bs → (f b x).toList = b.toList ++ bs) →
      ∀ (b : ByteArray) (bss : List Bytes), l.mapM g = some bss → (l.foldl f b).toList = b.toList ++ bss.flatten := by
  intro l
  induction l with
  | nil => intro _ b bss h; simp [List.mapM_nil] at h; subst h; simp
  | cons x xs ih =>
    intro hf b bss h
    cases hx : g x with
    | none => simp [List.mapM_cons, hx] at h
    | some bx =>
      cases hxs : xs.mapM g with
      | none => simp [List.mapM_cons, hx, hxs] at h
      | some rest =>
        simp [List.mapM_cons, hx, hxs] at h
        subst h
        simp only [List.foldl_cons, List.flatten_cons]
        rw [ih (fun b y bs hy => hf b y bs (List.mem_cons_of_mem _ hy)) _ _ hxs,
          hf b x bx (List.mem_cons_self) hx]
        simp

private theorem leAll5 {w1 w2 w3 w4 w5 n1 n2 n3 n4 n5 : Nat} {bs : Bytes}
    (h : leAll [w1, w2, w3, w4, w5] [n1, n2, n3, n4, n5] = some bs) :
    ∃ b1 b2 b3 b4 b5, le w1 n1 = some b1 ∧ le w2 n2 = some b2 ∧ le w3 n3 = some b3 ∧ le w4 n4 = some b4 ∧
      le w5 n5 = some b5 ∧ bs = b1 ++ (b2 ++ (b3 ++ (b4 ++ b5))) := by
  cases h1 : le w1 n1 <;> cases h2 : le w2 n2 <;> cases h3 : le w3 n3 <;> cases h4 : le w4 n4 <;>
    cases h5 : le w5 n5 <;> simp [leAll, List.mapM_cons, h1, h2, h3, h4, h5] at h ⊢
  simp [guard] at h
  exact h.symm

private theorem answer_aux (shard batch : Nat) (digest head root hold grant auth : ByteArray) (ds : Array Dec)
    (ruleOf : Dec → UInt8) (locOf : Nat → UInt32 × UInt32) (held : Array Held) (notes : Array ByteArray)
    (leaves : Array Leaf) (lines : Array LineSrc) (rel unr : Array Nat)
    (h : (encodeAns (ansOfOut shard batch digest head root hold grant auth ds ruleOf locOf held notes leaves lines rel unr)).isSome)
    (hrule : ∀ d ∈ ds, (ruleOf d).toNat < rules.length)
    (hg1 : ∀ i ∈ rel, RowGood 1 lines[i]!) (hg2 : ∀ i ∈ unr, RowGood 2 lines[i]!) :
    some (encodeAnsOut shard batch digest head root hold grant auth ds ruleOf locOf held notes leaves lines rel unr).toList =
      encodeAns (ansOfOut shard batch digest head root hold grant auth ds ruleOf locOf held notes leaves lines rel unr) := by
  obtain ⟨bs, hbs⟩ := Option.isSome_iff_exists.mp h
  rw [hbs]
  have hw : (ansOfOut shard batch digest head root hold grant auth ds ruleOf locOf held notes leaves lines rel unr).word = .OK := rfl
  obtain ⟨c1, c2, c3, hv, rv, xv, e1, e2, e3, rfl⟩ := encodeAns_ok _ hw bs hbs
  obtain ⟨hh, hgr, har, ns, ls, ad, nl, ll, al, f1, f2, f3, f4, f5, f6, rfl⟩ := encExt_ok _ xv e3
  dsimp only [ansOfOut] at c1 c2 c3 e1 e2 hh hgr har f1 f2 f3 f4 f5 f6
  have hn : ds.size + held.size =
      (ds.toList.map (decRec ruleOf locOf) ++ held.toList.map heldRec).length := by simp
  have e1' : leAll [2, 1, 4, 8, 4] [ansVersion, Word.OK.code, shard, batch, ds.size + held.size] = some hv := by
    rw [hn]; exact e1
  obtain ⟨q1, q2, q3, q4, q5, i1, i2, i3, i4, i5, rfl⟩ := leAll5 e1'
  have e2' : (ds.toList.map (decRec ruleOf locOf) ++ held.toList.map heldRec).mapM encRec = some rv := e2
  obtain ⟨r1, r2, m1, m2, rfl⟩ := mapM_append_some encRec _ _ _ e2'
  rw [mapM_map] at m1 m2
  have f1' : notes.toList.mapM (fun x => blob2 x.toList) = some ns := f1
  have f2' : leaves.toList.mapM encLeaf = some ls := f2
  have f3' : (rel.toList.map (fun i => rowOfLine 1 lines[i]!) ++ unr.toList.map (fun i => rowOfLine 2 lines[i]!)).mapM
      (fun x => blob2 x.toList) = some ad := f3
  obtain ⟨a1, a2, k1, k2, rfl⟩ := mapM_append_some _ _ _ _ f3'
  rw [mapM_map] at k1 k2
  have f4' : le 4 notes.size = some nl := by simpa using f4
  have f5' : le 4 leaves.size = some ll := by simpa using f5
  have f6' : le 4 (rel.size + unr.size) = some al := by simpa using f6
  have hE : encodeAnsOut shard batch digest head root hold grant auth ds ruleOf locOf held notes leaves lines rel unr =
      (let cap := 160 + 20 * (ds.size + held.size) + notes.foldl (fun n x => n + 2 + x.size) 4 +
          140 * leaves.size + 4 + 930 * (rel.size + unr.size)
       let b := putL (ByteArray.emptyWithCapacity cap) magicAns
       let b := put (put (put (put (put b 2 ansVersion) 1 Word.OK.code) 4 shard) 8 batch) 4 (ds.size + held.size)
       let b := b ++ digest
       let b := ds.foldl (decStep ruleOf locOf) b
       let b := held.foldl heldStep b
       let b := b ++ head ++ root ++ hold ++ grant ++ auth
       let b := notes.foldl putBlob2 (put b 4 notes.size)
       let b := leaves.foldl putLeaf (put b 4 leaves.size)
       let b := put b 4 (rel.size + unr.size)
       let b := rel.foldl (fun b i => putRow (put b 2 924) 1 lines[i]!) b
       unr.foldl (fun b i => putRow (put b 2 924) 2 lines[i]!) b) := rfl
  have hF2 : ∀ (b : ByteArray) (x : Nat) (bs : Bytes), x ∈ unr.toList → blob2 (rowOfLine 2 lines[x]!).toList = some bs →
      (putRow (put b 2 924) 2 lines[x]!).toList = b.toList ++ bs :=
    fun b i bs hi hg => rowStep_eq b 2 lines[i]! bs (hg2 i (by simpa using hi)) hg
  have hF1 : ∀ (b : ByteArray) (x : Nat) (bs : Bytes), x ∈ rel.toList → blob2 (rowOfLine 1 lines[x]!).toList = some bs →
      (putRow (put b 2 924) 1 lines[x]!).toList = b.toList ++ bs :=
    fun b i bs hi hg => rowStep_eq b 1 lines[i]! bs (hg1 i (by simpa using hi)) hg
  have T2 := foldl_mapM' (fun b i => putRow (put b 2 924) 2 lines[i]!) (fun i => blob2 (rowOfLine 2 lines[i]!).toList)
    unr.toList hF2
  have T1 := foldl_mapM' (fun b i => putRow (put b 2 924) 1 lines[i]!) (fun i => blob2 (rowOfLine 1 lines[i]!).toList)
    rel.toList hF1
  have TL := foldl_mapM' putLeaf encLeaf leaves.toList (fun b l bs _ hg => putLeaf_eq b l bs hg)
  have TN := foldl_mapM' putBlob2 (fun x => blob2 x.toList) notes.toList (fun b x bs _ hg => putBlob2_eq b x bs hg)
  have TH := foldl_mapM' heldStep (fun h => encRec (heldRec h)) held.toList (fun b x bs _ hg => heldStep_eq b x bs hg)
  have TD := foldl_mapM' (decStep ruleOf locOf) (fun d => encRec (decRec ruleOf locOf d)) ds.toList
    (fun b d bs hd hg => decStep_eq ruleOf locOf b d bs (hrule d (by simpa using hd)) hg)
  rw [hE]
  dsimp only
  simp only [← Array.foldl_toList]
  rw [T2 _ _ k2, T1 _ _ k1, le_put _ 4 (rel.size + unr.size) al f6', TL _ _ f2', le_put _ 4 leaves.size ll f5', TN _ _ f1',
    le_put _ 4 notes.size nl f4']
  simp only [Flat.Bin.toList_append']
  rw [TH _ _ m2, TD _ _ m1]
  simp only [Flat.Bin.toList_append']
  rw [le_put _ 4 (ds.size + held.size) q5 i5, le_put _ 8 batch q4 i4,
    le_put _ 4 shard q3 i3, le_put _ 1 Word.OK.code q2 i2, le_put _ 2 ansVersion q1 i1]
  simp [ansOfOut, toList_putL, empty_toList, List.flatten_append]

private theorem or_shift (a c k : Nat) (h : c < 2 ^ k) : a <<< k ||| c = a * 2 ^ k + c := by
  rw [← Nat.shiftLeft_add_eq_or_of_lt h, Nat.shiftLeft_eq]

private theorem or_mul (a c k : Nat) (h : c < 2 ^ k) : a * 2 ^ k ||| c = a * 2 ^ k + c := by
  rw [← Nat.shiftLeft_eq, or_shift a c k h, Nat.shiftLeft_eq]

private theorem shl_mod (a k : Nat) (ha : a < 256) (hk : k ≤ 56) : a <<< k % 2 ^ 64 = a * 2 ^ k := by
  rw [Nat.shiftLeft_eq, Nat.mod_eq_of_lt]
  have : 2 ^ k ≤ 2 ^ 56 := Nat.pow_le_pow_right (by omega) hk
  have : a * 2 ^ k < 256 * 2 ^ k := Nat.mul_lt_mul_of_pos_right ha (Nat.two_pow_pos k)
  have : 256 * 2 ^ k ≤ 256 * 2 ^ 56 := Nat.mul_le_mul_left 256 (by assumption)
  have : (256 : Nat) * 2 ^ 56 = 2 ^ 64 := by decide
  omega

private theorem or8 {a0 a1 a2 a3 a4 a5 a6 a7 : Nat} (h0 : a0 < 256) (h1 : a1 < 256) (h2 : a2 < 256) (h3 : a3 < 256)
    (h4 : a4 < 256) (h5 : a5 < 256) (h6 : a6 < 256) (h7 : a7 < 256) :
    (a0 <<< 56 % 2 ^ 64 ||| a1 <<< 48 % 2 ^ 64 ||| a2 <<< 40 % 2 ^ 64 ||| a3 <<< 32 % 2 ^ 64 ||| a4 <<< 24 % 2 ^ 64 |||
      a5 <<< 16 % 2 ^ 64 ||| a6 <<< 8 % 2 ^ 64 ||| a7) =
    a0 * 256 ^ 7 + (a1 * 256 ^ 6 + (a2 * 256 ^ 5 + (a3 * 256 ^ 4 + (a4 * 256 ^ 3 + (a5 * 256 ^ 2 +
      (a6 * 256 ^ 1 + (a7 * 256 ^ 0 + 0))))))) := by
  rw [shl_mod a0 56 h0 (by omega), shl_mod a1 48 h1 (by omega), shl_mod a2 40 h2 (by omega),
    shl_mod a3 32 h3 (by omega), shl_mod a4 24 h4 (by omega), shl_mod a5 16 h5 (by omega), shl_mod a6 8 h6 (by omega)]
  simp only [Nat.or_assoc]
  rw [or_mul a6 a7 8 (by simp only [Nat.reducePow]; omega)]
  rw [or_mul a5 _ 16 (by simp only [Nat.reducePow]; omega)]
  rw [or_mul a4 _ 24 (by simp only [Nat.reducePow]; omega)]
  rw [or_mul a3 _ 32 (by simp only [Nat.reducePow]; omega)]
  rw [or_mul a2 _ 40 (by simp only [Nat.reducePow]; omega)]
  rw [or_mul a1 _ 48 (by simp only [Nat.reducePow]; omega)]
  rw [or_mul a0 _ 56 (by simp only [Nat.reducePow]; omega)]
  simp only [Nat.reducePow]
  omega

private theorem take_succ_drop (L : List UInt8) (p k : Nat) (h : p < L.length) :
    (L.drop p).take (k + 1) = L[p] :: (L.drop (p + 1)).take k := by
  rw [List.drop_eq_getElem_cons h, List.take_succ_cons]

private theorem beNat_slice (L : List UInt8) (p k : Nat) (h : p + k + 1 ≤ L.length) :
    beNat ((L.drop p).take (k + 1)) = L[p].toNat * 256 ^ k + beNat ((L.drop (p + 1)).take k) := by
  rw [take_succ_drop L p k (by omega), beNat_cons]
  simp only [List.length_take, List.length_drop]
  rw [show min k (L.length - (p + 1)) = k by omega]


private theorem be8_toNat (b : ByteArray) (p : Nat) (h : p + 8 ≤ b.size) :
    (be8 b p).toNat = beNat ((b.toList.drop p).take 8) := by
  have hL : b.toList.length = b.size := (Flat.Bin.size_eq_length' b).symm
  have g : ∀ i (hi : i < 8), b.get! (p + i) = b.toList[p + i]'(by omega) := fun i hi => get!_lt b (p + i) (by omega)
  rw [beNat_slice _ p 7 (by omega), beNat_slice _ (p + 1) 6 (by omega), beNat_slice _ (p + 1 + 1) 5 (by omega),
    beNat_slice _ (p + 1 + 1 + 1) 4 (by omega), beNat_slice _ (p + 1 + 1 + 1 + 1) 3 (by omega),
    beNat_slice _ (p + 1 + 1 + 1 + 1 + 1) 2 (by omega), beNat_slice _ (p + 1 + 1 + 1 + 1 + 1 + 1) 1 (by omega),
    beNat_slice _ (p + 1 + 1 + 1 + 1 + 1 + 1 + 1) 0 (by omega)]
  unfold be8
  have g0 := g 0 (by omega); have g1 := g 1 (by omega); have g2 := g 2 (by omega); have g3 := g 3 (by omega)
  have g4 := g 4 (by omega); have g5 := g 5 (by omega); have g6 := g 6 (by omega); have g7 := g 7 (by omega)
  simp only [Nat.add_zero] at g0
  rw [g0, g1, g2, g3, g4, g5, g6, g7]
  simp only [UInt64.toNat_or, UInt64.toNat_shiftLeft, UInt8.toNat_toUInt64, List.take_zero, beNat, List.foldl_nil,
    Nat.add_assoc]
  simp only [UInt64.reduceToNat, Nat.reduceMod, Nat.reduceAdd]
  exact or8 (UInt8.toNat_lt _) (UInt8.toNat_lt _) (UInt8.toNat_lt _) (UInt8.toNat_lt _) (UInt8.toNat_lt _)
    (UInt8.toNat_lt _) (UInt8.toNat_lt _) (UInt8.toNat_lt _)

private theorem be2_toNat (b : ByteArray) (p : Nat) (h : p + 2 ≤ b.size) :
    (be2 b p).toNat = beNat ((b.toList.drop p).take 2) := by
  have hL : b.toList.length = b.size := (Flat.Bin.size_eq_length' b).symm
  rw [beNat_slice _ p 1 (by omega), beNat_slice _ (p + 1) 0 (by omega)]
  unfold be2
  rw [get!_lt b p (by omega), get!_lt b (p + 1) (by omega)]
  simp only [UInt64.toNat_or, UInt64.toNat_shiftLeft, UInt8.toNat_toUInt64, List.take_zero, beNat, List.foldl_nil,
    UInt64.reduceToNat, Nat.reduceMod]
  rw [shl_mod _ 8 (UInt8.toNat_lt _) (by omega), or_mul _ _ 8 (by simp only [Nat.reducePow]; exact UInt8.toNat_lt _)]
  simp only [Nat.reducePow]; omega


private theorem len_slice (L : List UInt8) (p k : Nat) (h : p + k ≤ L.length) : ((L.drop p).take k).length = k := by
  simp; omega


private theorem or4 {a0 a1 a2 a3 : Nat} (h0 : a0 < 256) (h1 : a1 < 256) (h2 : a2 < 256) (h3 : a3 < 256) :
    (a0 <<< 24 % 2 ^ 64 ||| a1 <<< 16 % 2 ^ 64 ||| a2 <<< 8 % 2 ^ 64 ||| a3) =
    a0 * 256 ^ 3 + (a1 * 256 ^ 2 + (a2 * 256 ^ 1 + (a3 * 256 ^ 0 + 0))) := by
  rw [shl_mod a0 24 h0 (by omega), shl_mod a1 16 h1 (by omega), shl_mod a2 8 h2 (by omega)]
  simp only [Nat.or_assoc]
  rw [or_mul a2 a3 8 (by simp only [Nat.reducePow]; omega)]
  rw [or_mul a1 _ 16 (by simp only [Nat.reducePow]; omega)]
  rw [or_mul a0 _ 24 (by simp only [Nat.reducePow]; omega)]
  simp only [Nat.reducePow]
  omega

private theorem be4_toNat (b : ByteArray) (p : Nat) (h : p + 4 ≤ b.size) :
    (be4 b p).toNat = beNat ((b.toList.drop p).take 4) := by
  have hL : b.toList.length = b.size := (Flat.Bin.size_eq_length' b).symm
  rw [beNat_slice _ p 3 (by omega), beNat_slice _ (p + 1) 2 (by omega), beNat_slice _ (p + 1 + 1) 1 (by omega),
    beNat_slice _ (p + 1 + 1 + 1) 0 (by omega)]
  unfold be4
  rw [get!_lt b p (by omega), get!_lt b (p + 1) (by omega), get!_lt b (p + 2) (by omega), get!_lt b (p + 3) (by omega)]
  simp only [UInt64.toNat_or, UInt64.toNat_shiftLeft, UInt8.toNat_toUInt64, List.take_zero, beNat, List.foldl_nil,
    Nat.add_assoc]
  simp only [UInt64.reduceToNat, Nat.reduceMod, Nat.reduceAdd]
  exact or4 (UInt8.toNat_lt _) (UInt8.toNat_lt _) (UInt8.toNat_lt _) (UInt8.toNat_lt _)


private theorem idxFold (b : ByteArray) : ∀ (m s acc : Nat), s + m ≤ b.size →
    (List.range' s m).foldl (fun acc t => acc * 256 + (b.get! t).toNat) acc =
      acc * 256 ^ m + beNat ((b.toList.drop s).take m)
  | 0, s, acc, _ => by simp [beNat]
  | m + 1, s, acc, h => by
    have hL : b.toList.length = b.size := (Flat.Bin.size_eq_length' b).symm
    rw [List.range'_succ, List.foldl_cons, idxFold b m (s + 1) _ (by omega), beNat_slice _ s m (by omega),
      get!_lt b s (by omega), Nat.pow_succ]
    have : acc * 256 * 256 ^ m = acc * (256 ^ m * 256) := by rw [Nat.mul_assoc, Nat.mul_comm 256]
    simp only [Nat.add_mul, Nat.add_assoc, this]

private theorem u64Fold (b : ByteArray) : ∀ (m s : Nat) (c : UInt64), m ≤ 7 → c.toNat < 256 ^ (7 - m) →
    ((List.range' s m).foldl (fun (c : UInt64) t => c <<< 8 ||| (b.get! t).toUInt64) c).toNat =
      (List.range' s m).foldl (fun acc t => acc * 256 + (b.get! t).toNat) c.toNat
  | 0, s, c, _, _ => by simp
  | m + 1, s, c, hm, hc => by
    rw [List.range'_succ, List.foldl_cons, List.foldl_cons]
    have hc6 : c.toNat < 72057594037927936 := by
      have : 256 ^ (7 - (m + 1)) ≤ 256 ^ 6 := Nat.pow_le_pow_right (by omega) (by omega)
      have : (256 : Nat) ^ 6 < 72057594037927936 := by decide
      omega
    have hx : (b.get! s).toNat < 256 := UInt8.toNat_lt _
    have step : (c <<< 8 ||| (b.get! s).toUInt64).toNat = c.toNat * 256 + (b.get! s).toNat := by
      rw [UInt64.toNat_or, UInt64.toNat_shiftLeft, UInt8.toNat_toUInt64]
      simp only [UInt64.reduceToNat, Nat.reduceMod]
      rw [Nat.shiftLeft_eq, Nat.mod_eq_of_lt (by simp only [Nat.reducePow]; omega),
        or_mul _ _ 8 (by simp only [Nat.reducePow]; omega)]
    rw [u64Fold b m (s + 1) _ (by omega) (by
      rw [step]
      have : 256 ^ (7 - m) = 256 ^ (7 - (m + 1)) * 256 := by rw [← Nat.pow_succ]; congr 1; omega
      omega), step]

private theorem range'_app1 (s m n : Nat) : List.range' s m ++ List.range' (s + m) n = List.range' s (m + n) := by
  have := List.range'_append (s := s) (m := m) (n := n) (step := 1)
  simp only [Nat.one_mul] at this
  exact this

private theorem outerFold (b : ByteArray) (i : Nat) : ∀ (k acc : Nat), i + 7 * k ≤ b.size →
    (List.range' 0 k).foldl (fun acc g => acc * 72057594037927936 +
      ((List.range' (i + 7 * g) 7).foldl (fun (c : UInt64) t => c <<< 8 ||| (b.get! t).toUInt64) 0).toNat) acc =
    (List.range' i (7 * k)).foldl (fun acc t => acc * 256 + (b.get! t).toNat) acc
  | 0, acc, _ => by simp
  | k + 1, acc, h => by
    rw [← range'_app1 0 k 1, List.foldl_append, outerFold b i k acc (by omega), Nat.mul_succ, ← range'_app1 i (7 * k) 7,
      List.foldl_append]
    simp only [Nat.zero_add, List.range'_one, List.foldl_cons, List.foldl_nil]
    rw [u64Fold b 7 _ 0 (by omega) (by decide), idxFold b 7 _ _ (by omega), idxFold b 7 _ _ (by omega)]
    simp

private theorem beNatA_eq (b : ByteArray) (i j acc : Nat) (hj : j ≤ b.size) (hij : i ≤ j) :
    beNatA b i j acc = acc * 256 ^ (j - i) + beNat ((b.toList.drop i).take (j - i)) := by
  unfold beNatA
  simp only [Id.run, Std.Legacy.Range.forIn_eq_forIn_range', List.forIn_pure_yield_eq_foldl, pure_bind,
    Std.Legacy.Range.size, Nat.add_sub_cancel_left, Nat.add_sub_cancel, Nat.div_one, Nat.sub_zero]
  have hk : 7 * ((j - i) / 7) ≤ j - i := Nat.mul_div_le (j - i) 7
  rw [outerFold b i _ _ (by omega), ← List.foldl_append, range'_app1, show 7 * ((j - i) / 7) + (j - (i + 7 * ((j - i) / 7))) = j - i by omega,
    idxFold b _ _ _ (by omega)]
  rfl

private theorem copySlice_toList (src dest : ByteArray) (so d len : Nat) (hd : d = dest.size) :
    (src.copySlice so dest d len).toList = dest.toList ++ (src.toList.drop so).take len := by
  subst hd
  simp only [ByteArray.copySlice, Flat.Bin.toList_eq', Array.toList_append, Array.toList_extract, List.extract_eq_take_drop, List.drop_zero, Nat.sub_zero]
  have e : dest.size = dest.data.toList.length := by rw [Flat.Bin.size_eq_length', Flat.Bin.toList_eq']
  rw [e, List.take_length, Nat.add_sub_cancel_left, List.drop_eq_nil_of_le (Nat.le_add_right _ _), List.take_nil,
    List.append_nil]

private theorem size_extract' (x : ByteArray) (p e : Nat) (he : e ≤ x.size) : (x.extract p e).size = e - p := by
  rw [ByteArray.size_extract]; omega

private theorem get!_extract (x : ByteArray) (p e i : Nat) (h : i < e - p) (he : e ≤ x.size) :
    (x.extract p e).get! i = x.get! (p + i) := by
  have hL : x.toList.length = x.size := (Flat.Bin.size_eq_length' x).symm
  have hl : i < (x.extract p e).toList.length := by
    rw [← Flat.Bin.size_eq_length', size_extract' x p e he]; exact h
  rw [get!_lt _ i hl, get!_lt x (p + i) (by omega)]
  simp [Flat.Bin.toList_extract']

private theorem identRest_extract (x : ByteArray) (p e : Nat) (he : e ≤ x.size) :
    ∀ (k i f : Nat), f - i = k → f ≤ e - p → identRest (x.extract p e) i f = identRest x (p + i) (p + f) := by
  intro k
  induction k with
  | zero =>
    intro i f hk hf
    unfold identRest
    rw [if_neg (by omega), if_neg (by omega)]
  | succ k ih =>
    intro i f hk hf
    unfold identRest
    rw [if_pos (by omega), if_pos (by omega), get!_extract x p e i (by omega) he, ih (i + 1) f (by omega) hf,
      show p + (i + 1) = p + i + 1 by omega]

private def Nid (b : ByteArray) (p : Nat) : Nat := (b.get! p).toNat * 256 + (b.get! (p + 1)).toNat

private theorem identEnd_iff (b : ByteArray) (p lim : Nat) :
    identEnd b p lim ≠ 0 ↔ (p + 3 ≤ lim ∧ lim ≤ b.size ∧ 1 ≤ Nid b p ∧ Nid b p ≤ 128 ∧ p + 2 + Nid b p ≤ lim ∧
      identTab.get! (b.get! (p + 2)).toNat = 1 ∧ identRest b (p + 3) (p + 2 + Nid b p) = true) := by
  unfold identEnd Nid
  by_cases c1 : (decide (lim < p + 3) || decide (b.size < lim)) = true
  · rw [if_pos c1]
    simp only [Bool.or_eq_true, decide_eq_true_eq] at c1
    constructor
    · intro h; exact absurd rfl h
    · intro h; omega
  · rw [if_neg c1]
    simp only [Bool.or_eq_true, decide_eq_true_eq, not_or] at c1
    dsimp only
    split
    · rename_i h
      simp only [Bool.or_eq_true, beq_iff_eq, decide_eq_true_eq, bne_iff_ne, ne_eq, Bool.not_eq_true'] at h
      constructor
      · intro h0; exact absurd rfl h0
      · intro hr
        obtain ⟨_, _, h3, h4, h5, h6, h7⟩ := hr
        rcases h with ((((h | h) | h) | h) | h)
        · omega
        · omega
        · omega
        · exact absurd h6 h
        · rw [show p + 2 + 1 = p + 3 by omega] at h
          rw [h7] at h; cases h
    · rename_i h
      simp only [Bool.or_eq_true, beq_iff_eq, decide_eq_true_eq, bne_iff_ne, ne_eq, Bool.not_eq_true', not_or] at h
      obtain ⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, h5⟩ := h
      constructor
      · intro _
        refine ⟨by omega, by omega, by omega, by omega, by omega, Classical.not_not.mp h4, ?_⟩
        rw [show p + 3 = p + 2 + 1 by omega]
        simpa using h5
      · intro _; omega

private theorem identEnd_val {b : ByteArray} {p lim : Nat} (h : identEnd b p lim ≠ 0) :
    identEnd b p lim = p + 2 + Nid b p := by
  have hi := (identEnd_iff b p lim).mp h
  unfold identEnd Nid at *
  rw [if_neg (by simp only [Bool.or_eq_true, decide_eq_true_eq]; omega)]
  dsimp only
  rw [if_neg]
  simp only [Bool.or_eq_true, beq_iff_eq, decide_eq_true_eq, bne_iff_ne, ne_eq, Bool.not_eq_true', not_or]
  obtain ⟨_, _, h3, h4, h5, h6, h7⟩ := hi
  refine ⟨⟨⟨⟨?_, ?_⟩, ?_⟩, ?_⟩, ?_⟩
  all_goals first | omega | exact h6 | exact (fun h => h h6) | exact h7 | (simpa using h7)

private theorem push_tl (b : ByteArray) (c : UInt8) : (b.push c).toList = b.toList ++ [c] := by
  simp [Flat.Bin.toList_eq', ByteArray.data_push]

private theorem identEnd_extract (x : ByteArray) (p e q : Nat) (he : e ≤ x.size) (hpq : p ≤ q)
    (h : identEnd x q e ≠ 0) : identEnd (x.extract p e) (q - p) (e - p) = identEnd x q e - p := by
  have hi := (identEnd_iff x q e).mp h
  have hv := identEnd_val h
  obtain ⟨a1, a2, a3, a4, a5, a6, a7⟩ := hi
  have sz := size_extract' x p e he
  have n1 : Nid (x.extract p e) (q - p) = Nid x q := by
    unfold Nid
    rw [get!_extract x p e (q - p) (by omega) he, get!_extract x p e (q - p + 1) (by omega) he,
      show p + (q - p) = q by omega, show p + (q - p + 1) = q + 1 by omega]
  have h' : identEnd (x.extract p e) (q - p) (e - p) ≠ 0 := by
    rw [identEnd_iff, n1, sz]
    refine ⟨by omega, by omega, a3, a4, by omega, ?_, ?_⟩
    · rw [get!_extract x p e (q - p + 2) (by omega) he, show p + (q - p + 2) = q + 2 by omega]
      exact a6
    · rw [identRest_extract x p e he _ (q - p + 3) (q - p + 2 + Nid x q) rfl (by omega),
        show p + (q - p + 3) = q + 3 by omega, show p + (q - p + 2 + Nid x q) = q + 2 + Nid x q by omega]
      exact a7
  rw [identEnd_val h', n1, hv]
  omega

private theorem copySlice_tl (src dest : ByteArray) (so len : Nat) (ex : Bool) :
    (src.copySlice so dest dest.size len ex).toList = dest.toList ++ (src.toList.drop so).take len := by
  simp only [ByteArray.copySlice, Flat.Bin.toList_eq', Array.toList_append, Array.toList_extract, List.extract_eq_take_drop, List.drop_zero, Nat.sub_zero]
  have e : dest.size = dest.data.toList.length := by rw [Flat.Bin.size_eq_length', Flat.Bin.toList_eq']
  rw [e, List.take_length, Nat.add_sub_cancel_left, List.drop_eq_nil_of_le (Nat.le_add_right _ _), List.take_nil,
    List.append_nil]

private theorem zeroPad_tl : zeroPad.toList = List.replicate 261 0 := by
  simp [zeroPad, Flat.Bin.toList_eq']

private theorem putNum_tl (b s : ByteArray) (w o n : Nat) (hn : n + 1 ≤ w) (hw : w ≤ 262) :
    (putNum b s w o n).toList = b.toList ++ (List.replicate (w - 1 - n) 0 ++ 1 :: (s.toList.drop o).take n) := by
  unfold putNum
  dsimp only
  rw [copySlice_tl, push_tl, copySlice_tl, zeroPad_tl, List.drop_zero, List.take_replicate]
  rw [show min (w - 1 - n) 261 = w - 1 - n by omega]
  simp

private theorem beNat_lt' (xs : Bytes) : beNat xs < 256 ^ xs.length := by
  induction xs with
  | nil => simp [beNat]
  | cons a xs ih =>
    rw [beNat_cons, List.length_cons, Nat.pow_succ]
    have h0 := a.toNat_lt
    have h1 : (a.toNat + 1) * 256 ^ xs.length ≤ 256 * 256 ^ xs.length := Nat.mul_le_mul_right _ (by omega)
    rw [Nat.add_mul] at h1
    omega

private theorem be_bytes (xs : Bytes) : Rules.be xs.length (beNat xs) = some xs := by
  unfold Rules.be
  rw [if_pos (beNat_lt' xs)]
  congr 1
  exact natBE_beNat xs

private theorem beNat_zeros (k : Nat) (ys : Bytes) : beNat (List.replicate k 0 ++ ys) = beNat ys := by
  induction k with
  | zero => simp
  | succ k ih =>
    rw [List.replicate_succ, List.cons_append, beNat_cons, ih]
    simp

private theorem beNatA_slice (s : ByteArray) (o n : Nat) (ho : o + n ≤ s.size) :
    beNatA s o (o + n) 1 = beNat (1 :: (s.toList.drop o).take n) := by
  have hL : s.toList.length = s.size := (Flat.Bin.size_eq_length' s).symm
  rw [beNatA_eq s o (o + n) 1 (by omega) (by omega), beNat_cons, show o + n - o = n by omega,
    len_slice _ _ _ (by omega)]
  simp

private theorem be_num (s : ByteArray) (w o j n : Nat) (hj : j = o + n) (hw : n + 1 ≤ w) (hs : j ≤ s.size) :
    Rules.be w (beNatA s o j 1) = some (List.replicate (w - 1 - n) 0 ++ 1 :: (s.toList.drop o).take n) := by
  subst hj
  have hL : s.toList.length = s.size := (Flat.Bin.size_eq_length' s).symm
  have hlen : (List.replicate (w - 1 - n) 0 ++ 1 :: (s.toList.drop o).take n).length = w := by
    rw [List.length_append, List.length_replicate, List.length_cons, len_slice _ _ _ (by omega)]
    omega
  have := be_bytes (List.replicate (w - 1 - n) 0 ++ 1 :: (s.toList.drop o).take n)
  rw [hlen, beNat_zeros, ← beNatA_slice s o n hs] at this
  exact this

private theorem be4_be (b : ByteArray) (p : Nat) (h : p + 4 ≤ b.size) :
    Rules.be 4 (be4 b p).toNat = some ((b.toList.drop p).take 4) := by
  have hL : b.toList.length = b.size := (Flat.Bin.size_eq_length' b).symm
  rw [be4_toNat b p h]
  have := be_bytes ((b.toList.drop p).take 4)
  rwa [len_slice _ _ _ (by omega)] at this

private theorem be8_be (b : ByteArray) (p : Nat) (h : p + 8 ≤ b.size) :
    Rules.be 8 (be8 b p).toNat = some ((b.toList.drop p).take 8) := by
  have hL : b.toList.length = b.size := (Flat.Bin.size_eq_length' b).symm
  rw [be8_toNat b p h]
  have := be_bytes ((b.toList.drop p).take 8)
  rwa [len_slice _ _ _ (by omega)] at this

private theorem be_flow (t : UInt8) (h1 : 1 ≤ t.toNat) (h3 : t.toNat ≤ 3) : Rules.be 1 (flowOfTag t).tag = some [t] := by
  have : t = 1 ∨ t = 2 ∨ t = 3 := by
    rcases (by omega : t.toNat = 1 ∨ t.toNat = 2 ∨ t.toNat = 3) with h | h | h
    · exact Or.inl (UInt8.toNat_inj.mp (by simpa using h))
    · exact Or.inr (Or.inl (UInt8.toNat_inj.mp (by simpa using h)))
    · exact Or.inr (Or.inr (UInt8.toNat_inj.mp (by simpa using h)))
  rcases this with rfl | rfl | rfl <;> decide

private def LnOK (l : ByteArray) : Prop :=
  ∃ ie pe re oe : Nat, identEnd l 1 l.size = ie ∧ identEnd l (ie + 32) l.size = pe ∧ identEnd l pe l.size = re ∧
    identEnd l (re + 4) l.size = oe ∧ 1 ≤ (l.get! 0).toNat ∧ (l.get! 0).toNat ≤ 3 ∧ ie ≠ 0 ∧ ie + 32 ≤ l.size ∧
    pe ≠ 0 ∧ re ≠ 0 ∧ re + 4 ≤ l.size ∧ oe ≠ 0 ∧ oe + 12 = l.size

private theorem len10 (tag : UInt8) (a1 a2 a3 a4 a5 a6 a7 a8 a9 a10 : List UInt8) :
    (tag :: [a1, a2, a3, a4, a5, a6, a7, a8, a9, a10].flatten).length =
      1 + a1.length + a2.length + a3.length + a4.length + a5.length + a6.length + a7.length + a8.length + a9.length + a10.length := by
  simp only [List.length_cons, List.flatten_cons, List.flatten_nil, List.append_nil, List.length_append]
  omega

private theorem row_good_of (tag : UInt8) (pk l : ByteArray) (hp : pk.size ≤ 260) (hl : LnOK l) :
    (rowOfLine tag ⟨pk, l⟩).size = 924 ∧
      ∀ b, (putRow b tag ⟨pk, l⟩).toList = b.toList ++ (rowOfLine tag ⟨pk, l⟩).toList := by
  obtain ⟨ie, pe, re, oe, h1, h2, h3, h4, f1, f3, n1, m1, n2, n3, r4, n4, hsz⟩ := hl
  have hL : l.toList.length = l.size := (Flat.Bin.size_eq_length' l).symm
  have n1' : identEnd l 1 l.size ≠ 0 := by rw [h1]; exact n1
  have n2' : identEnd l (ie + 32) l.size ≠ 0 := by rw [h2]; exact n2
  have n3' : identEnd l pe l.size ≠ 0 := by rw [h3]; exact n3
  have n4' : identEnd l (re + 4) l.size ≠ 0 := by rw [h4]; exact n4
  have v1 := identEnd_val n1'
  have v2 := identEnd_val n2'
  have v3 := identEnd_val n3'
  have v4 := identEnd_val n4'
  have i1 := (identEnd_iff l 1 l.size).mp n1'
  have i2 := (identEnd_iff l (ie + 32) l.size).mp n2'
  have i3 := (identEnd_iff l pe l.size).mp n3'
  have i4 := (identEnd_iff l (re + 4) l.size).mp n4'
  rw [h1] at v1
  rw [h2] at v2
  rw [h3] at v3
  rw [h4] at v4
  obtain ⟨_, _, a1, a1', a1'', _, _⟩ := i1
  obtain ⟨_, _, a2, a2', a2'', _, _⟩ := i2
  obtain ⟨_, _, a3, a3', a3'', _, _⟩ := i3
  obtain ⟨_, _, a4, a4', a4'', _, _⟩ := i4
  have e1 := be_num l 129 3 ie (ie - 3) (by omega) (by omega) (by omega)
  have e2 : Rules.be 261 (idNatA pk) = some (List.replicate (261 - 1 - pk.size) 0 ++ 1 :: (pk.toList.drop 0).take pk.size) :=
    be_num pk 261 0 pk.size pk.size (by omega) (by omega) (by omega)
  have eF := be_flow (l.get! 0) f1 f3
  have e3 := be_num l 129 ie (ie + 32) 32 (by omega) (by omega) (by omega)
  have e4 := be_num l 129 (ie + 34) pe (pe - ie - 34) (by omega) (by omega) (by omega)
  have e5 := be_num l 129 (pe + 2) re (re - pe - 2) (by omega) (by omega) (by omega)
  have e6 := be4_be l re (by omega)
  have e7 := be_num l 129 (re + 6) oe (oe - re - 6) (by omega) (by omega) (by omega)
  have e8 := be4_be l oe (by omega)
  have e9 := be8_be l (oe + 4) (by omega)
  have e12 : (l.toList.drop oe).take 12 = (l.toList.drop oe).take 4 ++ (l.toList.drop (oe + 4)).take 8 := by
    rw [show 12 = 4 + 8 from rfl, List.take_add, List.drop_drop]
  have hR : Rules.Run.rowBytes tag (lineOfBytes (idNatA pk) l) = some (tag :: [
      List.replicate (129 - 1 - (ie - 3)) 0 ++ 1 :: (l.toList.drop 3).take (ie - 3),
      List.replicate (261 - 1 - pk.size) 0 ++ 1 :: (pk.toList.drop 0).take pk.size, [l.get! 0],
      List.replicate (129 - 1 - 32) 0 ++ 1 :: (l.toList.drop ie).take 32,
      List.replicate (129 - 1 - (pe - ie - 34)) 0 ++ 1 :: (l.toList.drop (ie + 34)).take (pe - ie - 34),
      List.replicate (129 - 1 - (re - pe - 2)) 0 ++ 1 :: (l.toList.drop (pe + 2)).take (re - pe - 2),
      (l.toList.drop re).take 4,
      List.replicate (129 - 1 - (oe - re - 6)) 0 ++ 1 :: (l.toList.drop (re + 6)).take (oe - re - 6),
      (l.toList.drop oe).take 4, (l.toList.drop (oe + 4)).take 8].flatten) := by
    unfold Rules.Run.rowBytes Rules.Line.fields lineOfBytes
    dsimp only
    rw [h1, h2, h3, h4]
    simp [Rules.idWidth, Rules.payWidth, List.mapM_cons, e1, e2, eF, e3, e4, e5, e6, e7, e8, e9]
  have hR2 := BlindLedger.Gate.Rules.Fast.rowBytesFast_eq (tag := tag) (l := lineOfBytes (idNatA pk) l)
  rw [hR] at hR2
  cases hrb : Rules.Run.rowBytesFast tag (lineOfBytes (idNatA pk) l) with
  | none => rw [hrb] at hR2; simp at hR2
  | some r =>
    rw [hrb] at hR2
    simp only [Option.map_some, Option.some.injEq] at hR2
    have hrow : rowOfLine tag ⟨pk, l⟩ = r := by
      unfold rowOfLine
      dsimp only
      rw [hrb]
      rfl
    rw [hrow]
    have l1 := BlindLedger.Gate.be_length e1
    have l2 := BlindLedger.Gate.be_length e2
    have l3 := BlindLedger.Gate.be_length eF
    have l4 := BlindLedger.Gate.be_length e3
    have l5 := BlindLedger.Gate.be_length e4
    have l6 := BlindLedger.Gate.be_length e5
    have l7 := BlindLedger.Gate.be_length e6
    have l8 := BlindLedger.Gate.be_length e7
    have l9 := BlindLedger.Gate.be_length e8
    have l10 := BlindLedger.Gate.be_length e9
    refine ⟨?_, fun b => ?_⟩
    · rw [Flat.Bin.size_eq_length', Flat.Bin.toList_eq', hR2]
      rw [len10]
      omega
    · unfold putRow
      dsimp only
      rw [h1, h2, h3, h4, Flat.Bin.toList_eq' r, hR2]
      rw [copySlice_tl, putNum_tl _ l 129 (re + 6) (oe - re - 6) (by omega) (by omega), copySlice_tl,
        putNum_tl _ l 129 (pe + 2) (re - pe - 2) (by omega) (by omega),
        putNum_tl _ l 129 (ie + 34) (pe - ie - 34) (by omega) (by omega),
        putNum_tl _ l 129 ie 32 (by omega) (by omega), push_tl,
        putNum_tl _ pk 261 0 pk.size (by omega) (by omega),
        putNum_tl _ l 129 3 (ie - 3) (by omega) (by omega), push_tl, e12]
      simp [List.append_assoc]

private theorem lineRow_info {x : ByteArray} {p e : Nat} {tag : UInt8} {mem ps pn : Nat} {payW : UInt64} {r : LineRow}
    (h : lineRow x p e tag mem ps pn payW = some r) :
    ∃ ie pe re oe : Nat, p + 1 ≤ e ∧ x.get! p = tag ∧ identEnd x (p + 1) e = ie ∧ identEnd x (ie + 32) e = pe ∧
      identEnd x pe e = re ∧ identEnd x (re + 4) e = oe ∧ ie ≠ 0 ∧ ie + 32 ≤ e ∧ pe ≠ 0 ∧ re ≠ 0 ∧ re + 4 ≤ e ∧ oe ≠ 0 ∧
      oe + 12 = e := by
  unfold lineRow at h
  simp only at h
  split at h
  · cases h
  rename_i c1
  simp only [Bool.or_eq_true, decide_eq_true_eq, bne_iff_ne, ne_eq, not_or, Decidable.not_not] at c1
  obtain ⟨ie, hie⟩ : ∃ ie, identEnd x (p + 1) e = ie := ⟨_, rfl⟩
  rw [hie] at h
  split at h
  · cases h
  rename_i c2
  simp only [Bool.or_eq_true, decide_eq_true_eq, beq_iff_eq, not_or, Bool.not_eq_true', Bool.not_eq_false] at c2
  obtain ⟨pe, hpe⟩ : ∃ pe, identEnd x (ie + 32) e = pe := ⟨_, rfl⟩
  rw [hpe] at h
  split at h
  · cases h
  rename_i c3
  simp only [Bool.or_eq_true, beq_iff_eq, bne_iff_ne, ne_eq, not_or, Decidable.not_not, Bool.not_eq_true',
    Bool.not_eq_false] at c3
  obtain ⟨re, hre⟩ : ∃ re, identEnd x pe e = re := ⟨_, rfl⟩
  rw [hre] at h
  split at h
  · cases h
  rename_i c4
  simp only [Bool.or_eq_true, decide_eq_true_eq, beq_iff_eq, not_or] at c4
  obtain ⟨oe, hoe⟩ : ∃ oe, identEnd x (re + 4) e = oe := ⟨_, rfl⟩
  rw [hoe] at h
  split at h
  · cases h
  rename_i c5
  simp only [Bool.or_eq_true, beq_iff_eq, bne_iff_ne, ne_eq, not_or, Decidable.not_not] at c5
  obtain ⟨c1a, c1b⟩ := c1
  obtain ⟨⟨c2a, c2b⟩, c2c⟩ := c2
  obtain ⟨⟨c3a, c3b⟩, c3c⟩ := c3
  obtain ⟨c4a, c4b⟩ := c4
  obtain ⟨c5a, c5b⟩ := c5
  exact ⟨ie, pe, re, oe, by omega, c1b, hie, hpe, hre, hoe, c2a, by omega, c3a, c4a, by omega, c5a, by omega⟩

private theorem identEnd_ge {b : ByteArray} {p lim : Nat} (h : identEnd b p lim ≠ 0) :
    p + 3 ≤ identEnd b p lim ∧ identEnd b p lim ≤ lim ∧ identEnd b p lim ≤ p + 130 := by
  have hi := (identEnd_iff b p lim).mp h
  have hv := identEnd_val h
  obtain ⟨_, _, a1, a2, a3, _, _⟩ := hi
  omega

private theorem lnOK_of_lineRow {x : ByteArray} {p e : Nat} {tag : UInt8} {mem ps pn : Nat} {payW : UInt64} {r : LineRow}
    (he : e ≤ x.size) (ht1 : 1 ≤ tag.toNat) (ht3 : tag.toNat ≤ 3)
    (h : lineRow x p e tag mem ps pn payW = some r) : LnOK (x.extract p e) := by
  obtain ⟨ie, pe, re, oe, c1, c2, hie, hpe, hre, hoe, n1, m1, n2, n3, r4, n4, hsz⟩ := lineRow_info h
  have n1' : identEnd x (p + 1) e ≠ 0 := by rw [hie]; exact n1
  have n2' : identEnd x (ie + 32) e ≠ 0 := by rw [hpe]; exact n2
  have n3' : identEnd x pe e ≠ 0 := by rw [hre]; exact n3
  have n4' : identEnd x (re + 4) e ≠ 0 := by rw [hoe]; exact n4
  have g1 := identEnd_ge n1'
  have g2 := identEnd_ge n2'
  have g3 := identEnd_ge n3'
  have g4 := identEnd_ge n4'
  rw [hie] at g1
  rw [hpe] at g2
  rw [hre] at g3
  rw [hoe] at g4
  have sz := size_extract' x p e he
  have x1 := identEnd_extract x p e (p + 1) he (by omega) n1'
  have x2 := identEnd_extract x p e (ie + 32) he (by omega) n2'
  have x3 := identEnd_extract x p e pe he (by omega) n3'
  have x4 := identEnd_extract x p e (re + 4) he (by omega) n4'
  rw [hie, show p + 1 - p = 1 by omega] at x1
  rw [hpe, show ie + 32 - p = ie - p + 32 by omega] at x2
  rw [hre] at x3
  rw [hoe, show re + 4 - p = re - p + 4 by omega] at x4
  refine ⟨ie - p, pe - p, re - p, oe - p, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · rw [sz]; exact x1
  · rw [sz]; exact x2
  · rw [sz]; exact x3
  · rw [sz]; exact x4
  · rw [get!_extract x p e 0 (by omega) he, Nat.add_zero, c2]; exact ht1
  · rw [get!_extract x p e 0 (by omega) he, Nat.add_zero, c2]; exact ht3
  · omega
  · rw [sz]; omega
  · omega
  · omega
  · rw [sz]; omega
  · omega
  · rw [sz]; omega

private abbrev ESt := Option (Option RowsReq) × Nat × Array ByteArray

private def evStep (x : ByteArray) (i : Nat) (s : ESt) : Id (ForInStep ESt) :=
  if (decide (0 < i) && !lt64 x (s.2.1 - 64) s.2.1 0) = true then pure (.done (some none, s.2))
  else pure (.yield (none, s.2.1 + 64, s.2.2.push (x.extract s.2.1 (s.2.1 + 64))))

private theorem evLoop2 (x : ByteArray) : ∀ (k s q : Nat) (evid : Array ByteArray) (R : ESt),
    Id.run (forIn (List.range' s k) ((none : Option (Option RowsReq)), q, evid) (evStep x)) = R →
    R.1 = none ∨ R.1 = some none := by
  intro k
  induction k with
  | zero =>
    intro s q evid R hR
    simp only [List.range'_zero, List.forIn_nil, Id.run_pure] at hR
    subst hR
    exact Or.inl rfl
  | succ k ih =>
    intro s q evid R hR
    rw [List.range'_succ] at hR
    simp only [Id.run, List.forIn_cons, evStep] at hR
    by_cases hc : (decide (0 < s) && !lt64 x (q - 64) q 0) = true
    · simp only [hc, ↓reduceIte, pure_bind] at hR
      subst hR
      exact Or.inr rfl
    · simp only [hc, ↓reduceIte, pure_bind] at hR
      exact ih (s + 1) _ _ R hR

private abbrev LSt := Option (Option RowsReq) × Nat × Nat × Array ByteArray × Array LineRow

private abbrev lineStep (x : ByteArray) (tag : UInt8) (ye ee : Nat) (payW : UInt64) (ruled : Prop) [Decidable ruled] (_i : Nat) (s : LSt) :
    Id (ForInStep LSt) :=
  if x.size < s.2.1 + 2 then pure (.done (some none, s.2))
  else if ((be2 x s.2.1).toNat == 0 || decide (569 < (be2 x s.2.1).toNat) ||
      decide (x.size < s.2.1 + 2 + (be2 x s.2.1).toNat)) = true then pure (.done (some none, s.2))
  else match lineRow x (s.2.1 + 2) (s.2.1 + 2 + (be2 x s.2.1).toNat) tag ye (ye + 34) (ee - ye - 34) payW with
    | some r => if ruled then pure (.yield (none, s.2.1 + 2 + (be2 x s.2.1).toNat, s.2.2.1 + r.cents.toNat,
          s.2.2.2.1.push (x.extract (s.2.1 + 2) (s.2.1 + 2 + (be2 x s.2.1).toNat)), s.2.2.2.2.push r))
        else pure (.yield (none, s.2.1 + 2 + (be2 x s.2.1).toNat, s.2.2.1 + r.cents.toNat,
          s.2.2.2.1.push (x.extract (s.2.1 + 2) (s.2.1 + 2 + (be2 x s.2.1).toNat)), s.2.2.2.2))
    | none => pure (.done (some none, s.2))

private theorem lineLoop3 (x : ByteArray) (tag : UInt8) (ye ee : Nat) (payW : UInt64) (ruled : Prop) [Decidable ruled] :
    ∀ (k s q sum : Nat) (lines : Array ByteArray) (rows : Array LineRow) (R : LSt),
      Id.run (forIn (List.range' s k) ((none : Option (Option RowsReq)), q, sum, lines, rows)
        (lineStep x tag ye ee payW ruled)) = R →
      (R.1 = none ∨ R.1 = some none) ∧
      (R.1 = none → ∃ ls : List ByteArray, R.2.2.2.1.toList = lines.toList ++ ls ∧
        ∀ ln ∈ ls, ∃ q' l0 r, ln = x.extract (q' + 2) (q' + 2 + l0) ∧ q' + 2 + l0 ≤ x.size ∧
          lineRow x (q' + 2) (q' + 2 + l0) tag ye (ye + 34) (ee - ye - 34) payW = some r) := by
  intro k
  induction k with
  | zero =>
    intro s q sum lines rows R hR
    simp only [List.range'_zero, List.forIn_nil, Id.run_pure] at hR
    subst hR
    exact ⟨Or.inl rfl, fun _ => ⟨[], by simp, by simp⟩⟩
  | succ k ih =>
    intro s q sum lines rows R hR
    rw [List.range'_succ] at hR
    simp only [Id.run, List.forIn_cons, lineStep] at hR
    by_cases hA : x.size < q + 2
    · simp only [hA, ↓reduceIte, pure_bind] at hR
      subst hR
      exact ⟨Or.inr rfl, fun h => by simp at h⟩
    by_cases hB : ((be2 x q).toNat == 0 || decide (569 < (be2 x q).toNat) || decide (x.size < q + 2 + (be2 x q).toNat)) = true
    · simp only [hA, hB, ↓reduceIte, pure_bind] at hR
      subst hR
      exact ⟨Or.inr rfl, fun h => by simp at h⟩
    have hB' : 1 ≤ (be2 x q).toNat ∧ (be2 x q).toNat ≤ 569 ∧ q + 2 + (be2 x q).toNat ≤ x.size := by
      simp only [Bool.or_eq_true, beq_iff_eq, decide_eq_true_eq] at hB
      omega
    obtain ⟨ln, hln⟩ : ∃ ln, (be2 x q).toNat = ln := ⟨_, rfl⟩
    rw [hln] at hB' hR hB
    simp only [hA, hB, ↓reduceIte, Bool.false_eq_true, pure_bind] at hR
    rcases hl : lineRow x (q + 2) (q + 2 + ln) tag ye (ye + 34) (ee - ye - 34) payW with _ | r
    · rw [hl] at hR
      simp only [pure_bind] at hR
      subst hR
      exact ⟨Or.inr rfl, fun h => by simp at h⟩
    · rw [hl] at hR
      by_cases hrl : ruled
      · simp only [if_pos hrl, pure_bind] at hR
        obtain ⟨hor, hrest⟩ := ih (s + 1) _ _ _ _ R hR
        refine ⟨hor, fun hfl => ?_⟩
        obtain ⟨ls, h1, h3⟩ := hrest hfl
        refine ⟨x.extract (q + 2) (q + 2 + ln) :: ls, by rw [h1]; simp, ?_⟩
        intro l hl'
        rcases List.mem_cons.mp hl' with rfl | hl'
        · exact ⟨q, ln, r, rfl, by omega, hl⟩
        · exact h3 l hl'
      · simp only [if_neg hrl, pure_bind] at hR
        obtain ⟨hor, hrest⟩ := ih (s + 1) _ _ _ _ R hR
        refine ⟨hor, fun hfl => ?_⟩
        obtain ⟨ls, h1, h3⟩ := hrest hfl
        refine ⟨x.extract (q + 2) (q + 2 + ln) :: ls, by rw [h1]; simp, ?_⟩
        intro l hl'
        rcases List.mem_cons.mp hl' with rfl | hl'
        · exact ⟨q, ln, r, rfl, by omega, hl⟩
        · exact h3 l hl'

private theorem u8_c2 (t : UInt8) : (t == 0 || decide (5 < t)) = true ↔ (t.toNat = 0 ∨ 5 < t.toNat) := by
  simp only [Bool.or_eq_true, beq_iff_eq, decide_eq_true_eq, UInt8.lt_iff_toNat_lt]
  constructor
  · rintro (h | h)
    · left; rw [h]; rfl
    · right; exact h
  · rintro (h | h)
    · left; exact UInt8.toNat_inj.mp (by simpa using h)
    · right; exact h

private theorem ruled_iff (t : Nat) (h1 : 1 ≤ t) (h5 : t ≤ 5) : (flows.getD (t - 1) .FFS_CYCLE).ruled = true ↔ t ≤ 3 := by
  match t, h1, h5 with
  | 1, _, _ => decide
  | 2, _, _ => decide
  | 3, _, _ => decide
  | 4, _, _ => decide
  | 5, _, _ => decide

private theorem decode_lines (x : ByteArray) (d : RowsReq) (h : decodeRows x = some d) (hr : d.ra.flow.ruled = true) :
    d.payKey.size ≤ 260 ∧ ∀ ln ∈ d.ra.lines, LnOK ln := by
  unfold decodeRows at h
  extract_lets n dn te ge tag ce ye ee amount ke nl payKey payW ruled q0 sum0 lines0 rows0 at h
  have hn : n = x.size := rfl
  have hte : te = identEnd x dn n := rfl
  have hge : ge = identEnd x te n := rfl
  have hce : ce = identEnd x (ge + 1) n := rfl
  have hye : ye = identEnd x ce n := rfl
  have hee : ee = identEnd x (ye + 32) n := rfl
  have hpk : payKey = x.copySlice ce (x.extract te ge) (ge - te) (ye - ce) := rfl
  have hq0 : q0 = ke + 2 := rfl
  have hsum0 : sum0 = 0 := rfl
  have hlines0 : lines0 = Array.mkEmpty nl := rfl
  have hrows0 : rows0 = Array.mkEmpty (if ruled then nl else 0) := rfl
  clear_value rows0 lines0 sum0 q0 payW payKey nl ke amount ee ye ce tag ge te dn n
  subst hn
  letI hdec : Decidable ruled := inferInstanceAs (Decidable (tag ≤ 3))
  by_cases c1 : (decide (maxRequestBytes < x.size) || decide (x.size < dn) || !sameBytes x requestDomain 0 0 dn) = true
  · rw [if_pos c1] at h; simp at h
  rw [if_neg c1] at h
  by_cases c2 : (te == 0 || ge == 0 || decide (x.size < ge + 1)) = true
  · rw [if_pos c2] at h; simp at h
  rw [if_neg c2] at h
  by_cases c3 : (tag == 0 || decide (5 < tag)) = true
  · rw [if_pos c3] at h; simp at h
  rw [if_neg c3] at h
  by_cases c4 : (ce == 0 || ye == 0 || decide (x.size < ye + 32)) = true
  · rw [if_pos c4] at h; simp at h
  rw [if_neg c4] at h
  by_cases c5 : (ee == 0 || decide (x.size < ee + 8)) = true
  · rw [if_pos c5] at h; simp at h
  rw [if_neg c5] at h
  by_cases c6 : 9223372036854775807 < amount
  · rw [if_pos c6] at h; simp at h
  rw [if_neg c6] at h
  by_cases c7 : (ke == 0 || decide (x.size < ke + 2)) = true
  · rw [if_pos c7] at h; simp at h
  rw [if_neg c7] at h
  have ht : 1 ≤ tag.toNat ∧ tag.toNat ≤ 5 := by
    by_cases hc : 1 ≤ tag.toNat ∧ tag.toNat ≤ 5
    · exact hc
    · exact absurd ((u8_c2 tag).mpr (by omega)) c3
  simp only [Bool.or_eq_true, beq_iff_eq, decide_eq_true_eq, not_or] at c2 c4 c5
  obtain ⟨⟨hte0, hge0⟩, hs2⟩ := c2
  obtain ⟨⟨hce0, hye0⟩, hs3⟩ := c4
  subst hq0 hsum0 hlines0 hrows0
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.sub_zero, Nat.add_sub_cancel, Nat.div_one] at h
  have hgeb := identEnd_ge (b := x) (p := te) (lim := x.size) (by rw [← hge]; exact hge0)
  have hyeb := identEnd_ge (b := x) (p := ce) (lim := x.size) (by rw [← hye]; exact hye0)
  rw [← hge] at hgeb
  rw [← hye] at hyeb
  have hps : payKey.size ≤ 260 := by
    have hsz := size_extract' x te ge (by omega)
    have e : x.copySlice ce (x.extract te ge) (ge - te) (ye - ce) =
        x.copySlice ce (x.extract te ge) (x.extract te ge).size (ye - ce) := by rw [hsz]
    have e2 := Flat.Bin.size_eq_length' (x.copySlice ce (x.extract te ge) (x.extract te ge).size (ye - ce))
    rw [hpk, e, e2, copySlice_tl, List.length_append, ← Flat.Bin.size_eq_length', hsz, List.length_take]
    omega
  have hrul : ruled → tag.toNat ≤ 3 := by
    intro hrl
    have : tag ≤ 3 := hrl
    rw [UInt8.le_iff_toNat_le] at this
    exact this
  obtain ⟨R, hR⟩ : ∃ R, Id.run (forIn (List.range' 0 nl) ((none : Option (Option RowsReq)), ke + 2, (0 : Nat),
      (Array.mkEmpty nl : Array ByteArray), (Array.mkEmpty (if ruled then nl else 0) : Array LineRow))
      (lineStep x tag ye ee payW ruled)) = R := ⟨_, rfl⟩
  obtain ⟨hor, hrest⟩ := lineLoop3 x tag ye ee payW ruled
    nl 0 (ke + 2) 0 (Array.mkEmpty nl) (Array.mkEmpty (if ruled then nl else 0)) R hR
  have hR' : forIn (m := Id) (List.range' 0 nl) ((none : Option (Option RowsReq)), ke + 2, (0 : Nat),
      (Array.mkEmpty nl : Array ByteArray), (Array.mkEmpty (if ruled then nl else 0) : Array LineRow))
      (lineStep x tag ye ee payW ruled) = R := hR
  generalize hX : (forIn (m := Id) (List.range' 0 nl) ((none : Option (Option RowsReq)), ke + 2, (0 : Nat),
      (Array.mkEmpty nl : Array ByteArray), (Array.mkEmpty (if ruled then nl else 0) : Array LineRow)) _) = X at h
  have hXR : X = R := by
    rw [← hX]
    refine Eq.trans ?_ hR'
    congr 1
    funext i s
    unfold lineStep
    cases lineRow x (s.snd.fst + 2) (s.snd.fst + 2 + (be2 x s.snd.fst).toNat) tag ye (ye + 34) (ee - ye - 34) payW <;> rfl
  subst hXR
  dsimp only [bind, Bind.bind, Id.run, pure, Pure.pure] at h
  rcases hor with hfl | hfl
  case inr =>
    rw [hfl] at h; dsimp only at h; simp at h
  rw [hfl] at h
  dsimp only at h
  by_cases c8 : (decide ruled && nl == 0 || nl != 0 && X.2.2.1 != amount.toNat || decide (x.size < X.2.1 + 2)) = true
  · rw [if_pos c8] at h; simp at h
  rw [if_neg c8] at h
  by_cases c9 : (decide (256 < (be2 x X.2.1).toNat) || decide (x.size < X.2.1 + 2 + 64 * (be2 x X.2.1).toNat)) = true
  · rw [if_pos c9] at h; simp at h
  rw [if_neg c9] at h
  simp only [Bool.or_eq_true, decide_eq_true_eq, not_or] at c8 c9
  obtain ⟨R2, hR2⟩ : ∃ R2, Id.run (forIn (List.range' 0 (be2 x X.2.1).toNat) ((none : Option (Option RowsReq)), X.2.1 + 2,
      (Array.mkEmpty (be2 x X.2.1).toNat : Array ByteArray)) (evStep x)) = R2 := ⟨_, rfl⟩
  have hev := evLoop2 x (be2 x X.2.1).toNat 0 (X.2.1 + 2) (Array.mkEmpty _) R2 hR2
  have hR2' : forIn (m := Id) (List.range' 0 (be2 x X.2.1).toNat) ((none : Option (Option RowsReq)), X.2.1 + 2,
      (Array.mkEmpty (be2 x X.2.1).toNat : Array ByteArray)) (evStep x) = R2 := hR2
  generalize hY : forIn (m := Id) (List.range' 0 (be2 x X.2.1).toNat) ((none : Option (Option RowsReq)), X.2.1 + 2,
      (Array.mkEmpty (be2 x X.2.1).toNat : Array ByteArray)) _ = Y at h
  have hYR : Y = R2 := by
    rw [← hY]
    refine Eq.trans ?_ hR2'
    congr 1
  subst hYR
  have hf1 : Y.1 = none := by
    rcases hev with hf2 | hf2
    · exact hf2
    · rw [hf2] at h; dsimp only at h; simp at h
  rw [hf1] at h
  dsimp only at h
  by_cases c10 : (Y.2.1 != x.size) = true
  · rw [if_pos c10] at h; simp at h
  rw [if_neg c10] at h
  simp only [Option.some.injEq] at h
  subst h
  dsimp only at hr
  have h3t : tag.toNat ≤ 3 := (ruled_iff tag.toNat ht.1 ht.2).mp hr
  have hrr : ruled := by
    show tag ≤ 3
    rw [UInt8.le_iff_toNat_le]; exact h3t
  obtain ⟨ls, h1, h3⟩ := hrest hfl
  refine ⟨hps, fun ln hln => ?_⟩
  have hln' : ln ∈ X.2.2.2.1.toList := hln
  rw [h1] at hln'
  have hln'' : ln ∈ ls := by simpa using hln'
  obtain ⟨q', l0, r, rfl, hq, hl⟩ := h3 ln hln''
  exact lnOK_of_lineRow hq ht.1 h3t hl

private theorem rowGood_all (lines : Array LineSrc) (rel unr : Array Nat)
    (hrow : ∀ i ∈ rel ++ unr, ∃ s x d, lines[i]? = some s ∧ decodeRows x = some d ∧ d.ra.flow.ruled = true ∧
      s.ln ∈ d.ra.lines ∧ s.payKey = d.payKey) (t : UInt8) (i : Nat) (hi : i ∈ rel ++ unr) :
    (rowOfLine t lines[i]!).size = 924 ∧ ∀ b, (putRow b t lines[i]!).toList = b.toList ++ (rowOfLine t lines[i]!).toList := by
  obtain ⟨s, x, d, hs, hd, hru, hln, hpk⟩ := hrow i hi
  have hget : lines[i]! = s := by rw [getElem!_def, hs]
  rw [hget]
  obtain ⟨hps, hok⟩ := decode_lines x d hd hru
  have hps' : s.payKey.size ≤ 260 := by rw [hpk]; exact hps
  exact row_good_of t s.payKey s.ln hps' (hok _ hln)

/-- The one-pass answer is the codec's (proof owed) when the codec's answer encodes (sizes, ranges, `Rec.ok`, `Leaf.ok`,
    the record order), each decision's rule code names a rule (a held line's must, or its record is not `Rec.ok`), and
    each added row is a line of a ruled flow that `decodeRows` accepted, with its payment's `payKey` (an unruled line's
    flow byte is not its `flowOfTag` tag). -/
theorem encodeAnsOut_eq (shard batch : Nat) (digest head root hold grant auth : ByteArray) (ds : Array Dec) (ruleOf : Dec → UInt8)
    (locOf : Nat → UInt32 × UInt32) (held : Array Held) (notes : Array ByteArray) (leaves : Array Leaf)
    (lines : Array LineSrc) (rel unr : Array Nat)
    (h : (encodeAns (ansOfOut shard batch digest head root hold grant auth ds ruleOf locOf held notes leaves lines rel unr)).isSome)
    (hrule : ∀ d ∈ ds, (ruleOf d).toNat < rules.length)
    (hrow : ∀ i ∈ rel ++ unr, ∃ s x d, lines[i]? = some s ∧ decodeRows x = some d ∧ d.ra.flow.ruled = true ∧
      s.ln ∈ d.ra.lines ∧ s.payKey = d.payKey) :
    some (encodeAnsOut shard batch digest head root hold grant auth ds ruleOf locOf held notes leaves lines rel unr).toList =
      encodeAns (ansOfOut shard batch digest head root hold grant auth ds ruleOf locOf held notes leaves lines rel unr) := by
  exact answer_aux shard batch digest head root hold grant auth ds ruleOf locOf held notes leaves lines rel unr h hrule
    (fun i hi => rowGood_all lines rel unr hrow 1 i (Array.mem_append.mpr (Or.inl hi)))
    (fun i hi => rowGood_all lines rel unr hrow 2 i (Array.mem_append.mpr (Or.inr hi)))

/-! ### Proof of `encodeAnsFast_eq` -/

private theorem bind_inv {α β : Type} {x : Option α} {f : α → Option β} {b : β} (h : (x >>= f) = some b) :
    ∃ a, x = some a ∧ f a = some b := by
  cases x with
  | none => cases h
  | some a => exact ⟨a, rfl, h⟩

private theorem encodeAns_some (a : AnsFrame) (bs : Bytes) (h : encodeAns a = some bs) :
    ∃ hv rv xv, leAll [2, 1, 4, 8, 4] [ansVersion, a.word.code, a.shard, a.batch, a.recs.length] = some hv ∧
      a.recs.mapM encRec = some rv ∧ (if a.word == .OK then encExt a.ext else pure []) = some xv ∧
      bs = magicAns ++ (hv ++ (a.digest.toList ++ (rv.flatten ++ (a.head.toList ++ (a.root.toList ++ xv))))) := by
  unfold encodeAns at h
  obtain ⟨_, -, h⟩ := bind_inv h
  obtain ⟨_, -, h⟩ := bind_inv h
  obtain ⟨hv, e1, h⟩ := bind_inv h
  obtain ⟨rv, e2, h⟩ := bind_inv h
  dsimp only at h
  split at h
  · rename_i hb
    obtain ⟨xv, e3, h⟩ := bind_inv h
    refine ⟨hv, rv, xv, e1, e2, by rw [if_pos hb]; exact e3, ?_⟩
    simpa only [List.append_assoc] using (Option.some.inj h).symm
  · rename_i hb
    refine ⟨hv, rv, [], e1, e2, by rw [if_neg hb]; rfl, ?_⟩
    simpa only [List.append_assoc] using (Option.some.inj h).symm

private theorem putRec_eq (b : ByteArray) (r : Rec) (bs : Bytes) (h : encRec r = some bs) :
    (putRec b r).toList = b.toList ++ bs := by
  obtain ⟨-, hl⟩ := encRec_some _ _ h
  unfold putRec
  generalize r.ref.getD (noChunk, noRow) = p at hl ⊢
  obtain ⟨c, w⟩ := p
  obtain ⟨b1, b2, b3, b4, b5, b6, e1, e2, e3, e4, e5, e6, rfl⟩ := leAll6 hl
  dsimp only
  rw [le_put _ _ _ _ e6, le_put _ _ _ _ e5, le_put _ _ _ _ e4, le_put _ _ _ _ e3, le_put _ _ _ _ e2,
    le_put _ _ _ _ e1]
  simp

private theorem putExt_eq (b : ByteArray) (e : Ext) (xv : Bytes) (h : encExt e = some xv) :
    (putExt b e).toList = b.toList ++ xv := by
  obtain ⟨-, -, -, ns, ls, ad, nl, ll, al, f1, f2, f3, f4, f5, f6, rfl⟩ := encExt_ok e xv h
  have TN := foldl_mapM putBlob2 (fun x => blob2 x.toList) (fun b x bs hg => putBlob2_eq b x bs hg)
  have TL := foldl_mapM putLeaf encLeaf (fun b l bs hg => putLeaf_eq b l bs hg)
  unfold putExt
  dsimp only
  rw [TN _ _ _ f3, le_put _ 4 _ _ f6, TL _ _ _ f2, le_put _ 4 _ _ f5, TN _ _ _ f1, le_put _ 4 _ _ f4]
  simp [Flat.Bin.toList_append']

/-- The engine's answer encoder writes the codec's bytes for every answer the codec encodes. -/
theorem encodeAnsFast_eq (a : AnsFrame) (h : (encodeAns a).isSome) : some (encodeAnsFast a).toList = encodeAns a := by
  obtain ⟨bs, hbs⟩ := Option.isSome_iff_exists.mp h
  rw [hbs]
  obtain ⟨hv, rv, xv, e1, e2, e3, rfl⟩ := encodeAns_some a bs hbs
  obtain ⟨q1, q2, q3, q4, q5, i1, i2, i3, i4, i5, rfl⟩ := leAll5 e1
  have TR := foldl_mapM putRec encRec (fun b r bs hr => putRec_eq b r bs hr) a.recs
  unfold encodeAnsFast
  dsimp only
  split
  · rename_i hb
    rw [if_pos hb] at e3
    rw [putExt_eq _ _ _ e3]
    simp only [Flat.Bin.toList_append']
    rw [TR _ _ e2]
    simp only [Flat.Bin.toList_append']
    rw [le_put _ 4 _ q5 i5, le_put _ 8 _ q4 i4, le_put _ 4 _ q3 i3, le_put _ 1 _ q2 i2, le_put _ 2 _ q1 i1]
    simp [toList_putL, empty_toList]
  · rename_i hb
    rw [if_neg hb] at e3
    cases e3
    simp only [Flat.Bin.toList_append']
    rw [TR _ _ e2]
    simp only [Flat.Bin.toList_append']
    rw [le_put _ 4 _ q5 i5, le_put _ 8 _ q4 i4, le_put _ 4 _ q3 i3, le_put _ 1 _ q2 i2, le_put _ 2 _ q1 i1]
    simp [toList_putL, empty_toList]

end BlindLedger.Gate.Frame.Fast
