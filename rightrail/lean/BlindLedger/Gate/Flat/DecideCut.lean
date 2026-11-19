import BlindLedger.Gate.Flat.DecideRows

/-! The history summary hands `decideRows` fewer prior rows of a key than the key holds (`Engine3.Hist.readSet`):

    * released: the first row only, when no line of a redone payment is on the key and no unresolved row's id key is
      the key;
    * unresolved: the first row and the first row not identical to it, when every row of the key is non-CAP, the key is
      no line's id key and every line on the key meets the first row (exact, id or near match).

    `decideRows_cut` proves `decideRows` on such a layout decides as on the layout with every row: the same decisions
    (line, mask, outcome), the same counterpart as the answer names it (`locOf`: set and store position), and the same
    rows joining each set.  A layout is compared slot by slot through its reads (`relV`, `unrV`), so the two layouts
    may place their rows anywhere. -/

namespace BlindLedger.Gate.Flat.Rows

open BlindLedger.Gate.Rules BlindLedger.Gate.Rules.Fast BlindLedger.Gate.Flat
open BlindLedger.Gate.Engine3 (RowX)

/-! ## Reads of a slot -/

/-- The released reads of slot `k`, in order: row and store position. -/
def relV (x : Lay) (k : Nat) : List (RowX × Nat) :=
  (List.range' x.slots[k]!.rs x.slots[k]!.rn).map fun j => (x.relP[j]!, x.relSeq[j]!)

/-- An unresolved read: row, store position, its member's spans, the slot of its id key. -/
abbrev UEnt := RowX × Nat × Rg × Nat

def entAt (x : Lay) (j : Nat) : UEnt := (x.unrP[j]!, x.unrSeq[j]!, x.uSpan[j]!, x.uId[j]!)

/-- The unresolved reads of slot `k`, in order. -/
def unrV (x : Lay) (k : Nat) : List UEnt := (List.range' x.slots[k]!.us x.slots[k]!.un).map (entAt x)

/-- A counterpart as the answer names it: released (0) or unresolved (1), and its store position. -/
def locOf (x : Lay) (cp : Nat) : Option (Nat × Nat) :=
  if cp == 0 then none else if cp % 2 == 1 then (x.relSeq[cp / 2]?).map (0, ·) else (x.unrSeq[cp / 2 - 1]?).map (1, ·)

/-- A decision as the answer reads it. -/
def ansOf (x : Lay) (d : Dec) : Nat × UInt32 × UInt8 × Option (Nat × Nat) := (d.line, d.mask, d.out, locOf x d.cp)

/-! ## The cut -/

/-- Slot `k`'s released reads cut to the first. -/
def RelCut (x x' : Lay) (k : Nat) : Prop :=
  relV x' k = (relV x k).take 1 ∧
    (∀ li ∈ x.lines, (li.ke = k ∨ li.kn = k ∨ li.ki = k) → x.pRedo[li.pay]! = false) ∧
    ∀ k', k' < x.slots.size → ∀ e ∈ unrV x k', e.2.2.2 ≠ k

/-- Slot `k`'s unresolved reads cut to the first and the first not identical to it. -/
def UnrCut (x x' : Lay) (k : Nat) : Prop :=
  ∃ h t, unrV x k = h :: t ∧ unrV x' k = h :: (t.find? fun e => !h.1.same e.1).toList ∧
    (∀ e ∈ unrV x k, e.1.cap = false) ∧ (∀ li ∈ x.lines, li.ki ≠ k) ∧
    ∀ li ∈ x.lines, (li.ke = k ∨ li.kn = k) → (li.row.exactEq h.1 || li.row.idEq h.1 || li.row.nearEq h.1) = true

/-- `x'` is `x` with some slots cut: everything but the rows is equal, and each slot reads the same rows or a cut. -/
structure Cut (x x' : Lay) : Prop where
  today : x'.today = x.today
  relCh : x'.relCh = x.relCh
  unrCh : x'.unrCh = x.unrCh
  dmfSome : x'.dmfSome = x.dmfSome
  pdSome : x'.pdSome = x.pdSome
  exclSome : x'.exclSome = x.exclSome
  spanSome : x'.spanSome = x.spanSome
  eligSome : x'.eligSome = x.eligSome
  dmfOk : x'.dmfOk = x.dmfOk
  pdOk : x'.pdOk = x.pdOk
  exclOk : x'.exclOk = x.exclOk
  spanOk : x'.spanOk = x.spanOk
  eligOk : x'.eligOk = x.eligOk
  lines : x'.lines = x.lines
  dmf : x'.dmf = x.dmf
  pdeath : x'.pdeath = x.pdeath
  excl : x'.excl = x.excl
  spans : x'.spans = x.spans
  eligs : x'.eligs = x.eligs
  redo : x'.redo = x.redo
  pRedo : x'.pRedo = x.pRedo
  pByp : x'.pByp = x.pByp
  lLim : x'.lLim = x.lLim
  size : x'.slots.size = x.slots.size
  kind : ∀ k, k < x.slots.size → x'.slots[k]!.kind = x.slots[k]!.kind
  rc : ∀ k, k < x.slots.size → x'.slots[k]!.rc = x.slots[k]!.rc
  uc : ∀ k, k < x.slots.size → x'.slots[k]!.uc = x.slots[k]!.uc
  keys : ∀ li ∈ x.lines, li.ke < x.slots.size ∧ li.kn < x.slots.size ∧ li.ki < x.slots.size
  bnd : ∀ k, k < x.slots.size → x.slots[k]!.rs + x.slots[k]!.rn ≤ x.relSeq.size ∧
    x.slots[k]!.us + x.slots[k]!.un ≤ x.unrP.size ∧ x.slots[k]!.us + x.slots[k]!.un ≤ x.unrSeq.size
  bnd' : ∀ k, k < x.slots.size → x'.slots[k]!.rs + x'.slots[k]!.rn ≤ x'.relSeq.size ∧
    x'.slots[k]!.us + x'.slots[k]!.un ≤ x'.unrP.size ∧ x'.slots[k]!.us + x'.slots[k]!.un ≤ x'.unrSeq.size
  rel : ∀ k, k < x.slots.size → relV x' k = relV x k ∨ RelCut x x' k
  unr : ∀ k, k < x.slots.size → unrV x' k = unrV x k ∨ UnrCut x x' k

/-! ## Lists and rows -/

theorem any_congr_mem {α : Type} {p q : α → Bool} : ∀ {l : List α}, (∀ a ∈ l, p a = q a) → l.any p = l.any q
  | [], _ => rfl
  | a :: l, h => by
    have ih := @any_congr_mem α p q l (fun b hb => h b (List.mem_cons_of_mem _ hb))
    rw [List.any_cons, List.any_cons, h a (by simp), ih]

theorem find?_congr' {α : Type} {p q : α → Bool} : ∀ {l : List α}, (∀ a ∈ l, p a = q a) → l.find? p = l.find? q
  | [], _ => rfl
  | a :: l, h => by
    have ih := @find?_congr' α p q l (fun b hb => h b (List.mem_cons_of_mem _ hb))
    simp only [List.find?_cons, h a (by simp), ih]

theorem find_any {α : Type} (p : α → Bool) : ∀ (t : List α), (t.find? p).toList.any p = t.any p
  | [] => rfl
  | a :: t => by
    by_cases h : p a = true
    · simp [h]
    · simp [h, find_any p t]

theorem any_take1 {α : Type} (l : List α) : (l.take 1).any (fun _ => true) = l.any (fun _ => true) := by
  cases l <;> simp

theorem arr_ext! {α : Type} [Inhabited α] (a b : Array α) (n : Nat) (ha : a.size = n) (hb : b.size = n)
    (h : ∀ k, k < n → a[k]! = b[k]!) : a = b :=
  Array.ext (by omega) fun k h1 h2 => by
    have := h k (by omega)
    rwa [getElem!_pos a k h1, getElem!_pos b k h2] at this

theorem same_refl (a : RowX) : a.same a = true := by
  simp [RowX.same, RowX.idEq, RowX.payEq, RowX.memEq, RowX.payeeEq, RowX.rendEq, RowX.procEq]

/-- `RowX.lt` as the order of a list of numbers. -/
def rkey (a : RowX) : List Nat :=
  [a.flow.toNat, a.m0.toNat, a.m1.toNat, a.m2.toNat, a.m3.toNat, a.a0.toNat, a.a1.toNat, a.a2.toNat, a.r0.toNat,
    a.r1.toNat, a.r2.toNat, a.date.toNat, a.q0.toNat, a.q1.toNat, a.q2.toNat, a.q3.toNat, a.units.toNat, a.cents.toNat,
    a.i0.toNat, a.i1.toNat, a.i2.toNat, a.i3.toNat, a.i4.toNat, a.i5.toNat, a.i6.toNat, a.p0.toNat, a.p1.toNat,
    a.p2.toNat, a.p3.toNat, a.p4.toNat, a.p5.toNat, a.p6.toNat, a.p7.toNat, a.p8.toNat]

theorem rowX_lt_key (a b : RowX) : a.lt b = true ↔ rkey a < rkey b := by
  simp only [RowX.lt, beq_iff_eq, Engine3.lt_then', Std.compare_eq_lt, Std.compare_eq_iff_eq, rkey,
    List.cons_lt_cons_iff, List.not_lt_nil, and_false, or_false, UInt64.lt_iff_toNat_lt, UInt32.lt_iff_toNat_lt,
    UInt8.lt_iff_toNat_lt, ← UInt64.toNat_inj, ← UInt32.toNat_inj, ← UInt8.toNat_inj]

theorem nat_list_lt_irrefl : ∀ (l : List Nat), ¬ l < l
  | [] => List.not_lt_nil _
  | a :: t => by
    rw [List.cons_lt_cons_iff]
    rintro (h | ⟨-, h⟩)
    · exact Nat.lt_irrefl _ h
    · exact nat_list_lt_irrefl t h

theorem lt_strict (x : Lay) : QS.Strict (fun i j => x.lines[i]!.row.lt x.lines[j]!.row) (fun _ : Nat => True) where
  irr i _ := by
    rw [Bool.eq_false_iff]
    intro h
    exact nat_list_lt_irrefl _ ((rowX_lt_key _ _).1 h)
  tr i j k _ _ _ h1 h2 :=
    (rowX_lt_key _ _).2 (List.lt_trans (i₁ := ⟨Nat.lt_trans⟩) ((rowX_lt_key _ _).1 h1) ((rowX_lt_key _ _).1 h2))

theorem qsort_lt (x : Lay) (p : Nat → Bool) (n i : Nat)
    (h : i ∈ ((Array.range n).filter p).qsort (fun i j => x.lines[i]!.row.lt x.lines[j]!.row)) : i < n := by
  have hs := (QS.qsort_spec _ (lt_strict x) ((Array.range n).filter p) (fun _ _ => trivial)).1
  have h2 := hs.mem_iff.1 h
  simp only [Array.mem_filter, Array.mem_range] at h2
  exact h2.1

/-! ## A slot through its reads -/

theorem anySame_rel (x : Lay) (k : Nat) (r : RowX) :
    anySame x.relP x.slots[k]!.rs x.slots[k]!.rn r = (relV x k).any fun e => e.1.same r := by
  unfold anySame
  rw [rangeAny1 _ _ (fun j => (x.relP[j]!.same r) = true)]
  simp [relV, List.any_map, Function.comp_def]

theorem anySame_unr (x : Lay) (k : Nat) (r : RowX) :
    anySame x.unrP x.slots[k]!.us x.slots[k]!.un r = (unrV x k).any fun e => e.1.same r := by
  unfold anySame
  rw [rangeAny1 _ _ (fun j => (x.unrP[j]!.same r) = true)]
  simp [unrV, entAt, List.any_map, Function.comp_def]

theorem seen_view (x : Lay) (k : Nat) (A : Array Nat) (L : Array LineIn) :
    ((List.range' x.slots[k]!.rs x.slots[k]!.rn).any fun j => !(A.any fun i => L[i]!.row.same x.relP[j]!)) =
      (relV x k).any fun e => !(A.any fun i => L[i]!.row.same e.1) := by
  simp [relV, List.any_map, Function.comp_def]

theorem ov_view (x : Lay) (k : Nat) :
    ((List.range' x.slots[k]!.us x.slots[k]!.un).any fun j => x.unrP[j]!.cap && x.uSpan[j]!.over) =
      (unrV x k).any fun e => e.1.cap && e.2.2.1.over := by
  simp [unrV, entAt, List.any_map, Function.comp_def]

/-- The claim of an unresolved read drops its near key (`capClaimAt`). -/
def ccE (x : Lay) (e : UEnt) : Bool :=
  e.1.cap && (x.spanOk && validDate e.1.date.toNat && !enrolledIn x.spans e.2.2.1 e.1) && !ownRow x e.2.2.2 e.1

theorem ccE_nocap (x : Lay) (e : UEnt) (h : e.1.cap = false) : ccE x e = false := by simp [ccE, h]

/-- Whether an unresolved read takes part in the first claimer of a slot. -/
def qE (near : Bool) (cc : UEnt → Bool) (e : UEnt) : Bool := !near || !cc e

/-- `pendAt` through the reads of the slot. -/
def pendV (near : Bool) (cc : UEnt → Bool) (v : List UEnt) (bp : Bool) (r : RowX) : Bool :=
  match v.find? (qE near cc) with
  | none => false
  | some h => !bp || !(!((v.filter (qE near cc)).any fun e => !h.1.same e.1) && h.1.same r)

theorem pend_view (x : Lay) (cc : Array Bool) (hcc : ∀ j, j < x.unrP.size → cc[j]! = ccE x (entAt x j)) (k : Nat)
    (hb : x.slots[k]!.us + x.slots[k]!.un ≤ x.unrP.size) (cf : Array Nat) (cs : Array Bool)
    (hcf : cf[k]! = (scanU (fun j => x.unrP[j]!.cap && x.uSpan[j]!.over)
      (qOf (fun k => x.slots[k]!.kind) (fun j => cc[j]!) k) (fun g j => !x.unrP[g]!.same x.unrP[j]!) false
      (List.range' x.slots[k]!.us x.slots[k]!.un)).1.getD x.unrP.size)
    (hcs : cs[k]! = (scanU (fun j => x.unrP[j]!.cap && x.uSpan[j]!.over)
      (qOf (fun k => x.slots[k]!.kind) (fun j => cc[j]!) k) (fun g j => !x.unrP[g]!.same x.unrP[j]!) false
      (List.range' x.slots[k]!.us x.slots[k]!.un)).2.1) (bp : Bool) (r : RowX) :
    pendAt x cf cs bp r k = pendV (x.slots[k]!.kind == 0 || x.slots[k]!.kind == 2) (ccE x) (unrV x k) bp r := by
  have hbnd : ∀ j ∈ List.range' x.slots[k]!.us x.slots[k]!.un, j < x.unrP.size := fun j hj => by
    rw [List.mem_range'_1] at hj; omega
  have hq : ∀ j ∈ List.range' x.slots[k]!.us x.slots[k]!.un,
      qOf (fun k => x.slots[k]!.kind) (fun j => cc[j]!) k j =
        (qE (x.slots[k]!.kind == 0 || x.slots[k]!.kind == 2) (ccE x) ∘ entAt x) j := by
    intro j hj
    simp only [qOf, qE, Function.comp, hcc j (hbnd j hj)]
  unfold pendAt pendV unrV
  rw [hcf, hcs]
  simp only [scanU, find?_congr' hq, List.filter_congr hq, List.find?_map, List.filter_map, List.any_map]
  generalize List.range' x.slots[k]!.us x.slots[k]!.un = l at hbnd ⊢
  rcases hf : l.find? (qE (x.slots[k]!.kind == 0 || x.slots[k]!.kind == 2) (ccE x) ∘ entAt x) with _ | j
  · simp
  · have hj : j < x.unrP.size := hbnd j (List.mem_of_find?_eq_some hf)
    simp [hj, entAt, Function.comp_def]

theorem pendV_congr (near : Bool) (cc cc' : UEnt → Bool) (v : List UEnt) (bp : Bool) (r : RowX)
    (h : ∀ e ∈ v, cc' e = cc e) : pendV near cc' v bp r = pendV near cc v bp r := by
  unfold pendV
  have h1 : v.find? (qE near cc') = v.find? (qE near cc) := find?_congr' fun e he => by simp [qE, h e he]
  have h2 : v.filter (qE near cc') = v.filter (qE near cc) := List.filter_congr fun e he => by simp [qE, h e he]
  rw [h1, h2]

theorem pendV_cut (near : Bool) (cc cc' : UEnt → Bool) (h : UEnt) (t : List UEnt) (bp : Bool) (r : RowX)
    (hc : ∀ e ∈ h :: t, cc e = false) (hc' : ∀ e ∈ h :: (t.find? fun e => !h.1.same e.1).toList, cc' e = false) :
    pendV near cc' (h :: (t.find? fun e => !h.1.same e.1).toList) bp r = pendV near cc (h :: t) bp r := by
  have f1 : (h :: t).filter (qE near cc) = h :: t := List.filter_eq_self.2 fun e he => by simp [qE, hc e he]
  have f2 : (h :: (t.find? fun e => !h.1.same e.1).toList).filter (qE near cc') =
      h :: (t.find? fun e => !h.1.same e.1).toList := List.filter_eq_self.2 fun e he => by simp [qE, hc' e he]
  have g1 : qE near cc h = true := by simp [qE, hc h (by simp)]
  have g2 : qE near cc' h = true := by simp [qE, hc' h (by simp)]
  unfold pendV
  simp only [List.find?_cons, g1, g2, f1, f2, List.any_cons, same_refl, Bool.not_true, Bool.false_or, find_any]

/-! ## Counterparts -/

def oRel (x : Lay) (k : Nat) : Option (Nat × Nat) :=
  if x.slots[k]!.rn > 0 then some (2 * x.slots[k]!.rs + 1, x.relSeq[x.slots[k]!.rs]!) else none

def oUnr (x : Lay) (cc : Array Bool) (r : RowX) (k : Nat) : Option (Nat × Nat) :=
  match (List.range' x.slots[k]!.us x.slots[k]!.un).find?
      (fun j => r.exactEq x.unrP[j]! || r.idEq x.unrP[j]! || !cc[j]! && r.nearEq x.unrP[j]!) with
  | none => none
  | some j => some (2 * j + 2, x.unrSeq[j]!)

theorem relC_o (x : Lay) (k : Nat) (acc : Nat × Nat) : relC x k acc = stepC (oRel x k) acc := relC_eq x k acc

theorem unrC_o (x : Lay) (cc : Array Bool) (r : RowX) (k : Nat) (acc : Nat × Nat) :
    unrC x cc r k acc = stepC (oUnr x cc r k) acc := unrC_eq x cc r k acc

/-- A found counterpart as the answer names it, and its order key. -/
def uMean (x : Lay) (o : Option (Nat × Nat)) : Option (Option (Nat × Nat) × Nat) := o.map fun p => (locOf x p.1, p.2)

def ORel (x x' : Lay) (o' o : Option (Nat × Nat)) : Prop :=
  uMean x' o' = uMean x o ∧ (∀ p ∈ o', p.1 ≠ 0) ∧ ∀ p ∈ o, p.1 ≠ 0

def ARel (x x' : Lay) (a' a : Nat × Nat) : Prop := (a'.1 == 0) = (a.1 == 0) ∧ a'.2 = a.2 ∧ locOf x' a'.1 = locOf x a.1

theorem stepC_rel {x x' : Lay} {o o' : Option (Nat × Nat)} {a a' : Nat × Nat} (ho : ORel x x' o' o)
    (ha : ARel x x' a' a) : ARel x x' (stepC o' a') (stepC o a) := by
  obtain ⟨hm, h1, h2⟩ := ho
  obtain ⟨a1, a2, a3⟩ := ha
  rcases o' with _ | ⟨c', q'⟩ <;> rcases o with _ | ⟨c, q⟩
  · exact ⟨a1, a2, a3⟩
  · simp [uMean] at hm
  · simp [uMean] at hm
  · simp only [uMean, Option.map_some, Option.some.injEq, Prod.mk.injEq] at hm
    have hc' : c' ≠ 0 := h1 (c', q') rfl
    have hc : c ≠ 0 := h2 (c, q) rfl
    simp only [stepC]
    rw [a1, a2, hm.2]
    by_cases hcnd : (a.1 == 0 || q < a.2) = true
    · rw [if_pos hcnd, if_pos hcnd]
      refine ⟨?_, rfl, hm.1⟩
      rw [Bool.eq_iff_iff]
      simp only [beq_iff_eq]
      exact ⟨fun h => absurd h hc', fun h => absurd h hc⟩
    · rw [if_neg hcnd, if_neg hcnd]
      exact ⟨a1, a2, a3⟩

theorem oRel_nz (x : Lay) (k : Nat) : ∀ p ∈ oRel x k, p.1 ≠ 0 := by
  intro p hp
  simp only [Option.mem_def] at hp
  unfold oRel at hp
  split at hp
  · cases hp; simp
  · cases hp

theorem oUnr_nz (x : Lay) (cc : Array Bool) (r : RowX) (k : Nat) : ∀ p ∈ oUnr x cc r k, p.1 ≠ 0 := by
  intro p hp
  simp only [Option.mem_def] at hp
  unfold oUnr at hp
  split at hp
  · cases hp
  · cases hp; simp

theorem rel_mean (x : Lay) (k : Nat) (hb : x.slots[k]!.rs + x.slots[k]!.rn ≤ x.relSeq.size) :
    uMean x (oRel x k) = (relV x k).head?.map fun e => (some (0, e.2), e.2) := by
  unfold oRel uMean relV
  rcases Nat.eq_zero_or_pos x.slots[k]!.rn with h | h
  · simp [h]
  · obtain ⟨n, hn⟩ : ∃ n, x.slots[k]!.rn = n + 1 := ⟨_, (Nat.succ_pred_eq_of_pos h).symm⟩
    have hs : x.slots[k]!.rs < x.relSeq.size := by omega
    have e1 : (2 * x.slots[k]!.rs + 1) / 2 = x.slots[k]!.rs := by omega
    have e2 : (2 * x.slots[k]!.rs + 1) % 2 = 1 := by omega
    rw [if_pos h, hn, List.range'_succ]
    simp [locOf, e1, e2, hs]

/-- Whether an unresolved read meets line row `r` (`unrC`). -/
def Qr (x : Lay) (r : RowX) (e : UEnt) : Bool := r.exactEq e.1 || r.idEq e.1 || !ccE x e && r.nearEq e.1

theorem unr_mean (x : Lay) (cc : Array Bool) (hcc : ∀ j, j < x.unrP.size → cc[j]! = ccE x (entAt x j)) (r : RowX)
    (k : Nat) (hb1 : x.slots[k]!.us + x.slots[k]!.un ≤ x.unrP.size)
    (hb2 : x.slots[k]!.us + x.slots[k]!.un ≤ x.unrSeq.size) :
    uMean x (oUnr x cc r k) = ((unrV x k).find? (Qr x r)).map fun e => (some (1, e.2.1), e.2.1) := by
  have hq : ∀ j ∈ List.range' x.slots[k]!.us x.slots[k]!.un,
      (r.exactEq x.unrP[j]! || r.idEq x.unrP[j]! || !cc[j]! && r.nearEq x.unrP[j]!) = (Qr x r ∘ entAt x) j := by
    intro j hj
    rw [List.mem_range'_1] at hj
    simp only [Function.comp, Qr, entAt, hcc j (by omega)]
  unfold oUnr uMean unrV
  rw [find?_congr' hq, List.find?_map]
  rcases hf : (List.range' x.slots[k]!.us x.slots[k]!.un).find? (Qr x r ∘ entAt x) with _ | j
  · rfl
  · have hj := List.mem_of_find?_eq_some hf
    rw [List.mem_range'_1] at hj
    have hs : j < x.unrSeq.size := by omega
    have e1 : (2 * j + 2) / 2 - 1 = j := by omega
    have e2 : (2 * j + 2) % 2 = 0 := by omega
    simp [locOf, e1, e2, hs, entAt]

theorem cp_final {x x' : Lay} (a a' u u' : Nat × Nat) (ha : ARel x x' a' a) (hu : ARel x x' u' u) :
    locOf x' (if (a'.1 != 0) = true then a'.1 else u'.1) = locOf x (if (a.1 != 0) = true then a.1 else u.1) := by
  obtain ⟨h1, -, h3⟩ := ha
  obtain ⟨-, -, h6⟩ := hu
  have : (a'.1 != 0) = (a.1 != 0) := by simp only [bne, h1]
  rw [this]
  split
  · exact h3
  · exact h6

/-! ## Per slot, between the layouts -/

section
variable {x x' : Lay}

theorem mem_unr (C : Cut x x') {k : Nat} (hk : k < x.slots.size) {e : UEnt} (he : e ∈ unrV x' k) :
    e ∈ unrV x k := by
  rcases C.unr k hk with hv | ⟨h, t, hv, hv', -, -, -⟩
  · rwa [hv] at he
  · rw [hv', List.mem_cons] at he
    rw [hv]
    rcases he with rfl | he
    · simp
    · cases hf : t.find? fun e => !h.1.same e.1 with
      | none => rw [hf] at he; simp at he
      | some d =>
        rw [hf] at he
        simp only [Option.toList_some, List.mem_singleton] at he
        subst he
        exact List.mem_cons_of_mem _ (List.mem_of_find?_eq_some hf)

theorem ownRow_eq (C : Cut x x') (u : Nat) (y : RowX) (hu : u < x.slots.size → relV x' u = relV x u) :
    ownRow x' u y = ownRow x u y := by
  simp only [ownRow]
  rw [C.redo, C.size]
  by_cases h : u < x.slots.size
  · rw [anySame_rel x' u y, anySame_rel x u y, hu h]
  · simp [h]

theorem ccE_eq (C : Cut x x') (e : UEnt) (he : ∃ k, k < x.slots.size ∧ e ∈ unrV x k) : ccE x' e = ccE x e := by
  obtain ⟨k, hk, hek⟩ := he
  unfold ccE
  rw [C.spanOk, C.spans, ownRow_eq C _ _ fun hu => ?_]
  rcases C.rel e.2.2.2 hu with hv | ⟨-, -, hn⟩
  · exact hv
  · exact absurd rfl (hn k hk e hek)

theorem own_eq (C : Cut x x') (li : LineIn) (hli : li ∈ x.lines) :
    (x.pRedo[li.pay]! && anySame x'.relP x'.slots[li.ki]!.rs x'.slots[li.ki]!.rn li.row) =
      (x.pRedo[li.pay]! && anySame x.relP x.slots[li.ki]!.rs x.slots[li.ki]!.rn li.row) := by
  rw [anySame_rel, anySame_rel]
  rcases C.rel li.ki (C.keys li hli).2.2 with hv | ⟨-, hp, -⟩
  · rw [hv]
  · rw [hp li hli (Or.inr (Or.inr rfl))]
    rfl

theorem held_eq (C : Cut x x') (li : LineIn) (hli : li ∈ x.lines) :
    anySame x'.unrP x'.slots[li.ki]!.us x'.slots[li.ki]!.un li.row =
      anySame x.unrP x.slots[li.ki]!.us x.slots[li.ki]!.un li.row := by
  rw [anySame_unr, anySame_unr]
  rcases C.unr li.ki (C.keys li hli).2.2 with hv | ⟨-, -, -, -, -, hki, -⟩
  · rw [hv]
  · exact absurd rfl (hki li hli)

theorem hot0_eq (C : Cut x x') :
    (x'.slots.map fun sl => decide (capN < sl.rc) || decide (capN < sl.uc)) =
      x.slots.map fun sl => decide (capN < sl.rc) || decide (capN < sl.uc) := by
  refine arr_ext! _ _ x.slots.size (by simp [C.size]) (by simp) fun k hk => ?_
  rw [getElem!_pos _ k (by simp [C.size, hk]), getElem!_pos _ k (by simp [hk]), Array.getElem_map, Array.getElem_map,
    ← getElem!_pos x'.slots k (by rw [C.size]; exact hk), ← getElem!_pos x.slots k hk, C.rc k hk, C.uc k hk]

theorem rel_or (C : Cut x x') (k : Nat) (hk : k < x.slots.size) : ORel x x' (oRel x' k) (oRel x k) := by
  refine ⟨?_, oRel_nz _ _, oRel_nz _ _⟩
  rw [rel_mean x' k (C.bnd' k hk).1, rel_mean x k (C.bnd k hk).1]
  rcases C.rel k hk with hv | ⟨hv, -, -⟩
  · rw [hv]
  · rw [hv, List.head?_take]
    simp

theorem unr_or (C : Cut x x') (cc cc' : Array Bool) (hcc : ∀ j, j < x.unrP.size → cc[j]! = ccE x (entAt x j))
    (hcc' : ∀ j, j < x'.unrP.size → cc'[j]! = ccE x' (entAt x' j)) (li : LineIn) (hli : li ∈ x.lines) (k : Nat)
    (hkl : k = li.ke ∨ k = li.kn ∨ k = li.ki) (hk : k < x.slots.size) :
    ORel x x' (oUnr x' cc' li.row k) (oUnr x cc li.row k) := by
  refine ⟨?_, oUnr_nz _ _ _ _, oUnr_nz _ _ _ _⟩
  rw [unr_mean x' cc' hcc' li.row k (C.bnd' k hk).2.1 (C.bnd' k hk).2.2,
    unr_mean x cc hcc li.row k (C.bnd k hk).2.1 (C.bnd k hk).2.2]
  rcases C.unr k hk with hv | ⟨h, t, hv, hv', hcap, hki, hmeet⟩
  · rw [hv]
    congr 1
    exact find?_congr' fun e he => by
      simp only [Qr, ccE_eq C e ⟨k, hk, he⟩]
  · have hm : (li.row.exactEq h.1 || li.row.idEq h.1 || li.row.nearEq h.1) = true := by
      rcases hkl with e | e | e
      · exact hmeet li hli (Or.inl e.symm)
      · exact hmeet li hli (Or.inr e.symm)
      · exact absurd e.symm (hki li hli)
    have hh : h.1.cap = false := hcap h (by rw [hv]; simp)
    have g1 : Qr x li.row h = true := by simpa [Qr, ccE_nocap x h hh] using hm
    have g2 : Qr x' li.row h = true := by simpa [Qr, ccE_nocap x' h hh] using hm
    rw [hv, hv']
    simp only [List.find?_cons, g1, g2]

end

/-! ## Decision order -/

theorem maskC_congr (x x' : Lay) (hl : x'.lines = x.lines) (hpb : x'.pByp = x.pByp) (base : Array UInt32)
    (fcap hot : Array Bool) (ic : Bool) (sn seen0 : Array Bool) (cf cf' : Array Nat) (cs cs' : Array Bool) (i : Nat)
    (hp : ∀ k, (k = x.lines[i]!.ke ∨ k = x.lines[i]!.kn ∨ k = x.lines[i]!.ki) →
      ∀ bp r, pendAt x' cf' cs' bp r k = pendAt x cf cs bp r k) :
    maskC x' base fcap hot ic sn seen0 cf' cs' i = maskC x base fcap hot ic sn seen0 cf cs i := by
  simp only [maskC, mask0, hl, hpb, hp _ (Or.inl rfl), hp _ (Or.inr (Or.inl rfl)), hp _ (Or.inr (Or.inr rfl))]

abbrev St6 := Array Bool × Array Dec × Array Bool × Array Bool × Array Bool × Array Bool

theorem fold_sim (x x' : Lay) (own held notEnr : Array Bool) (base : Array UInt32) (fcap hot : Array Bool) (ic : Bool)
    (seen0 : Array Bool) (cf cf' : Array Nat) (cs cs' cc cc' : Array Bool)
    (hl : x'.lines = x.lines) (hpr : x'.pRedo = x.pRedo) (hpb : x'.pByp = x.pByp) (L : List Nat)
    (hm : ∀ i ∈ L, ∀ sn, maskC x' base fcap hot ic sn seen0 cf' cs' i = maskC x base fcap hot ic sn seen0 cf cs i)
    (hc : ∀ i ∈ L, locOf x' (cpOf x' cc' i) = locOf x (cpOf x cc i)) :
    ∀ (s s' : St6), s'.1 = s.1 → s'.2.2 = s.2.2 → s'.2.1.toList.map (ansOf x') = s.2.1.toList.map (ansOf x) →
      (L.foldl (fun st i => stepG x' own held notEnr base fcap hot ic seen0 cf' cs' cc' i st) s').1 =
          (L.foldl (fun st i => stepG x own held notEnr base fcap hot ic seen0 cf cs cc i st) s).1 ∧
        (L.foldl (fun st i => stepG x' own held notEnr base fcap hot ic seen0 cf' cs' cc' i st) s').2.2 =
          (L.foldl (fun st i => stepG x own held notEnr base fcap hot ic seen0 cf cs cc i st) s).2.2 ∧
        (L.foldl (fun st i => stepG x' own held notEnr base fcap hot ic seen0 cf' cs' cc' i st) s').2.1.toList.map
            (ansOf x') =
          (L.foldl (fun st i => stepG x own held notEnr base fcap hot ic seen0 cf cs cc i st) s).2.1.toList.map
            (ansOf x) := by
  induction L with
  | nil => intro s s' h1 h2 h3; exact ⟨h1, h2, h3⟩
  | cons i L ih =>
    intro s s' h1 h2 h3
    have hi : i ∈ i :: L := by simp
    obtain ⟨a1, d1, b1⟩ := s
    obtain ⟨a2, d2, b2⟩ := s'
    simp only at h1 h2 h3
    subst h1 h2
    simp only [List.foldl_cons]
    refine ih (fun j hj => hm j (List.mem_cons_of_mem _ hj)) (fun j hj => hc j (List.mem_cons_of_mem _ hj)) _ _
      ?_ ?_ ?_
    · simp only [stepG, hl, hpr, hpb, hm i hi a2]
    · simp only [stepG, hl, hpr, hpb, hm i hi a2]
    · simp only [stepG, hl, hpr, hpb, hm i hi a2, Array.toList_push, List.map_append, h3, List.map_cons,
        List.map_nil, ansOf, hc i hi]

theorem filt_eq (P : Dec → Bool) (hP : ∀ d, P d = P ⟨d.line, d.mask, d.out, 0⟩) :
    ∀ (l l' : List Dec), l'.map (fun d => (d.line, d.mask, d.out)) = l.map (fun d => (d.line, d.mask, d.out)) →
      (l'.filter P).map (·.line) = (l.filter P).map (·.line)
  | [], [], _ => rfl
  | [], _ :: _, h => by simp at h
  | _ :: _, [], h => by simp at h
  | d :: l, d' :: l', h => by
    simp only [List.map_cons, List.cons.injEq, Prod.mk.injEq] at h
    obtain ⟨⟨h1, h2, h3⟩, h4⟩ := h
    have e : P d' = P d := by rw [hP d', hP d, h1, h2, h3]
    simp only [List.filter_cons, e]
    split <;> simp [h1, filt_eq P hP l l' h4]

/-! ## The theorem -/

theorem relPr_cut {x x' : Lay} (C : Cut x x') : relPr x' = relPr x := by
  unfold relPr bypOf liftOf
  rw [C.lines, C.pRedo, C.pByp, C.lLim]

theorem unrPr_cut {x x' : Lay} (C : Cut x x') : unrPr x' = unrPr x := by
  unfold unrPr bypOf liftOf
  rw [C.lines, C.pRedo, C.pByp, C.lLim]

theorem liftStep_cut {x x' : Lay} (C : Cut x x') : liftStep x' = liftStep x := by
  funext d a
  unfold liftStep
  rw [C.lines, C.lLim]

set_option maxHeartbeats 4000000 in
/-- `decideRows` on a layout with cut slots decides as on the full layout: the same decisions and counterparts as the
    answer names them, and the same rows joining each set. -/
theorem decideRows_cut (x x' : Lay) (C : Cut x x') :
    (decideRows x').ds.toList.map (ansOf x') = (decideRows x).ds.toList.map (ansOf x) ∧
      (decideRows x').rel = (decideRows x).rel ∧ (decideRows x').unr = (decideRows x).unr := by
  generalize ho : decideRows x = o
  unfold decideRows
  dsimp only
  generalize hr1' : (forIn x'.lines _ _ : Id _) = r1'
  rw [idbind]
  generalize hr2' : (forIn ([:x'.unrP.size] : Std.Legacy.Range) _ _ : Id _) = r2'
  rw [idbind]
  generalize hr3' : (forIn ([:x'.lines.size] : Std.Legacy.Range) _ _ : Id _) = r3'
  rw [idbind]
  generalize hr4' : (forIn ([:x'.slots.size] : Std.Legacy.Range) _ _ : Id _) = r4'
  rw [idbind]
  generalize hr5' : (forIn x'.lines _ _ : Id _) = r5'
  rw [idbind]
  generalize hr6' : (forIn (_ : Array Nat) _ _ : Id _) = r6'
  rw [idbind]
  generalize hr7' : (forIn (_ : Array Dec) _ _ : Id _) = r7'
  rw [idbind]
  generalize hr8' : (forIn (_ : Array Dec) _ _ : Id _) = r8'
  rw [idbind]
  rw [← ho]
  unfold decideRows
  dsimp only
  generalize hr1 : (forIn x.lines _ _ : Id _) = r1
  rw [idbind]
  generalize hr2 : (forIn ([:x.unrP.size] : Std.Legacy.Range) _ _ : Id _) = r2
  rw [idbind]
  generalize hr3 : (forIn ([:x.lines.size] : Std.Legacy.Range) _ _ : Id _) = r3
  rw [idbind]
  generalize hr4 : (forIn ([:x.slots.size] : Std.Legacy.Range) _ _ : Id _) = r4
  rw [idbind]
  generalize hr5 : (forIn x.lines _ _ : Id _) = r5
  rw [idbind]
  generalize hr6 : (forIn (_ : Array Nat) _ _ : Id _) = r6
  rw [idbind]
  generalize hr7 : (forIn (_ : Array Dec) _ _ : Id _) = r7
  rw [idbind]
  generalize hr8 : (forIn (_ : Array Dec) _ _ : Id _) = r8
  rw [idbind]
  rw [forIn_push5] at hr1 hr1'
  -- the per-line pass
  have e1 : r1' = r1 := by
    rw [← hr1, ← hr1']
    refine Prod.ext ?_ (Prod.ext ?_ (Prod.ext ?_ (Prod.ext ?_ ?_)))
    · show _ ++ _ = _ ++ _
      rw [C.lines]
      congr 1
      exact Array.map_congr_left fun li hli => by simp only [C.pRedo]; exact own_eq C li hli
    · show _ ++ _ = _ ++ _
      rw [C.lines]
      congr 1
      exact Array.map_congr_left fun li hli => held_eq C li hli
    all_goals simp only [C.lines, C.today, C.relCh, C.unrCh, C.dmfSome, C.pdSome, C.exclSome, C.spanSome, C.eligSome,
      C.dmfOk, C.pdOk, C.exclOk, C.spanOk, C.eligOk, C.dmf, C.pdeath, C.excl, C.spans, C.eligs]
  have hown : ∀ i, i < x.lines.size → r1.1[i]! = (x.pRedo[x.lines[i]!.pay]! &&
      anySame x.relP x.slots[x.lines[i]!.ki]!.rs x.slots[x.lines[i]!.ki]!.rn x.lines[i]!.row) := by
    intro i hi
    rw [← hr1]
    simp only [Array.emptyWithCapacity, Array.empty_append, getElem!_pos, Array.getElem_map, hi, Array.size_map]
  have hmem : ∀ i, i < x.lines.size → x.lines[i]! ∈ x.lines := fun i hi => by
    rw [getElem!_pos x.lines i hi]; exact Array.getElem_mem hi
  -- the claims
  obtain ⟨c1, c2⟩ := range_push (g := capClaimAt x) _ _ (un r2) hr2
  obtain ⟨c1', c2'⟩ := range_push (g := capClaimAt x') _ _ (un r2') hr2'
  have hcc : ∀ j, j < x.unrP.size → (un r2)[j]! = ccE x (entAt x j) := fun j hj => c2 j hj
  have hcc' : ∀ j, j < x'.unrP.size → (un r2')[j]! = ccE x' (entAt x' j) := fun j hj => c2' j hj
  -- own lines per slot and hot lines
  have e3 : r3' = r3 := by
    rw [← hr3', ← hr3, e1, hot0_eq C, C.lines, C.size]
  obtain ⟨o1, o2, o3, o4⟩ := loop3 x.lines.size r1.1 (fun i => x.lines[i]!.ke)
    (fun i => x.lines[i]!.kn) (fun i => x.lines[i]!.ki)
    (fun i => x.lines[i]!.row.cap && x.lines[i]!.span.over) _ _ (un r3) hr3
  have hh : (un r3).2.size = x.slots.size := by simpa using o2
  have hh' : (un r3').2.size = x'.slots.size := by rw [e3, C.size]; exact hh
  -- per slot
  obtain ⟨p1, p2, p3, p4, p5, p6⟩ := loop4 x.unrP.size (fun k => x.slots[k]!.kind)
    (fun k => x.slots[k]!.rs) (fun k => x.slots[k]!.rn) (fun k => x.slots[k]!.rc) (fun k => x.slots[k]!.us)
    (fun k => x.slots[k]!.un) (fun k j => (un r3).1[k]!.any fun i => x.lines[i]!.row.same x.relP[j]!)
    (fun j => x.unrP[j]!.cap && x.uSpan[j]!.over) (fun j => (un r2)[j]!)
    (fun g j => !x.unrP[g]!.same x.unrP[j]!) x.slots.size (un r3).2 hh
    (fun k _ g _ => by simp [same_refl]) (un r4) hr4
  obtain ⟨p1', p2', p3', p4', p5', p6'⟩ := loop4 x'.unrP.size (fun k => x'.slots[k]!.kind)
    (fun k => x'.slots[k]!.rs) (fun k => x'.slots[k]!.rn) (fun k => x'.slots[k]!.rc) (fun k => x'.slots[k]!.us)
    (fun k => x'.slots[k]!.un) (fun k j => (un r3').1[k]!.any fun i => x'.lines[i]!.row.same x'.relP[j]!)
    (fun j => x'.unrP[j]!.cap && x'.uSpan[j]!.over) (fun j => (un r2')[j]!)
    (fun g j => !x'.unrP[g]!.same x'.unrP[j]!) x'.slots.size (un r3').2 hh'
    (fun k _ g _ => by simp [same_refl]) (un r4') hr4'
  have e_ic : (un r4').2.1 = (un r4).2.1 := by
    rw [p5', p5, C.size]
    exact any_congr_mem fun k hk => by
      rw [List.mem_range'_1] at hk
      simp only [C.kind k (by omega), C.rc k (by omega)]
  have e_s0 : (un r4').2.2.1 = (un r4).2.2.1 := by
    refine arr_ext! _ _ x.slots.size (by rw [p2', C.size]) p2 fun k hk => ?_
    rw [(p6' k (by rw [C.size]; exact hk)).1, (p6 k hk).1]
    rw [e3, C.lines, seen_view x' k, seen_view x k]
    rcases C.rel k hk with hv | ⟨hv, hp, -⟩
    · rw [hv]
    · have hA : ∀ y, ((un r3).1[k]!.any fun i => x.lines[i]!.row.same y) = false := by
        intro y
        rw [Array.any_eq_false']
        intro i hi
        rcases (o3 k (by simpa using hk) i).1 hi with h | ⟨hin, hw, hkey⟩
        · have hz : (Array.replicate x.slots.size (#[] : Array Nat))[k]! = #[] := by
            rw [getElem!_pos _ k (by simpa using hk)]; simp
          rw [hz] at h
          simp at h
        · exfalso
          have hf := hp _ (hmem i hin) (by rcases hkey with e | e | e <;> simp [e])
          rw [hown i hin, hf] at hw
          exact Bool.false_ne_true hw
      simp only [hA, Bool.not_false]
      rw [hv, any_take1]
  have e_hot : (un r4').1 = (un r4).1 := by
    refine arr_ext! _ _ x.slots.size (by rw [p1', C.size]) p1 fun k hk => ?_
    rw [(p6' k (by rw [C.size]; exact hk)).2.2.2, (p6 k hk).2.2.2]
    rw [e3, ov_view x' k, ov_view x k]
    rcases C.unr k hk with hv | ⟨h, t, hv, hv', hcap, -, -⟩
    · rw [hv]
    · have z : ∀ v : List UEnt, (∀ e ∈ v, e.1.cap = false) → (v.any fun e => e.1.cap && e.2.2.1.over) = false :=
        fun v hv => List.any_eq_false.2 fun e he => by simp [hv e he]
      rw [z _ hcap, z _ fun e he => hcap e (mem_unr C hk he)]
  have hpend : ∀ k, k < x.slots.size → ∀ bp r, pendAt x' (un r4').2.2.2.1 (un r4').2.2.2.2 bp r k =
      pendAt x (un r4).2.2.2.1 (un r4).2.2.2.2 bp r k := by
    intro k hk bp r
    have hk' : k < x'.slots.size := by rw [C.size]; exact hk
    rw [pend_view x' (un r2') hcc' k (C.bnd' k hk).2.1 _ _ (p6' k hk').2.1 (p6' k hk').2.2.1 bp r,
      pend_view x (un r2) hcc k (C.bnd k hk).2.1 _ _ (p6 k hk).2.1 (p6 k hk).2.2.1 bp r, C.kind k hk]
    rcases C.unr k hk with hv | ⟨h, t, hv, hv', hcap, -, -⟩
    · rw [hv]
      exact pendV_congr _ _ _ _ _ _ fun e he => ccE_eq C e ⟨k, hk, he⟩
    · rw [hv, hv']
      refine pendV_cut _ _ _ h t bp r (fun e he => ccE_nocap x e (hcap e (by rw [hv]; exact he)))
        fun e he => ccE_nocap x' e (hcap e (mem_unr C hk (by rw [hv']; exact he)))
  -- the decision-order loop
  have e5 : r5' = r5 := by rw [← hr5', ← hr5, C.lines, C.size]
  rw [← Array.forIn_toList, forIn_eq_foldl _ _ _ (stepG x r1.1 r1.2.1 r1.2.2.1 r1.2.2.2.1 r1.2.2.2.2 r4.1 r4.2.1
    r4.2.2.1 r4.2.2.2.1 r4.2.2.2.2 (un r2)) ?hstep] at hr6
  case hstep =>
    intro i st
    simp only [← mask0.eq_1, ← maskC.eq_1, ← cpOf.eq_1]
    simp only [stepG]
    repeat' split
    all_goals rfl
  rw [← Array.forIn_toList, forIn_eq_foldl _ _ _ (stepG x' r1'.1 r1'.2.1 r1'.2.2.1 r1'.2.2.2.1 r1'.2.2.2.2 r4'.1
    r4'.2.1 r4'.2.2.1 r4'.2.2.2.1 r4'.2.2.2.2 (un r2')) ?hstep'] at hr6'
  case hstep' =>
    intro i st
    simp only [← mask0.eq_1, ← maskC.eq_1, ← cpOf.eq_1]
    simp only [stepG]
    repeat' split
    all_goals rfl
  rw [e1, e5, C.lines, C.pRedo] at hr6'
  rw [show r4'.1 = r4.1 from e_hot, show r4'.2.1 = r4.2.1 from e_ic, show r4'.2.2.1 = r4.2.2.1 from e_s0] at hr6'
  generalize hL : (((Array.range x.lines.size).filter (r1.1[·]!)).qsort
    (fun i j => x.lines[i]!.row.lt x.lines[j]!.row) ++ ((Array.range x.lines.size).filter (!r1.1[·]!)).qsort
    (fun i j => x.lines[i]!.row.lt x.lines[j]!.row)) = ord at hr6 hr6'
  have hord : ∀ i ∈ ord.toList, i < x.lines.size := by
    intro i hi
    rw [← hL, Array.mem_toList_iff, Array.mem_append] at hi
    rcases hi with h | h
    · exact qsort_lt x _ _ _ h
    · exact qsort_lt x _ _ _ h
  obtain ⟨F1, F2, F3⟩ := fold_sim x x' r1.1 r1.2.1 r1.2.2.1 r1.2.2.2.1 r1.2.2.2.2 r4.1 r4.2.1 r4.2.2.1 r4.2.2.2.1
    r4'.2.2.2.1 r4.2.2.2.2 r4'.2.2.2.2 (un r2) (un r2') C.lines C.pRedo C.pByp ord.toList
    (fun i hi sn => maskC_congr x x' C.lines C.pByp _ _ _ _ sn _ _ _ _ _ i fun k hkl bp r => by
      have hks := C.keys _ (hmem i (hord i hi))
      exact hpend k (by rcases hkl with e | e | e <;> rw [e] <;> omega) bp r)
    (fun i hi => by
      have hli := hmem i (hord i hi)
      have hks := C.keys _ hli
      have hkk : ∀ k, (k = x.lines[i]!.ke ∨ k = x.lines[i]!.kn ∨ k = x.lines[i]!.ki) → k < x.slots.size :=
        fun k hkl => by rcases hkl with e | e | e <;> rw [e] <;> omega
      unfold cpOf
      simp only [relC_o, unrC_o, C.lines]
      have a0 : ARel x x' (0, 0) (0, 0) := ⟨rfl, rfl, by simp [locOf]⟩
      have hR := fun k hkl => rel_or C k (hkk k hkl)
      have hU := fun k hkl => unr_or C (un r2) (un r2') hcc hcc' _ hli k hkl (hkk k hkl)
      exact cp_final _ _ _ _
        (stepC_rel (hR _ (Or.inr (Or.inr rfl))) (stepC_rel (hR _ (Or.inr (Or.inl rfl)))
          (stepC_rel (hR _ (Or.inl rfl)) a0)))
        (stepC_rel (hU _ (Or.inr (Or.inr rfl))) (stepC_rel (hU _ (Or.inr (Or.inl rfl)))
          (stepC_rel (hU _ (Or.inl rfl)) a0))))
    (r5, Array.emptyWithCapacity x.lines.size, Array.replicate x.pRedo.size false, Array.replicate x.pRedo.size true,
      Array.replicate x.pRedo.size false, Array.replicate x.pRedo.size true)
    (r5, Array.emptyWithCapacity x.lines.size, Array.replicate x.pRedo.size false, Array.replicate x.pRedo.size true,
      Array.replicate x.pRedo.size false, Array.replicate x.pRedo.size true) rfl rfl (by simp)
  rw [hr6, hr6'] at F1 F2 F3
  -- per payment, whether it goes at HOLD authority
  rw [← Array.forIn_toList, forIn_eq_foldl _ _ _ (liftStep x) ?hstepL] at hr7
  case hstepL =>
    intro d st
    simp only [liftStep]
    repeat' split
    all_goals rfl
  rw [← Array.forIn_toList, forIn_eq_foldl _ _ _ (liftStep x') ?hstepL'] at hr7'
  case hstepL' =>
    intro d st
    simp only [liftStep]
    repeat' split
    all_goals rfl
  have hl3 : r6'.2.1.toList.map (fun d => (d.line, d.mask, d.out)) =
      r6.2.1.toList.map (fun d => (d.line, d.mask, d.out)) := by
    have := congrArg (List.map fun t : Nat × UInt32 × UInt8 × Option (Nat × Nat) => (t.1, t.2.1, t.2.2.1)) F3
    simpa [List.map_map, Function.comp_def, ansOf] using this
  have e7 : r7' = r7 := by
    rw [← hr7', ← hr7, liftStep_cut C, C.pRedo]
    exact fold_lift_congr x _ _ hl3 _
  -- the rows each set gains
  rw [← Array.forIn_toList, forIn_eq_foldl _ _ _ (relStep x r1.1 r1.2.1 r6.2.2.1 r6.2.2.2.1 r6.2.2.2.2.1
    r6.2.2.2.2.2 r7) ?hstep8] at hr8
  case hstep8 =>
    intro d st
    exact ite_pair_gen _ _ _ _ _
  rw [← Array.forIn_toList, forIn_eq_foldl _ _ _ (relStep x' r1'.1 r1'.2.1 r6'.2.2.1 r6'.2.2.2.1 r6'.2.2.2.2.1
    r6'.2.2.2.2.2 r7') ?hstep8'] at hr8'
  case hstep8' =>
    intro d st
    exact ite_pair_gen _ _ _ _ _
  obtain ⟨g1, g2⟩ := fold_rel x r1.1 r1.2.1 r6.2.2.1 r6.2.2.2.1 r6.2.2.2.2.1 r6.2.2.2.2.2 r7 r6.2.1.toList (#[], #[])
  obtain ⟨g1', g2'⟩ := fold_rel x' r1'.1 r1'.2.1 r6'.2.2.1 r6'.2.2.2.1 r6'.2.2.2.2.1 r6'.2.2.2.2.2 r7'
    r6'.2.1.toList (#[], #[])
  rw [hr8] at g1 g2
  rw [hr8'] at g1' g2'
  refine ⟨?_, ?_, ?_⟩
  · exact F3
  · show r8'.1 = r8.1
    apply Array.ext'
    rw [g1', g1, F2, relPr_cut C, e1, e7, filt_eq _ (fun d => rfl) _ _ hl3]
  · show r8'.2 = r8.2
    apply Array.ext'
    rw [g2', g2, F2, unrPr_cut C, e1, e7, filt_eq _ (fun d => rfl) _ _ hl3]

end BlindLedger.Gate.Flat.Rows
