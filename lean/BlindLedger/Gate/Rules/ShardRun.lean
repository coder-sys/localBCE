import BlindLedger.Gate.Rules.Shards
import BlindLedger.Gate.Rules.FastEq

/-! Multi-shard runtime (rrb/designs/multi-shard-runtime-v1.md §5): the id registry protocol as reserve,
    seal and settle events of any shards in any order, and its safety; the `Fast` twins proved equal.
    A crash is an absent event; a restored registry is refused at boot (design §4), so a run never steps
    back.  Synthetic, nonpayment, activation=false. -/

namespace BlindLedger.Gate.Rules

/-! ### The answers -/

theorem contains_filter_map {α : Type} (p : α → Bool) (f : α → Nat) (os : List α) (i : Nat) :
    ((os.filter p).map f).contains i = os.any fun o => f o == i && p o := by
  apply Bool.eq_iff_iff.mpr
  rw [List.contains_iff_mem, List.any_eq_true]
  constructor
  · intro h
    obtain ⟨o, ho, rfl⟩ := List.mem_map.mp h
    obtain ⟨ho, hp⟩ := List.mem_filter.mp ho
    exact ⟨o, ho, by simp [hp]⟩
  · rintro ⟨o, ho, h⟩
    simp only [Bool.and_eq_true, beq_iff_eq] at h
    exact List.mem_map.mpr ⟨o, List.mem_filter.mpr ⟨ho, h.2⟩, h.1⟩

/-- If every answer naming shard `k` is true, a line `k` decides that the registry does not give `k` is
    recorded elsewhere: it is in `foreignOf`, so it is `ALREADY_DECIDED` (`fresh_owner`). -/
theorem ready_hf {reg : Nat → Option Nat} {k : Nat} {os : List Owner} {b : List Line}
    (hos : ∀ o ∈ os, o.shard = k → reg o.id = some k) :
    ∀ l ∈ ready k os b, reg l.id ≠ some k → l.id ∈ foreignOf k os (ready k os b) := by
  intro l hl hne
  have hb : l ∈ b := (List.mem_filter.mp hl).1
  have hw : (!b.any fun m => m.pay == l.pay && !okId k os m.id) = true := (List.mem_filter.mp hl).2
  have hok : okId k os l.id = true := by
    cases h : okId k os l.id
    · have : (b.any fun m => m.pay == l.pay && !okId k os m.id) = true :=
        List.any_eq_true.mpr ⟨l, hb, by simp [h]⟩
      rw [this] at hw
      cases hw
    · rfl
  obtain ⟨o, ho, he⟩ := List.any_eq_true.mp hok
  simp only [Bool.and_eq_true, Bool.or_eq_true, beq_iff_eq] at he
  by_cases hk : o.shard = k
  · exact (hne (by rw [← he.1]; exact hos o ho hk)).elim
  · have hs : o.settled = true := he.2.resolve_left hk
    refine List.mem_filter.mpr ⟨List.mem_map.mpr ⟨l, hl, rfl⟩, List.any_eq_true.mpr ⟨o, ho, ?_⟩⟩
    simp [he.1, hk, hs]

/-- A freed id is in neither of the shard's sealed sets. -/
theorem settleFree_out {rel unr : List Line} {p : List Nat} {i : Nat}
    (h : i ∈ settleFree rel unr p) : ∀ x ∈ rel ++ unr, x.id ≠ i := by
  intro x hx he
  have h2 : (!((rel ++ unr).map (·.id)).contains i) = true := (List.mem_filter.mp h).2
  rw [List.contains_iff_mem.mpr (List.mem_map.mpr ⟨x, hx, he⟩)] at h2
  cases h2

/-! ### The protocol model -/

/-- The registry (`reg i`: the shard holding id `i`), each shard's sealed sets, and every ALLOW line sealed
    with its shard. -/
structure World where
  reg : Nat → Option Nat
  rel : Nat → List Line
  unr : Nat → List Line
  paid : List (Nat × Line)

inductive Ev
  | reserve (k : Nat) (ids : List Nat)
  | sealB (k : Nat) (c : Ctx) (os : List Owner) (b : List Line)
  | settle (k : Nat) (pending : List Nat)

/-- `reserve` gives each free id to `k`; `settle` frees those of `k`'s ids its sets do not hold; `seal`
    decides `decideReg` on `k`'s own sets, refused unless every answer naming `k` is the registry's. -/
def World.step (w : World) : Ev → Option World
  | .reserve k ids => some { w with reg := fun i => if w.reg i = none ∧ i ∈ ids then some k else w.reg i }
  | .settle k p => some { w with
      reg := fun i => if i ∈ settleFree (w.rel k) (w.unr k) p ∧ w.reg i = some k then none else w.reg i }
  | .sealB k c os b =>
    if releasedSet c = w.rel k ∧ unresolvedSet c = w.unr k ∧ ∀ o ∈ os, o.shard = k → w.reg o.id = some k then
      let r := decideReg c k os b
      some { w with rel := fun j => if j = k then r.released.entries else w.rel j,
                    unr := fun j => if j = k then r.unresolved.entries else w.unr j,
                    paid := w.paid ++ ((r.decisions.filter fun d =>
                      payOutcome c r.decisions d.line.pay == .ALLOW).map fun d => (k, d.line)) }
    else none

def World.run (w : World) : List Ev → Option World
  | [] => some w
  | e :: es => (w.step e).bind (·.run es)

/-- Every set row is its shard's in the registry, released ids are unique per shard, and every ALLOW line
    sealed is in its shard's released set. -/
def World.Ok (w : World) : Prop :=
  (∀ k, ∀ x ∈ w.rel k ++ w.unr k, w.reg x.id = some k) ∧ (∀ k, ((w.rel k).map (·.id)).Nodup) ∧
    ∀ p ∈ w.paid, p.2 ∈ w.rel p.1

theorem World.step_ok {w w' : World} {e : Ev} (h : w.Ok) (hs : w.step e = some w') : w'.Ok := by
  obtain ⟨ho, hn, hp⟩ := h
  cases e with
  | reserve k ids =>
    simp only [World.step, Option.some.injEq] at hs
    subst hs
    refine ⟨fun j x hx => ?_, hn, hp⟩
    have hj := ho j x hx
    show (if w.reg x.id = none ∧ x.id ∈ ids then some k else w.reg x.id) = some j
    rw [if_neg (by rw [hj]; simp), hj]
  | settle k p =>
    simp only [World.step, Option.some.injEq] at hs
    subst hs
    refine ⟨fun j x hx => ?_, hn, hp⟩
    have hj := ho j x hx
    show (if x.id ∈ settleFree (w.rel k) (w.unr k) p ∧ w.reg x.id = some k then none else w.reg x.id) = some j
    rw [if_neg, hj]
    rintro ⟨h1, h2⟩
    rw [hj] at h2
    obtain rfl := Option.some.inj h2
    exact settleFree_out h1 x hx rfl
  | sealB k c os b =>
    simp only [World.step] at hs
    split at hs
    · rename_i hg
      obtain ⟨hrel, hunr, hos⟩ := hg
      simp only [Option.some.injEq] at hs
      subst hs
      have hf := ready_hf (b := b) hos
      refine ⟨fun j x hx => ?_, fun j => ?_, fun p hp' => ?_⟩
      · show w.reg x.id = some j
        by_cases hj : j = k
        · have hx : x ∈ (decideReg c k os b).released.entries ++ (decideReg c k os b).unresolved.entries := by
            simpa only [if_pos hj] using hx
          rw [hj]
          rcases List.mem_append.mp hx with hx | hx
          · exact (released_owner hf hx).elim
              (fun h => ho k x (List.mem_append_left _ (by rw [← hrel]; exact h))) id
          · exact (unresolved_owner hf hx).elim
              (fun h => ho k x (List.mem_append_right _ (by rw [← hunr]; exact h))) id
        · have hx : x ∈ w.rel j ++ w.unr j := by simpa only [if_neg hj] using hx
          exact ho j x hx
      · show ((if j = k then (decideReg c k os b).released.entries else w.rel j).map (·.id)).Nodup
        by_cases hj : j = k
        · rw [if_pos hj]
          exact released_nodup (by rw [hrel]; exact hn k)
        · rw [if_neg hj]
          exact hn j
      · show p.2 ∈ (if p.1 = k then (decideReg c k os b).released.entries else w.rel p.1)
        have hp' : p ∈ w.paid ++ (((decideReg c k os b).decisions.filter fun d =>
            payOutcome c (decideReg c k os b).decisions d.line.pay == .ALLOW).map fun d => (k, d.line)) := hp'
        rcases List.mem_append.mp hp' with hp' | hp'
        · by_cases hj : p.1 = k
          · rw [if_pos hj]
            exact row_next (Or.inl (by rw [hrel, ← hj]; exact hp p hp'))
          · rw [if_neg hj]
            exact hp p hp'
        · obtain ⟨d, hd, rfl⟩ := List.mem_map.mp hp'
          obtain ⟨hd, ha⟩ := List.mem_filter.mp hd
          rw [if_pos rfl]
          exact row_next (Or.inr ⟨d, hd, rfl, beq_iff_eq.mp ha⟩)
    · cases hs

theorem World.run_ok {w w' : World} {es : List Ev} (h : w.Ok) (hr : w.run es = some w') : w'.Ok := by
  induction es generalizing w with
  | nil =>
    simp only [World.run, Option.some.injEq] at hr
    exact hr ▸ h
  | cons e es ih =>
    simp only [World.run] at hr
    cases hs : w.step e with
    | none => rw [hs] at hr; cases hr
    | some w1 => rw [hs] at hr; exact ih (World.step_ok h hs) hr

/-- Headline (runtime): over any interleaving of reserve, seal and settle events of any shards, two ALLOW
    lines sealed anywhere with one id are one line of one shard. -/
theorem run_one_payment_per_line {w w' : World} {es : List Ev} (h : w.Ok) (hr : w.run es = some w')
    {k k' : Nat} {x y : Line} (hx : (k, x) ∈ w'.paid) (hy : (k', y) ∈ w'.paid) (hid : x.id = y.id) :
    k = k' ∧ x = y := by
  obtain ⟨ho, hn, hp⟩ := World.run_ok h hr
  have hx' : x ∈ w'.rel k := hp _ hx
  have hy' : y ∈ w'.rel k' := hp _ hy
  have h1 := ho k x (List.mem_append_left _ hx')
  have h2 := ho k' y (List.mem_append_left _ hy')
  rw [hid, h2] at h1
  obtain rfl := Option.some.inj h1
  exact ⟨rfl, map_nodup_inj (hn k') hx' hy' hid⟩

/-- No line id is in two shards' sets, after any run. -/
theorem run_no_id_two_shards {w w' : World} {es : List Ev} (h : w.Ok) (hr : w.run es = some w')
    {k k' : Nat} {x y : Line} (hx : x ∈ w'.rel k ++ w'.unr k) (hy : y ∈ w'.rel k' ++ w'.unr k')
    (hid : x.id = y.id) : k = k' := by
  obtain ⟨ho, -, -⟩ := World.run_ok h hr
  have h1 := ho k x hx
  rw [hid, ho k' y hy] at h1
  exact (Option.some.inj h1).symm

/-! ### The twins -/

namespace Fast

open Std (HashSet)

theorem readyF_eq (k : Nat) (os : List Owner) (b : List Line) : readyF k os b = ready k os b := by
  simp only [readyF, ready]
  congr 1
  funext l
  simp only [HashSet.contains_ofList, contains_filter_map, okId]

theorem foreignOfF_eq (k : Nat) (os : List Owner) (b : List Line) : foreignOfF k os b = foreignOf k os b := by
  simp only [foreignOfF, foreignOf]
  congr 1
  funext i
  simp only [HashSet.contains_ofList, contains_filter_map, taken]

theorem settleFreeF_eq (rel unr : List Line) (p : List Nat) : settleFreeF rel unr p = settleFree rel unr p := by
  simp only [settleFreeF, settleFree, HashSet.contains_ofList]

theorem decideRegF_eq (c : Ctx) (k : Nat) (os : List Owner) (b : List Line) :
    decideRegF c k os b = decideReg c k os b := by
  simp only [decideRegF, decideReg, readyF_eq, foreignOfF_eq, decideBatchFIn_eq]

end Fast

/-! Axiom pins. -/
/-- info: 'BlindLedger.Gate.Rules.run_one_payment_per_line' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms run_one_payment_per_line
/-- info: 'BlindLedger.Gate.Rules.run_no_id_two_shards' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms run_no_id_two_shards
/-- info: 'BlindLedger.Gate.Rules.Fast.decideRegF_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Fast.decideRegF_eq
/-- info: 'BlindLedger.Gate.Rules.Fast.settleFreeF_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Fast.settleFreeF_eq

end BlindLedger.Gate.Rules
