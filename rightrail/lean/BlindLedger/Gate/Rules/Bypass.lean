import BlindLedger.Gate.Keyset
import BlindLedger.Gate.Rules.DecideLayer

namespace BlindLedger.Gate.Rules

/-! What a bypass can and cannot release.  A bypass names a payment the gate held in this shard (a line of it is
    unresolved) and sets a mask of the reasons it overrides; `bypassed` holds only if every reason on every line of
    the payment is bypassable and in the mask.  The payment's lines then join the released set, whose id keys never
    age out, so the same lines are `ALREADY_DECIDED` ever after and no second bypass can name them. -/

/-- Reading `bypassed` back gives its parts. -/
theorem bypassed_iff {c : Ctx} {ds : List Decision} {p : Nat} (h : bypassed c ds p = true) :
    ∃ m, c.byp.lookup p = some m ∧ c.redo.contains p = false ∧
      (∃ d ∈ ds, d.line.pay = p ∧ d.line ∈ unresolvedSet c) ∧
      ∀ d ∈ ds, d.line.pay = p → ∀ r ∈ d.reasons, bypassable r = true ∧ Keyset.bit m r.idx = true := by
  unfold bypassed at h
  split at h
  · cases h
  · rename_i m hm
    simp only [Bool.and_eq_true] at h
    obtain ⟨⟨h1, h3⟩, h4⟩ := h
    refine ⟨m, hm, by simpa using h1, ?_, ?_⟩
    · obtain ⟨d, hd, hdp⟩ := List.any_eq_true.mp h3
      simp only [Bool.and_eq_true, beq_iff_eq] at hdp
      exact ⟨d, hd, hdp.1, by simpa using hdp.2⟩
    · intro d hd hp r hr
      have h5 := List.all_eq_true.mp h4 d hd
      simp only [Bool.or_eq_true] at h5
      rcases h5 with h5 | h5
      · exact absurd hp (bne_iff_ne.mp h5)
      · have := List.all_eq_true.mp h5 r hr
        exact (Bool.and_eq_true _ _).mp this

theorem mem_decideAll_lines {c : Ctx} {b : List Line} {d : Decision}
    (hd : d ∈ decideAll c (seen0 c b) (order c b)) : d.line ∈ b := by
  have := List.mem_map_of_mem (f := (·.line)) hd
  rw [lines_decideAll] at this
  exact (order_perm c b).mem_iff.mp this

theorem lines_mem_decideAll {c : Ctx} {b : List Line} {l : Line} (hl : l ∈ b) :
    ∃ d ∈ decideAll c (seen0 c b) (order c b), d.line = l := by
  have : l ∈ (decideAll c (seen0 c b) (order c b)).map (·.line) := by
    rw [lines_decideAll]; exact (order_perm c b).mem_iff.mpr hl
  obtain ⟨d, hd, e⟩ := List.mem_map.mp this
  exact ⟨d, hd, e⟩

/-- A released line is of an ALLOW payment, or of a payment an admitted bypass names, held here, with every reason on
    it bypassable and overridden, or of a payment under a HOLD-level grant entry with every reason on it bypassable
    and not one the entry holds for. -/
theorem fail_closed_unless_bypass (c : Ctx) (batch : List Line) (l : Line)
    (hl : l ∈ releasedLines c (decideAll c (seen0 c batch) (order c batch))) :
    let ds := decideAll c (seen0 c batch) (order c batch)
    payOutcome c ds l.pay = .ALLOW ∨
      (∃ m, c.byp.lookup l.pay = some m ∧ (∃ l' ∈ batch, l'.pay = l.pay ∧ l' ∈ unresolvedSet c) ∧
        ∀ d ∈ ds, d.line.pay = l.pay → ∀ r ∈ d.reasons, bypassable r = true ∧ Keyset.bit m r.idx = true) ∨
      ∃ m, c.lim.lookup l.pay = some m ∧
        ∀ d ∈ ds, d.line.pay = l.pay → ∀ r ∈ d.reasons, bypassable r = true ∧ Keyset.bit m r.idx = false := by
  intro ds
  unfold releasedLines at hl
  obtain ⟨d, hd, rfl⟩ := List.mem_map.mp hl
  obtain ⟨-, hP⟩ := List.mem_filter.mp hd
  rcases (Bool.or_eq_true _ _).mp hP with h1 | h1
  · rcases (Bool.or_eq_true _ _).mp h1 with h1 | h1
    · left
      simp only [Bool.and_eq_true, beq_iff_eq] at h1
      exact h1.2
    · right; left
      obtain ⟨m, hm, -, ⟨d', hd', hp', hu'⟩, hall⟩ := bypassed_iff h1
      exact ⟨m, hm, ⟨d'.line, mem_decideAll_lines hd', hp', hu'⟩, hall⟩
  · right; right
    have hlp := ((Bool.and_eq_true _ _).mp h1).1
    unfold limitedPay at hlp
    split at hlp
    · cases hlp
    · rename_i m hm
      exact ⟨m, hm, (lifts_iff.mp ((Bool.and_eq_true _ _).mp hlp).2).2.2⟩

/-- A bypass, or a HOLD-level grant entry, releases only lines of the payment it names, from this batch: no window, no
    other payment. -/
theorem bypass_no_window (c : Ctx) (batch : List Line) (l : Line)
    (hl : l ∈ releasedLines c (decideAll c (seen0 c batch) (order c batch)))
    (hn : payOutcome c (decideAll c (seen0 c batch) (order c batch)) l.pay ≠ .ALLOW) :
    ((c.byp.lookup l.pay).isSome ∨ (c.lim.lookup l.pay).isSome) ∧ l ∈ batch := by
  have hb : l ∈ batch := by
    unfold releasedLines at hl
    obtain ⟨d, hd, rfl⟩ := List.mem_map.mp hl
    exact mem_decideAll_lines (List.mem_filter.mp hd).1
  rcases fail_closed_unless_bypass c batch l hl with h | ⟨m, hm, -⟩ | ⟨m, hm, -⟩
  · exact absurd h hn
  · exact ⟨Or.inl (by simp [hm]), hb⟩
  · exact ⟨Or.inr (by simp [hm]), hb⟩

/-- A never-bypassable reason on any line of p rules the bypass out. -/
theorem never_bypassable {c : Ctx} {ds : List Decision} {d : Decision} {r : Reason} (hd : d ∈ ds)
    (hr : r ∈ d.reasons) (hb : bypassable r = false) : bypassed c ds d.line.pay = false := by
  cases h : bypassed c ds d.line.pay
  · rfl
  · obtain ⟨m, -, -, -, hall⟩ := bypassed_iff h
    have := (hall d hd rfl r hr).1
    rw [hb] at this
    cases this

/-- A line whose identity is in the keys seen is `ALREADY_DECIDED`. -/
theorem already_decided_of_seen {c : Ctx} {seen : List Key} {ls : List Line} {d : Decision}
    (hd : d ∈ decideAll c seen ls) (hk : idKey d.line ∈ seen) : Reason.ALREADY_DECIDED ∈ d.reasons := by
  obtain ⟨pre, l, rfl⟩ := mem_decideAll hd
  exact mem_decideLine.mpr (Or.inl (List.mem_append_right _ hk))

/-- A line of the batch that the released set already holds, and that is not a re-decision's own, is
    `ALREADY_DECIDED`, which no bypass overrides: nothing bypasses it again. -/
theorem not_bypassed_of_released {c : Ctx} {b : List Line} {l : Line} (hl : l ∈ b) (hr : l ∈ releasedSet c)
    (hredo : c.redo.contains l.pay = false) : bypassed c (decideBatch c b).decisions l.pay = false := by
  obtain ⟨d, hd, rfl⟩ := lines_mem_decideAll (c := c) hl
  have hown : own c d.line = false := by simp only [own, hredo, Bool.false_and]
  have hk : idKey d.line ∈ seen0 c b :=
    List.mem_flatMap.mpr ⟨d.line, List.mem_filter.mpr ⟨hr, by simp [hown]⟩, idKey_mem⟩
  exact never_bypassable (c := c) (ds := decideAll c (seen0 c b) (order c b)) hd
    (already_decided_of_seen hd hk) rfl

/-- The rules' decision of one batch, then the shard's next state: each batch's bypasses are set, and the sets it
    left are carried. -/
structure Step where
  ctx : Ctx
  batch : List Line

def Step.ds (s : Step) : List Decision := (decideBatch s.ctx s.batch).decisions

def Step.lines (s : Step) (p : Nat) : List Line := s.batch.filter (·.pay == p)

/-- A shard's history: each batch with the bypasses admitted for it, each deciding on the sets the one before left. -/
def steps : Ctx → List (List Line × List (Nat × Nat)) → List Step
  | _, [] => []
  | c, (b, byp) :: bs =>
    ⟨{ c with byp := byp }, b⟩ :: steps (carried { c with byp := byp } (decideBatch { c with byp := byp } b).released
      (decideBatch { c with byp := byp } b).unresolved) bs

/-- Every set a later batch reads holds the lines of the earlier ones. -/
theorem steps_released : ∀ (bs : List (List Line × List (Nat × Nat))) (c : Ctx) (t : Step), t ∈ steps c bs →
    ∀ x ∈ releasedSet c, x ∈ releasedSet t.ctx
  | [], c, t, ht, x, hx => by simp [steps] at ht
  | (b, byp) :: bs, c, t, ht, x, hx => by
    rw [steps, List.mem_cons] at ht
    rcases ht with rfl | ht
    · exact hx
    · refine steps_released bs _ t ht x ?_
      rw [(carried_sets _ _ _).1]
      exact List.mem_append_left _ hx

/-- A bypassed payment's lines are all in the released set after the batch. -/
theorem released_of_bypassed {c : Ctx} {b : List Line} {p : Nat} (h : bypassed c (decideBatch c b).decisions p = true)
    {l : Line} (hl : l ∈ b) (hp : l.pay = p) : l ∈ (decideBatch c b).released.entries := by
  obtain ⟨d, hd, hdl⟩ := lines_mem_decideAll (c := c) hl
  have hpay : d.line.pay = p := by rw [hdl]; exact hp
  have h2 : bypassed c (decideAll c (seen0 c b) (order c b)) d.line.pay = true := by rw [hpay]; exact h
  refine List.mem_append_right _ (List.mem_map.mpr ⟨d, List.mem_filter.mpr ⟨hd, ?_⟩, hdl⟩)
  simp [h2]

/-- No step after one that bypassed a payment bypasses the same lines again. -/
theorem later_not_bypassed {ls : List Line} (hne : ls ≠ []) : ∀ (bs : List (List Line × List (Nat × Nat))) (c : Ctx),
    (∀ l ∈ ls, l ∈ releasedSet c) → ∀ t ∈ steps c bs, ¬∃ p, bypassed t.ctx t.ds p = true ∧ t.lines p = ls := by
  intro bs c hls t ht ⟨p, hb, hlp⟩
  obtain ⟨l, hl⟩ := List.exists_mem_of_ne_nil ls hne
  have hl2 := hl
  rw [← hlp, Step.lines, List.mem_filter] at hl2
  have hpay : l.pay = p := by simpa using hl2.2
  obtain ⟨m, -, hredo, -⟩ := bypassed_iff hb
  have h3 := not_bypassed_of_released (c := t.ctx) hl2.1 (steps_released bs c t ht l (hls l hl))
    (by rw [hpay]; exact hredo)
  rw [hpay] at h3
  rw [Step.ds, h3] at hb
  cases hb

open Classical in
/-- Single use per shard history. -/
theorem bypass_once (c0 : Ctx) (bs : List (List Line × List (Nat × Nat))) (ls : List Line) (hne : ls ≠ []) :
    ((steps c0 bs).filter fun s => ∃ p, bypassed s.ctx s.ds p = true ∧ s.lines p = ls).length ≤ 1 := by
  induction bs generalizing c0 with
  | nil => simp [steps]
  | cons hd bs ih =>
    obtain ⟨b, byp⟩ := hd
    rw [steps, List.filter_cons]
    split
    · rename_i hP
      obtain ⟨p, hb, hlp⟩ := of_decide_eq_true hP
      have hnil : List.filter _ (steps (carried { c0 with byp := byp } (decideBatch { c0 with byp := byp } b).released
          (decideBatch { c0 with byp := byp } b).unresolved) bs) = [] :=
        List.filter_eq_nil_iff.mpr fun t ht hPt => later_not_bypassed hne bs _ (fun l hl => by
          rw [(carried_sets _ _ _).1]
          have hl2 := hl
          rw [← hlp, Step.lines, List.mem_filter] at hl2
          exact released_of_bypassed hb hl2.1 (by simpa using hl2.2)) t ht (of_decide_eq_true hPt)
      rw [hnil]
      simp
    · exact ih _

end BlindLedger.Gate.Rules
