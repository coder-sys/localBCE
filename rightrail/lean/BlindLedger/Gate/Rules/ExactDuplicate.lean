import BlindLedger.Gate.Rules.Bypass

namespace BlindLedger.Gate.Rules

/-! Exact duplicates answered at once (Constitution I.4; docs/RIGHTRAIL_FULL_STACK_TARGET.md §6, "Exact duplicates").
    The engine answers through these definitions (`Run.answering`, the worker's leaves and unresolved additions).

    A line exactly repeats a paid line when that line is in the gate's view of the released set and equals it in every
    canonical line field but the line id (`sameLine`; the payment is not a line field).  A re-decided payment's own
    lines are excluded.  A payment with such a line, unless its sender contests (`k`), is `ANSWERED` in the batch that
    carries it, names the earlier payments (`earlier`), and joins neither set: it is never held for a person and never
    released.  The rules' decisions and the released set are exactly those of `decideBatch` (`released_unchanged`):
    the amendment only stops the payment from waiting for a person.  A contested payment is decided as before. -/

/-- Equal in every canonical line field (`pLine`) except the line id. -/
def sameLine (x l : Line) : Bool :=
  x.flow == l.flow && x.member == l.member && x.payee == l.payee && x.rendering == l.rendering && x.date == l.date &&
    x.proc == l.proc && x.units == l.units && x.cents == l.cents

/-- The paid line `l` exactly repeats, if any: the first such line of the gate's view of the released set.  Never one
    of the loose rows an unchained set shows, and never for a re-decided payment's own line. -/
def twin (c : Ctx) (l : Line) : Option Line :=
  if own c l then none else (releasedSet c).find? (sameLine · l)

/-- Payment `p` is answered: its sender did not contest (`k` lists the contested payments) and a line of it exactly
    repeats a paid line. -/
def answered (c : Ctx) (k : List Nat) (ds : List Decision) (p : Nat) : Bool :=
  !k.contains p && ds.any fun d => d.line.pay == p && (twin c d.line).isSome

/-- The answer's list: for each line of `p` that exactly repeats a paid line, its id, the earlier payment and the
    earlier line id. -/
def earlier (c : Ctx) (ds : List Decision) (p : Nat) : List (Nat × Nat × Nat) :=
  (ds.filter (·.line.pay == p)).filterMap fun d => (twin c d.line).map fun x => (d.line.id, x.pay, x.id)

inductive AnswerOutcome | ALLOW | HOLD | HUMAN_REVIEW | ANSWERED deriving DecidableEq, Repr

def AnswerOutcome.ofOutcome : Outcome → AnswerOutcome
  | .ALLOW => .ALLOW | .HOLD => .HOLD | .HUMAN_REVIEW => .HUMAN_REVIEW

/-- The leaf's outcome in the order `Run.emitWith` gives it: an unencodable payment HOLD, an answered one ANSWERED,
    else the outcome `o` the existing path gives (the rules', a bypass's or a HOLD-level lift's). -/
def answerLeaf (c : Ctx) (k : List Nat) (ds : List Decision) (unf : Nat → Bool) (o : Outcome) (p : Nat) :
    AnswerOutcome :=
  if unf p then .HOLD else if answered c k ds p then .ANSWERED else .ofOutcome o

/-- Payer check 8 (`Gate.allows`) on the new outcome: it pays only ALLOW at TRANSFER authority. -/
def payerPays (o : AnswerOutcome) (a : Gate.Authority) : Bool := o == .ALLOW && a == .TRANSFER

/-- HOLD and HUMAN_REVIEW lines that wait for a person, less every line of an answered payment. -/
def unresolvedLinesX (c : Ctx) (k : List Nat) (ds : List Decision) : List Line :=
  (unresolvedLines c ds).filter fun l => !answered c k ds l.pay

/-- `decideBatch` with the contested payments `k`: the same decisions and released lines; answered payments' lines
    leave the unresolved additions. -/
def decideBatchX (c : Ctx) (k : List Nat) (batch : List Line) : Result :=
  let ds := decideAll c (seen0 c batch) (order c batch)
  { decisions := ds, released := advance c.today c.releasedPrior c.released (releasedLines c ds),
    unresolved := advance c.today c.unresolvedPrior c.unresolved (unresolvedLinesX c k ds) }

/-- The amendment changes neither a decision nor what is released. -/
theorem released_unchanged (c : Ctx) (k : List Nat) (batch : List Line) :
    (decideBatchX c k batch).decisions = (decideBatch c batch).decisions ∧
      (decideBatchX c k batch).released = (decideBatch c batch).released := ⟨rfl, rfl⟩

theorem sameLine_exactKey {x l : Line} (h : sameLine x l = true) : exactKey x = exactKey l := by
  simp only [sameLine, Bool.and_eq_true, beq_iff_eq] at h
  obtain ⟨⟨⟨⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, h5⟩, h6⟩, h7⟩, h8⟩ := h
  simp [exactKey, isCap, h1, h2, h3, h5, h6, h7, h8]

/-- The twin is a line of the released view, equal in every field but the id, of a line that is not a re-decision's
    own. -/
theorem twin_spec {c : Ctx} {l x : Line} (h : twin c l = some x) :
    x ∈ releasedSet c ∧ sameLine x l = true ∧ own c l = false := by
  unfold twin at h
  split at h
  · cases h
  · rename_i ho
    refine ⟨List.mem_of_find?_eq_some h, ?_, by simpa using ho⟩
    have := List.find?_some h
    simpa using this

/-- A line with a twin has seen its twin's exact key. -/
theorem twin_seen {c : Ctx} {b : List Line} {d : Decision} (hd : d ∈ decideAll c (seen0 c b) (order c b))
    (ht : (twin c d.line).isSome) :
    ∃ seen, d = decideLine c seen d.line ∧ exactKey d.line ∈ seen := by
  obtain ⟨x, hx⟩ := Option.isSome_iff_exists.mp ht
  obtain ⟨h1, h2, h3⟩ := twin_spec hx
  obtain ⟨seen, hs, hall⟩ := seen_all (c := c) (b := b) (e := d) hd h3
  refine ⟨seen, hs, hall x h1 _ ?_⟩
  simp [keys, sameLine_exactKey h2]

/-- An exactly repeated line carries the duplicate reason the rules already give it, so the leaf states it. -/
theorem twin_reason {c : Ctx} {b : List Line} {d : Decision} (hd : d ∈ decideAll c (seen0 c b) (order c b))
    (ht : (twin c d.line).isSome) :
    Reason.FFS_DUPLICATE_LINE ∈ d.reasons ∨ Reason.CAP_MEMBER_MONTH_DUPLICATE ∈ d.reasons := by
  obtain ⟨seen, hs, hk⟩ := twin_seen hd ht
  have hr : d.reasons = (decideLine c seen d.line).reasons := congrArg Decision.reasons hs
  rw [hr]
  have hk' : seen.contains (exactKey d.line) = true := List.contains_iff_mem.mpr hk
  cases hc : isCap d.line
  · left
    simp only [decideLine, List.mem_filter]
    exact ⟨by simp [reasons], by simp [fires, hc, hk]⟩
  · right
    simp only [decideLine, List.mem_filter]
    exact ⟨by simp [reasons], by simp [fires, hc, hk]⟩

/-- A near duplicate is never classed exact: a line the rules find a near duplicate has no twin. -/
theorem near_never_exact {c : Ctx} {b : List Line} {d : Decision} (hd : d ∈ decideAll c (seen0 c b) (order c b))
    (hn : Reason.FFS_NEAR_DUPLICATE ∈ d.reasons) : twin c d.line = none := by
  cases ht : twin c d.line
  · rfl
  · exfalso
    obtain ⟨seen, hs, hk⟩ := twin_seen hd (by simp [ht])
    have hr : d.reasons = (decideLine c seen d.line).reasons := congrArg Decision.reasons hs
    rw [hr] at hn
    simp only [decideLine, List.mem_filter] at hn
    have h2 := hn.2
    simp only [fires, Bool.and_eq_true, Bool.not_eq_true'] at h2
    have := h2.2
    have hk' : seen.contains (exactKey d.line) = true := List.contains_iff_mem.mpr hk
    rw [hk'] at this
    cases this

/-- Only an exact repeat answers: a payment none of whose lines equals a line of the released view in every field but
    the id (or whose lines are a re-decision's own) is not answered. -/
theorem not_answered_of_no_twin {c : Ctx} {k : List Nat} {ds : List Decision} {p : Nat}
    (h : ∀ d ∈ ds, d.line.pay = p → own c d.line = true ∨ ∀ x ∈ releasedSet c, sameLine x d.line = false) :
    answered c k ds p = false := by
  unfold answered
  cases hk : k.contains p
  · cases ha : ds.any fun d => d.line.pay == p && (twin c d.line).isSome
    · rfl
    · obtain ⟨d, hd, hdp⟩ := List.any_eq_true.mp ha
      simp only [Bool.and_eq_true, beq_iff_eq] at hdp
      obtain ⟨hp, ht⟩ := hdp
      obtain ⟨x, hx⟩ := Option.isSome_iff_exists.mp ht
      obtain ⟨h1, h2, h3⟩ := twin_spec hx
      rcases h d hd hp with h4 | h4
      · rw [h4] at h3; cases h3
      · rw [h4 x h1] at h2; cases h2
  · rfl

/-- An answered payment has a decided line that the rules hold for a reason no bypass or lift overrides. -/
theorem answered_bad {c : Ctx} {k : List Nat} {b : List Line} {p : Nat}
    (h : answered c k (decideAll c (seen0 c b) (order c b)) p = true) :
    ∃ d ∈ decideAll c (seen0 c b) (order c b), d.line.pay = p ∧ d.outcome = .HOLD ∧
      ∃ r ∈ d.reasons, bypassable r = false := by
  unfold answered at h
  simp only [Bool.and_eq_true] at h
  obtain ⟨d, hd, hdp⟩ := List.any_eq_true.mp h.2
  simp only [Bool.and_eq_true, beq_iff_eq] at hdp
  obtain ⟨hp, ht⟩ := hdp
  have hr := twin_reason hd ht
  refine ⟨d, hd, hp, ?_⟩
  obtain ⟨pre, l, rfl⟩ := mem_decideAll hd
  rcases hr with hr | hr
  · exact ⟨outcomeOf_certain hr rfl, _, hr, rfl⟩
  · exact ⟨outcomeOf_certain hr rfl, _, hr, rfl⟩

/-- The rules already hold an answered payment: it is never ALLOW on the merits. -/
theorem answered_held {c : Ctx} {k : List Nat} {b : List Line} {p : Nat}
    (h : answered c k (decideAll c (seen0 c b) (order c b)) p = true) :
    payOutcome c (decideAll c (seen0 c b) (order c b)) p = .HOLD := by
  obtain ⟨d, hd, hp, ho, -⟩ := answered_bad h
  unfold payOutcome
  rw [if_pos]
  exact List.any_eq_true.mpr ⟨d, List.mem_filter.mpr ⟨hd, by simp [hp]⟩, by simp [ho]⟩

/-- No approval reaches an answered payment: no bypass or cause release (both `bypassed`) and no HOLD-level lift. -/
theorem answered_no_approval {c : Ctx} {k : List Nat} {b : List Line} {p : Nat}
    (h : answered c k (decideAll c (seen0 c b) (order c b)) p = true) :
    bypassed c (decideAll c (seen0 c b) (order c b)) p = false ∧
      limitedPay c (decideAll c (seen0 c b) (order c b)) p = false := by
  obtain ⟨d, hd, hp, -, r, hr, hb⟩ := answered_bad h
  constructor
  · rw [← hp]; exact never_bypassable hd hr hb
  · unfold limitedPay
    split
    · rfl
    · rename_i m hm
      cases hh : (!c.redo.contains p && lifts m (decideAll c (seen0 c b) (order c b)) p
          (payOutcome c (decideAll c (seen0 c b) (order c b)) p))
      · rfl
      · exfalso
        have := (lifts_iff.mp ((Bool.and_eq_true _ _).mp hh).2).2.2 d hd hp r hr
        rw [hb] at this
        cases this.1

/-- No money moves twice: no line of an answered payment is released. -/
theorem answered_not_released {c : Ctx} {k : List Nat} {b : List Line} {p : Nat}
    (h : answered c k (decideAll c (seen0 c b) (order c b)) p = true) :
    ∀ l ∈ releasedLines c (decideAll c (seen0 c b) (order c b)), l.pay ≠ p := by
  intro l hl hlp
  obtain ⟨d, hd, hp, ho, r, hr, hb⟩ := answered_bad h
  rw [← hlp] at hp
  rcases fail_closed_unless_bypass c b l hl with h1 | ⟨m, -, -, hall⟩ | ⟨m, -, hall⟩
  · have := answered_held h
    rw [hlp, this] at h1
    cases h1
  · have := (hall d hd hp r hr).1
    rw [hb] at this
    cases this
  · have := (hall d hd hp r hr).1
    rw [hb] at this
    cases this

/-- An answered payment never carries TRANSFER authority to pay: whatever the existing outcome and authority, the payer's
    check 8 refuses its leaf. -/
theorem answered_never_paid {c : Ctx} {k : List Nat} {ds : List Decision} {p : Nat} (h : answered c k ds p = true)
    (unf : Nat → Bool) (o : Outcome) (a : Gate.Authority) : payerPays (answerLeaf c k ds unf o p) a = false := by
  cases hu : unf p <;> simp [payerPays, answerLeaf, hu, h]

/-- Answered at once: in the batch that carries it, the payment's leaf is ANSWERED (unless unencodable), it names at
    least one earlier payment, and none of its lines waits for a person. -/
theorem answered_at_once {c : Ctx} {k : List Nat} {ds : List Decision} {p : Nat} (h : answered c k ds p = true)
    (unf : Nat → Bool) (hu : unf p = false) (o : Outcome) :
    answerLeaf c k ds unf o p = .ANSWERED ∧ earlier c ds p ≠ [] ∧ ∀ l ∈ unresolvedLinesX c k ds, l.pay ≠ p := by
  refine ⟨by simp [answerLeaf, hu, h], ?_, ?_⟩
  · unfold answered at h
    simp only [Bool.and_eq_true] at h
    obtain ⟨d, hd, hdp⟩ := List.any_eq_true.mp h.2
    simp only [Bool.and_eq_true, beq_iff_eq] at hdp
    obtain ⟨hp, ht⟩ := hdp
    obtain ⟨x, hx⟩ := Option.isSome_iff_exists.mp ht
    intro he
    have hm : (d.line.id, x.pay, x.id) ∈ earlier c ds p :=
      List.mem_filterMap.mpr ⟨d, List.mem_filter.mpr ⟨hd, by simp [hp]⟩, by simp [hx]⟩
    rw [he] at hm
    cases hm
  · intro l hl hlp
    have := (List.mem_filter.mp hl).2
    rw [hlp, h] at this
    cases this

/-- Each answer names a paid line equal to one of the payment's lines in every field but the id. -/
theorem earlier_paid {c : Ctx} {ds : List Decision} {p i q j : Nat} (h : (i, q, j) ∈ earlier c ds p) :
    ∃ d ∈ ds, d.line.pay = p ∧ d.line.id = i ∧
      ∃ x ∈ releasedSet c, x.pay = q ∧ x.id = j ∧ sameLine x d.line = true := by
  obtain ⟨d, hd, hm⟩ := List.mem_filterMap.mp h
  obtain ⟨hd1, hd2⟩ := List.mem_filter.mp hd
  obtain ⟨x, hx, he⟩ := Option.map_eq_some_iff.mp hm
  obtain ⟨h1, h2, -⟩ := twin_spec hx
  simp only [Prod.mk.injEq] at he
  exact ⟨d, hd1, by simpa using hd2, he.1, x, h1, he.2.1, he.2.2, h2⟩

/-- A contested payment is decided as before the amendment: its outcome is the existing one, and its lines wait for a
    person exactly as they did. -/
theorem contested_as_before {c : Ctx} {k : List Nat} {ds : List Decision} {p : Nat} (hk : k.contains p = true)
    (unf : Nat → Bool) (o : Outcome) :
    answerLeaf c k ds unf o p = (if unf p then .HOLD else .ofOutcome o) ∧
      ∀ l : Line, l.pay = p → (l ∈ unresolvedLinesX c k ds ↔ l ∈ unresolvedLines c ds) := by
  have hn : ∀ q, q = p → answered c k ds q = false := by
    intro q hq; subst hq; unfold answered; rw [hk]; rfl
  refine ⟨by simp [answerLeaf, hn p rfl], fun l hlp => ?_⟩
  simp only [unresolvedLinesX, List.mem_filter, hn l.pay hlp]
  simp

end BlindLedger.Gate.Rules
