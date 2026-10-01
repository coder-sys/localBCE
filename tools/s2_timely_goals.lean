import BlindLedger.Financial.Evaluation

/-! S2, an offset's timeliness is judged when it was committed: the theorem STATEMENTS of design
    C:\Users\neers\rrb\designs\s2-timely-v1.md.  Every proof is `sorry`.
    This file is outside `lean/`, so no executable, library target, TCB report or pin manifest sees it.
    Check: from `lean/`, `lake env lean ../tools/s2_timely_goals.lean` over a build of
    `BlindLedger.Financial.Evaluation`.
    Both statements are claimed true of the current evaluator, which stays unchanged: the first holds
    for every evaluated input; the second adds the S2 rule the owner and the checker enforce, and is
    false without it (the safety-sweep S2 test is the counterexample).  A later evaluator re-pin
    (lead's call, design step 6) moves the definitions beside `evaluate` with their proofs and axiom pins. -/

namespace BlindLedger.Financial

/-- When an offset was committed: the `createdAt` of its one bound action, the owner's clock at the write. -/
def offsetCommitAt (input : FinancialInput) (d : OffsetDetermination) : Nat :=
  match actionsForDetermination input d.determinationId with
  | action :: _ => action.createdAt
  | [] => d.decidedAt

/-- The S2 rule: an offset committed after the due date names no decision time at or before it. -/
def offsetsNotBackdatedPastDue (input : FinancialInput) : Bool :=
  input.determinations.all fun d =>
    d.decision != .OFFSET_AUTHORIZED || decide (input.obligation.dueAt < d.decidedAt) ||
      decide (offsetCommitAt input d ≤ input.obligation.dueAt)

/-- Cents in hand by the due date: active payments by their event time, offsets by `offsetTime`. -/
def centsByDue (input : FinancialInput) (offsetTime : OffsetDetermination → Nat) : Nat :=
  ((input.payments.filter fun p => p.status = .ACTIVE && p.eventAt ≤ input.obligation.dueAt).map
      Payment.amountCents).sum +
    ((input.determinations.filter fun d =>
        d.decision = .OFFSET_AUTHORIZED && offsetTime d ≤ input.obligation.dueAt).map
      OffsetDetermination.amountCents).sum

/-- What the evaluator decides today: timely exactly when the cents dated by the due date cover what is
    owed (offsets dated by their named decision time). -/
theorem evaluate_timely_iff_covered_by_due {input : FinancialInput} {r : FinancialResult}
    (h : evaluate input = some r) :
    r.timely = decide (input.obligation.owedCents ≤ centsByDue input OffsetDetermination.decidedAt) := by
  sorry

/-- S2: under the rule, the evaluator's `timely` is the one judged at each offset's commit. -/
theorem timely_judged_at_commit {input : FinancialInput} {r : FinancialResult}
    (h : evaluate input = some r) (hRule : offsetsNotBackdatedPastDue input = true) :
    r.timely = decide (input.obligation.owedCents ≤ centsByDue input (offsetCommitAt input)) := by
  sorry

end BlindLedger.Financial
