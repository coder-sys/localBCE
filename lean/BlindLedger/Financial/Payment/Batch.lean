import BlindLedger.Financial.Payment.Chain

namespace BlindLedger.Financial.Payment

open BlindLedger.Financial

/-! Owner batch (hold-release r4.2 section 11). Not imported by any executable.
    Per call the store keeps the rows and the event, never the intermediate evaluation
    (semantic_adapter.py:1146-1175; owner.py:3992 moves to once per obligation per chunk). -/

/-- What section 11 stores of one call: `PaymentOutcome` without `post`, and of the result only
    the event's before/after revision. -/
inductive Erased where
  | mutated (kind : Mutation) (writes : Writes) (beforeRevision afterRevision : Nat)
  | alias (paymentId : String) (evidence : EvidenceRecord)
  | duplicate (paymentId : Option String)
  | conflictUnchanged (conflictId : String)
  | refused (reason : Refusal)
deriving DecidableEq, Repr

def erase : PaymentOutcome → Erased
  | .mutated k w _ res => .mutated k w res.beforeRevision res.afterRevision
  | .alias pid e _ => .alias pid e
  | .duplicate pid => .duplicate pid
  | .conflictUnchanged id => .conflictUnchanged id
  | .refused f => .refused f

/-- The stored part of a view step: its summary and result are not stored per call. -/
def Erased.ofStep : StepOutcome → Erased
  | .mutated k w _ res => .mutated k w res.beforeRevision res.afterRevision
  | .alias pid e => .alias pid e
  | .duplicate pid => .duplicate pid
  | .conflictUnchanged id => .conflictUnchanged id
  | .refused f => .refused f

/-- What one write needs to know of the pre-state to decide `evaluate (applyWrites i w)`: the head,
    three row counts and the totals. O(1) to carry per call. -/
structure Summary where
  env : Env
  payments : Nat
  evidence : Nat
  conflicts : Nat
  totals : Option EvaluatedTotals

/-- The specification of the carried summary (O(input); `batchFast` never calls it per call). -/
def summary (i : FinancialInput) : Summary :=
  { env := envOf i, payments := i.payments.length, evidence := i.evidence.length,
    conflicts := i.conflicts.length, totals := evaluateTotals i }

/-- `evaluate (applyWrites i w)` is `some`, read from the summary (`evaluate_delta`). The head is
    re-checked whole (it carries the revision bound and the clock); the new rows are checked
    against the context, so an ill-formed command is still POST_REJECTED. A payment write with a
    receipt inserts (RECORDED); without one it replaces an ACTIVE row by its REVERSED image. -/
def deltaOk (s : Summary) (w : Writes) : Bool :=
  let ins := w.payment.isSome && w.receipt.isSome
  envWellFormed s.env &&
    s.payments + (if ins then 1 else 0) ≤ maxRows &&
    s.evidence + (if w.evidence.isSome then 1 else 0) ≤ maxRows &&
    s.conflicts + (if w.conflict.isSome then 1 else 0) ≤ maxRows &&
    w.payment.all (paymentWellFormed s.env.context) &&
    w.evidence.all (evidenceWellFormed s.env.context) &&
    s.totals.any fun t => !ins || (w.payment.all fun p => t.cash + p.amountCents + t.lawful ≤ maxCents)

end BlindLedger.Financial.Payment
